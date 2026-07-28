// SPDX-License-Identifier: Apache-2.0

//! Structural parser for the native Go fuzzing lane (M3.3).
//!
//! Mirrors the other tree-sitter parsers: extracts the function shapes the ranker
//! (`target_rank::go_rank`) needs — name, 1-based line, package, exported-ness
//! (Go capitalizes exported identifiers), whether it is a method (has a receiver),
//! and typed parameters. Go is statically typed, so — like C/Rust — the harness
//! generator decodes by the parameter's declared type.

use thiserror::Error;

/// One parameter of a Go function: binding name and declared type spelling.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GoParam {
    pub name: String,
    /// Type spelling, whitespace-collapsed (`[]byte`, `string`, `int`, `*Foo`).
    pub ty: String,
}

/// A Go function or method declaration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GoFunc {
    pub name: String,
    /// 1-based line of `func`.
    pub line: u32,
    /// Owning package (from the `package` clause).
    pub package: String,
    /// Exported = the name begins with an uppercase letter (Go visibility). Only
    /// exported funcs are callable from a separate harness package.
    pub is_exported: bool,
    /// `true` for a method (has a receiver) — needs a receiver value to call.
    pub is_method: bool,
    /// Receiver type spelling for a method (`*Decoder` / `Decoder`), else `None`.
    pub receiver_type: Option<String>,
    pub params: Vec<GoParam>,
    /// Result spelling as written (`*Decoder`, `Decoder`, `(Decoder, error)`), or
    /// `None` for a function that returns nothing.
    ///
    /// Carried so a CONSTRUCTOR can be told from any other no-arg function: the
    /// harness builds a method's receiver from a sibling `func NewT() *T` rather
    /// than demanding `--force` and a zero value, and without the result there is
    /// nothing to match `T` against.
    pub returns: Option<String>,
}

#[derive(Debug, Error)]
pub enum GoParseError {
    #[error("failed to load the Go grammar")]
    Grammar,
    #[error("tree-sitter failed to parse the source")]
    Parse,
}

const MAX_DEPTH: usize = 250;

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn node_text<'a>(node: tree_sitter::Node<'_>, bytes: &'a [u8]) -> &'a str {
    node.utf8_text(bytes).unwrap_or("")
}

/// Parse all function + method declarations from one Go source file.
pub fn parse_go_functions(source: &str) -> Result<Vec<GoFunc>, GoParseError> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .map_err(|_| GoParseError::Grammar)?;
    let tree = parser.parse(source, None).ok_or(GoParseError::Parse)?;
    let bytes = source.as_bytes();
    let package = find_package(tree.root_node(), bytes).unwrap_or_else(|| "main".to_owned());
    let mut out = Vec::new();
    collect(tree.root_node(), bytes, &package, 0, &mut out);
    Ok(out)
}

fn find_package(root: tree_sitter::Node<'_>, bytes: &[u8]) -> Option<String> {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "package_clause" {
            return child
                .children(&mut child.walk())
                .find(|c| c.kind() == "package_identifier")
                .map(|c| node_text(c, bytes).to_owned());
        }
    }
    None
}

fn collect(
    node: tree_sitter::Node<'_>,
    bytes: &[u8],
    package: &str,
    depth: usize,
    out: &mut Vec<GoFunc>,
) {
    if depth > MAX_DEPTH {
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_declaration" => {
                if let Some(f) = parse_function(child, bytes, package, false) {
                    out.push(f);
                }
            }
            "method_declaration" => {
                if let Some(f) = parse_function(child, bytes, package, true) {
                    out.push(f);
                }
            }
            _ => {}
        }
    }
}

fn parse_function(
    func: tree_sitter::Node<'_>,
    bytes: &[u8],
    package: &str,
    is_method: bool,
) -> Option<GoFunc> {
    let name_node = func
        .children(&mut func.walk())
        .find(|c| matches!(c.kind(), "identifier" | "field_identifier"))?;
    let name = node_text(name_node, bytes).to_owned();
    if name.is_empty() {
        return None;
    }
    let line = func.start_position().row as u32 + 1;
    let is_exported = name.chars().next().is_some_and(|c| c.is_uppercase());

    // For a method, the FIRST parameter_list is the receiver, the SECOND is params.
    // For a function, the FIRST parameter_list is params.
    let param_lists: Vec<tree_sitter::Node<'_>> = func
        .children(&mut func.walk())
        .filter(|c| c.kind() == "parameter_list")
        .collect();
    let (receiver_type, params_node) = if is_method {
        let recv = param_lists.first().and_then(|pl| receiver_type(*pl, bytes));
        (recv, param_lists.get(1).copied())
    } else {
        (None, param_lists.first().copied())
    };

    let params = params_node
        .map(|pl| parse_params(pl, bytes))
        .unwrap_or_default();

    // tree-sitter-go puts the result — a bare type, or a parameter_list for a
    // multi-value return — in the `result` field.
    let returns = func
        .child_by_field_name("result")
        .map(|node| node_text(node, bytes).trim().to_owned())
        .filter(|text| !text.is_empty());

    Some(GoFunc {
        name,
        line,
        package: package.to_owned(),
        is_exported,
        is_method,
        receiver_type,
        params,
        returns,
    })
}

fn receiver_type(pl: tree_sitter::Node<'_>, bytes: &[u8]) -> Option<String> {
    let decl = pl
        .children(&mut pl.walk())
        .find(|c| c.kind() == "parameter_declaration")?;
    decl.children(&mut decl.walk())
        .find(|c| is_type_node(c.kind()))
        .map(|t| collapse_ws(node_text(t, bytes)))
}

fn parse_params(pl: tree_sitter::Node<'_>, bytes: &[u8]) -> Vec<GoParam> {
    let mut out = Vec::new();
    let mut cursor = pl.walk();
    for decl in pl.children(&mut cursor) {
        if decl.kind() != "parameter_declaration" {
            continue;
        }
        let names: Vec<String> = decl
            .children(&mut decl.walk())
            .filter(|c| c.kind() == "identifier")
            .map(|c| node_text(c, bytes).to_owned())
            .collect();
        let ty = decl
            .children(&mut decl.walk())
            .find(|c| is_type_node(c.kind()))
            .map(|t| collapse_ws(node_text(t, bytes)))
            .unwrap_or_default();
        if names.is_empty() {
            if !ty.is_empty() {
                out.push(GoParam {
                    name: format!("a{}", out.len()),
                    ty,
                });
            }
        } else {
            for n in names {
                out.push(GoParam {
                    name: n,
                    ty: ty.clone(),
                });
            }
        }
    }
    out
}

fn is_type_node(kind: &str) -> bool {
    matches!(
        kind,
        "type_identifier"
            | "slice_type"
            | "array_type"
            | "pointer_type"
            | "map_type"
            | "qualified_type"
            | "interface_type"
            | "channel_type"
            | "function_type"
            | "generic_type"
            | "struct_type"
            | "variadic_parameter_declaration"
    )
}

/// Count tree-sitter ERROR nodes.
pub fn count_parse_errors(source: &str) -> usize {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .is_err()
    {
        return usize::MAX;
    }
    let Some(tree) = parser.parse(source, None) else {
        return usize::MAX;
    };
    let mut count = 0;
    walk_errors(tree.root_node(), &mut count);
    count
}

fn walk_errors(node: tree_sitter::Node<'_>, count: &mut usize) {
    if node.is_error() || node.is_missing() {
        *count += 1;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_errors(child, count);
    }
}

/// Mine string- and number-like source literals into fuzzing-dictionary tokens
/// (magic values that gate `==`/`switch` comparisons). Mirrors the C/C++ lanes so
/// the Go lane no longer fuzzes "cold". The tree is untrusted, so the walk is
/// depth-capped ([`DICT_MAX_DEPTH`]) to avoid stack overflow.
pub fn extract_go_dictionary_tokens(source: &str) -> Result<Vec<String>, GoParseError> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .map_err(|_| GoParseError::Grammar)?;
    let tree = parser.parse(source, None).ok_or(GoParseError::Parse)?;
    let mut tokens = Vec::new();
    collect_dictionary_tokens(tree.root_node(), source.as_bytes(), 0, &mut tokens);
    Ok(tokens)
}

/// Recursion cap for the untrusted-tree dictionary walk.
const DICT_MAX_DEPTH: usize = 256;

fn collect_dictionary_tokens(
    node: tree_sitter::Node<'_>,
    src: &[u8],
    depth: usize,
    out: &mut Vec<String>,
) {
    if depth >= DICT_MAX_DEPTH {
        return;
    }
    let kind = node.kind();
    if dict_kind_is_string_like(kind) {
        if let Ok(text) = node.utf8_text(src) {
            if let Some(tok) = clean_dict_string(text) {
                push_unique_token(out, tok);
            }
        }
        return; // a string is a leaf value — never recurse into its content
    }
    if dict_kind_is_number_like(kind) {
        if let Ok(text) = node.utf8_text(src) {
            if let Some(tok) = clean_dict_number(text) {
                push_unique_token(out, tok);
            }
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_dictionary_tokens(child, src, depth + 1, out);
    }
}

fn dict_kind_is_string_like(kind: &str) -> bool {
    kind.contains("string")
        || matches!(
            kind,
            "char_literal"
                | "character_literal"
                | "rune_literal"
                | "interpolated_string_literal"
                | "heredoc_content"
                | "quoted_content"
        )
}

fn dict_kind_is_number_like(kind: &str) -> bool {
    matches!(
        kind,
        "integer_literal"
            | "int_literal"
            | "integer"
            | "decimal_integer_literal"
            | "hex_integer_literal"
            | "octal_integer_literal"
            | "binary_integer_literal"
            | "number"
            | "numeric_literal"
            | "float_literal"
    )
}

/// Strip an optional byte/raw/format prefix (`b`, `r`, `f`, `u`, `L`, ...), one
/// matching layer of surrounding quotes/backticks, and raw-string `#` hashes from
/// a string-like literal, keeping the inner bytes verbatim (no unescaping). Rejects
/// empty/whitespace and results outside 1..=64 bytes.
fn clean_dict_string(raw: &str) -> Option<String> {
    let mut s = raw.trim();
    let lead = s.bytes().take_while(u8::is_ascii_alphabetic).count();
    if lead > 0
        && s.as_bytes()
            .get(lead)
            .is_some_and(|&c| matches!(c, b'"' | b'\'' | b'`' | b'#'))
    {
        s = &s[lead..];
    }
    let hashes = s.bytes().take_while(|b| *b == b'#').count();
    if hashes > 0 && s.len() >= 2 * hashes {
        s = &s[hashes..s.len() - hashes];
    }
    let b = s.as_bytes();
    if b.len() >= 2 {
        let (first, last) = (b[0], b[b.len() - 1]);
        if matches!(first, b'"' | b'\'' | b'`') && first == last {
            s = &s[1..s.len() - 1];
        }
    }
    if s.trim().is_empty() || s.len() > 64 {
        return None;
    }
    Some(s.to_owned())
}

/// Keep a number-like literal verbatim (trimmed); reject empty / over 32 bytes.
fn clean_dict_number(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() || s.len() > 32 {
        return None;
    }
    Some(s.to_owned())
}

fn push_unique_token(out: &mut Vec<String>, tok: String) {
    if !out.contains(&tok) {
        out.push(tok);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_string_and_integer_dictionary_tokens() {
        let toks = extract_go_dictionary_tokens(
            "package p\nfunc f(n int) string {\n\tx := \"MAGIC\"\n\tif n == 4919 {\n\t\treturn x\n\t}\n\treturn x\n}\n",
        )
        .expect("parse");
        assert!(toks.contains(&"MAGIC".to_string()), "tokens: {toks:?}");
        assert!(toks.contains(&"4919".to_string()), "tokens: {toks:?}");
    }

    const SRC: &str = "package parser\nimport \"errors\"\nfunc ParseRecord(data []byte) (int, error) {\n  if len(data) == 0 { return 0, errors.New(\"empty\") }\n  return len(data), nil\n}\nfunc Decode(s string, limit int) string { return s }\nfunc (p *Decoder) Feed(chunk []byte) error { return nil }\nfunc NewDecoder() *Decoder { return nil }\nfunc unexported(s string) {}\n";

    #[test]
    fn extracts_exported_function_with_typed_params() {
        let fns = parse_go_functions(SRC).unwrap();
        let pr = fns.iter().find(|f| f.name == "ParseRecord").unwrap();
        assert_eq!(pr.package, "parser");
        assert!(pr.is_exported && !pr.is_method);
        assert_eq!(pr.params.len(), 1);
        assert_eq!(pr.params[0].name, "data");
        assert_eq!(pr.params[0].ty, "[]byte");
        // A multi-value result comes back as its written parameter_list.
        assert_eq!(pr.returns.as_deref(), Some("(int, error)"));
    }

    #[test]
    fn multi_name_params_and_types() {
        let fns = parse_go_functions(SRC).unwrap();
        let d = fns.iter().find(|f| f.name == "Decode").unwrap();
        assert_eq!(d.params.len(), 2);
        assert_eq!(d.params[0].ty, "string");
        assert_eq!(d.params[1].ty, "int");
    }

    #[test]
    fn detects_method_with_receiver() {
        let fns = parse_go_functions(SRC).unwrap();
        let feed = fns.iter().find(|f| f.name == "Feed").unwrap();
        assert!(feed.is_method);
        assert_eq!(feed.receiver_type.as_deref(), Some("*Decoder"));
        // The result is carried so a constructor can be told from any other
        // no-arg function — see `GoFunc::returns`.
        let ctor = fns
            .iter()
            .find(|f| f.name == "NewDecoder")
            .expect("NewDecoder parsed");
        assert_eq!(ctor.returns.as_deref(), Some("*Decoder"));
        assert!(ctor.params.is_empty());
        assert_eq!(feed.returns.as_deref(), Some("error"));
        assert_eq!(feed.params.len(), 1, "receiver excluded from params");
        assert_eq!(feed.params[0].ty, "[]byte");
    }

    #[test]
    fn exported_flag() {
        let fns = parse_go_functions(SRC).unwrap();
        assert!(
            !fns.iter()
                .find(|f| f.name == "unexported")
                .unwrap()
                .is_exported
        );
    }

    #[test]
    fn counts_parse_errors() {
        assert_eq!(count_parse_errors("package x\nfunc ok() {}\n"), 0);
    }
}
