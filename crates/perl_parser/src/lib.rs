// SPDX-License-Identifier: Apache-2.0

//! Structural parser for the native Perl fuzzing lane (M3.2).
//!
//! Mirrors the other tree-sitter parsers: a thin walk extracting the sub shapes
//! the ranker (`target_rank::perl_rank`) needs — name, 1-based line, owning
//! `package`, private-by-convention (`_name`), and whether the sub is an OO method
//! (its body unpacks `$self`/`$class` from `@_`, the Perl receiver idiom).
//!
//! Perl has no declared parameter types — subs unpack `@_` — so the ranker leans
//! on the sub NAME (parse/decode/load) and the harness passes the fuzz bytes as a
//! string scalar, the classic text-processor calling shape.

use thiserror::Error;

/// A Perl subroutine.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PerlSub {
    pub name: String,
    /// 1-based line of the `sub` keyword.
    pub line: u32,
    /// Owning package (`main` when no `package` statement precedes it).
    pub package: String,
    /// Leading-underscore name (`_helper`) — private by convention.
    pub is_private: bool,
    /// The body unpacks `$self`/`$class` as the first `@_` element — an OO method
    /// that needs a blessed receiver, not a plain function call.
    pub is_method: bool,
}

impl PerlSub {
    /// Fully-qualified name `Package::sub` (the call path minus the OO arrow).
    pub fn qualified(&self) -> String {
        format!("{}::{}", self.package, self.name)
    }
}

#[derive(Debug, Error)]
pub enum PerlParseError {
    #[error("failed to load the Perl grammar")]
    Grammar,
    #[error("tree-sitter failed to parse the source")]
    Parse,
}

const MAX_DEPTH: usize = 250;

fn node_text<'a>(node: tree_sitter::Node<'_>, bytes: &'a [u8]) -> &'a str {
    node.utf8_text(bytes).unwrap_or("")
}

/// Parse all subroutine definitions from one Perl source file.
pub fn parse_perl_subs(source: &str) -> Result<Vec<PerlSub>, PerlParseError> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_perl::LANGUAGE.into())
        .map_err(|_| PerlParseError::Grammar)?;
    let tree = parser.parse(source, None).ok_or(PerlParseError::Parse)?;
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut package = String::from("main");
    collect(tree.root_node(), bytes, &mut package, 0, &mut out);
    Ok(out)
}

fn collect(
    node: tree_sitter::Node<'_>,
    bytes: &[u8],
    package: &mut String,
    depth: usize,
    out: &mut Vec<PerlSub>,
) {
    if depth > MAX_DEPTH {
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "package_statement" => {
                if let Some(name) = child.child_by_field_name("name").or_else(|| {
                    child
                        .children(&mut child.walk())
                        .find(|c| c.kind() == "package_name")
                }) {
                    let pkg = node_text(name, bytes).trim().to_owned();
                    if !pkg.is_empty() {
                        *package = pkg;
                    }
                }
            }
            "function_definition" => {
                if let Some(sub) = parse_sub(child, bytes, package) {
                    out.push(sub);
                }
            }
            // Recurse into any other container so subs nested in blocks are found.
            _ => {
                if child.child_count() > 0 {
                    collect(child, bytes, package, depth + 1, out);
                }
            }
        }
    }
}

fn parse_sub(func: tree_sitter::Node<'_>, bytes: &[u8], package: &str) -> Option<PerlSub> {
    let name_node = func
        .children(&mut func.walk())
        .find(|c| c.kind() == "identifier")?;
    let name = node_text(name_node, bytes).to_owned();
    if name.is_empty() {
        return None;
    }
    let line = func.start_position().row as u32 + 1;
    let is_private = name.starts_with('_');
    let is_method = body_binds_self(func, bytes);
    Some(PerlSub {
        name,
        line,
        package: package.to_owned(),
        is_private,
        is_method,
    })
}

/// Whether the sub's body unpacks `$self`/`$class` as the first `@_` element
/// (`my ($self, ...) = @_` or `my $self = shift`) — the Perl OO receiver idiom.
fn body_binds_self(func: tree_sitter::Node<'_>, bytes: &[u8]) -> bool {
    let Some(block) = func
        .children(&mut func.walk())
        .find(|c| c.kind() == "block")
    else {
        return false;
    };
    let mut cursor = block.walk();
    for stmt in block.children(&mut cursor).take(4) {
        let text = node_text(stmt, bytes);
        if !text.contains("my ") && !text.contains("my(") {
            continue;
        }
        if let Some(first) = first_my_scalar(stmt, bytes) {
            return first == "$self" || first == "$class";
        }
    }
    false
}

/// The first scalar bound by a `my` declaration within `node` (e.g. `$self` in
/// `my ($self, $data) = @_`).
fn first_my_scalar(node: tree_sitter::Node<'_>, bytes: &[u8]) -> Option<String> {
    if node.kind() == "variable_declaration" {
        return first_scalar(node, bytes);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(s) = first_my_scalar(child, bytes) {
            return Some(s);
        }
    }
    None
}

fn first_scalar(node: tree_sitter::Node<'_>, bytes: &[u8]) -> Option<String> {
    if node.kind() == "scalar_variable" {
        return Some(node_text(node, bytes).to_owned());
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(s) = first_scalar(child, bytes) {
            return Some(s);
        }
    }
    None
}

/// Count tree-sitter ERROR nodes — a coarse "how broken is this file" signal.
pub fn count_parse_errors(source: &str) -> usize {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_perl::LANGUAGE.into())
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
/// (magic values that gate `eq`/`==` comparisons). Mirrors the C/C++ lanes so the
/// Perl lane no longer fuzzes "cold". The tree is untrusted, so the walk is
/// depth-capped ([`DICT_MAX_DEPTH`]) to avoid stack overflow.
pub fn extract_perl_dictionary_tokens(source: &str) -> Result<Vec<String>, PerlParseError> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_perl::LANGUAGE.into())
        .map_err(|_| PerlParseError::Grammar)?;
    let tree = parser.parse(source, None).ok_or(PerlParseError::Parse)?;
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
/// matching layer of surrounding quotes, and raw-string `#` hashes from a
/// string-like literal, keeping the inner bytes verbatim (no unescaping). Rejects
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
        let toks =
            extract_perl_dictionary_tokens("my $x = \"MAGIC\"; if ($n == 4919) { print $x; }\n")
                .expect("parse");
        assert!(toks.contains(&"MAGIC".to_string()), "tokens: {toks:?}");
        assert!(toks.contains(&"4919".to_string()), "tokens: {toks:?}");
    }

    const SAMPLE: &str = "package My::Parser;\nuse strict;\nsub new { my $class = shift; return bless {}, $class; }\nsub parse_string {\n    my ($self, $data) = @_;\n    return length($data);\n}\nsub decode {\n    my $bytes = shift;\n    return $bytes;\n}\nsub _helper { return 1; }\n1;\n";

    #[test]
    fn extracts_subs_with_package_and_line() {
        let subs = parse_perl_subs(SAMPLE).unwrap();
        let names: Vec<&str> = subs.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"parse_string"));
        assert!(names.contains(&"decode"));
        let ps = subs.iter().find(|s| s.name == "parse_string").unwrap();
        assert_eq!(ps.package, "My::Parser");
        assert_eq!(ps.qualified(), "My::Parser::parse_string");
    }

    #[test]
    fn detects_oo_method_via_self_binding() {
        let subs = parse_perl_subs(SAMPLE).unwrap();
        let parse = subs.iter().find(|s| s.name == "parse_string").unwrap();
        assert!(parse.is_method, "parse_string binds $self -> method");
        let decode = subs.iter().find(|s| s.name == "decode").unwrap();
        assert!(
            !decode.is_method,
            "decode uses shift, not $self -> function"
        );
        let new = subs.iter().find(|s| s.name == "new").unwrap();
        assert!(new.is_method, "new binds $class -> method/ctor");
    }

    #[test]
    fn flags_private() {
        let subs = parse_perl_subs(SAMPLE).unwrap();
        assert!(
            subs.iter()
                .find(|s| s.name == "_helper")
                .unwrap()
                .is_private
        );
        assert!(!subs.iter().find(|s| s.name == "decode").unwrap().is_private);
    }

    #[test]
    fn counts_parse_errors() {
        assert_eq!(count_parse_errors("sub ok { 1 }\n"), 0);
    }
}
