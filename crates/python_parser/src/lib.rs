// SPDX-License-Identifier: Apache-2.0

//! Structural parser for the native Python fuzzing lane (M3.1).
//!
//! Mirrors `rust_parser`/`java_parser`: a thin tree-sitter walk that extracts the
//! function shapes the ranker (`target_rank::python_rank`) needs to score
//! discovery candidates — name, line, parameters (binding + annotation),
//! decorators, return annotation, whether the function is a module-level `def`
//! or a method, and the owning class. It reasons over the signature only; it does
//! not resolve types or build a semantic model.
//!
//! Python is dynamically typed, so the ranker leans on parameter *names* and
//! optional annotations (`bytes`, `str`, `bytearray`, `data`, `buf`, ...) rather
//! than a static type, exactly as the C ranker leans on `const char *` + naming.

use thiserror::Error;

/// One parameter of a Python function: the binding name and its optional
/// annotation spelling (`data: bytes` -> name `data`, annotation `bytes`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PyParam {
    pub name: String,
    /// Raw annotation spelling (whitespace-collapsed), or `None` when unannotated.
    pub annotation: Option<String>,
    /// `*args` / `**kwargs` style variadic — the harness cannot synthesize these
    /// positionally, so the ranker/generator treats a trailing varargs as "no
    /// more decodable params".
    pub is_varargs: bool,
    /// Has a default value (`x=...`); the harness may omit it.
    pub has_default: bool,
}

/// A Python function: a module-level `def`, or a method inside a class.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PyFunction {
    pub name: String,
    /// 1-based line of the `def` keyword.
    pub line: u32,
    /// Parameters, excluding an implicit `self`/`cls` receiver (those are recorded
    /// via `is_method`/`is_classmethod`/`is_staticmethod`).
    pub params: Vec<PyParam>,
    /// Decorator names as written (`staticmethod`, `property`, `app.route`, ...).
    pub decorators: Vec<String>,
    /// Raw return-annotation spelling (after `->`), or `None`.
    pub return_annotation: Option<String>,
    /// `true` when defined inside a `class` body.
    pub is_method: bool,
    /// Owning class name when `is_method`, else `None`.
    pub class_name: Option<String>,
    /// `@staticmethod` — callable without an instance, no `self`.
    pub is_staticmethod: bool,
    /// `@classmethod` — receives `cls`.
    pub is_classmethod: bool,
    /// `@property` — an attribute accessor, not a normal call target.
    pub is_property: bool,
    /// `async def`.
    pub is_async: bool,
    /// Leading-underscore name (`_helper`, `__mangled`) — private by convention.
    /// Dunder methods (`__init__`, `__eq__`) are NOT flagged private here; the
    /// ranker handles them separately (a constructor is reachable, `__eq__` noise).
    pub is_private: bool,
    /// `true` for `__dunder__` names (e.g. `__init__`, `__call__`).
    pub is_dunder: bool,
}

impl PyFunction {
    /// Dotted call path for reporting/harnessing: `module.Class.method` minus the
    /// module (the discovery layer adds the module). `Class.method` or `func`.
    pub fn qualified(&self) -> String {
        match &self.class_name {
            Some(c) => format!("{c}.{}", self.name),
            None => self.name.clone(),
        }
    }
}

#[derive(Debug, Error)]
pub enum PyParseError {
    #[error("failed to load the Python grammar")]
    Grammar,
    #[error("tree-sitter failed to parse the source")]
    Parse,
}

/// Hard cap on recursive AST-walk depth (matches the other parsers' safety bound).
const MAX_DEPTH: usize = 250;

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn node_text<'a>(node: tree_sitter::Node<'_>, bytes: &'a [u8]) -> &'a str {
    node.utf8_text(bytes).unwrap_or("")
}

/// Parse all module-level functions and class methods from one Python source file.
pub fn parse_python_functions(source: &str) -> Result<Vec<PyFunction>, PyParseError> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .map_err(|_| PyParseError::Grammar)?;
    let tree = parser.parse(source, None).ok_or(PyParseError::Parse)?;
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    collect(tree.root_node(), bytes, None, 0, &mut out);
    Ok(out)
}

fn collect(
    node: tree_sitter::Node<'_>,
    bytes: &[u8],
    class_name: Option<&str>,
    depth: usize,
    out: &mut Vec<PyFunction>,
) {
    if depth > MAX_DEPTH {
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_definition" => {
                if let Some(f) = parse_function(child, bytes, class_name, &[]) {
                    out.push(f);
                }
                // Nested functions/classes inside a body are out of scope as harness
                // targets (closures over locals), so we don't descend into the body.
            }
            "decorated_definition" => {
                let decorators = collect_decorators(child, bytes);
                // The wrapped definition is the last named child.
                if let Some(def) = child.child_by_field_name("definition") {
                    match def.kind() {
                        "function_definition" => {
                            if let Some(f) = parse_function(def, bytes, class_name, &decorators) {
                                out.push(f);
                            }
                        }
                        "class_definition" => {
                            descend_class(def, bytes, depth, out);
                        }
                        _ => {}
                    }
                }
            }
            "class_definition" => {
                descend_class(child, bytes, depth, out);
            }
            // Recurse into compound statements that can hold top-level defs
            // (if/try blocks guarding platform-specific defs), but not function
            // bodies.
            "if_statement" | "try_statement" | "else_clause" | "elif_clause" | "except_clause"
            | "finally_clause" | "block" | "with_statement" => {
                collect(child, bytes, class_name, depth + 1, out);
            }
            _ => {}
        }
    }
}

fn descend_class(
    class_node: tree_sitter::Node<'_>,
    bytes: &[u8],
    depth: usize,
    out: &mut Vec<PyFunction>,
) {
    let name = class_node
        .child_by_field_name("name")
        .map(|n| node_text(n, bytes).to_owned());
    if let Some(body) = class_node.child_by_field_name("body") {
        collect(body, bytes, name.as_deref(), depth + 1, out);
    }
}

fn collect_decorators(decorated: tree_sitter::Node<'_>, bytes: &[u8]) -> Vec<String> {
    let mut decs = Vec::new();
    let mut cursor = decorated.walk();
    for child in decorated.children(&mut cursor) {
        if child.kind() == "decorator" {
            // A decorator node is `@ <expression>`; take the expression text.
            let txt = node_text(child, bytes).trim_start_matches('@').trim();
            // Reduce a call like `app.route("/x")` to `app.route`.
            let head = txt.split('(').next().unwrap_or(txt).trim();
            decs.push(head.to_owned());
        }
    }
    decs
}

fn parse_function(
    func: tree_sitter::Node<'_>,
    bytes: &[u8],
    class_name: Option<&str>,
    decorators: &[String],
) -> Option<PyFunction> {
    let name_node = func.child_by_field_name("name")?;
    let name = node_text(name_node, bytes).to_owned();
    let line = func.start_position().row as u32 + 1;
    let is_async = func
        .children(&mut func.walk())
        .any(|c| c.kind() == "async" || node_text(c, bytes) == "async");

    let is_staticmethod = decorators.iter().any(|d| d == "staticmethod");
    let is_classmethod = decorators.iter().any(|d| d == "classmethod");
    let is_property = decorators
        .iter()
        .any(|d| d == "property" || d.ends_with(".setter") || d.ends_with(".getter"));

    let mut params = Vec::new();
    if let Some(plist) = func.child_by_field_name("parameters") {
        let mut first = true;
        let mut cursor = plist.walk();
        for p in plist.children(&mut cursor) {
            // Drop the implicit receiver for instance/class methods.
            if first && class_name.is_some() && !is_staticmethod && matches!(p.kind(), "identifier")
            {
                let txt = node_text(p, bytes);
                if txt == "self" || txt == "cls" {
                    first = false;
                    continue;
                }
            }
            if let Some(param) = parse_param(p, bytes) {
                params.push(param);
                first = false;
            }
        }
    }

    let return_annotation = func
        .child_by_field_name("return_type")
        .map(|n| collapse_ws(node_text(n, bytes)));

    let is_dunder = name.starts_with("__") && name.ends_with("__");
    let is_private = name.starts_with('_') && !is_dunder;

    Some(PyFunction {
        name,
        line,
        params,
        decorators: decorators.to_vec(),
        return_annotation,
        is_method: class_name.is_some(),
        class_name: class_name.map(str::to_owned),
        is_staticmethod,
        is_classmethod,
        is_property,
        is_async,
        is_private,
        is_dunder,
    })
}

fn parse_param(node: tree_sitter::Node<'_>, bytes: &[u8]) -> Option<PyParam> {
    match node.kind() {
        "identifier" => Some(PyParam {
            name: node_text(node, bytes).to_owned(),
            annotation: None,
            is_varargs: false,
            has_default: false,
        }),
        "typed_parameter" => {
            // `name : type` — first identifier child is the name, `type` field is the annotation.
            let name = node
                .children(&mut node.walk())
                .find(|c| c.kind() == "identifier")
                .map(|c| node_text(c, bytes).to_owned())?;
            let annotation = node
                .child_by_field_name("type")
                .map(|t| collapse_ws(node_text(t, bytes)));
            Some(PyParam {
                name,
                annotation,
                is_varargs: false,
                has_default: false,
            })
        }
        "default_parameter" => {
            let name = node
                .child_by_field_name("name")
                .map(|c| node_text(c, bytes).to_owned())
                .or_else(|| {
                    node.children(&mut node.walk())
                        .find(|c| c.kind() == "identifier")
                        .map(|c| node_text(c, bytes).to_owned())
                })?;
            Some(PyParam {
                name,
                annotation: None,
                is_varargs: false,
                has_default: true,
            })
        }
        "typed_default_parameter" => {
            let name = node
                .child_by_field_name("name")
                .map(|c| node_text(c, bytes).to_owned())
                .or_else(|| {
                    node.children(&mut node.walk())
                        .find(|c| c.kind() == "identifier")
                        .map(|c| node_text(c, bytes).to_owned())
                })?;
            let annotation = node
                .child_by_field_name("type")
                .map(|t| collapse_ws(node_text(t, bytes)));
            Some(PyParam {
                name,
                annotation,
                is_varargs: false,
                has_default: true,
            })
        }
        "list_splat_pattern" | "dictionary_splat_pattern" => {
            let name = node
                .children(&mut node.walk())
                .find(|c| c.kind() == "identifier")
                .map(|c| node_text(c, bytes).to_owned())
                .unwrap_or_default();
            Some(PyParam {
                name,
                annotation: None,
                is_varargs: true,
                has_default: false,
            })
        }
        // `*` / `/` separators and keyword-only markers carry no binding.
        _ => None,
    }
}

/// Count tree-sitter ERROR nodes — a coarse "how broken is this file" signal,
/// mirroring the other parsers' `count_parse_errors`.
pub fn count_parse_errors(source: &str) -> usize {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
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

/// M22: a tolerant, line-based extractor for **Python 2** source.
///
/// The bundled tree-sitter-python grammar is Python 3 only, so a Python 2 file
/// (a `print` statement, `except E, e:`, `exec` statement, `<>`) fails to parse
/// and its functions are never discovered. This fallback finds `def`/`class`
/// declarations directly so legacy Python 2 targets are still ranked, harnessed,
/// or — when no `python2` interpreter is available — reported on (discover +
/// SBOM + static findings). It is deliberately approximate: it only needs enough
/// signature shape (name, line, params, class membership, privacy) to rank and
/// drive a target, not a full parse.
pub fn parse_python2_functions(source: &str) -> Vec<PyFunction> {
    let lines: Vec<&str> = source.lines().collect();
    let mut out = Vec::new();
    // Stack of (indent, class_name) for the enclosing `class` scopes.
    let mut class_stack: Vec<(usize, String)> = Vec::new();
    let mut decorators: Vec<String> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let raw = lines[i];
        let trimmed = raw.trim_start();
        let indent = raw.len() - trimmed.len();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            i += 1;
            continue;
        }
        // Pop class scopes we have dedented out of.
        while let Some((cindent, _)) = class_stack.last() {
            if indent <= *cindent {
                class_stack.pop();
            } else {
                break;
            }
        }
        if let Some(rest) = trimmed.strip_prefix('@') {
            // Decorator name = the dotted identifier head (strip any call args).
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
                .collect();
            if !name.is_empty() {
                decorators.push(name);
            }
            i += 1;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("class ") {
            let cname: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !cname.is_empty() {
                class_stack.push((indent, cname));
            }
            decorators.clear();
            i += 1;
            continue;
        }
        let is_def = trimmed.starts_with("def ") || trimmed.starts_with("async def ");
        if is_def {
            // Accumulate the header across line continuations until the param
            // list's closing paren (Python 2 has no return annotation to skip).
            let (header, consumed) = join_def_header(&lines, i);
            let line_no = (i + 1) as u32;
            if let Some(func) = parse_def_header(&header, line_no, &class_stack, &decorators) {
                out.push(func);
            }
            decorators.clear();
            i += consumed;
            continue;
        }
        // Any other statement at this indent clears pending decorators.
        decorators.clear();
        i += 1;
    }
    out
}

/// Join a `def` header that wraps across lines (a multi-line parameter list)
/// into one string, returning `(header, lines_consumed)`.
fn join_def_header(lines: &[&str], start: usize) -> (String, usize) {
    let mut depth: i32 = 0;
    let mut seen_open = false;
    let mut header = String::new();
    let mut count = 0;
    for line in &lines[start..] {
        header.push_str(line);
        header.push(' ');
        count += 1;
        for ch in line.chars() {
            match ch {
                '(' => {
                    depth += 1;
                    seen_open = true;
                }
                ')' => depth -= 1,
                _ => {}
            }
        }
        if seen_open && depth <= 0 {
            break;
        }
        if count > 50 {
            break; // pathological; bail out
        }
    }
    (header, count.max(1))
}

/// Parse a (possibly joined) `def` header into a [`PyFunction`].
fn parse_def_header(
    header: &str,
    line: u32,
    class_stack: &[(usize, String)],
    decorators: &[String],
) -> Option<PyFunction> {
    let after_def = header
        .trim_start()
        .strip_prefix("async def ")
        .map(|s| (true, s))
        .or_else(|| header.trim_start().strip_prefix("def ").map(|s| (false, s)))?;
    let (is_async, rest) = after_def;
    let name: String = rest
        .trim_start()
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        return None;
    }
    let open = rest.find('(')?;
    let close = matching_paren(&rest[open..])? + open;
    let param_src = &rest[open + 1..close];
    let mut params = Vec::new();
    let mut had_receiver = false;
    for (idx, raw) in split_top_level(param_src).into_iter().enumerate() {
        let p = raw.trim();
        if p.is_empty() {
            continue;
        }
        // Drop an implicit self/cls receiver (first positional in a method).
        if idx == 0 && (p == "self" || p == "cls") {
            had_receiver = true;
            continue;
        }
        let is_varargs = p.starts_with('*');
        let pname: String = p
            .trim_start_matches('*')
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if pname.is_empty() {
            continue;
        }
        let has_default = p.contains('=');
        let annotation = p
            .split_once(':')
            .map(|(_, a)| a.split('=').next().unwrap_or("").trim().to_owned())
            .filter(|a| !a.is_empty());
        params.push(PyParam {
            name: pname,
            annotation,
            is_varargs,
            has_default,
        });
    }
    let class_name = class_stack.last().map(|(_, c)| c.clone());
    let is_method = class_name.is_some();
    let dec_has = |d: &str| decorators.iter().any(|x| x == d);
    let is_staticmethod = dec_has("staticmethod");
    let is_classmethod = dec_has("classmethod");
    // A method whose first param was self/cls is a normal/class method; a method
    // with neither and no decorator is treated as static-callable.
    let is_staticmethod = is_staticmethod || (is_method && !had_receiver && !is_classmethod);
    let is_dunder = name.starts_with("__") && name.ends_with("__");
    let is_private = name.starts_with('_') && !is_dunder;
    Some(PyFunction {
        name,
        line,
        params,
        decorators: decorators.to_vec(),
        return_annotation: None,
        is_method,
        class_name,
        is_staticmethod,
        is_classmethod,
        is_property: dec_has("property"),
        is_async,
        is_private,
        is_dunder,
    })
}

/// Index of the `)` matching the leading `(` in `s` (which must start with `(`).
fn matching_paren(s: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (i, ch) in s.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Split a parameter list on top-level commas (ignoring commas nested in
/// brackets/parens/braces, e.g. a `Dict[str, int]` annotation or a default
/// `={'a': 1}`).
fn split_top_level(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for ch in s.chars() {
        match ch {
            '(' | '[' | '{' => {
                depth += 1;
                cur.push(ch);
            }
            ')' | ']' | '}' => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if depth == 0 => {
                parts.push(std::mem::take(&mut cur));
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        parts.push(cur);
    }
    parts
}

/// Mine string- and number-like source literals into fuzzing-dictionary tokens
/// (magic values that gate `==`/comparison guards). Mirrors the C/C++ lanes so
/// the Python lane no longer fuzzes "cold". The tree is untrusted, so the walk is
/// depth-capped ([`DICT_MAX_DEPTH`]) to avoid stack overflow.
pub fn extract_python_dictionary_tokens(source: &str) -> Result<Vec<String>, PyParseError> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .map_err(|_| PyParseError::Grammar)?;
    let tree = parser.parse(source, None).ok_or(PyParseError::Parse)?;
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
        let toks = extract_python_dictionary_tokens("x = \"MAGIC\"\nif n == 4919:\n    y = x\n")
            .expect("parse");
        assert!(toks.contains(&"MAGIC".to_string()), "tokens: {toks:?}");
        assert!(toks.contains(&"4919".to_string()), "tokens: {toks:?}");
    }

    #[test]
    fn parses_module_level_function_with_annotations() {
        let src = "def parse(data: bytes, limit: int = 0) -> dict:\n    return {}\n";
        let fns = parse_python_functions(src).unwrap();
        assert_eq!(fns.len(), 1);
        let f = &fns[0];
        assert_eq!(f.name, "parse");
        assert_eq!(f.line, 1);
        assert!(!f.is_method);
        assert_eq!(f.params.len(), 2);
        assert_eq!(f.params[0].name, "data");
        assert_eq!(f.params[0].annotation.as_deref(), Some("bytes"));
        assert!(f.params[1].has_default);
        assert_eq!(f.return_annotation.as_deref(), Some("dict"));
    }

    #[test]
    fn drops_self_receiver_and_records_class() {
        let src = "class Decoder:\n    def feed(self, chunk: bytes):\n        pass\n";
        let fns = parse_python_functions(src).unwrap();
        assert_eq!(fns.len(), 1);
        let f = &fns[0];
        assert!(f.is_method);
        assert_eq!(f.class_name.as_deref(), Some("Decoder"));
        assert_eq!(f.params.len(), 1, "self should be dropped");
        assert_eq!(f.params[0].name, "chunk");
    }

    #[test]
    fn recognizes_decorators_static_class_property() {
        let src = "class A:\n    @staticmethod\n    def s(x): pass\n    @classmethod\n    def c(cls, y): pass\n    @property\n    def p(self): return 1\n";
        let fns = parse_python_functions(src).unwrap();
        let s = fns.iter().find(|f| f.name == "s").unwrap();
        assert!(s.is_staticmethod);
        assert_eq!(s.params.len(), 1, "staticmethod keeps its first param");
        let c = fns.iter().find(|f| f.name == "c").unwrap();
        assert!(c.is_classmethod);
        assert_eq!(c.params.len(), 1, "cls dropped");
        let p = fns.iter().find(|f| f.name == "p").unwrap();
        assert!(p.is_property);
    }

    #[test]
    fn flags_private_and_dunder() {
        let src = "def _helper(): pass\ndef __init_subclass__(): pass\ndef public(): pass\n";
        let fns = parse_python_functions(src).unwrap();
        assert!(fns.iter().find(|f| f.name == "_helper").unwrap().is_private);
        assert!(
            fns.iter()
                .find(|f| f.name == "__init_subclass__")
                .unwrap()
                .is_dunder
        );
        let pubf = fns.iter().find(|f| f.name == "public").unwrap();
        assert!(!pubf.is_private && !pubf.is_dunder);
    }

    #[test]
    fn varargs_flagged() {
        let src = "def f(a, *args, **kwargs): pass\n";
        let fns = parse_python_functions(src).unwrap();
        let f = &fns[0];
        assert!(f.params.iter().any(|p| p.is_varargs));
        assert_eq!(f.params[0].name, "a");
    }

    #[test]
    fn async_def_and_qualified() {
        let src = "class C:\n    async def handle(self, body: str): pass\n";
        let fns = parse_python_functions(src).unwrap();
        let f = &fns[0];
        assert!(f.is_async);
        assert_eq!(f.qualified(), "C.handle");
    }

    #[test]
    fn counts_parse_errors() {
        assert_eq!(count_parse_errors("def ok(): pass\n"), 0);
        assert!(count_parse_errors("def broken(:\n") > 0);
    }

    #[test]
    fn python2_print_statement_file_tolerant_extracts() {
        // A genuine Python 2 file: print statement + except-comma. The tolerant
        // extractor finds the function regardless of how the py3 grammar fares.
        let src = "def parse(data):\n    print 'parsing', data\n    try:\n        return int(data)\n    except ValueError, e:\n        return None\n";
        let fns = parse_python2_functions(src);
        assert_eq!(fns.len(), 1);
        let f = &fns[0];
        assert_eq!(f.name, "parse");
        assert_eq!(f.line, 1);
        assert!(!f.is_method);
        assert_eq!(f.params.len(), 1);
        assert_eq!(f.params[0].name, "data");
    }

    #[test]
    fn python2_tolerant_records_methods_defaults_varargs_and_privacy() {
        let src = "\
class OldStyle:
    def __init__(self, name):
        self.name = name

    def decode(self, data, encoding='utf-8', *extra):
        print data
        return data

    def _helper(self):
        pass

def free_fn(a, b):
    return a + b
";
        let fns = parse_python2_functions(src);
        let by = |n: &str| fns.iter().find(|f| f.name == n).expect(n);

        let init = by("__init__");
        assert!(init.is_method && init.is_dunder);
        assert_eq!(init.class_name.as_deref(), Some("OldStyle"));
        assert_eq!(init.params.len(), 1); // self dropped
        assert_eq!(init.params[0].name, "name");

        let decode = by("decode");
        assert!(decode.is_method);
        assert_eq!(decode.params.len(), 3); // self dropped; data, encoding, *extra
        assert!(decode.params[1].has_default);
        assert!(decode.params[2].is_varargs);

        assert!(by("_helper").is_private);

        let free = by("free_fn");
        assert!(!free.is_method);
        assert!(free.class_name.is_none());
        assert_eq!(free.params.len(), 2);
    }

    #[test]
    fn python2_tolerant_handles_multiline_def_header() {
        let src = "def configure(\n    host,\n    port=8080,\n    timeout=30,\n):\n    pass\n";
        let fns = parse_python2_functions(src);
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].name, "configure");
        assert_eq!(fns[0].params.len(), 3);
        assert!(fns[0].params[1].has_default);
    }
}
