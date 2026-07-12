// SPDX-License-Identifier: Apache-2.0

//! JavaScript / Node.js fuzzing lane (M3.7).
//!
//! Strategy (like the Python/Perl lanes): reuse govfuzz's builtin engine over the
//! framed fork-server protocol driving a warm Node process. An **exported** function
//! taking at least one argument is the fuzzable unit. The generated launcher execs
//! `node js_runtime/govfuzz_driver.js`, which `require`s the target module, calls the
//! function with the fuzz bytes decoded to a `Buffer` (or a UTF-8 `string`), records
//! real per-input V8 block coverage via the inspector Profiler folded into the shared
//! `GOVFUZZ_COV_SHM` edge bitmap, and reports an uncaught non-rejection exception as a
//! finding (exit 86) — no Jazzer.js, no jsfuzz, no libFuzzer.
//!
//! This module is the discovery/parser half; the build + launch half is
//! [`crate::auto::js_build`].

/// A discovered, exported JavaScript function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsFunction {
    /// Display + candidate name (the export path, e.g. `parse` or `default`).
    pub name: String,
    /// Dotted export path the driver resolves from `module.exports`
    /// (`""` = the module itself is the function, i.e. `module.exports = fn`).
    pub export_path: String,
    pub line: u32,
    /// How the fuzz bytes are handed to the first parameter.
    pub arg_kind: JsArgKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsArgKind {
    /// A `Buffer` over the fuzz bytes (default; preserves arbitrary bytes).
    Buffer,
    /// A UTF-8 `string` (chosen when the first parameter name reads text-like).
    Str,
}

impl JsArgKind {
    pub fn as_env(self) -> &'static str {
        match self {
            JsArgKind::Buffer => "buffer",
            JsArgKind::Str => "string",
        }
    }
}

/// Infer the argument kind from the first parameter's name: a text-like name
/// (`str`, `text`, `source`, `input`, `code`, `json`, `xml`, `html`, `url`, `s`)
/// gets a `string`; a byte-like name (`buf`, `bytes`, `data`, `chunk`, `payload`,
/// `raw`) or anything else gets a `Buffer` (the safe default — a `Buffer` also
/// round-trips through a `String()`/`.toString()` a text parser may call).
fn infer_arg_kind(first_param: &str) -> JsArgKind {
    let p = first_param.to_ascii_lowercase();
    let text_like = [
        "str", "string", "text", "source", "src", "input", "code", "json", "xml", "html", "yaml",
        "url", "uri", "path", "line", "content", "s",
    ];
    let byte_like = [
        "buf", "buffer", "bytes", "data", "chunk", "payload", "raw", "blob",
    ];
    if byte_like.iter().any(|b| p == *b || p.starts_with(b)) {
        return JsArgKind::Buffer;
    }
    if text_like.iter().any(|t| p == *t || p.contains(t)) {
        return JsArgKind::Str;
    }
    JsArgKind::Buffer
}

/// Strip JS comments (`//`, `/* */`) and collapse string/template/regex literals so
/// braces/keywords inside them don't confuse the scanner. One line out per line in.
fn normalize(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_block = false;
    for raw in source.lines() {
        let bytes = raw.as_bytes();
        let mut line = String::with_capacity(raw.len());
        let mut i = 0;
        let mut in_str: Option<u8> = None;
        while i < bytes.len() {
            let c = bytes[i];
            if in_block {
                if c == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    in_block = false;
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            if let Some(q) = in_str {
                if c == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if c == q {
                    in_str = None;
                }
                i += 1;
                continue;
            }
            if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                break;
            }
            if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                in_block = true;
                i += 2;
                continue;
            }
            if c == b'"' || c == b'\'' || c == b'`' {
                in_str = Some(c);
                line.push(c as char);
                i += 1;
                continue;
            }
            line.push(c as char);
            i += 1;
        }
        out.push(line);
    }
    out
}

/// A top-level function/arrow declaration: `name -> (params, line)`.
#[derive(Clone)]
struct Decl {
    params: Vec<String>,
    line: u32,
}

fn is_ident(s: &str) -> bool {
    let mut ch = s.chars();
    match ch.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {}
        _ => return false,
    }
    ch.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// The parameter names in a `(...)` list starting at `s` (which begins with `(`).
fn parse_param_names(s: &str) -> Vec<String> {
    let inner = match balanced(s) {
        Some(v) => v,
        None => return Vec::new(),
    };
    inner
        .split(',')
        .filter_map(|p| {
            // Drop defaults / destructuring markers; take the leading identifier.
            let p = p.trim().trim_start_matches("...");
            let name: String = p
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
                .collect();
            (!name.is_empty()).then_some(name)
        })
        .collect()
}

/// The content of a balanced `(...)` starting at the first `(` of `s`.
fn balanced(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let start = s.find('(')?;
    let mut depth = 0i32;
    for (i, &c) in b.iter().enumerate().skip(start) {
        match c {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(s[start + 1..i].to_owned());
                }
            }
            _ => {}
        }
    }
    None
}

/// Extract a `function NAME(...)` / `const NAME = (...) =>` / `NAME = function(...)`
/// declaration on this line: `(name, params)`.
fn parse_decl_line(line: &str) -> Option<(String, Vec<String>)> {
    let t = line.trim();
    // `function NAME(...)` (optionally `async`).
    if let Some(rest) = t
        .strip_prefix("function ")
        .or_else(|| t.strip_prefix("async function "))
    {
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
            .collect();
        if is_ident(&name) {
            if let Some(paren) = rest.find('(') {
                return Some((name, parse_param_names(&rest[paren..])));
            }
        }
    }
    // `const/let/var NAME = (...) =>` or `= function(...)`.
    for kw in ["const ", "let ", "var "] {
        if let Some(rest) = t.strip_prefix(kw) {
            if let Some((name, params)) = parse_assignment(rest) {
                return Some((name, params));
            }
        }
    }
    // Bare `NAME = function(...)` / `NAME = (...) =>` (no declaration keyword).
    parse_assignment(t)
}

/// `NAME = <function-expr>` → `(name, params)` if the RHS is a function/arrow.
fn parse_assignment(rest: &str) -> Option<(String, Vec<String>)> {
    let eq = rest.find('=')?;
    let name = rest[..eq].trim().to_owned();
    if !is_ident(&name) {
        return None;
    }
    let rhs = rest[eq + 1..].trim();
    function_params(rhs).map(|p| (name, p))
}

/// If `rhs` is a function/arrow expression, return its parameter names.
fn function_params(rhs: &str) -> Option<Vec<String>> {
    let rhs = rhs.trim();
    if let Some(after) = rhs
        .strip_prefix("function")
        .or_else(|| rhs.strip_prefix("async function"))
    {
        // `function [name](...)`
        let after = after.trim_start();
        let paren = after.find('(')?;
        return Some(parse_param_names(&after[paren..]));
    }
    let arrow = rhs.strip_prefix("async ").unwrap_or(rhs).trim_start();
    // Arrow: `(...) =>` or `x =>`.
    if arrow.starts_with('(') {
        // Must actually be an arrow (contain `=>` after the params).
        if let Some(inner) = balanced(arrow) {
            let after_paren = &arrow[arrow.find(')').map(|i| i + 1).unwrap_or(arrow.len())..];
            if after_paren.trim_start().starts_with("=>") {
                return Some(
                    inner
                        .split(',')
                        .filter_map(|p| {
                            let n: String = p
                                .trim()
                                .trim_start_matches("...")
                                .chars()
                                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
                                .collect();
                            (!n.is_empty()).then_some(n)
                        })
                        .collect(),
                );
            }
        }
        return None;
    }
    // `single =>` single-identifier arrow.
    let name: String = arrow
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
        .collect();
    if !name.is_empty() {
        let after = &arrow[name.len()..];
        if after.trim_start().starts_with("=>") {
            return Some(vec![name]);
        }
    }
    None
}

/// Scan JS source for exported, fuzzable functions.
pub fn parse_js(source: &str) -> Vec<JsFunction> {
    let lines = normalize(source);
    // Pass 1: collect top-level declarations (name -> params, line).
    let mut decls: std::collections::HashMap<String, Decl> = std::collections::HashMap::new();
    for (idx, line) in lines.iter().enumerate() {
        if let Some((name, params)) = parse_decl_line(line) {
            decls.entry(name).or_insert(Decl {
                params,
                line: (idx + 1) as u32,
            });
        }
    }

    let mut out: Vec<JsFunction> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut push = |name: String, export_path: String, params: &[String], line: u32| {
        if params.is_empty() || !seen.insert(export_path.clone()) {
            return;
        }
        out.push(JsFunction {
            name,
            export_path,
            line,
            arg_kind: infer_arg_kind(&params[0]),
        });
    };

    for (idx, line) in lines.iter().enumerate() {
        let t = line.trim();
        let line_no = (idx + 1) as u32;

        // ESM: `export function NAME(...)` / `export async function NAME(...)`.
        if let Some(rest) = t
            .strip_prefix("export function ")
            .or_else(|| t.strip_prefix("export async function "))
        {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
                .collect();
            if is_ident(&name) {
                if let Some(paren) = rest.find('(') {
                    let params = parse_param_names(&rest[paren..]);
                    push(name.clone(), name, &params, line_no);
                }
            }
            continue;
        }
        // ESM: `export const NAME = (...) =>` / `= function(...)`.
        if let Some(rest) = t
            .strip_prefix("export const ")
            .or_else(|| t.strip_prefix("export let "))
            .or_else(|| t.strip_prefix("export var "))
        {
            if let Some((name, params)) = parse_assignment(rest) {
                push(name.clone(), name, &params, line_no);
            }
            continue;
        }
        // ESM default: `export default function [NAME](...)`.
        if let Some(rest) = t.strip_prefix("export default ") {
            if let Some(params) = function_params(rest) {
                push("default".to_owned(), "default".to_owned(), &params, line_no);
            }
            continue;
        }

        // CommonJS: `exports.NAME = ...` / `module.exports.NAME = ...`.
        for prefix in ["exports.", "module.exports."] {
            if let Some(rest) = t.strip_prefix(prefix) {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
                    .collect();
                if !is_ident(&name) {
                    continue;
                }
                let after = rest[name.len()..].trim_start();
                if let Some(rhs) = after.strip_prefix('=') {
                    let rhs = rhs.trim();
                    if let Some(params) = function_params(rhs) {
                        // Inline function expression.
                        push(name.clone(), name, &params, line_no);
                    } else if let Some(decl) = decls.get(rhs.trim_end_matches(';').trim()) {
                        // `exports.NAME = someTopLevelFn`.
                        let (p, l) = (decl.params.clone(), decl.line);
                        push(name.clone(), name, &p, l);
                    }
                }
            }
        }

        // CommonJS default: `module.exports = function(...)` / `= (...) =>`.
        if let Some(rhs) = t
            .strip_prefix("module.exports =")
            .or_else(|| t.strip_prefix("module.exports="))
        {
            let rhs = rhs.trim();
            if let Some(params) = function_params(rhs) {
                push("default".to_owned(), String::new(), &params, line_no);
            } else if rhs.starts_with('{') {
                // `module.exports = { a, b, c }` — resolve each name to a decl.
                if let Some(names) = brace_names(&lines, idx) {
                    for name in names {
                        if let Some(decl) = decls.get(&name) {
                            let (p, l) = (decl.params.clone(), decl.line);
                            push(name.clone(), name, &p, l);
                        }
                    }
                }
            } else if let Some(decl) = decls.get(rhs.trim_end_matches(';').trim()) {
                let (p, l) = (decl.params.clone(), decl.line);
                push("default".to_owned(), String::new(), &p, l);
            }
        }
    }
    out
}

/// Collect the bare identifier keys of a `module.exports = { ... }` object literal
/// spanning one or more lines from `start`. Handles `{ a, b, foo: bar }` (takes the
/// KEY for `key: value`, and the value name for shorthand).
fn brace_names(lines: &[String], start: usize) -> Option<Vec<String>> {
    let mut collected = String::new();
    let mut depth = 0i32;
    let mut started = false;
    for line in lines.iter().skip(start) {
        for c in line.chars() {
            match c {
                '{' => {
                    depth += 1;
                    started = true;
                }
                '}' => {
                    depth -= 1;
                    if started && depth == 0 {
                        return Some(parse_object_keys(&collected));
                    }
                }
                _ if started && depth >= 1 => collected.push(c),
                _ => {}
            }
        }
        collected.push(' ');
    }
    None
}

fn parse_object_keys(inner: &str) -> Vec<String> {
    inner
        .split(',')
        .filter_map(|entry| {
            // `key: value` -> the value is the referenced function; `name` -> shorthand.
            let name = match entry.split_once(':') {
                Some((_k, v)) => v.trim(),
                None => entry.trim(),
            };
            let id: String = name
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
                .collect();
            is_ident(&id).then_some(id)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commonjs_object_export() {
        let src = "\
function parse(input) { return input.length; }
function helper(x) { return x; }
module.exports = { parse, helper };
";
        let fns = parse_js(src);
        let names: Vec<&str> = fns.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"parse"));
        assert!(names.contains(&"helper"));
        let parse = fns.iter().find(|f| f.name == "parse").unwrap();
        assert_eq!(parse.export_path, "parse");
        assert_eq!(parse.arg_kind, JsArgKind::Str); // "input" is text-like
    }

    #[test]
    fn commonjs_exports_dot_inline() {
        let src = "exports.decode = function(buf) { return buf.length; };\n";
        let fns = parse_js(src);
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].name, "decode");
        assert_eq!(fns[0].arg_kind, JsArgKind::Buffer); // "buf" is byte-like
    }

    #[test]
    fn commonjs_default_function() {
        let src = "module.exports = function(data) { return data; };\n";
        let fns = parse_js(src);
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].export_path, ""); // module itself is the function
        assert_eq!(fns[0].arg_kind, JsArgKind::Buffer);
    }

    #[test]
    fn esm_named_and_arrow() {
        let src = "\
export function parseXml(source) { return source; }
export const toJson = (text) => text;
";
        let fns = parse_js(src);
        assert_eq!(fns.len(), 2);
        assert_eq!(fns[0].name, "parseXml");
        assert_eq!(fns[0].arg_kind, JsArgKind::Str);
        assert_eq!(fns[1].name, "toJson");
    }

    #[test]
    fn no_arg_function_not_fuzzable() {
        let src = "module.exports = { version };\nfunction version() { return '1.0'; }\n";
        let fns = parse_js(src);
        assert!(fns.is_empty()); // zero params -> no input channel
    }

    #[test]
    fn exports_dot_reference_to_decl() {
        let src = "\
function tokenize(str) { return str.split(' '); }
exports.tokenize = tokenize;
";
        let fns = parse_js(src);
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].name, "tokenize");
        assert_eq!(fns[0].line, 1); // resolves to the declaration line
    }

    #[test]
    fn arg_kind_inference() {
        assert_eq!(infer_arg_kind("buf"), JsArgKind::Buffer);
        assert_eq!(infer_arg_kind("bytes"), JsArgKind::Buffer);
        assert_eq!(infer_arg_kind("source"), JsArgKind::Str);
        assert_eq!(infer_arg_kind("html"), JsArgKind::Str);
        assert_eq!(infer_arg_kind("x"), JsArgKind::Buffer); // unknown -> Buffer default
    }
}
