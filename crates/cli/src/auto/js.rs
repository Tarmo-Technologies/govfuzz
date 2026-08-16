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
    /// A temporary file containing the fuzz bytes. Selected for path/file-name
    /// parameters so file parsers receive content, not an arbitrary nonexistent
    /// filename.
    FilePath,
}

impl JsArgKind {
    pub fn as_env(self) -> &'static str {
        match self {
            JsArgKind::Buffer => "buffer",
            JsArgKind::Str => "string",
            JsArgKind::FilePath => "path",
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
    if ["path", "filepath", "file_path", "filename", "file_name"]
        .iter()
        .any(|name| p == *name || p.ends_with(name))
    {
        return JsArgKind::FilePath;
    }
    let text_like = [
        "str", "string", "text", "source", "src", "input", "code", "json", "xml", "html", "yaml",
        "url", "uri", "line", "content", "s",
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

/// Whether the first parameter's name marks the function as NOT a string/bytes
/// input channel — an internal helper taking an array, options object, callback,
/// or regexp. Fuzzing such a function with a `Buffer`/`string` only produces
/// our-fault `TypeError`s (e.g. validator.js's `multilineRegexp(parts)`), so it is
/// not discovered. Names that are plausibly a string/bytes input (or generic) pass.
fn non_input_first_param(name: &str) -> bool {
    let p = name.to_ascii_lowercase();
    const NON_INPUT: &[&str] = &[
        "parts",
        "arr",
        "array",
        "list",
        "items",
        "item",
        "nodes",
        "node",
        "tree",
        "opts",
        "options",
        "option",
        "config",
        "cfg",
        "settings",
        "obj",
        "object",
        "fn",
        "func",
        "cb",
        "callback",
        "re",
        "regex",
        "regexp",
        "pattern",
        "matches",
        "map",
        "set",
        "el",
        "elem",
        "element",
        "ctx",
        "context",
        "props",
        "params",
        "args",
        "collection",
        "coll",
    ];
    NON_INPUT.contains(&p.as_str())
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

/// Parse an object-property function assignment `OBJ.PROP = <fn-expr>` or
/// `OBJ.PROP = fnRef` (a reference to a top-level function decl). Returns
/// `(obj, prop, decl)`. Skips the module-export sinks (`module.exports.x`,
/// `exports.x`) and `this.x`, which are handled by the export scan directly.
fn parse_obj_property_fn(
    line: &str,
    decls: &std::collections::HashMap<String, Decl>,
    line_no: u32,
) -> Option<(String, String, Decl)> {
    let t = line.trim().trim_end_matches(';').trim();
    let eq = t.find('=')?;
    // Reject `==`/`=>`/`<=`/`>=`/`!=` — only a plain assignment.
    if t.as_bytes().get(eq + 1) == Some(&b'=') || t[..eq].ends_with(['!', '<', '>', '=']) {
        return None;
    }
    let lhs = t[..eq].trim();
    let rhs = t[eq + 1..].trim();
    let dot = lhs.find('.')?;
    let obj = &lhs[..dot];
    let prop = &lhs[dot + 1..];
    if !is_ident(obj) || !is_ident(prop) || matches!(obj, "module" | "exports" | "this") {
        return None;
    }
    if let Some(params) = function_params(rhs) {
        Some((
            obj.to_owned(),
            prop.to_owned(),
            Decl {
                params,
                line: line_no,
            },
        ))
    } else {
        decls
            .get(rhs)
            .map(|decl| (obj.to_owned(), prop.to_owned(), decl.clone()))
    }
}

/// If `t` is an export assignment of a bare identifier — `module.exports = obj` or
/// an aliased UMD `<mod>.exports = obj` (e.g. `freeModule.exports = he`) — return the
/// exported object's identifier. Used to resolve an exports object built by property
/// assignment to its members.
fn exports_assignment_ident(t: &str) -> Option<&str> {
    let t = t.trim().trim_end_matches(';').trim();
    let eq = t.find('=')?;
    if t.as_bytes().get(eq + 1) == Some(&b'=') {
        return None; // `==`
    }
    let lhs = t[..eq].trim_end();
    if !lhs.ends_with(".exports") {
        return None;
    }
    let rhs = t[eq + 1..].trim();
    is_ident(rhs).then_some(rhs)
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
    // Pass 1b: object-property function assignments (`OBJ.PROP = fn` / `= fnRef`), so an
    // exports object built up by assignment — the common CommonJS/UMD idiom
    // `var he = {}; he.decode = ...; module.exports = he;` — can be resolved to its
    // members when that object is exported. Keyed by the object identifier.
    let mut obj_props: std::collections::HashMap<String, Vec<(String, Decl)>> =
        std::collections::HashMap::new();
    // Raw source lines (indices align with `lines`) — needed to recover object-literal
    // KEYS, which `normalize` strips because it discards quoted-string contents (a key
    // like `'encode'` survives normalization only as the bare quote).
    let raw: Vec<&str> = source.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        if let Some((obj, prop, decl)) = parse_obj_property_fn(line, &decls, (idx + 1) as u32) {
            obj_props.entry(obj).or_default().push((prop, decl));
        }
        // `[var|let|const] IDENT = { key: fnRef, ... }` — an exports object built as an
        // object literal (`he`'s `var he = { 'encode': encode, 'decode': decode };`).
        // Map each function-valued property (export name = key) to its decl.
        if let Some(obj) = object_literal_var(line) {
            for (key, val) in brace_kv(&raw, idx) {
                if let Some(decl) = decls.get(&val) {
                    obj_props
                        .entry(obj.clone())
                        .or_default()
                        .push((key, decl.clone()));
                }
            }
        }
    }

    let mut out: Vec<JsFunction> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut push = |name: String, export_path: String, params: &[String], line: u32| {
        if params.is_empty()
            || non_input_first_param(&params[0])
            || !seen.insert(export_path.clone())
        {
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
                // `module.exports = { key: fn, shorthand }` — the export name is the KEY
                // (`require(mod).key`), resolved to the value's decl. Shorthand keys
                // equal their value.
                for (key, val) in brace_kv(&raw, idx) {
                    if let Some(decl) = decls.get(&val) {
                        let (p, l) = (decl.params.clone(), decl.line);
                        push(key.clone(), key, &p, l);
                    }
                }
            } else if let Some(decl) = decls.get(rhs.trim_end_matches(';').trim()) {
                let (p, l) = (decl.params.clone(), decl.line);
                push("default".to_owned(), String::new(), &p, l);
            }
        }

        // CommonJS / UMD: `module.exports = OBJ` or an aliased `<mod>.exports = OBJ`
        // (e.g. `freeModule.exports = he`) where OBJ is an exports object built by
        // property assignment. Resolve each function member to a dotted export the
        // driver reaches via `require(mod).PROP` at runtime.
        if let Some(ident) = exports_assignment_ident(t) {
            if let Some(props) = obj_props.get(ident) {
                for (prop, decl) in props {
                    let (p, l) = (decl.params.clone(), decl.line);
                    push(prop.clone(), prop.clone(), &p, l);
                }
            }
        }
    }

    // Pass 2: exported classes → fuzz each public instance method as `Class#method`.
    // The driver `new`s the class (no-arg) and calls the method, so only
    // no-arg-constructible classes qualify (mirrors the C# instance-method guard).
    let classes = collect_classes(&lines);
    let mut push_method = |export_path: &str, method: &ClassMethod, class_constructible: bool| {
        if method.params.is_empty() || non_input_first_param(&method.params[0]) {
            return;
        }
        // A static method is `Class.method` (no construction needed — resolved by the
        // driver's dotted path). An instance method is `Class#method` (the driver
        // `new`s the class), so it qualifies only when the class is no-arg-constructible.
        let full = if method.is_static {
            if export_path.is_empty() {
                method.name.clone() // default class export: `mod.method`
            } else {
                format!("{export_path}.{}", method.name)
            }
        } else if class_constructible {
            format!("{export_path}#{}", method.name)
        } else {
            return;
        };
        if !seen.insert(full.clone()) {
            return;
        }
        out.push(JsFunction {
            name: full.clone(),
            export_path: full,
            line: method.line,
            arg_kind: infer_arg_kind(&method.params[0]),
        });
    };
    for (idx, line) in lines.iter().enumerate() {
        let t = line.trim();
        let line_no = (idx + 1) as u32;
        // (class-key, export-path). The class-key selects the ClassInfo; the
        // export-path is what the driver resolves from module.exports.
        // TS allows an `abstract` modifier before `class`; normalize it away so the
        // prefix matches (`export abstract class` / `export default abstract class`).
        let t_norm = t.replace("abstract class", "class");
        let t = t_norm.as_str();
        let exported: Option<(Option<String>, String)> =
            if let Some(r) = t.strip_prefix("export class ") {
                class_name(r).map(|n| (Some(n.clone()), n))
            } else if let Some(rest) = t.strip_prefix("export default class") {
                // ESM default: interop-loaded as `mod.default`.
                Some((
                    class_name(rest).or_else(|| class_at_line(&classes, line_no)),
                    "default".to_owned(),
                ))
            } else if let Some(r) = t
                .strip_prefix("module.exports = class")
                .or_else(|| t.strip_prefix("module.exports=class"))
            {
                // `module.exports = class [Name] {` — default export, path "".
                Some((
                    class_name(r).or_else(|| class_at_line(&classes, line_no)),
                    String::new(),
                ))
            } else {
                class_export_assignment(t).map(|(k, p)| (Some(k), p))
            };
        if let Some((Some(key), export_path)) = exported {
            if let Some(info) = classes.get(&key) {
                for m in &info.methods {
                    push_method(&export_path, m, info.constructible);
                }
            }
        }
    }
    // Classes exported via `module.exports = { Foo }` / `export { Foo }`.
    for (idx, line) in lines.iter().enumerate() {
        let t = line.trim();
        let names = if t.starts_with("module.exports =") && t.contains('{') {
            brace_names(&lines, idx).unwrap_or_default()
        } else if let Some(r) = t.strip_prefix("export {") {
            parse_object_keys(r.trim_end_matches('}'))
        } else {
            continue;
        };
        for name in names {
            if let Some(info) = classes.get(&name) {
                for m in &info.methods {
                    push_method(&name, m, info.constructible);
                }
            }
        }
    }
    out
}

/// A public method of a class (instance or static).
#[derive(Clone)]
struct ClassMethod {
    name: String,
    params: Vec<String>,
    line: u32,
    is_static: bool,
}

/// A discovered class: its methods and whether it is no-arg-constructible.
struct ClassInfo {
    methods: Vec<ClassMethod>,
    constructible: bool,
    open_line: u32,
}

/// The class name after a `class ` keyword (up to `extends`/`{`/whitespace).
fn class_name(rest: &str) -> Option<String> {
    let name: String = rest
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
        .collect();
    is_ident(&name).then_some(name)
}

/// `exports.Foo = class` / `module.exports.Foo = class` → (class-name-key, export-path).
fn class_export_assignment(t: &str) -> Option<(String, String)> {
    for prefix in ["exports.", "module.exports."] {
        if let Some(rest) = t.strip_prefix(prefix) {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
                .collect();
            let after = rest[name.len()..].trim_start();
            if is_ident(&name) {
                if let Some(rhs) = after.strip_prefix('=') {
                    if rhs.trim_start().starts_with("class") {
                        return Some((name.clone(), name));
                    }
                }
            }
        }
    }
    None
}

fn class_at_line(
    classes: &std::collections::HashMap<String, ClassInfo>,
    line: u32,
) -> Option<String> {
    classes
        .iter()
        .find(|(_, info)| info.open_line == line)
        .map(|(k, _)| k.clone())
}

/// Scan for class declarations and their public instance methods, tracking brace
/// depth so nested braces don't confuse method detection. A class is
/// no-arg-constructible unless it declares a `constructor` with a required argument.
fn collect_classes(lines: &[String]) -> std::collections::HashMap<String, ClassInfo> {
    let mut classes = std::collections::HashMap::new();
    let mut depth = 0i32;
    // Stack of (class_name, body_depth). A method is directly in the class body when
    // depth == body_depth.
    let mut stack: Vec<(String, i32)> = Vec::new();
    let mut pending_class: Option<String> = None;

    for (idx, line) in lines.iter().enumerate() {
        let t = line.trim();
        let line_no = (idx + 1) as u32;
        // A class header (any form): `[export] [default] class Name ...` or
        // `... = class Name ...`. Extract the name (may be anonymous).
        if let Some(name) = class_header_name(t) {
            pending_class = Some(name.clone());
            // A TS `abstract class` can never be `new`d, so its instance methods are
            // not fuzzable (static methods still are — gated in push_method).
            let abstract_class = t.split_whitespace().any(|w| w == "abstract");
            classes.entry(name.clone()).or_insert(ClassInfo {
                methods: Vec::new(),
                constructible: !abstract_class,
                open_line: line_no,
            });
        } else if !stack.is_empty() && pending_class.is_none() {
            // Directly inside a class body → method / constructor?
            let (cls, body_depth) = stack.last().unwrap().clone();
            if depth == body_depth {
                if let Some((mname, params)) = class_member_signature(t) {
                    if mname == "constructor" {
                        let required = params
                            .iter()
                            .zip(constructor_has_default(t))
                            .filter(|(_, has_def)| !*has_def)
                            .count();
                        if !params.is_empty() && required > 0 {
                            if let Some(info) = classes.get_mut(&cls) {
                                info.constructible = false;
                            }
                        }
                    } else if let Some(info) = classes.get_mut(&cls) {
                        let is_static = t.split_whitespace().any(|w| w == "static");
                        info.methods.push(ClassMethod {
                            name: mname,
                            params,
                            line: line_no,
                            is_static,
                        });
                    }
                }
            }
        }
        // Brace accounting for this line.
        for ch in line.bytes() {
            match ch {
                b'{' => {
                    depth += 1;
                    if let Some(cls) = pending_class.take() {
                        stack.push((cls, depth));
                    }
                }
                b'}' => {
                    if stack.last().map(|(_, d)| *d == depth).unwrap_or(false) {
                        stack.pop();
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
    }
    classes
}

/// If `t` declares/opens a class, return its name (or a synthetic name for an
/// anonymous class keyed by nothing — callers match anonymous by open line).
fn class_header_name(t: &str) -> Option<String> {
    let idx = t.find("class")?;
    // Require `class` to be a standalone token (preceded by start/space/=, followed
    // by space/{).
    let before_ok = idx == 0 || matches!(t.as_bytes()[idx - 1], b' ' | b'=' | b'(');
    let after = &t[idx + 5..];
    let after_ok = after.starts_with(' ') || after.starts_with('{');
    if !before_ok || !after_ok {
        return None;
    }
    let name = class_name(after).unwrap_or_else(|| format!("__anon_class_{idx}"));
    Some(name)
}

/// A class member signature `name(params) {` (or `=> `-less). Returns None for
/// getters/setters, `private`/`protected` (incl. TS access modifiers and `#`)
/// members, and non-method lines.
fn class_member_signature(t: &str) -> Option<(String, Vec<String>)> {
    let open = t.find('(')?;
    let head = t[..open].trim();
    // Tokens before `(`: modifiers + name. The name is the last token.
    let toks: Vec<&str> = head.split_whitespace().collect();
    let name_tok = *toks.last()?;
    // Exclude getters/setters, generators, non-public (TS `private`/`protected`),
    // and control keywords. `public`/`static`/`async`/`readonly`/`override`/`abstract`
    // modifiers are allowed (TS member methods).
    if toks.iter().any(|m| {
        matches!(
            *m,
            "get"
                | "set"
                | "private"
                | "protected"
                | "abstract"
                | "if"
                | "for"
                | "while"
                | "switch"
                | "catch"
                | "return"
                | "function"
        )
    }) {
        return None;
    }
    let name = name_tok.trim_start_matches('*');
    if name.starts_with('#') || !is_ident(name) {
        return None;
    }
    // The line must open a method body: `) {`, or a TS `): ReturnType {`. A call
    // (`foo()` used as a statement) can't reach here — statements live inside a
    // method body (depth+1), not directly in the class body.
    let after = &t[open..];
    let close = after.find(')')?;
    let post = after[close..].trim_start_matches(')').trim_start();
    // Accept a `{` body directly, or a `:` return-type annotation (TS) that will be
    // followed by the body. Reject a `;` (interface/abstract signature, no body) and
    // a `.`/`(` continuation (a call/chain).
    if !(post.starts_with('{') || post.starts_with(':')) {
        return None;
    }
    let params = parse_param_names(after);
    Some((name.to_owned(), params))
}

/// Per-parameter "has a default value" flags for a `constructor(...)` line.
fn constructor_has_default(t: &str) -> Vec<bool> {
    let open = match t.find('(') {
        Some(o) => o,
        None => return Vec::new(),
    };
    let inner = balanced(&t[open..]).unwrap_or_default();
    inner.split(',').map(|p| p.contains('=')).collect()
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

/// If `line` is `[var|let|const] IDENT = {` (an object literal assigned to a
/// variable), return `IDENT`. Used to resolve an exports object defined as a literal.
fn object_literal_var(line: &str) -> Option<String> {
    let t = line.trim();
    let rest = t
        .strip_prefix("var ")
        .or_else(|| t.strip_prefix("let "))
        .or_else(|| t.strip_prefix("const "))?;
    let eq = rest.find('=')?;
    let name = rest[..eq].trim();
    if !is_ident(name) {
        return None;
    }
    rest[eq + 1..]
        .trim_start()
        .starts_with('{')
        .then(|| name.to_owned())
}

/// Collect an object literal's `key: value` pairs from RAW source lines starting at
/// `start` (the line with the opening `{`), scanning until the matching close brace.
/// Operates on raw text (not normalized) so quoted keys survive; tracks strings and
/// line comments so braces/`}` inside them don't mis-terminate. The key is the property
/// name (quotes stripped); the value is the leading identifier of the RHS (a function
/// reference). Shorthand `name` yields `(name, name)`.
fn brace_kv(raw: &[&str], start: usize) -> Vec<(String, String)> {
    let mut collected = String::new();
    let mut depth = 0i32;
    let mut started = false;
    let mut in_str: Option<char> = None;
    for line in raw.iter().skip(start) {
        let bytes = line.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i] as char;
            if let Some(q) = in_str {
                if c == '\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    in_str = None;
                }
                if started && depth == 1 {
                    collected.push(c);
                }
                i += 1;
                continue;
            }
            if c == '/' && bytes.get(i + 1) == Some(&b'/') {
                break; // line comment
            }
            match c {
                '\'' | '"' | '`' => {
                    in_str = Some(c);
                    if started && depth == 1 {
                        collected.push(c);
                    }
                }
                '{' => {
                    depth += 1;
                    started = true;
                }
                '}' => {
                    depth -= 1;
                    if started && depth == 0 {
                        return parse_object_kv(&collected);
                    }
                }
                // Only collect the OUTER object's entries (depth 1); a nested object
                // value belongs to a property we don't resolve.
                _ if started && depth == 1 => collected.push(c),
                _ => {}
            }
            i += 1;
        }
        collected.push(' ');
    }
    Vec::new()
}

/// Parse `key: value` / shorthand pairs from an object-literal body. Key quotes are
/// stripped; value is the leading identifier of the RHS.
fn parse_object_kv(inner: &str) -> Vec<(String, String)> {
    inner
        .split(',')
        .filter_map(|entry| {
            let (key, val) = match entry.split_once(':') {
                Some((k, v)) => {
                    let key = k.trim().trim_matches(['\'', '"']).to_owned();
                    let val: String = v
                        .trim()
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
                        .collect();
                    (key, val)
                }
                None => {
                    let id: String = entry
                        .trim()
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
                        .collect();
                    (id.clone(), id)
                }
            };
            (is_ident(&key) && is_ident(&val)).then_some((key, val))
        })
        .collect()
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
    fn commonjs_exports_object_built_by_property_assignment() {
        // `var he = {}; he.decode = decode; module.exports = he;` — an exports object
        // built by property assignment (govfuzz discovered 0 of these before).
        let src = "\
var decode = function(html) { return html.toLowerCase(); };
var encode = function(string) { return string.toUpperCase(); };
var he = {};
he.decode = decode;
he.encode = encode;
module.exports = he;
";
        let fns = parse_js(src);
        let paths: Vec<&str> = fns.iter().map(|f| f.export_path.as_str()).collect();
        assert!(paths.contains(&"decode"), "decode missing: {paths:?}");
        assert!(paths.contains(&"encode"), "encode missing: {paths:?}");
    }

    #[test]
    fn commonjs_exports_object_literal_with_quoted_keys_and_alias() {
        // The `he` shape: functions defined as var-fn-expressions, collected into an
        // object literal with QUOTED keys (whose contents `normalize` strips, so the
        // key must be recovered from the raw source), exported via a UMD alias. The
        // `'unescape': decode` alias resolves to the `decode` function.
        let src = "\
;(function(root) {
\tvar encode = function(string, options) { return string; };
\tvar decode = function(html, options) { return html; };
\tvar he = {
\t\t'version': '1.2.0',
\t\t'encode': encode,
\t\t'decode': decode,
\t\t'unescape': decode
\t};
\tvar freeModule = module;
\tfreeModule.exports = he;
}(this));
";
        let fns = parse_js(src);
        let paths: Vec<&str> = fns.iter().map(|f| f.export_path.as_str()).collect();
        assert!(paths.contains(&"encode"), "encode missing: {paths:?}");
        assert!(paths.contains(&"decode"), "decode missing: {paths:?}");
        assert!(
            paths.contains(&"unescape"),
            "unescape alias missing: {paths:?}"
        );
        // `version` is a string, not a function — it must NOT be a target.
        assert!(!paths.contains(&"version"), "non-function property leaked");
    }

    #[test]
    fn non_exported_object_members_are_not_discovered() {
        // An internal object that is NOT exported must not have its members discovered
        // (no false attacker-reachable targets).
        let src = "\
var helper = function(x) { return x; };
var internal = {};
internal.helper = helper;
module.exports = { real: helper };
";
        let fns = parse_js(src);
        let paths: Vec<&str> = fns.iter().map(|f| f.export_path.as_str()).collect();
        assert!(paths.contains(&"real"), "explicit export missing");
        // `helper` reached only via the non-exported `internal` object → not a target.
        assert!(
            !paths.contains(&"helper"),
            "internal (non-exported) object member leaked: {paths:?}"
        );
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
        assert_eq!(infer_arg_kind("filePath"), JsArgKind::FilePath);
        assert_eq!(infer_arg_kind("config_filename"), JsArgKind::FilePath);
        assert_eq!(infer_arg_kind("x"), JsArgKind::Buffer); // unknown -> Buffer default
    }

    #[test]
    fn discovers_exported_class_methods() {
        let src = "\
class Parser {
  parse(input) { return input.length; }
  reset() { }
  #secret(x) { }
  static make() { return new Parser(); }
}
module.exports = { Parser };
";
        let fns = parse_js(src);
        // `Parser#parse` is discovered; `reset` (0 args), `#secret` (private), and
        // `make` (static, 0 args) are not.
        let paths: Vec<&str> = fns.iter().map(|f| f.export_path.as_str()).collect();
        assert!(paths.contains(&"Parser#parse"), "got {paths:?}");
        assert!(!paths.iter().any(|p| p.contains("reset")));
        assert!(!paths.iter().any(|p| p.contains("secret")));
    }

    #[test]
    fn skips_class_needing_ctor_args() {
        let src = "\
class Validator {
  constructor(schema) { this.schema = schema; }
  validate(input) { return this.schema.test(input); }
}
module.exports = { Validator };
";
        // Not no-arg-constructible -> no methods discovered.
        assert!(parse_js(src).is_empty());
    }

    #[test]
    fn typescript_signatures_discovered_types_stripped() {
        let src = "\
export interface Options { strict: boolean; }
export type Result = number | null;
export function parseValue(input: string, opts?: Options): Result {
  return input.length;
}
export class Lexer {
  private state = 0;
  public tokenize(source: string): string[] { return source.split(''); }
  private helper(x: string): void { }
}
";
        let fns = parse_js(src);
        let names: Vec<&str> = fns.iter().map(|f| f.name.as_str()).collect();
        // Exported function discovered (param name `input` extracted past `: string`).
        assert!(fns.iter().any(|f| f.name == "parseValue"));
        let pv = fns.iter().find(|f| f.name == "parseValue").unwrap();
        assert_eq!(pv.arg_kind, JsArgKind::Str);
        // Public class method discovered; interface/type/private-method excluded.
        assert!(names.contains(&"Lexer#tokenize"));
        assert!(!names.iter().any(|n| n.contains("helper"))); // private
        assert!(!names.iter().any(|n| n.contains("Options"))); // interface
    }

    #[test]
    fn ts_abstract_class_instance_method_skipped() {
        let src = "\
export abstract class Base {
  parse(input: string): void { }
  static create(spec: string): Base { return null; }
}
";
        let fns = parse_js(src);
        // Instance method skipped (abstract can't be `new`d); static method kept.
        assert!(!fns.iter().any(|f| f.export_path.contains('#')));
        assert!(fns.iter().any(|f| f.export_path == "Base.create"));
    }

    #[test]
    fn static_class_method_needs_no_constructor() {
        // A class with a required-arg constructor is not instance-fuzzable, but its
        // STATIC method needs no instance and is still discovered (dotted path).
        let src = "\
class Url {
  constructor(href) { this.href = href; }
  static parse(input) { return new Url(input); }
}
module.exports = { Url };
";
        let fns = parse_js(src);
        let paths: Vec<&str> = fns.iter().map(|f| f.export_path.as_str()).collect();
        assert!(paths.contains(&"Url.parse"), "got {paths:?}"); // static -> dotted
        assert!(!paths.iter().any(|p| p.contains('#'))); // no instance method
    }

    #[test]
    fn exported_class_default_ctor_ok() {
        let src = "\
export class Lexer {
  constructor() { this.pos = 0; }
  tokenize(source) { return source.split(''); }
}
";
        let fns = parse_js(src);
        assert!(fns.iter().any(|f| f.export_path == "Lexer#tokenize"));
    }

    #[test]
    fn skips_non_input_first_param() {
        // An internal helper taking an array/options is not a string/bytes channel.
        let src = "\
export function multilineRegexp(parts, flags) { return parts.join(''); }
export function isEmail(str) { return str.includes('@'); }
";
        let fns = parse_js(src);
        let names: Vec<&str> = fns.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"isEmail"));
        assert!(!names.contains(&"multilineRegexp")); // first param `parts` -> skipped
    }
}
