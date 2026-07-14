// SPDX-License-Identifier: Apache-2.0

//! Lua fuzzing lane (M3.10) — discovery/parser half.
//!
//! Strategy (like the Ruby/Perl/Python lanes): reuse govfuzz's builtin engine over
//! the framed fork-server protocol driving a warm `lua` process. A function taking at
//! least one argument is the fuzzable unit; the first argument is the
//! attacker-controlled channel (fed a fuzz `string`). The generated launcher execs
//! `lua lua_runtime/govfuzz_driver.lua`, which `dofile`s the target, calls the
//! function with the fuzz bytes, records per-line edge coverage via a
//! `debug.sethook` line hook folded into the shared `GOVFUZZ_COV_SHM` bitmap, and
//! reports an uncaught bug-class error (integer divide-by-zero, stack overflow,
//! out-of-memory, an explicit assert) as a finding (exit 86) — no third-party fuzzer.
//!
//! This module is the discovery/parser half; the build + launch half is
//! [`crate::auto::lua_build`].

/// A discovered, callable Lua function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LuaFunction {
    /// Display + candidate name. For a table field: `Mod.fn` / `Mod:fn`; for a global
    /// function: `fn`.
    pub name: String,
    /// The field/global name used to resolve the function at call time.
    pub field: String,
    /// A colon method (`function M:fn(...)`) receives an implicit `self`; the harness
    /// calls it as `mod:field(data)`.
    pub is_method: bool,
    /// A global function (`function fn(...)`, no `T.`/`T:` qualifier) — resolved from
    /// the global environment rather than the returned module table.
    pub is_global: bool,
    pub line: u32,
    /// The first parameter's name (the input channel).
    pub first_param: String,
}

/// Whether the first parameter's name marks the function as NOT a string input
/// channel — an internal helper taking a table/options/callback/index. Fuzzing such a
/// function with a `string` only produces our-fault "attempt to index/call" errors.
fn non_input_first_param(name: &str) -> bool {
    let p = name.to_ascii_lowercase();
    const NON_INPUT: &[&str] = &[
        "t", "tbl", "table", "arr", "array", "list", "items", "item", "node", "nodes", "tree",
        "opts", "options", "option", "config", "cfg", "settings", "obj", "object", "o", "fn",
        "func", "cb", "callback", "f", "pattern", "map", "set", "el", "elem", "ctx", "context",
        "args", "params", "self", "count", "n", "num", "index", "idx", "i", "size", "len",
        "length", "k", "key",
    ];
    NON_INPUT.contains(&p.as_str())
}

impl LuaFunction {
    /// A function is fuzzable when it has an input-channel first parameter.
    pub fn is_fuzzable(&self) -> bool {
        !self.first_param.is_empty() && !non_input_first_param(&self.first_param)
    }
}

/// Strip a Lua comment (`--` to end of line, and `--[[ ]]` blocks) and string
/// CONTENTS (so `function`/`end`/quotes inside a literal don't confuse the scanner),
/// keeping the opening quote. One line out per line in.
fn normalize(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_block_comment = false;
    for raw in source.lines() {
        let bytes = raw.as_bytes();
        let mut line = String::with_capacity(raw.len());
        let mut i = 0;
        let mut in_str: Option<u8> = None;
        while i < bytes.len() {
            let c = bytes[i];
            if in_block_comment {
                if c == b']' && bytes.get(i + 1) == Some(&b']') {
                    in_block_comment = false;
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
            // `--` starts a comment (line or `--[[` block).
            if c == b'-' && bytes.get(i + 1) == Some(&b'-') {
                if bytes.get(i + 2) == Some(&b'[') && bytes.get(i + 3) == Some(&b'[') {
                    in_block_comment = true;
                    i += 4;
                    continue;
                }
                break; // line comment
            }
            if c == b'"' || c == b'\'' {
                in_str = Some(c);
                line.push(c as char);
                i += 1;
                continue;
            }
            line.push(c as char);
            i += 1;
        }
        out.push(line.trim_end().to_owned());
    }
    out
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Scan Lua source for callable, fuzzable functions.
pub fn parse_lua(source: &str) -> Vec<LuaFunction> {
    let lines = normalize(source);
    let mut out: Vec<LuaFunction> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (idx, line) in lines.iter().enumerate() {
        let t = line.trim();
        // A `local function` / `local X = function` is not externally callable — skip.
        if t.starts_with("local ") {
            continue;
        }
        if let Some(f) = parse_function_header(t, (idx + 1) as u32) {
            if f.is_fuzzable() && seen.insert(f.name.clone()) {
                out.push(f);
            }
        }
    }
    out
}

/// Parse a `function` header line into a [`LuaFunction`], or `None`. Handles
/// `function name(a)`, `function T.name(a)`, `function T:name(a)`, and the assignment
/// form `T.name = function(a)` / `name = function(a)`.
fn parse_function_header(t: &str, line_no: u32) -> Option<LuaFunction> {
    // Form 1: `function <target>(params)`.
    let (target, params_src) = if let Some(rest) = t.strip_prefix("function ") {
        let paren = rest.find('(')?;
        (rest[..paren].trim(), &rest[paren..])
    } else {
        // Form 2: `<lhs> = function(params)` (a function-valued assignment).
        let eq = t.find('=')?;
        // Reject comparisons and `==`.
        if t.as_bytes().get(eq + 1) == Some(&b'=') || t[..eq].ends_with(['<', '>', '~', '=']) {
            return None;
        }
        let lhs = t[..eq].trim();
        let rhs = t[eq + 1..].trim();
        let after_fn = rhs.strip_prefix("function")?;
        // `function(...)` or `function (...)`.
        let paren = after_fn.find('(')?;
        if !after_fn[..paren].trim().is_empty() {
            return None; // `function name()` on the RHS — not the assignment form
        }
        (lhs, &after_fn[paren..])
    };

    // Split the target into an optional table qualifier and the field/name.
    let (is_global, is_method, field) = if let Some(colon) = target.rfind(':') {
        (false, true, &target[colon + 1..])
    } else if let Some(dot) = target.rfind('.') {
        (false, false, &target[dot + 1..])
    } else {
        (true, false, target)
    };
    let field = field.trim();
    if field.is_empty() || !field.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
        return None;
    }
    if !field.chars().all(is_ident_char) {
        return None;
    }

    let params = parse_params(params_src);
    // A colon method's first real parameter is the input (self is implicit); a plain
    // function's first parameter is the input.
    let first_param = params.into_iter().next().unwrap_or_default();

    // For a table field/method, keep the qualified `Mod.fn` / `Mod:fn` for display; a
    // global function shows just its name.
    let display = if is_global {
        field.to_owned()
    } else {
        target.to_owned()
    };

    Some(LuaFunction {
        name: display,
        field: field.to_owned(),
        is_method,
        is_global,
        line: line_no,
        first_param,
    })
}

/// The parameter names from a `(...)` list starting at `s` (which begins with `(`).
/// A trailing `...` vararg is dropped.
fn parse_params(s: &str) -> Vec<String> {
    let inner = match s.strip_prefix('(') {
        Some(rest) => rest.split(')').next().unwrap_or(""),
        None => return Vec::new(),
    };
    inner
        .split(',')
        .filter_map(|p| {
            let name: String = p.trim().chars().take_while(|&c| is_ident_char(c)).collect();
            (!name.is_empty()).then_some(name)
        })
        .collect()
}

/// Mine string/number literals as a fuzzing dictionary (magic values that gate
/// coverage), skipping trivial values. Mirrors the Ruby/JS/Perl dictionary miners.
pub fn extract_lua_dictionary_tokens(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for raw in source.lines() {
        let bytes = raw.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i];
            if c == b'-' && bytes.get(i + 1) == Some(&b'-') {
                break;
            }
            if c == b'"' || c == b'\'' {
                let q = c;
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() {
                    if bytes[j] == b'\\' {
                        j += 2;
                        continue;
                    }
                    if bytes[j] == q {
                        break;
                    }
                    j += 1;
                }
                if j <= bytes.len() && j > start {
                    let lit = &raw[start..j.min(raw.len())];
                    if lit.len() >= 2
                        && lit.len() <= 64
                        && lit.chars().all(|ch| !ch.is_control())
                        && seen.insert(lit.to_owned())
                    {
                        out.push(lit.to_owned());
                    }
                }
                i = j + 1;
                continue;
            }
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_function() {
        let f = &parse_lua("function parse(input)\n  return #input\nend\n")[0];
        assert_eq!(f.name, "parse");
        assert_eq!(f.field, "parse");
        assert!(f.is_global);
        assert!(!f.is_method);
        assert_eq!(f.first_param, "input");
        assert!(f.is_fuzzable());
    }

    #[test]
    fn module_field_function() {
        let src = "local M = {}\nfunction M.decode(text)\n  return text\nend\nreturn M\n";
        let f = &parse_lua(src)[0];
        assert_eq!(f.name, "M.decode");
        assert_eq!(f.field, "decode");
        assert!(!f.is_global);
        assert!(!f.is_method);
    }

    #[test]
    fn colon_method_is_flagged() {
        let src = "local M = {}\nfunction M:parse(str)\n  return str\nend\nreturn M\n";
        let f = &parse_lua(src)[0];
        assert_eq!(f.field, "parse");
        assert!(f.is_method);
        assert!(!f.is_global);
    }

    #[test]
    fn local_functions_are_skipped() {
        let src = "local function helper(s)\n  return s\nend\nlocal g = function(s) return s end\n";
        assert!(parse_lua(src).is_empty());
    }

    #[test]
    fn non_input_first_param_skipped() {
        let src =
            "function render(opts)\n  return opts\nend\nfunction walk(node)\n  return node\nend\n";
        assert!(parse_lua(src).is_empty());
    }

    #[test]
    fn assignment_form_function() {
        let src = "M = {}\nM.parse = function(s)\n  return s\nend\n";
        let f = &parse_lua(src)[0];
        assert_eq!(f.field, "parse");
        assert!(!f.is_global);
        assert_eq!(f.first_param, "s");
    }

    #[test]
    fn dictionary_tokens_mined() {
        let toks = extract_lua_dictionary_tokens("if s == 'MAGIC' then end\n");
        assert!(toks.contains(&"MAGIC".to_owned()));
    }
}
