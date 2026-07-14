// SPDX-License-Identifier: Apache-2.0

//! PHP fuzzing lane (M3.11) — discovery/parser half.
//!
//! Strategy (like the Ruby/Lua/Perl lanes): reuse govfuzz's builtin engine over the
//! framed fork-server protocol driving a warm `php` process. A function or a public
//! static/instance method taking at least one argument is the fuzzable unit; the first
//! argument is the attacker-controlled channel (fed a fuzz `string`). The generated
//! launcher execs `php -d pcov.enabled=1 govfuzz_driver.php`, which `require`s the
//! target, calls the function, records per-line edge coverage via the `pcov` extension
//! folded into the shared `GOVFUZZ_COV_SHM` bitmap, and reports an uncaught bug-class
//! `Throwable` (DivisionByZeroError, an assertion, out-of-memory) as a finding
//! (exit 86) — no third-party fuzzer.
//!
//! This module is the discovery/parser half; the build + launch half is
//! [`crate::auto::php_build`].

/// A discovered, callable PHP function or method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhpFunction {
    /// Display + candidate name: `func` (namespaced `Ns\func`), `Class::method`
    /// (static), or `Class#method` (instance).
    pub name: String,
    /// The bare function/method name used to build the call.
    pub func: String,
    /// The fully-qualified class the method lives on (`\Ns\Class`), or empty for a
    /// free function.
    pub class: String,
    /// A `static` method — callable as `Class::method(...)`.
    pub is_static: bool,
    /// An instance method — needs `(new Class)->method(...)`.
    pub needs_instance: bool,
    pub line: u32,
    /// The first parameter's name (without the leading `$`).
    pub first_param: String,
}

/// Whether the first parameter's name marks the function as NOT a string input
/// channel — an internal helper taking an array/options/callback. Fuzzing such a
/// function with a `string` only produces our-fault `TypeError`s, so it is skipped.
fn non_input_first_param(name: &str) -> bool {
    let p = name.to_ascii_lowercase();
    const NON_INPUT: &[&str] = &[
        "arr", "array", "list", "items", "item", "node", "nodes", "tree", "opts", "options",
        "option", "config", "cfg", "settings", "obj", "object", "callback", "cb", "fn", "func",
        "callable", "closure", "pattern", "map", "set", "el", "elem", "element", "ctx", "context",
        "args", "params", "count", "n", "num", "index", "idx", "i", "size", "len", "length", "key",
        "k", "offset", "flags",
    ];
    NON_INPUT.contains(&p.as_str())
}

impl PhpFunction {
    /// A function is fuzzable when it has an input-channel first parameter.
    pub fn is_fuzzable(&self) -> bool {
        !self.first_param.is_empty() && !non_input_first_param(&self.first_param)
    }
}

/// Strip PHP comments (`//`, `#`, `/* */`) and string CONTENTS (so `function`/`{`/`}`
/// inside a literal don't confuse the scanner), keeping the opening quote. One line
/// out per line in.
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
                if c == b'*' && bytes.get(i + 1) == Some(&b'/') {
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
            if c == b'/' && bytes.get(i + 1) == Some(&b'/') {
                break;
            }
            if c == b'#' {
                break;
            }
            if c == b'/' && bytes.get(i + 1) == Some(&b'*') {
                in_block = true;
                i += 2;
                continue;
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

/// Scan PHP source for callable, fuzzable functions and methods.
pub fn parse_php(source: &str) -> Vec<PhpFunction> {
    let lines = normalize(source);
    let mut out: Vec<PhpFunction> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut namespace = String::new();
    // The current class scope: (fq-name, brace-depth-at-open). PHP is brace-delimited,
    // so a class body is between its `{` and the matching `}`.
    let mut class_stack: Vec<(String, i32)> = Vec::new();
    let mut depth = 0i32;

    for (idx, raw) in lines.iter().enumerate() {
        let t = raw.trim();
        let line_no = (idx + 1) as u32;

        // `namespace Foo\Bar;`
        if let Some(rest) = t.strip_prefix("namespace ") {
            let ns: String = rest
                .chars()
                .take_while(|&c| is_ident_char(c) || c == '\\')
                .collect();
            if !ns.is_empty() {
                namespace = ns;
            }
        }
        // `class Name` / `abstract class Name` / `final class Name` / `trait` / `interface`.
        if let Some(cls) = class_header(t) {
            let fq = if namespace.is_empty() {
                cls
            } else {
                format!("{namespace}\\{cls}")
            };
            class_stack.push((fq, depth));
        }

        // A method/function header on this line.
        if let Some(mut f) =
            parse_function_header(t, line_no, class_stack.last().map(|(n, _)| n.as_str()))
        {
            // Namespace a free function.
            if f.class.is_empty() && !namespace.is_empty() {
                f.name = format!("{namespace}\\{}", f.func);
            }
            if f.is_fuzzable() && seen.insert(f.name.clone()) {
                out.push(f);
            }
        }

        // Track brace depth to pop class scopes.
        for c in raw.bytes() {
            match c {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if let Some((_, open_depth)) = class_stack.last() {
                        if depth <= *open_depth {
                            class_stack.pop();
                        }
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// Recognize a class/trait/interface header and return the type name.
fn class_header(t: &str) -> Option<String> {
    let mut rest = t;
    for kw in ["final ", "abstract ", "readonly "] {
        if let Some(r) = rest.strip_prefix(kw) {
            rest = r.trim_start();
        }
    }
    let rest = rest
        .strip_prefix("class ")
        .or_else(|| rest.strip_prefix("trait "))
        .or_else(|| rest.strip_prefix("interface "))?;
    let name: String = rest
        .trim_start()
        .chars()
        .take_while(|&c| is_ident_char(c))
        .collect();
    (!name.is_empty() && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_'))
        .then_some(name)
}

/// Parse a `function` header (with optional visibility/static modifiers) into a
/// [`PhpFunction`], or `None`.
fn parse_function_header(t: &str, line_no: u32, class: Option<&str>) -> Option<PhpFunction> {
    // Collect leading modifier tokens up to `function`.
    let fpos = t.find("function ")?;
    let before = &t[..fpos];
    let mods: Vec<&str> = before.split_whitespace().collect();
    // A method (inside a class) with no visibility keyword defaults to public — but a
    // `private`/`protected` one is not externally callable.
    let in_class = class.is_some();
    if mods.iter().any(|m| matches!(*m, "private" | "protected")) {
        return None;
    }
    // Only plausible leading tokens (visibility/static/final/abstract). Anything else
    // means this isn't a top-level method declaration (e.g. `$x = function (...)`).
    if !mods
        .iter()
        .all(|m| matches!(*m, "public" | "static" | "final" | "abstract"))
    {
        return None;
    }
    if mods.contains(&"abstract") {
        return None; // no body
    }
    let is_static = mods.contains(&"static");

    let rest = &t[fpos + "function ".len()..];
    // A `function &name(` returns by reference — skip the `&`.
    let rest = rest
        .trim_start()
        .strip_prefix('&')
        .unwrap_or(rest)
        .trim_start();
    let name: String = rest.chars().take_while(|&c| is_ident_char(c)).collect();
    if name.is_empty() || !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
        return None;
    }
    // Skip magic methods (`__construct`, `__toString`, …) — not fuzz entry points.
    if name.starts_with("__") {
        return None;
    }
    let paren = rest.find('(')?;
    let params = parse_params(&rest[paren..]);
    let first_param = params.into_iter().next().unwrap_or_default();

    let (class_fq, is_static, needs_instance, display) = match class {
        Some(c) => {
            let fq = if c.starts_with('\\') {
                c.to_owned()
            } else {
                format!("\\{c}")
            };
            if is_static {
                (fq.clone(), true, false, format!("{c}::{name}"))
            } else {
                (fq.clone(), false, true, format!("{c}#{name}"))
            }
        }
        None => (String::new(), false, false, name.clone()),
    };
    let _ = in_class;

    Some(PhpFunction {
        name: display,
        func: name,
        class: class_fq,
        is_static,
        needs_instance,
        line: line_no,
        first_param,
    })
}

/// The parameter names from a `(...)` list starting at `s` (which begins with `(`).
/// Type hints, defaults, `&` refs, variadics, and visibility-promoted params are
/// reduced to the bare `$name` (the `$` is dropped).
fn parse_params(s: &str) -> Vec<String> {
    let inner = match s.strip_prefix('(') {
        Some(rest) => rest.split(')').next().unwrap_or(""),
        None => return Vec::new(),
    };
    inner
        .split(',')
        .filter_map(|p| {
            // The parameter variable is the token after the last `$`.
            let dollar = p.rfind('$')?;
            let name: String = p[dollar + 1..]
                .chars()
                .take_while(|&c| is_ident_char(c))
                .collect();
            (!name.is_empty()).then_some(name)
        })
        .collect()
}

/// Mine string literals as a fuzzing dictionary (magic values that gate coverage).
pub fn extract_php_dictionary_tokens(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for raw in source.lines() {
        let bytes = raw.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i];
            if (c == b'/' && bytes.get(i + 1) == Some(&b'/')) || c == b'#' {
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
                        && !lit.contains("$")
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
    fn free_function() {
        let f = &parse_php("<?php\nfunction parse_it($input) {\n  return strlen($input);\n}\n")[0];
        assert_eq!(f.name, "parse_it");
        assert_eq!(f.func, "parse_it");
        assert!(f.class.is_empty());
        assert!(!f.is_static);
        assert_eq!(f.first_param, "input");
        assert!(f.is_fuzzable());
    }

    #[test]
    fn namespaced_function() {
        let f = &parse_php(
            "<?php\nnamespace Toml\\Parser;\nfunction decode($text) {\n  return $text;\n}\n",
        )[0];
        assert_eq!(f.name, "Toml\\Parser\\decode");
        assert_eq!(f.func, "decode");
    }

    #[test]
    fn public_static_method() {
        let src = "<?php\nclass Toml {\n  public static function parse($str) {\n    return $str;\n  }\n}\n";
        let f = &parse_php(src)[0];
        assert_eq!(f.name, "Toml::parse");
        assert!(f.is_static);
        assert!(!f.needs_instance);
        assert_eq!(f.class, "\\Toml");
    }

    #[test]
    fn public_instance_method_needs_receiver() {
        let src =
            "<?php\nclass Parser {\n  public function parse($data) {\n    return $data;\n  }\n}\n";
        let f = &parse_php(src)[0];
        assert_eq!(f.name, "Parser#parse");
        assert!(f.needs_instance);
    }

    #[test]
    fn private_and_protected_methods_skipped() {
        let src = "<?php\nclass P {\n  public function pub($s){ return $s; }\n  private function priv($s){ return $s; }\n  protected function prot($s){ return $s; }\n}\n";
        let names: Vec<String> = parse_php(src).into_iter().map(|f| f.name).collect();
        assert!(names.iter().any(|n| n == "P#pub"));
        assert!(!names.iter().any(|n| n.contains("priv")));
        assert!(!names.iter().any(|n| n.contains("prot")));
    }

    #[test]
    fn non_input_first_param_and_magic_skipped() {
        let src = "<?php\nfunction render($options){ return $options; }\nclass C { public function __construct($x){} }\n";
        assert!(parse_php(src).is_empty());
    }

    #[test]
    fn typed_param_reduced_to_name() {
        let f = &parse_php("<?php\nfunction f(string $input, int $n = 0) { return $input; }\n")[0];
        assert_eq!(f.first_param, "input");
    }
}
