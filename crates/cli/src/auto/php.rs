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
    /// Declared type of the first input parameter, or empty when untyped.
    pub first_param_type: String,
    /// Parameters that have neither a default nor a variadic marker. The current
    /// harness supplies one decoded input, so functions requiring more are not
    /// directly callable.
    pub required_param_count: usize,
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
        !self.first_param.is_empty()
            && !non_input_first_param(&self.first_param)
            && self.required_param_count <= 1
            && supported_input_type(&self.first_param_type)
    }
}

fn supported_input_type(ty: &str) -> bool {
    if ty.is_empty() {
        return true;
    }
    ty.trim_start_matches('?').split('|').any(|part| {
        let part = part.trim();
        matches!(
            part.to_ascii_lowercase().as_str(),
            "mixed"
                | "string"
                | "int"
                | "integer"
                | "bool"
                | "boolean"
                | "float"
                | "double"
                | "array"
        ) || php_class_type(part)
    })
}

fn php_class_type(ty: &str) -> bool {
    let bare = ty.trim_start_matches('\\');
    !bare.is_empty()
        && bare.split('\\').all(|part| {
            !part.is_empty()
                && part.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                && part.chars().all(is_ident_char)
        })
        && !matches!(
            bare.to_ascii_lowercase().as_str(),
            "self"
                | "static"
                | "parent"
                | "void"
                | "never"
                | "null"
                | "callable"
                | "iterable"
                | "object"
        )
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
    let mut imported_types = std::collections::HashMap::<String, String>::new();
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
                imported_types.clear();
            }
        }
        if class_stack.is_empty() {
            if let Some((alias, qualified)) = parse_type_import(t) {
                imported_types.insert(alias, qualified);
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
            f.first_param_type =
                resolve_type_name(&f.first_param_type, &namespace, &imported_types);
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

fn parse_type_import(line: &str) -> Option<(String, String)> {
    let body = line.strip_prefix("use ")?.trim().strip_suffix(';')?.trim();
    if body.starts_with("function ") || body.starts_with("const ") || body.contains('{') {
        return None;
    }
    let (qualified, alias) = if let Some((qualified, alias)) = body.rsplit_once(" as ") {
        (qualified.trim(), alias.trim())
    } else {
        (body, body.rsplit('\\').next()?)
    };
    php_class_type(qualified).then(|| {
        (
            alias.to_owned(),
            format!("\\{}", qualified.trim_start_matches('\\')),
        )
    })
}

fn resolve_type_name(
    ty: &str,
    namespace: &str,
    imported_types: &std::collections::HashMap<String, String>,
) -> String {
    let nullable = ty.starts_with('?');
    let body = ty.trim_start_matches('?');
    let resolved = body
        .split('|')
        .map(|part| {
            let part = part.trim();
            let lower = part.to_ascii_lowercase();
            if matches!(
                lower.as_str(),
                "mixed"
                    | "string"
                    | "int"
                    | "integer"
                    | "bool"
                    | "boolean"
                    | "float"
                    | "double"
                    | "array"
            ) || part.starts_with('\\')
            {
                part.to_owned()
            } else if let Some(imported) = imported_types.get(part) {
                imported.clone()
            } else if php_class_type(part) && !namespace.is_empty() {
                format!("\\{namespace}\\{part}")
            } else {
                part.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("|");
    format!("{}{resolved}", if nullable { "?" } else { "" })
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
    let first_param = params
        .first()
        .map(|param| param.name.clone())
        .unwrap_or_default();
    let first_param_type = params
        .first()
        .map(|param| param.ty.clone())
        .unwrap_or_default();
    let required_param_count = params.iter().filter(|param| param.required).count();

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
        first_param_type,
        required_param_count,
    })
}

/// The parameter names from a `(...)` list starting at `s` (which begins with `(`).
/// Type hints, defaults, `&` refs, variadics, and visibility-promoted params are
/// reduced to the bare `$name` (the `$` is dropped).
struct PhpParam {
    name: String,
    ty: String,
    required: bool,
}

fn parse_params(s: &str) -> Vec<PhpParam> {
    let inner = match s.strip_prefix('(') {
        Some(rest) => rest.split(')').next().unwrap_or(""),
        None => return Vec::new(),
    };
    inner
        .split(',')
        .filter_map(|p| {
            // The parameter variable is the token after the last `$`.
            let dollar = p.rfind('$')?;
            let after_dollar = &p[dollar + 1..];
            let name: String = after_dollar
                .chars()
                .take_while(|&c| is_ident_char(c))
                .collect();
            if name.is_empty() {
                return None;
            }
            let prefix = p[..dollar]
                .trim()
                .trim_end_matches('&')
                .trim_end_matches("...")
                .trim();
            let ty = prefix.split_whitespace().last().unwrap_or("").to_owned();
            let variadic = p[..dollar].trim_end().ends_with("...");
            let required = !variadic && !after_dollar[name.len()..].contains('=');
            Some(PhpParam { name, ty, required })
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
        assert_eq!(f.first_param_type, "string");
        assert_eq!(f.required_param_count, 1);
    }

    #[test]
    fn unsupported_or_multiple_required_parameters_are_not_candidates() {
        assert!(parse_php("<?php\nfunction f(object $input) {}\n").is_empty());
        assert!(parse_php("<?php\nfunction f(string $input, int $required) {}\n").is_empty());
        assert_eq!(
            parse_php("<?php\nfunction f(array $input, int $optional = 1) {}\n")[0]
                .first_param_type,
            "array"
        );
    }

    #[test]
    fn imported_value_object_type_is_resolved_and_fuzzable() {
        let source = "<?php\nnamespace Monolog\\Formatter;\nuse Monolog\\LogRecord;\nclass ChromePHPFormatter {\n  public function format(LogRecord $record) {}\n}\n";
        let functions = parse_php(source);
        assert_eq!(functions.len(), 1);
        assert_eq!(
            functions[0].name,
            "Monolog\\Formatter\\ChromePHPFormatter#format"
        );
        assert_eq!(functions[0].first_param_type, "\\Monolog\\LogRecord");
        assert!(functions[0].is_fuzzable());
    }
}
