// SPDX-License-Identifier: Apache-2.0

//! C# / .NET fuzzing lane (M3.6).
//!
//! Strategy (like the COBOL/Fortran lanes): reuse govfuzz's builtin engine. A
//! `public` method taking a byte buffer (`byte[]`, `ReadOnlySpan<byte>`,
//! `Memory<byte>`), a `string`, or a `System.IO.Stream` is the fuzzable unit. The
//! target assembly is built (`dotnet build`) and its IL instrumented with
//! SharpFuzz (`sharpfuzz <dll>`), which writes edge coverage into a shared map.
//! govfuzz maps that map onto its own `GOVFUZZ_COV_SHM` AFL-style bitmap and
//! drives a warm, persistent CLR one input at a time over the framed fork-server
//! protocol — no AFL fork-server, no libFuzzer. An uncaught exception that is not
//! input rejection is reported as a finding (the driver exits 86); the engine's
//! `parse_csharp_finding` maps the exception type to a GF rule + CWE.
//!
//! This module is only the discovery/parser half; the build + instrument + launch
//! half is [`crate::auto::csharp_build`].

/// A discovered C# method and its parameter list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CSharpMethod {
    /// Root namespace of the declaring type (`""` if the type is in the global
    /// namespace). Drives `GOVFUZZ_CS_NAMESPACE` so the target library's own
    /// exceptions are treated as declared input rejection, not findings.
    pub namespace: String,
    /// Fully-qualified declaring type name, `Namespace.Outer.Type` (or bare
    /// `Type` in the global namespace). This is the reflection/`using` handle the
    /// generated entry shim calls through.
    pub type_name: String,
    /// Method name.
    pub method: String,
    pub line: u32,
    pub params: Vec<CSharpParam>,
    /// `true` for a `static` method (called as `Type.Method(...)`); `false` for an
    /// instance method (the shim must `new Type()` first).
    pub is_static: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CSharpParam {
    pub name: String,
    pub kind: CSharpParamKind,
    /// The parameter's type spelling as written (whitespace-compacted), e.g.
    /// `ReadOnlySpan<byte>` — the entry shim emits the exact conversion from it.
    pub raw_type: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CSharpParamKind {
    /// `byte[]` — the fuzz bytes, passed straight through.
    Bytes,
    /// `ReadOnlySpan<byte>` / `Span<byte>` / `ReadOnlyMemory<byte>` / `Memory<byte>`
    /// — the fuzz bytes wrapped by the entry shim.
    ByteSpan,
    /// `string` — the fuzz bytes UTF-8-decoded (lenient) by the entry shim.
    Str,
    /// `System.IO.Stream` / `MemoryStream` — a `MemoryStream` over the fuzz bytes.
    Stream,
    /// `int`/`long`/`uint`/... — a length/count/offset operand (driven from the byte
    /// count, or 0 for an offset/index/position by name).
    Int,
    /// `bool` — a synthesizable flag argument (driven to `false`).
    Bool,
    /// Anything else — a defaulted (`default`/`null`) scratch argument.
    Other,
}

impl CSharpMethod {
    /// A method is fuzzable when it has exactly one attacker-controlled input
    /// parameter (a byte buffer, string, or stream) and every *other* parameter is
    /// a synthesizable scalar (an `int`/... length operand). Methods that would
    /// force us to synthesize a reference-type argument (`Other`) are excluded:
    /// passing `null`/`default` for a required options/context object produces a
    /// `NullReferenceException` that is our fault, not a target defect — a
    /// false-positive source. Campaigns can widen this later.
    pub fn is_fuzzable(&self) -> bool {
        let input_params = self
            .params
            .iter()
            .filter(|p| {
                matches!(
                    p.kind,
                    CSharpParamKind::Bytes
                        | CSharpParamKind::ByteSpan
                        | CSharpParamKind::Str
                        | CSharpParamKind::Stream
                )
            })
            .count();
        if input_params != 1 {
            return false;
        }
        self.params.iter().all(|p| {
            matches!(
                p.kind,
                CSharpParamKind::Bytes
                    | CSharpParamKind::ByteSpan
                    | CSharpParamKind::Str
                    | CSharpParamKind::Stream
                    | CSharpParamKind::Int
                    | CSharpParamKind::Bool
            )
        })
    }

    /// Index of the primary input buffer (first byte/span/string/stream param).
    pub fn primary_buffer_index(&self) -> Option<usize> {
        self.params.iter().position(|p| {
            matches!(
                p.kind,
                CSharpParamKind::Bytes
                    | CSharpParamKind::ByteSpan
                    | CSharpParamKind::Str
                    | CSharpParamKind::Stream
            )
        })
    }

    /// `Type.Method` — the display/candidate name (stable across runs).
    pub fn qualified(&self) -> String {
        format!("{}.{}", self.type_name, self.method)
    }
}

/// Strip C# comments (`//` line, `/* */` block) and collapse string/char literals
/// to a placeholder so braces/keywords inside them never confuse the scanner.
/// Returns one normalized string per input line (block comments span lines).
fn normalize(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_block = false;
    for raw in source.lines() {
        let bytes = raw.as_bytes();
        let mut line = String::with_capacity(raw.len());
        let mut i = 0;
        let mut in_str: Option<u8> = None; // Some(b'"') or Some(b'\'')
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
                // Collapse literal content; keep the closing quote so token shape
                // (an argument present) survives.
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
                break; // line comment
            }
            if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
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
        out.push(line);
    }
    out
}

/// The keyword that opens a type body, if `tok` is one.
fn type_keyword(tok: &str) -> bool {
    matches!(tok, "class" | "struct" | "record" | "interface" | "enum")
}

/// Scan C# source for fuzzable methods. A line-oriented parser that tracks the
/// namespace and the enclosing type by brace depth, then recognizes a method
/// signature (a `public` member with a `(param-list)`) declared directly in a
/// type body. Properties (no `()`), constructors (name == type), and local
/// functions (not directly in a type body) are excluded.
pub fn parse_csharp(source: &str) -> Vec<CSharpMethod> {
    let lines = normalize(source);
    let mut methods = Vec::new();

    // File-scoped namespace applies to the whole file.
    let mut file_namespace = String::new();
    // Block scopes maintained in lockstep with brace depth: pushed on `{`, popped
    // on `}`. A method is "directly in a type body" when the innermost scope is a
    // type — that filters local functions, initializers, and statements.
    let mut scopes: Vec<Scope> = Vec::new();
    // A header seen but whose `{` hasn't arrived yet (header and brace can be on
    // different lines).
    let mut pending: Option<Scope> = None;

    for (idx, line) in lines.iter().enumerate() {
        let line_no = (idx + 1) as u32;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // File-scoped namespace: `namespace Foo.Bar;`
        if let Some(rest) = trimmed.strip_prefix("namespace ") {
            let name = rest
                .trim()
                .trim_end_matches(';')
                .trim_end_matches('{')
                .trim();
            if trimmed.ends_with(';') {
                file_namespace = name.to_owned();
                continue;
            }
            // Block namespace header; the `{` may be on this or a later line.
            pending = Some(Scope {
                is_type: false,
                instantiable: false,
                accessible: true,
                name: name.to_owned(),
            });
        } else if let Some(scope) = type_header(trimmed) {
            pending = Some(scope);
        } else if pending.is_none()
            && scopes
                .last()
                .map(|s| s.is_type && s.instantiable)
                .unwrap_or(false)
        {
            // Directly inside an instantiable type body: this may be a method sig.
            if let Some(m) = parse_method_line(trimmed, line_no, &scopes, &file_namespace) {
                methods.push(m);
            }
        }

        // Count braces to maintain scope depth. A single line can open and close.
        for ch in line.bytes() {
            match ch {
                b'{' => {
                    scopes.push(pending.take().unwrap_or(Scope {
                        // An anonymous block (method body, initializer). Non-type so
                        // members inside aren't seen as methods.
                        is_type: false,
                        instantiable: false,
                        accessible: true,
                        name: String::new(),
                    }));
                }
                b'}' => {
                    scopes.pop();
                }
                _ => {}
            }
        }
    }
    methods
}

/// A lexical scope on the brace stack.
#[derive(Clone)]
struct Scope {
    is_type: bool,
    /// `true` for `class`/`struct`/`record` (a type the shim can `new` and whose
    /// methods have bodies); `false` for `interface`/`enum` (no fuzzable member) and
    /// for non-type scopes.
    instantiable: bool,
    /// Whether this type is externally visible (declared `public`). A top-level type
    /// defaults to `internal` and a nested type to `private` — neither is reachable
    /// from the generated harness (a separate assembly), so a `public` method of a
    /// non-`public` class fails to compile with CS0122. Non-type scopes are `true`.
    accessible: bool,
    name: String,
}

/// Parse a type header (`... class Name ...`, struct/record/interface/enum),
/// returning the scope to push. Returns `None` if the line isn't a type header.
fn type_header(line: &str) -> Option<Scope> {
    // Tokenize up to `{`, `(`, `:`, or `;`.
    let head: String = line
        .chars()
        .take_while(|&c| c != '{' && c != '(' && c != ';')
        .collect();
    // Split off a base-list (`: Base`) — keep only the declaration part.
    let decl = head.split(':').next().unwrap_or(&head);
    let toks: Vec<&str> = decl.split_whitespace().collect();
    let kw_pos = toks.iter().position(|t| type_keyword(t))?;
    // `record class`/`record struct` — the name follows the last type keyword.
    let mut name_pos = kw_pos + 1;
    if toks.get(kw_pos) == Some(&"record")
        && matches!(toks.get(kw_pos + 1), Some(&"class") | Some(&"struct"))
    {
        name_pos = kw_pos + 2;
    }
    let name = toks.get(name_pos)?;
    // Strip generic parameters `<T>` from the name.
    let bare: String = name.chars().take_while(|&c| c != '<').collect();
    if !is_ident(&bare) {
        return None;
    }
    // enum/interface bodies hold no fuzzable methods with bodies, but we still push
    // a type scope so nested members are correctly attributed / skipped.
    let kw = toks[kw_pos];
    Some(Scope {
        is_type: true,
        instantiable: matches!(kw, "class" | "struct" | "record"),
        // Externally reachable only when declared `public` (top-level types default to
        // `internal`, nested to `private` — both invisible to the harness assembly).
        accessible: toks.contains(&"public"),
        name: bare,
    })
}

/// A parsed method signature line inside a type body → a `CSharpMethod`.
fn parse_method_line(
    line: &str,
    line_no: u32,
    scopes: &[Scope],
    file_namespace: &str,
) -> Option<CSharpMethod> {
    // Must look like a member declaration with a parameter list.
    let open = line.find('(')?;
    let before = &line[..open];
    let toks: Vec<&str> = before.split_whitespace().collect();
    if toks.len() < 2 {
        return None; // need at least a return type + name (public omitted still needs 2)
    }
    // Require `public` — the callable surface. (internal/private methods are not a
    // stable external fuzz surface; campaigns can widen this later.)
    if !toks.contains(&"public") {
        return None;
    }
    // Every enclosing type must ALSO be externally visible: a `public` method of an
    // `internal`/`private` class is unreachable from the harness assembly and fails to
    // compile (CS0122), a confusing failed_build and a false attacker-reachability
    // claim (Tomlyn's `internal static class TomlKeyValidation.IsValidKeyName`).
    if scopes.iter().any(|s| s.is_type && !s.accessible) {
        return None;
    }
    // Exclude abstract/partial/extern declarations without a body and delegates.
    if toks
        .iter()
        .any(|t| matches!(*t, "delegate" | "abstract" | "event"))
    {
        return None;
    }
    let is_static = toks.contains(&"static");
    // The method name is the token immediately before `(`.
    let name_tok = *toks.last()?;
    // Skip generic methods (`Foo<T>`) — the entry shim can't supply type arguments,
    // so calling `Foo(args)` would not compile / would fail inference.
    if name_tok.contains('<') {
        return None;
    }
    let method: String = name_tok.to_owned();
    if method.is_empty() || !is_ident(&method) {
        return None;
    }
    // The token before the name is (part of) the return type; a constructor has no
    // return type, so the token before the name would be a modifier/type keyword
    // equal to the enclosing type name. Exclude constructors and operators.
    let type_name_full = qualified_type(scopes, file_namespace);
    let type_leaf = scopes
        .iter()
        .rev()
        .find(|s| s.is_type)
        .map(|s| s.name.as_str())
        .unwrap_or("");
    if method == type_leaf {
        return None; // constructor
    }
    if name_tok.starts_with("operator") || toks.contains(&"operator") {
        return None;
    }
    // Require an explicit return type token (`void`/type) between `public`/mods and
    // the name — filters property accessors and stray lines. The token just before
    // the name must not itself be a modifier keyword.
    let ret = toks[toks.len() - 2];
    if matches!(
        ret,
        "public"
            | "static"
            | "private"
            | "internal"
            | "protected"
            | "sealed"
            | "virtual"
            | "override"
            | "async"
            | "unsafe"
            | "new"
            | "readonly"
    ) {
        return None;
    }

    // Extract the parameter list (balanced to the matching `)`).
    let params_str = balanced_params(&line[open..])?;
    let params = parse_params(&params_str);

    let namespace = root_namespace(&type_name_full);
    Some(CSharpMethod {
        namespace,
        type_name: type_name_full,
        method,
        line: line_no,
        params,
        is_static,
    })
}

/// The `(...)` content of a signature, balanced across nested generics/tuples.
fn balanced_params(from_open_paren: &str) -> Option<String> {
    let b = from_open_paren.as_bytes();
    if b.first() != Some(&b'(') {
        return None;
    }
    let mut depth = 0i32;
    let mut end = None;
    for (i, &c) in b.iter().enumerate() {
        match c {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let end = end?;
    Some(from_open_paren[1..end].to_owned())
}

/// Split a parameter list at top-level commas (not inside `<...>` or `(...)`),
/// classify each parameter's type.
fn parse_params(s: &str) -> Vec<CSharpParam> {
    let s = s.trim();
    if s.is_empty() {
        return Vec::new();
    }
    let mut params = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '<' | '(' | '[' => {
                depth += 1;
                cur.push(c);
            }
            '>' | ')' | ']' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => {
                params.push(classify_param(&cur));
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        params.push(classify_param(&cur));
    }
    params
}

fn classify_param(raw: &str) -> CSharpParam {
    // Drop a default value.
    let no_default = raw.split('=').next().unwrap_or(raw).trim();
    // Drop leading modifiers.
    let mut toks: Vec<&str> = no_default.split_whitespace().collect();
    while let Some(first) = toks.first() {
        if matches!(
            *first,
            "this" | "ref" | "out" | "in" | "params" | "scoped" | "readonly"
        ) {
            toks.remove(0);
        } else {
            break;
        }
    }
    if toks.len() < 2 {
        // No name (e.g. bad parse) — treat the whole thing as the type.
        let ty = toks.first().copied().unwrap_or("");
        return CSharpParam {
            name: String::new(),
            kind: classify_type(ty),
            raw_type: compact_type(ty),
        };
    }
    let name = (*toks.last().unwrap()).to_owned();
    let ty = toks[..toks.len() - 1].join(" ");
    CSharpParam {
        name,
        kind: classify_type(&ty),
        raw_type: compact_type(&ty),
    }
}

/// Whitespace-compacted type spelling (drops spaces inside generics), used by the
/// entry-shim generator to emit the exact static conversion.
fn compact_type(ty: &str) -> String {
    ty.trim().chars().filter(|c| !c.is_whitespace()).collect()
}

/// Classify a C# type spelling into a parameter kind.
fn classify_type(ty: &str) -> CSharpParamKind {
    let t = ty.trim().trim_end_matches('?'); // nullable
                                             // Normalize whitespace inside generics: `ReadOnlySpan < byte >`.
    let compact: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    let leaf = compact.rsplit('.').next().unwrap_or(&compact);
    if leaf == "byte[]" || leaf == "Byte[]" {
        return CSharpParamKind::Bytes;
    }
    if matches!(
        leaf,
        "ReadOnlySpan<byte>"
            | "Span<byte>"
            | "ReadOnlyMemory<byte>"
            | "Memory<byte>"
            | "ReadOnlySpan<Byte>"
            | "Span<Byte>"
    ) {
        return CSharpParamKind::ByteSpan;
    }
    if leaf == "string" || leaf == "String" {
        return CSharpParamKind::Str;
    }
    if leaf == "Stream" || leaf == "MemoryStream" || leaf == "UnmanagedMemoryStream" {
        return CSharpParamKind::Stream;
    }
    if matches!(
        leaf,
        "int"
            | "uint"
            | "long"
            | "ulong"
            | "short"
            | "ushort"
            | "nint"
            | "nuint"
            | "Int32"
            | "UInt32"
            | "Int64"
            | "UInt64"
    ) {
        return CSharpParamKind::Int;
    }
    if leaf == "bool" || leaf == "Boolean" {
        return CSharpParamKind::Bool;
    }
    CSharpParamKind::Other
}

/// Fully-qualified declaring type name from the scope stack + file namespace.
fn qualified_type(scopes: &[Scope], file_namespace: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if !file_namespace.is_empty() {
        parts.push(file_namespace);
    }
    for s in scopes {
        if !s.name.is_empty() {
            parts.push(&s.name);
        }
    }
    parts.join(".")
}

/// The root (first) namespace segment of a fully-qualified type. For a global-
/// namespace type (no dots, and no file namespace) this is `""`.
fn root_namespace(fqn: &str) -> String {
    // The namespace is everything up to the first *type* segment; we can't tell
    // namespace vs type boundaries syntactically, so use the first segment as the
    // root package handle (mirrors Python's top-level-package heuristic).
    match fqn.split_once('.') {
        Some((root, _)) => root.to_owned(),
        None => String::new(),
    }
}

fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_static_byte_array_method() {
        let src = "\
namespace Acme.Parsing {
  public class JsonReader {
    public static object Parse(byte[] data) {
      return null;
    }
  }
}
";
        let m = &parse_csharp(src)[0];
        assert_eq!(m.type_name, "Acme.Parsing.JsonReader");
        assert_eq!(m.method, "Parse");
        assert_eq!(m.namespace, "Acme");
        assert!(m.is_static);
        assert!(m.is_fuzzable());
        assert_eq!(m.params[0].kind, CSharpParamKind::Bytes);
        assert_eq!(m.primary_buffer_index(), Some(0));
        assert_eq!(m.qualified(), "Acme.Parsing.JsonReader.Parse");
    }

    #[test]
    fn public_method_of_internal_class_is_not_discovered() {
        // Tomlyn shape: a `public` method on an `internal`/`private`/default class is
        // unreachable from the harness assembly (CS0122) — must be skipped, not offered
        // as attacker-reachable and then failed_build.
        let src = "\
namespace Lib;
internal static class KeyValidation {
  public static bool IsValidKeyName(string key) { return key.Length > 0; }
}
public static class PublicApi {
  public static bool Check(string s) { return s.Length > 0; }
}
class DefaultInternal {
  public static bool Also(string s) { return true; }
}
public class Outer {
  private class Nested {
    public static bool Hidden(string s) { return true; }
  }
  public static bool Reachable(string s) { return true; }
}
";
        let methods = parse_csharp(src);
        let names: Vec<&str> = methods.iter().map(|m| m.method.as_str()).collect();
        assert!(names.contains(&"Check"), "public class method must remain");
        assert!(
            names.contains(&"Reachable"),
            "public nested-in-public method must remain"
        );
        assert!(
            !names.contains(&"IsValidKeyName"),
            "internal-class method leaked"
        );
        assert!(
            !names.contains(&"Also"),
            "default-internal-class method leaked"
        );
        assert!(
            !names.contains(&"Hidden"),
            "private-nested-class method leaked"
        );
    }

    #[test]
    fn file_scoped_namespace_and_span() {
        let src = "\
namespace Lib;
public class P {
  public void Feed(ReadOnlySpan<byte> input) { }
}
";
        let m = &parse_csharp(src)[0];
        assert_eq!(m.type_name, "Lib.P");
        assert_eq!(m.namespace, "Lib");
        assert!(!m.is_static);
        assert_eq!(m.params[0].kind, CSharpParamKind::ByteSpan);
    }

    #[test]
    fn string_and_stream_and_int() {
        let src = "\
namespace X {
  public class Y {
    public static void A(string s) { }
    public static void B(Stream st) { }
    public static void C(byte[] b, int n) { }
  }
}
";
        let ms = parse_csharp(src);
        assert_eq!(ms.len(), 3);
        assert_eq!(ms[0].params[0].kind, CSharpParamKind::Str);
        assert_eq!(ms[1].params[0].kind, CSharpParamKind::Stream);
        assert_eq!(ms[2].params[0].kind, CSharpParamKind::Bytes);
        assert_eq!(ms[2].params[1].kind, CSharpParamKind::Int);
    }

    #[test]
    fn excludes_constructor_property_and_non_fuzzable() {
        let src = "\
namespace X {
  public class Y {
    public Y(byte[] data) { }        // constructor - excluded
    public int Count { get; set; }   // property - no ()
    public static void Z(int n) { }  // no input channel
  }
}
";
        let ms = parse_csharp(src);
        // Only Z is a method with (), but it's not fuzzable.
        let fuzzable: Vec<_> = ms.iter().filter(|m| m.is_fuzzable()).collect();
        assert!(fuzzable.is_empty());
        // The constructor must not be discovered as a method named "Y".
        assert!(ms.iter().all(|m| m.method != "Y"));
    }

    #[test]
    fn excludes_local_function() {
        let src = "\
namespace X {
  public class Y {
    public static void Outer(byte[] data) {
      void Inner(byte[] x) { }
      Inner(data);
    }
  }
}
";
        let ms = parse_csharp(src);
        // Only Outer is directly in the type body; Inner is a local function.
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].method, "Outer");
    }

    #[test]
    fn global_namespace_type() {
        let src = "\
public class Top {
  public static void Run(byte[] data) { }
}
";
        let m = &parse_csharp(src)[0];
        assert_eq!(m.type_name, "Top");
        assert_eq!(m.namespace, "");
        assert!(m.is_fuzzable());
    }

    #[test]
    fn nested_type_qualified_name() {
        let src = "\
namespace A.B {
  public class Outer {
    public class Inner {
      public static void P(byte[] d) { }
    }
  }
}
";
        let m = &parse_csharp(src)[0];
        assert_eq!(m.type_name, "A.B.Outer.Inner");
        assert_eq!(m.namespace, "A");
    }

    #[test]
    fn memory_and_nullable_string() {
        assert_eq!(classify_type("Memory<byte>"), CSharpParamKind::ByteSpan);
        assert_eq!(classify_type("string?"), CSharpParamKind::Str);
        assert_eq!(classify_type("System.IO.Stream"), CSharpParamKind::Stream);
        assert_eq!(classify_type("System.Byte[]"), CSharpParamKind::Bytes);
    }
}
