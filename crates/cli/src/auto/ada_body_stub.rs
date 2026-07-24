// SPDX-License-Identifier: Apache-2.0

//! Force-fuzz: synthesize a trivial *body* for a project unit whose real body
//! can't compile offline.
//!
//! Some project unit bodies are unbuildable without a missing external library —
//! e.g. `spat.adb` instantiates the missing generic `SI_Units.Metric.Fixed_Image`
//! and `with`s an unstubbable command-line package. Yet that body is dragged into
//! *every* target's build because it is the parent body of a package whose spec
//! declares subprograms (so a body is mandatory). The body's own code is almost
//! never on the fuzz target's call path.
//!
//! Under `--force` we replace such a body with a minimal one synthesized from the
//! (compilable) SPEC: every body-requiring subprogram gets a `raise Program_Error`
//! implementation. The stub compiles (no return value to construct, and it copies
//! only the spec's context clauses — dropping the body's problematic `with`s), and
//! since the fuzz target never calls those subprograms the raise never fires.
//!
//! Dialect note: the body is synthesized under the SAME `-gnatXXXX` the build
//! settled on (the legacy-dialect ladder in `crate::auto::attempt` may drop below
//! Ada 2012). For a function, Ada 2012+ uses a raise EXPRESSION (`return raise
//! ...`, any type, so no return value must be constructed for limited /
//! class-wide / indefinite returns); older standards raise then fall into an
//! UNREACHABLE recursive `return` (valid since Ada 83). The suppress-marker
//! message requires Ada 2005+. See [`stub_raise_body`].

use std::path::Path;

use ada_parser::ast::AdaStandard;

/// The raise statement(s) for a synthesized stub subprogram body, valid under
/// `standard`. A procedure always uses a plain `raise`. A function needs a
/// syntactic `return`: Ada 2012+ uses a raise EXPRESSION (`return raise ...`, any
/// type, no value constructed); older standards raise then fall into an
/// UNREACHABLE recursive `return` (valid since Ada 83). The suppress-marker
/// message requires Ada 2005+.
fn stub_raise_body(
    is_function: bool,
    recursive_call: Option<&str>,
    standard: AdaStandard,
) -> String {
    let marker = if standard >= AdaStandard::Ada2005 {
        format!(" with \"{STUB_RAISE_MARKER}\"")
    } else {
        String::new()
    };
    if !is_function {
        return format!("      raise Program_Error{marker};\n");
    }
    if standard >= AdaStandard::Ada2012 {
        return format!("      return raise Program_Error{marker};\n");
    }
    let call = recursive_call.unwrap_or("raise Program_Error");
    format!("      raise Program_Error{marker};\n      return {call};\n")
}

/// Ada `Exception_Message` a synthesized stub body raises with, so the crash
/// oracle can recognize (and suppress) a fault that is merely a fuzz target
/// reaching one of these placeholder bodies rather than a genuine defect.
pub const STUB_RAISE_MARKER: &str = "GOVFUZZ_STUB_BODY";

/// A synthesized stub body plus the lowercased names of the subprograms it
/// actually implemented (so the caller can tell whether a fuzz target's own
/// body would be replaced by a `raise` — which must be avoided).
pub struct StubBody {
    pub text: String,
    pub implemented: std::collections::BTreeSet<String>,
}

/// Synthesize a trivial package body from a package SPEC source, valid under the
/// build's `standard`. Returns `None` if the spec has no package unit or declares
/// nothing requiring a body.
pub fn synth_stub_body(spec_source: &str, path: &Path, standard: AdaStandard) -> Option<StubBody> {
    let ast = ada_parser::reconcile::build_structural_ast(spec_source, None, path).ok()?;
    let package_name = spec_package_name(spec_source)?;

    let mut bodies = String::new();
    let mut implemented = std::collections::BTreeSet::new();
    for sp in &ast.subprograms {
        // A completion already exists (expression function / the parser found an
        // inline body), or no body is legal/needed.
        if sp.body_span.is_some() || sp.is_abstract || sp.is_generic {
            continue;
        }
        let (start, end) = (
            sp.decl_span.start_byte as usize,
            sp.decl_span.end_byte as usize,
        );
        if start >= end || end > spec_source.len() {
            continue;
        }
        let decl = spec_source[start..end].trim();
        let low = decl.to_ascii_lowercase();
        // Renamings, expression functions, `is null`, `is abstract`, `is <>` all
        // carry their own completion — a separate body would duplicate it. Match
        // `renames`/`is` as whole tokens so multi-line spans (a `renames` at
        // end-of-line) and identifiers containing them are handled correctly.
        if contains_word(&low, "renames") || contains_word(&low, "is") {
            continue;
        }
        let profile = strip_aspects(decl.trim_end_matches(';').trim_end());
        // For a pre-2012 function the raise-expression form is unavailable, so an
        // unreachable recursive call supplies the mandatory `return`; build it from
        // the parsed formal names.
        let recursive = sp.return_type.is_some().then(|| {
            let actuals: Vec<&str> = sp.params.iter().map(|p| p.name.as_str()).collect();
            if actuals.is_empty() {
                sp.name.clone()
            } else {
                format!("{} ({})", sp.name, actuals.join(", "))
            }
        });
        bodies.push_str("   ");
        bodies.push_str(profile);
        bodies.push_str(" is\n   begin\n");
        bodies.push_str(&stub_raise_body(
            sp.return_type.is_some(),
            recursive.as_deref(),
            standard,
        ));
        bodies.push_str("   end;\n");
        implemented.insert(sp.name.to_ascii_lowercase());
    }
    // Operator functions (`function "<" (...) return ...`) are not surfaced by the
    // structural parser; scan the spec text for their declarations so the stub
    // body completes them too (otherwise: `missing body for "<"`).
    let (op_bodies, op_names) = synth_operator_bodies(spec_source, standard);
    bodies.push_str(&op_bodies);
    implemented.extend(op_names);

    if bodies.is_empty() {
        return None;
    }

    let mut out = String::new();
    out.push_str("--  SPDX-License-Identifier: Apache-2.0\n");
    out.push_str("--  Force-fuzz stub body for an offline-unbuildable project unit.\n");
    for clause in context_clauses(spec_source) {
        out.push_str(&clause);
        out.push('\n');
    }
    out.push_str(&format!("package body {package_name} is\n"));
    out.push_str(&bodies);
    out.push_str(&format!("end {package_name};\n"));
    Some(StubBody {
        text: out,
        implemented,
    })
}

/// The spec's context clauses, adapted so the stub body sees the same external
/// units its profiles name. `limited with` / `private with` become a plain `with`
/// (a body may not carry those forms). `use type` / `use all type` clauses are
/// dropped — they make a *specific* (often private-part) type directly visible and
/// are neither needed by nor legal at the body's context-clause position; the
/// verbatim profiles keep whatever qualification the spec used.
fn context_clauses(spec_source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in spec_source.lines() {
        let line = match raw.find("--") {
            Some(i) => &raw[..i],
            None => raw,
        };
        let t = line.trim();
        let low = t.to_ascii_lowercase();
        if let Some(rest) = low
            .strip_prefix("limited with ")
            .or_else(|| low.strip_prefix("private with "))
        {
            out.push(format!("with {}", t[t.len() - rest.len()..].trim_start()));
        } else if low.starts_with("with ") {
            out.push(t.to_owned());
        } else if low.starts_with("use type ") || low.starts_with("use all type ") {
            // dropped — see doc comment
        } else if low.starts_with("use ") {
            out.push(t.to_owned());
        }
    }
    out
}

/// The fully-qualified name from a spec's `package <Name> is` declaration.
fn spec_package_name(spec_source: &str) -> Option<String> {
    for raw in spec_source.lines() {
        let line = match raw.find("--") {
            Some(i) => &raw[..i],
            None => raw,
        };
        let t = line.trim();
        let low = t.to_ascii_lowercase();
        let prefix_len = if low.starts_with("package ") {
            "package ".len()
        } else if low.starts_with("private package ") {
            "private package ".len()
        } else {
            continue;
        };
        let name: String = t[prefix_len..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.')
            .collect();
        if !name.is_empty() {
            return Some(name);
        }
    }
    None
}

/// Text-scan for operator function declarations the structural parser misses
/// (`function "<" (...) return T;`). Returns the raise-bodies plus the lowercased
/// operator names (with quotes) it implemented. Skips operator expression
/// functions / renamings (which already carry a completion).
fn synth_operator_bodies(
    spec_source: &str,
    standard: AdaStandard,
) -> (String, std::collections::BTreeSet<String>) {
    let stripped: String = spec_source
        .lines()
        .map(|l| match l.find("--") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n");
    let bytes = stripped.as_bytes();
    let mut out = String::new();
    let mut names = std::collections::BTreeSet::new();
    let mut search = 0;
    while let Some(rel) = stripped[search..].find("function \"") {
        let fstart = search + rel;
        // Find the `;` terminating this declaration at paren depth 0.
        let mut depth: i32 = 0;
        let mut end = None;
        let mut j = fstart;
        while j < bytes.len() {
            match bytes[j] {
                b'(' => depth += 1,
                b')' => depth -= 1,
                b';' if depth == 0 => {
                    end = Some(j);
                    break;
                }
                _ => {}
            }
            j += 1;
        }
        let Some(end) = end else { break };
        let decl = stripped[fstart..end].trim();
        search = end + 1;
        let low = decl.to_ascii_lowercase();
        if contains_word(&low, "is") || contains_word(&low, "renames") {
            continue;
        }
        let profile = strip_aspects(decl);
        // Operators are always functions; a pre-2012 recursive `return` reuses the
        // operator applied to its own formals (`"<" (Left, Right)`).
        let recursive = operator_recursive_call(profile);
        out.push_str("   ");
        out.push_str(profile);
        out.push_str(" is\n   begin\n");
        out.push_str(&stub_raise_body(true, recursive.as_deref(), standard));
        out.push_str("   end;\n");
        if let Some(op) = decl.split('"').nth(1) {
            names.insert(format!("\"{}\"", op.to_ascii_lowercase()));
        }
    }
    (out, names)
}

/// Build the unreachable recursive call for a pre-2012 operator stub body:
/// `"<" (Left, Right)` from `function "<" (Left, Right : in T) return Boolean`.
fn operator_recursive_call(profile: &str) -> Option<String> {
    let op = format!("\"{}\"", profile.split('"').nth(1)?);
    let open = profile.find('(')?;
    let bytes = profile.as_bytes();
    let mut depth: i32 = 0;
    let mut close = None;
    for (i, &b) in bytes[open..].iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(open + i);
                    break;
                }
            }
            _ => {}
        }
    }
    let params = &profile[open + 1..close?];
    let mut actuals = Vec::new();
    for group in params.split(';') {
        let names_part = group.split(':').next().unwrap_or("");
        for name in names_part.split(',') {
            let n = name.trim();
            if !n.is_empty() {
                actuals.push(n.to_owned());
            }
        }
    }
    if actuals.is_empty() {
        Some(op)
    } else {
        Some(format!("{op} ({})", actuals.join(", ")))
    }
}

/// Strip a subprogram declaration's aspect specification (`... with Pre => ...`,
/// `with Inline`, etc.) so the synthesized body carries only the profile. Aspects
/// belong on the declaration; repeating them on the body is illegal. The aspect
/// mark is the first top-level ` with ` following the profile, so cut there.
fn strip_aspects(profile: &str) -> &str {
    // Find ` with ` as a whole-word token at paren depth 0 (aspects are outside
    // the parameter list / any expression parens).
    let bytes = profile.as_bytes();
    let mut depth: i32 = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b'w' | b'W' if depth == 0 => {
                let before_ok = i == 0 || bytes[i - 1].is_ascii_whitespace();
                let rest = &profile[i..];
                if before_ok
                    && rest.len() >= 5
                    && rest[..4].eq_ignore_ascii_case("with")
                    && rest.as_bytes()[4].is_ascii_whitespace()
                {
                    return profile[..i].trim_end();
                }
            }
            _ => {}
        }
        i += 1;
    }
    profile
}

/// Whether `haystack` contains `word` as a standalone token (space-delimited).
fn contains_word(haystack: &str, word: &str) -> bool {
    haystack
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|tok| tok == word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthesizes_raise_bodies_and_skips_expression_and_renaming() {
        let spec = "with GNATCOLL.JSON;\n\
                    package SPAT is\n\
                    function Image (Value : Duration) return String;\n\
                    procedure Go (X : Integer);\n\
                    function Ren (S : String) return String renames Image;\n\
                    function Expr (X : Integer) return Integer is (X + 1);\n\
                    end SPAT;\n";
        let stub =
            synth_stub_body(spec, Path::new("spat.ads"), AdaStandard::Ada2022).expect("body");
        let body = &stub.text;
        assert!(body.contains("package body SPAT is"), "{body}");
        assert!(
            body.contains("with GNATCOLL.JSON;"),
            "copies context clause: {body}"
        );
        assert!(
            body.contains("function Image (Value : Duration) return String is"),
            "verbatim profile + body: {body}"
        );
        assert!(body.contains("procedure Go (X : Integer) is"), "{body}");
        // Function bodies use an Ada 2012 raise expression (no value to build);
        // procedures use a plain raise statement. Both carry the suppress marker.
        assert!(
            body.contains(&format!(
                "return raise Program_Error with \"{STUB_RAISE_MARKER}\";"
            )),
            "function raise expr + marker: {body}"
        );
        assert!(
            body.contains(&format!(
                "raise Program_Error with \"{STUB_RAISE_MARKER}\";\n   end;"
            )),
            "procedure raise stmt + marker: {body}"
        );
        // Renaming and expression function must NOT get a duplicate body.
        assert!(!body.contains("function Ren"), "skips renaming: {body}");
        assert!(
            !body.contains("function Expr"),
            "skips expression fn: {body}"
        );
        // Reports the implemented subprograms (for target-body protection); the
        // renaming and expression function are NOT implemented here.
        assert!(stub.implemented.contains("image"), "{:?}", stub.implemented);
        assert!(stub.implemented.contains("go"), "{:?}", stub.implemented);
        assert!(!stub.implemented.contains("expr"), "{:?}", stub.implemented);
    }

    #[test]
    fn pre_2012_function_uses_recursive_return_not_a_raise_expression() {
        // Under Ada 95 (no raise expression, no exception message) a function stub
        // raises then falls into an UNREACHABLE recursive `return`, and an operator
        // recurses on its own formals. Procedures stay a plain raise.
        let spec = "package P is\n\
                    function Image (Value : Duration) return String;\n\
                    procedure Go (X : Integer);\n\
                    function \"<\" (Left : T; Right : T) return Boolean;\n\
                    end P;\n";
        let stub = synth_stub_body(spec, Path::new("p.ads"), AdaStandard::Ada95).expect("body");
        let body = &stub.text;
        assert!(
            !body.contains("return raise Program_Error"),
            "no raise expression pre-2012: {body}"
        );
        assert!(
            !body.contains(" with \""),
            "no exception message pre-2005: {body}"
        );
        // Parser-sourced names are lowercased (Ada is case-insensitive, so the
        // recursive call still resolves); operator formals keep their spelling.
        assert!(
            body.contains("raise Program_Error;\n      return image (value);"),
            "function recursive return: {body}"
        );
        assert!(
            body.contains("raise Program_Error;\n      return \"<\" (Left, Right);"),
            "operator recursive return: {body}"
        );
        assert!(
            body.contains("procedure Go (X : Integer) is\n   begin\n      raise Program_Error;\n"),
            "procedure plain raise: {body}"
        );
    }
}
