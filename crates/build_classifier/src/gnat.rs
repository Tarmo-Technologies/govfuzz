// SPDX-License-Identifier: Apache-2.0

use crate::BuildErrorKind;
use regex::Regex;
use std::sync::OnceLock;

/// #100: whether `symbol` is an Ada reserved word or a standard literal
/// (`True`/`False`/`null`) — a token that can never be a missing user-defined
/// callable symbol, so it must never become a `MissingAdaSymbol` stub proposal.
/// Ada identifiers are case-insensitive, so the comparison is lower-cased.
fn is_ada_reserved_or_literal(symbol: &str) -> bool {
    // A dotted selected name (`Object.Ref`) is not a bare literal — only reject a
    // simple name here; selected names are resolved by the repair planner.
    if symbol.contains('.') {
        return false;
    }
    const RESERVED: &[&str] = &[
        // Standard boolean/access literals (enumeration literals + the null keyword).
        "true",
        "false",
        "null", //
        // Ada 2012 reserved words.
        "abort",
        "abs",
        "abstract",
        "accept",
        "access",
        "aliased",
        "all",
        "and",
        "array",
        "at",
        "begin",
        "body",
        "case",
        "constant",
        "declare",
        "delay",
        "delta",
        "digits",
        "do",
        "else",
        "elsif",
        "end",
        "entry",
        "exception",
        "exit",
        "for",
        "function",
        "generic",
        "goto",
        "if",
        "in",
        "interface",
        "is",
        "limited",
        "loop",
        "mod",
        "new",
        "not",
        "of",
        "or",
        "others",
        "out",
        "overriding",
        "package",
        "pragma",
        "private",
        "procedure",
        "protected",
        "raise",
        "range",
        "record",
        "rem",
        "renames",
        "requeue",
        "return",
        "reverse",
        "select",
        "separate",
        "some",
        "subtype",
        "synchronized",
        "tagged",
        "task",
        "terminate",
        "then",
        "type",
        "until",
        "use",
        "when",
        "while",
        "with",
        "xor",
    ];
    let lower = symbol.to_ascii_lowercase();
    RESERVED.contains(&lower.as_str())
}

pub fn classify_into(stderr: &str, hits: &mut Vec<BuildErrorKind>) {
    for line in stderr.lines() {
        if let Some(caps) = file_not_found().captures(line) {
            // captured is "foo.ads" or "bar.adb"; the unit name is the
            // stem with dots preserved (Ada style: dots become dashes
            // on disk so "Demo.Parser" -> demo-parser.ads).
            let path = &caps[1];
            let unit = path
                .strip_suffix(".ads")
                .or_else(|| path.strip_suffix(".adb"))
                .unwrap_or(path)
                .replace('-', ".");
            hits.push(BuildErrorKind::MissingAdaWith { unit });
            continue;
        }
        if let Some(caps) = is_undefined().captures(line) {
            // #100: never treat an Ada reserved word or standard literal
            // (True/False/null, keywords, operators) as a missing CALLABLE symbol.
            // GNAT reporting one as "undefined" signals a visibility/syntax error,
            // not a symbol to stub — a stub cannot recover a valid program and only
            // buries the real diagnostic. Leave the raw line for the Other tail.
            if is_ada_reserved_or_literal(&caps[1]) {
                continue;
            }
            // Best-effort: GNAT doesn't always print the unit context.
            // Use empty string and let the auto loop disambiguate via
            // the harness's own package.
            hits.push(BuildErrorKind::MissingAdaSymbol {
                unit: String::new(),
                symbol: caps[1].to_owned(),
            });
            continue;
        }
        if let Some(caps) = not_declared_in().captures(line) {
            // #100: same rejection — a reserved word/literal "not declared in P" is
            // never a missing symbol; do not propose a stub for it.
            if is_ada_reserved_or_literal(&caps[1]) {
                continue;
            }
            hits.push(BuildErrorKind::MissingAdaSymbol {
                unit: caps[2].to_owned(),
                symbol: caps[1].to_owned(),
            });
            continue;
        }
        if let Some(caps) = missing_body().captures(line) {
            hits.push(BuildErrorKind::MissingAdaPackageBody {
                unit: caps[1].to_owned(),
            });
            continue;
        }
        if let Some(caps) = cannot_generate_code().captures(line) {
            // "cannot generate code for file <unit>.ads (package spec)"
            // — gprbuild's way of saying the spec was found but no
            // body was supplied. Strip the .ads suffix and normalise
            // dashes to dots to match the unit name a `with` clause
            // would have used.
            let path = &caps[1];
            let unit = path.strip_suffix(".ads").unwrap_or(path).replace('-', ".");
            hits.push(BuildErrorKind::MissingAdaPackageBody { unit });
            continue;
        }
        if let Some(caps) = cannot_find_gpr().captures(line) {
            // Either flavour matched — take whichever group captured the name.
            let path = caps
                .get(1)
                .or_else(|| caps.get(2))
                .map(|m| m.as_str().to_owned())
                .unwrap_or_default();
            if !path.is_empty() {
                hits.push(BuildErrorKind::MissingGprImport { path });
                continue;
            }
        }
        if let Some(caps) = uncompilable_asm().captures(line) {
            // `<file>.adb:NN: Error: no such instruction: ...` — the assembler
            // rejected target-specific inline machine code on this host.
            hits.push(BuildErrorKind::UncompilableAdaBody {
                source: caps[1].to_owned(),
            });
            continue;
        }
        if let Some(caps) = missing_return_body().captures(line) {
            // `<file>.adb:NN:CC: error: missing "return" statement in function
            // body` — a bare-metal intrinsic that returns a value through an asm
            // output register with no Ada `return` (bb-runtimes' `mrs`-based
            // accessors). The body won't compile as written; stub it.
            hits.push(BuildErrorKind::UncompilableAdaBody {
                source: caps[1].to_owned(),
            });
            continue;
        }
    }
}

/// Assembler errors from target-specific inline machine code compiled on the
/// wrong host (bb-runtimes ARM `mcr p15` / AArch64 `mrs ... el1` built on x86).
/// Captures the `.adb` path so the body can be stubbed.
fn uncompilable_asm() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r#"(?m)^(\S+\.adb):\d+: +Error: +(?:no such instruction|junk .* after expression|unknown pseudo-op|bad register|operand .* (?:out of range|mismatch)|invalid operand)"#,
        )
        .expect("regex")
    })
}

/// A function body that lacks a `return` (an intrinsic returning via an asm
/// output register). Captures the `.adb` path so the body can be stubbed.
fn missing_return_body() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"(?mi)^(\S+\.adb):\d+:\d+: +error: +missing "return" statement"#)
            .expect("regex")
    })
}

fn file_not_found() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"file "(.+?\.ad[sb])" not found"#).expect("regex"))
}

fn is_undefined() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#""([A-Za-z_][A-Za-z0-9_.]*)" is undefined"#).expect("regex"))
}

fn not_declared_in() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r#""([A-Za-z_][A-Za-z0-9_.]*)"\s+not\s+declared\s+in\s+(?:package\s+)?"([A-Za-z_][A-Za-z0-9_.]*)""#,
        )
        .expect("regex")
    })
}

fn missing_body() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"missing body for unit "([A-Za-z_][A-Za-z0-9_.]*)""#).expect("regex")
    })
}

fn cannot_generate_code() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"cannot generate code for file (\S+\.ads) \(package spec\)"#).expect("regex")
    })
}

fn cannot_find_gpr() -> &'static Regex {
    // gprbuild emits the missing-import error in several flavours; the imported
    // name may or may not carry the `.gpr` extension depending on how the `with`
    // clause spelled it:
    //   demo.gpr:5:09: cannot find "gnatcoll.gpr"
    //   govfuzz_build.gpr:3:06: imported project file "missing.gpr" not found
    //   spat.gpr:1:06: imported project file "gnatcoll" not found   (no extension)
    // Group 1 = the `cannot find "<x>.gpr"` name; group 2 = the
    // `imported project file "<x>" not found` name (extension optional).
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"(?:cannot find "(.+?\.gpr)")|(?:imported project file "([^"]+?)" not found)"#)
            .expect("regex")
    })
}
