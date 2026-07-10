// SPDX-License-Identifier: Apache-2.0

use crate::BuildErrorKind;
use regex::Regex;
use std::sync::OnceLock;

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
            hits.push(BuildErrorKind::MissingGprImport {
                path: caps[1].to_owned(),
            });
            continue;
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
    // gprbuild emits the missing-import error in two flavours:
    //   demo.gpr:5:09: cannot find "gnatcoll.gpr"
    //   govfuzz_build.gpr:3:06: imported project file "missing.gpr" not found
    // Match either with a single regex.
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"(?:cannot find|imported project file) "(.+?\.gpr)"(?: not found)?"#)
            .expect("regex")
    })
}
