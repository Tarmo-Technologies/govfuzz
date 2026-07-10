// SPDX-License-Identifier: Apache-2.0

//! Language-version / dialect spine for govfuzz's legacy-support program (M22).
//!
//! govfuzz historically hardcoded the *modern* dialect of every language at
//! three layers — the tree-sitter grammar only knows current syntax, the
//! generated harness assumes modern headers/features, and the runtime/coverage
//! tracer assumes a modern interpreter. There was no place that named the
//! detected source dialect or that told codegen which floor to emit against.
//!
//! This crate is that place. It is a dependency-free leaf so every lane (the
//! discovery walk in `cli`, `harness_gen`, the build orchestrator) can consult
//! it without a dependency cycle:
//!
//! * [`Dialect`] — the detected language version/dialect of a source unit.
//! * [`detect_c`] / [`detect_cpp`] / [`detect_python`] / [`detect_perl`] —
//!   cheap, source-text heuristics for the lanes whose tree-sitter grammar only
//!   knows the modern dialect. (Ada/Rust/Go carry their version in project
//!   metadata or the parser already, so their callers set the [`Dialect`]
//!   directly.)
//! * [`HarnessProfile`] — the floor codegen should emit against for a dialect:
//!   compiler `-std` flags, a runtime-floor tag, and a [`CoverageMode`].
//!   [`HarnessProfile::for_dialect`] reproduces today's modern behavior for
//!   every currently-fuzzed dialect, so threading it through codegen is a no-op
//!   until a later phase deliberately lowers a floor.
//! * [`Dialect::fuzz_support`] — whether a dialect fuzzes end-to-end today or
//!   should degrade to the report-only path (discover + SBOM + static findings).

use serde::{Deserialize, Serialize};

/// The detected language version / dialect of a discovered source unit.
///
/// Variants are grouped by language family. Within a family they are ordered
/// oldest → newest so callers can compare with the derived `PartialOrd` *inside
/// a family* (cross-family ordering is meaningless and never relied upon).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Dialect {
    // --- Ada (95/2005/2012/2022 fuzz today; 83 is M22 Phase 4) ---
    Ada83,
    Ada95,
    Ada2005,
    Ada2012,
    Ada2022,

    // --- C (C89..C23 build with modern clang; K&R needs Phase 3 normalization) ---
    /// K&R / pre-ANSI C: old-style (untyped) parameter declarations.
    CKAndR,
    /// ANSI C / C90.
    C89,
    C99,
    C11,
    C17,
    C23,

    // --- C++ (C++98..C++23 build under gnu++20; pre-98 is Phase 5 report-only) ---
    /// cfront / ARM-era "C with classes" — no modern compiler accepts it.
    CppPre98,
    Cpp98,
    Cpp11,
    Cpp14,
    Cpp17,
    Cpp20,
    Cpp23,

    // --- Rust (editions) ---
    Rust2015,
    Rust2018,
    Rust2021,
    Rust2024,

    // --- Python ---
    /// Python 2.x (Phase 2). The 2/3 split is a hard dialect boundary.
    Python2,
    /// Python 3.x. The exact minor (3.0–3.5 f-string floor, 3.12+ `sys.monitoring`)
    /// is a [`HarnessProfile`] concern, not a separate dialect.
    Python3,

    // --- Perl ---
    /// Perl 4 / very old Perl 5 (Phase 5).
    Perl4,
    /// Perl 5.
    Perl5,

    // --- Go (version-agnostic grammar; floor handled by the build overlay) ---
    Go,

    /// Dialect could not be determined (e.g. a parse that did not expose a
    /// version signal). Treated as fuzzable with the modern profile.
    Unknown,
}

impl Dialect {
    /// Stable lowercase tag for the discovery cache / report serialization,
    /// mirroring the `lang`/`input_reachability` string approach so the cache
    /// format never depends on serde derives on a cross-crate enum.
    pub fn as_str(self) -> &'static str {
        match self {
            Dialect::Ada83 => "ada83",
            Dialect::Ada95 => "ada95",
            Dialect::Ada2005 => "ada2005",
            Dialect::Ada2012 => "ada2012",
            Dialect::Ada2022 => "ada2022",
            Dialect::CKAndR => "c_knr",
            Dialect::C89 => "c89",
            Dialect::C99 => "c99",
            Dialect::C11 => "c11",
            Dialect::C17 => "c17",
            Dialect::C23 => "c23",
            Dialect::CppPre98 => "cpp_pre98",
            Dialect::Cpp98 => "cpp98",
            Dialect::Cpp11 => "cpp11",
            Dialect::Cpp14 => "cpp14",
            Dialect::Cpp17 => "cpp17",
            Dialect::Cpp20 => "cpp20",
            Dialect::Cpp23 => "cpp23",
            Dialect::Rust2015 => "rust2015",
            Dialect::Rust2018 => "rust2018",
            Dialect::Rust2021 => "rust2021",
            Dialect::Rust2024 => "rust2024",
            Dialect::Python2 => "python2",
            Dialect::Python3 => "python3",
            Dialect::Perl4 => "perl4",
            Dialect::Perl5 => "perl5",
            Dialect::Go => "go",
            Dialect::Unknown => "unknown",
        }
    }

    /// Inverse of [`Dialect::as_str`]; `None` for an unrecognized tag.
    ///
    /// Intentionally an inherent method returning `Option` (not `FromStr`, which
    /// returns `Result`): a missing/unknown dialect tag in a persisted cache or
    /// finding must degrade to `None`, never surface a parse error.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Dialect> {
        Some(match s {
            "ada83" => Dialect::Ada83,
            "ada95" => Dialect::Ada95,
            "ada2005" => Dialect::Ada2005,
            "ada2012" => Dialect::Ada2012,
            "ada2022" => Dialect::Ada2022,
            "c_knr" => Dialect::CKAndR,
            "c89" => Dialect::C89,
            "c99" => Dialect::C99,
            "c11" => Dialect::C11,
            "c17" => Dialect::C17,
            "c23" => Dialect::C23,
            "cpp_pre98" => Dialect::CppPre98,
            "cpp98" => Dialect::Cpp98,
            "cpp11" => Dialect::Cpp11,
            "cpp14" => Dialect::Cpp14,
            "cpp17" => Dialect::Cpp17,
            "cpp20" => Dialect::Cpp20,
            "cpp23" => Dialect::Cpp23,
            "rust2015" => Dialect::Rust2015,
            "rust2018" => Dialect::Rust2018,
            "rust2021" => Dialect::Rust2021,
            "rust2024" => Dialect::Rust2024,
            "python2" => Dialect::Python2,
            "python3" => Dialect::Python3,
            "perl4" => Dialect::Perl4,
            "perl5" => Dialect::Perl5,
            "go" => Dialect::Go,
            "unknown" => Dialect::Unknown,
            _ => return None,
        })
    }

    /// Human label for reports (e.g. `"Ada 83"`, `"K&R C"`, `"Python 2"`).
    pub fn label(self) -> &'static str {
        match self {
            Dialect::Ada83 => "Ada 83",
            Dialect::Ada95 => "Ada 95",
            Dialect::Ada2005 => "Ada 2005",
            Dialect::Ada2012 => "Ada 2012",
            Dialect::Ada2022 => "Ada 2022",
            Dialect::CKAndR => "K&R C",
            Dialect::C89 => "ANSI C (C89/C90)",
            Dialect::C99 => "C99",
            Dialect::C11 => "C11",
            Dialect::C17 => "C17",
            Dialect::C23 => "C23",
            Dialect::CppPre98 => "pre-C++98 (cfront/ARM)",
            Dialect::Cpp98 => "C++98",
            Dialect::Cpp11 => "C++11",
            Dialect::Cpp14 => "C++14",
            Dialect::Cpp17 => "C++17",
            Dialect::Cpp20 => "C++20",
            Dialect::Cpp23 => "C++23",
            Dialect::Rust2015 => "Rust 2015",
            Dialect::Rust2018 => "Rust 2018",
            Dialect::Rust2021 => "Rust 2021",
            Dialect::Rust2024 => "Rust 2024",
            Dialect::Python2 => "Python 2",
            Dialect::Python3 => "Python 3",
            Dialect::Perl4 => "Perl 4",
            Dialect::Perl5 => "Perl 5",
            Dialect::Go => "Go",
            Dialect::Unknown => "unknown",
        }
    }

    /// Whether this dialect fuzzes end-to-end on the current build path, or must
    /// degrade to the report-only path (discover + rank + SBOM + static findings
    /// with a CWE, no execution).
    ///
    /// The legacy dialects that no fuzzing lane handles yet are
    /// [`FuzzSupport::ReportOnly`]; each M22 phase flips its dialect to
    /// [`FuzzSupport::Fuzzable`] as the lane lands. This is additive: these
    /// dialects are not even discovered today (their modern grammar rejects the
    /// syntax), so the table regresses nothing.
    pub fn fuzz_support(self) -> FuzzSupport {
        match self {
            // Discovered + statically analyzed, not fuzzed end-to-end.
            Dialect::Ada83 // Phase 4: parses + builds -gnat83 but report-only for now
            | Dialect::CKAndR // Phase 3: K&R discovered via the tolerant extractor
            | Dialect::CppPre98 // Phase 5: no modern compiler accepts cfront/ARM
            | Dialect::Python2 => FuzzSupport::ReportOnly, // Phase 2: needs python2
            // Perl 4 fuzzes via the Perl 5 lane (Perl 5 is backward-compatible and
            // runs most Perl 4 — M22 Phase 5 design), so it is Fuzzable, not
            // report-only.
            _ => FuzzSupport::Fuzzable,
        }
    }
}

/// Whether a [`Dialect`] can be fuzzed end-to-end or must use the report-only path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzSupport {
    /// Builds + executes on the current path; fuzz it.
    Fuzzable,
    /// Degrade to discover + SBOM + static findings (no execution).
    ReportOnly,
}

/// How coverage is collected for a dialect's harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageMode {
    /// Native sancov/PC-guard edge coverage into the shared map (C/C++/Rust/Ada).
    Builtin,
    /// Interpreted lane edge coverage via a tracer (Python `sys.monitoring`/
    /// `settrace`, Perl `DB::DB`).
    Interpreted,
    /// No edge feedback (Go today).
    BlackBox,
    /// Report-only: nothing is executed, so no coverage is collected.
    None,
}

/// The language-version floor codegen should emit a harness against for a given
/// [`Dialect`]: the compiler `-std` flags to pass, a coarse runtime-floor tag
/// the templates branch on, whether the source needs a pre-parse normalization
/// pass (K&R → ANSI), and the [`CoverageMode`].
///
/// [`HarnessProfile::for_dialect`] returns the *modern* floor for every dialect
/// that fuzzes today, so consulting a profile instead of a hardcoded constant is
/// behavior-preserving until a phase deliberately lowers a floor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessProfile {
    pub dialect: Dialect,
    /// `-std=`/`-ansi`/`-gnatNN` flags to add to the build for this floor.
    /// Empty means "use the toolchain default" (today's behavior for C).
    pub std_flags: Vec<String>,
    /// Coarse runtime-floor tag the harness templates branch on
    /// (e.g. `"c99"`, `"c89"`, `"c++20"`, `"c++11"`, `"py3"`, `"py2"`).
    pub runtime_floor: String,
    /// Whether the source must be normalized before the modern parser can read
    /// it (K&R → ANSI prototype synthesis, Phase 3).
    pub needs_normalization: bool,
    pub coverage_mode: CoverageMode,
}

impl HarnessProfile {
    /// The floor to emit against for `dialect`. Modern dialects map to today's
    /// exact behavior (no `-std` for C, `gnu++20` for C++); legacy dialects map
    /// to a lowered floor for the phase that consumes it.
    pub fn for_dialect(dialect: Dialect) -> HarnessProfile {
        let std = |args: &[&str]| args.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        match dialect {
            // ---- C: modern dialects use the compiler default (today's behavior) ----
            Dialect::C99 | Dialect::C11 | Dialect::C17 | Dialect::C23 | Dialect::Unknown => {
                HarnessProfile {
                    dialect,
                    std_flags: vec![],
                    runtime_floor: "c99".into(),
                    needs_normalization: false,
                    coverage_mode: CoverageMode::Builtin,
                }
            }
            Dialect::C89 => HarnessProfile {
                dialect,
                std_flags: std(&["-std=c89", "-ansi"]),
                runtime_floor: "c89".into(),
                needs_normalization: false,
                coverage_mode: CoverageMode::Builtin,
            },
            Dialect::CKAndR => HarnessProfile {
                dialect,
                std_flags: std(&["-std=c89", "-ansi"]),
                runtime_floor: "c89".into(),
                needs_normalization: true,
                coverage_mode: CoverageMode::Builtin,
            },

            // ---- C++: modern default is gnu++20 (today's behavior) ----
            Dialect::Cpp20 | Dialect::Cpp23 => HarnessProfile {
                dialect,
                std_flags: std(&["-std=gnu++20"]),
                runtime_floor: "c++20".into(),
                needs_normalization: false,
                coverage_mode: CoverageMode::Builtin,
            },
            Dialect::Cpp17 => HarnessProfile {
                dialect,
                std_flags: std(&["-std=c++17"]),
                runtime_floor: "c++17".into(),
                needs_normalization: false,
                coverage_mode: CoverageMode::Builtin,
            },
            Dialect::Cpp14 => HarnessProfile {
                dialect,
                std_flags: std(&["-std=c++14"]),
                runtime_floor: "c++14".into(),
                needs_normalization: false,
                coverage_mode: CoverageMode::Builtin,
            },
            Dialect::Cpp98 | Dialect::Cpp11 => HarnessProfile {
                dialect,
                std_flags: std(&["-std=c++11"]),
                runtime_floor: "c++11".into(),
                needs_normalization: false,
                coverage_mode: CoverageMode::Builtin,
            },
            Dialect::CppPre98 => HarnessProfile {
                dialect,
                std_flags: vec![],
                runtime_floor: "pre98".into(),
                needs_normalization: false,
                coverage_mode: CoverageMode::None,
            },

            // ---- Ada: per-standard GNAT switch (mirrors project_synth) ----
            Dialect::Ada83 => ada_profile(dialect, "-gnat83"),
            Dialect::Ada95 => ada_profile(dialect, "-gnat95"),
            Dialect::Ada2005 => ada_profile(dialect, "-gnat05"),
            Dialect::Ada2012 => ada_profile(dialect, "-gnat12"),
            Dialect::Ada2022 => ada_profile(dialect, "-gnat2022"),

            // ---- Rust: edition flows through Cargo.toml, not -std ----
            Dialect::Rust2015 | Dialect::Rust2018 | Dialect::Rust2021 | Dialect::Rust2024 => {
                HarnessProfile {
                    dialect,
                    std_flags: vec![],
                    runtime_floor: "rust".into(),
                    needs_normalization: false,
                    coverage_mode: CoverageMode::Builtin,
                }
            }

            // ---- Python ----
            Dialect::Python3 => HarnessProfile {
                dialect,
                std_flags: vec![],
                runtime_floor: "py3".into(),
                needs_normalization: false,
                coverage_mode: CoverageMode::Interpreted,
            },
            Dialect::Python2 => HarnessProfile {
                dialect,
                std_flags: vec![],
                runtime_floor: "py2".into(),
                needs_normalization: false,
                coverage_mode: CoverageMode::Interpreted,
            },

            // ---- Perl ----
            Dialect::Perl5 => HarnessProfile {
                dialect,
                std_flags: vec![],
                runtime_floor: "perl5".into(),
                needs_normalization: false,
                coverage_mode: CoverageMode::Interpreted,
            },
            Dialect::Perl4 => HarnessProfile {
                dialect,
                std_flags: vec![],
                runtime_floor: "perl4".into(),
                needs_normalization: false,
                coverage_mode: CoverageMode::Interpreted,
            },

            // ---- Go ----
            Dialect::Go => HarnessProfile {
                dialect,
                std_flags: vec![],
                runtime_floor: "go".into(),
                needs_normalization: false,
                coverage_mode: CoverageMode::BlackBox,
            },
        }
    }
}

fn ada_profile(dialect: Dialect, switch: &str) -> HarnessProfile {
    HarnessProfile {
        dialect,
        std_flags: vec![switch.to_string()],
        runtime_floor: "ada".into(),
        needs_normalization: false,
        coverage_mode: CoverageMode::Builtin,
    }
}

// ---------------------------------------------------------------------------
// Source-text detection for the lanes whose tree-sitter grammar only knows the
// modern dialect. These are deliberately cheap and conservative: a false
// "modern" classification just keeps today's behavior, while a confident legacy
// signal routes the unit to its lowered floor / report-only path.
// ---------------------------------------------------------------------------

/// Detect the C dialect of `source`. Today's grammar only parses C99+, so the
/// signal that matters is K&R old-style parameter declarations, which the
/// grammar cannot represent at all (Phase 3 normalizes them). Everything else
/// defaults to [`Dialect::C99`] (the modern, fuzzable floor).
pub fn detect_c(source: &str) -> Dialect {
    if has_knr_definition(source) {
        Dialect::CKAndR
    } else {
        Dialect::C99
    }
}

/// Detect the C++ dialect of `source`. The only confident *legacy* signal is the
/// use of a pre-standard C++ standard-library header — the `.h`-suffixed iostream
/// family (`<iostream.h>`, `<fstream.h>`, `<iomanip.h>`) and `<strstream>` /
/// `<strstream.h>` — which modern (headerless `<iostream>`) C++ never uses. Such
/// code is pre-C++98 / cfront-ARM era that no modern compiler accepts, so it is
/// flagged [`Dialect::CppPre98`] (report-only). Everything else defaults to the
/// modern [`Dialect::Cpp20`] floor, matching today's `gnu++20` behavior.
pub fn detect_cpp(source: &str) -> Dialect {
    if has_pre_standard_cpp_header(source) {
        Dialect::CppPre98
    } else {
        Dialect::Cpp20
    }
}

/// True if `source` includes a pre-standard C++ standard-library header — a
/// strong, low-false-positive signal of pre-C++98 code. (`complex.h` / `math.h`
/// etc. are C headers, not flagged; only the C++ iostream/strstream family.)
fn has_pre_standard_cpp_header(source: &str) -> bool {
    const PRE_STD: &[&str] = &[
        "<iostream.h>",
        "<fstream.h>",
        "<iomanip.h>",
        "<strstream.h>",
        "<strstream>",
        "<ostream.h>",
        "<istream.h>",
    ];
    for raw in source.lines() {
        let line = raw.trim_start();
        if !line.starts_with("#") {
            continue;
        }
        if !line.contains("include") {
            continue;
        }
        if PRE_STD.iter().any(|h| line.contains(h)) {
            return true;
        }
    }
    false
}

/// Detect the Python dialect of `source`. Python 2 has several syntactic
/// markers that are hard errors under a Python 3 parser; any one of them is a
/// confident Python-2 signal. Otherwise [`Dialect::Python3`].
pub fn detect_python(source: &str) -> Dialect {
    if has_python2_marker(source) {
        Dialect::Python2
    } else {
        Dialect::Python3
    }
}

/// Detect the Perl dialect of `source`. Perl 4 is handled by the Perl 5 lane
/// (Perl 5 is backward-compatible and runs most Perl 4 — M22 Phase 5 design), so
/// no Perl-4 detection is attempted; always [`Dialect::Perl5`].
pub fn detect_perl(_source: &str) -> Dialect {
    Dialect::Perl5
}

/// Detect the Ada dialect of `source`. Only an explicit `pragma Ada_83;`
/// (the unambiguous legacy signal) is reported, as [`Dialect::Ada83`]; otherwise
/// `None` so the Ada lane's own pragma/feature detection picks the standard
/// (95/2005/2012/2022) and the modern path is unchanged. The scan is
/// case-insensitive and ignores `--` line comments.
pub fn detect_ada(source: &str) -> Option<Dialect> {
    for raw in source.lines() {
        let line = raw.split("--").next().unwrap_or("");
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.split_once("pragma") {
            let after = rest.1.trim_start();
            if after.starts_with("ada_83") || after.starts_with("ada83") {
                return Some(Dialect::Ada83);
            }
        }
    }
    None
}

/// True if `source` contains a K&R old-style function definition: a
/// `name(args)` header whose parameter list is bare identifiers, followed by
/// one or more parameter *type declarations* before the opening `{`.
///
/// e.g. `int f(x, y)\n int x; char *y;\n{ ... }`. This is conservative — it
/// looks for the declarator-block-before-brace shape that ANSI prototypes never
/// have — to avoid misflagging modern code.
fn has_knr_definition(source: &str) -> bool {
    // Robustness (M22 campaign): the modern portable-C idiom `#if defined(X)`
    // followed by a file-scope `static`/`const` global used to false-positive
    // here, routing a normal ANSI file to the K&R extractor (which finds nothing)
    // and silently hiding ALL its functions. Guard against that:
    //   * drop preprocessor lines (so `#if defined(...)` parens aren't scanned),
    //   * drop string/char literals (so `)`/`;`/`{` inside them don't confuse it),
    //   * require the `(...)` to be a non-empty list of BARE identifiers (a real
    //     K&R param list — not a call/expression/`while (cond)`), and
    //   * require the following declaration to start with a type keyword, have a
    //     `;` before the body `{`, and carry NO `=` initializer (a `static int
    //     x = 5;` global is a definition, never a K&R parameter declaration).
    let filtered: String = source
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .map(strip_c_literals)
        .collect::<Vec<_>>()
        .join("\n");
    let s = filtered.as_str();
    let mut i = 0;
    while let Some(rel) = s[i..].find(')') {
        let close = i + rel;
        i = close + 1;
        let Some(open) = find_matching_open_paren(s, close) else {
            continue;
        };
        if !is_bare_ident_list(&s[open + 1..close]) {
            continue;
        }
        let rest = s[close + 1..].trim_start();
        let (Some(brace), Some(semi)) = (rest.find('{'), rest.find(';')) else {
            continue;
        };
        if semi >= brace {
            continue;
        }
        let first_decl = &rest[..semi];
        if starts_with_c_decl_keyword(first_decl) && !first_decl.contains('=') {
            return true;
        }
    }
    false
}

/// Replace C string/char-literal spans in a single line with spaces, so a `<>`,
/// `)`, `;` or `{` inside a literal is not mistaken for code. Best-effort
/// (per-line; multi-line literals are rare in the patterns we scan for).
fn strip_c_literals(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut j = 0;
    while j < bytes.len() {
        let c = bytes[j];
        if c == b'"' || c == b'\'' {
            let quote = c;
            out.push(' ');
            j += 1;
            while j < bytes.len() {
                if bytes[j] == b'\\' {
                    out.push(' ');
                    j += 2;
                    continue;
                }
                if bytes[j] == quote {
                    j += 1;
                    break;
                }
                out.push(' ');
                j += 1;
            }
            out.push(' ');
        } else {
            out.push(c as char);
            j += 1;
        }
    }
    out
}

/// Index of the `(` matching the `)` at `close` in `s`, scanning backward.
fn find_matching_open_paren(s: &str, close: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut k = close;
    loop {
        match bytes[k] {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    return Some(k);
                }
            }
            _ => {}
        }
        if k == 0 {
            return None;
        }
        k -= 1;
    }
}

/// Whether `s` is a non-empty, comma-separated list of bare C identifiers — the
/// shape of a K&R parameter list (`a, b, c`), distinguishing it from a call with
/// typed/expression args, a `while (cond)` control header, etc.
fn is_bare_ident_list(s: &str) -> bool {
    let mut any = false;
    for part in s.split(',') {
        let p = part.trim();
        if p.is_empty() || !p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return false;
        }
        if p.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            return false;
        }
        any = true;
    }
    any
}

/// Whether `s` begins (after trimming) with a C declaration-specifier keyword,
/// the hallmark of a K&R parameter declaration block.
fn starts_with_c_decl_keyword(s: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "int", "char", "short", "long", "unsigned", "signed", "float", "double", "void", "struct",
        "union", "enum", "const", "register", "static", "volatile",
    ];
    let word: String = s
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    KEYWORDS.contains(&word.as_str())
}

/// True if `source` contains a syntactic construct that is valid Python 2 but a
/// hard `SyntaxError` under Python 3. Comments/strings are not stripped; the
/// markers chosen are specific enough that incidental matches inside strings are
/// rare, and a false positive only routes a unit to the (safe) report-only
/// path.
fn has_python2_marker(source: &str) -> bool {
    for raw in source.lines() {
        let line = raw.trim_start();
        if line.starts_with('#') {
            continue;
        }
        // Robustness (M22 campaign): a `<>` INSIDE a string literal must not be
        // read as the py2 not-equal operator — `url.strip("<> '\"")` in modern
        // Python 3 (requests) used to misclassify the whole file as Python 2 and
        // demote every target to report-only. The `<>`/`except` checks run on the
        // literal-stripped line; the `print`/`exec` check runs on the ORIGINAL
        // line because the string ARGUMENT is what distinguishes `print "x"`
        // (py2) from a bare `print` name (py3).
        let stripped = strip_python_strings(raw);
        let stripped_line = stripped.trim_start();
        // `print` / `exec` statement (not the py3 function call): the keyword
        // followed by something other than `(`, `=`, end-of-line, or `.`.
        for kw in ["print", "exec"] {
            if let Some(rest) = line.strip_prefix(kw) {
                // Must be a keyword, not an identifier prefix (`printer`, `execute`).
                let next = rest.trim_start();
                let boundary = rest.is_empty()
                    || rest.starts_with(char::is_whitespace)
                    || next.starts_with(['(', '=', ':', '.', ',', '>']);
                if !boundary {
                    continue;
                }
                let c = next.as_bytes().first().copied();
                match c {
                    // `print(...)` / `print` EOL / `print =` (a variable) / `print:` →
                    // valid py3; anything else (`print "x"`, `print >>f`, `exec code`) is py2.
                    None => {}
                    Some(b'(') | Some(b'=') | Some(b':') | Some(b'.') | Some(b',') => {}
                    Some(_) => return true,
                }
            }
        }
        // `except Exc, e:` (py2 comma-bind) — an `except` line with a comma
        // before the colon and no `(` tuple.
        if stripped_line.starts_with("except ") {
            if let Some(head) = stripped_line.split(':').next() {
                if head.contains(',') && !head.contains('(') {
                    return true;
                }
            }
        }
        // The `<>` not-equal operator (py2-only), with literals stripped.
        if stripped_line.contains("<>") {
            return true;
        }
    }
    false
}

/// Replace Python string-literal spans in a single line with spaces (handles
/// `'...'`, `"..."`, and backslash escapes; triple-quoted multi-line strings are
/// best-effort per-line). Used so literal content is not scanned as code.
fn strip_python_strings(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut j = 0;
    while j < bytes.len() {
        let c = bytes[j];
        if c == b'#' {
            // Rest of the line is a comment; keep `#` so the caller's
            // comment-line check still works, blank the remainder.
            out.push('#');
            break;
        }
        if c == b'"' || c == b'\'' {
            let quote = c;
            out.push(' ');
            j += 1;
            while j < bytes.len() {
                if bytes[j] == b'\\' {
                    out.push(' ');
                    j += 2;
                    continue;
                }
                if bytes[j] == quote {
                    j += 1;
                    break;
                }
                out.push(' ');
                j += 1;
            }
            out.push(' ');
        } else {
            out.push(c as char);
            j += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dialect_str_roundtrips_every_variant() {
        let all = [
            Dialect::Ada83,
            Dialect::Ada95,
            Dialect::Ada2005,
            Dialect::Ada2012,
            Dialect::Ada2022,
            Dialect::CKAndR,
            Dialect::C89,
            Dialect::C99,
            Dialect::C11,
            Dialect::C17,
            Dialect::C23,
            Dialect::CppPre98,
            Dialect::Cpp98,
            Dialect::Cpp11,
            Dialect::Cpp14,
            Dialect::Cpp17,
            Dialect::Cpp20,
            Dialect::Cpp23,
            Dialect::Rust2015,
            Dialect::Rust2018,
            Dialect::Rust2021,
            Dialect::Rust2024,
            Dialect::Python2,
            Dialect::Python3,
            Dialect::Perl4,
            Dialect::Perl5,
            Dialect::Go,
            Dialect::Unknown,
        ];
        for d in all {
            assert_eq!(Dialect::from_str(d.as_str()), Some(d), "roundtrip {d:?}");
            assert!(!d.label().is_empty());
        }
        assert_eq!(Dialect::from_str("not-a-dialect"), None);
    }

    #[test]
    fn legacy_dialects_are_report_only_modern_are_fuzzable() {
        for d in [
            Dialect::Ada83,
            Dialect::CKAndR,
            Dialect::CppPre98,
            Dialect::Python2,
        ] {
            assert_eq!(d.fuzz_support(), FuzzSupport::ReportOnly, "{d:?}");
        }
        for d in [
            Dialect::Ada95,
            Dialect::C89,
            Dialect::C99,
            Dialect::Cpp20,
            Dialect::Python3,
            Dialect::Perl5,
            // Perl 4 fuzzes via the backward-compatible Perl 5 lane (Phase 5 design).
            Dialect::Perl4,
            Dialect::Rust2021,
            Dialect::Go,
            Dialect::Unknown,
        ] {
            assert_eq!(d.fuzz_support(), FuzzSupport::Fuzzable, "{d:?}");
        }
    }

    #[test]
    fn modern_c_profile_keeps_compiler_default_no_std_flag() {
        // Behavior-preserving: today's C build passes no -std.
        let p = HarnessProfile::for_dialect(Dialect::C99);
        assert!(p.std_flags.is_empty());
        assert!(!p.needs_normalization);
        assert_eq!(p.coverage_mode, CoverageMode::Builtin);
    }

    #[test]
    fn modern_cpp_profile_keeps_gnupp20() {
        // Behavior-preserving: today's C++ build uses gnu++20.
        let p = HarnessProfile::for_dialect(Dialect::Cpp20);
        assert_eq!(p.std_flags, vec!["-std=gnu++20".to_string()]);
    }

    #[test]
    fn c89_and_knr_profiles_lower_the_floor() {
        let c89 = HarnessProfile::for_dialect(Dialect::C89);
        assert_eq!(c89.std_flags, vec!["-std=c89", "-ansi"]);
        assert!(!c89.needs_normalization);
        let knr = HarnessProfile::for_dialect(Dialect::CKAndR);
        assert_eq!(knr.std_flags, vec!["-std=c89", "-ansi"]);
        assert!(knr.needs_normalization, "K&R needs ANSI normalization");
    }

    #[test]
    fn cpp11_profile_drops_to_cpp11() {
        let p = HarnessProfile::for_dialect(Dialect::Cpp11);
        assert_eq!(p.std_flags, vec!["-std=c++11".to_string()]);
        assert_eq!(p.runtime_floor, "c++11");
    }

    #[test]
    fn ada_profiles_use_per_standard_gnat_switch() {
        assert_eq!(
            HarnessProfile::for_dialect(Dialect::Ada83).std_flags,
            vec!["-gnat83".to_string()]
        );
        assert_eq!(
            HarnessProfile::for_dialect(Dialect::Ada2022).std_flags,
            vec!["-gnat2022".to_string()]
        );
    }

    #[test]
    fn detects_knr_function_definition() {
        let knr = "int add(a, b)\n    int a;\n    int b;\n{\n    return a + b;\n}\n";
        assert_eq!(detect_c(knr), Dialect::CKAndR);
    }

    #[test]
    fn modern_portable_c_idiom_is_not_flagged_as_knr() {
        // M22 campaign regression: `#if defined(...)` followed by a file-scope
        // static/const global (the ubiquitous portable-C idiom, e.g. cwalk) used
        // to false-positive as K&R, silently hiding ALL the file's functions.
        let src = "\
#include <stddef.h>
#if defined(__GNUC__) || defined(_MSC_VER)
static const char *FZ_SEP = \"/\\\\\";
#endif

size_t path_join(const char *a, const char *b, char *out)
{
    size_t n = 0;
    return n;
}
";
        assert_eq!(
            detect_c(src),
            Dialect::C99,
            "modern portable C must not be K&R"
        );
        // A function call whose args are bare identifiers, followed by a `;`, must
        // not look like a K&R header either.
        let call = "void g(void) {\n    int r;\n    r = combine(a, b);\n    use(r);\n}\n";
        assert_eq!(detect_c(call), Dialect::C99);
        // A `static int x = 5;` global after a `)` must not be read as a K&R decl.
        let glob = "int seed(void) { return 1; }\nstatic int counter = 5;\nint next(void) { return counter; }\n";
        assert_eq!(detect_c(glob), Dialect::C99);
    }

    #[test]
    fn python2_marker_not_triggered_by_angle_brackets_in_string() {
        // M22 campaign regression: `<>` inside a string literal (requests
        // utils.py: `url.strip("<> '\"")`) must NOT classify a Py3 file as Py2.
        let py3 = "def get_auth(url):\n    host = url.strip(\"<> '\\\"\")\n    return host\n";
        assert_eq!(detect_python(py3), Dialect::Python3);
        // `print`/`exec` as identifier prefixes (printer/execute) are not py2.
        assert_eq!(
            detect_python("printer = make_printer()\n"),
            Dialect::Python3
        );
        assert_eq!(detect_python("execute(query)\n"), Dialect::Python3);
        // A real `<>` operator (outside a string) is still detected.
        assert_eq!(detect_python("if a <> b:\n    pass\n"), Dialect::Python2);
    }

    #[test]
    fn ansi_c_is_not_flagged_as_knr() {
        let ansi = "int add(int a, int b)\n{\n    return a + b;\n}\n";
        assert_eq!(detect_c(ansi), Dialect::C99);
        // A prototype declaration must not trip the K&R heuristic.
        let proto = "int add(int a, int b);\nvoid g(void) { add(1, 2); }\n";
        assert_eq!(detect_c(proto), Dialect::C99);
        // A call with a following statement (`)` then identifier) must not trip it.
        let call = "void g(void) {\n    int x;\n    x = add(1, 2);\n    use(x);\n}\n";
        assert_eq!(detect_c(call), Dialect::C99);
    }

    #[test]
    fn detects_python2_print_statement() {
        assert_eq!(detect_python("print 'hello world'\n"), Dialect::Python2);
        assert_eq!(detect_python("print >>sys.stderr, 'x'\n"), Dialect::Python2);
        assert_eq!(detect_python("exec code in ns\n"), Dialect::Python2);
    }

    #[test]
    fn detects_python2_except_comma_and_neq() {
        assert_eq!(
            detect_python("try:\n    pass\nexcept ValueError, e:\n    pass\n"),
            Dialect::Python2
        );
        assert_eq!(detect_python("if a <> b:\n    pass\n"), Dialect::Python2);
    }

    #[test]
    fn detect_cpp_flags_pre_standard_headers_only() {
        assert_eq!(
            detect_cpp("#include <iostream.h>\nclass C { public: void f(); };\n"),
            Dialect::CppPre98
        );
        assert_eq!(
            detect_cpp("#include <strstream>\nint main() { return 0; }\n"),
            Dialect::CppPre98
        );
        // Modern, headerless iostream -> not flagged.
        assert_eq!(
            detect_cpp("#include <iostream>\nint main() { return 0; }\n"),
            Dialect::Cpp20
        );
        // A `.h` mention inside a comment / string must not trip it.
        assert_eq!(
            detect_cpp("// once used <iostream.h>\n#include <vector>\n"),
            Dialect::Cpp20
        );
    }

    #[test]
    fn detect_ada_flags_only_explicit_pragma_ada_83() {
        assert_eq!(
            detect_ada("pragma Ada_83;\nprocedure P is begin null; end P;\n"),
            Some(Dialect::Ada83)
        );
        assert_eq!(detect_ada("PRAGMA ada83;\n"), Some(Dialect::Ada83));
        // A comment mentioning Ada 83 must not trip detection.
        assert_eq!(
            detect_ada("-- written for pragma Ada_83 originally\npackage Q is end Q;\n"),
            None
        );
        // Modern Ada -> None (the Ada lane's own detection picks 95/2005/2012/2022).
        assert_eq!(detect_ada("pragma Ada_2012;\npackage R is end R;\n"), None);
        assert_eq!(
            detect_ada("procedure Main is begin null; end Main;\n"),
            None
        );
    }

    #[test]
    fn modern_python3_is_not_flagged_as_python2() {
        let py3 =
            "def f(x):\n    print(x)\n    exec(compile('1', '<s>', 'eval'))\n    return x != 0\n";
        assert_eq!(detect_python(py3), Dialect::Python3);
        // `print` as a function call, and `print` used as a value, are py3.
        assert_eq!(detect_python("print()\n"), Dialect::Python3);
        assert_eq!(detect_python("p = print\n"), Dialect::Python3);
    }
}
