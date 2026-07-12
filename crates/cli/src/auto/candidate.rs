// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

/// Source-language tag used to dispatch the per-language attempt path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lang {
    Ada,
    C,
    Cpp,
    /// Native Rust lane. A Rust candidate is discovered + ranked (M1.1), then
    /// built as a sancov+ASan staticlib linked with the C fork-server driver and
    /// fuzzed by the builtin engine on the same execution path as C/C++ (M1.2).
    Rust,
    /// Native Java lane (M2.1). A Java candidate is discovered + ranked, then
    /// built (javac/maven/gradle) and fuzzed by the builtin engine driving a
    /// persistent JVM whose bytecode is instrumented by govfuzz's own coverage
    /// agent (8-bit counters into the shared coverage map) — no third-party fuzzer.
    Java,
    /// Native Python lane (M3.1). A Python candidate is discovered + ranked, then
    /// "built" (a py_compile/import check) and fuzzed by the builtin engine driving
    /// a persistent CPython process that speaks the framed fork-server protocol and
    /// records edge coverage via `sys.monitoring`/`sys.settrace` into the shared
    /// coverage map — no Atheris, no libFuzzer. Interpreted: there is no native
    /// binary, the launcher execs the interpreter on the generated driver.
    Python,
    /// Native Perl lane (M3.2). A Perl candidate is discovered + ranked, then
    /// "built" (a `perl -c` check) and fuzzed by the builtin engine driving a
    /// persistent `perl` process (run under `perl -d:GovfuzzCov`) that speaks the
    /// framed fork-server protocol and records per-statement edge coverage via the
    /// `DB::DB` debugger hook into the shared coverage map — no third-party fuzzer.
    /// Interpreted: the launcher execs the interpreter on the generated driver.
    Perl,
    /// Native Go lane (M3.3). A Go candidate is discovered + ranked, then built
    /// (`go build` of a generated harness `main` that imports the target package
    /// via a module `replace`) and fuzzed by the builtin engine over the framed
    /// fork-server protocol. A Go panic (nil deref, index OOB, ...) is recovered
    /// and reported as a finding. Compiled + statically typed, so the harness
    /// decodes by the parameter's declared type, like the C/Rust lanes.
    Go,
    /// COBOL lane (M3.4). A COBOL subprogram (`PROGRAM-ID` with a fuzzable
    /// `LINKAGE SECTION` driven `PROCEDURE DIVISION USING`) is translated to C
    /// with `cobc -C` (GnuCOBOL), wrapped in a generated `LLVMFuzzerTestOneInput`
    /// glue that fills the `PIC X(N)` buffer from the fuzz bytes, and built +
    /// fuzzed on the C fork-server path — reusing edge coverage, cmplog, and ASan.
    /// Compiling with `-fec=all` adds libcob runtime bound-check aborts as a
    /// second (COBOL-semantic) oracle. See [`crate::auto::cobol`].
    Cobol,
    /// Fortran lane (M3.5). A `subroutine`/`function` with a `character`
    /// (byte-buffer) argument is compiled with `gfortran -fsanitize=address
    /// -fsanitize-coverage=trace-pc -fcheck=all`, wrapped in a generated glue
    /// that calls it via the gfortran C ABI, and fuzzed on the C fork-server
    /// path. ASan reports memory corruption with the exact `.f90:line`. See
    /// [`crate::auto::fortran`].
    Fortran,
    /// C# / .NET lane (M3.6). A public method taking `byte[]`/`string`/`Stream`
    /// is the fuzzable unit. The target assembly is built (`dotnet build`) and its
    /// IL instrumented with SharpFuzz (`sharpfuzz <dll>`), which writes edge
    /// coverage into a shared map; govfuzz maps that map onto its own
    /// `GOVFUZZ_COV_SHM` AFL-style bitmap and drives a warm, persistent CLR over
    /// the framed fork-server protocol — no AFL, no libFuzzer. An uncaught
    /// exception that is not input rejection is a finding (exit 86). See
    /// [`crate::auto::csharp`].
    CSharp,
    /// JavaScript / Node.js lane (M3.7). An exported function taking ≥1 argument is
    /// discovered, then fuzzed by the builtin engine driving a persistent Node
    /// process that speaks the framed fork-server protocol and records real V8
    /// precise block coverage (inspector Profiler) into the shared coverage map — no
    /// Jazzer.js, no jsfuzz, no libFuzzer. Interpreted: the launcher execs `node` on
    /// the generated driver. An uncaught non-rejection exception is a finding (exit
    /// 86). See [`crate::auto::js`].
    Js,
}

/// CLI-facing selector for `--languages`: the eight fuzzable source languages,
/// each accepting its canonical name plus the spellings operators reach for
/// (`c++`/`cxx`/`cc` → C++, `rs` → Rust, `py` → Python, `pl` → Perl,
/// `golang` → Go). Matching is case-insensitive. `to_lang` projects a selector
/// onto the internal [`Lang`] tag used for dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum LangSelector {
    Ada,
    C,
    #[value(name = "cpp", aliases = ["c++", "cxx", "cc"])]
    Cpp,
    #[value(name = "rust", alias = "rs")]
    Rust,
    Java,
    #[value(name = "python", alias = "py")]
    Python,
    #[value(name = "perl", alias = "pl")]
    Perl,
    #[value(name = "go", alias = "golang")]
    Go,
    #[value(name = "cobol", aliases = ["cob", "cbl"])]
    Cobol,
    #[value(name = "fortran", aliases = ["f90", "f", "for"])]
    Fortran,
    #[value(name = "csharp", aliases = ["cs", "c#", "dotnet", "net"])]
    CSharp,
    #[value(name = "javascript", aliases = ["js", "node", "nodejs", "mjs", "cjs"])]
    Js,
}

impl LangSelector {
    /// Project the CLI selector onto the internal dispatch tag.
    pub fn to_lang(self) -> Lang {
        match self {
            LangSelector::Ada => Lang::Ada,
            LangSelector::C => Lang::C,
            LangSelector::Cpp => Lang::Cpp,
            LangSelector::Rust => Lang::Rust,
            LangSelector::Java => Lang::Java,
            LangSelector::Python => Lang::Python,
            LangSelector::Perl => Lang::Perl,
            LangSelector::Go => Lang::Go,
            LangSelector::Cobol => Lang::Cobol,
            LangSelector::Fortran => Lang::Fortran,
            LangSelector::CSharp => Lang::CSharp,
            LangSelector::Js => Lang::Js,
        }
    }
}

/// A discovered, fuzz-eligible target. Constructed by
/// `discovery::discover()` and consumed by `attempt::attempt()`.
/// The `harness_id` is stable across runs (derived from source path,
/// line, and name) so the auto manifest and report URLs survive
/// re-sweeps.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub harness_id: String,
    pub lang: Lang,
    pub source_path: PathBuf,
    pub line: u32,
    pub name: String,
    pub score: i32,
    /// Internal linkage (`static` storage class on the definition).
    /// C direct harnesses can include the defining `.c` source into
    /// `main.c`; other language/internal-linkage paths may still
    /// pre-skip when no safe include strategy exists.
    pub is_static: bool,
    /// Preprocessor condition naming a foreign-platform macro (e.g.
    /// `_WIN32` on a non-Windows host) that guards the definition.
    /// The attempt loop pre-skips these with the condition text.
    pub foreign_guard: Option<String>,
    /// Whether the target's fuzzed parameters are an attacker-controlled input
    /// channel (C/C++ only; `None` for Ada, which is ranked differently). Drives
    /// honest reporting: a crash on a non-`AttackerReachable` target is not
    /// demonstrably reachable from attacker input as fuzzed, so the report flags
    /// it rather than presenting it as a vulnerability.
    pub input_reachability: Option<target_rank::InputReachability>,
    /// Detected source-language dialect/version (M22). `Some` for the lanes whose
    /// modern grammar would otherwise hide the version signal (C/C++/Python/Perl);
    /// `None` where dialect detection is not yet wired (Ada/Rust/Java/Go). Drives
    /// the [`lang_profile::HarnessProfile`] codegen consults and the report-only
    /// gate ([`lang_profile::Dialect::fuzz_support`]).
    pub dialect: Option<lang_profile::Dialect>,
}

impl Candidate {
    /// Stable two-character prefix used by `Candidate::harness_id`
    /// so reports can tell at a glance which engine a target was
    /// built for: `H-A` Ada, `H-C` C, `H-X` C++, `H-R` Rust, `H-J` Java,
    /// `H-P` Python.
    pub fn id_prefix(&self) -> &'static str {
        match self.lang {
            Lang::Ada => "H-A",
            Lang::C => "H-C",
            Lang::Cpp => "H-X",
            Lang::Rust => "H-R",
            Lang::Java => "H-J",
            Lang::Python => "H-P",
            Lang::Perl => "H-L",
            Lang::Go => "H-G",
            Lang::Cobol => "H-B",
            Lang::Fortran => "H-F",
            Lang::CSharp => "H-S",
            Lang::Js => "H-N",
        }
    }
}
