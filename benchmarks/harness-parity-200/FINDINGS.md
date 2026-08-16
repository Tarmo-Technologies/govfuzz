<!-- SPDX-License-Identifier: Apache-2.0 -->
# 200-project expert-parity findings

## What was measured

The audit pins 200 real repositories across all 16 supported languages (12 or
13 per lane). Each run allows the normal ten-candidate backfill, requires an
exact target-entry checkpoint, and separately records dynamic project coverage.
`GOVFUZZ_BLIND_EXPERT_HARNESSES=1` prevents a repository's checked-in fuzz
driver from influencing auto selection. The independent comparison uses one
reviewed expert harness per language at the identical project revision.

The first complete pass reached and dynamically covered 93/200 selected target
bodies. Its residual classification was:

| Initial class | Projects |
|---|---:|
| Entered and covered | 93 |
| Unsupported signature/call shape | 34 |
| Compile or build context | 31 |
| Entered without dynamic body coverage | 13 |
| Timeout | 11 |
| Discovery or no attempt result | 11 |
| Link or source closure | 4 |
| Framework host environment | 2 |
| Toolchain/language version | 1 |

Those counts are a triage taxonomy, not 107 equivalent generator defects.
Missing SDKs, newer language versions, unavailable packages, Android/Windows
hosts, and project build failures remain distinct from a generated call-shape
failure.

The clean durable rerun completed 200/200 rows with no interrupted/negative
exit records. It proved 118 selected calls were entered and 105 produced dynamic
project coverage, up from 93 in the first pass:

| Language | Projects | Entry proved | Body covered |
|---|---:|---:|---:|
| Ada | 12 | 4 | 4 |
| C | 13 | 9 | 9 |
| C++ | 13 | 5 | 5 |
| Rust | 13 | 5 | 5 |
| Java | 13 | 9 | 9 |
| Python | 13 | 9 | 9 |
| Perl | 12 | 8 | 8 |
| Go | 13 | 10 | 3 |
| COBOL | 12 | 5 | 5 |
| Fortran | 12 | 4 | 4 |
| C# | 12 | 6 | 6 |
| JavaScript | 13 | 8 | 7 |
| TypeScript | 13 | 10 | 10 |
| Ruby | 12 | 8 | 7 |
| Lua | 12 | 7 | 5 |
| PHP | 12 | 11 | 9 |

Its remaining classes were 28 unsupported signatures, 24 compile/build-context
failures, 13 entered-without-body-coverage, 12 timeouts, 12 discovery/no-attempt,
three link/source-closure failures, two framework-host failures, and one
toolchain/language-version failure.

That rerun exposed a Go instrumentation fallback defect: module-wide
`-coverpkg=module/...` failed on unrelated platform packages and immediately
fell back to a blind build. The final binary retries the exact selected package
before going blind. A like-for-like rerun of all 13 Go projects raised body proof
from 3/13 to 10/13 (10/10 entered targets), leaving only three unsupported call
shapes. Substituting that measured lane into the complete matrix yields 112/200
body-covered projects; this 112 figure is explicitly a composite of the durable
200-project run plus the final-binary Go rerun, not a claim of a second monolithic
200-project execution.

The final C++ regression lane held its prior 5/13 entry/body result while moving
nlohmann/json from the `_json` literal helper to the expert public parser. Its
sole `unsupported_params` row then exposed a separate build-context defect:
the static MSBuild probe preserved unresolved `$(IntDir)` paths, which the
Makefile-injection guard correctly rejected. Dropping unresolved MSBuild
properties (while retaining resolved project paths and defines) made
TrafficMonitor's `tinyxml2::XMLDocument::Parse(const char *, size_t)` build and
cover on attempt one, with 299 dynamic edges and 907 covered project lines.
Substituting this focused final-binary result raises C++ to 6/13 and the explicit
cross-run composite to 113/200; as with the Go figure, this is not represented
as a second monolithic 200-project run.

The broad target list also exposed substring-ranking artifacts: `download_audio`
was credited as `load`, `mariadb_threadpool`/`already_included` as `read`, and
`reload` as `load`. Identifier-token scoring plus low-value helper penalties were
then validated on 11 affected real projects. All 11 still entered and covered a
body; nine moved to meaningfully deeper surfaces, including `ingest_scip_json`,
`load_source`, `CPAN::Meta::YAML::LoadFile`, `linux_lvm_parseurl`, and
`M.format_filter`. Two application-sized projects still chose shallow fallbacks
because their higher-value surfaces could not reproduce the project build graph;
that is a build/dependency closure gap rather than a ranking-token gap.

## Expert comparison

The final-binary focused comparison has 16/16 expert projects entering the
selected endpoint and producing dynamic project coverage. Auto selects the same
semantic entrypoint as the expert in 13/16 lanes under normalized exact-leaf
equality, up from 6/16 before the fixes. In nlohmann/json it now selects
`basic_json::parse`, proves the default `json = basic_json<>` specialization,
instantiates the byte-input member template with `std::string`, and omits its
four defaulted arguments. That first-attempt run entered and dynamically covered
the expert public parser with 558 edges and 216 covered project lines.

The three conservative exact-target differences are Rust, COBOL, and PHP:

- zoxide: auto is restricted to a public separate-crate surface, while the expert
  runs in-package, materializes a database, and calls private `Database::open_dir`;
- webbol: auto chooses the higher-ranked pure `URL-DECODE`, while the expert
  intentionally uses `FILE-OPS` to test file/output resource synthesis (that
  synthesis is implemented and separately exercised);
- Monolog: auto deeply covers `LogmaticFormatter::normalizeRecord`, while the
  expert chooses `ChromePHPFormatter::format`; auto now constructs the required
  `LogRecord`, so the object-construction lever is closed even though selection
  differs.

Of those three differences, only Rust represents an expert setup capability the
auto lane still lacks. COBOL file materialization and PHP typed-object synthesis
are both implemented and dynamically exercised; their rows differ because two
viable deep surfaces rank differently, not because the expert call shape is
unrepresentable.

For C/C++, the pre-existing 30-project blind line comparison remains the deeper
coverage control: all 30 pairs were comparable, 19 had no expert-only
implementation lines, and 25 were within seven expert-only lines. Auto covered
50,340 implementation lines versus 48,742 for the independent experts, with 123
expert-only lines in total. Aggregate line count is not a substitute for exact
surface selection, which is why this audit reports both.

## Gaps closed during the audit

| Lever | Result |
|---|---|
| Honest execution proof | All 16 generators checkpoint immediately before the selected call; decode/setup-only runs are demoted. |
| Semantic target selection | Parser/decoder tiers, data-format nouns, host/registry penalties, file-wrapper penalties, and public whole-artifact C entry ranking replaced alphabetical/shallow choices. |
| Identifier-aware ranking | Snake/camel/qualified tokens prevent `download`→`load`, `threadpool`→`read`, and `reload`→`load` false bonuses; explicit debug/fail/report/inspect penalties demote shallow helpers. |
| File-backed inputs | JavaScript, Ruby, and COBOL materialize fuzz bytes for path/file operands and clean resources after the call. |
| Async file lifetime | JavaScript awaits returned promises before cleanup, so async reads retain their materialized input and rejected promises use the normal finding classifier. |
| Stateful APIs | Go infers a public one-input feeder followed by a zero-argument terminal; Cobra now generates the expert-equivalent `SetArgs` then `Execute` sequence with NUL-delimited arguments. |
| Go coverage scope | A failed module-wide coverage build retries the exact selected package before black-box fallback; body evidence rose from 3/13 to 10/13 on the same Go corpus. |
| Typed value objects | PHP resolves imported parameter types and recursively constructs scalars, arrays, enums, dates, and bounded constructor graphs before entry proof. |
| C++ public member templates | Macro-declared class scope is recovered from malformed outer syntax; defaulted parameters, rvalue byte inputs, inferred `std::string` member-template instantiation, and default-template aliases now produce a legal public parser call. |
| Static MSBuild context | Known project-directory properties resolve normally, while unresolved configuration properties such as `$(IntDir)` are omitted instead of becoming unsafe fake include paths; the build-safety boundary remains fail-closed. |
| ABI-specific arrays | Fortran assumed-shape character arrays use the required descriptor and preserve the full fuzz-input extent. |
| Managed instrumentation | C# source inclusion builds a separate target library, instruments only project IL, recovers BOM-prefixed global usings, and avoids nested `obj/` duplicate attributes. |
| Dynamic-language parser correctness | Ruby tracks RHS blocks and `class << self`; Lua rejects invented call-expression assignment targets; PHP rejects multi-required call shapes. |
| Runtime isolation | Script/VM smoke tests run in the harness directory, and native `LD_PRELOAD` tracing is disabled for runtimes that supply language-aware coverage. |
| Audit durability | Rows record the exact binary version/hash; timeout handling kills the entire spawned process group; interrupted negative-exit rows and partial work directories are retried. |

## Remaining major paths

1. **Rust in-package private harnesses and resource recipes.** Add a controlled
   in-crate test/fuzz module mode so private targets remain visible, then infer
   path-backed constructors/openers from nearby call sites. That closes zoxide's
   `Database::open_dir` gap without making private APIs public.

2. **Build-graph fidelity.** Large Ada, C++, C#, Fortran, Java, and Rust projects
   still fail primarily when a reduced source closure cannot reproduce generated
   files, feature flags, platform SDKs, or the project's own build graph. Prefer a
   successfully built project artifact/compile graph before source-inclusion
   fallback, and classify unavailable host SDKs separately from codegen failures.

3. **Dependency and framework bootstrapping.** Missing Ruby/Python/Perl/PHP/JS
   packages and browser/Neovim/Android/Windows globals dominate several residual
   lanes. Reuse lockfile-local caches and project boot entrypoints; permit minimal
   host stubs only when the selected utility's observed dependency slice is small
   and the stub is reported explicitly.

4. **Structured scientific data.** The Fortran corpus often exposes numeric
   vectors/matrices plus dimension/leading-dimension operands. The current lane
   can enter routines through character control flags but cannot yet build the
   coherent numeric shapes an expert LAPACK/scientific harness would generate.
   Infer array extents and coupled dimension operands, allocate bounded typed
   arrays, and preserve alias/intent constraints.

5. **General state/resource sequence mining.** The new Go feeder-terminal rule is
   intentionally narrow. A next step is bounded call-site recipe mining for
   constructor → setter/feed → parse/execute → cleanup sequences, with provenance
   and no silent zero-value fabrication. This should also drive file, stream, and
   output-buffer setup in native and managed lanes.

The generated `gap-report.md`, `expert-parity-report.md`, `results.tsv`, and
content-addressed `expert-harnesses.tsv` in the audit output contain the exact
per-project evidence behind these conclusions.
