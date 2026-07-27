<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

## 0.2.21 - 2026-07-27

Reach release: the targets `--force` was supposed to rescue and did not.

- **`--force` now works outside C/C++/Ada.** The forced sweep's residual
  blockers showed 116 Go targets and 31 C# targets ending `unsupported_params`
  however hard you forced them — Go's undrivable count was identical between the
  forced and unforced arms, because nothing attempted it. Both lanes now have
  the C-family's best-effort driver:
  - **Go** drives an undrivable parameter as its type's zero value, qualifying
    the spelling into the harness package, and calls a method on an addressable
    zero receiver (not a nil pointer, which would panic on first field access).
    An unexported, generic, variadic, or inline-literal type is still refused
    rather than guessed.
  - **C#** allocates a receiver whose type has no accessible parameterless
    constructor without running one, via the runtime's own
    `GetUninitializedObject`, resolved by reflection so the shim compiles on any
    target framework. An abstract type or interface is still refused.
  - A target built on a fabricated value is recorded as such, so the report
    floors its findings to Low with the forced caveat and counts it separately —
    a forced nil-map panic never reads as a confirmed defect.

- **A function returning a struct by value can be stubbed.** Twenty raylib
  symbols in one clay harness stubbed fine and one did not, because it returns
  an aggregate by value and the stub generator had no way to name the type. It
  now constructs a zeroed return value where the type is complete (the
  header-backed path), which is exactly as neutral as the `return 0;` its
  siblings get. clay: 3 of 6 attempted targets fuzzed, now 4.

- **A configure-style `#error` guard no longer ends the build.** Sweeping what
  `--force` still cannot build, ten of 104 sampled unbuilt harnesses died on a
  header's own `#error` — libssh's "no strtoull function found", ImageMagick's
  "you should set MAGICKCORE_QUANTUM_DEPTH" — where nothing is missing from the
  tree at all and a real `./configure` would have defined the macro the guard
  tests. GovFuzz now reads the conditional that owns the `#error` and defines
  that macro, with the value the guard itself requires — preferring the outermost
  feature-test wrapper, so libssh's guard defines `HAVE_STRTOULL` and leaves the
  real libc function alone rather than taking the inner branch and aliasing
  `strtoull` to a symbol this host lacks. Undecidable guards (a comparison, a
  compound condition, an error that fires *because* a macro is defined) are
  refused rather than guessed. Measured on the two corpus projects that carry the
  class: the guard errors are gone from every build log and more targets reach
  the report-only floor (WindTerm 3 → 6, ImageMagick 1 → 4); neither converts a
  target to fuzzing inside a 90-second campaign, because what remains behind them
  is a different class.

- **`findings.csv` columns line up again.** The optional `scan_type`/`forced`
  columns are written before the stub-accounting block but their names were
  appended after it, so under `--force` or `--static-dynamic` every stub column
  carried its left neighbour's value and `forced` read out `linked_real`. With
  neither flag the header is unchanged.

- **Tooling.** `benchmarks/campaign-2026-07-25/residual_errors.py` sweeps the
  corpus forced and histograms the actual compiler errors behind every harness
  that did not fuzz — the worklist that produced the `#error`-guard fix.

## 0.2.20 - 2026-07-24

- **More real legacy Ada/C/C++ targets reach the fuzzer.** A focused audit of
  the offline Ada/C/C++ fuzzing path fixed a set of defects, each of which
  silently prevented a class of real targets from being fuzzed:
  - Library-, aggregate-, and abstract-governed Ada projects now build. The
    synthesized build project no longer *extends* a library project (which GNAT
    rejects without `Library_Dir`, and which can't carry the harness main) or an
    aggregate (which can't be extended) — it builds a standalone project over the
    instrumented source overlay instead. Validated in a 20-project sweep against
    real library-project repos (AdaYaml, Ada-Crypto-Library, ada-toml).
  - GCC-instrumented C/C++ harnesses now record coverage. The coverage/cmplog
    shared-memory maps are opened unconditionally in the driver, not only on the
    clang `trace-pc-guard` path — a GCC (`trace-pc`) build previously left them
    NULL and fuzzed blind.
  - The framed fork-server no longer desyncs or deadlocks on inputs larger than
    the harness's 1 MiB buffer: the engine clamps each frame to that buffer.
  - UBSan-class faults (signed overflow, out-of-bounds index, shift, null deref)
    are detected on the default run — the builtin fuzz child now arms
    `UBSAN_OPTIONS`/`ASAN_OPTIONS` halt-on-error, matching the AFL path.
  - A translation unit that mixes old-style K&R and ANSI-prototyped functions
    keeps its ANSI parsers (the real targets), which were previously dropped;
    `list`/`scan` recover the correct K&R signatures too.
  - C++ rvalue-reference parameters (`T&&`) are moved into the call instead of
    being passed as an uncompilable lvalue.
  - `@response-file` compile-database arguments are expanded, preserving the
    `-I`/`-D` context they carried instead of dropping it.

- **Honest fuzz outcomes.** An `--engine afl++` run that executed zero inputs is
  recorded as built, not fuzzed. A native target that was entered and executed
  but produced zero coverage edges is flagged as having fuzzed blind. A legacy
  C++ target whose older-dialect build ties the default's error count now adopts
  the repairable older-dialect errors and converges instead of failing outright.

- **Dependencies.** Upgraded the Tera template engine to 2.x (with the
  corresponding harness-template syntax update) and refreshed the Cargo
  minor/patch set and pinned GitHub Actions.

## 0.2.19 - 2026-07-23

- **Legacy Ada/C/C++ zero-fuzz remediation.** Forty-seven discovery,
  ranking, generation, build-recovery, and execution-accounting issues found in
  a top-500 legacy-code sweep were investigated and covered by focused and
  end-to-end regressions. Fixes include exact Ada overload identity and
  dependency closure, merged reopened IDL modules, checked-in CORBA servants,
  C++ default/lifecycle construction, neutral `CORBA::Environment` handling,
  namespace-safe type resolution, legacy header preprocessing, and exact
  per-translation-unit compile contexts for original and repair-added sources.
  Directly included C++ implementation files are de-duplicated from that object
  graph, and generated C/C++ Makefiles explicitly select the complete build as
  their default goal. C++ standalone-header preflights now share the harness's
  standard-library path recovery and essential defensive prelude. Ada projects
  with obsolete runtime imports are overlaid without inheriting those imports,
  and generic-local result types are qualified through the generated instance.

- **Honest target execution and fallback evidence.** Successful campaigns now
  prove entry into the selected project endpoint rather than counting driver
  execution alone. Generation fallback chains, repairs, terminal stages, cache
  provenance, and stable structured failure categories survive into per-target
  checkpoints and final reports.

- **Durable and safe campaign resume.** `auto --resume` reloads atomically
  checkpointed completed targets from an unchanged campaign and retries only
  unfinished targets. Regenerable state is refreshed on normal reruns and
  incompatible upgrades while corpora and findings are preserved. The README
  now documents reboot/power-loss recovery and the target-level resume boundary.

- **Compact scrubbed bug reports.** The release includes
  `govfuzz-bug-report`, which creates one size-capped support report from a
  running or completed auto work directory. It reports structured decision,
  build, repair, and execution facts without source, harness or corpus content,
  paths, filenames, or project identifiers.

- **Full distribution is a permanent release artifact.** Every tagged release
  builds, installs, smokes, and publishes the all-in-one Linux
  `govfuzz-dist-<version>-x86_64-unknown-linux-gnu.tar.gz` with `install.sh`.
  The bundle now always contains `INSTALL.md`, `LICENSE`, `README.md`, and
  `RELEASE_NOTES.md`, enforced by packaging regressions and release-workflow
  archive checks.

## 0.2.18 - 2026-07-21

- **Restored all-in-one Linux installer bundle.** The release now publishes
  `govfuzz-dist-v0.2.18-x86_64-unknown-linux-gnu.tar.gz` with a bundled
  `install.sh`, CLI, daemon, both Linux preload shims, harness runtimes, signed
  content, and smoke fixture. The release workflow builds this bundle from the
  EL7-baseline artifacts and exercises an extracted install before publication.
  Separate component archives remain available for manual layouts; every one
  now includes `INSTALL.md` with exact checksum, extraction, co-location,
  optional-daemon, and environment-override commands.

- **Exact CLI archive validation.** The Linux and Windows release gates now
  select the exact `govfuzz` CLI archive instead of allowing the similarly
  named daemon archive to win an order-dependent wildcard match. This release
  completes publication of the self-contained harness-runtime packaging added
  in v0.2.17; the v0.2.17 tag did not publish after its gate correctly rejected
  the mistakenly selected daemon archive.

- **Task-based release asset guide.** The README, install, Windows, offline,
  and release-packaging guides now say exactly when to use the CLI, daemon,
  runtrace shim, compiler-interception shim, source archive, manifests, and
  checksum files. They distinguish installer-based and manual/archive installs,
  explain the effect of omitting optional components, and give an exact offline
  download pattern that cannot accidentally select the similarly named daemon.

- **ThreadSanitizer replay reliability.** Corpus replay now gives explicit TSan
  shadow-memory mapping failures a larger harness-wide bounded retry budget and
  retries transient unsymbolized reports, avoiding missed GF-556 findings under
  parallel sanitizer load without multiplying the bound across every corpus
  input. The live-runtime E2E also rechecks TSan availability at the point of
  failure instead of treating an ASLR/runtime outage as a govfuzz defect.

- **Clear RHEL 7 installation prerequisites.** The README now includes a
  copy-paste EL7 quick install. The v0.2.18 Unix CLI installer detects RHEL /
  CentOS 7 and explains that it installs only the CLI, prints the exact RHSCL
  LLVM 7 packages, and links the separate runtrace and compiler-interception
  shim installers instead of leaving a fresh host with an unexplained toolchain
  failure.

- **Current platform matrix.** Release compatibility now extends through RHEL
  10 and Ubuntu 26.04 LTS, while retaining RHEL 7/8/9 and Ubuntu 22.04/24.04.
  Native Windows coverage spans Windows 11 Enterprise 25H2, Windows 11
  Enterprise LTSC 2024 (24H2 codebase), and Windows Server 2019/2022/2025. CI
  exercises release binaries through scan, target discovery, native C harness
  compilation, and fuzzing instead of checking only startup.

- **Working Linux shim installers.** The v0.2.18 runtrace and compiler-
  interception shell installer assets were repaired in place after clean-host
  validation exposed cargo-dist 0.31 applying `chmod` to the final library path
  before moving the library out of its temporary directory. The release
  workflow now patches and gates both generated library installers so the
  failure cannot recur. Every Unix installer now also checks for the `xz`
  helper up front, and the RHEL setup commands install it explicitly; this
  replaces an opaque extraction failure on minimal RHEL images.

- **Platform installer and prerequisite diagnostics.** The v0.2.18 CLI and
  daemon PowerShell installer assets were updated in place so `irm ... | iex`
  also works in a non-interactive Windows Server 2019 OpenSSH session. Missing
  Windows C/C++ tools now recommend LLVM, VS 2022 Build Tools/Windows SDK, and
  GNU make instead of incorrectly printing an Ubuntu `apt-get` command. Linux
  C/C++ diagnostics now distinguish the RHEL 7 LLVM Toolset, RHEL 8+ `dnf`, and
  Ubuntu `apt-get` paths.

## 0.2.17 - 2026-07-21

- **Self-contained release harness runtimes.** Supersedes v0.2.16: the
  published CLI archives now carry all eleven language-runtime trees needed to
  generate and compile C/C++, Ada, Rust, Java, Python, Perl, C#, JavaScript /
  TypeScript, Ruby, Lua, PHP, COBOL, Fortran, and Go harnesses. Installer-only
  deployments securely materialize the same sources from the CLI's embedded
  copy, so a release binary never depends on the GitHub runner checkout path.
  Linux and Windows release jobs now inspect their completed archives and fail
  if any runtime is missing.

## 0.2.16 - 2026-07-21

- **Windows, Ubuntu, and RHEL release artifacts.** Releases now publish the
  `govfuzz` CLI and daemon for both `x86_64-pc-windows-msvc` and
  `x86_64-unknown-linux-gnu`, with native PowerShell and Unix shell installers.
  Windows Server 2022 CI tests and smokes the Windows executables. The Linux
  artifact is built at the GLIBC 2.17 baseline for Ubuntu and RHEL 7 through 9;
  Linux-only runtime and compiler-interception shims remain separate Linux
  assets.

- **Windows cargo-dist packaging.** The Linux-only runtrace shim now skips its
  GNU C hook compilation and linker version script when cargo-dist assembles a
  Windows release. Windows CI explicitly builds the shim package to keep this
  release-only path covered.

- **Native Windows C harness linking.** Generated harnesses and the external
  driver no longer emit competing COFF weak defaults for the Linux-only
  runtrace input hook. This fixes the `LNK1227` failure that previously stopped
  an otherwise valid MSVC/Clang harness before fuzzing.

- **UTF-8-safe C++ type qualification.** The C++ decoder no longer slices
  through a multibyte character when fuzzed or recovered type text places a
  non-ASCII scalar immediately before an identifier. This fixes the GF-210
  panic found by the repository's self-fuzzing PR gate.

- **Offline sanitizer replay reliability.** Capsule verification and direct
  sanitizer integration runners no longer inherit a distro-configured remote
  `DEBUGINFOD_URLS`. This prevents `llvm-symbolizer` from hanging indefinitely
  when the network or debuginfod service is unavailable; the ASan pool bridge
  regression also has a hard timeout.

- **RHEL 7 through RHEL 9 support and release compatibility.** GNU/Linux release
  artifacts now build in a pinned manylinux2014 / CentOS 7 userspace and pass an
  automated GLIBC 2.17 ABI plus preload-export gate instead of inheriting the
  newer Ubuntu runner ABI. The binary distribution installer auto-detects
  `dnf`/`yum`, maps selected lanes to RHEL package names, and installs available
  dependencies even when an optional supplemental package is absent. Dedicated
  RHEL-compatible CI and Proxmox validation cover the release build, package
  install, signed content, bundled C smoke target, and a real miniz run.

- **TypeScript fuzzing lane.** `govfuzz auto --languages typescript` discovers
  exported functions and public class methods in `.ts`/`.tsx` source (the
  name-extracting parser strips type annotations; interfaces, type aliases, and
  `private`/`protected`/`abstract` members are excluded), transpiles the target to
  CommonJS with esbuild, and fuzzes it with the same warm-Node framed driver, V8
  block coverage, dictionary, and command-injection detector as the JavaScript
  lane. Node + esbuild required (`npm i -g esbuild`); absent either, the lane skips
  cleanly. `.d.ts` declaration files are not fuzzed.

- **Self-fuzz dogfood CI.** A nightly `dogfood` workflow runs `govfuzz auto` on
  govfuzz's own C runtime decoders (the untrusted-input parsers every harness
  links), uploads SARIF + findings, and fails on a fuzz-confirmed crash — govfuzz
  fuzzing itself.

- **JS/TS runtime-load check.** A module that passes `node -c` (syntax) but whose
  `require('...')` cannot resolve at runtime — an npm dependency not installed
  (e.g. `qs` → `side-channel`) — previously built a harness that died at startup and
  fuzzed 0 inputs while being reported as "built". It now skips cleanly with an
  actionable reason (`… requires an npm dependency that is not installed; run
  npm install`). Applies to the transpiled TypeScript output too.

- **JavaScript/TypeScript prototype-pollution detector (GF-509 / CWE-1321).** The
  top JS injection class. The driver snapshots `Object.prototype`/`Array.prototype`
  and, after an input carrying a `__proto__`/`constructor`/`prototype` vector,
  reports a new own-property that appeared on them; complete `{"__proto__":{…}}`
  payloads are seeded into the dictionary so an unsafe `JSON.parse`+merge is
  reachable end-to-end. Verified: a recursive-merge vuln is found (GF-509) while a
  benign `JSON.parse` (which never pollutes) is not — 0 false positives.

- **JavaScript command-injection detector (GF-431 / CWE-78).** The JS lane runs
  without the LD_PRELOAD shim (managed runtime), so — like Jazzer.js's bug detectors
  — the driver hooks `child_process.exec`/`execSync` in JS and reports a
  taint-confirmed command injection when a shell-metacharacter-bearing substring of
  the fuzz input reaches the command (the input controls shell *syntax*, not just
  data). The command is never executed (a benign stub is returned). Verified:
  `execSync('convert ' + input)` is caught while a fixed command with metachar-laden
  input is not — 0 false positives.

- **Wider fuzzable surface for the C# and JavaScript lanes.** The C# lane now
  fuzzes methods with a `bool` sibling (driven to `false`) and drives an
  `offset`/`index`/`start` integer to `0` (not the buffer length, which threw), so
  `Parse(string, bool)` and `Read(byte[], int offset, int count)` shapes are covered.
  The JavaScript lane now discovers **static** methods of exported classes
  (`Class.parse`-style, no construction needed) in addition to instance methods.

- **Coverage depth for the C# and JavaScript lanes.** Three improvements from a
  post-merge dogfood sweep: (1) both lanes now **mine a magic-value dictionary**
  from the target's string/integer literals — the managed/interpreted drivers carry
  no CmpLog, so a single multi-byte comparison gate (`if (s == "OPENSESAME")`) was
  previously uncrackable; with the dictionary it is found (the libFuzzer-autodict /
  Jazzer-value-profile lever the other managed lanes already had). (2) The
  **JavaScript lane discovers public methods of exported classes** (`Class#method`),
  not just free functions — the driver `new`s a no-arg-constructible class and calls
  the method, covering class-based libraries. (3) The **JavaScript lane no longer
  runs under the LD_PRELOAD runtrace shim** (like the JVM/.NET lanes): Node's
  `stat()`→`open()` on every `require` is the same TOCTOU pattern that false-positived
  on the .NET host, so it is excluded.

- **JavaScript / Node.js fuzzing lane.** `govfuzz auto --languages javascript`
  discovers exported functions (CommonJS + ESM) taking a `Buffer`/`string`, and
  fuzzes them coverage-guided on govfuzz's own fork-server engine driving one warm
  Node process — no Jazzer.js, no jsfuzz, no libFuzzer, no `fuzz(data)` to
  hand-write. Coverage is **real V8 precise block coverage** (the inspector
  Profiler, no Babel/Istanbul source rewrite) folded per input — keyed on `(script,
  block span, taken/not-taken)` — into govfuzz's cumulative `GOVFUZZ_COV_SHM` edge
  bitmap, so the engine gets genuine branch feedback. An uncaught exception that is
  not input rejection hard-halts (exit 86) and maps to a GF rule + CWE (stack
  overflow → GF-207/CWE-674, resource `RangeError`/OOM → GF-209, `ReferenceError` /
  assertion / explicit `throw` → GF-210). `TypeError` (and `SyntaxError`/`URIError`/
  validating `RangeError`) are treated as input rejection — the untyped-lane policy
  the Python lane uses — since govfuzz synthesizes only the first argument; a
  first-argument name filter also keeps internal array/options helpers out of the
  fuzz set. Validated on a 30-project / 2,018-file campaign (express, lodash, axios,
  moment, validator.js, node-semver, marked, joi, …): 0 panics, 531 fuzzable
  functions discovered, 0 false positives; end-to-end it finds an
  uncontrolled-recursion crash with the V8 stack. The driver uses only Node
  built-ins (`inspector`, `fs`) — nothing linked into govfuzz. See
  [docs/site/javascript.md](docs/site/javascript.md).

- **C# / .NET fuzzing lane.** `govfuzz auto --languages csharp` discovers `public`
  methods taking a `byte[]`/`string`/`Stream`, builds the target with `dotnet`
  through a project reference, instruments its IL with
  [SharpFuzz](https://github.com/Metalnem/sharpfuzz) (`sharpfuzz <dll>`), and fuzzes
  it coverage-guided on govfuzz's own fork-server engine — no AFL, no libFuzzer, no
  `Fuzzer.Run` to hand-write. The driver `mmap`s govfuzz's `GOVFUZZ_COV_SHM` edge
  bitmap (64 KB = the AFL map size SharpFuzz targets) into
  `SharpFuzz.Common.Trace.SharedMem`, so the instrumented target writes coverage
  straight into govfuzz's cumulative map, and speaks the framed fork-server protocol
  to keep **one warm CLR** alive across all inputs. An uncaught exception that is not
  input rejection is a finding (exit 86), mapped to a GF rule + CWE by type (index
  OOB → GF-201/CWE-125, null-deref → GF-206/CWE-476, arithmetic → GF-205, OOM →
  GF-209, stack overflow → GF-207, else GF-210). Input-rejection exceptions
  (`ArgumentException`, `FormatException`, …) and the target namespace's own
  exceptions are suppressed. Like the JVM lane, it runs without the LD_PRELOAD shim
  (the .NET host's own startup I/O would otherwise trip the TOCTOU/open oracles).
  The target project reference is pinned to the best framework the installed SDK
  supports, so a library that multi-targets a newer preview TFM still builds.
  Validated on a 25-project / 69,608-file campaign (dotnet/runtime, roslyn, EF Core,
  Newtonsoft.Json, MessagePack, YamlDotNet, ImageSharp, …): 0 panics, 3,113 fuzzable
  methods discovered; end-to-end at ~6,900 exec/s on a warm CLR with real edge
  coverage and 0 shim false positives. SharpFuzz/SharpFuzz.Common are Apache-2.0 and
  link into the user harness, never into govfuzz. See
  [docs/site/csharp.md](docs/site/csharp.md).

- **Fortran fuzzing lane.** `govfuzz auto --languages fortran` discovers Fortran
  `subroutine`/`function` procedures with a `character` (byte-buffer) argument,
  compiles them with `gfortran -fsanitize=address
  -fsanitize-coverage=trace-pc,trace-cmp`, and fuzzes them coverage-guided on the C
  fork-server engine. AddressSanitizer is the memory oracle — a Fortran array/
  substring out-of-bounds is reported directly as a crash with the exact
  `.f90:line` and CWE (heap → CWE-122/787). The glue calls the routine via the
  gfortran C ABI (args by reference, a hidden length per character argument) with
  the primary buffer heap-allocated to the input size so a real OOB lands in ASan's
  redzone. Validated on a 20-project / 40,367-file campaign: 0 panics, 13,406
  fuzzable procedures discovered, 6,500+ exec/s, 0 false positives. See
  [docs/site/fortran.md](docs/site/fortran.md). libgfortran (LGPLv3 + GCC RLE) links
  into the user harness like the C runtime; gfortran is a subprocess only.

- **COBOL fuzzing lane — the first turnkey COBOL fuzzer.** `govfuzz auto
  --languages cobol` discovers COBOL programs (`PROGRAM-ID` with a fuzzable
  `LINKAGE` `PIC X` operand), translates them to C with GnuCOBOL (`cobc -C
  -debug -fec=all`; free/fixed format detected, copybook `-I` dirs collected),
  generates a driver that drives the full `USING` operand list (primary buffer +
  length + zeroed rest), and fuzzes on the C fork-server path (edge coverage,
  CmpLog, ASan). Two crash oracles — ASan for raw memory corruption and libcob
  `-fec=all` for COBOL-semantic violations — with each crash attributed to its
  `.cob:line` and CWE (out-of-bounds ref-mod → CWE-125, zero-divide → CWE-369,
  size overflow → CWE-190). The taint-confirmed sink oracles (command/SQL/path
  injection, CWE-78/89/22) apply too. Validated on a 23-project / 2925-file
  campaign: 0 panics, 30/38 build+fuzz, 0 false positives, 2 real
  command-injection findings. cobc is GPLv3 (subprocess-only); libcob is LGPLv3
  and links into the user harness like the GNAT runtime. See
  [docs/site/cobol.md](docs/site/cobol.md).

- **PR-native CI + GitHub Action.** New `govfuzz ci --changed-since <ref>` mode
  scopes a run to only the files a pull request changes (merge-base aware,
  reusing the discovery cache), with `--sarif` output, a compact `--ci-json`
  result, and a `--pr-gate {confirmed,all,never}` policy that by default fails
  only on a fuzz-confirmed finding. A composite action
  (`.github/actions/govfuzz-pr`) makes it one `uses:` line: it resolves the PR
  base, installs govfuzz, runs the scoped fuzz, uploads SARIF for inline
  code-scanning annotations, and posts a sticky PR summary comment. See
  [docs/site/ci.md](docs/site/ci.md). The git-diff helpers are factored into a
  shared module reused by `list-targets --changed-since`; non-scoped `ci`
  behavior is unchanged.
- **Two-compiler differential fuzzing in `auto`.** New `govfuzz auto
  --differential clang:gcc` rebuilds each C/C++ harness under both compilers via
  a portable `make diff` target and replays the fuzz corpus through both, flagging
  any input on which their exit/crash behavior diverges — a codegen- or
  UB-dependent bug one compiler exposes and the other hides — as a GF-301 finding
  in the normal report. Comparison is on exit status (govfuzz harnesses suppress
  target stdout); a failed second-compiler build logs and skips. The standalone
  `govfuzz differential` subcommand (arbitrary two-harness / metamorphic) is
  unchanged.

## v0.2.15 - 2026-07-10

- **First public release.** Hardened for public distribution: Dependabot version
  updates, GitHub Actions pinned to commit SHAs, least-privilege workflow
  permissions, and a security review that fixed a SQL-shim out-of-bounds read
  (counted `mysql_real_query`/`sqlite3_prepare*` buffers), an Ada-stub path
  traversal from untrusted compiler diagnostics, signal-unsafe shim locking, and
  two resource-exhaustion caps (IDL parser recursion, event-log allocation).
- **Cross-language static coverage sweep** closing per-language gaps found vs
  semgrep/gosec/spotbugs/cppcheck: `GF-551` Java JNDI injection (Log4Shell class,
  CWE-917; non-literal `Context.lookup`), `GF-552` Rust unsafe `transmute`
  (CWE-843), `GF-553` Rust `unwrap()`/`expect()` panic in library code (CWE-248,
  scoped to fallible boundaries to stay precise), `GF-554` C/C++ printf
  argument-type mismatch (CWE-686, high-confidence literal cases only). Broadened
  `GF-429` hardcoded-secret detection with a generic `NAME = "secret"` assignment
  pattern (language-agnostic, placeholder-guarded) and `GF-422` weak-crypto to
  cover DES/3DES/RC4/ECB/Blowfish/MD4 across C/Go/Rust/Python/Java (new Rust
  detector). All cross-checked against the competitor and verified 0 false
  positives on the 14-repo comparison corpus.
- **Static C/C++ now best-in-class outright.** Added the two bug classes cppcheck
  caught and govfuzz missed, as precise per-function intraprocedural scanners:
  `GF-549` dangling-lifetime return (returning the address/reference of a local;
  CWE-562) and `GF-550` resource leak (an allocation/handle never freed, closed,
  returned, or escaped; CWE-401/772). Cross-checked against cppcheck's
  `returnDanglingLifetime`/`memleak` — govfuzz fires on the same real defects with
  0 false positives on the corpus.

- **Best-in-class comparison + static/SBOM/SLOC improvements** (see
  `docs/site/comparison-2026-07.md`). New static rules: `GF-546` Python
  `try/except/pass` swallowed exception (CWE-703), `GF-547` unbounded
  `scanf`/`getwd` reads (CWE-120/676), `GF-548` cleartext `ws://` transport
  (CWE-319). Every static finding now carries its CWE and a `remediation` line in
  the JSON, Markdown, and SARIF (`help`/`helpUri`) outputs.
- **SBOM: lockfile ingestion + SPDX.** Reads `uv.lock` (and the existing
  lockfiles) for pinned/transitive components so CVE correlation works; adds an
  SPDX-2.3 JSON emitter (`--format spdx-json`) alongside CycloneDX/VEX.
- **`govfuzz sloc <PATH>...`** — a standalone, rayon-parallel SLOC counter (no SAST
  scan) that counts one or more roots in a single invocation; best-in-class on both
  accuracy and speed.
- **`auto --force` (alias `--force-fuzz`)** — force-fuzz mode: attempt every
  discovered C/C++/Ada function even when a parameter can't be driven or a
  type/symbol is undefined. Bypasses the pre-build skip gates, synthesizes
  best-effort drivers for opaque/function-pointer/unknown params, applies
  universal compiler-diagnostic-driven stubbing until the harness builds, and
  never hard-fails (a still-unbuildable target degrades to a report-only static
  scan). Findings from a forced/stub-heavy build are floored to Low confidence
  with a `forced` note and counted separately, since a forced crash may be a stub
  artifact rather than a real defect.
- **Win32/MFC + qualified-call recovery (no flag)** — the repair loop injects the
  synthesized `windows.h` typedefs (`BOOL`/`DWORD`/`PUCHAR`/…) for stray Win32
  names so such targets build+fuzz with real semantics; the C/C++ decoder drives
  Win32 pointer typedefs; and a namespaced free function gets a forward
  declaration even when an unrelated header (e.g. `StdAfx.h`) is auto-included,
  fixing `use of undeclared identifier`.
- **`findings.csv` overhaul** — weakness-describing messages, bare CWE numbers, a
  `remediation` column (replacing the meaningless `fix_location`), `source` +
  `data_flow` (source→sink from taint traces), an `entity` column (tainted
  variable/sink), blank `member_finding_ids` for singleton issues, and relative
  report-only (`F-RO-*`) paths.
- **`--static-dynamic`** adds a `scan_type` column to `findings.csv`
  (`static-dynamic` for a static-scan result, `dynamic` for a fuzzed result).
- Renamed the user-facing `report-only` outcome to `static-only`.

## v0.2.14 - 2026-07-08

- Added a `--sloc <FILE>` flag to `govfuzz static-scan` and `govfuzz auto` that
  writes an accurate per-language SLOC breakdown (LANGUAGE, FILES, TOTAL,
  COMMENTS, BLANKS, SLOC). Comment counting is language-aware (Ada `--`, C-family
  `//`/`/* */`, hash comments, Perl POD, Python docstrings) via the same stripper
  the rule engine uses, and the same dependency/build-tree pruning as the scan
  applies, so vendored/`node_modules`/`.venv` code is excluded. A `.json`
  extension emits JSON; anything else emits an aligned text table.

## v0.2.13 - 2026-07-08

- Added a Python static rule (`GF-545`, CWE-943) that flags a GraphQL operation
  document parsed via `gql()` from a dynamically-built string carrying GraphQL
  operation syntax. A literal document with request data bound through
  `variable_values` is the safe form and does not fire, mirroring the SQL rule.
- Fixed `govfuzz auto --external-tools` so the flag activates the external
  analyzers on its own: it now defaults to the `external-tools` license profile
  instead of the no-op `strict-permissive`, matching `static-scan --external-tools`
  (an explicit `GOVFUZZ_PROFILE` still wins). Previously the flag silently ran no
  analyzers unless `GOVFUZZ_PROFILE=external-tools` was also set.
- Expanded framework raw-HTML XSS coverage (`GF-512`) across Vue, Svelte, and
  Angular sinks, and stopped the static scanner from analyzing generated
  `compiled/` bundles (e.g. Next.js build output).
- Reworked the README for an outward-facing audience: dropped the internal Status
  section, added a concise "What it does" overview, and documented `auto --static`
  and `--external-tools` usage.

## v0.2.12 - 2026-07-07

- Added Python static rules for unsafe `tarfile` extraction without a safe filter
  (`GF-542`, CWE-22), Flask/Jinja request-data-as-template-source injection
  (`GF-543`, CWE-1336), and tainted values reaching a logging sink without CR/LF
  neutralization (`GF-544`, CWE-117).

## v0.2.11 - 2026-07-07

- Degrade C/C++ targets that reference an unsuppliable external class to a
  report-only static scan instead of a bare failed build: a placeholdered
  external class (e.g. MFC `CString`) whose rebuild fails with scalar-used-as-
  class errors, and a forward-declared type whose definition is not visible to
  the generated harness translation unit, now both fall back to "fuzz the
  source" with CWE-tagged findings.
- Overhauled `findings.csv` for static findings: added `rule_id` and a
  human-readable `message` column so a row says what the issue is, not just a
  CWE; blanked the redundant `harness_id` for static rows; surfaced the
  emit-time confidence instead of a flattened report-time value; and populated
  `sink_function` with the enclosing function name rather than the file name.
- Extended SBOM cataloging to list external COTS/OSS/GOTS software traced from
  C/C++ `#include` directives and Ada `with` clauses even without a dependency
  manifest, while excluding the project's own headers/packages and system or
  toolchain headers. `--sbom` now explains an empty result.
- Annotated the `auto` bug report so known, working-as-intended limitations
  (opaque-handle lifecycle skips, classes with no public constructor/factory)
  are tagged and not mistaken for reportable bugs.
- Made the SBOM golden test version-agnostic so it no longer breaks on each
  release version bump.

## v0.2.10 - 2026-07-07

- Re-cut the v0.2.9 release after GitHub rejected Artifact Attestations for the
  private Tarmo-Technologies organization/repository plan.
- Disabled GitHub Artifact Attestations in the generated release workflow and
  updated release documentation to describe checksum verification plus signed
  content-pack verification as the supported release integrity path.

## v0.2.9 - 2026-07-07

- Re-cut the v0.2.8 static-analysis release payload with the generated release
  matrix limited to the smoke-tested `x86_64-unknown-linux-gnu` target.
- Documented the supported binary release target and the Linux-only runtime
  preload package constraint.
- Guarded a Linux-only fuzz-runner `prctl` call so non-Linux source builds do
  not fail on that symbol.

## v0.2.8 - 2026-07-07

- Expanded `govfuzz static-scan` with broad framework, JavaScript, container,
  GitHub Actions, Django, Electron, and Qt WebEngine rule coverage.
- Added Qt WebEngine hardening detections for sandboxing, mixed content, local
  file/remote URL access, plugins, clipboard access, geolocation, unknown URL
  schemes, DNS prefetch, WebRTC local IP exposure, screen capture, canvas
  readback, and hyperlink auditing.
- Added Django deployment hardening detections for HTTPS redirect defaults,
  HSTS, proxy HTTPS state, referrer policy, nosniff, host allowlists,
  CSRF/session cookies, frame options, request-size limits, debug mode, and
  weak password hashers.
- Improved static-analysis release documentation, benchmark coverage for the
  Django HTTPS redirect rule, and release-flow guidance for `dist` tag planning.

## v0.2.7 - 2026-07-02

- Added `auto --static` whole-tree static scanning alongside fuzzing.
- Mapped static findings into sink/fix location reporting.
