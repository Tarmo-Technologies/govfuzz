<!-- SPDX-License-Identifier: Apache-2.0 -->

# CLI

The govfuzz CLI is the stable operator surface for scanning, harness
generation, instrumentation, replay, minimization, reporting, and policy
checks.

## Common Flow

```sh
govfuzz scan path/to/src --work-dir govfuzz_work
govfuzz static-scan path/to/src --out govfuzz_work/static --sarif
govfuzz binary-scan path/to/bin-or-firmware --out govfuzz_work/binary
govfuzz --profile external-tools binary-adapter path/to/bin --adapter rizin --out govfuzz_work/binary-adapter
govfuzz binary-fuzz path/to/bin --work-dir govfuzz_work --input-mode stdin --seed-input smoke
govfuzz list-targets path/to/pkg.adb --top 20
govfuzz instrument path/to/pkg.adb --output govfuzz_work/src_instrumented
govfuzz generate-harness govfuzz_work/src_instrumented/pkg.adb --target Pkg.Parse --output govfuzz_work/generated_harnesses
govfuzz build govfuzz_work --harness H-PKG-PARSE
govfuzz fuzz govfuzz_work --harness H-PKG-PARSE --iterations 1000 --seed-input smoke
govfuzz replay --finding findings/F-0001 --harness build/H-PKG-PARSE/main
govfuzz minimize --finding findings/F-0001 --harness build/H-PKG-PARSE/main
govfuzz report --findings findings --out reports
govfuzz introspect path/to/src --work-dir govfuzz_work
govfuzz clean govfuzz_work --build --corpus --reports
```

## Actionability Modes

`govfuzz auto` and `govfuzz fuzz` accept `--mode reporting|attacking`. The
default is `reporting`.

`reporting` mode keeps developer workflow quality first: findings are reported
with replay commands, minimized artifacts when available, source fix locations,
patch guidance, and clear labels for lab-only paths.

`attacking` mode prioritizes targets that look externally reachable and
security-relevant. It still records findings that depend on generated stubs,
fake resources, missing-environment shims, or mocks, but those findings are
classified as `lab_only` and are not included in real-reachable counts.

CI can gate on actionability:

```text
govfuzz ci . --fail-on-actionability likely --min-actionability-confidence medium
```

Use `real` for strict attacker-reachable gates, `likely` for security gates
that accept strong static entry/sink evidence, `lab` when lab-only findings
should fail the build, and `any` to fail on every recorded finding.

For a point-and-shoot sweep over an entire (possibly partial) source tree, use
`govfuzz auto` instead of running the steps individually. See [Auto](../auto/).

`govfuzz fuzz --structured-inputs auto|off|record|json|xml|kv|url|multipart|csv|http|ini|toml|yaml|recursive`
controls the built-in engine's structured input synthesis from loaded
dictionaries. `auto` is the default and enables record/TLV, JSON-shaped,
XML element, key/value text, URL-encoded query-string, multipart/form-data, and
CSV/table-row, raw HTTP request, INI section/key, TOML table/key, YAML
section/key, and nested-grammar/recursive-structure synthesis. `record`,
`json`, `xml`, `kv`, `url`, `multipart`, `csv`, `http`, `ini`, `toml`, `yaml`,
and `recursive` force one structured family (`recursive` forces nested-grammar /
recursive-structure synthesis, also on under `auto`); `off` preserves
byte/dictionary mutation without structured synthesis.
Generated Ada harnesses write `dictionary.txt` from enum literals and string
literals; generated C/C++ harnesses write the same artifact from source and
header constants, including C++ namespaced `enum class` members and switch case
labels. The fuzz command loads a harness-specific dictionary automatically when
present.

`govfuzz scan` accepts an Ada, C, or C++ source file or directory tree. It
writes `govfuzz_work/scan_index.json`, prints the same JSON summary to stdout,
records skipped source files with diagnostics, and exits `1` only when no
supported source file was scanned.

`govfuzz static-scan <PATH>` writes `static-report.json` and
`static-report.md` to `govfuzz_work/static/` by default. Use `--sarif` to also
write `static-report.sarif`, `--suppressions <JSON>` for exact
rule/path/line suppressions, `--baseline <static-report.json>` to mark findings
as `new`, `unchanged`, or `resolved`, `--policy <JSON>` / `--enable-rule` /
`--disable-rule` to apply policy-as-code rule filters, and `--fail-on
low|medium|high|critical` for CI-style static gates.

Use `--sloc <FILE>` to also write an accurate per-language SLOC breakdown
(`LANGUAGE`, `FILES`, `TOTAL`, `COMMENTS`, `BLANKS`, `SLOC`) as a side output of
the scan. A `.json` extension emits JSON; anything else emits an aligned text
table. A relative path is written into the `--out` report directory (beside
`static-report.json`); an absolute path is written as given. Comment counting is
language-aware (Ada `--`, C-family `//`/`/* */`, hash comments, Perl POD, Python
docstrings), and the same dependency/build-tree pruning as the scan applies, so
vendored, `node_modules`, and `.venv` code is excluded. The same `--sloc <FILE>`
flag works on `govfuzz auto`, where a relative path lands in `<work-dir>/auto/`.

For **pure counting with no rule scanning**, use the dedicated `govfuzz sloc
<PATH>...` command instead — it runs only the SLOC tree walk, so it is much
faster than `static-scan --sloc` (which pays the full parse+scan cost). It takes
one or more roots and prints a per-root table plus a grand total, to stdout by
default or to `--out` (`.json` or `--json` emits JSON with a corpus-wide
`total.code_lines`):

```sh
govfuzz sloc path/to/src              # text table -> stdout
govfuzz sloc repos/* --out sloc.json  # whole corpus -> JSON with grand total
```

The static scanner now emits:

- A lightweight cross-file interprocedural taint trace for source-to-sink
  vulnerabilities. Command execution is covered across **all eight languages**
  (Ada/C/C++/Go/Rust/Java/Python/Perl), and the same engine also confirms path
  traversal, SQL injection, SSRF, XXE, LDAP injection, unsafe reflection,
  uncontrolled allocation size, open redirect, and log injection/log forging
  where the language has modeled sinks. Findings carry proven source→sink traces
  and supersede lower-confidence pattern heuristics at the same site. Includes
  local assignment aliases, Ada named-argument taint mapping, sanitizer/constant
  taint kills (including language-standard shell quoters), C++ namespace/class-aware
  local call resolution, typed object/`this`/initialized-object member-call
  resolution, overload arity filtering, string-literal-aware comment matching,
  and explicit unresolved-call gaps when source is missing.
- CWE/CERT/MISRA-oriented seed rules for unsafe string copy, path-controlled
  file opens, environment reads, unchecked integer conversion, nonliteral
  format strings, Ada unchecked conversion, Ada unchecked deallocation, Ada
  tasking constructs, Ada process/runtime dependencies, and broad Ada exception
  suppression.
- Framework and embedded-browser hardening checks for Django deployment
  settings (`SECURE_SSL_REDIRECT`, HSTS, proxy HTTPS state, nosniff, referrer
  policy, CSRF/session cookies), Flask host/CSRF controls, Electron renderer
  isolation, and Qt WebEngine settings such as sandboxing, mixed content,
  local file/remote URL access, plugins, clipboard, WebRTC local IP exposure,
  screen capture, canvas readback, and hyperlink auditing.
- Path predicates, blocked-path demotion, actionability metadata, triage
  states from baselines/suppressions, and SARIF related locations for trace
  steps.

The current engine is intentionally conservative and source-pattern driven. The
M20 backlog still tracks deeper CFG precision, richer taint modeling, and
larger rule packs as follow-up hardening.

`govfuzz binary-scan <PATH>` writes `binary-inventory.json` with offline binary
metadata for ELF, PE, Mach-O, ar archives, and raw firmware-style blobs. The
inventory records format, architecture, bitness, endianness, size, SHA-256,
ELF note build IDs, parsed entry-point/header layout, symbol/debug-info state, exact ELF/Mach-O
symbol-table import/export names, exact PE thunk import and export-directory
names, risky import APIs, dynamic library/interpreter/RPATH evidence including
ELF `PT_INTERP`, GNU build-id notes, `DT_NEEDED`, `DT_RPATH`, `DT_RUNPATH`, PE import descriptors,
and Mach-O dylib load commands, entropy/packed-binary evidence, named
section/segment evidence,
exploit-mitigation posture (a `checksec`/`winchecksec`-style read: for ELF,
RELRO — Full vs Partial via `PT_GNU_RELRO` + `BIND_NOW` — stack canary,
PIE, NX/executable-stack via `PT_GNU_STACK`, and `_FORTIFY_SOURCE`; for PE,
ASLR/`DYNAMIC_BASE`, DEP/`NX_COMPAT`, and Control Flow Guard/`GUARD_CF` from the
`DllCharacteristics` field; for Mach-O, `MH_PIE`, non-executable stack via
`MH_ALLOW_STACK_EXECUTION`, and code signing via `LC_CODE_SIGNATURE`),
hardcoded credentials baked into the binary's strings (AWS access keys, GitHub /
GitLab / Slack / Stripe / Google / npm / PyPI tokens, PEM private keys — each
carrying a CWE (`CWE-798`, or `CWE-321` for private keys), redacted in the report
and promoted to high-priority triage), triage
risk factors, container/member provenance, skipped
malformed inputs, and size-limit skips. Writable or relative RPATH/RUNPATH
entries are promoted into loader-path review triage, while high entropy,
UPX/packed section names, executable+writable sections or segments, and an
executable stack (`hardening:nx_disabled`) are
promoted into packed-binary or binary-layout review triage. Use
`--max-bytes <N>` to skip individual files or archive members above a byte
limit.

`govfuzz binary-adapter <BINARY> --adapter mock|rizin|ghidra|angr --out <DIR>`
writes `binary-adapter-report.json` with adapter-derived functions, call-graph
hints, strings, xrefs, signatures, and errors. The command never links external
tools into GovFuzz. The mock adapter consumes `--mock-output` JSON for contract
tests. Real adapters are subprocess smoke paths, are blocked in
`strict-permissive`, require `--profile external-tools` or `research-lab`, and
write `status: skipped` when the requested tool is absent.

`govfuzz binary-fuzz <BINARY>` executes source-unavailable binaries through
`--input-mode stdin|file`, `--seed-input` / `--seed-file`, `--timeout-ms`, and
repeatable `--env KEY=VALUE` launch profiles. Crashes and timeouts are written
under `<work-dir>/findings/BF-NNNN/` as `kind: binary_crash` findings with the
command, input mode, testcase, environment, binary SHA-256, stderr excerpt, and
exit/timeout signature. Existing `govfuzz replay`, `govfuzz minimize`, and
`govfuzz ci --fail-on ...` understand these binary findings.

`govfuzz differential --harness-a <A> --harness-b <B> --inputs <DIR>` replays
each input through two implementations and emits GF-301 output-divergence
findings when stdout, exit status, or timeout behavior differs. Differential
findings carry `oracle.name = "differential-output-runtime"` evidence from the
same executable-oracle registry used by runtime runtrace findings.
`govfuzz differential --harness <H> --metamorphic-transform append-newline
--inputs <DIR>` replays each input through one harness before and after
appending a trailing newline; mismatched stdout, exit status, or timeout
behavior emits GF-307 `metamorphic-relation-runtime` findings with both the
original and transformed testcase bytes.

Runtrace `runtime_check` events from Ada instrumentation can promote handled
`Constraint_Error` range/index checks into GF-102
`ada-runtime-constraint-check` oracle findings with check, handler, message,
and source evidence, handled `Storage_Error` events into GF-103
`ada-runtime-storage-error` findings, and handled `Tasking_Error` events into
GF-104 `ada-runtime-tasking-error` findings. Handled user-defined Ada
exceptions become GF-105 `ada-runtime-user-exception` findings. Runtime
`dlopen` evidence for bare, relative, parent-directory, temporary-directory, or
otherwise non-system library paths can also promote to GF-413
`dynamic-library-load-runtime` oracle findings. Successful `unlink`,
`unlinkat`, or `remove` events whose path contains a parent-directory segment
promote to GF-414 `file-deletion-runtime` findings. Native C/C++ assertion
failures observed through the runtrace shim promote to GF-415
`native-assertion-contract` findings with expression and source evidence. Open
paths that the runtrace shim observed carrying byte-origin taint from the fuzz
input — and that were never opened untainted across the run — promote to GF-405
`path-controlled-open-runtime` findings carrying a `taint_path` source→sink
string (`fuzz_input[offset..] → open(path)`). These are emitted once per run
from cross-execution correlation, not per input, and capped per harness.

These runtrace-derived findings — GF-413, GF-414, GF-415, and GF-405, together
with the GF-304 command-injection, GF-417 insecure-temp, and GF-305
sensitive-environment behavioral/taint oracles — are produced by the LD_PRELOAD
runtrace shim. The shim is armed for Ada, C, C++,
Rust, Python, Perl, and Go targets (for the interpreted Python and Perl lanes it
interposes the interpreter process; for Go it is native), but is **not** loaded
during Java fuzzing (LD_PRELOAD-ing it into
the JVM would intercept the JVM's own libc activity and report false positives)
and is **not** armed under cross-compiled or emulated (qemu/wine) runs. These
behavioral and taint findings are therefore unavailable in the Java lane and for
emulated targets.

## Enterprise Operations

M20 introduces offline governance commands for enclaves and CI systems:

```sh
govfuzz policy validate govfuzz-policy.json --out govfuzz_work/policy-summary.json
govfuzz runners validate runners.json --out govfuzz_work/runner-summary.json
govfuzz runners plan runners.json --queue runner-queue.json --policy govfuzz-policy.json --out govfuzz_work/runner-plan.json
govfuzz pack create --root packs/current --pack-id rules-2026-06 --item rules:rules/static.json --sign-key offline-root --out packs/current/update-pack.json
govfuzz pack verify update-pack.json --root packs/current --out govfuzz_work/pack-verify.json
govfuzz sbom path/to/src --out govfuzz_work/sbom --vuln-db packs/current/cve-db.json --policy govfuzz-policy.json
govfuzz ci . --work-dir govfuzz_work --policy govfuzz-policy.json --runner-plan govfuzz_work/runner-plan.json --dashboard-out govfuzz_work/ci-dashboard.json
govfuzz export --work-dir govfuzz_work --out govfuzz_work/export-manifest.json --bundle-dir govfuzz_work/export-bundle --policy govfuzz-policy.json --update-pack update-pack.json --runner-plan govfuzz_work/runner-plan.json
```

`policy validate` checks the policy-as-code document and emits a deterministic
summary of enabled languages, rule counts, runner requirements, CI thresholds,
and allowed update-pack kinds.

`runners validate` checks an offline runner capability manifest and emits the
runner ids, kinds, languages, engines, sandbox settings, and target triples
declared by the enclave.

`runners plan` reads a queue of offline fuzz/static/binary jobs, applies
policy runner allow-lists, sandbox requirements, target triples, capabilities,
and runner capacity, then writes a deterministic assignment plan. Jobs blocked
by policy or capacity remain in `unassigned` with diagnostics, and the command
exits non-zero unless every job is assigned.

`pack create` builds a deterministic air-gapped update pack manifest from
`kind:path` items under `--root`, computes item SHA-256 hashes, and can add a
`sha256-items-v1` offline signature digest via `--sign-key`. `pack verify`
recomputes hashes under `--root` and enforces update-pack policy constraints.
Tampered or missing items make verification exit non-zero.

`sbom` writes `sbom.json`, `cyclonedx.json`, `vulnerabilities.json`,
`openvex.json`, and — under the `csv` kind — both a flat one-row-per-component
`sbom.csv` inventory and a one-row-per-CVE-match `vulnerabilities.csv`
offline (select a subset with `--emit cyclonedx,sbom,vulnerabilities,openvex,csv,cyclonedx-vex`).
The `sbom.csv` projection carries name, version, ecosystem, type, supplier,
license, purl, cpe, sha256, identity confidence, matching method, usage, runtime
harnesses, and evidence — RFC-4180 escaped for spreadsheet/procurement ingestion.
The `vulnerabilities.csv` projection carries component, version, purl, cve,
severity, cvss_score, cwe, kev, reachability, and advisory — one row per offline
CVE match, with the CWE pulled from the same normalized field as
`vulnerabilities.json` and the CycloneDX `vulnerabilities` entries.
It detects local component manifests (`Cargo.toml`, `package.json`,
declared component JSON, and vendored `VERSION` directories), can ingest
`--binary-inventory` evidence, and also folds runtime `dlopen` observations
from `auto/run.json` into `runtime-dlopen` components. It emits CycloneDX 1.6
JSON with component purls, declared component CPEs, hashes, dependency
relationships, declared component supplier/license metadata, GovFuzz evidence
properties, and GovFuzz tool metadata including supplier, license, and package
URL, then matches against an offline
`--vuln-db` from an update pack. Vulnerability entries can identify packages by
`package.ecosystem`/`package.name` plus `affected_versions`, or by
`package.purl` or `package.cpe` plus `affected_versions`; PURL and CPE matches
are reported as high-confidence `matching_method: "purl"` or
`matching_method: "cpe"` findings. Identifiers are compared structurally
rather than as exact strings: comparison is case-insensitive, both CPE 2.2
URIs and 2.3 formatted strings are accepted with `*` fields treated as
wildcards, and an advisory purl without a version matches any component
version covered by `affected_versions` — while an advisory purl or CPE that
contradicts the component's identifier vetoes a name/version match.
Declared component JSON may set `supplier`, `license`, and `sha256` strings to
populate the corresponding GovFuzz SBOM and CycloneDX component fields.
Vulnerability entries can carry
`kev` metadata (`known_exploited`, `date_added`, `due_date`,
`required_action`), CVSS metadata (`version`, `score`, `vector`), and CWE
metadata (`cwe` or `cwes`), plus advisory/reference URLs, which are preserved
in `vulnerabilities.json` and counted under `counts.kev_matches`. The same
offline matches are also emitted in CycloneDX `vulnerabilities` entries with
affected component refs, CVSS ratings, CWE ids, `advisories`, and GovFuzz
properties for match method, confidence, reachability, and KEV status. When an
`auto/run.json` is present under the
scanned root or sibling work directory, CVE matches whose source/binary
component evidence overlaps a built-and-fuzzed target, or whose runtime-dlopen
component was observed by a built-and-fuzzed harness, are annotated with
`reachability.status: "reached_by_fuzz"` and counted under
`counts.reached_matches`. Use `--fail-on
low|medium|high|critical` for a direct gate, or `--policy` to read
`/ci/fail_on_vulnerability_severity` from policy-as-code. `govfuzz ci` forwards
the `auto` budget knobs so a CI run can be bounded the same way: `--per-target-time`
(per-target total fuzz wall), `--per-target-finding-count N` (stop a target after
N distinct findings; `1` ≈ stop-on-first-crash), and `--campaign-time` (whole-run
cap, or an even split across targets when paired with `--min-target-time`).

`export` writes a deterministic manifest for handoff artifacts already present
under the work directory, including report JSON/Markdown/SARIF/JUnit/CSV, static
reports, SPDX-style SBOM, CycloneDX SBOM, vulnerability reports, `auto` run
metadata, policy files, and update-pack manifests. Pass `--runner-plan` to include assignment evidence in
the export and governance summary. `govfuzz ci --runner-plan` uses the same plan
to populate dashboard budget allocation counts, and policies can set
`/ci/require_runner_plan` plus `/ci/require_full_runner_assignment` to fail CI
when scheduling evidence is missing or jobs remain unassigned. Pass
`--bundle-dir` to copy all exported artifacts into a deterministic
`artifacts/<kind>/...` tree and write a bundle-local `export-manifest.json` for
air-gapped handoff.

`govfuzz list-targets` prints each candidate's stable `harness_id` in table and
JSON output. Use that id with `govfuzz auto --harness-id <ID>` to rerun one
specific target when names collide across files.

`govfuzz fuzz` runs the built-in engine against a built harness under
`govfuzz_work/build/<harness-id>/`. It accepts literal `--seed-input` values,
`--seed-file` bytes, or prototype `--symbolic-seed-source` Ada files whose
guarded string literals are mined into seed bytes. It writes corpus entries under
`govfuzz_work/corpus/`, emits findings under `govfuzz_work/findings/`, and stores
the latest run metadata in `govfuzz_work/fuzz_runs/<harness-id>-latest.json`.
Fuzz run summaries and finding records include `sandbox` metadata so reports
distinguish sandboxed and unsandboxed executions.

`govfuzz fuzz` flags (libFuzzer-parity knobs and engine controls):

- `--engine <builtin|afl++>` — engine to run. Default `builtin`.
- `--iterations <N>` — execution cap. Defaults to `256` when neither this nor `--time` is set; with `--time` set and this omitted, the run is bounded only by the time budget.
- `--time <DURATION>` — whole-campaign wall-clock budget (e.g. `30s`, `5m`, `1h`).
- `--max-len <BYTES>` — maximum generated input length (libFuzzer `-max_len`). Default `4096`. With adaptive length control on this is the ceiling.
- `--len-control <N>` — adaptive length control (libFuzzer `-len_control`): executions without a new corpus signature before the effective length doubles toward `--max-len`. Default `100`; `0` disables it.
- `--timeout <DURATION>` — per-input timeout (libFuzzer `-timeout`): a single C/C++ harness execution longer than this is killed and the slow unit reported. Distinct from `--time`. Default `10s`. (Ada bounds runaway inputs via CPU rlimits.)
- `--rss-limit-mb <MB>` — per-execution resident-memory ceiling for a C/C++ harness (libFuzzer `-rss_limit_mb`); an execution over budget is killed and reported as an OOM finding. `0` (default) disables it.
- `--print-final-stats` — print a final-stats line (libFuzzer `-print_final_stats`): executions, exec/s, new vs duplicate corpus signatures, findings, elapsed time.
- `--workers <N|auto>` — run multiple fuzz workers.
- `--fork-server` / `--no-fork-server` — the persistent fork-server is the default for the builtin engine (one harness process kept alive and fed inputs over a framed protocol, ~38x more execs/sec while preserving coverage feedback) — except Java, whose JVM launcher owns its own in-process input loop and does not use the fork-server; every finding is replay-validated in a fresh process so a global-state artifact never escapes (#416). `--no-fork-server` runs a fresh process per input — use it for a target that intentionally carries fuzz-relevant global state across calls.
- `--cmplog-log <PATH>` — replay a runtrace audit log captured with `GOVFUZZ_CMPLOG=1`; recovered cmplog operands seed both the mutator dictionary and an offset-aware RedQueen-style splice that replaces `operand_a` with `operand_b` at the offset it appears in the current input (#400).
- `--sanitizers <asan,msan,ubsan,tsan,lsan>` — sanitizer campaign matrix to arm.
- `--rng-seed <N>` — deterministic RNG seed for built-in mutation.

`govfuzz fuzz --engine` accepts only `builtin` (the default) and `afl++`;
`libfuzzer`, `libafl`, and `nyx` are **not** valid `--engine` values and clap
rejects them. C/C++ generated harnesses do expose `LLVMFuzzerTestOneInput` and
are built as libFuzzer-style sanitizer binaries, but GovFuzz's built-in engine
runs those binaries one input at a time so it can normalize sanitizer findings;
there is no separate `libfuzzer` runtime path through this flag. The standalone
libFuzzer/LibAFL/Nyx adapters are not reachable through `govfuzz fuzz --engine`,
and the Ada libFuzzer adapter remains deferred until users have a viable
Ada/LLVM/libFuzzer toolchain.

Replay, minimize, and built-in fuzzing accept `--sandbox none|auto|firejail|bubblewrap`.
Use `--sandbox-tool` to point at a specific wrapper and `--sandbox-strict` to
fail instead of falling back when the requested wrapper is missing.

For real project layouts where the target body depends on parent package specs
outside its directory, pass each additional source root to harness generation:

```sh
govfuzz generate-harness src/base/dates/util-dates-iso8601.adb --target Value --source-root src/core --source-root src/base/dates
```

For C and C++ manual runs, pass `--target` explicitly. The generated harness is
Makefile-based, so `govfuzz build` runs `make` and stages `build/<harness-id>/main`.

```sh
govfuzz generate-harness src/parser.cpp --target parse --output govfuzz_work/generated_harnesses
govfuzz build govfuzz_work --harness H-CPP000A
govfuzz fuzz govfuzz_work --harness H-CPP000A --iterations 1000 --seed-input smoke
```

Use `--extra-source`, `--extra-include`, and `--cleanup` when the target needs
additional translation units, include directories, or return-value cleanup. See
[C and C++ Fuzzing](../c-cpp/) for supported parameter shapes and limits.

For AFL++ on a generated C/C++ harness:

```sh
govfuzz build govfuzz_work --harness H-CPP000A --c-engine afl++
govfuzz fuzz govfuzz_work --harness H-CPP000A --engine afl++ --time 30s --seed-input smoke
```

`govfuzz clean` is conservative when no scope is selected. Use `--build`,
`--corpus`, `--reports`, `--findings`, or `--all` to remove only known
GovFuzz-owned subtrees under the work directory.

## Auto

`govfuzz auto <PATH>` sweeps an Ada, C, C++, Rust, Java, Python, Perl, or Go
source tree, including
definition-bearing C/C++ headers, generates one harness per fuzzable function,
auto-stubs missing headers and undefined symbols so previously-unbuildable code
builds, runs a three-pass fuzz cascade against each built harness with the
runtime virtualisation shim loaded on native targets (not Java), and writes a
persistent fuzz lab plus
`run.md`, `run.json`, and a
`needed_for_build` ledger.

```sh
govfuzz auto path/to/src --work-dir govfuzz_work --per-target-time 60
```

Flags:

- `--work-dir <DIR>` — output root. Default `./govfuzz_work/`.
- `--per-target-time <SECS>` — the **total** per-target fuzz wall, split evenly across the passes (`auto` runs empty / rng / fuzz-driven) under one shared deadline, so the per-target wall ≈ this regardless of pass count. Default `60`. libFuzzer `-max_total_time` / AFL `-V` parity (#402). When more than one engine runs for a target (see `--engine`), this budget splits evenly across the engines too.
- `--engine <builtin[,afl++]>` — fuzz engine(s) for the per-target fuzz phase, comma-separated. `builtin` (default) is the in-process coverage-guided engine. `afl++` drives AFL++ on the **auto-recovered** build — `auto` runs `make afl` to produce the afl-instrumented `main_afl`, then `afl-fuzz`; crashes fold into the same findings pipeline and the pass is attributed to `afl++` in `run.json`. `--engine builtin,afl++` runs BOTH per target, splitting `--per-target-time` evenly. AFL applies to **native C/C++ targets only** (Ada/Rust/Java, and cross-compiled C/C++, fall back to the builtin engine, logged — never a silent skip). If `afl-fuzz`/`afl-clang-fast` are not on PATH, the run warns once and falls back to builtin. Unlike `govfuzz build`/`fuzz --engine afl++`, this needs no separate steps and works on trees that don't build as-is, because `auto` recovers the build first.
- `--per-target-finding-count <N>` — stop a target's cascade as soon as it has produced N *distinct* findings (crash signatures), or when `--per-target-time` is spent, whichever first. Checked mid-pass (stops the instant the Nth lands; remaining passes skipped). `1` ≈ libFuzzer stop-on-first-crash. Unset by default (collect every finding).
- `--total-time <SECS>` — **deprecated** alias of `--per-target-time` (overrides it when set); retained for existing benchmark/parity invocations. Hidden from `--help`.
- `--iterations <N>` — per-pass execution cap (libFuzzer `-runs`); unset (or `0`) lets `--per-target-time` govern depth. The old hardcoded 1024 cap is retired.
- `--rss-limit-mb <MB>` — per-harness resident-set memory cap; a test case over budget is killed and reported as a GF-209 OOM finding instead of OOM-killing the host (libFuzzer `-rss_limit_mb`). Default `2048`.
- `--max-targets <N>` — keep only the top-N highest-scored targets after ranking, before the build/fuzz sweep; `--list-targets` still prints the full ranked list and the kept-vs-total count is logged (never a silent truncation). Bounds *which* targets a huge tree attempts. Unset by default.
- `--campaign-time <SECS>` — whole-*run* budget across all targets. Default: an OUTER wall-clock cap — once exceeded, `auto` stops STARTING new (ranked) targets and reports how many of the N discovered were reached. With `--min-target-time`, switches to SPLIT mode (below). Unset by default.
- `--min-target-time <SECS>` — SPLIT-mode floor, used only with `--campaign-time` (errors otherwise): divide the campaign budget across the N attempted targets — each gets `max(min, campaign / N)` of fuzz time, and only the top `floor(campaign / per_target)` ranked targets are attempted (the rest logged unfuzzed), never below this floor. Overrides `--per-target-time`. Unset by default.
- `--jobs <N>` / `-j <N>` — build+fuzz up to N targets concurrently via a bounded worker pool. Peak RAM ≈ `jobs × --rss-limit-mb`, so size it to the host (too high OOM-kills, e.g. inside a cgroup `MemoryMax` slice). Results aggregate deterministically regardless of completion order. Default `1` (serial).
- `--passes <SET>` — restrict the per-target cascade to a comma list of passes (`empty`, `rng`, `fuzz`); e.g. `--passes fuzz` runs only the fuzz-driven pass (~3× the 3-pass throughput). Mutually exclusive with `--single-pass`. Default: all passes.
- `--single-pass` — convenience for `--passes fuzz`: run only the fuzz-driven pass per target.
- `--max-repair-rounds <N>` — ceiling on build-fail → repair → retry rounds per target; a low value (2–3) fails un-buildable targets fast for a triage sweep. The no-progress early-break still applies, so it is a cap, not a fixed cost. Default `48`.
- Discovery cache (**on by default**) — a re-run reuses the prior discovery from `<work>/discovery-cache.json` when a **build-stable** content fingerprint of the target source (file paths + sizes + content hashes + dir-filter) is unchanged, skipping the tree-sitter re-parse + re-rank. The fingerprint depends only on the fuzzed code, not on which govfuzz build computed it, so rebuilding govfuzz does not invalidate it. A mismatch recomputes and rewrites the cache; a stale cache is never used silently.
- `--fresh-discovery` — force a fresh discovery this run (ignore any cache), then overwrite the cache.
- `--no-discovery-cache` — disable the discovery cache entirely (never read or write it).
- `--resume` — resume a prior sweep over the same work-dir: reload targets that already completed (a per-target `auto/<id>/result.json` is written as each target finishes, so an interrupted run is resumable) and re-run only the rest. Reloaded targets are FULLY re-integrated into the new report (outcome buckets, repair manifest, findings, pass detail), with a `resumed` count of how many were carried over. Requires the discovery cache to hit (target source unchanged).
- `--reuse-discovery` — deprecated no-op (caching is now the default); accepted for back-compat.
- `--sanitizers <asan,ubsan,msan,tsan,lsan>` — arm the named sanitizer matrix on the auto build, the same arming `govfuzz fuzz --sanitizers` does, now for the auto pipeline.
- `--languages <LIST>` (alias `--lang`) — restrict the sweep to a comma-separated subset of source languages (`ada`, `c`, `cpp`, `rust`, `java`, `python`, `perl`, `go`). Candidates in other languages are dropped after discovery and before `--list-targets`/`--max-targets`, so the ranked list and the top-N reflect the filter. Common spellings accepted (`c++`/`cxx`/`cc`→cpp, `rs`→rust, `py`→python, `pl`→perl, `golang`→go); case-insensitive. Unset = fuzz every language found. The SBOM/SCA pass is unaffected.
- `--target <NAME>` — exact target-name filter. Repeat to run a small named subset.
- `--target-file <PATH>` — exact source-file filter. Accepts absolute paths or paths relative to the sweep root.
- `--harness-id <ID>` — exact stable harness-id filter from a prior auto report.
- `--exclude-path <TEXT>` — drop targets whose normalized relative source path contains `TEXT`. Repeatable.
- `--exclude <tests,tools,examples>` — drop common project areas before attempts run.
- `--no-stubs` — skip the build-time repair planner (diagnostics mode).
- `--mode reporting|attacking` — actionability profile and, in attacking mode, target scheduling.
- `--seed-file <PATH>` / `--seed-dir <DIR>` — seed bytes bootstrapped into every target's corpus (a real `.zip`, `.bz2`, sample document) so parsers reach deep code. Repeatable.
- `--extra-include <DIR>` — extra C/C++ include dirs for dependency headers outside the swept tree (cFE OSAL/PSP, a vendored SDK's `include/`). Read from local disk only. Repeatable.
- `--max-decode-depth <N>` — C decoder synthesis: max recursion depth for nested struct/union/array decoders; past it a field is left zeroed. Default `4`.
- `--max-array-elems <N>` — C decoder synthesis: max elements decoded per fixed array (a larger array fuzzes its fill count `0..cap` instead of every slot). Default `64`.
- `--max-decl-bytes <BYTES>` — C decoder synthesis: byte ceiling on a single parameter's decoder body; a larger body rejects the parameter. Default `65536`. C++ has the parallel `--container-size-max`, `--bitset-max-size`, and `--array-max-size` caps.
- `--ada-deps <DIR>` — local Ada dependency-source dirs to put on the build path (offline, never fetched). Repeatable; locally-cached Alire deps are picked up automatically.
- `--comparison-progress` — enable laf-intel comparison-progress coverage for multi-byte magic / format gates (#421). Alias `--cmp-progress`. Off by default.
- `--probe-build` — run the project's own build offline (CMake configure / `make` under a compiler-interposing wrapper) to recover real compile flags and generated headers before harnessing. Executes untrusted build scripts (sandboxed when bwrap/firejail present). Off by default.
- `--run-untrusted` — consent gate for running the project's own untrusted build/codegen; the umbrella for `--probe-build` plus an Ada (`alr build` / `gprbuild`) build probe. Implies `--probe-build`. Off by default.
- `--deps-only` — build each target as far as possible (stubbing what is missing) and emit the missing-dependency manifest (`<work>/auto/missing-deps.txt`), but SKIP fuzzing.
- `--install-deps` — after the sweep, fetch the still-blocking dependencies (apt-get for known headers/libs, `alr get` for Ada units). Opt-in and ONLINE — the only part of `auto` that touches the network.
- `--list-fakes` — print the fake-resource plugin inventory and exit.
- `--verbose` / `-v` — print an extra indented line per target: skip/fail reason, repairs applied, and per-pass execution/finding counts.

Exit codes: `0` at least one target built and ran, `1` discovery found
candidates but none built, `2` no candidates discovered.

The runtime audit and the shim's faking modes are Linux-only. On other hosts
`govfuzz auto` still runs the build-time sweep but prints a one-line notice
that runtime audit is disabled.

See [Auto](../auto/) for the full pipeline and
[Runtime Virtualisation](../runtime-virtualisation/) for the LD_PRELOAD shim,
three-pass cascade, and replay env vars.

## Fake CORBA And IDL Dictionaries

`govfuzz fake-corba <work-dir> --idl <file.idl>` emits Ada mapping packages for
the IDL model and writes `fake_corba/dictionary.txt` when the IDL or translated
ROS interfaces contain reusable tokens. The dictionary includes module,
interface, operation, struct, enum, exception, typedef, constant, union, and
case-label names plus constant values. `govfuzz fuzz` automatically falls back
to this work-dir dictionary when a harness-specific dictionary is not present;
the built-in engine uses the tokens as insertions and as ingredients for
record/TLV-, JSON-, XML element-, key/value-, URL-encoded query-shaped,
multipart/form-data, CSV/table-row, raw HTTP request, INI section/key, TOML
table/key, or YAML section/key structured inputs.

## Introspection

`govfuzz introspect <PATH>` inventories discovered Ada, C, C++, Rust, Java, Python, Perl, and Go fuzz targets
and compares them with a prior `govfuzz auto` run when
`<work-dir>/auto/run.json` exists. The report highlights targets that were
already fuzzed, built but not fuzzed, build/link blocked, unsupported, or newly
discovered since the prior run.

The command also builds a lightweight static call graph from the scanned source
tree. The first Ada slices resolve simple local calls, package-qualified
package-body calls such as `Helpers.Helper;`, parenthesized calls whose
argument count matches the discovered callee, grouped formal parameter lists
such as `procedure Helper (Left, Right : in String)`, defaulted formals such as
`procedure Helper (Required : in String; Optional : in String := "fallback")`,
multi-line subprogram body headers where the profile and `is` are split across
lines, and parameterless procedure statements such as `Helper;`, alongside the
C/C++ call graph. When a previously
fuzzed target reaches another discovered target that was not present in the
prior auto run, either directly or through a call chain, `introspect` reports a
`static_reachability_gap` coverage blocker and recommends adding or rerunning a
harness for the blocked callee. Static reachability blockers include depth
evidence and a `call_chain` such as
`parse_packet -> parse_header -> parse_magic` when the path crosses multiple
targets.
When a discovered public target was absent from the prior run and is not
already explained by a fuzzed static caller, the top-level
`coverage_blockers` list includes `unreached_public_target` with a direct
"add or run a harness" recommendation for the per-tree gap. When a fuzzed
target has a project-local call that the static graph cannot resolve, including
a missing Ada statement call such as `Missing_Helper;` or an Ada arity mismatch
such as `Helper (Input);` when only `Helper;` exists, it reports an
`unresolved_static_call` blocker and recommends adding source roots, headers, or
wrappers so reachable code is visible. JSON output includes the per-target
`static_reachability` object with direct callees, uncovered direct callees,
reachable callees, uncovered reachable callees, and unresolved calls.
The top-level `coverage_blockers` array is priority ordered: direct static
callee gaps rank ahead of deeper static paths, unresolved static calls, dynamic
comparison gates, and orphan not-run public targets.

If a prior built-in fuzz run wrote `<work-dir>/fuzz_runs/<harness>-latest.json`
with CmpLog evidence, `introspect` also reports per-target `dynamic_coverage`.
When CmpLog observed comparison operands but no seed splice candidates existed,
the top-level `coverage_blockers` list includes a `comparison_gate` blocker
with suggested operand tokens to add to seeds or dictionaries.

```sh
govfuzz introspect path/to/src --work-dir govfuzz_work
govfuzz introspect path/to/src --work-dir govfuzz_work --format json --top 50
```

Use it after `auto` to decide where coverage is missing, or before the first
run to see the highest-priority discovered targets.

## Policy Profiles

`--profile strict-permissive` is the default and rejects probes or dependency
license expressions outside the project allow-list. Use
`--profile external-tools` only when an environment intentionally permits
external tool probes such as GNAT compiler-action experiments (FSF GNAT,
GPRbuild, AFL++, and the rizin/Ghidra/angr binary adapters as subprocesses).

`--profile research-lab` is the broadest profile: it permits every external-tool
probe and any subprocess, including GPL research tooling (Libadalang, GnatFuzz,
GNATcoverage, PolyORB) on top of the `external-tools` set. Use it only in a lab
where running arbitrary external analysis tools is acceptable; it never relaxes
the link-license allow-list (linked code still must be Apache-2.0/MIT/BSD).

## Release Commands

`govfuzz-daemon` is distributed beside `govfuzz` in release archives. Use the
CLI for batch workflows and the daemon for editor integrations that need the
same analysis through JSON-RPC.
