<!-- SPDX-License-Identifier: Apache-2.0 -->

# Offline `auto` Runbook for Ada, C, and C++

This runbook gives an offline source drop the best practical chance of reaching
real fuzz execution. It keeps the evidence-preserving run separate from the
forced, stub-heavy fallback so the report makes clear which results exercised
real project behavior.

## Required Offline Content

GovFuzz can recover compile flags, generate harnesses, repair broken build
closure, synthesize limited dependencies, and bypass a non-working original
build. Dynamic fuzzing still requires usable compilers and runtimes on the
offline host. Stage these before the scan:

- the complete source drop, including local Git history when exact recovery of
  deleted tracked files is required;
- matching GNAT/GPRbuild and C/C++ compiler/runtime toolchains;
- vendored dependency headers and sources that must retain real semantics;
- project code generators and their inputs when real generated output is
  required;
- representative input files or corpora for structured formats.

Do not use `--install-deps` on an offline host. Missing compilers, generated
interfaces, or semantic source files cannot be recovered from no information;
`auto/run.json` and `auto/missing-deps.txt` record those boundaries.

GovFuzz creates `auto/missing-deps.txt` and `auto/missing-deps.json` before the
first target starts. The first section is the offline handoff list: missing host
and cross compilers, target runtimes/emulators, generated source/codegen tools,
unfetched Git submodules, and declared Alire source that is not locally staged.
Each row says whether it was `declared`, `observed`, or `inferred` and includes
the metadata or diagnostic that supports it. Configure/CMake templates and
commands are reported as generated source, rather than as guessed distro header
packages. Literal C/C++/Ada source paths declared by CMake but absent from the
drop are listed separately as vendor/project source; GovFuzz does not replace
those implementation semantics with a claimed equivalent.

The files are atomically checkpointed after every completed target, including
parallel sweeps, and the final terminal line points to `missing-deps.txt` with
its blocking/substituted counts. Build-probe diagnostics are checkpointed before
target discovery begins. If the GovFuzz parent is OOM-killed, the latest project
metadata/build-probe/preflight pass and every previously completed target remain
in the last valid checkpoint. The actively running target can still be absent because an
unrecoverable process kill cannot execute its classifier; `complete: false` in
the JSON and `run still in progress` in the text make that boundary explicit.

"Exact" means exact where the project or toolchain provides evidence: a
`.gitmodules` path and URL, an `alire.toml` version constraint, a CMake output and
command, a compiler diagnostic, or a mapped platform guard. When an absent
proprietary SDK/source has no identifying metadata, GovFuzz records the
unresolved type/guard and marks it `inferred`; it does not invent a vendor,
version, ABI, or implementation semantics.

`--run-untrusted`, `--build-command`, and
`--unsafe-search-and-run-build-commands` execute code from the scanned tree.
Use them only in an isolated scan VM or equivalent sandbox with networking
disabled.

## Known Build Command

When the build entry point is known, name it explicitly. `--build-command`
intercepts the build's compiler invocations and recovers a compile database;
`--run-untrusted` also enables the Ada build/code-generation probe.

```sh
govfuzz auto /src/project \
  --work-dir /results/govfuzz-real \
  --languages ada,c,cpp \
  --run-untrusted \
  --build-command "./build.sh" \
  --static \
  --sanitizers asan,ubsan \
  --comparison-progress \
  --seed-dir /offline/seeds \
  --per-target-time 300 \
  --jobs 2 \
  --verbose
```

For a recognized CMake, Meson, Make, Ninja, Visual Studio, Alire, or GPRbuild
project that does not need a custom command, omit `--build-command`; keep
`--run-untrusted` to enable the normal C/C++ and Ada build probes.

If a legacy compiler rejects the requested sanitizer set, rerun without
`--sanitizers`. The default coverage-only build gives the target a better
compatibility chance, while the sanitizer run gives stronger memory-error
detection when the toolchain supports it.

## Unknown Build Command

When the build entry point is unknown and the source is trusted enough to
execute in the isolated VM, let GovFuzz find it:

```sh
govfuzz auto /src/project \
  --work-dir /results/govfuzz-real \
  --languages ada,c,cpp \
  --unsafe-search-and-run-build-commands \
  --static \
  --sanitizers asan,ubsan \
  --comparison-progress \
  --seed-dir /offline/seeds \
  --per-target-time 300 \
  --jobs 2 \
  --verbose
```

The unsafe-search flag finds a custom build entry point when one is present,
enables recognized build-system probes, and enables the Ada build/codegen
probe. It already supplies the consent represented by `--run-untrusted`.

## Supply Real Offline Dependencies

Add only the flags that describe content actually staged with the scan:

```sh
  --extra-include /offline/deps/include \
  --extra-source /src/project/lib/helper.c \
  --ada-deps /offline/deps/ada-src \
  --seed-file /offline/seeds/valid-message.bin \
  --seed-dir /offline/seeds
```

- `--extra-include` supplies real C/C++ dependency headers. Repeat it for
  multiple roots.
- `--extra-source` links a known sibling translation unit instead of stubbing
  its symbols. Repeat it for multiple files.
- `--ada-deps` puts vendored Ada dependency sources on the build path. Repeat
  it for multiple roots.
- `--include-dir NAME` restores discovery under a directory that GovFuzz would
  normally prune.
- `--seed-file`, `--seed-dir`, and `--grammar FILE` help structured parsers
  cross format gates and reach deeper code.
- `--engine builtin,afl++` adds AFL++ for native C/C++ when its binaries are
  already installed offline. The per-target time is split between engines.

Leave `--cxx-std` unset unless the required dialect is known; the automatic
dialect ladder normally gives legacy C++ a better chance. Keep the default
`--max-repair-rounds 16`: it covered every successful sample in the expanded
95-run clean/damaged validation population, whose maximum was 14 rounds.

## IDL and Generated Source

`auto` handles in-tree `.idl` files without a manual step. Its offline parser
resolves cross-directory IDL includes, emits fake CORBA base packages and Ada
Helper/Skel/Stub mapping units under `govfuzz_work/fake_corba`, adds that source
directory to Ada builds, and derives fuzz dictionary tokens.

Real project-specific C/C++ client/server output is a different contract. Use
`--run-untrusted` or `--build-command` when the actual offline generator is
present. When the generator or its inputs are absent, GovFuzz can synthesize
limited header/type scaffolding but cannot promise production-equivalent
generated behavior.

## Forced Fallback

Run the forced sweep into a different work directory. It attempts C/C++/Ada
targets whose parameters or dependencies could not be driven soundly in the
first run:

```sh
govfuzz auto /src/project \
  --work-dir /results/govfuzz-forced \
  --languages ada,c,cpp \
  --run-untrusted \
  --build-command "./build.sh" \
  --force \
  --static \
  --comparison-progress \
  --seed-dir /offline/seeds \
  --per-target-time 300 \
  --jobs 2 \
  --verbose
```

For the unknown-build variant, replace `--run-untrusted --build-command ...`
with `--unsafe-search-and-run-build-commands`.

Forced and stub-heavy findings are deliberately marked Low confidence because
they can depend on fabricated behavior. Do not combine their success counts
with the evidence-preserving run.

## Flag Combination Rules

- `--force` combines with either known-build or unknown-build recovery.
- `--run-untrusted` already implies `--probe-build`; specifying both is
  redundant.
- An explicit `--build-command` takes precedence over
  `--unsafe-search-and-run-build-commands`; choose one.
- `--static` complements fuzzing and covers files that still cannot execute.
- `--resume` is for continuing an interrupted run with the same work directory
  and unchanged source. Do not use it to turn the real run into a forced run.
- Size `--jobs` against memory: `jobs * --rss-limit-mb` is the fuzz-child
  allowance, not total peak. Also reserve RAM for GovFuzz's declaration index,
  retained target results, compiler processes, and the OS. Use `--jobs 1` on an
  8 GiB host unless measurement demonstrates safe headroom.

## Compact Scrubbed Support Report

If the campaign produces no successful harnesses, run the bundled collector
instead of copying many ad hoc command results. It works while the campaign is
still running because each completed target has an atomic result checkpoint:

```sh
govfuzz-bug-report /results/govfuzz-real
```

The script writes and prints `govfuzz-support-report.txt`, capped at 4,000 bytes
by default. It contains version/host/toolchain lines, outcomes by language,
structured build-error and repair counts, checkpoint health, and a small set of
the most frequent diagnostic shapes. It does not read or include source,
generated harness code, or corpus inputs. Project paths, file names, targets,
variables, types, Ada units, symbols, and macros are replaced with typed
placeholders before the report is written.

The equivalent direct CLI command is:

```sh
govfuzz bug-report /results/govfuzz-real \
  --output govfuzz-support-report.txt \
  --stdout
```

Send only that scrubbed text file. The raw `result.json`, `run.json`, build
trees, and source are not required for ordinary build/harness triage.

## Acceptance Check

Use `/results/govfuzz-real/auto/run.json` as the machine-readable evidence.
A dynamically successful target should report `built_and_fuzzed`, at least one
execution, and positive coverage. Review these fields and artifacts:

- `summary.built_and_fuzzed` and per-target outcomes;
- per-pass `executions` and `coverage_edges`;
- repairs and the `needed_for_build` ledger;
- `fuzzed_stub_only`, forced notes, and stub execution evidence;
- `auto/missing-deps.txt` for still-blocking offline content;
- the first `Required toolchains, runtimes, generated and vendor source`
  section in that file before reviewing lower-level headers/symbols;
- `auto/bug-report.md` for defects in GovFuzz itself.

Treat a zero-coverage run, a forced-only result, or a stub-only result as a gap,
not as proof that the real target was fuzzed.
