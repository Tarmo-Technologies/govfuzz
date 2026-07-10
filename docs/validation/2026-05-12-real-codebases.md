<!-- SPDX-License-Identifier: Apache-2.0 -->

# Real Codebase Validation - 2026-05-12

Issue: <https://github.com/Tarmo-Technologies/govfuzz/issues/200>

Workspace: `/tmp/govfuzz-validation-200`

## Repositories

| Repository | Commit | Ada files | IDL files | Result |
|---|---:|---:|---:|---|
| `zertovitch/hac` | `482c22ea8a000cb316fb068559ec83cdfbfad9bd` | 390 | 0 | Scan blocked by non-UTF-8 Ada source files. |
| `stcarrez/ada-util` | `6892c6c091723de5d816edc120a2a41f114fbf9e` | 538 | 0 | Target discovery and instrumentation worked; generated harness needs project source-root context to build. |
| `yaml/AdaYaml` | `7fde22a1a564bbece3e97430f469717ac46e5842` | 130 | 0 | Target discovery and instrumentation worked; top targets mostly exceed current direct-call harness type support. |
| `troeger/corba-example` | `bd853b16637edfc472239536296034efda69b653` | 0 | 1 | Fake CORBA generation from IDL worked. |
| `OpenDDS/OpenDDS` | `50140f6995cbffab59e294b7998f2e5ab19c9dea` | 0 | 233 | Simple CorbaSeq IDL worked; annotated DDS IDL failed on annotation syntax. |

## Commands And Outcomes

### Target Discovery

```sh
cargo run -p govfuzz -- list-targets /tmp/govfuzz-validation-200/repos/AdaYaml --format json --top 20
cargo run -p govfuzz -- list-targets /tmp/govfuzz-validation-200/repos/ada-util --format json --top 20
cargo run -p govfuzz -- list-targets /tmp/govfuzz-validation-200/repos/hac --format json --top 20
```

`AdaYaml` returned 20 ranked targets in 0.58 seconds. The top target was
`yaml-presenter.adb` / `put`, score 200.

`ada-util` returned 20 ranked targets in 1.68 seconds. The top target was
`util-encoders-base32.adb` / `transform`, score 110.

`hac` originally exited non-zero before returning targets because the scanner
attempted to read non-UTF-8 Ada sources as UTF-8. After #211 and #201,
standalone scan completed successfully:

```sh
cargo run -p govfuzz -- scan /tmp/govfuzz-validation-200/repos/hac --work-dir /tmp/govfuzz-validation-200/results/hac-scan-work
```

The scan wrote `scan_index.json`, parsed 388 Ada files, skipped the 2
unsupported-encoding files with diagnostics, and found 3709 target candidates.

### Instrumentation

```sh
cargo run -p govfuzz -- instrument /tmp/govfuzz-validation-200/repos/AdaYaml/src/implementation/yaml-presenter.adb --output /tmp/govfuzz-validation-200/results/AdaYaml-instrumented
cargo run -p govfuzz -- instrument /tmp/govfuzz-validation-200/repos/ada-util/src/sys/encoders/util-encoders-base32.adb --output /tmp/govfuzz-validation-200/results/ada-util-instrumented
```

Both commands exited 0 and wrote an instrumented source file plus
`breadcrumbs.json`.

### Harness Generation

```sh
cargo run -p govfuzz -- generate-harness /tmp/govfuzz-validation-200/repos/ada-util/src/base/dates/util-dates-iso8601.adb --target value --output /tmp/govfuzz-validation-200/results/ada-util-value-harness
gprbuild -P /tmp/govfuzz-validation-200/results/ada-util-value-harness/H-C34C/H_C34C.gpr
```

Harness generation exited 0 for `Util.Dates.ISO8601.Value`, but `gprbuild`
failed because the generated project only included the target file directory and
missed parent package source roots:

```text
main.adb:10:06: error: file "util.ads" not found
gprbuild: *** compilation phase failed
```

The highest-ranked `AdaYaml` and `ada-util` targets also showed the expected
current M3 limitation for direct-call harnesses: unsupported non-scalar,
non-string parameters.

### IDL / Fake CORBA

```sh
cargo run -p govfuzz -- fake-corba /tmp/govfuzz-validation-200/results/corba-example-work --idl /tmp/govfuzz-validation-200/repos/corba-example/echo.idl
cargo run -p govfuzz -- fake-corba /tmp/govfuzz-validation-200/results/opendds-corbaseq-work --idl /tmp/govfuzz-validation-200/repos/OpenDDS/dds/CorbaSeq/StringSeq.idl
cargo run -p govfuzz -- fake-corba /tmp/govfuzz-validation-200/results/opendds-messenger-work --idl /tmp/govfuzz-validation-200/repos/OpenDDS/DevGuideExamples/DCPS/Messenger/Messenger.idl
```

`corba-example/echo.idl` generated 4 fake CORBA files and 9 IDL mapping files.

`OpenDDS/dds/CorbaSeq/StringSeq.idl` generated 4 fake CORBA files and 2 IDL
mapping files.

`OpenDDS/DevGuideExamples/DCPS/Messenger/Messenger.idl` initially failed on DDS
annotation syntax:

```text
unexpected character '@' at line 8, column 3
```

## Issues Opened

- <https://github.com/Tarmo-Technologies/govfuzz/issues/211> - scanner should not abort project scans on non-UTF-8 Ada files.
- <https://github.com/Tarmo-Technologies/govfuzz/issues/212> - generated harness projects need real project source roots/dependencies.
- <https://github.com/Tarmo-Technologies/govfuzz/issues/213> - IDL parser should tolerate DDS/OpenDDS annotations.
- <https://github.com/Tarmo-Technologies/govfuzz/issues/214> - `fake-corba --idl` should not require an existing `src_instrumented` tree.
- <https://github.com/Tarmo-Technologies/govfuzz/issues/215> - harness source-root support should discover or expand real Ada source trees.
- <https://github.com/Tarmo-Technologies/govfuzz/issues/216> - IDL parser needs include path support for real OpenDDS include trees.
- <https://github.com/Tarmo-Technologies/govfuzz/issues/217> - IDL partial parsing should recover from missing includes and unsupported preprocessor branches.

## Reduced Reproducer

`examples/annotated_idl/` contains a reduced DDS/OpenDDS annotation fixture
derived from the `OpenDDS` Messenger IDL failure. After #213, the fixture parses
and fake CORBA generation ignores the unsupported annotations with warnings.

## Next Validation Slice

The 2026-05-12 rerun covered the #211, #212, and #213 follow-up items. Next,
address #214 through #216, then expand to repositories with complete GPR
projects and Alire metadata. Add one IDL validation slice that uses configured
include roots and nested angle-bracket includes.

## Rerun After Fixes

Date: 2026-05-12

Workspace: `/tmp/govfuzz-validation-200/rerun-2026-05-12`

### Baseline Checks

```sh
cargo test --workspace
npm test
python3 -m pytest editors/gnatstudio/tests
```

Results:

- `cargo test --workspace`: passed.
- `npm test` in `editors/vscode`: passed, 13 tests.
- `python3 -m pytest editors/gnatstudio/tests`: passed, 11 tests.
- `python -m pytest ...` was attempted first and failed because `python` is not
  installed; `python3` is present and works.

### Target Discovery And Scan

```sh
cargo run -p govfuzz -- list-targets /tmp/govfuzz-validation-200/repos/AdaYaml --format json --top 20
cargo run -p govfuzz -- list-targets /tmp/govfuzz-validation-200/repos/ada-util --format json --top 20
cargo run -p govfuzz -- list-targets /tmp/govfuzz-validation-200/repos/hac --format json --top 20
cargo run -p govfuzz -- scan /tmp/govfuzz-validation-200/repos/hac --work-dir /tmp/govfuzz-validation-200/rerun-2026-05-12/results/hac-scan-work
```

Results:

- `AdaYaml`: returned 20 ranked targets. Top target:
  `src/implementation/yaml-presenter.adb` / `put`, score 200.
- `ada-util`: returned 20 ranked targets. Top target:
  `src/sys/encoders/util-encoders-base32.adb` / `transform`, score 110.
- `hac`: returned 20 ranked targets. Top target:
  `src/execute/hac_sys-pcode-interpreter.adb` / `interpret`, score 247.
- `hac` scan wrote `scan_index.json`, parsed 388 Ada files, skipped 2
  unsupported-encoding files with diagnostics, and found 3709 target candidates.

This validates the non-UTF-8 source handling from #211 for both `scan` and
`list-targets`.

### Instrumentation

```sh
cargo run -p govfuzz -- instrument /tmp/govfuzz-validation-200/repos/AdaYaml/src/implementation/yaml-presenter.adb --output /tmp/govfuzz-validation-200/rerun-2026-05-12/results/AdaYaml-instrumented
cargo run -p govfuzz -- instrument /tmp/govfuzz-validation-200/repos/ada-util/src/sys/encoders/util-encoders-base32.adb --output /tmp/govfuzz-validation-200/rerun-2026-05-12/results/ada-util-instrumented
```

Both commands exited 0 and wrote an instrumented source file plus
`breadcrumbs.json`.

### Harness Generation And Build

`--source-root` is now accepted, but passing the broad repository `src`
directory is insufficient for real GNAT source lookup because generated GPR
`Source_Dirs` are non-recursive:

```sh
cargo run -p govfuzz -- generate-harness /tmp/govfuzz-validation-200/repos/ada-util/src/base/dates/util-dates-iso8601.adb \
  --target value \
  --source-root /tmp/govfuzz-validation-200/repos/ada-util/src \
  --output /tmp/govfuzz-validation-200/rerun-2026-05-12/results/ada-util-value-harness
gprbuild -P /tmp/govfuzz-validation-200/rerun-2026-05-12/results/ada-util-value-harness/H-C34C/H_C34C.gpr
```

Build result:

```text
main.adb:11:06: error: file "util.ads" not found
gprbuild: *** compilation phase failed
```

Passing the actual package source directories builds and the harness runs once
from stdin:

```sh
cargo run -p govfuzz -- generate-harness /tmp/govfuzz-validation-200/repos/ada-util/src/base/dates/util-dates-iso8601.adb \
  --target value \
  --source-root /tmp/govfuzz-validation-200/repos/ada-util/src/core \
  --source-root /tmp/govfuzz-validation-200/repos/ada-util/src/base \
  --source-root /tmp/govfuzz-validation-200/repos/ada-util/src/base/dates \
  --output /tmp/govfuzz-validation-200/rerun-2026-05-12/results/ada-util-value-harness-expanded
gprbuild -P /tmp/govfuzz-validation-200/rerun-2026-05-12/results/ada-util-value-harness-expanded/H-C34C/H_C34C.gpr
printf '2026-05-12T00:00:00Z' | /tmp/govfuzz-validation-200/rerun-2026-05-12/results/ada-util-value-harness-expanded/H-C34C/obj/main
```

The remaining source-root discovery/ergonomics gap is tracked in #215.

### IDL / Fake CORBA

Running `fake-corba --idl` against a fresh work directory still fails unless
`<work-dir>/src_instrumented` exists, even when the validation intent is IDL
only:

```text
generate fake CORBA under '/tmp/govfuzz-validation-200/rerun-2026-05-12/results/corba-example-work/fake_corba': No such file or directory (os error 2)
```

After creating an empty `src_instrumented` directory, the prior passing IDL
cases still pass:

```sh
mkdir -p /tmp/govfuzz-validation-200/rerun-2026-05-12/results/corba-example-work/src_instrumented
mkdir -p /tmp/govfuzz-validation-200/rerun-2026-05-12/results/opendds-corbaseq-work/src_instrumented
mkdir -p /tmp/govfuzz-validation-200/rerun-2026-05-12/results/opendds-messenger-work/src_instrumented
cargo run -p govfuzz -- fake-corba /tmp/govfuzz-validation-200/rerun-2026-05-12/results/corba-example-work --idl /tmp/govfuzz-validation-200/repos/corba-example/echo.idl
cargo run -p govfuzz -- fake-corba /tmp/govfuzz-validation-200/rerun-2026-05-12/results/opendds-corbaseq-work --idl /tmp/govfuzz-validation-200/repos/OpenDDS/dds/CorbaSeq/StringSeq.idl
cargo run -p govfuzz -- fake-corba /tmp/govfuzz-validation-200/rerun-2026-05-12/results/opendds-messenger-work --idl /tmp/govfuzz-validation-200/repos/OpenDDS/DevGuideExamples/DCPS/Messenger/Messenger.idl
```

Results:

- `corba-example/echo.idl`: generated 4 fake CORBA files and 9 IDL mapping files.
- `OpenDDS/dds/CorbaSeq/StringSeq.idl`: generated 4 fake CORBA files and 2 IDL
  mapping files.
- `OpenDDS/DevGuideExamples/DCPS/Messenger/Messenger.idl`: generated 4 fake
  CORBA files and 1 IDL mapping file, with warnings for ignored `@topic` and
  `@key` annotations.

This validates the annotation handling from #213. The IDL-only source directory
prerequisite is tracked in #214.

An include-heavy OpenDDS IDL still fails because includes are resolved only
relative to the current file:

```sh
mkdir -p /tmp/govfuzz-validation-200/rerun-2026-05-12/results/opendds-type-lookup-work/src_instrumented
cargo run -p govfuzz -- fake-corba /tmp/govfuzz-validation-200/rerun-2026-05-12/results/opendds-type-lookup-work \
  --idl /tmp/govfuzz-validation-200/repos/OpenDDS/etc/xtypes/type_lookup.idl
```

Result:

```text
parse IDL '/tmp/govfuzz-validation-200/repos/OpenDDS/etc/xtypes/type_lookup.idl': read /tmp/govfuzz-validation-200/repos/OpenDDS/etc/xtypes/RtpsRpc.idl: No such file or directory (os error 2) at line 1, column 1
```

`RtpsRpc.idl` exists elsewhere in the same repository at
`dds/DCPS/RTPS/RtpsRpc.idl` and includes additional IDL through both quoted and
angle-bracket include forms. Include-path support is tracked in #216.

## Final Fix Rerun

Date: 2026-05-12

Workspace: `/tmp/govfuzz-validation-200/final-2026-05-12`

This rerun covered the combined pending branches for #214, #215, #216, and #217
after making missing or partial software inputs recoverable for
`fake-corba --idl`. Until those code PRs are merged, this section is evidence
for the staged validation branch set rather than a claim about `main`.

### Verification Gates

```sh
cargo test --workspace
npm test
python3 -m pytest editors/gnatstudio/tests
```

Results:

- `cargo test --workspace`: passed after the final parser hardening pass.
- `npm test` in `editors/vscode`: passed, 13 tests.
- `python3 -m pytest editors/gnatstudio/tests`: passed, 11 tests.

### Ada Real-Code Slice

```sh
cargo run -p govfuzz -- list-targets /tmp/govfuzz-validation-200/repos/AdaYaml --format json --top 20
cargo run -p govfuzz -- list-targets /tmp/govfuzz-validation-200/repos/ada-util --format json --top 20
cargo run -p govfuzz -- list-targets /tmp/govfuzz-validation-200/repos/hac --format json --top 20
cargo run -p govfuzz -- scan /tmp/govfuzz-validation-200/repos/hac --work-dir /tmp/govfuzz-validation-200/final-2026-05-12/results/hac-scan-work
```

Results:

- `AdaYaml`: returned 20 ranked targets.
- `ada-util`: returned 20 ranked targets.
- `hac`: returned 20 ranked targets.
- `hac` scan completed with 388 parsed files and 3709 targets; 2 non-UTF-8 Ada
  files were recorded under `skipped` instead of aborting the scan.

Instrumentation passed for the same AdaYaml and ada-util targets used earlier.

The ada-util harness now accepts an expanded source tree:

```sh
cargo run -p govfuzz -- generate-harness /tmp/govfuzz-validation-200/repos/ada-util/src/base/dates/util-dates-iso8601.adb \
  --target value \
  --source-tree /tmp/govfuzz-validation-200/repos/ada-util/src \
  --output /tmp/govfuzz-validation-200/final-2026-05-12/results/ada-util-value-harness-source-tree
gprbuild -P /tmp/govfuzz-validation-200/final-2026-05-12/results/ada-util-value-harness-source-tree/H-C34C/H_C34C.gpr
printf '2026-05-12T00:00:00Z' | /tmp/govfuzz-validation-200/final-2026-05-12/results/ada-util-value-harness-source-tree/H-C34C/obj/main
```

Generation, `gprbuild`, and the one-input harness run all exited 0.

### IDL / Fake CORBA Slice

`fake-corba --idl` no longer requires a pre-existing `src_instrumented`
directory for IDL-only runs.

```sh
cargo run -p govfuzz -- fake-corba /tmp/govfuzz-validation-200/final-2026-05-12/results/corba-example-work --idl /tmp/govfuzz-validation-200/repos/corba-example/echo.idl
cargo run -p govfuzz -- fake-corba /tmp/govfuzz-validation-200/final-2026-05-12/results/opendds-corbaseq-work --idl /tmp/govfuzz-validation-200/repos/OpenDDS/dds/CorbaSeq/StringSeq.idl
cargo run -p govfuzz -- fake-corba /tmp/govfuzz-validation-200/final-2026-05-12/results/opendds-messenger-work --idl /tmp/govfuzz-validation-200/repos/OpenDDS/DevGuideExamples/DCPS/Messenger/Messenger.idl
cargo run -p govfuzz -- fake-corba /tmp/govfuzz-validation-200/final-2026-05-12/results/opendds-type-lookup-work-finalcheck \
  --idl /tmp/govfuzz-validation-200/repos/OpenDDS/etc/xtypes/type_lookup.idl \
  --idl-include-dir /tmp/govfuzz-validation-200/repos/OpenDDS/dds/DCPS/RTPS \
  --idl-include-dir /tmp/govfuzz-validation-200/repos/OpenDDS
```

Results:

- `corba-example/echo.idl`: generated 4 fake CORBA files and 9 IDL mapping files.
- `OpenDDS/dds/CorbaSeq/StringSeq.idl`: generated 4 fake CORBA files and 2 IDL
  mapping files.
- `OpenDDS/DevGuideExamples/DCPS/Messenger/Messenger.idl`: generated 4 fake
  CORBA files and 1 IDL mapping file.
- `OpenDDS/etc/xtypes/type_lookup.idl`: generated 4 fake CORBA files and 128 IDL
  mapping files with include roots configured.

The include-heavy OpenDDS run produced recoverable warnings for missing TAO
headers, unsupported preprocessor branches, ignored DDS annotations, named
bounds, arrays, and union declarations. The run did not abort. This validates
the #217 policy that incomplete source trees should degrade with warnings and
continue wherever the remaining IDL can still be used.
