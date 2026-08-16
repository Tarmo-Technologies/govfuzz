<!-- SPDX-License-Identifier: Apache-2.0 -->

# GovFuzz v0.2.31 release notes

Released 2026-08-15.

This release makes automatic harnessing materially closer to an expert-written
driver and makes large campaigns safe to leave running. It is grounded in a
pinned 200-project audit across all sixteen supported languages, with one
independently reviewed expert harness per lane, plus the existing blind
30-project C/C++ line-coverage comparison.

## Findings are now the front door

Every `auto` run writes an impact-ordered `<work>/FINDINGS.md` at the work-
directory root. It shows grouped root-cause issues, locations, confidence,
evidence, remediation, and replay commands. `<work>/findings.csv` is the matching
machine-readable grouped index, and `<work>/findings/` contains the complete
evidence bundles. The historical `<work>/auto/findings.csv` remains as a
compatibility alias; campaign mechanics and coverage stay under `<work>/auto/`.

The terminal summary now leads with the finding count and these paths before the
coverage and blocker breakdown. A run with no findings still creates the indexes,
so automation has one stable place to start.

## Bounded output and non-destructive cleanup

GovFuzz v0.2.27 could retain a private Cargo `target/` tree for every attempted
Rust harness. A measured real tree was about 589 MiB per target; multiplied across
roughly 70 candidates, that explains the reported 40+ GiB work directory. Those
trees are compiler intermediates, not replay evidence.

Rust build caches are now removed on every build return path after the final
replay harness has consumed them. `auto` also repairs old work directories at
startup. For explicit maintenance:

```sh
govfuzz clean govfuzz_work --compact
```

Compaction removes disposable compiler caches and scratch data while preserving
findings, reports, coverage corpora, result checkpoints, generated harness source,
and final replay binaries.

Two defaults bound future campaigns:

- `--max-work-dir-mb 4096` stops admitting new targets once allocated work-
  directory blocks reach 4 GiB. Findings are never deleted to meet the limit;
  in-flight targets finish and the report records the cutoff. `0` disables it.
- `--max-corpus-mb 64` bounds each target's active and persisted coverage corpus
  at 64 MiB. Finding testcases are stored separately and never evicted.

Both options are valid `.govfuzz.toml` keys. Parallel in-flight targets can
produce a bounded final overshoot, so the work-directory limit is an admission
ceiling rather than an unsafe hard-delete quota.

## Expert-parity auto harnessing

All sixteen generators now checkpoint immediately before the selected target
call. Loading a module, decoding input, or completing setup no longer counts as a
successful fuzz target entry.

The audit drove these expert setup levers into the automatic lanes:

- identifier-token-aware ranking favors public parsers, decoders, whole-artifact
  APIs, and stateful execution surfaces without substring false matches such as
  `download` → `load` or `reload` → `load`;
- JavaScript, Ruby, and COBOL materialize file/path inputs; JavaScript awaits
  returned promises before deleting temporary resources;
- Go mines a bounded feeder → terminal sequence (including Cobra `SetArgs` →
  `Execute`) and retries exact-package instrumentation when unrelated packages
  break module-wide coverage;
- PHP resolves imported types and creates bounded scalar, array, enum, date, and
  constructor graphs for typed parameters;
- C++ recovers macro-declared class scope, defaulted arguments, common public
  member-template instantiation, rvalue byte strings, and default-template aliases;
- Fortran emits correct descriptors for assumed-shape character arrays;
- C# builds a separate target library, instruments only project IL, handles
  BOM-prefixed global usings, and avoids nested `obj/` duplicate attributes;
- runtime smoke tests execute in the harness directory, while VMs with native
  language coverage avoid incompatible native preload tracing.

The clean durable audit completed 200/200 rows, proved 118 selected calls entered,
and dynamically covered 105 project bodies. Focused final-binary Go and C++
reruns raise the explicitly labeled cross-run composite to 113/200. Against the
independent expert set, the final binary entered and covered 16/16 selected
endpoints and matched the expert's normalized semantic entrypoint in 13/16 lanes,
up from 6/16. The three differences include two viable alternative target choices
(COBOL and PHP) and one real residual capability gap (private in-package Rust).

## Remaining manual-harness territory

The audit keeps the remaining gaps explicit: private Rust in-crate targets and
resource recipes; generated/platform-specific full build graphs; framework hosts
and unavailable package ecosystems; coherent scientific arrays with coupled
dimensions; and longer constructor → feed → execute → cleanup protocols. These
are documented in the published expert-parity audit and are not counted as clean
or successful when GovFuzz only reaches setup.

## Release installation

For offline or air-gapped Linux deployment, use the full
`govfuzz-dist-0.2.31-x86_64-unknown-linux-gnu.tar.gz` asset and its SHA-256
sidecar. It contains `install.sh`, `INSTALL.md`, the CLI and daemon, both preload
shims, all harness runtimes, this release note, and the recommended sweep guide.
Component archives and native Windows installers remain available for narrower
installations.
