<!-- SPDX-License-Identifier: Apache-2.0 -->
# Next.js Static-Scan Generated-Bundle Pruning - 2026-07-08

This memo records the follow-up validation for the `next` timeout found during
the 50-project `GF-512` framework raw-HTML sweep.

## Scope

- Worktree: `static-scan-generated-skip-2026-07-08`
- Repo under test:
  `/tmp/govfuzz-sast-gf512-framework-sweep-2026-07-07/repos/next`
- Scanner: `target/debug/govfuzz static-scan <path> --debug --enable-rule GF-512`
- Original symptom: full-tree Next.js scan timed out under a 600 second cap with
  no report.

## Root Cause Evidence

The Next.js tree contains many generated and vendored JavaScript bundles under
`packages/next/src/compiled`. Scanning that subtree produced zero `GF-512`
findings but consumed most of the `packages/next/src` budget:

| Path | Current pre-fix time | Findings |
|---|---:|---:|
| `packages/next/src/compiled` | 142.14 s | 0 |
| `packages/next/src` | 169.82 s | 0 |
| `test/e2e/app-dir` | 21.21 s | 0 |
| `test` | 77.73 s | 0 |
| `turbopack/crates/turbopack-ecmascript` | 22.81 s | 0 |
| `.github/actions` | 0.55 s | 0 |
| `examples` | 7.48 s | 0 |

This matched the scanner's existing SAST/SCA boundary: source SAST should scan
the project code, while dependency and generated payloads are handled by
SBOM/SCA inventory rather than source taint rules.

## Fix

The static scanner now prunes directory components named `compiled` during the
tree walk, alongside `node_modules`, `dist`, `vendor`, `third_party`, virtualenvs,
caches, and other dependency/build outputs.

## Focused Rescan

After pruning `compiled/` child directories:

| Path | Post-fix time | Findings |
|---|---:|---:|
| `packages/next/src` | 20.23 s | 0 |
| full Next.js tree | 253.79 s | 0 |

The full Next.js `GF-512` scan now exits successfully under the same 600 second
cap that previously timed out.

## Verification Commands

```sh
CARGO_TARGET_DIR=/path/to/govfuzz/target \
  cargo test -p static_analysis tree_walk_skips_dependency_and_build_dirs -- --nocapture

CARGO_TARGET_DIR=/path/to/govfuzz/target \
  cargo build -p govfuzz

timeout 600s /path/to/govfuzz/target/debug/govfuzz static-scan \
  /tmp/govfuzz-sast-gf512-framework-sweep-2026-07-07/repos/next \
  --out /tmp/gf-next-full-compiled-excluded \
  --debug \
  --enable-rule GF-512
```
