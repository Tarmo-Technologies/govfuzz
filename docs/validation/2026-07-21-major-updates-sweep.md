<!-- SPDX-License-Identifier: Apache-2.0 -->

# Post-update 53-project validation sweep (2026-07-21)

This validation was run after the RHEL 7 compatibility and generic C/C++
driver changes. It combines the pinned broken-project matrix with the complete
workspace and distribution checks so both legacy recovery and GovFuzz's wider
functionality are covered.

## Project sweep

The canonical manifest contains 53 pinned real repositories: 29 C, 12 C++, and
12 Ada. Each repository was run first as an unmodified control and then as a
deliberately damaged local Git clone, for 106 project runs total. Acceptance
requires the exact selected target to build and fuzz, positive executions and
coverage, a recorded repair in the damaged tree, and no selected-target stub.

```sh
GOVFUZZ_BIN=target/release/govfuzz \
python3 scripts/validation/legacy-breakage-matrix.py \
  --manifest tests/fixtures/legacy_breakage_validation/expanded-manifest.toml \
  --workspace /tmp/govfuzz-expanded-major-updates-20260721 \
  --offline --jobs 3 \
  --json-out /tmp/govfuzz-expanded-major-updates-20260721-result.json \
  --markdown-out /tmp/govfuzz-expanded-major-updates-20260721-result.md
```

| Population | Clean controls | Damaged recovery |
|---|---:|---:|
| Raw 53 repositories | 47/53 (88.7%) | 48/53 (90.6%) |
| Verified external constraints | 6 | 6 |
| In-scope repositories | **47/47 (100%)** | **47/47 (100%)** |

The six constraints were proved by pinned repository evidence and exact runtime
signatures: Ada Drivers Library (ARM cross-toolchain), Drake (version-matched
GNAT runtime), GNATCOLL Bindings (separate source dependency), RE2 (absent
Abseil source), TAMP (embedded ARM runtime/toolchain), and YAML-Ada (generated
binding). TAMP's damaged copy ran using a host substitution, but its clean
embedded runtime remained correctly classified as external and was not counted
as an in-scope success.

Successful repair rounds were p50 2, p95 6, p99 14, and maximum 14 under the
configured cap of 16. Full per-scenario results are retained in the JSON and
Markdown paths shown above; the stable manifest is checked into the repository.

## Wider regression coverage

- `cargo test --workspace --no-fail-fast --quiet` passed, exercising all
  workspace crates and real integrations across C, C++, Ada, COBOL, Fortran,
  C#, Java, JavaScript/TypeScript, Lua, Perl, PHP, Python, Ruby, Rust, and Go,
  plus sanitizers, coverage guidance, oracles, capsule replay, static analysis,
  reporting, SBOM/SCA, binary analysis, and packaging.
- Strict `cargo clippy --workspace --all-targets -- -D warnings` and
  `cargo fmt --all -- --check` passed.
- The 550 harness-generator tests and 1,237 CLI library tests passed after the
  final lint cleanups.
- The Python validation suite (14 tests), GNAT Studio helper suite (12 tests),
  and VS Code extension suite (14 tests) passed.
- Shell syntax, ShellCheck, and parsing of every GitHub Actions workflow passed.

Two broader regressions were fixed during this pass. Sanitizer replay could
hang indefinitely when Ubuntu supplied a remote `DEBUGINFOD_URLS`; replay now
disables remote debuginfod lookup and the ASan bridge has a hard timeout.
Strict linting also exposed eight redundant or unnecessarily nested parser and
repair expressions, which were simplified without changing behavior.

## EL7 release confirmation

The final source was rebuilt in the pinned manylinux2014 image. The ABI gate
reported GLIBC 2.16 for `govfuzz` and `govfuzz-daemon`, and GLIBC 2.14 for the
runtime shim, below RHEL 7's GLIBC 2.17 ceiling. The final signed offline bundle
was then checksum-verified, installed, and fuzz-smoked on the retained CentOS
7.9 Proxmox VM with SELinux enforcing. A planted C stack overflow was also
found after 89 executions, packaged as a PoC capsule/tarball, and self-verified
with the expected AddressSanitizer signature on that guest. See the
[EL7 VM record](./2026-07-21-rhel7-proxmox.md).
