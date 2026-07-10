<!-- SPDX-License-Identifier: Apache-2.0 -->
# Contributing to govfuzz

Thanks for your interest in govfuzz. This guide covers how to build, test, and submit
changes. By contributing you agree that your contributions are licensed under the
project's [Apache-2.0](./LICENSE) license.

## Development setup

govfuzz is a Rust workspace of ~40 crates. You need a recent stable Rust toolchain
(and a **nightly** toolchain for the Rust fuzzing lane's sanitizer staticlib). Per-lane
work also needs the relevant toolchain — GNAT + GPRbuild for Ada, `clang`/`make` for
C/C++, a JDK for Java, `python3`/`perl`/`go` for those lanes. See the
[README](./README.md#prerequisites) for the full list; install only the lanes you touch.
Tests that need a missing toolchain skip themselves, so a passing run on a partial
toolchain does **not** exercise every lane — don't mistake a skip for a pass.

```sh
cargo build --workspace     # also produces libgovfuzz_runtrace_shim.so next to the binaries
cargo test  --workspace     # full suite (~3850 tests)
cargo test -p c_parser      # a single crate
cargo test -p govfuzz --test auto_attempt name_substring   # a single test
```

## Before you open a PR

These are hard gates (CI enforces them):

```sh
cargo fmt --all
cargo clippy --workspace --all-targets    # must be clean; deny-level lints fail CI
cargo run -p spdx_check -- generate       # update SPDX/manifest.json after adding/removing files
```

- **SPDX header on every new file.** Source files start with
  `// SPDX-License-Identifier: Apache-2.0` (or the language's comment form);
  `docs/` and root markdown use `<!-- SPDX-License-Identifier: Apache-2.0 -->`. After
  adding or removing any tracked file, re-run `spdx_check -- generate` — the License
  Audit workflow diffs `SPDX/manifest.json` and fails on an unrecorded file.
- **Dependencies are license-gated.** The permissive core profile may link only
  Apache-2.0 / MIT / BSD code. Adding a dependency requires an entry in the ROADMAP
  license matrix (§1.2) and in `deny.toml`, in the same change — `cargo deny` and the
  License Audit workflow enforce this.
- **Codegen changes need a fixture.** Anything emitted into a user's workspace (harness
  source, `.gpr`, Makefiles, stubs) must have a fixture under `examples/` or
  `tests/fixtures/` proving the emitted source actually compiles.
- **Write regression tests.** New behavior and bug fixes get a test. Prefer real tests
  over rubber-stamp assertions.

## Conventions

- Library crates test in-file (`#[cfg(test)]` at the bottom of `src/lib.rs`); CLI
  integration tests live in `crates/cli/tests/` and shell the binary or call `auto`
  internals against `tests/fixtures/`.
- `ROADMAP.md` is the engineering source of truth (license matrix, milestone criteria);
  user-facing behavior docs live in `docs/site/`. Keep both honest when behavior
  changes — README/docs drift is treated as a bug.
- Treat all scanned trees, manifests, corpus files, and child-process output as
  **untrusted input** — govfuzz's threat model is analyzing code you don't trust.

## Reporting bugs & security issues

Functional bugs: open a GitHub issue with a minimal reproducer. Security issues: see
[SECURITY.md](./SECURITY.md) — please report privately, not in a public issue.
