// SPDX-License-Identifier: Apache-2.0

//! Classify `cargo`/`rustc` (nightly) build error output for the native Rust
//! fuzzing lane into [`RustBuildError`] variants the attempt loop can act on.
//!
//! Unlike the gcc/clang and gnat packs, the Rust pack feeds a *small* repair
//! vocabulary: most Rust harness build failures are not "stub a missing symbol"
//! — the target crate either resolves by path (cargo handles its transitive
//! deps) or it doesn't build at all. The actionable cases are:
//!
//! - **`E0432`/`E0433` unresolved import / undeclared crate/module** — the
//!   generated call path is wrong (wrong crate name or module path). The repair
//!   is to drop the candidate (the path can't be auto-fixed without semantic
//!   resolution); surfaced as [`RustBuildError::UnresolvedPath`].
//! - **`E0061` wrong number of arguments / `E0308` mismatched types** — a decode
//!   produced an argument the target won't accept (e.g. a non-decodable param we
//!   defaulted). Surfaced as [`RustBuildError::SignatureMismatch`] so the
//!   candidate is skipped rather than retried forever.
//! - **`E0658` nightly feature / sanitizer flag rejected** — the toolchain isn't
//!   nightly or lacks `-Zsanitizer`; surfaced as
//!   [`RustBuildError::ToolchainUnsupported`] so the lane skips cleanly.
//! - Anything else -> [`RustBuildError::Other`] with the first real error line.

use serde::Serialize;

/// A classified Rust build failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RustBuildError {
    /// An unresolved import / undeclared crate or module: the generated call
    /// path doesn't resolve. `path` is the offending segment when recoverable.
    UnresolvedPath { path: String },
    /// The call's arguments don't match the target signature (arity or types).
    SignatureMismatch { detail: String },
    /// The toolchain can't build a sancov/ASan staticlib (not nightly, or the
    /// `-Z`/`-C` flag was rejected).
    ToolchainUnsupported { detail: String },
    /// Any other rustc/cargo error; `tail` carries the first real error line(s).
    Other { tail: String },
}

/// Classify captured cargo/rustc stderr into one error per distinct cause, in
/// source order. Always returns at least one element.
pub fn classify(stderr: &str) -> Vec<RustBuildError> {
    let mut hits = Vec::new();

    for line in stderr.lines() {
        let l = line.trim();
        // `error[E0432]: unresolved import `foo::bar``
        if let Some(rest) = l.strip_prefix("error[E0432]:") {
            push_unresolved(rest, &mut hits);
            continue;
        }
        if let Some(rest) = l.strip_prefix("error[E0433]:") {
            // `failed to resolve: use of undeclared crate or module `foo``
            push_unresolved(rest, &mut hits);
            continue;
        }
        if l.starts_with("error[E0061]:") {
            push_unique(
                &mut hits,
                RustBuildError::SignatureMismatch {
                    detail: l.to_owned(),
                },
            );
            continue;
        }
        if l.starts_with("error[E0308]:") {
            push_unique(
                &mut hits,
                RustBuildError::SignatureMismatch {
                    detail: l.to_owned(),
                },
            );
            continue;
        }
        if l.starts_with("error[E0658]:")
            || l.contains("sanitizer is not supported")
            || l.contains("requires `-Z")
            || l.contains("the option `Z` is only accepted on the nightly")
        {
            push_unique(
                &mut hits,
                RustBuildError::ToolchainUnsupported {
                    detail: l.to_owned(),
                },
            );
            continue;
        }
    }

    if hits.is_empty() {
        // Cargo wraps: the `error:` line is a BANNER and the diagnosis is in the
        // `Caused by:` block under it, whose lines start with neither.
        //
        //     error: failed to parse manifest at `/p/Cargo.toml`
        //
        //     Caused by:
        //       can't find library `fd_find`, rename file to src/lib.rs …
        //
        // Keeping only the banner reported eight fd targets as "failed to parse
        // manifest at X" and said nothing about why — the histogram grouped
        // them, and the cause had to be reproduced by hand to recover.
        let mut error_lines: Vec<&str> = Vec::new();
        let mut in_cause = false;
        for line in stderr.lines() {
            let l = line.trim_start();
            if l.starts_with("Caused by:") {
                in_cause = true;
                continue;
            }
            if in_cause {
                // The block is indented; the first unindented or blank line ends it.
                if l.is_empty() || line.trim_start() == line {
                    in_cause = false;
                } else {
                    error_lines.push(l);
                    continue;
                }
            }
            if l.starts_with("error") || l.contains("error:") {
                error_lines.push(line);
            }
        }
        error_lines.truncate(8);
        let tail = if error_lines.is_empty() {
            stderr
                .lines()
                .rev()
                .take(8)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            error_lines.join("\n")
        };
        hits.push(RustBuildError::Other { tail });
    }
    hits
}

fn push_unresolved(rest: &str, hits: &mut Vec<RustBuildError>) {
    // Pull the first backtick-quoted token as the offending path, if present.
    let path = rest
        .split('`')
        .nth(1)
        .map(str::to_owned)
        .unwrap_or_else(|| rest.trim().to_owned());
    push_unique(hits, RustBuildError::UnresolvedPath { path });
}

fn push_unique(hits: &mut Vec<RustBuildError>, e: RustBuildError) {
    if !hits.contains(&e) {
        hits.push(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unresolved_import_e0432() {
        let stderr = "error[E0432]: unresolved import `mycrate::nope`\n  --> harness.rs:5:9\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                RustBuildError::UnresolvedPath { path } if path == "mycrate::nope"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn undeclared_crate_e0433() {
        let stderr =
            "error[E0433]: failed to resolve: use of undeclared crate or module `wrongname`\n";
        let kinds = classify(stderr);
        assert!(
            kinds.iter().any(|k| matches!(
                k,
                RustBuildError::UnresolvedPath { path } if path == "wrongname"
            )),
            "got {kinds:?}"
        );
    }

    #[test]
    fn arity_mismatch_e0061() {
        let stderr = "error[E0061]: this function takes 2 arguments but 1 was supplied\n";
        let kinds = classify(stderr);
        assert!(
            kinds
                .iter()
                .any(|k| matches!(k, RustBuildError::SignatureMismatch { .. })),
            "got {kinds:?}"
        );
    }

    #[test]
    fn type_mismatch_e0308() {
        let stderr = "error[E0308]: mismatched types\n  expected `&str`, found `Vec<u8>`\n";
        let kinds = classify(stderr);
        assert!(
            kinds
                .iter()
                .any(|k| matches!(k, RustBuildError::SignatureMismatch { .. })),
            "got {kinds:?}"
        );
    }

    #[test]
    fn nightly_flag_rejected_is_toolchain_unsupported() {
        for stderr in [
            "error[E0658]: `-Zsanitizer=address` is experimental\n",
            "the option `Z` is only accepted on the nightly compiler\n",
            "error: this sanitizer is not supported on this platform\n",
        ] {
            let kinds = classify(stderr);
            assert!(
                kinds
                    .iter()
                    .any(|k| matches!(k, RustBuildError::ToolchainUnsupported { .. })),
                "{stderr:?} -> {kinds:?}"
            );
        }
    }

    #[test]
    fn unknown_error_surfaces_first_error_line() {
        let stderr = "   Compiling foo v0.1.0\nerror: could not compile `foo` due to gremlins\n";
        let kinds = classify(stderr);
        match kinds.as_slice() {
            [RustBuildError::Other { tail }] => {
                assert!(tail.contains("gremlins"), "{tail:?}")
            }
            other => panic!("expected single Other, got {other:?}"),
        }
    }

    /// Cargo's `error:` line is a banner when it wraps: the diagnosis lives in
    /// the `Caused by:` block below it, which starts with neither "error" nor
    /// "error:". Reporting only the banner said "failed to parse manifest at X"
    /// and nothing about why, on eight fd targets.
    #[test]
    fn a_wrapped_cargo_error_carries_its_caused_by() {
        let stderr = "error: failed to parse manifest at `/p/Cargo.toml`\n\n\
                      Caused by:\n  \
                      can't find library `fd_find`, rename file to `src/lib.rs` or specify \
                      lib.path\n";
        match classify(stderr).as_slice() {
            [RustBuildError::Other { tail }] => {
                assert!(tail.contains("failed to parse manifest"), "{tail:?}");
                assert!(
                    tail.contains("can't find library"),
                    "the cause must survive: {tail:?}"
                );
            }
            other => panic!("expected single Other, got {other:?}"),
        }

        // A `Caused by:` chain keeps every level, and an unindented line after
        // the block ends it rather than swallowing the rest of the transcript.
        let chained = "error: failed to get `x` as a dependency\n\n\
                       Caused by:\n  failed to load source\n  network unreachable\n\n\
                       Compiling something-else v1.0.0\n";
        match classify(chained).as_slice() {
            [RustBuildError::Other { tail }] => {
                assert!(tail.contains("network unreachable"), "{tail:?}");
                assert!(!tail.contains("Compiling something-else"), "{tail:?}");
            }
            other => panic!("expected single Other, got {other:?}"),
        }
    }

    #[test]
    fn dedups_repeated_unresolved() {
        let stderr =
            "error[E0432]: unresolved import `a::b`\nerror[E0432]: unresolved import `a::b`\n";
        let kinds = classify(stderr);
        assert_eq!(kinds.len(), 1);
    }
}
