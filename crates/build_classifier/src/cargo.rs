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
        let error_lines: Vec<&str> = stderr
            .lines()
            .filter(|line| {
                let l = line.trim_start();
                l.starts_with("error") || l.contains("error:")
            })
            .take(8)
            .collect();
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

    #[test]
    fn dedups_repeated_unresolved() {
        let stderr =
            "error[E0432]: unresolved import `a::b`\nerror[E0432]: unresolved import `a::b`\n";
        let kinds = classify(stderr);
        assert_eq!(kinds.len(), 1);
    }
}
