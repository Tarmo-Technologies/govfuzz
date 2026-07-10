// SPDX-License-Identifier: Apache-2.0

//! Print the fake-resource plugin inventory in a fixed-width
//! table. Reads `govfuzz_runtrace_shim::manifest::MANIFEST` (the
//! cli-safe POD slice) so this code path does not link any libc
//! interceptors.

use runtrace_manifest::{ManifestEntry, MANIFEST};

pub fn render() -> String {
    render_entries(MANIFEST)
}

fn render_entries(entries: &[ManifestEntry]) -> String {
    let mut out = String::new();
    out.push_str("NAME                STATE        ENV_VAR                     INTERCEPTS\n");
    for entry in entries {
        let state = if entry.is_gated() {
            "env-gated"
        } else {
            "always-on"
        };
        let env_var = if entry.is_gated() {
            entry.env_var
        } else {
            "(always-on)"
        };
        out.push_str(&format!(
            "{:<20}{:<13}{:<28}{}\n",
            entry.name,
            state,
            env_var,
            intercepts_str(entry.intercepts),
        ));
    }
    out
}

fn intercepts_str(intercepts: &[&[u8]]) -> String {
    let mut s = String::new();
    for (i, name) in intercepts.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        let trimmed = if name.last() == Some(&0) {
            &name[..name.len() - 1]
        } else {
            name
        };
        s.push_str(std::str::from_utf8(trimmed).unwrap_or("<non-utf8>"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::{render, render_entries};
    use runtrace_manifest::ManifestEntry;

    #[test]
    fn render_lists_all_known_plugins() {
        let out = render();
        for name in ["env", "net", "fs", "dl", "dlsym", "proc", "identity"] {
            assert!(out.contains(name), "{name} present in output");
        }
    }

    #[test]
    fn render_marks_identity_env_gated() {
        let out = render();
        assert!(out.contains("identity"));
        assert!(out.contains("env-gated"));
        assert!(out.contains("GOVFUZZ_FAKE_IDENTITY"));
    }

    #[test]
    fn render_marks_legacy_plugins_always_on() {
        let out = render_entries(&[ManifestEntry::always_on(
            "demo",
            &[b"demo\0"],
            "demo plugin",
        )]);
        assert!(out.contains("always-on"));
        assert!(out.contains("(always-on)"));
    }

    #[test]
    fn render_strips_nul_terminator_from_intercept_names() {
        let out = render_entries(&[ManifestEntry::always_on(
            "demo",
            &[b"foo\0", b"bar\0"],
            "demo plugin",
        )]);
        assert!(out.contains("foo bar"));
        assert!(!out.contains("foo\0"));
    }
}
