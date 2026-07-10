// SPDX-License-Identifier: Apache-2.0

//! Static SDK for fake-resource plugins. Each plugin is a unit
//! struct that implements `FakeResource` and registers a matching
//! `ManifestEntry`. The trait carries metadata only — actual libc
//! interception is done by `#[no_mangle] extern "C" fn` declarations
//! the dynamic linker resolves when the shim is LD_PRELOAD'ed.
//!
//! `MANIFEST` (in `manifest.rs`) is the cli-safe view of the same
//! data: pure POD slices the cli can read without linking the
//! interceptors. A unit test in `registry.rs` asserts the two slices
//! stay in sync.

/// A virtualized resource. Implementations are unit structs (no
/// runtime state) referenced by static dispatch in `REGISTRY`.
pub trait FakeResource: Sync {
    /// Stable kebab-case identifier (e.g. `"identity"`).
    fn name(&self) -> &'static str;

    /// libc symbol names this plugin overrides, NUL-terminated.
    fn intercepts(&self) -> &'static [&'static [u8]];

    /// Returns true when the plugin's interception is active in
    /// this process. Advisory only — used by `--list-fakes` to
    /// distinguish "always-on" intercepts from env-var-gated ones.
    fn is_enabled(&self) -> bool;

    /// One-line human description of what is faked.
    fn describe(&self) -> &'static str;
}

/// Plain-data view of a plugin used by callers that must not link
/// libc interception code (the cli). Re-exported from
/// `runtrace_manifest` so the shim and the cli share a single
/// definition.
pub use runtrace_manifest::ManifestEntry;

#[cfg(test)]
mod tests {
    use super::{FakeResource, ManifestEntry};

    struct Demo;
    impl FakeResource for Demo {
        fn name(&self) -> &'static str {
            "demo"
        }
        fn intercepts(&self) -> &'static [&'static [u8]] {
            &[b"demo\0"]
        }
        fn is_enabled(&self) -> bool {
            false
        }
        fn describe(&self) -> &'static str {
            "demo plugin"
        }
    }

    #[test]
    fn fake_resource_is_object_safe() {
        let plugin: &dyn FakeResource = &Demo;
        assert_eq!(plugin.name(), "demo");
        assert_eq!(plugin.intercepts(), &[b"demo\0" as &[u8]]);
        assert!(!plugin.is_enabled());
        assert_eq!(plugin.describe(), "demo plugin");
    }

    #[test]
    fn manifest_entry_always_on_has_empty_env_var() {
        let entry = ManifestEntry::always_on("demo", &[b"demo\0"], "demo plugin");
        assert_eq!(entry.env_var, "");
        assert!(!entry.is_gated());
    }

    #[test]
    fn manifest_entry_gated_marks_is_gated() {
        let entry = ManifestEntry::gated("demo", &[b"demo\0"], "GOVFUZZ_FAKE_DEMO", "demo plugin");
        assert_eq!(entry.env_var, "GOVFUZZ_FAKE_DEMO");
        assert!(entry.is_gated());
    }
}
