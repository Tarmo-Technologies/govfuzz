// SPDX-License-Identifier: Apache-2.0

//! Compile-time registry of fake-resource plugins. Pairs with
//! `manifest::MANIFEST` (cli-safe POD). The unit test
//! `registry_and_manifest_match` keeps the two in sync.

use crate::hooks::{
    assertion::Assertion, cmplog::CmpLog, determinism::Determinism, dl::Dl, dlsym::Dlsym, env::Env,
    format::Format, fs::Fs, identity::Identity, ioctl::Ioctl, mem::Mem, mqueue::Mqueue, net::Net,
    proc::Proc, sql::Sql,
};
use crate::sdk::FakeResource;

pub static REGISTRY: &[&'static dyn FakeResource] = &[
    &Env,
    &Net,
    &Fs,
    &Dl,
    &Dlsym,
    &Proc,
    &Format,
    &Assertion,
    &Identity,
    &CmpLog,
    &Mem,
    &Mqueue,
    &Sql,
    &Determinism,
    &Ioctl,
];

/// Iterator over plugins whose `is_enabled()` returns true. Useful
/// for diagnostics; not consulted in the hook hot path (the
/// dynamic linker resolves intercepts by symbol name).
pub fn iter_enabled() -> impl Iterator<Item = &'static dyn FakeResource> {
    REGISTRY.iter().copied().filter(|p| p.is_enabled())
}

#[cfg(test)]
mod tests {
    use super::REGISTRY;
    use crate::manifest::MANIFEST;

    #[test]
    fn registry_and_manifest_match() {
        assert_eq!(
            REGISTRY.len(),
            MANIFEST.len(),
            "registry and manifest length differ"
        );
        for (plugin, entry) in REGISTRY.iter().zip(MANIFEST.iter()) {
            assert_eq!(plugin.name(), entry.name, "name mismatch");
            assert_eq!(
                plugin.intercepts(),
                entry.intercepts,
                "intercepts mismatch for {}",
                entry.name
            );
            assert_eq!(
                plugin.describe(),
                entry.describe,
                "describe mismatch for {}",
                entry.name
            );
        }
    }

    #[test]
    fn legacy_plugins_report_always_enabled() {
        for name in [
            "env",
            "net",
            "fs",
            "dl",
            "dlsym",
            "proc",
            "format",
            "assertion",
        ] {
            let plugin = REGISTRY
                .iter()
                .find(|p| p.name() == name)
                .expect("plugin present");
            assert!(plugin.is_enabled(), "{name} should always be enabled");
        }
    }
}
