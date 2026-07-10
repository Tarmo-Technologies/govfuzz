// SPDX-License-Identifier: Apache-2.0

//! SONAME → canonical library name lookup, sourced from the same embedded
//! native-component knowledge base the C/C++ source cataloger uses
//! (`data/native_components.toml`, `sonames` field).
//!
//! The `Linked` / `RuntimeLoaded` enrich lanes in `governance` use this to
//! bridge a built-binary soname (e.g. `libz.so.1`) to the component name a
//! manifest/source cataloger already produced (`zlib`), so the two collapse
//! into one component instead of duplicating.
//!
//! Matching is conservative: an exact soname (case-insensitive) maps to a KB
//! name; everything else returns `None` and the caller falls back to its own
//! base-name normalizer / create-as-new path. No network, no panics at runtime
//! (the KB is a trusted in-tree asset, parsed once).

use std::collections::BTreeMap;
use std::sync::OnceLock;

const KB_TOML: &str = include_str!("../data/native_components.toml");

/// Canonical library name for a SONAME, if the KB knows it. The lookup is
/// case-insensitive and tolerates a leading directory (`/usr/lib/libz.so.1`).
pub fn soname_to_library_name(soname: &str) -> Option<&'static str> {
    let leaf = soname
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(soname)
        .trim()
        .to_ascii_lowercase();
    if leaf.is_empty() {
        return None;
    }
    map().get(&leaf).copied()
}

fn map() -> &'static BTreeMap<String, &'static str> {
    static MAP: OnceLock<BTreeMap<String, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| parse(KB_TOML))
}

/// Build the soname → name map from the KB. A parse failure is a build-time bug
/// (the KB is in-tree), so this `expect`s — matching the C-source cataloger.
fn parse(text: &str) -> BTreeMap<String, &'static str> {
    let root: toml::Value = toml::from_str(text).expect("native_components.toml must parse");
    let mut map = BTreeMap::new();
    let Some(tables) = root.get("library").and_then(|v| v.as_array()) else {
        return map;
    };
    for table in tables {
        let Some(name) = table.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        // Leak the name once to obtain a 'static str (the KB is a small,
        // process-lifetime asset; this runs at most once via the OnceLock).
        let name: &'static str = Box::leak(name.to_owned().into_boxed_str());
        if let Some(sonames) = table.get("sonames").and_then(|v| v.as_array()) {
            for soname in sonames.iter().filter_map(|v| v.as_str()) {
                map.entry(soname.trim().to_ascii_lowercase())
                    .or_insert(name);
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_soname_to_library_name() {
        assert_eq!(soname_to_library_name("libz.so.1"), Some("zlib"));
        assert_eq!(soname_to_library_name("libz.so"), Some("zlib"));
        assert_eq!(soname_to_library_name("libssl.so.3"), Some("openssl"));
        assert_eq!(soname_to_library_name("libcrypto.so.3"), Some("openssl"));
    }

    #[test]
    fn lookup_is_case_insensitive_and_strips_directories() {
        assert_eq!(soname_to_library_name("LIBZ.SO.1"), Some("zlib"));
        assert_eq!(soname_to_library_name("/usr/lib/libz.so.1"), Some("zlib"));
    }

    #[test]
    fn unknown_soname_returns_none() {
        assert_eq!(soname_to_library_name("libfoobar.so.2"), None);
        assert_eq!(soname_to_library_name(""), None);
    }
}
