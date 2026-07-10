// SPDX-License-Identifier: Apache-2.0

//! Package-URL (PURL) construction per ecosystem. Each builder applies the
//! spec's type-specific normalization. Callers pass an EXACT version (lockfile
//! pin or `==`); never a range. See the Phase-2 ecosystem reference for the
//! per-type rules these encode.

/// pkg:cargo/<name>@<version> — no namespace; name case-preserved.
pub fn cargo(name: &str, version: &str) -> String {
    format!("pkg:cargo/{}@{}", encode_segment(name), version)
}

/// pkg:cargo/<name> — name-only purl for unresolved cargo deps whose version
/// is a range or unknown. A versionless PURL is valid per the PURL spec and
/// lets downstream SCA tools match by package name. The `version` field of the
/// emitting `Component` stays `None`; only the purl gains this form.
pub fn cargo_nameonly(name: &str) -> String {
    format!("pkg:cargo/{}", encode_segment(name))
}

/// pkg:npm/<name>@<version>; a `@scope/name` becomes `pkg:npm/%40scope/name@..`.
/// Name case is preserved (grandfathered mixed-case names exist).
pub fn npm(name: &str, version: &str) -> String {
    let body = if let Some(rest) = name.strip_prefix('@') {
        // scoped: @scope/pkg -> %40scope/pkg (the '@' encodes, '/' stays)
        format!("%40{}", rest)
    } else {
        name.to_owned()
    };
    format!("pkg:npm/{}@{}", body, version)
}

/// pkg:pypi/<name>@<version> — no namespace; name lowercased with `_`->`-`.
pub fn pypi(name: &str, version: &str) -> String {
    format!(
        "pkg:pypi/{}@{}",
        name.to_ascii_lowercase().replace('_', "-"),
        version
    )
}

/// PEP 503 normalized name (`[-_.]+` -> `-`, lowercase) — the Python
/// cross-source dedup key, which differs from the PURL name on dotted names.
pub fn pep503(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_sep = false;
    for ch in name.to_ascii_lowercase().chars() {
        if matches!(ch, '-' | '_' | '.') {
            if !prev_sep {
                out.push('-');
            }
            prev_sep = true;
        } else {
            out.push(ch);
            prev_sep = false;
        }
    }
    out.trim_matches('-').to_owned()
}

/// pkg:golang/<module>@<version> — case preserved; `/` NOT encoded; keep `v`.
pub fn golang(module: &str, version: &str) -> String {
    format!("pkg:golang/{module}@{version}")
}

/// pkg:golang/<module> — version-less purl for the scanned module's own identity
/// (go.mod's `module` directive carries no version for the module itself).
pub fn golang_nameonly(module: &str) -> String {
    format!("pkg:golang/{module}")
}

/// pkg:maven/<group>/<artifact>@<version> — group dots are literal (one segment).
pub fn maven(group: &str, artifact: &str, version: &str) -> String {
    format!("pkg:maven/{group}/{artifact}@{version}")
}

/// pkg:maven/<group>/<artifact> — versionless purl for a coordinate that resolved
/// (group + artifact known) but whose version is externally managed/unknown. A
/// versionless purl is valid per the spec and keeps Maven coordinates matchable
/// by SCA tooling, mirroring the name-only purls the flat ecosystems emit.
pub fn maven_nameonly(group: &str, artifact: &str) -> String {
    format!("pkg:maven/{group}/{artifact}")
}

/// pkg:nuget/<Name>@<Version> — no namespace; name case-PRESERVED (dotted IDs
/// like `Microsoft.Extensions.Logging` are one segment). Only the type lowercases.
pub fn nuget(name: &str, version: &str) -> String {
    format!("pkg:nuget/{}@{}", encode_segment(name), version)
}

/// pkg:gem/<name>@<version> — no namespace; name verbatim. A non-ruby platform
/// is carried by the caller as a `?platform=` qualifier (omitted for ruby).
pub fn gem(name: &str, version: &str) -> String {
    format!("pkg:gem/{}@{}", encode_segment(name), version)
}

/// pkg:cpan/<module>@<version> — Perl module by name (the CPAN spec also allows an
/// author/dist form; the module form is what a cpanfile/META prereq carries). The
/// `::` separators are kept (encoded per segment).
pub fn cpan(name: &str, version: &str) -> String {
    format!("pkg:cpan/{}@{}", encode_segment(name), version)
}

/// pkg:cpan/<module> with no version (a prereq with no pinned version).
pub fn cpan_nameonly(name: &str) -> String {
    format!("pkg:cpan/{}", encode_segment(name))
}

/// pkg:composer/<vendor>/<name>@<version> — namespace = vendor; BOTH vendor and
/// name lowercased. `id` is the `vendor/name` string from composer.json/.lock.
pub fn composer(id: &str, version: &str) -> String {
    format!("pkg:composer/{}@{}", id.to_ascii_lowercase(), version)
}

/// pkg:conan/<name>@<version> — ConanCenter (no user/channel); name lowercased.
/// A known recipe revision is added by the caller as a `?rrev=` qualifier.
pub fn conan(name: &str, version: &str) -> String {
    format!("pkg:conan/{}@{}", name.to_ascii_lowercase(), version)
}

/// pkg:generic/<name>@<version> — fallback for ecosystems with no registered
/// PURL type (vcpkg, Alire); name lowercased. The caller appends origin
/// qualifiers (`download_url=`/`vcs_url=`/`checksum=`) where available.
pub fn generic(name: &str, version: &str) -> String {
    format!("pkg:generic/{}@{}", name.to_ascii_lowercase(), version)
}

/// Best-effort VERSIONLESS purl for a component with a name + ecosystem but no
/// resolved version (a range-spec dependency with no lockfile pin). A purl
/// without `@version` is valid per the PURL spec and lets downstream SCA tools
/// match by package name — without it, range-declared pypi/npm/go/... deps carry
/// NO purl at all (requests: 18/20, express: 44/45). Mirrors each ecosystem's
/// name normalization from the versioned builders above, minus the version.
/// Returns `None` for ecosystems with no single-segment registry name (maven
/// needs group/artifact) or no PURL type (the `c`/`generic`/`ada` source scans).
pub fn name_only(ecosystem: &str, name: &str) -> Option<String> {
    Some(match ecosystem {
        "cargo" => cargo_nameonly(name),
        "npm" => {
            let body = name
                .strip_prefix('@')
                .map(|rest| format!("%40{rest}"))
                .unwrap_or_else(|| name.to_owned());
            format!("pkg:npm/{body}")
        }
        "pypi" => format!("pkg:pypi/{}", name.to_ascii_lowercase().replace('_', "-")),
        "golang" => format!("pkg:golang/{name}"),
        "nuget" => format!("pkg:nuget/{}", encode_segment(name)),
        "gem" => format!("pkg:gem/{}", encode_segment(name)),
        "composer" => format!("pkg:composer/{}", name.to_ascii_lowercase()),
        "conan" => format!("pkg:conan/{}", name.to_ascii_lowercase()),
        _ => return None,
    })
}

/// Normalize a native (`pkg:generic`) component name for cross-source dedup.
/// The same C/C++ library can be observed as a source `#include` (`nlohmann-json`,
/// ecosystem `c`) and as a build-system dependency (`nlohmann_json`, ecosystem
/// `generic`); lowercasing and folding `_`/`.`/runs of `-` to a single `-` lets
/// both key identically so they collapse to one component.
pub fn normalize_native_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_sep = false;
    for ch in name.to_ascii_lowercase().chars() {
        if matches!(ch, '-' | '_' | '.') {
            if !prev_sep {
                out.push('-');
            }
            prev_sep = true;
        } else {
            out.push(ch);
            prev_sep = false;
        }
    }
    out.trim_matches('-').to_owned()
}

/// Percent-encode the characters PURL reserves inside a name segment that
/// realistically occur in package names. (Cargo/most names are already safe.)
fn encode_segment(s: &str) -> String {
    s.replace('%', "%25").replace('@', "%40")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_is_plain_and_case_preserved() {
        assert_eq!(cargo("rand", "0.8.5"), "pkg:cargo/rand@0.8.5");
        assert_eq!(cargo("Inflector", "0.11.4"), "pkg:cargo/Inflector@0.11.4");
    }

    #[test]
    fn cargo_nameonly_emits_versionless_purl() {
        assert_eq!(cargo_nameonly("serde"), "pkg:cargo/serde");
        assert_eq!(cargo_nameonly("Inflector"), "pkg:cargo/Inflector");
    }

    #[test]
    fn name_only_emits_versionless_purls_per_ecosystem() {
        // Range-declared deps with no lockfile pin still get a name-matchable purl.
        assert_eq!(
            name_only("pypi", "charset_normalizer").as_deref(),
            Some("pkg:pypi/charset-normalizer")
        );
        assert_eq!(
            name_only("npm", "lodash").as_deref(),
            Some("pkg:npm/lodash")
        );
        assert_eq!(
            name_only("npm", "@types/node").as_deref(),
            Some("pkg:npm/%40types/node")
        );
        assert_eq!(
            name_only("golang", "github.com/spf13/cobra").as_deref(),
            Some("pkg:golang/github.com/spf13/cobra")
        );
        assert_eq!(name_only("gem", "rake").as_deref(), Some("pkg:gem/rake"));
        assert_eq!(
            name_only("cargo", "serde").as_deref(),
            Some("pkg:cargo/serde")
        );
        // Ecosystems with no single-segment registry purl return None.
        assert_eq!(name_only("maven", "x"), None);
        assert_eq!(name_only("c", "zlib"), None);
        assert_eq!(name_only("generic", "x"), None);
    }

    #[test]
    fn npm_scope_encodes_at_sign() {
        assert_eq!(npm("lodash", "4.17.21"), "pkg:npm/lodash@4.17.21");
        assert_eq!(npm("@babel/core", "7.8.3"), "pkg:npm/%40babel/core@7.8.3");
    }

    #[test]
    fn pypi_lowercases_and_underscore_to_dash() {
        assert_eq!(pypi("Flask", "3.0.3"), "pkg:pypi/flask@3.0.3");
        assert_eq!(
            pypi("typing_extensions", "4.0"),
            "pkg:pypi/typing-extensions@4.0"
        );
    }

    #[test]
    fn pep503_collapses_runs_and_dots() {
        assert_eq!(pep503("zope.interface"), "zope-interface");
        assert_eq!(pep503("a__b.-c"), "a-b-c");
        // diverges from the PURL name, which keeps the dot:
        assert_eq!(pypi("zope.interface", "6.0"), "pkg:pypi/zope.interface@6.0");
    }

    #[test]
    fn golang_preserves_case_and_slashes() {
        assert_eq!(
            golang("github.com/Azure/go-autorest", "v0.11.0"),
            "pkg:golang/github.com/Azure/go-autorest@v0.11.0"
        );
    }

    #[test]
    fn maven_group_dots_are_literal() {
        assert_eq!(
            maven("com.fasterxml.jackson.core", "jackson-databind", "2.17.0"),
            "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.0"
        );
    }

    #[test]
    fn maven_nameonly_is_versionless() {
        assert_eq!(
            maven_nameonly("org.springframework", "spring-core"),
            "pkg:maven/org.springframework/spring-core"
        );
    }

    #[test]
    fn golang_nameonly_is_versionless_and_keeps_slashes() {
        assert_eq!(
            golang_nameonly("github.com/example/myapp"),
            "pkg:golang/github.com/example/myapp"
        );
    }

    #[test]
    fn nuget_preserves_dotted_case() {
        assert_eq!(
            nuget("Microsoft.Extensions.Logging", "8.0.0"),
            "pkg:nuget/Microsoft.Extensions.Logging@8.0.0"
        );
    }

    #[test]
    fn gem_is_verbatim() {
        assert_eq!(gem("nokogiri", "1.16.5"), "pkg:gem/nokogiri@1.16.5");
    }

    #[test]
    fn composer_lowercases_vendor_and_name() {
        assert_eq!(
            composer("GuzzleHttp/Promises", "2.0.2"),
            "pkg:composer/guzzlehttp/promises@2.0.2"
        );
    }

    #[test]
    fn conan_lowercases_name() {
        assert_eq!(conan("ZLIB", "1.3.1"), "pkg:conan/zlib@1.3.1");
    }

    #[test]
    fn normalize_native_name_folds_separators_and_case() {
        assert_eq!(normalize_native_name("nlohmann_json"), "nlohmann-json");
        assert_eq!(normalize_native_name("nlohmann-json"), "nlohmann-json");
        assert_eq!(normalize_native_name("nlohmann.json"), "nlohmann-json");
        assert_eq!(normalize_native_name("Catch2"), "catch2");
        assert_eq!(normalize_native_name("a__b.-c"), "a-b-c");
    }

    #[test]
    fn generic_lowercases_name() {
        assert_eq!(
            generic("boost-system", "1.83.0"),
            "pkg:generic/boost-system@1.83.0"
        );
    }
}
