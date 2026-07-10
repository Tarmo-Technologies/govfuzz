// SPDX-License-Identifier: Apache-2.0

fn main() {
    // Without these directives Cargo would cache a successful build and
    // skip re-running this script when GOVFUZZ_PROFILE changes, which
    // would silently bypass the profile gate on subsequent invocations.
    println!("cargo:rerun-if-env-changed=GOVFUZZ_PROFILE");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_ENABLED");

    if std::env::var_os("CARGO_FEATURE_ENABLED").is_none() {
        return;
    }

    let profile = std::env::var("GOVFUZZ_PROFILE").unwrap_or_default();
    if !matches!(profile.as_str(), "external-tools" | "research-lab") {
        panic!(
            "probe_gnat_actions 'enabled' feature requires GOVFUZZ_PROFILE=external-tools or research-lab"
        );
    }
}
