// SPDX-License-Identifier: Apache-2.0

//! Shared, offline license identification for catalogers.
//!
//! Two complementary strategies, both deterministic and untrusted-input-safe:
//!
//! * [`spdx_license_id`] — read an inline `SPDX-License-Identifier:` tag (the
//!   authoritative, machine-readable form embedded in many vendored headers and
//!   single-header amalgamations).
//! * [`classify_license_text`] — fall back to recognizing a license from
//!   distinctive phrases in a `LICENSE`/`COPYING` file or a header banner.
//!
//! Conservative: both return `None` rather than guess on no clear match.

/// Extract an inline `SPDX-License-Identifier: <expr>` tag from source text
/// (header banner, license file, …). Returns the SPDX expression following the
/// marker, trimmed of surrounding whitespace and a trailing block-comment close.
/// Bounded length guards against a pathological line.
pub fn spdx_license_id(source: &str) -> Option<String> {
    const MARKER: &str = "SPDX-License-Identifier:";
    for line in source.lines() {
        let Some(pos) = line.find(MARKER) else {
            continue;
        };
        let after = &line[pos + MARKER.len()..];
        // Strip a trailing block-comment close (`*/`) and surrounding space.
        let id = after.trim().trim_end_matches("*/").trim();
        if !id.is_empty() && id.len() <= 100 {
            return Some(id.to_owned());
        }
    }
    None
}

/// Map the body of a license file or header banner to a best-effort SPDX id from
/// distinctive phrases. Conservative: returns `None` rather than guessing on no
/// clear match.
pub fn classify_license_text(text: &str) -> Option<String> {
    let t = text.to_ascii_lowercase();
    let has = |needle: &str| t.contains(needle);

    if has("apache license") && has("version 2.0") {
        return Some("Apache-2.0".to_owned());
    }
    if has("gnu lesser general public license") {
        if has("version 3") {
            return Some("LGPL-3.0".to_owned());
        }
        if has("version 2.1") {
            return Some("LGPL-2.1".to_owned());
        }
    }
    if has("gnu general public license") {
        if has("version 3") {
            return Some("GPL-3.0".to_owned());
        }
        if has("version 2") {
            return Some("GPL-2.0".to_owned());
        }
    }
    if has("mozilla public license") && has("2.0") {
        return Some("MPL-2.0".to_owned());
    }
    if has("boost software license") {
        return Some("BSL-1.0".to_owned());
    }
    if has("this is free and unencumbered software released into the public domain") {
        return Some("Unlicense".to_owned());
    }
    if has("redistribution and use in source and binary forms") {
        // BSD family: the 3-clause variant adds a no-endorsement clause.
        if has("neither the name") || has("endorse or promote") {
            return Some("BSD-3-Clause".to_owned());
        }
        return Some("BSD-2-Clause".to_owned());
    }
    if has("permission is hereby granted, free of charge")
        || (has("mit license") && !has("redistribution"))
    {
        return Some("MIT".to_owned());
    }
    if has("internet systems consortium") || has("isc license") {
        return Some("ISC".to_owned());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spdx_reads_line_comment_identifier() {
        assert_eq!(
            spdx_license_id("// SPDX-License-Identifier: MIT\nint x;\n").as_deref(),
            Some("MIT")
        );
    }

    #[test]
    fn spdx_strips_block_comment_close() {
        assert_eq!(
            spdx_license_id("/* SPDX-License-Identifier: BSL-1.0 */\n").as_deref(),
            Some("BSL-1.0")
        );
    }

    #[test]
    fn spdx_keeps_compound_expression() {
        assert_eq!(
            spdx_license_id("# SPDX-License-Identifier: Apache-2.0 OR MIT\n").as_deref(),
            Some("Apache-2.0 OR MIT")
        );
    }

    #[test]
    fn spdx_absent_is_none() {
        assert!(spdx_license_id("no marker here\n").is_none());
    }

    #[test]
    fn classify_detects_common_licenses() {
        assert_eq!(
            classify_license_text("Permission is hereby granted, free of charge, to any person")
                .as_deref(),
            Some("MIT")
        );
        assert_eq!(
            classify_license_text("Apache License\nVersion 2.0, January 2004").as_deref(),
            Some("Apache-2.0")
        );
        assert_eq!(
            classify_license_text("Distributed under the Boost Software License, Version 1.0.")
                .as_deref(),
            Some("BSL-1.0")
        );
        assert!(classify_license_text("some random readme text").is_none());
    }
}
