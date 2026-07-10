// SPDX-License-Identifier: Apache-2.0
//! M22 Phase 5 (Perl 4): Perl 5 is backward-compatible and runs most Perl 4
//! code, so a Perl-4-idiom script (subs with `local(...) = @_`, no `my`, `&`
//! calls) is discovered and fuzzed by the existing Perl 5 lane rather than taking
//! the report-only path. This test pins that design decision: such code is
//! discovered with the (fuzzable) Perl 5 dialect.

use cli::auto::candidate::Lang;
use cli::auto::discovery::discover;
use std::fs;
use std::path::PathBuf;

fn tmp(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("govfuzz-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn perl4_idiom_script_is_discovered_via_perl5_lane() {
    let dir = tmp("perl4-disc");
    // Perl 4 style: `local(...) = @_` argument binding, no `my`, no `use strict`.
    fs::write(
        dir.join("legacy.pl"),
        "sub parse_record {\n\
         \x20   local($data) = @_;\n\
         \x20   $n = length($data);\n\
         \x20   return $n;\n\
         }\n\
         1;\n",
    )
    .unwrap();

    let candidates = discover(&dir).expect("discover Perl tree");
    let perl = candidates
        .iter()
        .find(|c| c.lang == Lang::Perl && c.name.ends_with("parse_record"))
        .expect("the Perl 4 sub must be discovered by the Perl 5 lane");
    // Perl 5 dialect = fuzzable (Perl 5 runs the Perl 4 code); not report-only.
    assert_eq!(perl.dialect.map(|d| d.as_str()), Some("perl5"));

    let _ = fs::remove_dir_all(&dir);
}
