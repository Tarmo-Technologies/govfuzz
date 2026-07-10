// SPDX-License-Identifier: Apache-2.0
//! M22 Phase 4: original Ada 83 (MIL-STD-1815A) is no longer hard-rejected by
//! the parser. A `pragma Ada_83;` unit parses (best-effort, lexed with the
//! reduced 83 keyword set), is tagged with the Ada 83 dialect, and — having no
//! auto-build lane that targets `-gnat83` yet — is reported on (discovered +
//! statically analyzed) instead of failing the whole file.

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
fn ada83_unit_is_parsed_and_discovered_with_ada83_dialect() {
    let dir = tmp("ada83-disc");
    // A legacy Ada 83 package spec. `pragma Ada_83;` used to be a hard parse
    // error; now it parses and the function is discovered.
    fs::write(
        dir.join("legacy_parser.ads"),
        "pragma Ada_83;\n\
         package Legacy_Parser is\n\
         \x20  function Parse (Input : String) return Integer;\n\
         end Legacy_Parser;\n",
    )
    .unwrap();

    let candidates = discover(&dir).expect("discover Ada 83 tree");
    let ada = candidates
        .iter()
        .find(|c| c.lang == Lang::Ada && c.name.eq_ignore_ascii_case("Parse"))
        .expect("the Ada 83 function must be discovered (not rejected)");
    assert_eq!(
        ada.dialect.map(|d| d.as_str()),
        Some("ada83"),
        "discovered Ada 83 target must carry the Ada 83 dialect"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn ada83_uses_post83_reserved_word_as_identifier() {
    // In Ada 83 `interface` / `protected` are ordinary identifiers (they only
    // became reserved in Ada 95+). The reduced-keyword lexer (Ada83 is the
    // smallest dialect) must accept them, so such a unit still parses + discovers.
    let dir = tmp("ada83-kw");
    fs::write(
        dir.join("driver.ads"),
        "pragma Ada_83;\n\
         package Driver is\n\
         \x20  function Interface_Id (Protected_Flag : Integer) return Integer;\n\
         end Driver;\n",
    )
    .unwrap();

    let candidates = discover(&dir).expect("discover Ada 83 tree");
    assert!(
        candidates
            .iter()
            .any(|c| c.lang == Lang::Ada && c.dialect.map(|d| d.as_str()) == Some("ada83")),
        "Ada 83 unit using a post-83 word as an identifier must still parse + discover"
    );

    let _ = fs::remove_dir_all(&dir);
}
