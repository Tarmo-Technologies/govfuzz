// SPDX-License-Identifier: Apache-2.0

//! Regression test for #407: `govfuzz auto` stack-overflowed (aborted the whole
//! process) while *discovering / indexing* a C tree, before any build, when a
//! source file nested AST constructs pathologically deep (long else-if / `||`
//! ladders, nested parens — all common in real C). tree-sitter's own parser is
//! iterative and survives; the overflow was purely in govfuzz's recursive AST
//! walkers, which are now depth-bounded. This drives the same discovery + decl
//! index entry points the crash path uses and asserts they return (a stack
//! overflow aborts the test *process*, so a regression shows up as an abort,
//! not a catchable failure).

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use cli::auto::decl_index::DeclarationIndex;
use cli::auto::discovery;

fn tmpdir() -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("govfuzz-deep-src-{n}"));
    fs::create_dir_all(&p).unwrap();
    p
}

/// Build a `.c` source whose AST nests far past the walker depth cap via the
/// constructs that trip up real legacy C: a long else-if ladder, a deeply
/// nested parenthesised initializer, and a long `||` chain. A normal fuzzable
/// function sits at the top so discovery has something to find above the cap.
fn deep_c_source() -> String {
    const DEEP: usize = 6000;
    let mut s = String::from(
        "int parse_buf(const unsigned char *data, unsigned long len) {\n    return len ? data[0] : 0;\n}\n",
    );

    s.push_str("int else_if_ladder(int x) {\n    if (x == 0) { return 0; }\n");
    for _ in 0..DEEP {
        s.push_str("    else if (x == 0) { return 0; }\n");
    }
    s.push_str("    return 1;\n}\n");

    s.push_str("int nested_parens(void) {\n    int y = ");
    s.push_str(&"(".repeat(DEEP));
    s.push('0');
    s.push_str(&")".repeat(DEEP));
    s.push_str(";\n    return y;\n}\n");

    s.push_str("int or_chain(int a) {\n    return a");
    for _ in 0..DEEP {
        s.push_str(" || a");
    }
    s.push_str(";\n}\n");

    s
}

#[test]
fn auto_discovery_and_index_do_not_overflow_on_deep_c_source() {
    let root = tmpdir();
    fs::write(root.join("deep.c"), deep_c_source()).unwrap();

    // The discovery walk parses every file and ranks fuzzable subprograms; this
    // is the exact path that aborted in #407. It must return, not overflow.
    let candidates = discovery::discover(&root).expect("discovery must not abort on deep source");
    assert!(
        candidates.iter().any(|c| c.name == "parse_buf"),
        "the fuzzable function above the deep constructs must still be discovered: {:?}",
        candidates.iter().map(|c| &c.name).collect::<Vec<_>>()
    );

    // The declaration index parses declarations / type defs / referenced symbols
    // across the whole tree through the same recursive walkers — also bounded.
    DeclarationIndex::build(&root).expect("decl index build must not abort on deep source");

    let _ = fs::remove_dir_all(&root);
}

/// #102: a file dropped from discovery (here, an unreadable one) is recorded as a
/// structured, privacy-scrubbed diagnostic instead of silently vanishing, and the
/// sweep continues and still discovers the valid targets around it.
#[test]
fn discovery_records_a_dropped_file_without_aborting_the_sweep() {
    use cli::auto::bug_report;
    let root = tmpdir();
    // A valid C file so the sweep has something to find (proves it continues).
    fs::write(
        root.join("good.c"),
        "int parse_it(const unsigned char* d, unsigned long n){ return n? d[0]:0; }\n",
    )
    .unwrap();
    // An unreadable C++ file -> a read-stage drop.
    let bad = root.join("unreadable.cpp");
    fs::write(&bad, "int f(){return 0;}\n").unwrap();
    // A test running as root ignores the mode bits — only assert the drop when the
    // file is genuinely unreadable to this process.
    #[cfg(unix)]
    let unreadable = {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bad, fs::Permissions::from_mode(0o000)).unwrap();
        fs::read(&bad).is_err()
    };
    #[cfg(not(unix))]
    let unreadable = false;

    let candidates = discovery::discover(&root).expect("discovery must not abort on a bad file");
    assert!(
        candidates.iter().any(|c| c.name == "parse_it"),
        "the valid file must still be discovered around the dropped one"
    );

    if unreadable {
        let diags: Vec<_> = bug_report::snapshot()
            .into_iter()
            .filter(|i| i.category == bug_report::IssueCategory::DiscoveryDiagnostic)
            .collect();
        assert!(
            diags.iter().any(|d| d.summary.contains("read")),
            "unreadable file must record a read-stage discovery diagnostic; got {:?}",
            diags.iter().map(|d| &d.summary).collect::<Vec<_>>()
        );
        // The recorded detail/token must not leak the real path or filename.
        for d in &diags {
            assert!(!format!("{d:?}").contains("unreadable.cpp"));
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&bad, fs::Permissions::from_mode(0o644));
    }
    let _ = fs::remove_dir_all(&root);
}
