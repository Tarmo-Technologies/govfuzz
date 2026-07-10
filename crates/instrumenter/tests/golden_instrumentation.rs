// SPDX-License-Identifier: Apache-2.0

use ada_parser::reconcile::build_structural_ast;
use instrumenter::{instrument_unit, InstrumentArgs};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[test]
fn snapshot_swallowed_constraint_error_matches() {
    let (source, source_path) = swallowed_constraint_error_fixture();
    let ast = build_structural_ast(&source, None, &source_path).unwrap();
    let result = instrument_unit(InstrumentArgs {
        source: &source,
        ast: &ast,
        source_path: &source_path,
    })
    .unwrap();
    let expected = fs::read_to_string(snapshot_path("swallowed_constraint_error.adb")).unwrap();

    assert_eq!(result.rewritten_source, expected);
}

#[test]
fn snapshot_swallowed_constraint_error_rewritten_source_parses() {
    let (source, source_path) = swallowed_constraint_error_fixture();
    let ast = build_structural_ast(&source, None, &source_path).unwrap();
    let result = instrument_unit(InstrumentArgs {
        source: &source,
        ast: &ast,
        source_path: &source_path,
    })
    .unwrap();

    build_structural_ast(&result.rewritten_source, None, &source_path).unwrap();
}

#[test]
fn golden_corpus_all_fixtures_parse_after_instrumentation() {
    let mut failures = Vec::new();
    for fixture in walk_fixtures(&golden_root()) {
        let case = instrument_fixture(&fixture);
        if let Err(error) =
            build_structural_ast(&case.result.rewritten_source, None, &case.source_path)
        {
            failures.push(format!("{}: {error}", fixture.display()));
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn golden_corpus_breadcrumb_count_matches_statement_count() {
    let mut failures = Vec::new();
    for fixture in walk_fixtures(&golden_root()) {
        let case = instrument_fixture(&fixture);
        let expected = expected_breadcrumb_count(&case.ast, &case.source);
        if case.result.breadcrumbs.len() != expected {
            failures.push(format!(
                "{}: breadcrumbs {}, expected {expected}",
                fixture.display(),
                case.result.breadcrumbs.len()
            ));
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn golden_corpus_handler_probe_count_matches_handler_count() {
    let mut failures = Vec::new();
    for fixture in walk_fixtures(&golden_root()) {
        let manifest = load_manifest(&fixture);
        let case = instrument_fixture(&fixture);
        let actual = case
            .result
            .rewritten_source
            .matches("AdaFuzz.Probe.On_Handler_Entry")
            .count();
        if actual != manifest.expected.handlers {
            failures.push(format!(
                "{}: handler probes {actual}, expected {}",
                fixture.display(),
                manifest.expected.handlers
            ));
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn golden_corpus_raise_probe_count_matches_raise_count() {
    let mut failures = Vec::new();
    for fixture in walk_fixtures(&golden_root()) {
        let manifest = load_manifest(&fixture);
        let case = instrument_fixture(&fixture);
        let actual = case
            .result
            .rewritten_source
            .matches("AdaFuzz.Probe.On_Explicit_Raise")
            .count();
        if actual != manifest.expected.raises {
            failures.push(format!(
                "{}: raise probes {actual}, expected {}",
                fixture.display(),
                manifest.expected.raises
            ));
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn swallowed_constraint_error_fixture() -> (String, PathBuf) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ada_parser/tests/golden/ada95/swallowed_constraint_error/src.adb");
    let source = fs::read_to_string(&path).unwrap();

    (source, path)
}

#[derive(Debug, Deserialize)]
struct Manifest {
    dialect_hint: Option<String>,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Expected {
    handlers: usize,
    raises: usize,
}

struct InstrumentedFixture {
    source: String,
    source_path: PathBuf,
    ast: ada_parser::ast::StructuralAst,
    result: instrumenter::InstrumentedFile,
}

fn instrument_fixture(fixture: &Path) -> InstrumentedFixture {
    let manifest = load_manifest(fixture);
    let (source, source_path) = load_source(fixture);
    let dialect_hint = manifest
        .dialect_hint
        .as_deref()
        .map(ada_parser::ast::AdaStandard::from_str)
        .transpose()
        .unwrap();
    let ast = build_structural_ast(&source, dialect_hint, &source_path).unwrap();
    let result = instrument_unit(InstrumentArgs {
        source: &source,
        ast: &ast,
        source_path: &source_path,
    })
    .unwrap();

    InstrumentedFixture {
        source,
        source_path,
        ast,
        result,
    }
}

fn expected_breadcrumb_count(ast: &ada_parser::ast::StructuralAst, source: &str) -> usize {
    ast.statements
        .iter()
        .filter(|statement| {
            instrumenter::edge_cases::breadcrumb_injection_safe(source, statement, ast)
        })
        .filter(|statement| match &statement.owner {
            ada_parser::ast::StatementOwner::Subprogram(id) => ast
                .subprograms
                .iter()
                .find(|subprogram| subprogram.id == *id)
                .is_none_or(|subprogram| {
                    !instrumenter::edge_cases::is_expression_function(subprogram, source)
                }),
            ada_parser::ast::StatementOwner::PackageBody(_) => true,
        })
        .count()
}

fn golden_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../ada_parser/tests/golden")
}

fn walk_fixtures(root: &Path) -> Vec<PathBuf> {
    let mut fixtures = Vec::new();
    collect_fixtures(root, &mut fixtures);
    fixtures.sort();
    fixtures
}

fn collect_fixtures(dir: &Path, fixtures: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut entries = entries.map(|entry| entry.unwrap()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if path.join("manifest.toml").is_file() {
            fixtures.push(path);
        } else {
            collect_fixtures(&path, fixtures);
        }
    }
}

fn load_manifest(fixture: &Path) -> Manifest {
    let text = fs::read_to_string(fixture.join("manifest.toml")).unwrap();

    toml::from_str(&text).unwrap()
}

fn load_source(fixture: &Path) -> (String, PathBuf) {
    for file_name in ["src.adb", "src.ads"] {
        let path = fixture.join(file_name);
        if path.is_file() {
            return (fs::read_to_string(&path).unwrap(), path);
        }
    }

    panic!("{}: fixture has no src.adb or src.ads", fixture.display());
}

fn snapshot_path(file_name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots")
        .join(file_name)
}
