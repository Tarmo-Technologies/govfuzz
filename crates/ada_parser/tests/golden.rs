// SPDX-License-Identifier: Apache-2.0

use ada_parser::ast::{AdaStandard, InterfaceKind, ScalarKind, TypeKind, UnitKind};
use ada_parser::reconcile::build_structural_ast;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

const MIN_FIXTURES: usize = 50;
const MIN_FIXTURES_PER_DIALECT: usize = 10;
const SUBPROGRAM_THRESHOLD: f64 = 0.95;
const HANDLER_RAISE_THRESHOLD: f64 = 0.99;

#[derive(Debug, Deserialize)]
struct Manifest {
    description: String,
    dialect_hint: Option<String>,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Expected {
    ada_standard: String,
    unit_kind: String,
    subprograms: usize,
    handlers: usize,
    raises: usize,
    types: usize,
    #[serde(default)]
    statements: usize,
    #[serde(default)]
    use_clauses: usize,
    #[serde(default)]
    with_clauses: Vec<String>,
    #[serde(default)]
    pragmas: Vec<String>,
    #[serde(default)]
    names: ExpectedNames,
}

#[derive(Debug, Default, Deserialize)]
struct ExpectedNames {
    #[serde(default)]
    subprograms: Vec<String>,
    #[serde(default)]
    handler_choices: Vec<String>,
    #[serde(default)]
    type_kinds: Vec<String>,
}

#[test]
fn golden_corpus_meets_m1_acceptance() {
    let root = golden_root();
    let mut totals = Totals::default();
    let mut failures = Vec::new();

    for fixture in walk_fixtures(&root) {
        let manifest_path = fixture.join("manifest.toml");
        let manifest_text = fs::read_to_string(&manifest_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", manifest_path.display()));
        let manifest: Manifest = toml::from_str(&manifest_text)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", manifest_path.display()));
        let (source, source_path) = load_source(&fixture);
        let dialect_hint = manifest
            .dialect_hint
            .as_deref()
            .map(AdaStandard::from_str)
            .transpose()
            .unwrap_or_else(|error| panic!("{}: invalid dialect_hint: {error}", fixture.display()));

        match build_structural_ast(&source, dialect_hint, &source_path) {
            Ok(ast) => {
                let label = format!("{} ({})", fixture.display(), manifest.description);
                let unit = ast
                    .units
                    .first()
                    .unwrap_or_else(|| panic!("{label}: scanner returned no unit"));

                totals.expected_subprograms += manifest.expected.subprograms;
                totals.extracted_subprograms += ast.subprograms.len();
                totals.expected_handlers += manifest.expected.handlers;
                totals.extracted_handlers += ast.handlers.len();
                totals.expected_raises += manifest.expected.raises;
                totals.extracted_raises += ast.raises.len();

                let expected_std = AdaStandard::from_str(&manifest.expected.ada_standard)
                    .unwrap_or_else(|error| {
                        panic!("{label}: invalid expected ada_standard: {error}")
                    });
                if unit.ada_standard != expected_std {
                    failures.push(format!(
                        "{label}: ada_standard mismatch: expected {expected_std:?}, got {:?}",
                        unit.ada_standard
                    ));
                }

                let expected_unit_kind = parse_unit_kind(&manifest.expected.unit_kind)
                    .unwrap_or_else(|| panic!("{label}: invalid expected unit_kind"));
                if unit.kind != expected_unit_kind {
                    failures.push(format!(
                        "{label}: unit_kind mismatch: expected {expected_unit_kind:?}, got {:?}",
                        unit.kind
                    ));
                }

                check_not_over_extracted(
                    &label,
                    "subprograms",
                    ast.subprograms.len(),
                    manifest.expected.subprograms,
                    &mut failures,
                );
                check_not_over_extracted(
                    &label,
                    "handlers",
                    ast.handlers.len(),
                    manifest.expected.handlers,
                    &mut failures,
                );
                check_not_over_extracted(
                    &label,
                    "raises",
                    ast.raises.len(),
                    manifest.expected.raises,
                    &mut failures,
                );
                check_not_over_extracted(
                    &label,
                    "types",
                    ast.types.len(),
                    manifest.expected.types,
                    &mut failures,
                );
                check_exact_count(
                    &fixture,
                    "types",
                    manifest.expected.types,
                    ast.types.len(),
                    &mut failures,
                );
                check_exact_count(
                    &fixture,
                    "statements",
                    manifest.expected.statements,
                    ast.statements.len(),
                    &mut failures,
                );
                check_not_over_extracted(
                    &label,
                    "use_clauses",
                    unit.uses.len(),
                    manifest.expected.use_clauses,
                    &mut failures,
                );
                check_exact_count(
                    &fixture,
                    "use_clauses",
                    manifest.expected.use_clauses,
                    unit.uses.len(),
                    &mut failures,
                );

                let extracted_withs: Vec<&str> =
                    unit.withs.iter().map(|item| item.name.as_str()).collect();
                check_expected_strings(
                    &label,
                    "with_clauses",
                    &extracted_withs,
                    &manifest.expected.with_clauses,
                    &mut failures,
                );
                let extracted_withs: Vec<String> =
                    unit.withs.iter().map(|item| item.name.clone()).collect();
                check_required_subset_strings(
                    &fixture,
                    "with_clauses",
                    &manifest.expected.with_clauses,
                    &extracted_withs,
                    &mut failures,
                );

                let extracted_pragmas: Vec<&str> =
                    unit.pragmas.iter().map(|item| item.name.as_str()).collect();
                check_expected_strings(
                    &label,
                    "pragmas",
                    &extracted_pragmas,
                    &manifest.expected.pragmas,
                    &mut failures,
                );
                let extracted_pragmas: Vec<String> =
                    unit.pragmas.iter().map(|item| item.name.clone()).collect();
                check_required_subset_strings(
                    &fixture,
                    "pragmas",
                    &manifest.expected.pragmas,
                    &extracted_pragmas,
                    &mut failures,
                );

                if !manifest.expected.names.subprograms.is_empty() {
                    for subprogram in &ast.subprograms {
                        if !manifest
                            .expected
                            .names
                            .subprograms
                            .contains(&subprogram.name)
                        {
                            failures.push(format!(
                                "{label}: extracted subprogram '{}' not in manifest allow-list {:?}",
                                subprogram.name, manifest.expected.names.subprograms
                            ));
                        }
                    }
                }

                if !manifest.expected.names.handler_choices.is_empty() {
                    for choice in ast
                        .handlers
                        .iter()
                        .flat_map(|handler| handler.choices.iter())
                    {
                        if !manifest.expected.names.handler_choices.contains(&choice.0) {
                            failures.push(format!(
                                "{label}: extracted handler choice '{}' not in manifest allow-list {:?}",
                                choice.0, manifest.expected.names.handler_choices
                            ));
                        }
                    }
                }

                if !manifest.expected.names.type_kinds.is_empty() {
                    let extracted_type_kinds: Vec<String> = ast
                        .types
                        .iter()
                        .map(|item| type_kind_name(&item.kind))
                        .collect();
                    for kind in &extracted_type_kinds {
                        if !manifest.expected.names.type_kinds.contains(kind) {
                            failures.push(format!(
                                "{label}: extracted type kind '{kind}' not in manifest allow-list {:?}",
                                manifest.expected.names.type_kinds
                            ));
                        }
                    }
                    check_required_subset_strings(
                        &fixture,
                        "type_kinds",
                        &manifest.expected.names.type_kinds,
                        &extracted_type_kinds,
                        &mut failures,
                    );
                }
            }
            Err(error) => {
                failures.push(format!(
                    "{}: scanner returned error: {error}",
                    fixture.display()
                ));
            }
        }
    }

    let subprogram_ratio =
        extraction_ratio(totals.extracted_subprograms, totals.expected_subprograms);
    let handler_raise_expected = totals.expected_handlers + totals.expected_raises;
    let handler_raise_extracted = totals.extracted_handlers + totals.extracted_raises;
    let handler_raise_ratio = extraction_ratio(handler_raise_extracted, handler_raise_expected);

    println!("Corpus totals:");
    println!(
        "  subprograms:     {} / {} = {:.4}",
        totals.extracted_subprograms, totals.expected_subprograms, subprogram_ratio
    );
    println!(
        "  handlers+raises: {} / {} = {:.4}",
        handler_raise_extracted, handler_raise_expected, handler_raise_ratio
    );

    for failure in &failures {
        eprintln!("FIXTURE FAILURE: {failure}");
    }

    assert!(failures.is_empty(), "{} fixture failure(s)", failures.len());
    assert!(
        subprogram_ratio >= SUBPROGRAM_THRESHOLD,
        "subprogram extraction ratio {subprogram_ratio:.4} below {SUBPROGRAM_THRESHOLD:.2} threshold"
    );
    assert!(
        handler_raise_ratio >= HANDLER_RAISE_THRESHOLD,
        "handler+raise extraction ratio {handler_raise_ratio:.4} below {HANDLER_RAISE_THRESHOLD:.2} threshold"
    );
}

#[test]
fn golden_corpus_per_dialect_minimum_fixtures() {
    let counts = count_fixtures_per_dialect(&golden_root());

    assert!(
        counts.ada95 >= MIN_FIXTURES_PER_DIALECT,
        "ada95 has {} fixtures, expected >= {MIN_FIXTURES_PER_DIALECT}",
        counts.ada95
    );
    assert!(
        counts.ada2005 >= MIN_FIXTURES_PER_DIALECT,
        "ada2005 has {} fixtures, expected >= {MIN_FIXTURES_PER_DIALECT}",
        counts.ada2005
    );
    assert!(
        counts.ada2012 >= MIN_FIXTURES_PER_DIALECT,
        "ada2012 has {} fixtures, expected >= {MIN_FIXTURES_PER_DIALECT}",
        counts.ada2012
    );
    assert!(
        counts.ada2022 >= MIN_FIXTURES_PER_DIALECT,
        "ada2022 has {} fixtures, expected >= {MIN_FIXTURES_PER_DIALECT}",
        counts.ada2022
    );

    let total = counts.ada95 + counts.ada2005 + counts.ada2012 + counts.ada2022;
    assert!(
        total >= MIN_FIXTURES,
        "corpus has {total} fixtures, expected >= {MIN_FIXTURES}"
    );
}

#[test]
fn required_subset_strings_fails_when_expected_missing() {
    let mut failures = Vec::new();
    check_required_subset_strings(
        Path::new("fixture"),
        "with_clauses",
        &["Alpha".to_string(), "Beta.Gamma".to_string()],
        &["Alpha".to_string()],
        &mut failures,
    );
    assert_eq!(failures.len(), 1);
    assert!(failures[0].contains("Beta.Gamma"));
}

#[test]
fn required_subset_strings_passes_when_all_present() {
    let mut failures = Vec::new();
    check_required_subset_strings(
        Path::new("fixture"),
        "pragmas",
        &["Pure".to_string()],
        &["Pure".to_string(), "Ada_2012".to_string()],
        &mut failures,
    );
    assert!(failures.is_empty());
}

#[test]
fn exact_count_fails_when_extractor_returns_less() {
    let mut failures = Vec::new();
    check_exact_count(Path::new("fixture"), "types", 3, 1, &mut failures);
    assert_eq!(failures.len(), 1);
    assert!(failures[0].contains("expects types count = 3"));
    assert!(failures[0].contains("returned 1"));
}

#[test]
fn exact_count_passes_when_match() {
    let mut failures = Vec::new();
    check_exact_count(Path::new("fixture"), "types", 3, 3, &mut failures);
    assert!(failures.is_empty());
}

#[test]
fn exact_count_passes_when_expected_zero_and_extracted_zero() {
    let mut failures = Vec::new();
    check_exact_count(Path::new("fixture"), "types", 0, 0, &mut failures);
    assert!(failures.is_empty());
}

#[test]
fn expected_statements_count_drives_exact_count_check() {
    let manifest: Manifest = toml::from_str(
        r#"
description = "statement count fixture"

[expected]
ada_standard = "ada_95"
unit_kind = "body"
subprograms = 1
handlers = 0
raises = 0
types = 0
statements = 2
"#,
    )
    .unwrap();

    let mut failures = Vec::new();
    check_exact_count(
        Path::new("fixture"),
        "statements",
        manifest.expected.statements,
        2,
        &mut failures,
    );
    assert!(failures.is_empty());

    check_exact_count(
        Path::new("fixture"),
        "statements",
        manifest.expected.statements,
        1,
        &mut failures,
    );
    assert_eq!(failures.len(), 1);
    assert!(failures[0].contains("expects statements count = 2"));
}

#[test]
fn count_fixtures_per_dialect_returns_zero_for_empty_dir() {
    let tmp = test_temp_dir("empty");

    let counts = count_fixtures_per_dialect(&tmp);

    assert_eq!(counts.ada95, 0);
    assert_eq!(counts.ada2005, 0);
    assert_eq!(counts.ada2012, 0);
    assert_eq!(counts.ada2022, 0);

    fs::remove_dir_all(tmp).unwrap();
}

#[test]
fn count_fixtures_per_dialect_counts_manifest_files() {
    let tmp = test_temp_dir("manifests");
    fs::create_dir_all(tmp.join("ada2012/scenario_a")).unwrap();
    fs::write(tmp.join("ada2012/scenario_a/manifest.toml"), "").unwrap();
    fs::create_dir_all(tmp.join("ada2012/scenario_b")).unwrap();
    fs::write(tmp.join("ada2012/scenario_b/manifest.toml"), "").unwrap();

    let counts = count_fixtures_per_dialect(&tmp);

    assert_eq!(counts.ada2012, 2);
    assert_eq!(counts.ada95, 0);

    fs::remove_dir_all(tmp).unwrap();
}

fn test_temp_dir(name: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "govfuzz-golden-{name}-{}-{unique}",
        std::process::id()
    ));

    if path.exists() {
        fs::remove_dir_all(&path).unwrap();
    }
    fs::create_dir_all(&path).unwrap();
    path
}

#[derive(Default)]
struct Totals {
    expected_subprograms: usize,
    extracted_subprograms: usize,
    expected_handlers: usize,
    extracted_handlers: usize,
    expected_raises: usize,
    extracted_raises: usize,
}

#[derive(Default)]
struct DialectFixtureCounts {
    ada95: usize,
    ada2005: usize,
    ada2012: usize,
    ada2022: usize,
}

fn golden_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

fn count_fixtures_per_dialect(root: &Path) -> DialectFixtureCounts {
    DialectFixtureCounts {
        ada95: walk_fixtures(&root.join("ada95")).len(),
        ada2005: walk_fixtures(&root.join("ada2005")).len(),
        ada2012: walk_fixtures(&root.join("ada2012")).len(),
        ada2022: walk_fixtures(&root.join("ada2022")).len(),
    }
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

    let mut entries: Vec<_> = entries
        .map(|entry| entry.unwrap_or_else(|error| panic!("failed to read dir entry: {error}")))
        .collect();
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

fn load_source(fixture: &Path) -> (String, PathBuf) {
    for file_name in ["src.adb", "src.ads"] {
        let path = fixture.join(file_name);
        if path.is_file() {
            let source = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
            return (source, path);
        }
    }

    panic!("{}: fixture has no src.adb or src.ads", fixture.display());
}

fn parse_unit_kind(value: &str) -> Option<UnitKind> {
    match value {
        "spec" => Some(UnitKind::Spec),
        "body" => Some(UnitKind::Body),
        "subunit" => Some(UnitKind::Subunit),
        _ => None,
    }
}

fn check_not_over_extracted(
    label: &str,
    field: &str,
    extracted: usize,
    expected: usize,
    failures: &mut Vec<String>,
) {
    if extracted > expected {
        failures.push(format!(
            "{label}: extracted {field} count {extracted} exceeds expected ground truth {expected}"
        ));
    }
}

fn check_expected_strings(
    label: &str,
    field: &str,
    extracted: &[&str],
    expected: &[String],
    failures: &mut Vec<String>,
) {
    if extracted.len() > expected.len() {
        failures.push(format!(
            "{label}: extracted {field} count {} exceeds expected ground truth {}",
            extracted.len(),
            expected.len()
        ));
    }

    for item in extracted {
        if !expected.iter().any(|expected| expected == item) {
            failures.push(format!(
                "{label}: extracted {field} '{item}' not in manifest allow-list {expected:?}"
            ));
        }
    }
}

fn check_required_subset_strings(
    fixture_path: &Path,
    field_label: &str,
    expected: &[String],
    extracted: &[String],
    failures: &mut Vec<String>,
) {
    for required in expected {
        if !extracted.iter().any(|item| item == required) {
            failures.push(format!(
                "{}: manifest expects {} '{}' but it was not extracted (extracted: {:?})",
                fixture_path.display(),
                field_label,
                required,
                extracted
            ));
        }
    }
}

fn check_exact_count(
    fixture_path: &Path,
    field_label: &str,
    expected: usize,
    extracted: usize,
    failures: &mut Vec<String>,
) {
    if expected > 0 && extracted != expected {
        failures.push(format!(
            "{}: manifest expects {} count = {} but extractor returned {}",
            fixture_path.display(),
            field_label,
            expected,
            extracted
        ));
    }
}

fn extraction_ratio(extracted: usize, expected: usize) -> f64 {
    if expected == 0 {
        1.0
    } else {
        extracted as f64 / expected as f64
    }
}

fn type_kind_name(kind: &TypeKind) -> String {
    match kind {
        TypeKind::Scalar(ScalarKind::Integer) => "scalar.integer".to_owned(),
        TypeKind::Scalar(ScalarKind::Modular) => "scalar.modular".to_owned(),
        TypeKind::Scalar(ScalarKind::Float) => "scalar.float".to_owned(),
        TypeKind::Scalar(ScalarKind::Fixed) => "scalar.fixed".to_owned(),
        TypeKind::Scalar(ScalarKind::Decimal) => "scalar.decimal".to_owned(),
        TypeKind::Scalar(ScalarKind::Character) => "scalar.character".to_owned(),
        TypeKind::Scalar(ScalarKind::Boolean) => "scalar.boolean".to_owned(),
        TypeKind::Scalar(ScalarKind::Other) => "scalar.other".to_owned(),
        TypeKind::Enum(_) => "enum".to_owned(),
        TypeKind::Array { .. } => "array".to_owned(),
        TypeKind::Record(_) => "record".to_owned(),
        TypeKind::Discriminated { .. } => "discriminated".to_owned(),
        TypeKind::Tagged {
            is_abstract: true, ..
        } => "tagged.abstract".to_owned(),
        TypeKind::Tagged {
            is_abstract: false, ..
        } => "tagged".to_owned(),
        TypeKind::Derived { .. } => "derived".to_owned(),
        TypeKind::Interface {
            kind: InterfaceKind::Plain,
            ..
        } => "interface.plain".to_owned(),
        TypeKind::Interface {
            kind: InterfaceKind::Limited,
            ..
        } => "interface.limited".to_owned(),
        TypeKind::Interface {
            kind: InterfaceKind::Synchronized,
            ..
        } => "interface.synchronized".to_owned(),
        TypeKind::Interface {
            kind: InterfaceKind::Task,
            ..
        } => "interface.task".to_owned(),
        TypeKind::Interface {
            kind: InterfaceKind::Protected,
            ..
        } => "interface.protected".to_owned(),
        TypeKind::Access { .. } => "access".to_owned(),
        TypeKind::Private => "private".to_owned(),
        TypeKind::Generic(_) => "generic".to_owned(),
        TypeKind::Unknown => "unknown".to_owned(),
    }
}
