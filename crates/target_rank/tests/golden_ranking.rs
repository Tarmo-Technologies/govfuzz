// SPDX-License-Identifier: Apache-2.0

use ada_parser::ast::HandlerOwner;
use ada_parser::reconcile::build_structural_ast;
use std::fs;
use std::path::{Path, PathBuf};
use target_rank::rank_targets;

#[test]
fn swallowed_handler_subprograms_are_in_top_10_percent() {
    let corpus_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../ada_parser/tests/golden");
    let fixtures = walk_corpus(&corpus_root);
    let mut total_fixtures_with_handlers = 0usize;
    let mut fixtures_with_all_handler_owners_in_cutoff = 0usize;
    let mut violations = Vec::new();

    for fixture in fixtures {
        let Some(path) = fixture_source_path(&fixture) else {
            continue;
        };
        let source = match fs::read_to_string(&path) {
            Ok(source) => source,
            Err(error) => {
                violations.push(format!("{}: read failed: {error}", path.display()));
                continue;
            }
        };
        let ast = match build_structural_ast(&source, None, &path) {
            Ok(ast) => ast,
            Err(error) => {
                violations.push(format!("{}: scan failed: {error}", path.display()));
                continue;
            }
        };
        if ast.handlers.is_empty() {
            continue;
        }

        total_fixtures_with_handlers += 1;
        let targets = rank_targets(&ast);
        let top_cutoff = targets.len().div_ceil(10).max(1);
        let mut fixture_violations = Vec::new();
        let mut owners = Vec::new();
        for handler in &ast.handlers {
            if let HandlerOwner::Subprogram(owner_id) = handler.owner {
                if !owners.contains(&owner_id) {
                    owners.push(owner_id);
                }
            }
        }

        for owner_id in owners {
            let position = targets
                .iter()
                .position(|target| target.subprogram_id == owner_id);
            let Some(pos) = position else {
                fixture_violations.push(format!(
                    "{}: handler owner sp_id={owner_id:?} not in ranked targets",
                    fixture.display()
                ));
                continue;
            };
            if pos >= top_cutoff {
                fixture_violations.push(format!(
                    "{}: handler owner '{}' at rank {}/{} (cutoff: {})",
                    fixture.display(),
                    targets[pos].name,
                    pos + 1,
                    targets.len(),
                    top_cutoff
                ));
            }
        }

        if fixture_violations.is_empty() {
            fixtures_with_all_handler_owners_in_cutoff += 1;
        } else {
            violations.extend(fixture_violations);
        }
    }

    println!(
        "Evaluated {total_fixtures_with_handlers} fixtures with handlers; \
         {fixtures_with_all_handler_owners_in_cutoff}/{total_fixtures_with_handlers} fixtures passed"
    );
    assert!(
        violations.is_empty(),
        "{} top-10% violations:\n{}",
        violations.len(),
        violations.join("\n")
    );
}

fn walk_corpus(root: &Path) -> Vec<PathBuf> {
    let mut fixtures = Vec::new();
    collect_fixtures(root, &mut fixtures);
    fixtures.sort();
    fixtures
}

fn collect_fixtures(path: &Path, fixtures: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    let mut has_source = false;
    let mut child_dirs = Vec::new();
    for entry in entries.flatten() {
        let entry_path = entry.path();
        if entry_path.is_dir() {
            child_dirs.push(entry_path);
        } else if entry_path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| matches!(name, "src.adb" | "src.ads"))
        {
            has_source = true;
        }
    }

    if has_source {
        fixtures.push(path.to_path_buf());
        return;
    }

    child_dirs.sort();
    for child in child_dirs {
        collect_fixtures(&child, fixtures);
    }
}

fn fixture_source_path(fixture: &Path) -> Option<PathBuf> {
    let body = fixture.join("src.adb");
    if body.is_file() {
        return Some(body);
    }

    let spec = fixture.join("src.ads");
    if spec.is_file() {
        Some(spec)
    } else {
        None
    }
}
