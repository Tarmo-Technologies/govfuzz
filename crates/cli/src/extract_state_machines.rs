// SPDX-License-Identifier: Apache-2.0

//! `govfuzz extract-state-machines` subcommand: print state
//! machines inferred from Ada `protected type` and `task type`
//! declarations as JSON.

use ada_state_machine::infer_from_source;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct ExtractStateMachinesArgs {
    /// Path to an Ada source file (or directory of `.ad[bs]` files).
    pub path: PathBuf,
}

pub fn run(args: ExtractStateMachinesArgs) -> i32 {
    let files = match collect_ada_files(&args.path) {
        Ok(files) => files,
        Err(error) => {
            eprintln!("error: {error}");
            return 1;
        }
    };
    let mut all_machines: Vec<serde_json::Value> = Vec::new();
    for path in files {
        let source = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(error) => {
                eprintln!("warning: read {}: {error}", path.display());
                continue;
            }
        };
        match infer_from_source(&source) {
            Ok(machines) => {
                for machine in machines {
                    let mut value = serde_json::to_value(&machine).expect("serialize machine");
                    if let Some(obj) = value.as_object_mut() {
                        obj.insert(
                            "source_path".to_owned(),
                            serde_json::Value::String(path.display().to_string()),
                        );
                    }
                    all_machines.push(value);
                }
            }
            Err(error) => {
                eprintln!("warning: infer {}: {error}", path.display());
            }
        }
    }
    let json = serde_json::to_string_pretty(&all_machines).unwrap_or_else(|_| "[]".to_owned());
    println!("{json}");
    0
}

fn collect_ada_files(path: &PathBuf) -> Result<Vec<PathBuf>, String> {
    if path.is_file() {
        return Ok(vec![path.clone()]);
    }
    if !path.is_dir() {
        return Err(format!("path not found: {}", path.display()));
    }
    let mut files = Vec::new();
    walk(path, &mut files)?;
    files.sort();
    Ok(files)
}

fn walk(dir: &PathBuf, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| format!("read {}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let p = entry.path();
        if p.is_dir() {
            walk(&p, out)?;
            continue;
        }
        if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
            if matches!(ext, "adb" | "ads") {
                out.push(p);
            }
        }
    }
    Ok(())
}
