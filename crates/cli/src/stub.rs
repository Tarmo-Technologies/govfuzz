// SPDX-License-Identifier: Apache-2.0

use ada_parser::ast::AdaStandard;
use compiler_adapter::{probe_compiler, CompilerAdapter, ToolchainConfig};
use project_synth::{ProjectSpec, SourceRoot, Switches};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use stub_gen::{
    run_build_loop, synth_stub, write_manifest, BuildLoopOutcome, BuildLoopResult, StubGenError,
    StubManifest, StubManifestEntry, StubNeed, StubNeedKind, StubOp, StubOpKind,
};

use crate::probe_backend::{materialize_runtime_sources, ProbeBackend};

#[derive(Debug, Clone, clap::Args, PartialEq)]
pub struct StubArgs {
    /// Path to govfuzz_work directory containing src_instrumented and generated_harnesses.
    pub work_dir: PathBuf,

    /// Harness id to use. Defaults to the only harness present.
    #[arg(long)]
    pub harness: Option<String>,

    /// Target triple for cross-compilation project synthesis and default tool prefix.
    #[arg(long)]
    pub target: Option<String>,

    /// Ada runtime name to pass through the generated GPR project.
    #[arg(long)]
    pub runtime: Option<String>,

    /// Toolchain executable prefix, e.g. aarch64-linux-gnu for aarch64-linux-gnu-gprbuild.
    #[arg(long)]
    pub toolchain: Option<String>,

    /// AdaFuzz.Probe runtime backend to compile into the harness runtime.
    #[arg(long, value_enum, default_value = "host_file")]
    pub(crate) probe_backend: ProbeBackend,
}

pub fn run(args: StubArgs) -> i32 {
    let adapter = match CompilerAdapter::discover_for(toolchain_config(&args)) {
        Ok(adapter) => adapter,
        Err(error) => {
            eprintln!("{error}");
            return 2;
        }
    };

    if let Err(error) = probe_compiler(&adapter) {
        eprintln!("{error}");
        return 2;
    }

    let layout = match prepare_layout(&args) {
        Ok(layout) => layout,
        Err(error) => {
            eprintln!("{error}");
            return 3;
        }
    };

    let result = match run_build_loop(&layout.work_dir, &layout.project_spec, &adapter) {
        Ok(result) => result,
        Err(StubGenError::CompilerAdapter(error)) => {
            eprintln!("{error}");
            return 2;
        }
        Err(error) => {
            eprintln!("{error}");
            return 1;
        }
    };

    let manifest = manifest_from_result(&result, &layout.stubs_dir);
    if let Err(error) = write_manifest(&layout.stubs_dir.join("manifest.json"), &manifest) {
        eprintln!("{error}");
        return 1;
    }

    println!("stub generation outcome: {:?}", result.outcome);
    match result.outcome {
        BuildLoopOutcome::CleanBuild => 0,
        BuildLoopOutcome::BlockedNoProgress | BuildLoopOutcome::BlockedMaxIter => 4,
        BuildLoopOutcome::BlockedUnparseable => 5,
    }
}

struct StubLayout {
    work_dir: PathBuf,
    stubs_dir: PathBuf,
    project_spec: ProjectSpec,
}

fn prepare_layout(args: &StubArgs) -> Result<StubLayout, String> {
    let work_dir = absolutize(&args.work_dir)?;
    if !work_dir.is_dir() {
        return Err(format!("work dir '{}' does not exist", work_dir.display()));
    }

    let source_dir = work_dir.join("src_instrumented");
    if !source_dir.is_dir() {
        return Err(format!(
            "work dir malformed: missing {}",
            source_dir.display()
        ));
    }

    let (_harness_id, harness_dir) = select_harness(&work_dir, args.harness.as_deref())?;
    let main_adb = harness_dir.join("main.adb");
    if !main_adb.is_file() {
        return Err(format!(
            "work dir malformed: missing {}",
            main_adb.display()
        ));
    }

    let stubs_dir = work_dir.join("generated_stubs");
    fs::create_dir_all(&stubs_dir)
        .map_err(|error| format!("create stubs directory '{}': {error}", stubs_dir.display()))?;

    let obj_dir = work_dir.join("build/stub-obj");
    fs::create_dir_all(&obj_dir)
        .map_err(|error| format!("create object directory '{}': {error}", obj_dir.display()))?;

    let ada_standard = detect_ada_standard(&source_dir)?;
    let runtime_dir =
        materialize_runtime_sources(&work_dir.join("build/stub-runtime-src"), args.probe_backend)?;
    let project_spec = ProjectSpec {
        project_name: "Govfuzz_Build".to_owned(),
        source_roots: vec![
            SourceRoot {
                path: runtime_dir,
                language: "Ada".to_owned(),
            },
            SourceRoot {
                path: source_dir,
                language: "Ada".to_owned(),
            },
            SourceRoot {
                path: harness_dir,
                language: "Ada".to_owned(),
            },
            SourceRoot {
                path: stubs_dir.clone(),
                language: "Ada".to_owned(),
            },
        ],
        object_dir: obj_dir,
        main_adb: Some("main.adb".to_owned()),
        ada_standard,
        target: args.target.clone(),
        runtime: args.runtime.clone(),
        toolchain: args.toolchain.clone(),
        switches: Switches::default(),
        with_clauses: Vec::new(),
        executable_name: None,
        compile_c: false,
        excluded_source_files: Vec::new(),
    };

    Ok(StubLayout {
        work_dir,
        stubs_dir,
        project_spec,
    })
}

fn select_harness(work_dir: &Path, requested: Option<&str>) -> Result<(String, PathBuf), String> {
    let harness_root = work_dir.join("generated_harnesses");
    if !harness_root.is_dir() {
        return Err(format!(
            "work dir malformed: missing {}",
            harness_root.display()
        ));
    }

    if let Some(harness_id) = requested {
        let harness_dir = harness_root.join(harness_id);
        if harness_dir.is_dir() {
            return Ok((harness_id.to_owned(), harness_dir));
        }
        return Err(format!(
            "work dir malformed: harness '{}' not found under {}",
            harness_id,
            harness_root.display()
        ));
    }

    let mut harnesses = Vec::new();
    for entry in fs::read_dir(&harness_root).map_err(|error| {
        format!(
            "read harness directory '{}': {error}",
            harness_root.display()
        )
    })? {
        let entry = entry.map_err(|error| {
            format!(
                "read harness directory entry under '{}': {error}",
                harness_root.display()
            )
        })?;
        let file_type = entry.file_type().map_err(|error| {
            format!(
                "read harness entry type '{}': {error}",
                entry.path().display()
            )
        })?;
        if file_type.is_dir() {
            harnesses.push((
                entry.file_name().to_string_lossy().into_owned(),
                entry.path(),
            ));
        }
    }
    harnesses.sort_by(|left, right| left.0.cmp(&right.0));

    match harnesses.len() {
        0 => Err(format!(
            "work dir malformed: no harnesses under {}",
            harness_root.display()
        )),
        1 => {
            let only = harnesses.remove(0);
            Ok((only.0, only.1))
        }
        count => Err(format!(
            "work dir malformed: {count} harnesses found; pass --harness"
        )),
    }
}

fn detect_ada_standard(source_dir: &Path) -> Result<AdaStandard, String> {
    let source_path = first_ada_source(source_dir)?;
    let source = crate::source_text::read_source_text(&source_path)
        .map_err(|error| format!("read Ada source '{}': {error}", source_path.display()))?;
    let ast = ada_parser::reconcile::build_structural_ast(&source, None, &source_path)
        .map_err(|error| format!("scan Ada source '{}': {error}", source_path.display()))?;

    Ok(ast
        .units
        .first()
        .map(|unit| unit.ada_standard)
        .unwrap_or(AdaStandard::Ada2012))
}

fn first_ada_source(source_dir: &Path) -> Result<PathBuf, String> {
    let mut sources = Vec::new();
    for entry in fs::read_dir(source_dir)
        .map_err(|error| format!("read source directory '{}': {error}", source_dir.display()))?
    {
        let entry = entry.map_err(|error| {
            format!(
                "read source directory entry under '{}': {error}",
                source_dir.display()
            )
        })?;
        let path = entry.path();
        if is_ada_source(&path) {
            sources.push(path);
        }
    }
    sources.sort();

    sources.into_iter().next().ok_or_else(|| {
        format!(
            "work dir malformed: no Ada sources under {}",
            source_dir.display()
        )
    })
}

fn toolchain_config(args: &StubArgs) -> ToolchainConfig {
    ToolchainConfig {
        target: args.target.clone(),
        runtime: args.runtime.clone(),
        toolchain: args.toolchain.clone(),
    }
}

fn is_ada_source(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("adb") || extension.eq_ignore_ascii_case("ads")
        })
}

fn manifest_from_result(result: &BuildLoopResult, stubs_dir: &Path) -> StubManifest {
    let triggered_by = result
        .last_diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.clone())
        .collect::<Vec<_>>();
    let mut stubs = Vec::new();
    for need in &result.stub_needs {
        push_manifest_entry(&mut stubs, need, stubs_dir, &triggered_by);
        if let StubNeedKind::PackageSpec { decls } = &need.kind {
            if !decls.is_empty() {
                let body_need = package_body_need_from_spec(need, decls);
                push_manifest_entry(&mut stubs, &body_need, stubs_dir, &triggered_by);
            }
        }
    }

    StubManifest {
        generated_at: current_timestamp(),
        iterations: result.iterations,
        outcome: result.outcome,
        stubs,
    }
}

fn push_manifest_entry(
    entries: &mut Vec<StubManifestEntry>,
    need: &StubNeed,
    stubs_dir: &Path,
    triggered_by: &[String],
) {
    let stub = synth_stub(need, stubs_dir);
    entries.push(StubManifestEntry {
        unit_name: need.unit_name.clone(),
        kind: need.kind.clone(),
        path: stub.path,
        triggered_by: triggered_by.to_vec(),
        confidence_delta: 0.05,
    });
}

fn package_body_need_from_spec(need: &StubNeed, decls: &[String]) -> StubNeed {
    StubNeed {
        unit_name: need.unit_name.clone(),
        kind: StubNeedKind::PackageBody {
            ops: decls
                .iter()
                .map(|decl| StubOp {
                    name: decl.clone(),
                    kind: StubOpKind::Procedure,
                    return_type: None,
                    params: Vec::new(),
                })
                .collect(),
        },
    }
}

fn current_timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    format_unix_timestamp(seconds)
}

fn format_unix_timestamp(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let seconds_of_day = seconds % 86_400;
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    let (year, month, day) = civil_from_days(days);

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days_since_unix_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_unix_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };

    (year as i32, month as u32, day as u32)
}

fn absolutize(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|error| format!("resolve current directory: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use stub_gen::{BuildLoopOutcome, BuildLoopResult, StubNeed, StubNeedKind};

    use super::{format_unix_timestamp, manifest_from_result};

    #[test]
    fn format_unix_timestamp_formats_epoch_as_rfc3339() {
        assert_eq!(format_unix_timestamp(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn format_unix_timestamp_formats_next_day_as_rfc3339() {
        assert_eq!(format_unix_timestamp(86_400), "1970-01-02T00:00:00Z");
    }

    #[test]
    fn manifest_from_result_records_generated_spec_and_body_files() {
        let result = BuildLoopResult {
            outcome: BuildLoopOutcome::CleanBuild,
            iterations: 2,
            stub_needs: vec![StubNeed {
                unit_name: "External_Lib".to_owned(),
                kind: StubNeedKind::PackageSpec {
                    decls: vec!["Process".to_owned()],
                },
            }],
            last_diagnostics: Vec::new(),
            stubs_generated: Vec::new(),
        };

        let manifest = manifest_from_result(&result, Path::new("/tmp/stubs"));

        assert_eq!(manifest.stubs.len(), 2);
        assert_eq!(
            manifest.stubs[0].path,
            Path::new("/tmp/stubs/external_lib.ads")
        );
        assert_eq!(
            manifest.stubs[1].path,
            Path::new("/tmp/stubs/external_lib.adb")
        );
    }
}
