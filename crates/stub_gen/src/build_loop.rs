// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use compiler_adapter::{BuildResult, CompilerAdapter};
use project_synth::{write_project, ProjectSpec};

use crate::{
    derive_stub_needs, parse_json, parse_text, synth_all, Diagnostic, StubFile, StubGenError,
    StubNeed, StubNeedKind,
};

const MAX_ITER: u32 = 8;

#[derive(Debug, Clone)]
pub struct BuildLoopResult {
    pub outcome: BuildLoopOutcome,
    pub iterations: u32,
    pub stub_needs: Vec<StubNeed>,
    pub last_diagnostics: Vec<Diagnostic>,
    pub stubs_generated: Vec<StubFile>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildLoopOutcome {
    CleanBuild,
    BlockedNoProgress,
    BlockedMaxIter,
    BlockedUnparseable,
}

pub trait BuildBackend {
    fn check(&self, project: &Path) -> Result<BuildResult, StubGenError>;
    fn build(&self, project: &Path) -> Result<BuildResult, StubGenError>;
}

impl BuildBackend for CompilerAdapter {
    fn check(&self, project: &Path) -> Result<BuildResult, StubGenError> {
        CompilerAdapter::check(self, project).map_err(StubGenError::from)
    }

    fn build(&self, project: &Path) -> Result<BuildResult, StubGenError> {
        CompilerAdapter::build(self, project).map_err(StubGenError::from)
    }
}

pub fn run_build_loop(
    work_dir: &Path,
    project_spec: &ProjectSpec,
    adapter: &CompilerAdapter,
) -> Result<BuildLoopResult, StubGenError> {
    run_build_loop_with_backend(work_dir, project_spec, adapter)
}

pub fn run_build_loop_with_backend<B: BuildBackend>(
    work_dir: &Path,
    project_spec: &ProjectSpec,
    backend: &B,
) -> Result<BuildLoopResult, StubGenError> {
    let mut needs = Vec::new();
    let mut last_diagnostics = Vec::new();
    let stubs_dir = work_dir.join("generated_stubs");
    std::fs::create_dir_all(&stubs_dir)?;

    for iteration in 1..=MAX_ITER {
        let gpr_path = work_dir.join("build/govfuzz_build.gpr");
        if let Some(parent) = gpr_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::create_dir_all(&project_spec.object_dir)?;
        write_project(project_spec, &gpr_path)?;

        let check_result = backend.check(&gpr_path)?;
        let result = if check_result.exit_code == 0 {
            let full = backend.build(&gpr_path)?;
            if full.exit_code == 0 {
                return Ok(BuildLoopResult {
                    outcome: BuildLoopOutcome::CleanBuild,
                    iterations: iteration,
                    stub_needs: needs.clone(),
                    last_diagnostics: Vec::new(),
                    stubs_generated: synth_all(&needs, &stubs_dir),
                });
            }
            full
        } else {
            check_result
        };

        let diags = match parse_compiler_diagnostics(&result.stderr) {
            Ok(diags) => diags,
            Err(()) => {
                return Ok(BuildLoopResult {
                    outcome: BuildLoopOutcome::BlockedUnparseable,
                    iterations: iteration,
                    stub_needs: needs,
                    last_diagnostics: Vec::new(),
                    stubs_generated: Vec::new(),
                });
            }
        };
        let new_needs = derive_stub_needs(&diags);
        let mut added = false;
        for need in new_needs {
            added |= append_need(&mut needs, need);
        }

        if !added {
            return Ok(BuildLoopResult {
                outcome: BuildLoopOutcome::BlockedNoProgress,
                iterations: iteration,
                stub_needs: needs,
                last_diagnostics: diags,
                stubs_generated: Vec::new(),
            });
        }

        last_diagnostics = diags;
        write_generated_stubs(&needs, &stubs_dir)?;
    }

    Ok(BuildLoopResult {
        outcome: BuildLoopOutcome::BlockedMaxIter,
        iterations: MAX_ITER,
        stub_needs: needs.clone(),
        last_diagnostics,
        stubs_generated: synth_all(&needs, &stubs_dir),
    })
}

fn parse_compiler_diagnostics(stderr: &str) -> Result<Vec<Diagnostic>, ()> {
    if stderr
        .lines()
        .any(|line| line.trim_start().starts_with('{'))
    {
        let json = parse_json(stderr).map_err(|_| ())?;
        if !json.is_empty() {
            return Ok(json);
        }
    }

    let text = parse_text(stderr);
    if text.is_empty() && !stderr.trim().is_empty() {
        Err(())
    } else {
        Ok(text)
    }
}

fn append_need(needs: &mut Vec<StubNeed>, need: StubNeed) -> bool {
    match need.kind {
        StubNeedKind::PackageSpec { decls } => append_package_spec(needs, need.unit_name, decls),
        StubNeedKind::PackageBody { ops } => append_package_body(needs, need.unit_name, ops),
        StubNeedKind::Identifier { .. } | StubNeedKind::Visibility { .. } => {
            if needs.contains(&need) {
                false
            } else {
                needs.push(need);
                true
            }
        }
    }
}

fn append_package_spec(needs: &mut Vec<StubNeed>, unit_name: String, decls: Vec<String>) -> bool {
    if let Some(existing) = needs.iter_mut().find(|existing| {
        existing.unit_name == unit_name && matches!(existing.kind, StubNeedKind::PackageSpec { .. })
    }) {
        if let StubNeedKind::PackageSpec {
            decls: existing_decls,
        } = &mut existing.kind
        {
            let mut changed = false;
            for decl in decls {
                if !existing_decls.contains(&decl) {
                    existing_decls.push(decl);
                    changed = true;
                }
            }
            changed
        } else {
            false
        }
    } else {
        needs.push(StubNeed {
            unit_name,
            kind: StubNeedKind::PackageSpec { decls },
        });
        true
    }
}

fn append_package_body(
    needs: &mut Vec<StubNeed>,
    unit_name: String,
    ops: Vec<crate::StubOp>,
) -> bool {
    if let Some(existing) = needs.iter_mut().find(|existing| {
        existing.unit_name == unit_name && matches!(existing.kind, StubNeedKind::PackageBody { .. })
    }) {
        if let StubNeedKind::PackageBody { ops: existing_ops } = &mut existing.kind {
            let mut changed = false;
            for op in ops {
                if !existing_ops.contains(&op) {
                    existing_ops.push(op);
                    changed = true;
                }
            }
            changed
        } else {
            false
        }
    } else {
        needs.push(StubNeed {
            unit_name,
            kind: StubNeedKind::PackageBody { ops },
        });
        true
    }
}

fn write_generated_stubs(needs: &[StubNeed], stubs_dir: &Path) -> Result<(), StubGenError> {
    for stub in synth_all(needs, stubs_dir) {
        if let Some(parent) = stub.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&stub.path, stub.content)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::path::Path;
    use std::sync::Mutex;

    use ada_parser::ast::AdaStandard;
    use compiler_adapter::{BuildMode, BuildResult};
    use project_synth::{ProjectSpec, SourceRoot, Switches};

    use super::{run_build_loop_with_backend, BuildBackend};
    use crate::{BuildLoopOutcome, StubGenError, StubNeedKind};

    #[test]
    fn build_loop_clean_first_iteration_returns_clean_build() {
        let temp = tempfile::TempDir::new().expect("temp dir is created");
        let backend = FakeBackend::new(vec![clean_check()], vec![clean_build()]);

        let result = run_build_loop_with_backend(temp.path(), &project_spec(temp.path()), &backend)
            .expect("build loop runs");

        assert_eq!(result.outcome, BuildLoopOutcome::CleanBuild);
        assert_eq!(result.iterations, 1);
        assert!(result.stub_needs.is_empty());
    }

    #[test]
    fn build_loop_one_missing_unit_iterates_once_then_clean() {
        let temp = tempfile::TempDir::new().expect("temp dir is created");
        let backend =
            FakeBackend::new(vec![missing_external(), clean_check()], vec![clean_build()]);

        let result = run_build_loop_with_backend(temp.path(), &project_spec(temp.path()), &backend)
            .expect("build loop runs");

        assert_eq!(result.outcome, BuildLoopOutcome::CleanBuild);
        assert_eq!(result.iterations, 2);
        assert_eq!(result.stub_needs[0].unit_name, "External_Lib");
    }

    #[test]
    fn build_loop_two_iterations_for_chained_missing_units() {
        let temp = tempfile::TempDir::new().expect("temp dir is created");
        let backend = FakeBackend::new(
            vec![missing_external(), missing_helper(), clean_check()],
            vec![clean_build()],
        );

        let result = run_build_loop_with_backend(temp.path(), &project_spec(temp.path()), &backend)
            .expect("build loop runs");

        assert_eq!(result.outcome, BuildLoopOutcome::CleanBuild);
        assert_eq!(result.iterations, 3);
        assert_eq!(result.stub_needs.len(), 2);
    }

    #[test]
    fn build_loop_handles_missing_dependency_with_qualified_member_diagnostic() {
        let temp = tempfile::TempDir::new().expect("temp dir is created");
        let backend = FakeBackend::new(
            vec![
                failed_check(r#"demo.adb:3:10: file "external_lib.ads" not found"#),
                failed_check(r#"demo.adb:5:18: "Process" not declared in "External_Lib""#),
                clean_check(),
            ],
            vec![clean_build()],
        );

        let result = run_build_loop_with_backend(temp.path(), &project_spec(temp.path()), &backend)
            .expect("build loop runs");

        assert_eq!(result.outcome, BuildLoopOutcome::CleanBuild);
        assert_eq!(result.iterations, 3);

        let external_lib_specs = result
            .stub_needs
            .iter()
            .filter(|need| {
                need.unit_name == "External_Lib"
                    && matches!(need.kind, StubNeedKind::PackageSpec { .. })
            })
            .collect::<Vec<_>>();
        assert!(!external_lib_specs.is_empty());
        if let StubNeedKind::PackageSpec { decls } = &external_lib_specs[0].kind {
            assert!(decls.contains(&"Process".to_owned()));
        }
    }

    #[test]
    fn build_loop_blocks_at_max_iter() {
        let temp = tempfile::TempDir::new().expect("temp dir is created");
        let checks = (1..=8)
            .map(|index| {
                failed_check(&format!(
                    "foo.adb:1:1: file \"missing_{index}.ads\" not found\n"
                ))
            })
            .collect();
        let backend = FakeBackend::new(checks, Vec::new());

        let result = run_build_loop_with_backend(temp.path(), &project_spec(temp.path()), &backend)
            .expect("build loop runs");

        assert_eq!(result.outcome, BuildLoopOutcome::BlockedMaxIter);
        assert_eq!(result.iterations, 8);
        assert_eq!(result.stub_needs.len(), 8);
    }

    #[test]
    fn build_loop_blocks_when_no_new_needs_added() {
        let temp = tempfile::TempDir::new().expect("temp dir is created");
        let backend = FakeBackend::new(vec![missing_external(), missing_external()], Vec::new());

        let result = run_build_loop_with_backend(temp.path(), &project_spec(temp.path()), &backend)
            .expect("build loop runs");

        assert_eq!(result.outcome, BuildLoopOutcome::BlockedNoProgress);
        assert_eq!(result.iterations, 2);
        assert_eq!(result.stub_needs.len(), 1);
        assert_eq!(result.last_diagnostics.len(), 2);
    }

    #[test]
    fn build_loop_synthesizes_stub_files_to_disk() {
        let temp = tempfile::TempDir::new().expect("temp dir is created");
        let backend =
            FakeBackend::new(vec![missing_external(), clean_check()], vec![clean_build()]);

        let result = run_build_loop_with_backend(temp.path(), &project_spec(temp.path()), &backend)
            .expect("build loop runs");

        assert_eq!(result.outcome, BuildLoopOutcome::CleanBuild);
        assert!(temp
            .path()
            .join("generated_stubs/external_lib.ads")
            .is_file());
        assert!(temp
            .path()
            .join("generated_stubs/external_lib.adb")
            .is_file());
    }

    #[test]
    fn build_loop_uses_full_build_diagnostics_after_clean_check_failure() {
        let temp = tempfile::TempDir::new().expect("temp dir is created");
        let backend = FakeBackend::new(
            vec![clean_check(), clean_check()],
            vec![missing_external_build(), clean_build()],
        );

        let result = run_build_loop_with_backend(temp.path(), &project_spec(temp.path()), &backend)
            .expect("build loop runs");

        assert_eq!(result.outcome, BuildLoopOutcome::CleanBuild);
        assert_eq!(result.iterations, 2);
        assert_eq!(result.stub_needs[0].unit_name, "External_Lib");
    }

    #[test]
    fn build_loop_blocks_unparseable_when_stderr_has_no_diagnostics() {
        let temp = tempfile::TempDir::new().expect("temp dir is created");
        let backend = FakeBackend::new(
            vec![failed_check("compiler emitted unsupported text\n")],
            Vec::new(),
        );

        let result = run_build_loop_with_backend(temp.path(), &project_spec(temp.path()), &backend)
            .expect("build loop runs");

        assert_eq!(result.outcome, BuildLoopOutcome::BlockedUnparseable);
    }

    struct FakeBackend {
        checks: Mutex<VecDeque<BuildResult>>,
        builds: Mutex<VecDeque<BuildResult>>,
    }

    impl FakeBackend {
        fn new(checks: Vec<BuildResult>, builds: Vec<BuildResult>) -> Self {
            Self {
                checks: Mutex::new(VecDeque::from(checks)),
                builds: Mutex::new(VecDeque::from(builds)),
            }
        }
    }

    impl BuildBackend for FakeBackend {
        fn check(&self, _project: &Path) -> Result<BuildResult, StubGenError> {
            Ok(self
                .checks
                .lock()
                .expect("check queue lock")
                .pop_front()
                .expect("check result is queued"))
        }

        fn build(&self, _project: &Path) -> Result<BuildResult, StubGenError> {
            Ok(self
                .builds
                .lock()
                .expect("build queue lock")
                .pop_front()
                .expect("build result is queued"))
        }
    }

    fn project_spec(root: &Path) -> ProjectSpec {
        ProjectSpec {
            project_name: "Govfuzz_Build".to_owned(),
            extends_project: None,
            source_roots: vec![
                SourceRoot {
                    path: root.join("src_instrumented"),
                    language: "Ada".to_owned(),
                },
                SourceRoot {
                    path: root.join("generated_stubs"),
                    language: "Ada".to_owned(),
                },
            ],
            object_dir: root.join("obj"),
            exec_dir: None,
            main_adb: Some("main.adb".to_owned()),
            ada_standard: AdaStandard::Ada2012,
            target: None,
            runtime: None,
            toolchain: None,
            switches: Switches::default(),
            with_clauses: Vec::new(),
            executable_name: None,
            compile_c: false,
            excluded_source_files: Vec::new(),
        }
    }

    fn missing_external() -> BuildResult {
        failed_check(
            "foo.adb:1:1: file \"external_lib.ads\" not found\nfoo.adb:2:4: \"Process\" is undefined\n",
        )
    }

    fn missing_helper() -> BuildResult {
        failed_check("foo.adb:1:1: file \"helper_pkg.ads\" not found\n")
    }

    fn clean_check() -> BuildResult {
        result(BuildMode::CheckOnly, 0, "")
    }

    fn clean_build() -> BuildResult {
        result(BuildMode::Full, 0, "")
    }

    fn missing_external_build() -> BuildResult {
        result(
            BuildMode::Full,
            1,
            "foo.adb:1:1: file \"external_lib.ads\" not found\n",
        )
    }

    fn failed_check(stderr: &str) -> BuildResult {
        result(BuildMode::CheckOnly, 1, stderr)
    }

    fn result(mode: BuildMode, exit_code: i32, stderr: &str) -> BuildResult {
        BuildResult {
            mode,
            exit_code,
            stdout: String::new(),
            stderr: stderr.to_owned(),
            duration_ms: 0,
        }
    }
}
