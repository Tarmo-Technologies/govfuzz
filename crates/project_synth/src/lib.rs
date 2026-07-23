// SPDX-License-Identifier: Apache-2.0

pub use error::ProjectSynthError;
pub use spec::{ProjectSpec, SourceRoot, Switches};
pub use writer::{render_project, write_project};

pub mod error;
pub mod spec;
pub mod writer;

pub fn crate_name() -> &'static str {
    "project_synth"
}

#[cfg(test)]
mod tests {
    use ada_parser::ast::AdaStandard;

    use crate::{render_project, write_project, ProjectSpec, SourceRoot, Switches};

    fn spec_named(project_name: &str) -> ProjectSpec {
        ProjectSpec {
            project_name: project_name.to_owned(),
            extends_project: None,
            source_roots: vec![SourceRoot {
                path: "src_instrumented".into(),
                language: "Ada".to_owned(),
            }],
            object_dir: "obj".into(),
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

    #[test]
    fn project_spec_validate_accepts_valid_ada_identifier() {
        assert!(spec_named("Govfuzz_Build_1").validate().is_ok());
    }

    #[test]
    fn compile_c_declares_c_language_and_switch() {
        // A real Ada library (gnatcoll) binds to C glue; the project must declare
        // C so gprbuild compiles + links it, or the Ada link fails on the bound
        // C symbols. Default (pure Ada) stays Ada-only so a stray .c can't break
        // a previously-working build.
        let mut spec = spec_named("Govfuzz_Build");
        spec.compile_c = true;
        let with_c = render_project(&spec).unwrap();
        assert!(
            with_c.contains("for Languages use (\"Ada\", \"C\")"),
            "compile_c must declare C: {with_c}"
        );
        assert!(
            with_c.contains("for Default_Switches (\"C\") use (\"-g\")"),
            "compile_c must add the C switch: {with_c}"
        );

        let ada_only = render_project(&spec_named("Govfuzz_Build")).unwrap();
        assert!(
            !ada_only.contains("for Languages use"),
            "pure-Ada project must stay Ada-only (no Languages line): {ada_only}"
        );
    }

    #[test]
    fn excluded_source_files_emitted_only_when_populated() {
        // A same-stem `sxxx.adb` + `sxxx.c` collide on `sxxx.o`, which gprbuild
        // rejects; the colliding C file is excluded so the Ada unit wins.
        let mut spec = spec_named("Govfuzz_Build");
        spec.compile_c = true;
        spec.excluded_source_files = vec!["sxxx.c".to_owned()];
        let rendered = render_project(&spec).unwrap();
        assert!(
            rendered.contains("for Excluded_Source_Files use (\"sxxx.c\");"),
            "collision must drop the C source: {rendered}"
        );

        // Empty list emits no line — pure-Ada output stays byte-for-byte historical.
        let none = render_project(&spec_named("Govfuzz_Build")).unwrap();
        assert!(
            !none.contains("Excluded_Source_Files"),
            "no exclusions must emit no line: {none}"
        );
    }

    #[test]
    fn project_spec_validate_rejects_name_with_hyphen() {
        assert!(spec_named("Govfuzz-Build").validate().is_err());
    }

    #[test]
    fn project_spec_validate_rejects_name_starting_with_digit() {
        assert!(spec_named("1Govfuzz_Build").validate().is_err());
    }

    #[test]
    fn switches_default_includes_dash_g_and_dash_gnatwa() {
        let switches = Switches::default();

        assert!(switches.default.contains(&"-g".to_owned()));
        assert!(switches.default.contains(&"-gnatwa".to_owned()));
        assert!(switches.debug);
        assert!(!switches.warnings_as_errors);
    }

    #[test]
    fn source_root_serde_round_trip() {
        let root = SourceRoot {
            path: "generated_harnesses/H-TEST".into(),
            language: "Ada".to_owned(),
        };

        let encoded = serde_json::to_string(&root).expect("source root serializes");
        let decoded: SourceRoot = serde_json::from_str(&encoded).expect("source root deserializes");

        assert_eq!(decoded, root);
    }

    #[test]
    fn render_project_includes_spdx_header() {
        let rendered = render_project(&spec_named("Govfuzz_Build")).expect("project renders");

        assert!(rendered.starts_with("--  SPDX-License-Identifier: Apache-2.0\n"));
    }

    #[test]
    fn render_project_emits_with_clauses_in_order() {
        let mut spec = spec_named("Govfuzz_Build");
        spec.with_clauses = vec!["runtime/adafuzz.gpr".into(), "harness/harness.gpr".into()];

        let rendered = render_project(&spec).expect("project renders");

        assert!(rendered.contains("with \"runtime/adafuzz.gpr\";\nwith \"harness/harness.gpr\";\n"));
    }

    #[test]
    fn render_project_can_extend_a_governing_project() {
        let mut spec = spec_named("Govfuzz_Build");
        spec.extends_project = Some("/project/app.gpr".into());
        let rendered = render_project(&spec).unwrap();
        assert!(rendered.contains("project Govfuzz_Build extends \"/project/app.gpr\" is"));
    }

    #[test]
    fn render_project_lists_source_dirs_quoted() {
        let mut spec = spec_named("Govfuzz_Build");
        spec.source_roots = vec![
            SourceRoot {
                path: "src_instrumented".into(),
                language: "Ada".to_owned(),
            },
            SourceRoot {
                path: "generated_harnesses/H-TEST".into(),
                language: "Ada".to_owned(),
            },
        ];

        let rendered = render_project(&spec).expect("project renders");

        assert!(rendered.contains(
            "for Source_Dirs use (\"src_instrumented\", \"generated_harnesses/H-TEST\");"
        ));
    }

    #[test]
    fn render_project_writes_object_dir() {
        let rendered = render_project(&spec_named("Govfuzz_Build")).expect("project renders");

        assert!(rendered.contains("for Object_Dir use \"obj\";"));
    }

    #[test]
    fn render_project_omits_main_when_none() {
        let mut spec = spec_named("Govfuzz_Build");
        spec.main_adb = None;

        let rendered = render_project(&spec).expect("project renders");

        assert!(!rendered.contains("for Main use"));
    }

    #[test]
    fn render_project_includes_main_when_set() {
        let rendered = render_project(&spec_named("Govfuzz_Build")).expect("project renders");

        assert!(rendered.contains("for Main use (\"main.adb\");"));
    }

    #[test]
    fn render_project_emits_cross_toolchain_attributes_when_set() {
        let mut spec = spec_named("Govfuzz_Build");
        spec.target = Some("aarch64-linux-gnu".to_owned());
        spec.runtime = Some("ravenscar-full".to_owned());
        spec.toolchain = Some("aarch64-linux-gnu".to_owned());

        let rendered = render_project(&spec).expect("project renders");

        assert!(rendered.contains("for Target use \"aarch64-linux-gnu\";"));
        assert!(rendered.contains("for Runtime (\"Ada\") use \"ravenscar-full\";"));
        assert!(rendered.contains("for Toolchain_Name (\"Ada\") use \"aarch64-linux-gnu\";"));
    }

    #[test]
    fn render_project_default_switches_include_user_switches() {
        let mut spec = spec_named("Govfuzz_Build");
        spec.switches.default.push("-gnatVa".to_owned());

        let rendered = render_project(&spec).expect("project renders");

        assert!(rendered.contains("\"-g\", \"-gnatwa\", \"-gnatVa\""));
    }

    #[test]
    fn render_project_emits_dialect_switch_per_ada_standard_ada95() {
        assert_dialect_switch(AdaStandard::Ada95, "-gnat95");
    }

    #[test]
    fn render_project_emits_dialect_switch_per_ada_standard_ada2005() {
        assert_dialect_switch(AdaStandard::Ada2005, "-gnat05");
    }

    #[test]
    fn render_project_emits_dialect_switch_per_ada_standard_ada2012() {
        assert_dialect_switch(AdaStandard::Ada2012, "-gnat12");
    }

    #[test]
    fn render_project_emits_dialect_switch_per_ada_standard_ada2022() {
        assert_dialect_switch(AdaStandard::Ada2022, "-gnat2022");
    }

    #[test]
    fn render_project_rejects_invalid_project_name() {
        let error = render_project(&spec_named("Govfuzz-Build")).expect_err("name is invalid");

        assert!(error.to_string().contains("invalid project name"));
    }

    #[test]
    fn write_project_writes_to_disk_and_round_trips_through_render() {
        let spec = spec_named("Govfuzz_Build");
        let path = std::env::temp_dir().join(format!(
            "govfuzz-project-synth-test-{}-{}.gpr",
            std::process::id(),
            "write_project"
        ));

        write_project(&spec, &path).expect("project writes");
        let written = std::fs::read_to_string(&path).expect("project file is readable");
        std::fs::remove_file(&path).expect("temporary project file is removed");

        assert_eq!(written, render_project(&spec).expect("project renders"));
    }

    fn assert_dialect_switch(standard: AdaStandard, expected_switch: &str) {
        let mut spec = spec_named("Govfuzz_Build");
        spec.ada_standard = standard;

        let rendered = render_project(&spec).expect("project renders");

        assert!(rendered.contains(&format!("\"{expected_switch}\"")));
    }
}
