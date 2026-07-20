// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn list_targets_reports_ada_generics_tasking_subunit_and_type_metadata() {
    let root = temp_dir("ada-depth-metadata");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("src/legacy.adb"),
        r#"pragma Ada_95;
package body Legacy is
   generic
      type Element is private;
   package Stack is
      procedure Push (Item : Element);
   end Stack;

   protected type Gate is
      entry Enter;
   private
      Open : Boolean := False;
   end Gate;

   task type Worker is
      entry Start;
   end Worker;

   type Private_Record is private;
   type Tagged_Service is tagged record
      Count : Natural;
   end record;
   type Node_Access is access all Tagged_Service;

   procedure Dispatch (Input : String) is separate;

private
   type Private_Record is record
      Value : Integer;
   end record;
end Legacy;
"#,
    )
    .unwrap();
    fs::write(
        root.join("src/legacy-dispatch.adb"),
        r#"separate (Legacy)
procedure Dispatch (Input : String) is
begin
   null;
end Dispatch;
"#,
    )
    .unwrap();

    let output = Command::new(govfuzz_bin())
        .args([
            "list-targets",
            root.join("src").to_str().unwrap(),
            "--format",
            "json",
            "--top",
            "20",
        ])
        .output()
        .unwrap();
    assert_success(output);
    let targets: serde_json::Value = serde_json::from_slice(
        &Command::new(govfuzz_bin())
            .args([
                "list-targets",
                root.join("src").to_str().unwrap(),
                "--format",
                "json",
                "--top",
                "20",
            ])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let dispatch = targets
        .as_array()
        .unwrap()
        .iter()
        .find(|target| {
            target["file"]
                .as_str()
                .is_some_and(|path| path.ends_with("legacy-dispatch.adb"))
                && target["target"]["name"]
                    .as_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("Legacy.Dispatch"))
        })
        .expect("Dispatch target");
    let dispatch = &dispatch["target"];
    assert_eq!(dispatch["metadata"]["ada_standard"], "ada_95");
    assert_eq!(dispatch["metadata"]["unit_kind"], "subunit");
    assert_eq!(dispatch["metadata"]["subunit_parent"], "Legacy");
    assert_eq!(dispatch["metadata"]["generic_context"]["declarations"], 1);
    assert_eq!(dispatch["metadata"]["concurrency"]["protected_objects"], 1);
    assert_eq!(dispatch["metadata"]["concurrency"]["tasks"], 1);
    assert_eq!(dispatch["metadata"]["concurrency"]["entries"], 2);
    assert_eq!(dispatch["metadata"]["type_model"]["private_types"], 1);
    assert_eq!(dispatch["metadata"]["type_model"]["tagged_types"], 1);
    assert_eq!(dispatch["metadata"]["type_model"]["access_types"], 1);
    assert!(
        dispatch["breakdown"]["protected_or_task"]
            .as_i64()
            .unwrap_or(0)
            > 0,
        "task/protected targets should be ranked with concurrency signal: {dispatch:#}"
    );
}

#[test]
fn generate_harness_writes_ada_project_profile_for_gpr_variables_and_subunits() {
    let root = temp_dir("ada-project-profile");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("legacy.ads"),
        "package Legacy is\n   procedure Drive (Input : String);\nend Legacy;\n",
    )
    .unwrap();
    fs::write(
        src.join("legacy.adb"),
        "package body Legacy is\n   procedure Drive (Input : String) is separate;\nend Legacy;\n",
    )
    .unwrap();
    fs::write(
        src.join("legacy-drive.adb"),
        "separate (Legacy)\nprocedure Drive (Input : String) is\nbegin\n   null;\nend Drive;\n",
    )
    .unwrap();
    let project = root.join("legacy.gpr");
    fs::write(
        &project,
        r#"project Legacy is
   type Build_Mode is ("debug", "release");
   Build : Build_Mode := external ("BUILD_MODE", "debug");
   for Source_Dirs use ("src", "generated/" & Build);
   package Compiler is
      case Build is
         when "debug" =>
            for Default_Switches ("Ada") use ("-gnata");
         when "release" =>
            for Default_Switches ("Ada") use ("-O2");
      end case;
   end Compiler;
end Legacy;
"#,
    )
    .unwrap();

    let output_dir = root.join("generated");
    assert_success(
        Command::new(govfuzz_bin())
            .args([
                "generate-harness",
                src.join("legacy.adb").to_str().unwrap(),
                "--target",
                "Drive",
                "--id",
                "H-ADA-PROFILE",
                "--project",
                project.to_str().unwrap(),
                "--source-tree",
                root.to_str().unwrap(),
                "--output",
                output_dir.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    let profile = read_json(&output_dir.join("H-ADA-PROFILE/govfuzz-project-profile.json"));
    assert_eq!(profile["schema_version"], "govfuzz.ada_project_profile.v1");
    assert_eq!(
        profile["project"]["path"].as_str(),
        Some(project.to_string_lossy().as_ref())
    );
    assert_eq!(profile["project_variables"][0]["name"], "Build");
    assert_eq!(
        profile["project_variables"][0]["external_name"],
        "BUILD_MODE"
    );
    assert_eq!(profile["project_variables"][0]["default"], "debug");
    assert_eq!(profile["project_variables"][0]["values"][1], "release");
    assert_eq!(profile["source_dirs"][0]["path"], "src");
    assert_eq!(
        profile["unsupported_constructs"][0]["kind"],
        "dynamic_source_dir"
    );
    assert_eq!(profile["subunits"][0]["path"], "src/legacy-drive.adb");
    assert_eq!(profile["subunits"][0]["parent"], "Legacy");
    assert_eq!(profile["compatibility"]["ada_standards"][0], "ada_2012");

    let gpr = fs::read_to_string(output_dir.join("H-ADA-PROFILE/H_ADA_PROFILE.gpr")).unwrap();
    assert!(gpr.contains("-- GovFuzz project profile: govfuzz-project-profile.json"));
    assert!(gpr.contains("-- GPR provenance:"));
}

#[test]
fn generate_harness_blocks_concurrent_ada_without_explicit_assumptions() {
    let root = temp_dir("ada-concurrency-block");
    let source = root.join("service.adb");
    fs::write(
        &source,
        r#"procedure Service is
   task type Worker is
      entry Start;
   end Worker;
   task body Worker is
   begin
      accept Start;
   end Worker;

   protected type Gate is
      procedure Open;
   private
      Ready : Boolean := False;
   end Gate;

   procedure Drive is
   begin
      null;
   end Drive;
begin
   null;
end Service;
"#,
    )
    .unwrap();

    let output = Command::new(govfuzz_bin())
        .args([
            "generate-harness",
            source.to_str().unwrap(),
            "--target",
            "Drive",
            "--id",
            "H-CONCURRENT",
            "--output",
            root.join("generated").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "concurrent Ada harness should be blocked until scheduling assumptions are explicit"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("blocked_by_concurrency"), "{stderr}");
    assert!(stderr.contains("task/protected"), "{stderr}");
    assert!(stderr.contains("wrap scheduling assumptions"), "{stderr}");
}

fn govfuzz_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_govfuzz"))
}

fn temp_dir(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    path.push(format!("govfuzz-{name}-{unique}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(path).unwrap_or_else(|error| {
        panic!("read {}: {error}", path.display());
    }))
    .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn assert_success(output: std::process::Output) {
    assert!(
        output.status.success(),
        "command failed with {:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
