// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn fake_corba_servant_fixture_is_present_and_parses() {
    for name in ["bar_impl.ads", "bar_impl.adb"] {
        let path = fixture_root().join(name);
        let source = fs::read_to_string(&path).expect("fixture source is readable");
        ada_parser::reconcile::build_structural_ast(&source, None, &path)
            .unwrap_or_else(|error| panic!("{} parses: {error}", path.display()));
    }
    let spec =
        fs::read_to_string(fixture_root().join("bar_impl.ads")).expect("fixture spec is readable");
    let body =
        fs::read_to_string(fixture_root().join("bar_impl.adb")).expect("fixture body is readable");
    assert!(spec.contains("PortableServer.Servant_Base"));
    assert!(body.contains("CORBA.Object"));
    assert!(fixture_root().join("manifest.toml").is_file());
    assert!(fixture_root().join("README.md").is_file());
}

#[test]
fn fake_corba_generation_writes_exception_package_without_gnat() {
    let temp = temp_dir("m10-generate");
    let work_dir = create_work_dir(&temp);

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "fake-corba",
            work_dir.to_str().expect("work dir path is utf-8"),
        ]),
        0
    );

    assert!(work_dir.join("fake_corba/corba.ads").is_file());
    assert!(work_dir.join("fake_corba/portableserver.ads").is_file());
    assert!(work_dir.join("fake_corba/foo.ads").is_file());
}

#[test]
fn fake_corba_servant_builds_without_real_orb_when_gnat_available() {
    if which::which("gprbuild").is_err() {
        eprintln!("skipping: no gprbuild on PATH");
        return;
    }

    let temp = temp_dir("m10-build");
    let work_dir = create_work_dir(&temp);

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "fake-corba",
            work_dir.to_str().expect("work dir path is utf-8"),
        ]),
        0
    );
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "build",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--harness",
            "H-M10",
        ]),
        0
    );
}

#[test]
fn servant_direct_harness_generates_without_gnat() {
    let temp = temp_dir("m12-servant-direct-generate");
    let (work_dir, main_adb) = generate_servant_direct_harness(&temp);
    let main_text = fs::read_to_string(&main_adb).expect("generated main is readable");

    assert!(work_dir.join("src_instrumented/bar_impl.ads").is_file());
    assert!(work_dir.join("src_instrumented/bar_impl.adb").is_file());
    assert!(work_dir.join("fake_corba/corba.ads").is_file());
    assert!(work_dir.join("fake_corba/portableserver.ads").is_file());
    assert!(main_text.contains("Server : Bar_Impl.Servant;"));
    assert!(main_text.contains("S : String := AdaFuzz.Decode.Ada_String (Cur, 0, 1024);"));
    assert!(main_text.contains("Gf_Result : constant Integer := Bar_Impl.Compute (Server, S);"));
    ada_parser::reconcile::build_structural_ast(&main_text, None, &main_adb)
        .expect("generated servant-direct harness parses");
}

#[test]
fn servant_direct_harness_builds_with_fake_corba_when_gnat_available() {
    if which::which("gprbuild").is_err() {
        eprintln!("skipping: no gprbuild on PATH");
        return;
    }

    let temp = temp_dir("m12-servant-direct-build");
    let (work_dir, _main_adb) = generate_servant_direct_harness(&temp);

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "build",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--harness",
            "H-M12",
        ]),
        0
    );
}

#[test]
fn fake_corba_servant_produces_finding_when_gnat_available() {
    if which::which("gprbuild").is_err() {
        eprintln!("skipping: no gprbuild on PATH");
        return;
    }

    let temp = temp_dir("m12-servant-finding");
    let (work_dir, _main_adb) = generate_servant_direct_harness(&temp);

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "build",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--harness",
            "H-M12",
        ]),
        0
    );

    let input = fake_corba_bad_input_bytes();
    let events_path = temp.join("events.bin");
    run_harness_once(&work_dir, "H-M12", &input, &events_path);

    let events = parse_events(&events_path);
    let testcases = parse_testcases(&events_path);
    assert_eq!(testcases.len(), 1);
    let testcase = &testcases[0];
    assert!(
        testcase.top_level.is_none(),
        "servant handler should catch Foo.BadInput before the harness top-level catch"
    );
    let handler_idx = testcase
        .handlers
        .iter()
        .position(|handler| handler.exception_name.eq_ignore_ascii_case("Foo.BadInput"))
        .expect("Foo.BadInput handler is recorded");

    let mut manager = corpus::CorpusManager::new(temp.clone());
    let records = manager
        .record("H-M12", &input, &events)
        .expect("corpus records servant events");
    assert!(records.iter().any(|record| {
        record.class == corpus::SignatureClass::New
            && record.classification == corpus::Classification::ExplicitRaise
    }));

    let emitter = corpus::FindingEmitter::with_metadata(
        temp.clone(),
        "H-M12".to_owned(),
        "Ada_2005".to_owned(),
        "examples/fake_corba_servant/bar_impl.adb".to_owned(),
    );
    let id = emitter
        .emit(&input, testcase, handler_idx)
        .expect("finding is emitted");
    let finding_dir = temp.join("findings").join(&id.0);
    let finding: serde_json::Value =
        serde_json::from_slice(&fs::read(finding_dir.join("finding.json")).unwrap()).unwrap();

    assert_eq!(finding["classification"], "explicit_raise");
    assert_eq!(finding["harness_id"], "H-M12");
    assert_eq!(
        finding["fixture_path"],
        "examples/fake_corba_servant/bar_impl.adb"
    );
    assert_eq!(
        finding["handler"]["exception_name"]
            .as_str()
            .unwrap()
            .to_ascii_uppercase(),
        "FOO.BADINPUT"
    );
    assert!(finding["raises"].as_array().unwrap().iter().any(|raise| {
        raise["exception_name"]
            .as_str()
            .is_some_and(|name| name.eq_ignore_ascii_case("Foo.BadInput"))
    }));
    assert_eq!(fs::read(finding_dir.join("testcase.bin")).unwrap(), input);
}

#[test]
fn object_ref_harness_generates_without_gnat() {
    let temp = temp_dir("m12-object-ref-generate");
    let (work_dir, main_adb) = generate_object_ref_harness(&temp);
    let main_text = fs::read_to_string(&main_adb).expect("generated main is readable");

    assert!(work_dir.join("src_instrumented/obj_client.ads").is_file());
    assert!(work_dir.join("src_instrumented/obj_client.adb").is_file());
    assert!(work_dir.join("fake_corba/corba-object.ads").is_file());
    assert!(main_text.contains("function Decode_Obj return Corba.Object.Ref is"));
    assert!(main_text.contains("return CORBA.Object.Nil;"));
    assert!(main_text.contains("return CORBA.Object.Fake"));
    ada_parser::reconcile::build_structural_ast(&main_text, None, &main_adb)
        .expect("generated object-ref harness parses");
}

#[test]
fn object_ref_harness_builds_with_fake_corba_when_gnat_available() {
    if which::which("gprbuild").is_err() {
        eprintln!("skipping: no gprbuild on PATH");
        return;
    }

    let temp = temp_dir("m12-object-ref-build");
    let (work_dir, _main_adb) = generate_object_ref_harness(&temp);

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "build",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--harness",
            "H-M12-OBJ",
        ]),
        0
    );
}

#[test]
fn object_ref_mode_harness_generates_without_gnat() {
    let temp = temp_dir("m12-object-ref-modes-generate");
    let (work_dir, main_adb) = generate_object_ref_mode_harness(&temp);
    let main_text = fs::read_to_string(&main_adb).expect("generated main is readable");

    assert!(work_dir.join("src_instrumented/obj_modes.ads").is_file());
    assert!(work_dir.join("src_instrumented/obj_modes.adb").is_file());
    assert!(work_dir.join("fake_corba/corba-object.ads").is_file());
    assert!(main_text.contains("function Decode_Inout_Obj return Corba.Object.Ref is"));
    assert!(main_text.contains("Out_Obj : Corba.Object.Ref := CORBA.Object.Nil;"));
    assert!(main_text.contains("Inout_Obj : Corba.Object.Ref := Decode_Inout_Obj;"));
    assert!(main_text.contains("return CORBA.Object.Fake"));
    ada_parser::reconcile::build_structural_ast(&main_text, None, &main_adb)
        .expect("generated object-ref mode harness parses");
}

#[test]
fn object_ref_mode_harness_builds_with_fake_corba_when_gnat_available() {
    if which::which("gprbuild").is_err() {
        eprintln!("skipping: no gprbuild on PATH");
        return;
    }

    let temp = temp_dir("m12-object-ref-modes-build");
    let (work_dir, _main_adb) = generate_object_ref_mode_harness(&temp);

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "build",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--harness",
            "H-M12-MODES",
        ]),
        0
    );
}

#[test]
fn fake_corba_idl_mapping_builds_when_gnat_available() {
    if which::which("gprbuild").is_err() {
        eprintln!("skipping: no gprbuild on PATH");
        return;
    }

    let temp = temp_dir("m11-idl-build");
    let work_dir = create_idl_mapping_work_dir(&temp);
    let idl_path = temp.join("demo.idl");
    fs::write(
        &idl_path,
        "module Demo {
            typedef sequence<long> Long_List;
            interface Calculator {
                any Echo(in Object Obj, in sequence<long> Values);
            };
        };",
    )
    .expect("IDL source is written");

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "fake-corba",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--idl",
            idl_path.to_str().expect("IDL path is utf-8"),
        ]),
        0
    );
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "build",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--harness",
            "H-IDL",
        ]),
        0
    );
}

#[test]
fn fake_corba_lazy_any_typecode_builds_when_gnat_available() {
    if which::which("gprbuild").is_err() {
        eprintln!("skipping: no gprbuild on PATH");
        return;
    }

    let temp = temp_dir("m11-any-typecode-build");
    let work_dir = create_any_typecode_work_dir(&temp);

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "fake-corba",
            work_dir.to_str().expect("work dir path is utf-8"),
        ]),
        0
    );
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "build",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--harness",
            "H-ANY",
        ]),
        0
    );
}

#[test]
fn fake_corba_typecode_object_reference_builds_when_gnat_available() {
    if which::which("gprbuild").is_err() {
        eprintln!("skipping: no gprbuild on PATH");
        return;
    }

    let temp = temp_dir("m11-typecode-object-build");
    let work_dir = create_typecode_object_work_dir(&temp);

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "fake-corba",
            work_dir.to_str().expect("work dir path is utf-8"),
        ]),
        0
    );
    assert!(work_dir.join("fake_corba/corba-typecode.ads").is_file());
    assert!(!work_dir.join("fake_corba/corba-typecode.adb").is_file());
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "build",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--harness",
            "H-TYPECODE",
        ]),
        0
    );
}

#[test]
fn legacy_idl_acceptance_fixture_is_present_and_generates_mapping() {
    let root = legacy_idl_fixture_root();
    let idl_path = root.join("idl/legacy_system.idl");
    let ast = idl_parser::parse_idl_file(&idl_path)
        .unwrap_or_else(|error| panic!("{} parses: {error}", idl_path.display()));

    assert!(root.join("idl/legacy_common.idl").is_file());
    assert!(root.join("src/legacy_client.ads").is_file());
    assert!(root.join("src/legacy_client.adb").is_file());
    assert!(root.join("manifest.toml").is_file());
    assert!(root.join("README.md").is_file());
    assert!(ast
        .warnings
        .iter()
        .any(|warning| warning.contains("unknown IDL pragma '#pragma vendor legacy-orb keep'")));

    let output = idl_parser::emit_ada_packages(&ast);
    let packages = output
        .units
        .iter()
        .map(|unit| unit.package_name.as_str())
        .collect::<Vec<_>>();

    assert!(packages.contains(&"Legacy.Telemetry.Monitor"));
    assert!(packages.contains(&"Legacy.Telemetry.Monitor.Helper"));
    assert!(packages.contains(&"Legacy.Telemetry.Admin"));
    assert!(packages.contains(&"Legacy.Control.Controller"));
    assert!(packages.contains(&"Sequence_Of_Legacy_Telemetry_Reading_Bound_8"));
    assert!(unit_contents(&output, "Legacy.Telemetry.Monitor").contains(
        "Repository_Id : constant String := \"IDL:legacy.example/Legacy/Telemetry/Monitor:2.4\";"
    ));

    for unit in &output.units {
        ada_parser::reconcile::build_structural_ast(&unit.contents, None, &unit.relative_path)
            .unwrap_or_else(|error| panic!("{} parses: {error}", unit.relative_path.display()));
    }
}

#[test]
fn legacy_idl_acceptance_fixture_builds_when_gnat_available() {
    if which::which("gprbuild").is_err() {
        eprintln!("skipping: no gprbuild on PATH");
        return;
    }

    let temp = temp_dir("m11-legacy-idl-build");
    let work_dir = create_legacy_idl_work_dir(&temp);
    let idl_path = legacy_idl_fixture_root().join("idl/legacy_system.idl");

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "fake-corba",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--idl",
            idl_path.to_str().expect("IDL path is utf-8"),
        ]),
        0
    );
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "build",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--harness",
            "H-LEGACY-IDL",
        ]),
        0
    );
}

#[test]
fn annotated_idl_validation_fixture_parses_and_generates_mapping() {
    let root = annotated_idl_fixture_root();
    let idl_path = root.join("idl/annotated_topic.idl");
    let ast = idl_parser::parse_idl_file(&idl_path)
        .unwrap_or_else(|error| panic!("{} parses: {error}", idl_path.display()));

    assert!(root.join("manifest.toml").is_file());
    assert!(root.join("README.md").is_file());

    let output = idl_parser::emit_ada_packages(&ast);
    assert!(unit_contents(&output, "Validation").contains("type Message is record"));
}

#[test]
fn fake_corba_subcommand_writes_ros_interface_mapping_files() {
    let temp = temp_dir("fake-corba-ros-interface");
    let work_dir = create_work_dir(&temp);
    let msg_path = temp.join("Sample.msg");
    fs::write(
        &msg_path,
        "int32 LIMIT=8\nstring<=32 label\nuint8[4] key\nint32[] values\n",
    )
    .expect("ROS msg source is written");

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "fake-corba",
            work_dir.to_str().expect("work dir path is utf-8"),
            "--ros-interface",
            msg_path.to_str().expect("ROS interface path is utf-8"),
        ]),
        0
    );

    let package = work_dir.join("fake_corba/sample_msgs-msg.ads");
    let sequence = work_dir.join("fake_corba/sequence_of_integer.ads");
    assert!(package.is_file(), "ROS package mapping is written");
    assert!(
        sequence.is_file(),
        "ROS sequence support package is written"
    );
    let contents = fs::read_to_string(&package).expect("ROS package mapping is readable");
    assert!(contents.contains("LIMIT : constant Integer := 8;"));
    assert!(contents.contains("type Sample is record"));
    assert!(contents.contains("label : Standard.String;"));
    assert!(contents.contains("key : CORBA.Octet;"));
    assert!(contents.contains("values : Sequence_Of_Integer.Sequence;"));

    for path in [package, sequence] {
        let source = fs::read_to_string(&path).expect("generated Ada is readable");
        ada_parser::reconcile::build_structural_ast(&source, None, &path)
            .unwrap_or_else(|error| panic!("{} parses: {error}", path.display()));
    }
}

fn create_work_dir(temp: &Path) -> PathBuf {
    let work_dir = temp.join("govfuzz_work");
    let source_dir = work_dir.join("src_instrumented");
    let harness_dir = work_dir.join("generated_harnesses/H-M10");
    fs::create_dir_all(&source_dir).expect("source dir is created");
    fs::create_dir_all(&harness_dir).expect("harness dir is created");
    for name in ["bar_impl.ads", "bar_impl.adb"] {
        fs::copy(fixture_root().join(name), source_dir.join(name))
            .expect("fixture source is copied");
    }
    fs::write(
        harness_dir.join("main.adb"),
        "with Bar_Impl;\nwith CORBA.Object;\nprocedure Main is\n   Server : Bar_Impl.Servant;\n   Ref : CORBA.Object.Ref;\n   Result : Integer;\nbegin\n   Ref := Bar_Impl.Object_Ref;\n   if CORBA.Object.Is_Nil (Ref) then\n      Result := Bar_Impl.Compute (Server, \"neg\");\n   else\n      Result := 1;\n   end if;\n   if Result /= 0 then\n      raise Program_Error;\n   end if;\nend Main;\n",
    )
    .expect("minimal harness is written");
    work_dir
}

fn generate_servant_direct_harness(temp: &Path) -> (PathBuf, PathBuf) {
    let work_dir = temp.join("govfuzz_work");
    let instrumented_dir = work_dir.join("src_instrumented");
    let harness_root = work_dir.join("generated_harnesses");
    let source = fixture_root().join("bar_impl.adb");

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "instrument",
            source.to_str().expect("fixture source path is utf-8"),
            "--output",
            instrumented_dir
                .to_str()
                .expect("instrumented path is utf-8"),
        ]),
        0
    );
    fs::copy(
        fixture_root().join("bar_impl.ads"),
        instrumented_dir.join("bar_impl.ads"),
    )
    .expect("fixture spec is copied");

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "fake-corba",
            work_dir.to_str().expect("work dir path is utf-8"),
        ]),
        0
    );

    let instrumented_source = instrumented_dir.join("bar_impl.adb");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "generate-harness",
            instrumented_source
                .to_str()
                .expect("instrumented source path is utf-8"),
            "--target",
            "Compute",
            "--kind",
            "servant_direct",
            "--output",
            harness_root.to_str().expect("harness root path is utf-8"),
            "--id",
            "H-M12",
        ]),
        0
    );

    (work_dir, harness_root.join("H-M12/main.adb"))
}

fn generate_object_ref_harness(temp: &Path) -> (PathBuf, PathBuf) {
    let work_dir = temp.join("govfuzz_work");
    let source_dir = temp.join("object-ref-src");
    let instrumented_dir = work_dir.join("src_instrumented");
    let harness_root = work_dir.join("generated_harnesses");
    fs::create_dir_all(&source_dir).expect("object-ref source dir is created");
    fs::write(
        source_dir.join("obj_client.ads"),
        "with CORBA.Object;\npackage Obj_Client is\n   procedure Touch (Obj : CORBA.Object.Ref);\nend Obj_Client;\n",
    )
    .expect("object-ref spec is written");
    fs::write(
        source_dir.join("obj_client.adb"),
        "with CORBA.Object;\npackage body Obj_Client is\n   procedure Touch (Obj : CORBA.Object.Ref) is\n   begin\n      if CORBA.Object.Is_Nil (Obj) then\n         null;\n      else\n         null;\n      end if;\n   end Touch;\nend Obj_Client;\n",
    )
    .expect("object-ref body is written");

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "instrument",
            source_dir
                .join("obj_client.adb")
                .to_str()
                .expect("object-ref source path is utf-8"),
            "--output",
            instrumented_dir
                .to_str()
                .expect("instrumented path is utf-8"),
        ]),
        0
    );
    fs::copy(
        source_dir.join("obj_client.ads"),
        instrumented_dir.join("obj_client.ads"),
    )
    .expect("object-ref spec is copied");

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "fake-corba",
            work_dir.to_str().expect("work dir path is utf-8"),
        ]),
        0
    );

    let instrumented_source = instrumented_dir.join("obj_client.adb");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "generate-harness",
            instrumented_source
                .to_str()
                .expect("instrumented source path is utf-8"),
            "--target",
            "Touch",
            "--output",
            harness_root.to_str().expect("harness root path is utf-8"),
            "--id",
            "H-M12-OBJ",
        ]),
        0
    );

    (work_dir, harness_root.join("H-M12-OBJ/main.adb"))
}

fn generate_object_ref_mode_harness(temp: &Path) -> (PathBuf, PathBuf) {
    let work_dir = temp.join("govfuzz_work");
    let source_dir = temp.join("object-ref-modes-src");
    let instrumented_dir = work_dir.join("src_instrumented");
    let harness_root = work_dir.join("generated_harnesses");
    fs::create_dir_all(&source_dir).expect("object-ref mode source dir is created");
    fs::write(
        source_dir.join("obj_modes.ads"),
        "with CORBA.Object;\npackage Obj_Modes is\n   procedure Shuffle (Out_Obj : out CORBA.Object.Ref; Inout_Obj : in out CORBA.Object.Ref);\nend Obj_Modes;\n",
    )
    .expect("object-ref mode spec is written");
    fs::write(
        source_dir.join("obj_modes.adb"),
        "with CORBA.Object;\npackage body Obj_Modes is\n   procedure Shuffle (Out_Obj : out CORBA.Object.Ref; Inout_Obj : in out CORBA.Object.Ref) is\n   begin\n      Out_Obj := CORBA.Object.Fake (11);\n      if CORBA.Object.Is_Nil (Inout_Obj) then\n         Inout_Obj := CORBA.Object.Fake (12);\n      end if;\n   end Shuffle;\nend Obj_Modes;\n",
    )
    .expect("object-ref mode body is written");

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "instrument",
            source_dir
                .join("obj_modes.adb")
                .to_str()
                .expect("object-ref mode source path is utf-8"),
            "--output",
            instrumented_dir
                .to_str()
                .expect("instrumented path is utf-8"),
        ]),
        0
    );
    fs::copy(
        source_dir.join("obj_modes.ads"),
        instrumented_dir.join("obj_modes.ads"),
    )
    .expect("object-ref mode spec is copied");

    assert_eq!(
        cli::run_from([
            "govfuzz",
            "fake-corba",
            work_dir.to_str().expect("work dir path is utf-8"),
        ]),
        0
    );

    let instrumented_source = instrumented_dir.join("obj_modes.adb");
    assert_eq!(
        cli::run_from([
            "govfuzz",
            "generate-harness",
            instrumented_source
                .to_str()
                .expect("instrumented source path is utf-8"),
            "--target",
            "Shuffle",
            "--output",
            harness_root.to_str().expect("harness root path is utf-8"),
            "--id",
            "H-M12-MODES",
        ]),
        0
    );

    (work_dir, harness_root.join("H-M12-MODES/main.adb"))
}

fn create_legacy_idl_work_dir(temp: &Path) -> PathBuf {
    let work_dir = temp.join("govfuzz_work");
    let source_dir = work_dir.join("src_instrumented");
    let harness_dir = work_dir.join("generated_harnesses/H-LEGACY-IDL");
    fs::create_dir_all(&source_dir).expect("source dir is created");
    fs::create_dir_all(&harness_dir).expect("harness dir is created");
    for name in ["legacy_client.ads", "legacy_client.adb"] {
        fs::copy(
            legacy_idl_fixture_root().join("src").join(name),
            source_dir.join(name),
        )
        .expect("legacy fixture source is copied");
    }
    fs::write(
        harness_dir.join("main.adb"),
        "with Legacy_Client;\nprocedure Main is\nbegin\n   Legacy_Client.Touch;\nend Main;\n",
    )
    .expect("legacy IDL harness is written");
    work_dir
}

fn unit_contents<'a>(output: &'a idl_parser::AdaEmitOutput, name: &str) -> &'a str {
    &output
        .units
        .iter()
        .find(|unit| unit.package_name == name)
        .unwrap_or_else(|| panic!("{name} unit is emitted"))
        .contents
}

fn create_idl_mapping_work_dir(temp: &Path) -> PathBuf {
    let work_dir = temp.join("govfuzz_work");
    let source_dir = work_dir.join("src_instrumented");
    let harness_dir = work_dir.join("generated_harnesses/H-IDL");
    fs::create_dir_all(&source_dir).expect("source dir is created");
    fs::create_dir_all(&harness_dir).expect("harness dir is created");
    fs::write(
        source_dir.join("pkg.adb"),
        "procedure Pkg is begin null; end Pkg;\n",
    )
    .expect("minimal Ada source is written");
    fs::write(
        harness_dir.join("main.adb"),
        "with Demo;\nwith Demo.Calculator;\nwith Demo.Calculator.Helper;\nwith Demo.Calculator.Skel;\nwith Demo.Calculator.Stub;\nwith Sequence_Of_Integer;\nprocedure Main is\nbegin\n   null;\nend Main;\n",
    )
    .expect("IDL mapping harness is written");
    work_dir
}

fn create_any_typecode_work_dir(temp: &Path) -> PathBuf {
    let work_dir = temp.join("govfuzz_work");
    let source_dir = work_dir.join("src_instrumented");
    let harness_dir = work_dir.join("generated_harnesses/H-ANY");
    fs::create_dir_all(&source_dir).expect("source dir is created");
    fs::create_dir_all(&harness_dir).expect("harness dir is created");
    fs::write(
        source_dir.join("any_client.ads"),
        "with CORBA.Any;\npackage Any_Client is\n   procedure Touch (A : in out CORBA.Any.Value);\nend Any_Client;\n",
    )
    .expect("Any client spec is written");
    fs::write(
        source_dir.join("any_client.adb"),
        "with CORBA.Any;\nwith CORBA.TypeCode;\npackage body Any_Client is\n   procedure Touch (A : in out CORBA.Any.Value) is\n      TC : CORBA.TypeCode.Object := CORBA.Any.Get_Type (A);\n      Other : CORBA.TypeCode.Object := CORBA.TypeCode.Content_Type (TC);\n      Count : Natural := CORBA.TypeCode.Member_Count (TC) + CORBA.TypeCode.Length (TC);\n      Label : constant Standard.String := CORBA.TypeCode.Name (TC) & CORBA.TypeCode.Id (TC) & CORBA.TypeCode.Member_Name (TC, 0);\n   begin\n      CORBA.Any.Set_Type (A, TC);\n      if CORBA.Any.Equal (A, A)\n         or else CORBA.TypeCode.Equal (TC, Other)\n         or else CORBA.TypeCode.Equivalent (TC, Other)\n      then\n         null;\n      end if;\n      Other := CORBA.TypeCode.Member_Type (TC, Count);\n      if CORBA.TypeCode.Kind (Other) = CORBA.Tk_Null and then Label'Length >= 0 then\n         CORBA.Any.Clear (A);\n      end if;\n   end Touch;\nend Any_Client;\n",
    )
    .expect("Any client body is written");
    fs::write(
        harness_dir.join("main.adb"),
        "with Any_Client;\nwith CORBA.Any;\nprocedure Main is\n   A : CORBA.Any.Value;\nbegin\n   Any_Client.Touch (A);\nend Main;\n",
    )
    .expect("Any client harness is written");
    work_dir
}

fn create_typecode_object_work_dir(temp: &Path) -> PathBuf {
    let work_dir = temp.join("govfuzz_work");
    let source_dir = work_dir.join("src_instrumented");
    let harness_dir = work_dir.join("generated_harnesses/H-TYPECODE");
    fs::create_dir_all(&source_dir).expect("source dir is created");
    fs::create_dir_all(&harness_dir).expect("harness dir is created");
    fs::write(
        source_dir.join("any_client.ads"),
        "with CORBA.Any;\npackage Any_Client is\n   procedure Touch (A : in out CORBA.Any.Value);\nend Any_Client;\n",
    )
    .expect("Any client spec is written");
    fs::write(
        source_dir.join("any_client.adb"),
        "with CORBA.Any;\nwith CORBA.TypeCode;\npackage body Any_Client is\n   procedure Touch (A : in out CORBA.Any.Value) is\n      TC : CORBA.TypeCode.Object := CORBA.Any.Get_Type (A);\n   begin\n      CORBA.Any.Set_Type (A, TC);\n   end Touch;\nend Any_Client;\n",
    )
    .expect("Any client body is written");
    fs::write(
        harness_dir.join("main.adb"),
        "with Any_Client;\nwith CORBA.Any;\nprocedure Main is\n   A : CORBA.Any.Value;\nbegin\n   Any_Client.Touch (A);\nend Main;\n",
    )
    .expect("TypeCode object harness is written");
    work_dir
}

fn find_built_executable(work_dir: &Path, harness_id: &str) -> PathBuf {
    let build_dir = work_dir.join("build").join(harness_id);
    let candidates = [
        build_dir.join("main"),
        build_dir.join("obj").join("main"),
        build_dir.join("obj").join("main.exe"),
    ];

    candidates
        .into_iter()
        .find(|path| path.is_file())
        .unwrap_or_else(|| panic!("built executable not found under {}", build_dir.display()))
}

fn run_harness_once(work_dir: &Path, harness_id: &str, input: &[u8], events_path: &Path) {
    let exe = find_built_executable(work_dir, harness_id);
    let mut child = Command::new(exe)
        .env("GOVFUZZ_EVENTS_PATH", events_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("servant harness starts");
    {
        let mut stdin = child.stdin.take().expect("harness stdin is piped");
        stdin.write_all(input).expect("servant input is written");
    }
    let output = child.wait_with_output().expect("servant harness exits");
    assert!(
        output.status.success(),
        "servant harness failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(events_path.is_file(), "servant event log is written");
}

fn fake_corba_bad_input_bytes() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(1);
    bytes.extend_from_slice(&3_u32.to_le_bytes());
    bytes.extend_from_slice(b"neg");
    bytes
}

fn parse_events(path: &Path) -> Vec<event_log::Event> {
    let bytes = fs::read(path).expect("event log is readable");
    event_log::EventReader::new(bytes.as_slice())
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("events parse")
}

fn parse_testcases(path: &Path) -> Vec<event_log::Testcase> {
    let bytes = fs::read(path).expect("event log is readable");
    event_log::group_into_testcases(event_log::EventReader::new(bytes.as_slice()))
        .expect("testcases parse")
}

fn fixture_root() -> PathBuf {
    repo_root().join("examples/fake_corba_servant")
}

fn legacy_idl_fixture_root() -> PathBuf {
    repo_root().join("examples/legacy_idl_acceptance")
}

fn annotated_idl_fixture_root() -> PathBuf {
    repo_root().join("examples/annotated_idl")
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("cli crate is under crates/cli")
        .to_path_buf()
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-cli-{name}-{nonce}"));
    fs::create_dir_all(&dir).expect("temporary directory is created");
    dir
}
