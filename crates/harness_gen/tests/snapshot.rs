// SPDX-License-Identifier: Apache-2.0

use ada_parser::ast::{
    AdaStandard, Aspects, Constraints, Package, PackageId, ParamMode, Parameter, ScalarKind, Span,
    StructuralAst, Subprogram, SubprogramId, SubprogramKind, SubprogramOwner, TypeId, TypeKind,
    TypeOwner, TypeRef, Unit, UnitId, UnitKind, UnitRef, Visibility,
};
use harness_gen::{
    generate_direct_harness, generate_sequence_harness, generate_servant_direct_harness,
    GenerateDirectArgs, GenerateSequenceArgs, GenerateServantDirectArgs,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("govfuzz-harness-snapshot-{name}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn span() -> Span {
    Span::new(0, 10, 1, 1)
}

fn type_ref(name: &str, kind: TypeKind) -> TypeRef {
    TypeRef {
        id: TypeId(1),
        name_path: name.split('.').map(str::to_owned).collect(),
        visibility: Visibility::Public,
        owner: TypeOwner::LibraryLevel,
        kind,
        constraints: Constraints(String::new()),
        aspects: Aspects(Vec::new()),
    }
}

fn param(name: &str, type_name: &str, kind: TypeKind) -> Parameter {
    param_with_mode(name, type_name, kind, ParamMode::In)
}

fn param_with_mode(name: &str, type_name: &str, kind: TypeKind, mode: ParamMode) -> Parameter {
    Parameter {
        name: name.to_owned(),
        mode,
        type_ref: type_ref(type_name, kind),
        default: None,
    }
}

fn package(id: u32, name: &str) -> Package {
    Package {
        id: PackageId(id),
        name: name.to_owned(),
        parent: None,
        is_generic: false,
        formals: Vec::new(),
        decls: Vec::new(),
        is_private: false,
    }
}

fn subprogram(
    id: u32,
    owner: SubprogramOwner,
    name: &str,
    params: Vec<Parameter>,
    return_type: Option<TypeRef>,
) -> Subprogram {
    Subprogram {
        id: SubprogramId(id),
        owner,
        name: name.to_owned(),
        kind: if return_type.is_some() {
            SubprogramKind::Function
        } else {
            SubprogramKind::Procedure
        },
        params,
        return_type,
        is_abstract: false,
        is_dispatching: false,
        is_overriding: false,
        body_span: Some(span()),
        decl_span: span(),
        handlers: Vec::new(),
        raises: Vec::new(),
        visibility: Visibility::Public,
        is_generic: false,
    }
}

fn ast_with(target: Subprogram, packages: Vec<Package>) -> StructuralAst {
    StructuralAst {
        units: vec![Unit {
            id: UnitId(0),
            path: PathBuf::from("pkg.adb"),
            kind: UnitKind::Body,
            ada_standard: AdaStandard::Ada2012,
            withs: Vec::new(),
            uses: Vec::new(),
            packages: packages.iter().map(|package| package.id).collect(),
            pragmas: Vec::new(),
        }],
        packages,
        subprograms: vec![target],
        ..StructuralAst::new()
    }
}

fn generate_main(ast: &StructuralAst, target: &Subprogram, name: &str) -> PathBuf {
    let output_dir = temp_dir(name).join("H-0042");
    generate_direct_harness(GenerateDirectArgs {
        ast,
        target_subprogram: target,
        harness_id: "H-0042".to_owned(),
        output_dir: output_dir.clone(),
        source_path: PathBuf::from("src/pkg.adb"),
        source_roots: Vec::new(),
        project_imports: Vec::new(),
        generic_instance: None,
        generic_call: None,
        generic_suppress_params: false,
        child_harness_unit: None,
        force: false,
    })
    .unwrap()
    .main_adb
}

fn generate_sequence_main(ast: &StructuralAst, target_package: &Package, name: &str) -> PathBuf {
    let output_dir = temp_dir(name).join("H-M9");
    generate_sequence_harness(GenerateSequenceArgs {
        ast,
        target_package,
        harness_id: "H-M9".to_owned(),
        output_dir: output_dir.clone(),
        source_path: PathBuf::from("src/state.adb"),
        source_roots: Vec::new(),
        project_imports: Vec::new(),
    })
    .unwrap()
    .main_adb
}

fn generate_servant_direct_main(ast: &StructuralAst, target: &Subprogram, name: &str) -> PathBuf {
    let output_dir = temp_dir(name).join("H-M12");
    generate_servant_direct_harness(GenerateServantDirectArgs {
        ast,
        target_subprogram: target,
        harness_id: "H-M12".to_owned(),
        output_dir: output_dir.clone(),
        source_path: PathBuf::from("src/bar_impl.adb"),
        source_roots: Vec::new(),
        project_imports: Vec::new(),
    })
    .unwrap()
    .main_adb
}

fn snapshot_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("snapshots")
        .join(name)
}

fn snapshot_compare(generated_path: &Path, snapshot_name: &str) {
    parse_ada_file(generated_path);
    let generated = fs::read_to_string(generated_path).unwrap();
    let expected_path = snapshot_path(snapshot_name);
    parse_ada_file(&expected_path);
    let expected = fs::read_to_string(expected_path).unwrap();

    assert_eq!(generated, expected);
}

fn parse_ada_file(path: &Path) -> StructuralAst {
    let source = fs::read_to_string(path).unwrap();
    ada_parser::reconcile::build_structural_ast(&source, None, path).unwrap()
}

fn runtime_file(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("ada_runtime")
        .join(name)
}

fn runtime_text(name: &str) -> String {
    fs::read_to_string(runtime_file(name)).unwrap()
}

#[test]
fn snapshot_simple_string_target() {
    let target = subprogram(
        66,
        SubprogramOwner::Package(PackageId(1)),
        "Parse",
        vec![param("S", "String", TypeKind::Unknown)],
        Some(type_ref("Integer", TypeKind::Scalar(ScalarKind::Integer))),
    );
    let ast = ast_with(target.clone(), vec![package(1, "Pkg")]);

    let main_adb = generate_main(&ast, &target, "simple-string");

    snapshot_compare(&main_adb, "simple_string_target.main.adb");
}

#[test]
fn snapshot_integer_param_target() {
    let target = subprogram(
        1,
        SubprogramOwner::LibraryLevel,
        "Run",
        vec![param(
            "Count",
            "Integer",
            TypeKind::Scalar(ScalarKind::Integer),
        )],
        None,
    );
    let ast = ast_with(target.clone(), Vec::new());

    let main_adb = generate_main(&ast, &target, "integer-param");

    snapshot_compare(&main_adb, "integer_param_target.main.adb");
}

#[test]
fn snapshot_multi_param_target() {
    let target = subprogram(
        2,
        SubprogramOwner::Package(PackageId(1)),
        "Mix",
        vec![
            param("I", "Integer", TypeKind::Scalar(ScalarKind::Integer)),
            param("B", "Boolean", TypeKind::Scalar(ScalarKind::Boolean)),
            param("F", "Float", TypeKind::Scalar(ScalarKind::Float)),
            param("S", "String", TypeKind::Unknown),
        ],
        None,
    );
    let ast = ast_with(target.clone(), vec![package(1, "Pkg")]);

    let main_adb = generate_main(&ast, &target, "multi-param");

    snapshot_compare(&main_adb, "multi_param_target.main.adb");
}

#[test]
fn snapshot_enum_param_target() {
    let target = subprogram(
        10,
        SubprogramOwner::LibraryLevel,
        "Paint",
        vec![param(
            "Color",
            "Color",
            TypeKind::Enum(vec![
                "Red".to_owned(),
                "Green".to_owned(),
                "Blue".to_owned(),
            ]),
        )],
        None,
    );
    let ast = ast_with(target.clone(), Vec::new());

    let main_adb = generate_main(&ast, &target, "enum-param");

    snapshot_compare(&main_adb, "enum_param.main.adb");
}

#[test]
fn snapshot_array_param_target() {
    let target = subprogram(
        11,
        SubprogramOwner::LibraryLevel,
        "Load",
        vec![param(
            "Items",
            "Int_Array",
            TypeKind::Array {
                idx_types: vec![TypeId(2)],
                elem_type: TypeId(3),
                bounds: "Positive range <>".to_owned(),
                elem_name: String::new(),
            },
        )],
        None,
    );
    let ast = ast_with(target.clone(), Vec::new());

    let main_adb = generate_main(&ast, &target, "array-param");

    snapshot_compare(&main_adb, "array_param.main.adb");
}

#[test]
fn snapshot_record_param_target() {
    let target = subprogram(
        12,
        SubprogramOwner::LibraryLevel,
        "Store",
        vec![param(
            "R",
            "Root_Record",
            TypeKind::Record(ada_parser::ast::Fields(vec![
                "Count : Integer".to_owned(),
                "Name : String".to_owned(),
            ])),
        )],
        None,
    );
    let ast = ast_with(target.clone(), Vec::new());

    let main_adb = generate_main(&ast, &target, "record-param");

    snapshot_compare(&main_adb, "record_param.main.adb");
}

#[test]
fn snapshot_discriminated_param_target() {
    let target = subprogram(
        13,
        SubprogramOwner::LibraryLevel,
        "Switch",
        vec![param(
            "R",
            "Variant_Record",
            TypeKind::Discriminated {
                base: TypeId(8),
                discriminants: ada_parser::ast::Fields(vec!["Kind : Integer".to_owned()]),
            },
        )],
        None,
    );
    let ast = ast_with(target.clone(), Vec::new());

    let main_adb = generate_main(&ast, &target, "discriminated-param");

    snapshot_compare(&main_adb, "discriminated_param.main.adb");
}

#[test]
fn snapshot_access_param_target() {
    let target = subprogram(
        14,
        SubprogramOwner::LibraryLevel,
        "Process",
        vec![param(
            "Node",
            "Node_Ptr",
            TypeKind::Access { target: TypeId(9) },
        )],
        None,
    );
    let ast = ast_with(target.clone(), Vec::new());

    let main_adb = generate_main(&ast, &target, "access-param");

    snapshot_compare(&main_adb, "access_param.main.adb");
}

#[test]
fn snapshot_object_ref_param_target() {
    let target = subprogram(
        17,
        SubprogramOwner::Package(PackageId(2)),
        "Touch",
        vec![param("Obj", "CORBA.Object.Ref", TypeKind::Unknown)],
        None,
    );
    let mut ast = ast_with(target.clone(), vec![package(2, "Obj_Client")]);
    ast.units[0].withs.push(UnitRef {
        name: "CORBA.Object".to_owned(),
    });

    let main_adb = generate_main(&ast, &target, "object-ref-param");

    snapshot_compare(&main_adb, "object_ref_param.main.adb");
}

#[test]
fn snapshot_direct_param_modes_target() {
    let target = subprogram(
        31,
        SubprogramOwner::Package(PackageId(3)),
        "Shuffle",
        vec![
            param_with_mode(
                "Out_Obj",
                "CORBA.Object.Ref",
                TypeKind::Unknown,
                ParamMode::Out,
            ),
            param_with_mode(
                "Inout_Obj",
                "CORBA.Object.Ref",
                TypeKind::Unknown,
                ParamMode::InOut,
            ),
        ],
        None,
    );
    let mut ast = ast_with(target.clone(), vec![package(3, "Obj_Client")]);
    ast.units[0].withs.push(UnitRef {
        name: "CORBA.Object".to_owned(),
    });

    let main_adb = generate_main(&ast, &target, "direct-param-modes");

    snapshot_compare(&main_adb, "direct_param_modes.main.adb");
}

#[test]
fn snapshot_tagged_param_target() {
    let tagged_type = type_ref(
        "Root_Type",
        TypeKind::Tagged {
            base: TypeId(0),
            is_abstract: false,
        },
    );
    let target = subprogram(
        15,
        SubprogramOwner::LibraryLevel,
        "Handle",
        vec![Parameter {
            name: "Obj".to_owned(),
            mode: ParamMode::In,
            type_ref: tagged_type.clone(),
            default: None,
        }],
        None,
    );
    let constructor = subprogram(
        16,
        SubprogramOwner::LibraryLevel,
        "Make_Root",
        Vec::new(),
        Some(tagged_type),
    );
    let ast = StructuralAst {
        units: vec![Unit {
            id: UnitId(0),
            path: PathBuf::from("pkg.adb"),
            kind: UnitKind::Body,
            ada_standard: AdaStandard::Ada2012,
            withs: Vec::new(),
            uses: Vec::new(),
            packages: Vec::new(),
            pragmas: Vec::new(),
        }],
        subprograms: vec![target.clone(), constructor],
        ..StructuralAst::new()
    };

    let main_adb = generate_main(&ast, &target, "tagged-param");

    snapshot_compare(&main_adb, "tagged_param.main.adb");
}

#[test]
fn snapshot_private_state_sequence_target() {
    let state = package(7, "State");
    let push = subprogram(
        21,
        SubprogramOwner::Package(PackageId(7)),
        "Push",
        vec![param("X", "Integer", TypeKind::Scalar(ScalarKind::Integer))],
        None,
    );
    let pop = subprogram(
        22,
        SubprogramOwner::Package(PackageId(7)),
        "Pop",
        Vec::new(),
        None,
    );
    let top = subprogram(
        23,
        SubprogramOwner::Package(PackageId(7)),
        "Top",
        Vec::new(),
        Some(type_ref("Integer", TypeKind::Scalar(ScalarKind::Integer))),
    );
    let mut ast = ast_with(push, vec![state.clone()]);
    ast.subprograms.push(pop);
    ast.subprograms.push(top);

    let main_adb = generate_sequence_main(&ast, &state, "private-state-sequence");

    snapshot_compare(&main_adb, "private_state_sequence.main.adb");
}

#[test]
fn snapshot_servant_direct_target() {
    let bar_impl = package(12, "Bar_Impl");
    let servant_type = TypeRef {
        id: TypeId(91),
        name_path: vec!["Servant".to_owned()],
        visibility: Visibility::Public,
        owner: TypeOwner::Package(PackageId(12)),
        kind: TypeKind::Tagged {
            base: TypeId(90),
            is_abstract: false,
        },
        constraints: Constraints(String::new()),
        aspects: Aspects(Vec::new()),
    };
    let target = subprogram(
        43,
        SubprogramOwner::Package(PackageId(12)),
        "Compute",
        vec![
            param("Self", "Servant", TypeKind::Unknown),
            param("S", "String", TypeKind::Unknown),
        ],
        Some(type_ref("Integer", TypeKind::Scalar(ScalarKind::Integer))),
    );
    let mut ast = ast_with(target.clone(), vec![bar_impl]);
    ast.types.push(servant_type);

    let main_adb = generate_servant_direct_main(&ast, &target, "servant-direct");

    snapshot_compare(&main_adb, "servant_direct.main.adb");
}

#[test]
fn snapshot_servant_direct_param_modes_target() {
    let bar_impl = package(12, "Bar_Impl");
    let servant_type = TypeRef {
        id: TypeId(91),
        name_path: vec!["Servant".to_owned()],
        visibility: Visibility::Public,
        owner: TypeOwner::Package(PackageId(12)),
        kind: TypeKind::Tagged {
            base: TypeId(90),
            is_abstract: false,
        },
        constraints: Constraints(String::new()),
        aspects: Aspects(Vec::new()),
    };
    let target = subprogram(
        44,
        SubprogramOwner::Package(PackageId(12)),
        "Update",
        vec![
            param_with_mode("Self", "Servant", TypeKind::Unknown, ParamMode::InOut),
            param_with_mode(
                "Out_Count",
                "Integer",
                TypeKind::Scalar(ScalarKind::Integer),
                ParamMode::Out,
            ),
            param_with_mode(
                "Inout_Count",
                "Integer",
                TypeKind::Scalar(ScalarKind::Integer),
                ParamMode::InOut,
            ),
        ],
        None,
    );
    let mut ast = ast_with(target.clone(), vec![bar_impl]);
    ast.types.push(servant_type);

    let main_adb = generate_servant_direct_main(&ast, &target, "servant-direct-param-modes");

    snapshot_compare(&main_adb, "servant_direct_param_modes.main.adb");
}

#[test]
fn generated_harness_for_float_param_includes_explicit_float_conversion() {
    let target = subprogram(
        3,
        SubprogramOwner::LibraryLevel,
        "Run_Float",
        vec![param("F", "Float", TypeKind::Scalar(ScalarKind::Float))],
        None,
    );
    let ast = ast_with(target.clone(), Vec::new());

    let main_adb = generate_main(&ast, &target, "float-param");
    let main_text = fs::read_to_string(&main_adb).unwrap();

    assert!(
        main_text.contains("Float (AdaFuzz.Decode.F64 (Cur))"),
        "expected explicit Float conversion; got:\n{main_text}"
    );
    assert!(
        !main_text.contains(": Float := AdaFuzz.Decode.F64"),
        "expected explicit conversion, found bare F64 assignment"
    );
}

#[test]
fn direct_harness_result_var_does_not_collide_with_a_param_named_r() {
    // adamant `Image_With_Prefix (R : Byte_Array; ...) return String`: the
    // harness named both the decoded param and the function result `R`, so the
    // result decl `R : constant String := Target (R, ...)` self-referenced the
    // result being declared ("object R cannot be used before end of its
    // declaration"). The result must use a collision-proof name.
    let target = subprogram(
        1,
        SubprogramOwner::Package(PackageId(1)),
        "Echo",
        vec![param("R", "Integer", TypeKind::Scalar(ScalarKind::Integer))],
        Some(type_ref("Integer", TypeKind::Scalar(ScalarKind::Integer))),
    );
    let ast = ast_with(target.clone(), vec![package(1, "Pkg")]);

    let main_adb = generate_main(&ast, &target, "result-name-collision");
    let text = fs::read_to_string(&main_adb).unwrap();

    assert!(
        text.contains("Gf_Result : constant"),
        "result must use a collision-proof name: {text}"
    );
    assert!(
        !text.contains("R : constant"),
        "result must not reuse the param name R: {text}"
    );
    // The param R is still passed to the call.
    assert!(
        text.contains("Echo (R)") || text.contains("Echo(R)"),
        "{text}"
    );
    parse_ada_file(&main_adb);
}

#[test]
fn direct_harness_drives_root_stream_type_class_param_with_fuzz_source() {
    // gid's `Load_Image_Header (image : out Image_Descriptor;
    //   from : in out Ada.Streams.Root_Stream_Type'Class; ...)` reads the image
    // from a caller-supplied stream — the fuzz input channel. The harness must
    // back that by-reference class-wide stream with a generated fuzz source
    // stream (Read returns the fuzz bytes) instead of skipping the target.
    let target = subprogram(
        1,
        SubprogramOwner::Package(PackageId(1)),
        "Load_Image_Header",
        vec![param_with_mode(
            "From",
            "Ada.Streams.Root_Stream_Type.Class",
            TypeKind::Unknown,
            ParamMode::InOut,
        )],
        None,
    );
    let ast = ast_with(target.clone(), vec![package(1, "Gid")]);

    let main_adb = generate_main(&ast, &target, "root-stream-source");
    let text = fs::read_to_string(&main_adb).unwrap();

    assert!(text.contains("with Gf_Source_Streams;"), "{text}");
    assert!(
        text.contains("Gf_Source_Streams.Fuzz_Stream"),
        "harness must declare a fuzz source stream: {text}"
    );
    assert!(
        text.contains("Gf_Source_Streams.Set (From, Buf'Unchecked_Access, Last)"),
        "harness must load the source stream from the fuzz input: {text}"
    );

    let dir = main_adb.parent().unwrap();
    assert!(
        dir.join("gf_source_streams.ads").exists() && dir.join("gf_source_streams.adb").exists(),
        "fuzz source-stream package must be emitted beside the harness"
    );
    // The generated harness and the package must be valid Ada.
    parse_ada_file(&main_adb);
}

#[test]
fn direct_harness_constructs_private_type_via_out_param_ctor_with_fuzz_stream() {
    // gid: `Pixel_Width (Image : Image_Descriptor) return Positive` needs an
    // Image_Descriptor — a private type whose only constructor is the out-param
    // procedure `Load_Image_Header (Image : out Image_Descriptor;
    //   From : in out Ada.Streams.Root_Stream_Type'Class)`. The harness must
    // construct it by feeding the fuzz source stream through Load_Image_Header,
    // then call the target — rather than skipping for "no constructor".
    let ctor = subprogram(
        2,
        SubprogramOwner::Package(PackageId(1)),
        "Load_Image_Header",
        vec![
            param_with_mode(
                "Image",
                "Image_Descriptor",
                TypeKind::Private,
                ParamMode::Out,
            ),
            param_with_mode(
                "From",
                "Ada.Streams.Root_Stream_Type.Class",
                TypeKind::Unknown,
                ParamMode::InOut,
            ),
        ],
        None,
    );
    let target = subprogram(
        1,
        SubprogramOwner::Package(PackageId(1)),
        "Pixel_Width",
        vec![param("Image", "Image_Descriptor", TypeKind::Private)],
        Some(type_ref("Positive", TypeKind::Scalar(ScalarKind::Integer))),
    );
    let mut ast = ast_with(target.clone(), vec![package(1, "Gid")]);
    ast.subprograms.push(ctor);

    let main_adb = generate_main(&ast, &target, "private-ctor-stream");
    let text = fs::read_to_string(&main_adb).unwrap();

    assert!(text.contains("with Gf_Source_Streams;"), "{text}");
    assert!(
        text.contains("Gf_Source_Streams.Fuzz_Stream"),
        "constructor's stream arg must be backed by the fuzz source stream: {text}"
    );
    assert!(
        text.contains("Load_Image_Header"),
        "Image_Descriptor must be constructed via the out-param ctor: {text}"
    );
    assert!(
        text.contains("Gf_Source_Streams.Set"),
        "the source stream must be loaded before the ctor call: {text}"
    );
    parse_ada_file(&main_adb);
}

#[test]
fn generated_harness_main_adb_parses_via_ada_parser() {
    let target = subprogram(
        66,
        SubprogramOwner::Package(PackageId(1)),
        "Parse",
        vec![param("S", "String", TypeKind::Unknown)],
        Some(type_ref("Integer", TypeKind::Scalar(ScalarKind::Integer))),
    );
    let ast = ast_with(target.clone(), vec![package(1, "Pkg")]);

    let main_adb = generate_main(&ast, &target, "parse-main");

    parse_ada_file(&main_adb);
}

#[test]
fn ada_runtime_adafuzz_ads_parses() {
    parse_ada_file(&runtime_file("adafuzz.ads"));
}

#[test]
fn adafuzz_gpr_is_well_formed() {
    let gpr = runtime_text("adafuzz.gpr");

    assert!(gpr.contains("for Library_Name use \"adafuzz\";"));
    assert!(gpr.contains("for Library_Kind use \"static\";"));
}

#[test]
fn ada_runtime_adafuzz_input_ads_parses() {
    parse_ada_file(&runtime_file("adafuzz-input.ads"));
}

#[test]
fn ada_runtime_adafuzz_decode_ads_parses() {
    parse_ada_file(&runtime_file("adafuzz-decode.ads"));
}

#[test]
fn adafuzz_decode_ads_with_choose_tag_parses() {
    let text = runtime_text("adafuzz-decode.ads");

    assert!(text.contains("function Choose_Tag"));
    parse_ada_file(&runtime_file("adafuzz-decode.ads"));
}

#[test]
fn adafuzz_decode_adb_with_choose_tag_implementation_parses() {
    let text = runtime_text("adafuzz-decode.adb");

    assert!(text.contains("function Choose_Tag"));
    parse_ada_file(&runtime_file("adafuzz-decode.adb"));
}

#[test]
fn adafuzz_decode_ads_signatures_includes_three_new_functions() {
    let text = runtime_text("adafuzz-decode.ads");

    assert!(text.contains("function Choose_Tag (C : in out Cursor; N : Positive) return Positive;"));
    assert!(text
        .contains("function Slot_Index (C : in out Cursor; Slot_Count : Natural) return Natural;"));
    assert!(text.contains(
        "function Bounded_Length (C : in out Cursor; Min, Max : Natural) return Natural;"
    ));
}

#[test]
fn ada_runtime_adafuzz_probe_ads_parses() {
    parse_ada_file(&runtime_file("adafuzz-probe.ads"));
}

#[test]
fn ada_runtime_adafuzz_input_adb_parses() {
    parse_ada_file(&runtime_file("adafuzz-input.adb"));
}

#[test]
fn ada_runtime_adafuzz_decode_adb_parses() {
    parse_ada_file(&runtime_file("adafuzz-decode.adb"));
}

#[test]
fn ada_runtime_adafuzz_probe_adb_parses() {
    parse_ada_file(&runtime_file("adafuzz-probe.adb"));
}

#[test]
fn ada_runtime_adafuzz_probe_memory_buffer_adb_parses() {
    parse_ada_file(&runtime_file("adafuzz-probe-memory_buffer.adb"));
}

#[test]
fn ada_runtime_adafuzz_probe_semihosting_adb_parses() {
    parse_ada_file(&runtime_file("adafuzz-probe-semihosting.adb"));
}

#[test]
fn ada_runtime_adafuzz_probe_stub_adb_parses() {
    parse_ada_file(&runtime_file("adafuzz-probe-stub.adb"));
}

/// The probe BODY is Ada 2005 and its SPEC is Ada 95, deliberately and for a
/// reason the body's own header states: the spec is `Preelaborate`, and the body
/// declares a private `Stream_IO.File_Type` and `with`s
/// `Ada.Environment_Variables` — which Ada 95 forbids in a preelaborated unit
/// and Ada 2005 permits. `-gnatc` enforces that categorization rule, so calling
/// the body Ada 95 was wrong, not merely unchecked. This test asserted the old
/// claim and had been failing ever since the pragma was corrected; the parser
/// reads `pragma Ada_2005;` off line 10 and is right.
#[test]
fn ada_runtime_adafuzz_probe_body_is_ada2005_while_its_spec_stays_ada95() {
    let body = parse_ada_file(&runtime_file("adafuzz-probe.adb"));
    assert_eq!(body.units[0].ada_standard, AdaStandard::Ada2005);

    // The spec must NOT drift with it: preelaborated user code depends on it.
    let spec = parse_ada_file(&runtime_file("adafuzz-probe.ads"));
    assert_eq!(spec.units[0].ada_standard, AdaStandard::Ada95);
}

#[test]
fn ada_runtime_adafuzz_probe_memory_buffer_adb_uses_ada95() {
    let ast = parse_ada_file(&runtime_file("adafuzz-probe-memory_buffer.adb"));

    assert_eq!(ast.units[0].ada_standard, AdaStandard::Ada95);
}

#[test]
fn ada_runtime_adafuzz_probe_semihosting_adb_uses_ada95() {
    let ast = parse_ada_file(&runtime_file("adafuzz-probe-semihosting.adb"));

    assert_eq!(ast.units[0].ada_standard, AdaStandard::Ada95);
}

#[test]
fn ada_runtime_adafuzz_probe_stub_adb_uses_ada95() {
    let ast = parse_ada_file(&runtime_file("adafuzz-probe-stub.adb"));

    assert_eq!(ast.units[0].ada_standard, AdaStandard::Ada95);
}

#[test]
fn ada_runtime_adafuzz_probe_adb_extracts_package_body() {
    let ast = parse_ada_file(&runtime_file("adafuzz-probe.adb"));

    assert!(!ast.packages.is_empty());
}

#[test]
fn ada_runtime_adafuzz_probe_adb_extracts_runtime_subprograms() {
    let ast = parse_ada_file(&runtime_file("adafuzz-probe.adb"));

    assert!(ast.subprograms.len() >= 10);
}

#[test]
fn ada_runtime_adafuzz_probe_adb_extracts_no_raise_handlers() {
    let ast = parse_ada_file(&runtime_file("adafuzz-probe.adb"));

    assert!(ast.handlers.len() >= 10);
}

#[test]
fn ada_runtime_adafuzz_probe_memory_buffer_exports_drain_symbols_without_host_file_io() {
    let text = runtime_text("adafuzz-probe-memory_buffer.adb");

    assert!(text.contains("adafuzz_probe_memory_buffer"));
    assert!(text.contains("adafuzz_probe_memory_buffer_capacity"));
    assert!(text.contains("adafuzz_probe_memory_buffer_write"));
    assert!(text.contains("adafuzz_probe_memory_buffer_wrapped"));
    assert!(text.contains("pragma Volatile (Memory_Buffer);"));
    assert!(text.contains("pragma Volatile (Memory_Buffer_Capacity_Value);"));
    assert!(text.contains("pragma Volatile (Memory_Buffer_Write);"));
    assert!(text.contains("pragma Volatile (Memory_Buffer_Wrapped);"));
    assert!(!text.contains("Ada.Streams.Stream_IO"));
    assert!(!text.contains("Ada.Environment_Variables"));
}

#[test]
fn ada_runtime_adafuzz_probe_semihosting_imports_runtime_hook_without_host_file_io() {
    let text = runtime_text("adafuzz-probe-semihosting.adb");

    assert!(text.contains("adafuzz_semihosting_write"));
    assert!(text.contains("Semihosting_File_Descriptor"));
    assert!(text.contains("Buffer (Buffer'First)'Address"));
    assert!(!text.contains("Ada.Streams.Stream_IO"));
    assert!(!text.contains("Ada.Environment_Variables"));
}

#[test]
fn ada_runtime_adafuzz_probe_stub_sets_exit_status_without_output_channel() {
    let text = runtime_text("adafuzz-probe-stub.adb");

    assert!(text.contains("Ada.Command_Line.Set_Exit_Status"));
    assert!(text.contains("Exit_Result_Class"));
    assert!(text.contains("procedure On_Top_Level_Catch"));
    assert!(!text.contains("Ada.Streams.Stream_IO"));
    assert!(!text.contains("Ada.Environment_Variables"));
    assert!(!text.contains("adafuzz_semihosting_write"));
    assert!(!text.contains("adafuzz_probe_memory_buffer"));
}

#[test]
fn ada_runtime_adafuzz_probe_gnat_actions_ads_parses() {
    parse_ada_file(&runtime_file("adafuzz-probe-gnat_actions.ads"));
}
