// SPDX-License-Identifier: Apache-2.0

use crate::decoders::select_initializer_for_param;
use crate::registry::{discover_access_lifecycles, discover_constructors, AdaAccessLifecycle};
use crate::stream_init;
use crate::templates;
use crate::HarnessGenError;
use ada_parser::ast::{
    Package, PackageId, ParamMode, Parameter, ScalarKind, StructuralAst, Subprogram, SubprogramId,
    SubprogramKind, SubprogramOwner, TypeKind, TypeOwner, TypeRef, Visibility,
};
use serde::Serialize;
use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone)]
pub struct GenerateDirectArgs<'a> {
    pub ast: &'a ada_parser::ast::StructuralAst,
    pub target_subprogram: &'a ada_parser::ast::Subprogram,
    pub harness_id: String,
    pub output_dir: PathBuf,
    pub source_path: PathBuf,
    pub source_roots: Vec<PathBuf>,
    pub project_imports: Vec<PathBuf>,
    /// When the target lives in a generic package (or is a generic subprogram),
    /// the instantiation to emit before the call, plus the call expression that
    /// reaches the target through the instance.
    pub generic_instance: Option<crate::generic_instance::GenericInstance>,
    pub generic_call: Option<String>,
    /// Call the target with no arguments (a generic subprogram whose own
    /// parameters are all defaulted - the fuzzing happens through the
    /// instantiated callbacks, not the configuration parameters).
    pub generic_suppress_params: bool,
    /// When set, emit the harness as a *private child subprogram* of this name
    /// (e.g. `UnZip.Gf_Harness`) instead of `procedure Main`, plus a matching
    /// `.ads` spec. A private child's body sees the parent's private part, so a
    /// target whose signature uses parent-private types (which a public bridge
    /// cannot re-export) becomes fuzzable. The build picks this file as Main.
    pub child_harness_unit: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GenerateSequenceArgs<'a> {
    pub ast: &'a ada_parser::ast::StructuralAst,
    pub target_package: &'a ada_parser::ast::Package,
    pub harness_id: String,
    pub output_dir: PathBuf,
    pub source_path: PathBuf,
    pub source_roots: Vec<PathBuf>,
    pub project_imports: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct GenerateServantDirectArgs<'a> {
    pub ast: &'a ada_parser::ast::StructuralAst,
    pub target_subprogram: &'a ada_parser::ast::Subprogram,
    pub harness_id: String,
    pub output_dir: PathBuf,
    pub source_path: PathBuf,
    pub source_roots: Vec<PathBuf>,
    pub project_imports: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct GeneratedFiles {
    pub main_adb: PathBuf,
    pub gpr: PathBuf,
    pub harness_id: String,
}

pub fn generate_direct_harness(
    args: GenerateDirectArgs<'_>,
) -> Result<GeneratedFiles, HarnessGenError> {
    if !target_is_in_ast(args.ast, args.target_subprogram) {
        return Err(HarnessGenError::TargetNotFound(
            args.target_subprogram.name.clone(),
        ));
    }

    let context = build_context(&args)?;
    let tera = templates::build_tera()?;
    let main_adb = tera.render("direct_harness", &tera::Context::from_serialize(&context)?)?;
    let gpr = tera.render("harness_gpr", &tera::Context::from_serialize(&context)?)?;

    fs::create_dir_all(&args.output_dir)?;
    // A child-subprogram harness lives in `<parent>-gf_harness.ad{s,b}` (GNAT
    // crunch of `UnZip.Gf_Harness`) with a `private` spec; an ordinary harness
    // is `main.adb` with no spec.
    let main_path = match &args.child_harness_unit {
        Some(unit) => {
            let stem = unit.replace('.', "-").to_ascii_lowercase();
            let spec_path = args.output_dir.join(format!("{stem}.ads"));
            fs::write(
                &spec_path,
                format!("--  SPDX-License-Identifier: Apache-2.0\nprivate procedure {unit};\n"),
            )?;
            args.output_dir.join(format!("{stem}.adb"))
        }
        None => args.output_dir.join("main.adb"),
    };
    let gpr_path = args
        .output_dir
        .join(format!("{}.gpr", context.harness_id_underscore));
    fs::write(&main_path, main_adb)?;
    fs::write(&gpr_path, gpr)?;
    // Emit the discard-stream package beside the harness when a parameter sinks
    // an access-to-stream output. The harness GPR uses Source_Dirs, so these are
    // picked up and compiled automatically.
    if context.needs_stream_sink {
        let (spec, body) = gf_sink_streams_sources();
        fs::write(args.output_dir.join("gf_sink_streams.ads"), spec)?;
        fs::write(args.output_dir.join("gf_sink_streams.adb"), body)?;
    }
    // Emit the fuzz source-stream package when a by-reference
    // `Root_Stream_Type'Class` source parameter is driven from the fuzz input.
    if context.needs_source_stream {
        let (spec, body) = gf_source_streams_sources();
        fs::write(args.output_dir.join("gf_source_streams.ads"), spec)?;
        fs::write(args.output_dir.join("gf_source_streams.adb"), body)?;
    }
    // Emit the callback package when an access-to-subprogram parameter is backed
    // by a generated `Gf_Callbacks` subprogram.
    if context.needs_callbacks {
        let (spec, body) = gf_callbacks_sources();
        fs::write(args.output_dir.join("gf_callbacks.ads"), spec)?;
        fs::write(args.output_dir.join("gf_callbacks.adb"), body)?;
    }

    Ok(GeneratedFiles {
        main_adb: main_path,
        gpr: gpr_path,
        harness_id: args.harness_id,
    })
}

pub fn generate_sequence_harness(
    args: GenerateSequenceArgs<'_>,
) -> Result<GeneratedFiles, HarnessGenError> {
    if !package_is_in_ast(args.ast, args.target_package) {
        return Err(HarnessGenError::TargetNotFound(
            args.target_package.name.clone(),
        ));
    }

    let context = build_sequence_context(&args)?;
    let tera = templates::build_tera()?;
    let main_adb = tera.render(
        "sequence_harness",
        &tera::Context::from_serialize(&context)?,
    )?;
    let gpr = tera.render("harness_gpr", &tera::Context::from_serialize(&context)?)?;

    fs::create_dir_all(&args.output_dir)?;
    let main_path = args.output_dir.join("main.adb");
    let gpr_path = args
        .output_dir
        .join(format!("{}.gpr", context.harness_id_underscore));
    fs::write(&main_path, main_adb)?;
    fs::write(&gpr_path, gpr)?;

    Ok(GeneratedFiles {
        main_adb: main_path,
        gpr: gpr_path,
        harness_id: args.harness_id,
    })
}

pub fn generate_servant_direct_harness(
    args: GenerateServantDirectArgs<'_>,
) -> Result<GeneratedFiles, HarnessGenError> {
    if !target_is_in_ast(args.ast, args.target_subprogram) {
        return Err(HarnessGenError::TargetNotFound(
            args.target_subprogram.name.clone(),
        ));
    }

    let context = build_servant_direct_context(&args)?;
    let tera = templates::build_tera()?;
    let main_adb = tera.render(
        "servant_direct_harness",
        &tera::Context::from_serialize(&context)?,
    )?;
    let gpr = tera.render("harness_gpr", &tera::Context::from_serialize(&context)?)?;

    fs::create_dir_all(&args.output_dir)?;
    let main_path = args.output_dir.join("main.adb");
    let gpr_path = args
        .output_dir
        .join(format!("{}.gpr", context.harness_id_underscore));
    fs::write(&main_path, main_adb)?;
    fs::write(&gpr_path, gpr)?;

    Ok(GeneratedFiles {
        main_adb: main_path,
        gpr: gpr_path,
        harness_id: args.harness_id,
    })
}

#[derive(Debug, Serialize)]
struct TemplateContext {
    harness_id: String,
    harness_id_underscore: String,
    /// The harness subprogram name: `Main` for an ordinary root harness, or a
    /// private child like `UnZip.Gf_Harness`.
    harness_unit: String,
    harness_target_id_hex: String,
    target_unit_withs: Vec<String>,
    params: Vec<ParamContext>,
    return_type_present: bool,
    return_type_ada_name: String,
    qualified_target_name: String,
    ada_runtime_gpr_path: String,
    project_imports: Vec<String>,
    source_dirs: Vec<String>,
    /// `use` clauses (a generic-instance harness `use`s the formal types'
    /// parent so the synthesised stubs and instantiation compile).
    use_units: Vec<String>,
    /// Stub subprogram bodies + the `package/procedure ... is new ...` line for
    /// a generic-instance harness. Empty for an ordinary direct harness.
    generic_stub_decls: Vec<String>,
    generic_instantiation: String,
    /// True when any parameter is a bounded output sink, so the harness must
    /// `with Ada.Unchecked_Deallocation` for the freeing instantiations.
    needs_unchecked_dealloc: bool,
    /// `Gf_Free_<name> (<name>);` statements run once after the input loop ends,
    /// freeing each output-sink backing buffer so LeakSanitizer stays quiet.
    sink_frees: Vec<String>,
    /// True when a parameter is an access-to-stream sink, so the harness `with`s
    /// the generated `Gf_Sink_Streams` package (emitted beside `main.adb`).
    needs_stream_sink: bool,
    /// True when a by-reference `Root_Stream_Type'Class` source parameter is
    /// backed by the generated fuzz source stream, so the harness `with`s the
    /// `Gf_Source_Streams` package (emitted beside `main.adb`).
    needs_source_stream: bool,
    /// True when an access-to-subprogram parameter is backed by a generated
    /// `Gf_Callbacks` subprogram, so the harness `with`s the `Gf_Callbacks`
    /// package (emitted beside `main.adb`) and catches its `GF_Fuzz_EOF`.
    needs_callbacks: bool,
}

#[derive(Debug, Serialize)]
struct SequenceTemplateContext {
    harness_id: String,
    harness_id_underscore: String,
    harness_target_id_hex: String,
    target_unit_withs: Vec<String>,
    max_steps: u32,
    operation_count_minus_one: usize,
    operations: Vec<OperationContext>,
    ada_runtime_gpr_path: String,
    project_imports: Vec<String>,
    source_dirs: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ServantDirectTemplateContext {
    harness_id: String,
    harness_id_underscore: String,
    harness_target_id_hex: String,
    target_unit_withs: Vec<String>,
    servant_type_ada_name: String,
    params: Vec<ParamContext>,
    call_args: Vec<String>,
    return_type_present: bool,
    return_type_ada_name: String,
    qualified_target_name: String,
    ada_runtime_gpr_path: String,
    project_imports: Vec<String>,
    source_dirs: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ParamContext {
    name: String,
    ada_type_name: String,
    decoder_expr: String,
    setup_lines: Vec<String>,
    /// Whether the declaration carries an inline `:= decoder_expr` initializer.
    /// False for limited stateful objects (e.g. an Ada stream) that must be
    /// declared bare and initialised by `pre_call_lines` before the call.
    needs_initializer: bool,
    /// Statements run in the `begin` block before the target call — used to
    /// load a stateful object parameter from the fuzz input.
    pre_call_lines: Vec<String>,
    /// Statements run in the `begin` block AFTER the target call — the cleanup
    /// half of an access-type opaque-handle lifecycle (`Delete (H);`). Skipped on
    /// the exceptional path (the inner handler caught the call), which at worst
    /// leaks one handle for that input.
    #[serde(default)]
    post_call_lines: Vec<String>,
    /// When `Some`, the parameter is declared ONCE at the harness procedure's
    /// outermost declarative part (alongside `Buf`) instead of inside the
    /// per-input `declare` block, and this string is that declaration. Used for
    /// a bounded output sink — a heap-allocated backing buffer for an
    /// access-to-array parameter — so the allocation happens once at startup
    /// rather than leaking on every input under the persistent fork-server.
    #[serde(default)]
    once_decl: Option<String>,
}

#[derive(Debug, Serialize)]
struct OperationContext {
    selector: usize,
    qualified_name: String,
    params: Vec<ParamContext>,
    return_type_present: bool,
    return_type_ada_name: String,
    result_name: String,
}

const MAX_SEQUENCE_STEPS: u32 = 32;

#[derive(Debug, Clone, PartialEq)]
struct OperationSignature {
    kind: SubprogramKind,
    name: String,
    params: Vec<String>,
    return_type: Option<String>,
}

fn target_is_in_ast(ast: &StructuralAst, target: &Subprogram) -> bool {
    ast.subprograms
        .iter()
        .any(|subprogram| subprogram.id == target.id)
}

fn package_is_in_ast(ast: &StructuralAst, target: &Package) -> bool {
    ast.packages.iter().any(|package| package.id == target.id)
}

fn build_context(args: &GenerateDirectArgs<'_>) -> Result<TemplateContext, HarnessGenError> {
    let registry = qualify_constructors_through_instance(args, discover_constructors(args.ast));
    // #457: Init/Delete pairs for access-type opaque handles, so a handle parameter
    // is constructed via its lifecycle (`H := Create; .. ; Destroy (H);`) instead of
    // being passed null.
    let lifecycles = discover_access_lifecycles(args.ast);
    let target_name = display_target_name(args.ast, args.target_subprogram);
    let mut params = Vec::new();
    let mut stream_withs: Vec<String> = Vec::new();
    let mut sink_frees: Vec<String> = Vec::new();
    let mut needs_stream_sink = false;
    let mut needs_source_stream = false;
    let mut needs_callbacks = false;
    let mut callback_set_emitted = false;
    let target_params: &[Parameter] = if args.generic_suppress_params {
        &[]
    } else {
        &args.target_subprogram.params
    };
    for (param_index, param) in target_params.iter().enumerate() {
        let resolved_param = resolve_param_type(args.ast, param);
        let mut resolved_param = qualify_generic_local_param_type(args, resolved_param);
        qualify_local_container_instance_type(
            args.ast,
            args.target_subprogram,
            &mut resolved_param.type_ref,
        );
        // An unsupported anonymous callback may still be optional. When it and
        // every remaining formal have defaults, stop the positional actual list
        // here and let Ada apply those declared defaults. This avoids inventing a
        // callback whose nested parameter types are not visible in the harness
        // (`Reply_Filter : access function (Recipient : Email_Address) ...`).
        // Supported byte-source/sink profiles continue through the active
        // Gf_Callbacks path below.
        let anonymous_callback = resolved_param.type_ref.name_path.is_empty()
            && matches!(resolved_param.type_ref.kind, TypeKind::Access { .. })
            && matches!(
                resolved_param
                    .type_ref
                    .constraints
                    .0
                    .split_whitespace()
                    .next(),
                Some(word) if word.eq_ignore_ascii_case("function")
                    || word.eq_ignore_ascii_case("procedure")
            );
        if anonymous_callback
            && access_to_subprogram_callback(args.ast, &resolved_param.type_ref).is_none()
            && target_params[param_index..]
                .iter()
                .all(|remaining| remaining.default.is_some())
        {
            break;
        }
        // `with` the package that declares this parameter's type. A parameter of
        // a type from another package (e.g. `create_archive`'s `Zip_Streams.
        // Zipstream_Class_Access`) is named qualified in the harness, so that
        // package must be `with`ed or the name is not visible. This is additive:
        // a target that already builds has these packages visible (else it would
        // not compile), so it is a no-op there and only completes a missing
        // `with` on an otherwise-failing target.
        if let Some(with) = param_type_unit_with(args.ast, &resolved_param.type_ref.name_path) {
            if !is_template_provided_with(&with) && !stream_withs.contains(&with) {
                stream_withs.push(with);
            }
        }
        // Known stdlib subtypes (e.g. Ada.Calendar.Year_Number) are not in the
        // parsed AST, so `param_type_unit_with` cannot find their unit — add the
        // `with` explicitly so the fully-qualified decode/neutral compiles.
        if let Some(with) = crate::decoders::known_stdlib_type_with(&resolved_param.type_ref) {
            let with = with.to_owned();
            if !is_template_provided_with(&with) && !stream_withs.contains(&with) {
                stream_withs.push(with);
            }
        }
        // A tagged/private param is built via a constructor whose ARGS may use known
        // stdlib types (zip-ada `Zip_Streams.Calendar.Time_Of` takes
        // `Ada.Calendar.Year_Number` etc.). Those args are emitted fully qualified
        // inside the decode helper, so the harness must `with` their units too.
        let param_type_name = resolved_param.type_ref.name_path.join(".");
        for constructor in registry.for_tagged_type(&param_type_name) {
            for param_type in &constructor.param_type_names {
                if let Some(with) = crate::decoders::known_stdlib_with_for_type_name(param_type) {
                    let with = with.to_owned();
                    if !is_template_provided_with(&with) && !stream_withs.contains(&with) {
                        stream_withs.push(with);
                    }
                }
            }
        }
        // Abstract class-wide "stateful object" parameters (e.g. an Ada stream)
        // cannot be built by the direct decoder, but the source set often
        // provides a concrete derivation plus a byte initialiser. Declare the
        // concrete object and load it from the fuzz input before the call.
        if let Some(root) = stream_init::class_wide_root(&param.type_ref.name_path) {
            if let Some(init) = stream_init::discover_stream_init(args.ast, &root) {
                let name = ada_name(&param.name);
                params.push(ParamContext {
                    pre_call_lines: vec![format!(
                        "{} ({}, {});",
                        init.init_proc, name, init.arg_decoder
                    )],
                    name,
                    ada_type_name: init.concrete_type,
                    decoder_expr: String::new(),
                    setup_lines: Vec::new(),
                    needs_initializer: false,
                    post_call_lines: Vec::new(),
                    once_decl: None,
                });
                for w in init.extra_withs {
                    if !stream_withs.contains(&w) {
                        stream_withs.push(w);
                    }
                }
                continue;
            }
            // A nonabstract class-wide root can itself be the concrete actual.
            // This is the ordinary state-holder case, such as
            // `Argument_Parser'Class`: declare a fresh `Argument_Parser` and pass
            // it to the class-wide formal. Prefer the byte initializer above
            // when one exists because that drives richer stream state.
            if matches!(
                param.mode,
                ParamMode::In | ParamMode::InOut | ParamMode::AccessMode
            ) {
                if let Some(concrete_type) = default_constructible_class_wide_root(args.ast, &root)
                {
                    if let Some(with) = param_type_unit_with(
                        args.ast,
                        &concrete_type
                            .split('.')
                            .map(str::to_owned)
                            .collect::<Vec<_>>(),
                    ) {
                        if !is_template_provided_with(&with) && !stream_withs.contains(&with) {
                            stream_withs.push(with);
                        }
                    }
                    let name = ada_name(&param.name);
                    let (ada_type_name, once_decl) = if matches!(param.mode, ParamMode::AccessMode)
                    {
                        let backing = format!("{name}_Backing");
                        (
                            format!("access {concrete_type}"),
                            Some(format!(
                                "{backing} : aliased {concrete_type};\n   \
                                 {name} : constant access {concrete_type} := {backing}'Access;"
                            )),
                        )
                    } else {
                        (concrete_type, None)
                    };
                    params.push(ParamContext {
                        name,
                        ada_type_name,
                        decoder_expr: String::new(),
                        setup_lines: Vec::new(),
                        needs_initializer: false,
                        pre_call_lines: Vec::new(),
                        post_call_lines: Vec::new(),
                        once_decl,
                    });
                    continue;
                }
            }
            // The STANDARD Ada stream root with no project-provided concrete
            // derivation: a by-reference `in`/`in out Ada.Streams.
            // Root_Stream_Type'Class` source parameter is the fuzz input channel
            // (gid `Load_Image_Header`'s `from`, any `Ada.Streams.Stream_IO`
            // consumer). Back it with the generated fuzz source stream — declare
            // a concrete `Fuzz_Stream` and load it from the input bytes before
            // the call — instead of skipping the target. Access-to-stream
            // parameters are handled later by `stream_sink` (write sinks), so
            // exclude them here.
            if root.eq_ignore_ascii_case("root_stream_type")
                && matches!(param.mode, ParamMode::AccessMode)
            {
                // Anonymous `access Root_Stream_Type'Class` parameters are input
                // streams too (AGPL's filter `Create (Back : access ...)`). Keep
                // one aliased concrete stream for the persistent harness and an
                // anonymous access view whose designated type is the concrete
                // derivation; Ada permits it as the class-wide access actual.
                let name = ada_name(&param.name);
                let backing = format!("{name}_Backing");
                params.push(ParamContext {
                    pre_call_lines: vec![format!(
                        "Gf_Source_Streams.Set ({backing}, Buf'Unchecked_Access, Last);"
                    )],
                    name: name.clone(),
                    ada_type_name: "access Gf_Source_Streams.Fuzz_Stream".to_owned(),
                    decoder_expr: String::new(),
                    setup_lines: Vec::new(),
                    needs_initializer: false,
                    post_call_lines: Vec::new(),
                    once_decl: Some(format!(
                        "{backing} : aliased Gf_Source_Streams.Fuzz_Stream;\n   \
                         {name} : constant access Gf_Source_Streams.Fuzz_Stream := \
                         {backing}'Access;"
                    )),
                });
                needs_source_stream = true;
                continue;
            }
            if root.eq_ignore_ascii_case("root_stream_type")
                && matches!(param.mode, ParamMode::In | ParamMode::InOut)
                && !matches!(resolved_param.type_ref.kind, TypeKind::Access { .. })
                && stream_sink(args.ast, &resolved_param.type_ref).is_none()
            {
                let name = ada_name(&param.name);
                params.push(ParamContext {
                    pre_call_lines: vec![format!(
                        "Gf_Source_Streams.Set ({name}, Buf'Unchecked_Access, Last);"
                    )],
                    name,
                    ada_type_name: "Gf_Source_Streams.Fuzz_Stream".to_owned(),
                    decoder_expr: String::new(),
                    setup_lines: Vec::new(),
                    needs_initializer: false,
                    post_call_lines: Vec::new(),
                    once_decl: None,
                });
                needs_source_stream = true;
                continue;
            }
        }

        // An access-to-array parameter (e.g. zip-ada `output_memory_access : out
        // p_Stream_Element_Array`, where `p_Stream_Element_Array is access
        // Stream_Element_Array`) is otherwise decoded as a bare null pointer, so
        // the callee null-dereferences it the moment it writes a byte
        // (unzip-decompress.adb:351-class artifacts). Give it a real bounded
        // backing buffer instead: allocate it ONCE at the harness procedure level
        // (heap `new`, library-level accessibility, no per-input leak under the
        // persistent fork-server) and pass the access. This removes the null-deref
        // noise and lets the callee's real decode/write path fuzz. A real buffer is
        // strictly safer than null whether the callee reads or writes the pointer.
        if let Some(sink) = access_to_array_sink(args.ast, &resolved_param.type_ref) {
            let name = ada_name(&param.name);
            for with in sink.extra_withs {
                if !stream_withs.contains(&with) {
                    stream_withs.push(with);
                }
            }
            // Allocate the backing buffer once, and pair it with an
            // `Unchecked_Deallocation` instantiation so it is freed when the input
            // loop ends — otherwise LeakSanitizer reports the deliberate fixed
            // allocation as a leak on every process exit, drowning real findings.
            let once_decl = if sink.is_constant {
                // access-to-constant: cannot be freed (Unchecked_Deallocation needs
                // access-to-variable), so allocate the initialized buffer once and
                // leak it (a single fixed allocation, not per input).
                format!(
                    "{name} : {acc} := {alloc};",
                    acc = sink.access_type,
                    name = name,
                    alloc = sink.allocator,
                )
            } else {
                let free_proc = format!("Gf_Free_{name}");
                sink_frees.push(format!("{free_proc} ({name});"));
                format!(
                    "procedure {free} is new Ada.Unchecked_Deallocation\n     ({base}, {acc});\n   \
                     {name} : {acc} := {alloc};",
                    free = free_proc,
                    base = sink.designated_base,
                    acc = sink.access_type,
                    name = name,
                    alloc = sink.allocator,
                )
            };
            params.push(ParamContext {
                post_call_lines: Vec::new(),
                once_decl: Some(once_decl),
                name,
                ada_type_name: sink.access_type,
                decoder_expr: String::new(),
                setup_lines: Vec::new(),
                needs_initializer: false,
                pre_call_lines: Vec::new(),
            });
            continue;
        }

        // An access-to-stream parameter (zip-ada `output_stream_access : access all
        // Root_Stream_Type'Class`, `Z_Stream : Zipstream_Class_Access`) is
        // likewise otherwise null. Back it with a real stream — a generated
        // discard stream for the standard root, or a concrete in-memory
        // derivation for a custom root — so the callee's write path fuzzes
        // instead of null-dereferencing the stream.
        if let Some(sink) = stream_sink(args.ast, &resolved_param.type_ref) {
            let name = ada_name(&param.name);
            for with in sink.extra_withs {
                if !stream_withs.contains(&with) {
                    stream_withs.push(with);
                }
            }
            let free_proc = format!("Gf_Free_{name}");
            let once_decl = format!(
                "procedure {free} is new Ada.Unchecked_Deallocation\n     ({base}, {acc});\n   \
                 {name} : {acc} := {alloc};",
                free = free_proc,
                base = sink.designated_base,
                acc = sink.access_type,
                name = name,
                alloc = sink.allocator,
            );
            sink_frees.push(format!("{free_proc} ({name});"));
            needs_stream_sink = needs_stream_sink || sink.needs_null_stream_pkg;
            params.push(ParamContext {
                post_call_lines: Vec::new(),
                once_decl: Some(once_decl),
                name,
                ada_type_name: sink.access_type,
                decoder_expr: String::new(),
                setup_lines: Vec::new(),
                needs_initializer: false,
                pre_call_lines: Vec::new(),
            });
            continue;
        }

        // An access-to-subprogram parameter (a getchar/putchar-style callback the
        // callee invokes) is otherwise decoded as a bare null and null-called the
        // moment the callee uses it. Back it with a concrete `Gf_Callbacks`
        // subprogram whose `'Access` we pass: a source callback feeds the fuzz
        // bytes (raising `GF_Fuzz_EOF` at end-of-input), a sink callback discards.
        // This lets a callback-driven decoder run its real parse loop on the fuzz
        // input instead of crashing on the null callback.
        if let Some(cb) = access_to_subprogram_callback(args.ast, &resolved_param.type_ref) {
            let name = ada_name(&param.name);
            // Install the fuzz input as the callbacks' byte source once per
            // testcase, before the call. `Set` resets the cursor, so emit it on
            // the first callback parameter only — additional source callbacks
            // then share the one advancing cursor.
            let pre_call_lines = if callback_set_emitted {
                Vec::new()
            } else {
                callback_set_emitted = true;
                vec!["Gf_Callbacks.Set (Buf'Unchecked_Access, Last);".to_owned()]
            };
            params.push(ParamContext {
                name,
                ada_type_name: cb.decl_type,
                decoder_expr: cb.access_expr,
                setup_lines: Vec::new(),
                needs_initializer: true,
                pre_call_lines,
                post_call_lines: Vec::new(),
                once_decl: None,
            });
            needs_callbacks = true;
            continue;
        }

        // An anonymous access formal designating a definite tagged object needs
        // an access value, not the object value itself. Back it with one aliased,
        // default-initialized concrete object (`not null access
        // Validating_Reader`) so legacy APIs that use anonymous access as a
        // non-owning receiver can be called without a factory.
        if matches!(param.mode, ParamMode::AccessMode)
            && matches!(
                resolved_param.type_ref.kind,
                TypeKind::Tagged {
                    is_abstract: false,
                    ..
                }
            )
        {
            let name = ada_name(&param.name);
            let backing = format!("{name}_Backing");
            let concrete = ada_type_name(&resolved_param.type_ref);
            params.push(ParamContext {
                name: name.clone(),
                ada_type_name: format!("access {concrete}"),
                decoder_expr: String::new(),
                setup_lines: Vec::new(),
                needs_initializer: false,
                pre_call_lines: Vec::new(),
                post_call_lines: Vec::new(),
                once_decl: Some(format!(
                    "{backing} : aliased {concrete};\n   \
                     {name} : constant access {concrete} := {backing}'Access;"
                )),
            });
            continue;
        }

        // #457: an access-type opaque-handle parameter whose type has a discovered
        // Init/Delete lifecycle. Build the handle through its constructor and tear it
        // down after the call (`H := Create; target (H, ..); Destroy (H);`) instead
        // of passing a bare null the callee dereferences. Only an INPUT handle (`in`
        // / anonymous `access`) qualifies — an `in out`/`out` handle the callee
        // itself replaces is left to the bare-declarable receiver path so the
        // cleanup never double-frees a handle the callee already took ownership of.
        if matches!(param.mode, ParamMode::In | ParamMode::AccessMode) {
            if let Some(sink) =
                access_lifecycle_sink(args.ast, &resolved_param.type_ref, &lifecycles)
            {
                let name = ada_name(&param.name);
                for with in sink.extra_withs {
                    if !is_template_provided_with(&with) && !stream_withs.contains(&with) {
                        stream_withs.push(with);
                    }
                }
                let init_stmt = sink.init_stmt.replace("{handle}", &name);
                let post_call_lines = sink
                    .delete_stmt
                    .map(|d| vec![d.replace("{handle}", &name)])
                    .unwrap_or_default();
                params.push(ParamContext {
                    name,
                    ada_type_name: sink.access_type,
                    decoder_expr: String::new(),
                    setup_lines: Vec::new(),
                    needs_initializer: false,
                    pre_call_lines: vec![init_stmt],
                    post_call_lines,
                    once_decl: None,
                });
                continue;
            }
        }

        let decoder = match select_initializer_for_param(args.ast, &resolved_param, &registry) {
            Ok(decoder) => decoder,
            Err(error) => {
                // Ada permits a trailing suffix of defaulted formals to be
                // omitted. If the first unsupported value starts such a suffix,
                // stop emitting positional actuals and let the declaration's
                // defaults supply it. This is exact language behavior, not a
                // guessed neutral, and is especially common in old APIs with a
                // long tail of configuration handles and callbacks.
                if target_params[param_index..]
                    .iter()
                    .all(|remaining| remaining.default.is_some())
                {
                    break;
                }
                // The direct decoder cannot build this parameter from scratch
                // (a private/limited stateful type with no constructor
                // function). Before giving up, look for an out-parameter
                // "constructor" procedure - the canonical Ada idiom for
                // initialising such a type (e.g. `Zip.Load (Info : out
                // Zip_Info; ...)`). If found, declare the object bare and fill
                // it from the fuzz input before the call.
                let name = ada_name(&param.name);
                if let Some(ctor) = discover_out_param_constructor(
                    args.ast,
                    &registry,
                    args.target_subprogram.id,
                    &resolved_param.type_ref,
                    &name,
                ) {
                    for with in ctor.extra_withs {
                        if !stream_withs.contains(&with) {
                            stream_withs.push(with);
                        }
                    }
                    needs_stream_sink = needs_stream_sink || ctor.needs_stream_sink;
                    needs_source_stream = needs_source_stream || ctor.needs_source_stream;
                    for free in &ctor.arg_frees {
                        sink_frees.push(free.clone());
                    }
                    // When the constructor needs backing streams, declare them
                    // (and the receiver) once at procedure level so the `new`
                    // allocations are not repeated per input; otherwise keep the
                    // receiver as a bare per-input declaration (existing path).
                    let once_decl = if ctor.arg_decls.is_empty() {
                        None
                    } else {
                        let mut decls = vec![format!("{name} : {};", ctor.receiver_type)];
                        decls.extend(ctor.arg_decls.iter().cloned());
                        Some(decls.join("\n   "))
                    };
                    // Per-input statements that load any fuzz source-stream
                    // argument run before the constructor call.
                    let mut pre_call_lines = ctor.setup_lines;
                    pre_call_lines.push(ctor.init_call);
                    params.push(ParamContext {
                        name,
                        ada_type_name: ctor.receiver_type,
                        decoder_expr: String::new(),
                        setup_lines: Vec::new(),
                        needs_initializer: false,
                        pre_call_lines,
                        post_call_lines: Vec::new(),
                        once_decl,
                    });
                    continue;
                }
                // A receiver parameter the callee itself constructs: declare it
                // bare and let the call fill it. For a pure `out` parameter
                // (e.g. `LZMA.Decoding.Decode (info : out LZMA_Decoder_Info)`)
                // this is always sound — an `out` formal does not read the
                // initial value, and GNAT default-initializes any definite type.
                // For `in`/`in out`, a nonabstract tagged type is also useful
                // without a factory: Ada default-initializes a definite tagged
                // object, including the common `Limited_Controlled with private`
                // state-holder idiom (parse_args' `Argument_Parser`). This gives
                // mutators a valid fresh receiver instead of rejecting every
                // operation in the package. Keep an opaque non-tagged private
                // type conservative because it may have unknown discriminants.
                // Abstract tagged types are excluded because declaring an object
                // of one is illegal.
                let receiver_kind_ok = matches!(
                    resolved_param.type_ref.kind,
                    TypeKind::Private
                        | TypeKind::Tagged {
                            is_abstract: false,
                            ..
                        }
                        | TypeKind::Access { .. }
                );
                let generic_instance = {
                    let parts = split_name_path(&resolved_param.type_ref.name_path);
                    parts.len() >= 2
                        && parts
                            .last()
                            .is_some_and(|leaf| leaf.eq_ignore_ascii_case("instance"))
                };
                let bare_declarable = match param.mode {
                    ParamMode::Out => receiver_kind_ok || generic_instance,
                    // A tagged declaration performs its language-defined default
                    // initialization; an access type has the defined null default.
                    ParamMode::In | ParamMode::InOut => {
                        matches!(resolved_param.type_ref.kind, TypeKind::Access { .. })
                            || matches!(
                                resolved_param.type_ref.kind,
                                TypeKind::Tagged {
                                    is_abstract: false,
                                    ..
                                }
                            ) && find_declared_type(args.ast, &resolved_param.type_ref).is_some()
                            || (matches!(resolved_param.type_ref.kind, TypeKind::Private)
                                && is_constructor_like_name(&args.target_subprogram.name))
                            || generic_instance
                    }
                    _ => false,
                };
                if bare_declarable {
                    params.push(ParamContext {
                        name,
                        ada_type_name: aliased_local_type(
                            param,
                            ada_type_name(&resolved_param.type_ref),
                        ),
                        decoder_expr: String::new(),
                        setup_lines: Vec::new(),
                        needs_initializer: false,
                        pre_call_lines: Vec::new(),
                        post_call_lines: Vec::new(),
                        once_decl: None,
                    });
                    continue;
                }
                return Err(contextualize_initializer_error(
                    "direct-call",
                    &target_name,
                    param,
                    &resolved_param,
                    error,
                ));
            }
        };
        let uses_callbacks = decoder.call_expr.contains("Gf_Callbacks.")
            || decoder
                .setup_lines
                .iter()
                .any(|line| line.contains("Gf_Callbacks."));
        let pre_call_lines = if uses_callbacks && !callback_set_emitted {
            callback_set_emitted = true;
            vec!["Gf_Callbacks.Set (Buf'Unchecked_Access, Last);".to_owned()]
        } else {
            Vec::new()
        };
        needs_callbacks = needs_callbacks || uses_callbacks;
        params.push(ParamContext {
            name: ada_name(&param.name),
            ada_type_name: aliased_local_type(param, ada_type_name(&resolved_param.type_ref)),
            decoder_expr: decoder.call_expr,
            setup_lines: decoder.setup_lines,
            needs_initializer: true,
            pre_call_lines,
            post_call_lines: Vec::new(),
            once_decl: None,
        });
    }

    let return_type_ada_name = args
        .target_subprogram
        .return_type
        .as_ref()
        .map(|type_ref| generic_qualified_return_type_name(args, type_ref))
        .unwrap_or_default();

    let mut target_unit_withs = target_unit_withs(args.ast, args.target_subprogram)?;
    for w in stream_withs {
        if !target_unit_withs.contains(&w) {
            target_unit_withs.push(w);
        }
    }
    // A standard-library type named in a parameter or the return type needs its
    // parent unit `with`ed (`Ada.Strings.Unbounded.Unbounded_String` ->
    // `with Ada.Strings.Unbounded;`). The template already provides Ada.Streams /
    // Interfaces; everything else must be added or the harness won't compile.
    for type_name in params
        .iter()
        .map(|p| p.ada_type_name.as_str())
        .chain(std::iter::once(return_type_ada_name.as_str()))
    {
        if let Some(unit) = standard_library_parent_unit(type_name) {
            if !is_template_provided_with(&unit)
                && !target_unit_withs
                    .iter()
                    .any(|w| w.eq_ignore_ascii_case(&unit))
            {
                target_unit_withs.push(unit);
            }
        }
    }

    // Generic-instance fields: when the target is reached through a synthesised
    // generic instantiation, emit the stub bodies + the `is new ...` line, call
    // through the instance, and `use` the formal types' parent package.
    let mut use_units = Vec::new();
    let (generic_stub_decls, generic_instantiation, qualified_target_name) =
        if let Some(instance) = &args.generic_instance {
            for with in &instance.extra_withs {
                if !target_unit_withs.contains(with) {
                    target_unit_withs.push(with.clone());
                }
                use_units.push(with.clone());
            }
            (
                instance.stub_decls.clone(),
                instance.instantiation.clone(),
                args.generic_call.clone().unwrap_or_default(),
            )
        } else {
            (
                Vec::new(),
                String::new(),
                qualified_target_name(args.ast, args.target_subprogram)?,
            )
        };

    Ok(TemplateContext {
        harness_id: args.harness_id.clone(),
        harness_id_underscore: harness_project_name(&args.harness_id),
        harness_unit: args
            .child_harness_unit
            .clone()
            .unwrap_or_else(|| "Main".to_owned()),
        harness_target_id_hex: target_id_hex(args.target_subprogram),
        target_unit_withs,
        params,
        return_type_present: args.target_subprogram.return_type.is_some(),
        return_type_ada_name,
        qualified_target_name,
        ada_runtime_gpr_path: ada_runtime_gpr_path(&args.output_dir)?,
        project_imports: project_import_paths(&args.output_dir, &args.project_imports)?,
        source_dirs: project_source_dirs(
            &args.source_path,
            &args.source_roots,
            args.project_imports.is_empty(),
        )?,
        use_units,
        generic_stub_decls,
        generic_instantiation,
        needs_unchecked_dealloc: !sink_frees.is_empty(),
        sink_frees,
        needs_stream_sink,
        needs_source_stream,
        needs_callbacks,
    })
}

/// Return the qualified declaration name for a public, nonabstract tagged root
/// that can be used as the concrete actual for `<Root>'Class`.
fn default_constructible_class_wide_root(ast: &StructuralAst, root: &str) -> Option<String> {
    let ty = ast.types.iter().find(|ty| {
        ty.visibility == Visibility::Public
            && ty
                .name_path
                .last()
                .is_some_and(|name| name.trim_matches('.').eq_ignore_ascii_case(root))
            && matches!(
                ty.kind,
                TypeKind::Tagged {
                    is_abstract: false,
                    ..
                }
            )
    })?;
    Some(ada_path(&qualified_type_name_path(ast, ty)))
}

fn build_sequence_context(
    args: &GenerateSequenceArgs<'_>,
) -> Result<SequenceTemplateContext, HarnessGenError> {
    let operations = sequence_operations(args.ast, args.target_package);
    if operations.is_empty() {
        return Err(HarnessGenError::TargetNotFound(format!(
            "{} sequence operations",
            args.target_package.name
        )));
    }

    let registry = discover_constructors(args.ast);
    let package_name = ada_dotted_name(&args.target_package.name);
    let operations = operations
        .into_iter()
        .enumerate()
        .map(|(selector, operation)| {
            let operation_name = format!("{}.{}", package_name, ada_name(&operation.name));
            let params = operation
                .params
                .iter()
                .map(|param| {
                    let resolved_param = resolve_param_type(args.ast, param);
                    let decoder =
                        select_initializer_for_param(args.ast, &resolved_param, &registry)
                            .map_err(|error| {
                                contextualize_initializer_error(
                                    "sequence",
                                    &operation_name,
                                    param,
                                    &resolved_param,
                                    error,
                                )
                            })?;
                    Ok(ParamContext {
                        name: ada_name(&param.name),
                        ada_type_name: ada_type_name(&resolved_param.type_ref),
                        decoder_expr: decoder.call_expr,
                        setup_lines: decoder.setup_lines,
                        needs_initializer: true,
                        pre_call_lines: Vec::new(),
                        post_call_lines: Vec::new(),
                        once_decl: None,
                    })
                })
                .collect::<Result<Vec<_>, HarnessGenError>>()?;

            let return_type_ada_name = operation
                .return_type
                .as_ref()
                .map(|type_ref| resolved_type_name(args.ast, type_ref))
                .unwrap_or_default();

            Ok(OperationContext {
                selector,
                qualified_name: operation_name,
                params,
                return_type_present: operation.return_type.is_some(),
                return_type_ada_name,
                result_name: format!("R_{}", ada_name(&operation.name)),
            })
        })
        .collect::<Result<Vec<_>, HarnessGenError>>()?;

    Ok(SequenceTemplateContext {
        harness_id: args.harness_id.clone(),
        harness_id_underscore: harness_project_name(&args.harness_id),
        harness_target_id_hex: package_id_hex(args.target_package),
        target_unit_withs: package_unit_withs(args.ast, args.target_package),
        max_steps: MAX_SEQUENCE_STEPS,
        operation_count_minus_one: operations.len() - 1,
        operations,
        ada_runtime_gpr_path: ada_runtime_gpr_path(&args.output_dir)?,
        project_imports: project_import_paths(&args.output_dir, &args.project_imports)?,
        source_dirs: project_source_dirs(
            &args.source_path,
            &args.source_roots,
            args.project_imports.is_empty(),
        )?,
    })
}

fn build_servant_direct_context(
    args: &GenerateServantDirectArgs<'_>,
) -> Result<ServantDirectTemplateContext, HarnessGenError> {
    let Some(receiver) = args.target_subprogram.params.first() else {
        return Err(HarnessGenError::UnsupportedParamType(
            "servant_direct requires a first Servant receiver parameter".to_owned(),
        ));
    };

    if !matches!(receiver.mode, ParamMode::In | ParamMode::InOut) {
        return Err(HarnessGenError::UnsupportedParamType(format!(
            "servant receiver '{}' must be an in or in out parameter",
            receiver.name
        )));
    }

    let receiver = resolve_param_type(args.ast, receiver);
    let servant_type_ada_name =
        servant_receiver_type_name(args.ast, args.target_subprogram, &receiver)?;
    if !servant_type_ada_name
        .split('.')
        .next_back()
        .is_some_and(|name| name.to_ascii_lowercase().ends_with("servant"))
    {
        return Err(HarnessGenError::UnsupportedParamType(format!(
            "{servant_type_ada_name} is not a servant receiver type"
        )));
    }

    let registry = discover_constructors(args.ast);
    let target_name = display_target_name(args.ast, args.target_subprogram);
    let params = args
        .target_subprogram
        .params
        .iter()
        .skip(1)
        .map(|param| {
            let resolved_param = resolve_param_type(args.ast, param);
            let decoder = select_initializer_for_param(args.ast, &resolved_param, &registry)
                .map_err(|error| {
                    contextualize_initializer_error(
                        "servant-direct",
                        &target_name,
                        param,
                        &resolved_param,
                        error,
                    )
                })?;
            Ok(ParamContext {
                name: ada_name(&param.name),
                ada_type_name: ada_type_name(&resolved_param.type_ref),
                decoder_expr: decoder.call_expr,
                setup_lines: decoder.setup_lines,
                needs_initializer: true,
                pre_call_lines: Vec::new(),
                post_call_lines: Vec::new(),
                once_decl: None,
            })
        })
        .collect::<Result<Vec<_>, HarnessGenError>>()?;

    let return_type_ada_name = args
        .target_subprogram
        .return_type
        .as_ref()
        .map(|type_ref| resolved_type_name(args.ast, type_ref))
        .unwrap_or_default();

    let mut call_args = vec!["Server".to_owned()];
    call_args.extend(params.iter().map(|param| param.name.clone()));

    Ok(ServantDirectTemplateContext {
        harness_id: args.harness_id.clone(),
        harness_id_underscore: harness_project_name(&args.harness_id),
        harness_target_id_hex: target_id_hex(args.target_subprogram),
        target_unit_withs: target_unit_withs(args.ast, args.target_subprogram)?,
        servant_type_ada_name,
        params,
        call_args,
        return_type_present: args.target_subprogram.return_type.is_some(),
        return_type_ada_name,
        qualified_target_name: qualified_target_name(args.ast, args.target_subprogram)?,
        ada_runtime_gpr_path: ada_runtime_gpr_path(&args.output_dir)?,
        project_imports: project_import_paths(&args.output_dir, &args.project_imports)?,
        source_dirs: project_source_dirs(
            &args.source_path,
            &args.source_roots,
            args.project_imports.is_empty(),
        )?,
    })
}

fn contextualize_initializer_error(
    harness_kind: &str,
    target_name: &str,
    param: &Parameter,
    resolved_param: &Parameter,
    error: HarnessGenError,
) -> HarnessGenError {
    let HarnessGenError::UnsupportedParamType(reason) = error else {
        return error;
    };

    let type_name = ada_type_name(&resolved_param.type_ref);
    HarnessGenError::UnsupportedParamType(format!(
        "{harness_kind} harness cannot initialize parameter '{}' of target '{}' with type '{}': {reason}. Add a public constructor function returning '{type_name}' to the parsed source set, include the needed source roots/project dependencies, or use a sequence or servant harness when the call requires existing state.",
        ada_name(&param.name),
        target_name,
        type_name
    ))
}

fn sequence_operations<'a>(ast: &'a StructuralAst, package: &Package) -> Vec<&'a Subprogram> {
    let public_signatures = public_operation_signatures(ast, package);
    let mut operations = ast
        .subprograms
        .iter()
        .filter(|subprogram| subprogram.owner == SubprogramOwner::Package(package.id))
        .filter(|subprogram| is_sequence_operation_kind(subprogram))
        .filter(|subprogram| !subprogram.is_abstract)
        .filter(|subprogram| subprogram.body_span.is_some())
        .filter(|subprogram| {
            subprogram.visibility == Visibility::Public
                || public_signatures
                    .iter()
                    .any(|signature| *signature == operation_signature(subprogram))
        })
        .collect::<Vec<_>>();
    operations.sort_by_key(|subprogram| subprogram.id.0);
    operations
}

fn public_operation_signatures(ast: &StructuralAst, package: &Package) -> Vec<OperationSignature> {
    ast.subprograms
        .iter()
        .filter(|subprogram| subprogram.owner == SubprogramOwner::Package(package.id))
        .filter(|subprogram| subprogram.visibility == Visibility::Public)
        .filter(|subprogram| is_sequence_operation_kind(subprogram))
        .map(operation_signature)
        .collect()
}

fn is_sequence_operation_kind(subprogram: &Subprogram) -> bool {
    matches!(
        subprogram.kind,
        SubprogramKind::Procedure | SubprogramKind::Function
    )
}

fn operation_signature(subprogram: &Subprogram) -> OperationSignature {
    OperationSignature {
        kind: subprogram.kind.clone(),
        name: subprogram.name.to_ascii_lowercase(),
        params: subprogram
            .params
            .iter()
            .map(|param| type_signature_name(&param.type_ref))
            .collect(),
        return_type: subprogram.return_type.as_ref().map(type_signature_name),
    }
}

fn type_signature_name(type_ref: &TypeRef) -> String {
    if type_ref.name_path.is_empty() {
        return format!("{:?}", type_ref.kind).to_ascii_lowercase();
    }

    type_path_parts(type_ref)
        .into_iter()
        .map(|name| name.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(".")
}

/// Whether a procedure name reads like a constructor/initialiser rather than a
/// mutator. Used to gate `in out`-receiver initialisers (`Open`, `Create`,
/// ...), which would otherwise also match state-requiring mutators.
fn is_constructor_like_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    const VERBS: &[&str] = &[
        "create",
        "open",
        "load",
        "init",
        "initialize",
        "make",
        "new",
        "build",
        "setup",
    ];
    VERBS
        .iter()
        .any(|verb| name == *verb || name.starts_with(&format!("{verb}_")))
}

/// How to construct a stateful parameter via an out-parameter procedure.
struct OutParamConstructor {
    /// Qualified concrete type to declare for the receiver object.
    receiver_type: String,
    /// Full `Init (Obj, decoded_args ...);` statement to run before the call.
    init_call: String,
    /// Units the harness must `with` to compile the initialisation.
    extra_withs: Vec<String>,
    /// Procedure-level declarations for any stream arguments the constructor
    /// needs (a backing in-memory stream + its `Unchecked_Deallocation`), e.g.
    /// the `Z_Stream` of `Zip.Create.Create_Archive`. Empty for the common case.
    arg_decls: Vec<String>,
    /// `Gf_Free_<n> (<n>);` statements freeing those backing streams after the
    /// input loop (kept quiet for LeakSanitizer).
    arg_frees: Vec<String>,
    /// Per-input statements run before `init_call` — loading a fuzz source
    /// stream argument from the input bytes (`Gf_Source_Streams.Set (...)`).
    setup_lines: Vec<String>,
    /// True when a stream argument used the generated `Gf_Sink_Streams` package.
    needs_stream_sink: bool,
    /// True when a by-reference `Root_Stream_Type'Class` argument is backed by
    /// the generated `Gf_Source_Streams` fuzz source stream.
    needs_source_stream: bool,
}

/// Discover an out-parameter "constructor" for a stateful type the direct
/// decoder cannot build from scratch: a public procedure that takes the target
/// type as an `out` parameter (the canonical Ada idiom for initialising a
/// private or limited type, e.g. `Zip.Load (Info : out Zip_Info; ...)`), with
/// every other parameter an `in` value the decoder can synthesise. An `out`
/// (not `in out`) receiver is required: it signals a true constructor that
/// produces the value from nothing, rather than a mutator that reads existing
/// state.
fn discover_out_param_constructor(
    ast: &StructuralAst,
    registry: &crate::registry::ConstructorRegistry,
    target_id: SubprogramId,
    target_type: &TypeRef,
    obj_name: &str,
) -> Option<OutParamConstructor> {
    // The harness declares a bare object of this type for the initialiser to
    // fill, so the type must be concrete and definite. Abstract tagged types,
    // interfaces, and class-wide references (`Root_Zipstream_Type'Class`)
    // cannot be declared directly - those abstract stateful roots are the job
    // of stream_init, or stay skipped.
    if stream_init::class_wide_root(&target_type.name_path).is_some() {
        return None;
    }
    if !matches!(
        &target_type.kind,
        TypeKind::Private
            | TypeKind::Tagged {
                is_abstract: false,
                ..
            }
    ) {
        return None;
    }

    let target_type_name = resolved_type_name(ast, target_type);
    for sp in &ast.subprograms {
        if sp.id == target_id {
            // The target under test is never its own constructor.
            continue;
        }
        if sp.kind != SubprogramKind::Procedure || sp.visibility != Visibility::Public {
            continue;
        }
        let Some(receiver_index) = sp.params.iter().position(|param| {
            matches!(param.mode, ParamMode::Out | ParamMode::InOut)
                && out_param_receiver_matches(ast, sp, param, &target_type_name)
        }) else {
            continue;
        };
        // An `out` receiver is an unambiguous constructor (it produces the
        // value from nothing). An `in out` receiver is the idiom for limited
        // stream types (`Open`/`Create`), but it is also the shape of a
        // mutator that requires existing state - accept it only when the
        // procedure name reads like a constructor, so we do not call a mutator
        // on a default-initialised object.
        if matches!(sp.params[receiver_index].mode, ParamMode::InOut)
            && !is_constructor_like_name(&sp.name)
        {
            continue;
        }

        // Every non-receiver parameter must be one the harness can supply: an
        // `in` value the decoder builds with a plain expression (no setup
        // lines), or an `in`/`in out` access-to-stream the stream sink can back
        // with a concrete in-memory stream (the `Z_Stream` of
        // `Zip.Create.Create_Archive`). Anything else means we cannot call this
        // procedure correctly, so move on.
        let mut args: Vec<String> = Vec::with_capacity(sp.params.len());
        let mut arg_decls: Vec<String> = Vec::new();
        let mut arg_frees: Vec<String> = Vec::new();
        let mut arg_withs: Vec<String> = Vec::new();
        let mut arg_setup: Vec<String> = Vec::new();
        let mut arg_needs_stream_sink = false;
        let mut arg_needs_source_stream = false;
        let mut usable = true;
        for (index, param) in sp.params.iter().enumerate() {
            if index == receiver_index {
                args.push(obj_name.to_owned());
                continue;
            }
            let resolved = resolve_param_type(ast, param);
            // A by-reference `in`/`in out Root_Stream_Type'Class` source argument
            // (gid `Load_Image_Header`'s `from`): back it with the generated fuzz
            // source stream so the constructor parses the fuzz bytes. Declare the
            // stream once and load it from the input before each init call.
            if matches!(param.mode, ParamMode::In | ParamMode::InOut)
                && !matches!(resolved.type_ref.kind, TypeKind::Access { .. })
                && stream_init::class_wide_root(&resolved.type_ref.name_path)
                    .is_some_and(|root| root.eq_ignore_ascii_case("root_stream_type"))
                && stream_sink(ast, &resolved.type_ref).is_none()
            {
                let backing = format!("Gf_Ctor_Stream_{index}");
                arg_decls.push(format!("{backing} : Gf_Source_Streams.Fuzz_Stream;"));
                arg_setup.push(format!(
                    "Gf_Source_Streams.Set ({backing}, Buf'Unchecked_Access, Last);"
                ));
                args.push(backing);
                arg_needs_source_stream = true;
                continue;
            }
            // A stream argument (`in`/`in out access ... Root_Stream'Class`):
            // declare a concrete backing stream once and pass it, rather than
            // rejecting the whole constructor.
            if matches!(param.mode, ParamMode::In | ParamMode::InOut) {
                if let Some(sink) = stream_sink(ast, &resolved.type_ref) {
                    let backing = format!("Gf_Ctor_Stream_{index}");
                    let free_proc = format!("Gf_Free_{backing}");
                    arg_decls.push(format!(
                        "procedure {free_proc} is new Ada.Unchecked_Deallocation\n     ({base}, {acc});",
                        base = sink.designated_base,
                        acc = sink.access_type,
                    ));
                    arg_decls.push(format!(
                        "{backing} : {acc} := {alloc};",
                        acc = sink.access_type,
                        alloc = sink.allocator,
                    ));
                    arg_frees.push(format!("{free_proc} ({backing});"));
                    arg_withs.extend(sink.extra_withs);
                    arg_needs_stream_sink = arg_needs_stream_sink || sink.needs_null_stream_pkg;
                    args.push(backing);
                    continue;
                }
            }
            if !matches!(param.mode, ParamMode::In) {
                usable = false;
                break;
            }
            match select_initializer_for_param(ast, &resolved, registry) {
                Ok(decoder) if decoder.setup_lines.is_empty() => args.push(decoder.call_expr),
                _ => {
                    usable = false;
                    break;
                }
            }
        }
        if !usable {
            continue;
        }

        let owner = match &sp.owner {
            SubprogramOwner::Package(package_id) => ast
                .packages
                .iter()
                .find(|package| package.id == *package_id)
                .map(|package| ada_dotted_name(&package.name))
                .unwrap_or_default(),
            SubprogramOwner::LibraryLevel => String::new(),
        };
        let init_proc = if owner.is_empty() {
            ada_name(&sp.name)
        } else {
            format!("{owner}.{}", ada_name(&sp.name))
        };
        let mut extra_withs = Vec::new();
        if !owner.is_empty() {
            extra_withs.push(owner);
        }
        for with in arg_withs {
            if !extra_withs.contains(&with) {
                extra_withs.push(with);
            }
        }
        if !arg_decls.is_empty() {
            // The backing-stream Unchecked_Deallocation instantiations need it.
            let dealloc = "Ada.Unchecked_Deallocation".to_owned();
            if !extra_withs.contains(&dealloc) {
                extra_withs.push(dealloc);
            }
        }
        return Some(OutParamConstructor {
            receiver_type: resolved_type_name(ast, target_type),
            init_call: format!("{init_proc} ({});", args.join(", ")),
            extra_withs,
            arg_decls,
            arg_frees,
            setup_lines: arg_setup,
            needs_stream_sink: arg_needs_stream_sink,
            needs_source_stream: arg_needs_source_stream,
        });
    }
    None
}

/// Whether an out/in-out formal names `target_type_name` in the lexical package
/// scope of `sp`. Comparing only the bare leaf cross-matched ubiquitous names
/// such as `Stream_Type` across sibling packages (AGPL selected
/// `Agpl.Streams.Controlled.Initialize` for a Bandwidth_Throttle stream). For an
/// unqualified formal, try its owning package and each dotted ancestor so a
/// child unit can still initialize a type declared by its parent.
fn out_param_receiver_matches(
    ast: &StructuralAst,
    sp: &Subprogram,
    param: &Parameter,
    target_type_name: &str,
) -> bool {
    let raw_parts = split_name_path(&param.type_ref.name_path);
    let Some(leaf) = raw_parts.last() else {
        return false;
    };
    if raw_parts.len() > 1 {
        return crate::registry::type_name_matches(&raw_parts.join("."), target_type_name);
    }

    let SubprogramOwner::Package(package_id) = sp.owner else {
        return !target_type_name.contains('.') && leaf.eq_ignore_ascii_case(target_type_name);
    };
    let Some(owner) = package_full_name(ast, package_id) else {
        return false;
    };
    let owner_parts: Vec<&str> = owner.split('.').filter(|part| !part.is_empty()).collect();
    (1..=owner_parts.len()).rev().any(|depth| {
        let candidate = format!("{}.{}", owner_parts[..depth].join("."), leaf);
        crate::registry::type_name_matches(&candidate, target_type_name)
    })
}

/// When the target is an operation of a generic package reached through a
/// synthesised instance (`LZMA.Decoding.Decompress (hints : LZMA_Hints)`), a
/// param whose type is declared *inside that generic package* is not a library
/// unit the harness can name directly — it is visible only as
/// `<instance>.<Type>`. Rewrite such a param type's `name_path` to the
/// instance-qualified form so both the object declaration and the decoder's
/// aggregate qualifier (`<instance>.LZMA_Hints'(...)`) compile. Types from the
/// generic's *parent* (or elsewhere) are left untouched — they are reached via
/// the `use`d parent unit.
fn qualify_generic_local_param_type(
    args: &GenerateDirectArgs<'_>,
    mut resolved_param: Parameter,
) -> Parameter {
    if args.generic_instance.is_none() {
        return resolved_param;
    }
    let SubprogramOwner::Package(gen_pkg_id) = &args.target_subprogram.owner else {
        return resolved_param;
    };
    if let Some(path) = instance_qualified_name_path(&resolved_param.type_ref, *gen_pkg_id) {
        resolved_param.type_ref.name_path = path;
    }
    resolved_param
}

/// For a fully-qualified standard-library type (`Ada.Strings.Unbounded.
/// Unbounded_String`, `Interfaces.C.Size_T`), return the parent unit that must be
/// `with`ed (`Ada.Strings.Unbounded`, `Interfaces.C`). Returns `None` for plain
/// Standard types and in-tree types (those are reached via their own unit's with).
fn standard_library_parent_unit(type_name: &str) -> Option<String> {
    let parts: Vec<&str> = type_name.trim().split('.').map(str::trim).collect();
    if parts.len() < 2 || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    if !matches!(
        parts[0].to_ascii_lowercase().as_str(),
        "ada" | "interfaces" | "system" | "gnat"
    ) {
        return None;
    }
    Some(parts[..parts.len() - 1].join("."))
}

/// If `resolved` names a type declared inside the synthesised generic package
/// `gen_pkg`, return the instance-qualified name path
/// (`[Govfuzz_Generic_Instance, Word]`). A type declared inside the generic must
/// be reached through the instance, never the generic package itself ("prefix
/// must not be a generic package"). Returns `None` for types owned elsewhere.
fn instance_qualified_name_path(resolved: &TypeRef, gen_pkg: PackageId) -> Option<Vec<String>> {
    if resolved.owner != TypeOwner::Package(gen_pkg) {
        return None;
    }
    let leaf = resolved
        .name_path
        .last()
        .and_then(|part| part.rsplit('.').next())
        .map(str::to_owned)?;
    Some(vec![
        crate::generic_instance::INSTANCE_NAME.to_owned(),
        leaf,
    ])
}

/// Rewrite every constructor whose `qualified_path` is declared in the target's
/// owning generic package so it is named through the synthesised instance
/// (`Json.Types.Create_Null` -> `Govfuzz_Generic_Instance.Create_Null`). A
/// parameter whose type lives in a generic package is already qualified through
/// the instance (see [`qualify_generic_local_param_type`]); the *value* the
/// decoder builds for it must come from the same instance, because the
/// constructor functions live in the generic too and Ada forbids naming them
/// through the uninstantiated generic ("prefix must not be a generic package").
/// A no-op when no generic instance is in play or the target is library-level.
fn qualify_constructors_through_instance(
    args: &GenerateDirectArgs<'_>,
    mut registry: crate::registry::ConstructorRegistry,
) -> crate::registry::ConstructorRegistry {
    if args.generic_instance.is_none() {
        return registry;
    }
    let SubprogramOwner::Package(gen_pkg_id) = &args.target_subprogram.owner else {
        return registry;
    };
    let Some(gen_pkg_name) = args
        .ast
        .packages
        .iter()
        .find(|package| package.id == *gen_pkg_id)
        .map(|package| package.name.as_str())
    else {
        return registry;
    };
    for entry in &mut registry.entries {
        if let Some(rewritten) =
            instance_qualified_constructor_path(&entry.qualified_path, gen_pkg_name)
        {
            entry.qualified_path = rewritten;
        }
    }
    registry
}

/// If `qualified_path` (a constructor's owner-qualified dotted name) is declared
/// in the generic package `gen_pkg_name`, return the same path with that package
/// prefix replaced by the instance name; `None` for constructors owned
/// elsewhere. The match is component-wise and case-insensitive (Ada folds case,
/// and the parser may record the generic unit and the constructor owner with
/// different casing). The generic name must be a *strict* prefix so at least the
/// constructor's own leaf survives.
fn instance_qualified_constructor_path(qualified_path: &str, gen_pkg_name: &str) -> Option<String> {
    let pkg_parts: Vec<&str> = gen_pkg_name.split('.').collect();
    let path_parts: Vec<&str> = qualified_path.split('.').collect();
    if path_parts.len() <= pkg_parts.len() {
        return None;
    }
    if !pkg_parts
        .iter()
        .zip(&path_parts)
        .all(|(pkg, path)| pkg.eq_ignore_ascii_case(path))
    {
        return None;
    }
    let rest = path_parts[pkg_parts.len()..].join(".");
    Some(format!("{}.{rest}", crate::generic_instance::INSTANCE_NAME))
}

/// Resolve a subprogram's return type to its Ada name, rewriting a type declared
/// inside the synthesised generic instance to be named through the instance
/// (mirrors [`qualify_generic_local_param_type`] for parameters).
fn generic_qualified_return_type_name(args: &GenerateDirectArgs<'_>, type_ref: &TypeRef) -> String {
    let mut resolved = resolve_type_ref(args.ast, type_ref);
    if args.generic_instance.is_some() {
        if let SubprogramOwner::Package(gen_pkg_id) = &args.target_subprogram.owner {
            if let Some(path) = instance_qualified_name_path(&resolved, *gen_pkg_id) {
                resolved.name_path = path;
            }
        }
    }
    ada_type_name(&resolved)
}

fn resolve_param_type(ast: &StructuralAst, param: &Parameter) -> Parameter {
    let mut resolved_param = param.clone();
    resolved_param.type_ref = resolve_type_ref(ast, &param.type_ref);
    qualify_nested_package_type(ast, &mut resolved_param.type_ref);
    // An array whose element is a composite type (record/tagged) can't be
    // decoded element-wise as a fuzz byte (zip-ada `huffman.Descriptor =
    // array (...) of Length_Code_Pair`); assigning `U8` to a record element is
    // a hard type error. Mark it Unknown so the decoder skips the target
    // (unsupported_params) instead of emitting code that won't compile.
    if let TypeKind::Array { elem_name, .. } = &resolved_param.type_ref.kind {
        if array_element_is_composite(ast, elem_name) {
            resolved_param.type_ref.kind = TypeKind::Unknown;
        }
    }
    // A standard-library type the source named via a `use` clause (`S :
    // Unbounded_String`) reaches the harness without that `use`, so the bare
    // name is not visible. Rewrite to the fully-qualified name so the parameter
    // declaration compiles (the harness `with`s the unit but does not `use` it).
    qualify_known_library_type(&mut resolved_param.type_ref);
    resolved_param
}

/// Expand a type named through a nested package that was directly visible in
/// the target's declaration (`Arg_Lists.Vector`) to the package's full path
/// (`GNATCOLL.OS.Process.Arg_Lists.Vector`). A standalone harness only `with`s
/// the compilation unit and therefore cannot see the nested package by its
/// local simple name.
fn qualify_nested_package_type(ast: &StructuralAst, type_ref: &mut TypeRef) {
    let parts = split_name_path(&type_ref.name_path);
    if parts.len() < 2 {
        return;
    }
    let package_path = parts[..parts.len() - 1].join(".");
    if package_path.contains('.') {
        return;
    }
    let Some(package) = ast.packages.iter().find(|package| {
        package.parent.is_some() && package.name.eq_ignore_ascii_case(&package_path)
    }) else {
        return;
    };
    let Some(full_package) = package_full_name(ast, package.id) else {
        return;
    };
    let mut qualified = full_package
        .split('.')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    qualified.push(parts[parts.len() - 1].to_owned());
    type_ref.name_path = qualified;
}

/// Generic package instantiations do not open package scopes in the structural
/// AST (`package Arg_Lists is new Ada.Containers...`). For their canonical
/// container types, qualify a local two-part name through the target's owning
/// package so a standalone harness can name it.
fn qualify_local_container_instance_type(
    ast: &StructuralAst,
    target: &Subprogram,
    type_ref: &mut TypeRef,
) {
    let parts = split_name_path(&type_ref.name_path);
    if parts.len() != 2
        || !matches!(
            parts[1].to_ascii_lowercase().as_str(),
            "vector" | "map" | "list" | "set" | "tree" | "holder" | "instance"
        )
    {
        return;
    }
    // A real package node can already be qualified by the normal path above.
    if ast
        .packages
        .iter()
        .any(|package| package.name.eq_ignore_ascii_case(&parts[0]))
    {
        return;
    }
    let SubprogramOwner::Package(owner_id) = target.owner else {
        return;
    };
    let Some(owner) = package_full_name(ast, owner_id) else {
        return;
    };
    let mut qualified = owner.split('.').map(str::to_owned).collect::<Vec<_>>();
    qualified.extend(parts);
    type_ref.name_path = qualified;
}

/// Fully-qualify a standard-library type the source referenced via a `use`
/// clause, so it is visible in the harness (which `with`s but never `use`s).
/// Only types not declared in the tree (single-component name) are rewritten.
fn qualify_known_library_type(type_ref: &mut TypeRef) {
    if type_ref.name_path.len() != 1 {
        return;
    }
    let qualified: &[&str] = match type_ref.name_path[0].to_ascii_lowercase().as_str() {
        "unbounded_string" => &["Ada", "Strings", "Unbounded", "Unbounded_String"],
        "stream_element" => &["Ada", "Streams", "Stream_Element"],
        "stream_element_count" => &["Ada", "Streams", "Stream_Element_Count"],
        "stream_element_offset" => &["Ada", "Streams", "Stream_Element_Offset"],
        _ => return,
    };
    type_ref.name_path = qualified.iter().map(|s| (*s).to_owned()).collect();
}

/// Whether an array's element type resolves to a composite (record / tagged /
/// private / discriminated) type in the tree — not a byte/scalar the decoder
/// can fill with a fuzz byte.
fn array_element_is_composite(ast: &StructuralAst, elem_name: &str) -> bool {
    let leaf = elem_name.rsplit('.').next().unwrap_or(elem_name).trim();
    if leaf.is_empty() {
        return false;
    }
    ast.types.iter().any(|t| {
        t.name_path
            .last()
            .is_some_and(|n| n.eq_ignore_ascii_case(leaf))
            && matches!(
                t.kind,
                TypeKind::Record(_)
                    | TypeKind::Discriminated { .. }
                    | TypeKind::Tagged { .. }
                    | TypeKind::Private
            )
    })
}

fn resolved_type_name(ast: &StructuralAst, type_ref: &TypeRef) -> String {
    ada_type_name(&resolve_type_ref(ast, type_ref))
}

/// Default element count for a synthesized output sink. Generous enough that a
/// normal decode/serialize output fits without a spurious overflow, while still
/// bounded so a runaway (decompression-bomb-style) write trips the array's own
/// index check and surfaces as a finding.
const SINK_ELEMENT_COUNT: usize = 1024 * 1024;

/// A bounded heap backing buffer for an access-to-array parameter.
struct ArraySink {
    /// The access type's Ada name (the parameter's own declared type).
    access_type: String,
    /// The `new <designated> (...)` allocator expression assigned to the access.
    allocator: String,
    /// The designated subtype name (unconstrained), for the matching
    /// `Ada.Unchecked_Deallocation` instantiation that frees the buffer at exit.
    designated_base: String,
    /// Extra `with` clauses the designated array type needs to be visible.
    extra_withs: Vec<String>,
    /// True for `access constant <array>`: the allocator is initialized and the
    /// buffer is NOT freed (Unchecked_Deallocation requires access-to-variable).
    is_constant: bool,
}

/// The shape of a designated array type for `new`-allocation.
struct DesignatedArray {
    /// Ada name to allocate (`Stream_Element_Array`, a local array's qualified name).
    name: String,
    /// `Some(index_first_expr)` for an *unconstrained* array (needs an index
    /// constraint in the allocator, e.g. `0` or `Positive'First`); `None` for an
    /// already-constrained array type (allocate `new T` with no constraint).
    index_first: Option<String>,
    extra_withs: Vec<String>,
    /// A valid default element value (`' '`, `0`) for building an *initialized*
    /// allocator for an `access constant` buffer. `None` when we cannot name a
    /// default (a tree array of an unknown element type).
    elem_default: Option<&'static str>,
}

/// If `type_ref` is an access-to-array type whose designated array we can size,
/// describe a bounded heap backing buffer to allocate for it instead of passing
/// a bare null pointer. Covers the predefined standard byte/character arrays
/// (`Stream_Element_Array`, `String`, `Wide_String`, `Wide_Wide_String`) — the
/// canonical Ada output-buffer idiom — and a plain array type declared in the
/// tree. Cross-unit/qualified local arrays we cannot make visible are left to
/// the bare-null fallback (returns `None`).
fn access_to_array_sink(ast: &StructuralAst, type_ref: &TypeRef) -> Option<ArraySink> {
    let access_decl = find_access_type_decl(ast, type_ref)?;
    let is_constant = access_designates_constant(&access_decl.constraints.0);
    let designated_mark = designated_subtype_mark(&access_decl.constraints.0)?;
    let designated = designated_array_spec(ast, &designated_mark)?;
    let allocator = if is_constant {
        // An access-to-constant allocator must be INITIALIZED (a constant cannot be
        // left uninitialized). Build a default-filled aggregate; if we cannot name
        // a default element or the index, fall back to bare null (returns None).
        let index_first = designated.index_first.as_ref()?;
        let elem = designated.elem_default?;
        format!(
            "new {}'({} .. {} + {} - 1 => {})",
            designated.name, index_first, index_first, SINK_ELEMENT_COUNT, elem
        )
    } else {
        match &designated.index_first {
            Some(index_first) => format!(
                "new {} ({} .. {} + {} - 1)",
                designated.name, index_first, index_first, SINK_ELEMENT_COUNT
            ),
            None => format!("new {}", designated.name),
        }
    };
    Some(ArraySink {
        access_type: ada_type_name(type_ref),
        allocator,
        designated_base: designated.name,
        extra_withs: designated.extra_withs,
        is_constant,
    })
}

/// Whether an access type's constraint designates a `constant` subtype
/// (`access constant String`, `not null access constant T`).
fn access_designates_constant(constraints: &str) -> bool {
    let mut rest = constraints.trim();
    for prefix in ["all ", "not null ", "access "] {
        if let Some(stripped) = rest
            .strip_prefix(prefix)
            .or_else(|| rest.strip_prefix(&prefix.to_ascii_uppercase()))
        {
            rest = stripped.trim();
        }
    }
    rest.to_ascii_lowercase().starts_with("constant ")
}

/// A backing object for an access-to-class-wide-stream parameter.
struct StreamSink {
    /// The access type's Ada name (the parameter's own declared type).
    access_type: String,
    /// The designated class-wide subtype, for the freeing Unchecked_Deallocation.
    designated_base: String,
    /// The `new ...` allocator assigned to the access.
    allocator: String,
    /// Extra `with` clauses the allocator needs (the concrete derivation's unit).
    extra_withs: Vec<String>,
    /// True for the standard Ada stream root: emit the generated discard
    /// `Gf_Sink_Streams.Null_Stream` package beside the harness.
    needs_null_stream_pkg: bool,
}

/// If `type_ref` is an access to a class-wide stream root (`<Root>'Class`),
/// describe a real backing object so the callee's write/serialize path fuzzes
/// instead of null-dereferencing the stream (zip-ada `output_stream_access`,
/// `Z_Stream`). The STANDARD `Ada.Streams.Root_Stream_Type'Class` is backed by a
/// generated `Gf_Sink_Streams.Null_Stream` (Write discards, Read reports EOF);
/// any other class-wide stream root with a concrete in-memory derivation in the
/// tree (zip-ada `Root_Zipstream_Type'Class` -> `Memory_Zipstream`) is backed by
/// `new <that derivation>`. A custom root with no in-memory concrete derivation
/// falls back to the existing null decoder (returns `None`).
fn stream_sink(ast: &StructuralAst, type_ref: &TypeRef) -> Option<StreamSink> {
    let access_decl = find_access_type_decl(ast, type_ref)?;
    let mark = designated_subtype_mark(&access_decl.constraints.0)?;
    let leaf = mark.rsplit('.').next().unwrap_or(&mark);
    // Must designate a class-wide type (`<Root>'Class`).
    let root_simple = leaf
        .to_ascii_lowercase()
        .strip_suffix("'class")
        .map(str::to_owned)?;
    if root_simple.is_empty() {
        return None;
    }
    let access_type = ada_type_name(type_ref);
    if root_simple == "root_stream_type" {
        return Some(StreamSink {
            access_type,
            designated_base: "Ada.Streams.Root_Stream_Type'Class".to_owned(),
            allocator: "new Gf_Sink_Streams.Null_Stream".to_owned(),
            extra_withs: Vec::new(),
            needs_null_stream_pkg: true,
        });
    }
    // Custom class-wide stream root: allocate a concrete in-memory derivation.
    let derivation = concrete_inmemory_stream_derivation(ast, &root_simple)?;
    // Qualify the designated subtype with the derivation's package so the freeing
    // Unchecked_Deallocation can name it (`Zip_Streams.Root_Zipstream_Type'Class`).
    let designated_base = if mark.contains('.') {
        mark.clone()
    } else if let Some(pkg) = &derivation.with_unit {
        format!("{pkg}.{mark}")
    } else {
        mark.clone()
    };
    Some(StreamSink {
        access_type,
        designated_base,
        allocator: format!("new {}", derivation.qualified_name),
        extra_withs: derivation.with_unit.into_iter().collect(),
        needs_null_stream_pkg: false,
    })
}

struct StreamDerivation {
    qualified_name: String,
    with_unit: Option<String>,
}

/// Find a concrete, allocatable, in-memory derivation of the class-wide stream
/// root `root_simple` (e.g. `Memory_Zipstream` for `Root_Zipstream_Type`). Only
/// in-memory derivations (name contains memory/array/string/buffer) are accepted
/// — a file/socket-backed one would just shift the artifact to an open failure.
/// Abstract derivations cannot be allocated and are excluded.
fn concrete_inmemory_stream_derivation(
    ast: &StructuralAst,
    root_simple: &str,
) -> Option<StreamDerivation> {
    let derivation = ast.types.iter().find(|t| {
        let constraints = t.constraints.0.to_ascii_lowercase();
        let leaf = t
            .name_path
            .last()
            .map(|n| n.to_ascii_lowercase())
            .unwrap_or_default();
        constraints.contains(root_simple)
            && !constraints.contains("abstract")
            && !leaf.eq_ignore_ascii_case(root_simple)
            && ["memory", "array", "string", "buffer"]
                .iter()
                .any(|kw| leaf.contains(kw))
    })?;
    let qualified = qualified_type_name_path(ast, derivation);
    let with_unit = match derivation.owner {
        TypeOwner::Package(pkg_id) => package_root(ast, pkg_id).map(|p| ada_dotted_name(&p.name)),
        // Otherwise fall back to the qualified-name prefix (the package part).
        _ => (qualified.len() > 1).then(|| ada_path(&qualified[..qualified.len() - 1])),
    };
    Some(StreamDerivation {
        qualified_name: ada_path(&qualified),
        with_unit,
    })
}

/// The source of the generated discard-stream package emitted beside a harness
/// that sinks an access-to-stream parameter. `(spec, body)`.
fn gf_sink_streams_sources() -> (&'static str, &'static str) {
    (
        "--  SPDX-License-Identifier: Apache-2.0\n\
         with Ada.Streams;\n\
         package Gf_Sink_Streams is\n\
         \x20  --  A discard sink: a concrete Root_Stream_Type whose Write throws\n\
         \x20  --  bytes away and whose Read reports EOF. Lets a subprogram that\n\
         \x20  --  writes output to a caller-supplied stream run its real path\n\
         \x20  --  under fuzzing without a live stream object.\n\
         \x20  type Null_Stream is new Ada.Streams.Root_Stream_Type with null record;\n\
         \x20  overriding procedure Read\n\
         \x20    (S    : in out Null_Stream;\n\
         \x20     Item : out Ada.Streams.Stream_Element_Array;\n\
         \x20     Last : out Ada.Streams.Stream_Element_Offset);\n\
         \x20  overriding procedure Write\n\
         \x20    (S    : in out Null_Stream;\n\
         \x20     Item : Ada.Streams.Stream_Element_Array);\n\
         end Gf_Sink_Streams;\n",
        "--  SPDX-License-Identifier: Apache-2.0\n\
         package body Gf_Sink_Streams is\n\
         \x20  use type Ada.Streams.Stream_Element_Offset;\n\
         \x20  overriding procedure Read\n\
         \x20    (S    : in out Null_Stream;\n\
         \x20     Item : out Ada.Streams.Stream_Element_Array;\n\
         \x20     Last : out Ada.Streams.Stream_Element_Offset) is\n\
         \x20     pragma Unreferenced (S);\n\
         \x20  begin\n\
         \x20     Last := Item'First - 1;  --  immediate EOF\n\
         \x20  end Read;\n\
         \x20  overriding procedure Write\n\
         \x20    (S    : in out Null_Stream;\n\
         \x20     Item : Ada.Streams.Stream_Element_Array) is\n\
         \x20     pragma Unreferenced (S, Item);\n\
         \x20  begin\n\
         \x20     null;  --  discard\n\
         \x20  end Write;\n\
         end Gf_Sink_Streams;\n",
    )
}

/// The source of the generated fuzz source-stream package emitted beside a
/// harness that drives a by-reference `Root_Stream_Type'Class` source parameter
/// (gid `Load_Image_Header`'s `from`, any `Ada.Streams.Stream_IO` consumer):
/// `Read` serves the fuzz input bytes and `Write` discards, so the callee's real
/// decode path runs on fuzzer-controlled input. `(spec, body)`.
fn gf_source_streams_sources() -> (&'static str, &'static str) {
    (
        "--  SPDX-License-Identifier: Apache-2.0\n\
         with Ada.Streams;\n\
         package Gf_Source_Streams is\n\
         \x20  --  A fuzz source: a concrete Root_Stream_Type whose Read serves the\n\
         \x20  --  fuzz input bytes and whose Write discards. Lets a subprogram that\n\
         \x20  --  parses an Ada.Streams stream run its real decode path on\n\
         \x20  --  fuzzer-controlled bytes.\n\
         \x20  type Buffer_Ref is access all Ada.Streams.Stream_Element_Array;\n\
         \x20  type Fuzz_Stream is new Ada.Streams.Root_Stream_Type with private;\n\
         \x20  procedure Set\n\
         \x20    (S    : in out Fuzz_Stream;\n\
         \x20     Data : Buffer_Ref;\n\
         \x20     Last : Ada.Streams.Stream_Element_Offset);\n\
         \x20  overriding procedure Read\n\
         \x20    (S    : in out Fuzz_Stream;\n\
         \x20     Item : out Ada.Streams.Stream_Element_Array;\n\
         \x20     Last : out Ada.Streams.Stream_Element_Offset);\n\
         \x20  overriding procedure Write\n\
         \x20    (S    : in out Fuzz_Stream;\n\
         \x20     Item : Ada.Streams.Stream_Element_Array);\n\
         private\n\
         \x20  type Fuzz_Stream is new Ada.Streams.Root_Stream_Type with record\n\
         \x20     Data : Buffer_Ref := null;\n\
         \x20     Pos  : Ada.Streams.Stream_Element_Offset := 1;\n\
         \x20     Last : Ada.Streams.Stream_Element_Offset := 0;\n\
         \x20  end record;\n\
         end Gf_Source_Streams;\n",
        "--  SPDX-License-Identifier: Apache-2.0\n\
         package body Gf_Source_Streams is\n\
         \x20  use type Ada.Streams.Stream_Element_Offset;\n\
         \x20  procedure Set\n\
         \x20    (S    : in out Fuzz_Stream;\n\
         \x20     Data : Buffer_Ref;\n\
         \x20     Last : Ada.Streams.Stream_Element_Offset) is\n\
         \x20  begin\n\
         \x20     S.Data := Data;\n\
         \x20     S.Pos  := (if Data = null then 1 else Data'First);\n\
         \x20     S.Last := Last;\n\
         \x20  end Set;\n\
         \x20  overriding procedure Read\n\
         \x20    (S    : in out Fuzz_Stream;\n\
         \x20     Item : out Ada.Streams.Stream_Element_Array;\n\
         \x20     Last : out Ada.Streams.Stream_Element_Offset) is\n\
         \x20     Avail : Ada.Streams.Stream_Element_Offset;\n\
         \x20     Count : Ada.Streams.Stream_Element_Offset;\n\
         \x20  begin\n\
         \x20     if S.Data = null or else S.Pos > S.Last then\n\
         \x20        Last := Item'First - 1;  --  EOF\n\
         \x20        return;\n\
         \x20     end if;\n\
         \x20     Avail := S.Last - S.Pos + 1;\n\
         \x20     Count := Ada.Streams.Stream_Element_Offset'Min (Item'Length, Avail);\n\
         \x20     Item (Item'First .. Item'First + Count - 1) :=\n\
         \x20       S.Data (S.Pos .. S.Pos + Count - 1);\n\
         \x20     S.Pos := S.Pos + Count;\n\
         \x20     Last := Item'First + Count - 1;\n\
         \x20  end Read;\n\
         \x20  overriding procedure Write\n\
         \x20    (S    : in out Fuzz_Stream;\n\
         \x20     Item : Ada.Streams.Stream_Element_Array) is\n\
         \x20     pragma Unreferenced (S, Item);\n\
         \x20  begin\n\
         \x20     null;  --  discard\n\
         \x20  end Write;\n\
         end Gf_Source_Streams;\n",
    )
}

/// The library-level callback package emitted beside the harness when a target
/// parameter is an access-to-subprogram (a getchar/putchar-style callback the
/// callee invokes to pull/push bytes). It backs each supported callback profile
/// with a concrete library-level subprogram whose `'Access` the harness passes:
///
///   * Source callbacks (`Src_*`, `Fn_*`) serve the next fuzz input byte and
///     raise `GF_Fuzz_EOF` once the input is consumed. A read-until-EOF decode
///     loop (the canonical reason a parser takes a getchar callback) therefore
///     terminates cleanly on the fuzz input length instead of spinning forever
///     on a fixed buffer — the harness catches `GF_Fuzz_EOF` as normal
///     end-of-input, NOT a finding.
///   * Sink callbacks (`Snk_*`, `Noop`) discard — the callee's output channel.
fn gf_callbacks_sources() -> (&'static str, &'static str) {
    (
        "--  SPDX-License-Identifier: Apache-2.0\n\
         pragma Ada_2012;\n\
         with Ada.Streams;\n\
         with Interfaces;\n\
         package Gf_Callbacks is\n\
         \x20  --  Raised by a source callback when the fuzz input is exhausted. The\n\
         \x20  --  generated harness catches it as the normal end-of-input signal\n\
         \x20  --  (NOT a finding), so a callback-driven read-until-EOF decode loop\n\
         \x20  --  terminates cleanly instead of spinning on a fixed buffer.\n\
         \x20  GF_Fuzz_EOF : exception;\n\
         \x20  type Buffer_Ref is access all Ada.Streams.Stream_Element_Array;\n\
         \x20  --  Install the fuzz input as the byte source the callbacks serve.\n\
         \x20  procedure Set\n\
         \x20    (Data : Buffer_Ref;\n\
         \x20     Last : Ada.Streams.Stream_Element_Offset);\n\
         \x20  --  Source callbacks: yield the next fuzz byte, raise GF_Fuzz_EOF at end.\n\
         \x20  procedure Src_Char (C : out Character);\n\
         \x20  procedure Src_Byte (B : out Interfaces.Unsigned_8);\n\
         \x20  procedure Src_String (Item : out String; Last : out Natural);\n\
         \x20  function  Fn_Char return Character;\n\
         \x20  function  Fn_Byte return Interfaces.Unsigned_8;\n\
         \x20  function  Fn_Integer return Integer;\n\
         \x20  function  Fn_Boolean return Boolean;\n\
         \x20  --  Sink callbacks: discard the value (the callee's output channel).\n\
         \x20  procedure Snk_Char (C : Character);\n\
         \x20  procedure Snk_Byte (B : Interfaces.Unsigned_8);\n\
         \x20  procedure Snk_String (Item : in String);\n\
         \x20  procedure Noop;\n\
         end Gf_Callbacks;\n",
        "--  SPDX-License-Identifier: Apache-2.0\n\
         package body Gf_Callbacks is\n\
         \x20  use type Ada.Streams.Stream_Element_Offset;\n\
         \x20  use type Ada.Streams.Stream_Element;\n\
         \x20  Data : Buffer_Ref := null;\n\
         \x20  Pos  : Ada.Streams.Stream_Element_Offset := 1;\n\
         \x20  Last : Ada.Streams.Stream_Element_Offset := 0;\n\
         \x20  procedure Set\n\
         \x20    (Data : Buffer_Ref;\n\
         \x20     Last : Ada.Streams.Stream_Element_Offset) is\n\
         \x20  begin\n\
         \x20     Gf_Callbacks.Data := Data;\n\
         \x20     Gf_Callbacks.Pos  := (if Data = null then 1 else Data'First);\n\
         \x20     Gf_Callbacks.Last := Last;\n\
         \x20  end Set;\n\
         \x20  function Next return Ada.Streams.Stream_Element is\n\
         \x20  begin\n\
         \x20     if Data = null or else Pos > Last then\n\
         \x20        raise GF_Fuzz_EOF;\n\
         \x20     end if;\n\
         \x20     return B : constant Ada.Streams.Stream_Element := Data (Pos) do\n\
         \x20        Pos := Pos + 1;\n\
         \x20     end return;\n\
         \x20  end Next;\n\
         \x20  procedure Src_Char (C : out Character) is\n\
         \x20  begin\n\
         \x20     C := Character'Val (Integer (Next));\n\
         \x20  end Src_Char;\n\
         \x20  procedure Src_Byte (B : out Interfaces.Unsigned_8) is\n\
         \x20  begin\n\
         \x20     B := Interfaces.Unsigned_8 (Next);\n\
         \x20  end Src_Byte;\n\
         \x20  procedure Src_String (Item : out String; Last : out Natural) is\n\
         \x20     Count : Natural := 0;\n\
         \x20  begin\n\
         \x20     Item := (others => Character'Val (0));\n\
         \x20     for I in Item'Range loop\n\
         \x20        exit when Data = null or else Pos > Gf_Callbacks.Last;\n\
         \x20        Item (I) := Character'Val (Integer (Data (Pos)));\n\
         \x20        Pos := Pos + 1;\n\
         \x20        Count := Count + 1;\n\
         \x20     end loop;\n\
         \x20     Last := Count;\n\
         \x20  end Src_String;\n\
         \x20  function Fn_Char return Character is\n\
         \x20  begin\n\
         \x20     return Character'Val (Integer (Next));\n\
         \x20  end Fn_Char;\n\
         \x20  function Fn_Byte return Interfaces.Unsigned_8 is\n\
         \x20  begin\n\
         \x20     return Interfaces.Unsigned_8 (Next);\n\
         \x20  end Fn_Byte;\n\
         \x20  function Fn_Integer return Integer is\n\
         \x20     V : Integer := 0;\n\
         \x20  begin\n\
         \x20     for K in 1 .. 4 loop\n\
         \x20        V := V * 256 + Integer (Next);\n\
         \x20     end loop;\n\
         \x20     return V;\n\
         \x20  end Fn_Integer;\n\
         \x20  function Fn_Boolean return Boolean is\n\
         \x20  begin\n\
         \x20     return (Next and 1) = 1;\n\
         \x20  end Fn_Boolean;\n\
         \x20  procedure Snk_Char (C : Character) is\n\
         \x20     pragma Unreferenced (C);\n\
         \x20  begin\n\
         \x20     null;\n\
         \x20  end Snk_Char;\n\
         \x20  procedure Snk_Byte (B : Interfaces.Unsigned_8) is\n\
         \x20     pragma Unreferenced (B);\n\
         \x20  begin\n\
         \x20     null;\n\
         \x20  end Snk_Byte;\n\
         \x20  procedure Snk_String (Item : in String) is\n\
         \x20     pragma Unreferenced (Item);\n\
         \x20  begin\n\
         \x20     null;\n\
         \x20  end Snk_String;\n\
         \x20  procedure Noop is\n\
         \x20  begin\n\
         \x20     null;\n\
         \x20  end Noop;\n\
         end Gf_Callbacks;\n",
    )
}

/// The synthesized callback backing an access-to-subprogram parameter: the
/// library-level `Gf_Callbacks` subprogram whose `'Access` the harness passes,
/// and the type mark to declare the local access object with.
struct CallbackSynth {
    /// The local object's declared type: the named access-to-subprogram type
    /// (`Getchar_Ptr`), or the reconstructed anonymous form (`access procedure
    /// (C : out Character)`).
    decl_type: String,
    /// The initializer expression: `Gf_Callbacks.Src_Char'Access`.
    access_expr: String,
}

/// If `type_ref` is an access-to-subprogram parameter whose profile we can back
/// with a concrete callback, describe the `Gf_Callbacks` subprogram to pass
/// instead of leaving the parameter a bare null (which the callee null-calls the
/// moment it invokes the callback). Only the well-defined getchar/putchar-style
/// shapes are matched — a single `in`/`out` `Character`/`Unsigned_8` parameter,
/// a zero-parameter procedure, or a no-parameter function returning a scalar —
/// so the synthesized subprogram is subtype-conformant with the access type. Any
/// other profile returns `None` (the parameter falls back to the null decoder).
fn access_to_subprogram_callback(ast: &StructuralAst, type_ref: &TypeRef) -> Option<CallbackSynth> {
    let access_decl = find_access_type_decl(ast, type_ref)?;
    let profile = access_decl.constraints.0.trim();
    let lower = profile.to_ascii_lowercase();
    // Only access-to-subprogram (the parser stores the profile text); an
    // access-to-object constraint (`all X`, `constant X`, a subtype mark) is not
    // a callback.
    if !(lower.starts_with("procedure") || lower.starts_with("function")) {
        return None;
    }
    let subprogram = callback_subprogram_for_profile(&lower)?;
    // Declare the local with the parameter's own named access type when it has
    // one; otherwise reconstruct the anonymous access-to-subprogram type from
    // the profile so the object declaration is well-formed.
    let decl_type = if type_ref.name_path.is_empty() {
        format!("access {profile}")
    } else {
        ada_type_name(type_ref)
    };
    Some(CallbackSynth {
        decl_type,
        access_expr: format!("Gf_Callbacks.{subprogram}'Access"),
    })
}

/// Map a lower-cased access-to-subprogram profile (`procedure (c : out
/// character)`, `function return boolean`) to the `Gf_Callbacks` subprogram that
/// is subtype-conformant with it, or `None` when no canonical backing matches.
fn callback_subprogram_for_profile(lower: &str) -> Option<&'static str> {
    if let Some(rest) = lower.strip_prefix("procedure") {
        return match callback_paren_inner(rest) {
            // A no-parameter procedure callback (a tick/flush hook): discard.
            None => Some("Noop"),
            Some(inner) if inner.is_empty() => Some("Noop"),
            Some(inner) => {
                // Buffered reader callback (`Item : out String; Last : out
                // Natural`), used by yaml-ada and similar stream adapters.
                if inner.contains(';')
                    && inner.contains("item : out string")
                    && inner.contains("last : out natural")
                {
                    return Some("Src_String");
                }
                // A single in/out scalar parameter is the getchar/putchar shape;
                // anything with more parameters we cannot match a fixed backing
                // to, so skip.
                if inner.contains(';') {
                    return None;
                }
                let (mode, ty) = callback_parse_param(&inner)?;
                match (mode, ty.as_str()) {
                    (CbMode::Out, "character" | "standard.character") => Some("Src_Char"),
                    (CbMode::Out, t) if callback_is_byte(t) => Some("Src_Byte"),
                    (CbMode::In, "character" | "standard.character") => Some("Snk_Char"),
                    (CbMode::In, "string" | "standard.string") => Some("Snk_String"),
                    (CbMode::In, t) if callback_is_byte(t) => Some("Snk_Byte"),
                    _ => None,
                }
            }
        };
    }
    if let Some(rest) = lower.strip_prefix("function") {
        // Only a no-parameter function can be backed by a fixed getter; a
        // function callback taking arguments would need its parameters matched.
        if let Some(inner) = callback_paren_inner(rest) {
            if !inner.is_empty() {
                return None;
            }
        }
        let ret = rest
            .rsplit("return")
            .next()?
            .trim()
            .trim_end_matches(';')
            .trim();
        let ret = ret.split_whitespace().next().unwrap_or("");
        return match ret {
            "character" | "standard.character" => Some("Fn_Char"),
            t if callback_is_byte(t) => Some("Fn_Byte"),
            "integer" | "standard.integer" => Some("Fn_Integer"),
            "boolean" | "standard.boolean" => Some("Fn_Boolean"),
            _ => None,
        };
    }
    None
}

#[derive(Clone, Copy, PartialEq)]
enum CbMode {
    In,
    Out,
}

/// The text inside the outermost parentheses of a subprogram profile tail
/// (after `procedure`/`function`), or `None` when there is no parameter list.
fn callback_paren_inner(rest: &str) -> Option<String> {
    let open = rest.find('(')?;
    let close = rest.rfind(')')?;
    if close <= open {
        return None;
    }
    Some(rest[open + 1..close].trim().to_owned())
}

/// Parse a single lower-cased parameter spec (`c : out character`) into its mode
/// and (first-token) type mark. `in out` is rejected (returns `None`) — no fixed
/// backing matches a bidirectional scalar callback parameter.
fn callback_parse_param(spec: &str) -> Option<(CbMode, String)> {
    let (_name, after) = spec.split_once(':')?;
    let after = after.trim();
    let (mode, ty_text) = if let Some(t) = after.strip_prefix("in out ") {
        let _ = t;
        return None;
    } else if let Some(t) = after.strip_prefix("out ") {
        (CbMode::Out, t)
    } else if let Some(t) = after.strip_prefix("in ") {
        (CbMode::In, t)
    } else {
        (CbMode::In, after)
    };
    let ty = ty_text.split_whitespace().next()?.trim();
    if ty.is_empty() {
        return None;
    }
    Some((mode, ty.to_owned()))
}

/// Whether a lower-cased type mark is one of the byte types `Gf_Callbacks`'
/// `Unsigned_8` callbacks are subtype-conformant with.
fn callback_is_byte(ty: &str) -> bool {
    matches!(ty, "unsigned_8" | "interfaces.unsigned_8")
}

/// #457: how to construct and tear down an access-type opaque handle around the
/// target call. `init_stmt`/`delete_stmt` carry a `{handle}` placeholder the caller
/// substitutes with the rendered parameter name.
struct AccessLifecycleSink {
    /// The rendered Ada access type name used to declare the handle bare.
    access_type: String,
    /// The constructor statement: `{handle} := Pkg.Create;` (returning function) or
    /// `Pkg.Init ({handle});` (out-parameter procedure).
    init_stmt: String,
    /// The destructor statement (`Pkg.Destroy ({handle});`), if the type has one.
    delete_stmt: Option<String>,
    /// Units declaring Init/Delete, to `with` when they live outside the handle
    /// type's own (already-`with`ed) package.
    extra_withs: Vec<String>,
}

/// The leaf (last dotted segment) of `name`, lower-cased, for case-insensitive
/// access-type / designated-base matching.
fn leaf_lower(name: &str) -> String {
    name.rsplit('.')
        .next()
        .unwrap_or(name)
        .trim()
        .to_ascii_lowercase()
}

/// The library unit declaring a qualified subprogram path (`Widgets.Create` ->
/// `Widgets`), `None` for an unqualified library-level subprogram.
fn subprogram_path_unit(qualified: &str) -> Option<String> {
    let idx = qualified.rfind('.')?;
    let unit = qualified[..idx].trim();
    (!unit.is_empty()).then(|| ada_dotted_name(unit))
}

/// Pair an access-typed parameter with a discovered Init/Delete lifecycle (#457),
/// matched either by the access type's own name or — for a target spelled with a
/// different access ALIAS to the same designated base (`Zipstream_Class_Access` vs
/// the lifecycle's `Memory_Zipstream_Access`) — by the designated base type. Only
/// the synthesizable constructor shapes pair: a nullary returning function
/// (`H := Create;`) or a one-parameter out-handle procedure (`Init (H);`); anything
/// needing config arguments is left to the null-handle decoder.
fn access_lifecycle_sink(
    ast: &StructuralAst,
    type_ref: &TypeRef,
    lifecycles: &[AdaAccessLifecycle],
) -> Option<AccessLifecycleSink> {
    let acc_decl = find_access_type_decl(ast, type_ref)?;
    let param_leaf = leaf_lower(type_ref.name_path.last()?);
    let param_base = designated_subtype_mark(&acc_decl.constraints.0).map(|m| leaf_lower(&m));

    let lc = lifecycles.iter().find(|lc| {
        if lc.init.is_none() {
            return false;
        }
        let name_match = leaf_lower(&lc.access_type) == param_leaf;
        let base_match = match (&param_base, &lc.designated_base) {
            (Some(a), Some(b)) => *a == leaf_lower(b),
            _ => false,
        };
        name_match || base_match
    })?;

    let init = lc.init.as_ref()?;
    let init_path = ada_dotted_name(init);
    let init_stmt = if lc.init_returns_handle {
        if lc.init_param_count != 0 {
            return None;
        }
        format!("{{handle}} := {init_path};")
    } else {
        if lc.init_param_count != 1 {
            return None;
        }
        format!("{init_path} ({{handle}});")
    };
    let delete_stmt = lc.delete.as_ref().and_then(|d| {
        (lc.delete_param_count == 1).then(|| format!("{} ({{handle}});", ada_dotted_name(d)))
    });

    let mut extra_withs = Vec::new();
    for path in [Some(init), lc.delete.as_ref()].into_iter().flatten() {
        if let Some(unit) = subprogram_path_unit(path) {
            if !extra_withs.contains(&unit) {
                extra_withs.push(unit);
            }
        }
    }

    Some(AccessLifecycleSink {
        access_type: ada_type_name(type_ref),
        init_stmt,
        delete_stmt,
        extra_withs,
    })
}

/// The access type declaration backing `type_ref`: `type_ref` itself when it is
/// already resolved to `TypeKind::Access`, otherwise the matching `is access`
/// declaration found by name in the tree (a parameter of a private/cross-unit
/// access type may not resolve in place).
fn find_access_type_decl(ast: &StructuralAst, type_ref: &TypeRef) -> Option<TypeRef> {
    if matches!(type_ref.kind, TypeKind::Access { .. }) {
        return Some(type_ref.clone());
    }
    let leaf = type_ref.name_path.last()?.rsplit('.').next()?.trim();
    if leaf.is_empty() {
        return None;
    }
    ast.types
        .iter()
        .find(|t| {
            t.name_path
                .last()
                .is_some_and(|n| n.eq_ignore_ascii_case(leaf))
                && matches!(t.kind, TypeKind::Access { .. })
        })
        .cloned()
}

/// Extract the designated subtype mark from an access type's constraint text
/// (the parser stores `access X` / `access all X` / `access constant X` with the
/// leading `access` already removed, so the text is `X`, `all X`, `constant X`,
/// or `all X (lo .. hi)`). Returns the dotted subtype mark (`Stream_Element_Array`,
/// `Ada.Streams.Stream_Element_Array`).
fn designated_subtype_mark(constraints: &str) -> Option<String> {
    let mut rest = constraints.trim();
    for prefix in ["all ", "constant ", "not null "] {
        if let Some(stripped) = rest
            .strip_prefix(prefix)
            .or_else(|| rest.strip_prefix(&prefix.to_ascii_uppercase()))
        {
            rest = stripped.trim();
        }
    }
    // Drop a trailing index/discriminant constraint and any trailing words.
    let mark = rest
        .split(['(', ' ', '\t', '\n'])
        .next()
        .unwrap_or("")
        .trim();
    if mark.is_empty() || mark.eq_ignore_ascii_case("access") {
        return None;
    }
    Some(mark.to_owned())
}

/// Describe how to `new`-allocate the designated array named `mark`.
fn designated_array_spec(ast: &StructuralAst, mark: &str) -> Option<DesignatedArray> {
    let leaf = mark.rsplit('.').next().unwrap_or(mark).trim();
    // Predefined standard arrays (the common output-buffer idiom).
    match leaf.to_ascii_lowercase().as_str() {
        "stream_element_array" => {
            return Some(DesignatedArray {
                name: "Ada.Streams.Stream_Element_Array".to_owned(),
                index_first: Some("0".to_owned()),
                extra_withs: vec!["Ada.Streams".to_owned()],
                elem_default: Some("0"),
            })
        }
        "string" => {
            return Some(DesignatedArray {
                name: "String".to_owned(),
                index_first: Some("1".to_owned()),
                extra_withs: Vec::new(),
                elem_default: Some("' '"),
            })
        }
        "wide_string" => {
            return Some(DesignatedArray {
                name: "Wide_String".to_owned(),
                index_first: Some("1".to_owned()),
                extra_withs: Vec::new(),
                elem_default: Some("' '"),
            })
        }
        "wide_wide_string" => {
            return Some(DesignatedArray {
                name: "Wide_Wide_String".to_owned(),
                index_first: Some("1".to_owned()),
                extra_withs: Vec::new(),
                elem_default: Some("' '"),
            })
        }
        _ => {}
    }
    // A plain array type declared in the tree.
    let decl = ast.types.iter().find(|t| {
        t.name_path
            .last()
            .is_some_and(|n| n.eq_ignore_ascii_case(leaf))
            && matches!(t.kind, TypeKind::Array { .. })
    })?;
    let TypeKind::Array { bounds, .. } = &decl.kind else {
        return None;
    };
    let qualified = qualified_type_name_path(ast, decl);
    // Make the array type visible: with the qualified prefix (its package), if any.
    let extra_withs = if qualified.len() > 1 {
        vec![qualified[..qualified.len() - 1].join(".")]
    } else {
        Vec::new()
    };
    let name = ada_path(&qualified);
    // An unconstrained array (`array (Index range <>) of ...`) needs an index
    // constraint in the allocator; a constrained one is allocated as-is.
    let index_first = if bounds.contains("<>") {
        Some(array_index_first(bounds))
    } else {
        None
    };
    Some(DesignatedArray {
        name,
        index_first,
        extra_withs,
        // A tree array's element type is not resolved here, so no portable
        // default; an `access constant` of such an array falls back to bare null.
        elem_default: None,
    })
}

/// The `'First` expression for an unconstrained array's index, parsed from its
/// bounds text (`Positive range <>` -> `Positive'First`, `(Natural range <>)` ->
/// `Natural'First`). Falls back to `0` when no index subtype mark is recoverable.
fn array_index_first(bounds: &str) -> String {
    let cleaned = bounds.trim().trim_start_matches('(').trim();
    let mark = cleaned
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != '.');
    if mark.is_empty() || mark == "<>" {
        "0".to_owned()
    } else {
        format!("{mark}'First")
    }
}

/// Whether an external (not-in-source) base type name is a discrete type the
/// runtime makes available - so a local type derived from it can be decoded
/// with discrete attributes ('Val/'Pos) rather than skipped.
/// If an external derived-chain base is a known numeric type, the `ScalarKind`
/// to decode the *distinct* derived type as (keeping its own name). Covers the
/// `Interfaces` fixed-width integers/floats and the `Standard` numerics that
/// real Ada libraries derive size/offset/count types from.
fn external_base_scalar_kind(name_path: &[String]) -> Option<ScalarKind> {
    let leaf = name_path
        .iter()
        .next_back()
        .map(|s| s.to_ascii_lowercase())?;
    match leaf.as_str() {
        "integer_8"
        | "integer_16"
        | "integer_32"
        | "integer_64"
        | "unsigned_8"
        | "unsigned_16"
        | "unsigned_32"
        | "unsigned_64"
        | "integer"
        | "natural"
        | "positive"
        | "long_integer"
        | "short_integer"
        | "long_long_integer"
        | "short_short_integer"
        // Interfaces.C size/offset integer types real libraries derive size and
        // offset subtypes from (gnatcoll `File_Size is new Interfaces.C.size_t`).
        // The leaf is unambiguous (no Standard/Ada type shares it).
        | "size_t"
        | "ptrdiff_t" => Some(ScalarKind::Integer),
        "boolean" => Some(ScalarKind::Boolean),
        "character" | "wide_character" | "wide_wide_character" => Some(ScalarKind::Character),
        "ieee_float_32" | "ieee_float_64" | "float" | "long_float" | "short_float"
        | "long_long_float" => Some(ScalarKind::Float),
        _ => None,
    }
}

fn external_base_is_discrete(name_path: &[String]) -> bool {
    let dotted = name_path.join(".").to_ascii_lowercase();
    matches!(
        dotted.as_str(),
        "ada.streams.stream_io.file_mode"
            | "ada.text_io.file_mode"
            | "ada.direct_io.file_mode"
            | "ada.sequential_io.file_mode"
    )
}

fn resolve_type_ref(ast: &StructuralAst, type_ref: &TypeRef) -> TypeRef {
    let resolved_type = type_ref.clone();
    if let Some(declared_type) = find_declared_type(ast, type_ref) {
        let mut resolved_type = declared_type.clone();
        resolved_type.name_path = qualified_type_name_path(ast, declared_type);
        match resolve_derived_chain(ast, declared_type) {
            DerivedChainEnd::Resolved(base_type) => {
                resolved_type.kind = base_type.kind.clone();
            }
            DerivedChainEnd::External(external_name) => {
                if external_base_is_discrete(&external_name) {
                    // `type File_Mode is new Ada.Streams.Stream_IO.File_Mode` -
                    // a *distinct* discrete type derived from an external one.
                    // The local name is the one the declaration and call expect
                    // (a derived type is not its parent), so keep it; mark the
                    // resolved kind discrete so the decoder emits a 'Val/'Pos
                    // decode over the type's own range.
                    resolved_type.kind = TypeKind::Enum(vec!["__external_discrete".to_owned()]);
                } else if let Some(scalar) = external_base_scalar_kind(&external_name) {
                    // A distinct derived numeric type (`type Count is new
                    // Interfaces.Integer_64`, zip-ada `Unzip.Streams.Count`):
                    // KEEP its own qualified name — the function result /
                    // parameter expect `Count`, not `Integer_64`, and a derived
                    // type is not its base — but set the kind so the decoder
                    // emits an integer/float decode cast to that name.
                    resolved_type.kind = TypeKind::Scalar(scalar);
                } else if external_name.last().is_some_and(|name| {
                    matches!(
                        name.to_ascii_lowercase().as_str(),
                        "string" | "wide_string" | "wide_wide_string"
                    )
                }) {
                    // A subtype such as XMLAda's `Byte_Sequence is String`
                    // should take the normal string decode path. Keeping the
                    // stale Derived kind makes derived-base resolution fail
                    // before the distinctive Standard name is considered.
                    resolved_type.name_path = external_name;
                    resolved_type.kind = TypeKind::Unknown;
                } else {
                    // Chain bottomed out at a name we don't have an AST for
                    // (e.g. `subtype Byte_Access is Voidp;` where Voidp is
                    // `subtype Voidp is System.Address;`). Rewrite to the
                    // external base so builtin_named_type_neutral /
                    // last_type_name_is fallbacks can recognise it.
                    resolved_type.name_path = external_name;
                }
            }
            DerivedChainEnd::None => {}
        }
        // If the chain could not reduce the kind (it stayed Derived - e.g. the
        // loose name match in resolve_derived_chain looped a `type X is new
        // Ext.X` back onto itself), recover the discrete case directly from the
        // declared constraint: `type File_Mode is new Stream_IO.File_Mode` is a
        // distinct discrete type we can decode with attributes on its own name.
        if matches!(resolved_type.kind, TypeKind::Derived { .. }) {
            if let Some(base) = derived_base_name(&declared_type.constraints.0) {
                if external_base_is_discrete(&base) {
                    resolved_type.kind = TypeKind::Enum(vec!["__external_discrete".to_owned()]);
                }
            }
        }
        return resolved_type;
    }

    resolved_type
}

enum DerivedChainEnd<'a> {
    /// Chain terminated at a fully-described TypeRef that lives in \`ast.types\`.
    Resolved(&'a TypeRef),
    /// Chain pointed past \`ast.types\` to a name the parser never saw a
    /// declaration for. The name is the last constraint hop along the chain.
    External(Vec<String>),
    /// Chain could not be followed at all (input wasn't a derived/subtype).
    None,
}

fn servant_receiver_type_name(
    ast: &StructuralAst,
    target: &Subprogram,
    receiver: &Parameter,
) -> Result<String, HarnessGenError> {
    if receiver.type_ref.name_path.len() == 1 {
        if let SubprogramOwner::Package(package_id) = target.owner {
            let package = ast
                .packages
                .iter()
                .find(|package| package.id == package_id)
                .ok_or_else(|| HarnessGenError::TargetNotFound(target.name.clone()))?;
            return Ok(format!(
                "{}.{}",
                ada_dotted_name(&package.name),
                ada_name(&receiver.type_ref.name_path[0])
            ));
        }
    }

    Ok(ada_type_name(&receiver.type_ref))
}

fn find_declared_type<'a>(ast: &'a StructuralAst, type_ref: &TypeRef) -> Option<&'a TypeRef> {
    ast.types.iter().find(|declared_type| {
        type_path_matches(
            &qualified_type_name_path(ast, declared_type),
            &type_ref.name_path,
        )
    })
}

fn resolve_derived_chain<'a>(ast: &'a StructuralAst, type_ref: &'a TypeRef) -> DerivedChainEnd<'a> {
    if !matches!(type_ref.kind, TypeKind::Derived { .. }) {
        return DerivedChainEnd::None;
    }
    let mut current = type_ref;
    for _ in 0..16 {
        if !matches!(current.kind, TypeKind::Derived { .. }) {
            return DerivedChainEnd::Resolved(current);
        }
        let Some(base_name) = derived_base_name(&current.constraints.0) else {
            return DerivedChainEnd::Resolved(current);
        };
        match ast.types.iter().find(|candidate| {
            type_path_matches(&qualified_type_name_path(ast, candidate), &base_name)
        }) {
            Some(base) => current = base,
            None => return DerivedChainEnd::External(base_name),
        }
    }
    DerivedChainEnd::Resolved(current)
}

fn derived_base_name(constraints: &str) -> Option<Vec<String>> {
    // The constraint records the base type mark followed by an optional range
    // or index constraint, e.g. "Compression_Method range Reduce_1 .. Reduce_4"
    // or "Base (1 .. 4)". Keep only the base type mark: a `range` clause is
    // discarded here (splitting it on '.' would corrupt the `..` operator and
    // never match the declared base), and a parenthesised constraint is cut at
    // '('.
    let base = constraints
        .split_once('(')
        .map_or(constraints, |(base, _)| base);
    let base = match base.to_ascii_lowercase().find(" range ") {
        Some(idx) => &base[..idx],
        None => base,
    };
    let mut base = base.trim();
    // A subtype may add a null exclusion before the actual subtype mark:
    // `subtype Option_Ptr is not null General_Option_Ptr`. Following the
    // derived chain through the whole phrase loses the public subtype and emits
    // an invisible bare `General_Option_Ptr` in the harness. Strip only this Ada
    // qualifier and keep resolving to the declared access type.
    if base
        .get(.."not null ".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("not null "))
    {
        base = base["not null ".len()..].trim_start();
    }
    if base.is_empty() {
        return None;
    }
    Some(base.split('.').map(|part| part.trim().to_owned()).collect())
}

fn type_path_matches(candidate: &[String], requested: &[String]) -> bool {
    let candidate = split_name_path(candidate);
    let requested = split_name_path(requested);
    if candidate.is_empty() || requested.is_empty() {
        return false;
    }

    if candidate.len() == requested.len() {
        return candidate
            .iter()
            .zip(requested.iter())
            .all(|(left, right)| left.eq_ignore_ascii_case(right));
    }

    candidate
        .last()
        .zip(requested.last())
        .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn qualified_type_name_path(ast: &StructuralAst, type_ref: &TypeRef) -> Vec<String> {
    if type_ref.name_path.len() != 1 {
        return type_ref.name_path.clone();
    }

    match &type_ref.owner {
        TypeOwner::Package(package_id) => ast
            .packages
            .iter()
            .find(|package| package.id == *package_id)
            .map(|package| vec![package.name.clone(), type_ref.name_path[0].clone()])
            .unwrap_or_else(|| type_ref.name_path.clone()),
        TypeOwner::LibraryLevel | TypeOwner::Subprogram(_) => type_ref.name_path.clone(),
    }
}

fn ada_type_name(type_ref: &TypeRef) -> String {
    if !type_ref.name_path.is_empty() {
        return ada_path(&type_path_parts(type_ref));
    }

    match &type_ref.kind {
        TypeKind::Access { .. }
            if matches!(
                type_ref
                    .constraints
                    .0
                    .split_whitespace()
                    .next(),
                Some(word) if word.eq_ignore_ascii_case("function")
                    || word.eq_ignore_ascii_case("procedure")
            ) =>
        {
            format!("access {}", type_ref.constraints.0.trim())
        }
        TypeKind::Scalar(ScalarKind::Integer) => "Integer".to_owned(),
        TypeKind::Scalar(ScalarKind::Boolean) => "Boolean".to_owned(),
        TypeKind::Scalar(ScalarKind::Float) => "Float".to_owned(),
        _ => "Integer".to_owned(),
    }
}

fn target_unit_withs(
    ast: &StructuralAst,
    target: &Subprogram,
) -> Result<Vec<String>, HarnessGenError> {
    let mut withs = source_unit_withs(ast);

    match target.owner {
        SubprogramOwner::Package(package_id) => {
            // `with` the ROOT compilation unit — a nested package (`BZip2.CRC`)
            // is not itself with-able; you `with BZip2` and name `BZip2.CRC.X`.
            let root = package_root_name(ast, package_id)
                .ok_or_else(|| HarnessGenError::TargetNotFound(target.name.clone()))?;
            let normalized = ada_dotted_name(&root);
            if !is_template_provided_with(&normalized) {
                push_unique(&mut withs, normalized);
            }
        }
        SubprogramOwner::LibraryLevel => {
            // A library-level standalone subprogram IS its own compilation unit;
            // the harness must `with` it by name to call it
            // (`Set_Modification_Time_Gnat`).
            let normalized = ada_name(&target.name);
            if !is_template_provided_with(&normalized) {
                push_unique(&mut withs, normalized);
            }
        }
    }

    Ok(withs)
}

fn package_unit_withs(ast: &StructuralAst, package: &Package) -> Vec<String> {
    let mut withs = source_unit_withs(ast);
    push_unique(&mut withs, ada_dotted_name(&package.name));
    withs
}

fn source_unit_withs(ast: &StructuralAst) -> Vec<String> {
    let mut withs = Vec::new();
    for unit_ref in ast.units.iter().flat_map(|unit| unit.withs.iter()) {
        let normalized = ada_dotted_name(&unit_ref.name);
        if is_template_provided_with(&normalized) {
            continue;
        }
        push_unique(&mut withs, normalized);
    }
    withs
}

fn is_template_provided_with(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "ada.streams"
            | "ada.exceptions"
            | "interfaces"
            | "adafuzz.input"
            | "adafuzz.decode"
            | "adafuzz.probe"
    )
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(&value))
    {
        values.push(value);
    }
}

fn qualified_target_name(
    ast: &StructuralAst,
    target: &Subprogram,
) -> Result<String, HarnessGenError> {
    match target.owner {
        SubprogramOwner::LibraryLevel => Ok(ada_name(&target.name)),
        SubprogramOwner::Package(package_id) => {
            let full = package_full_name(ast, package_id)
                .ok_or_else(|| HarnessGenError::TargetNotFound(target.name.clone()))?;
            Ok(format!(
                "{}.{}",
                ada_dotted_name(&full),
                ada_name(&target.name)
            ))
        }
    }
}

/// Fully-qualified dotted name of a package, walking the parent chain so a
/// nested package resolves to its full path (`bzip2.crc`, not just `crc`).
fn package_full_name(ast: &StructuralAst, package_id: PackageId) -> Option<String> {
    let mut parts = Vec::new();
    let mut current = Some(package_id);
    while let Some(id) = current {
        let package = ast.packages.iter().find(|p| p.id == id)?;
        parts.push(package.name.clone());
        current = package.parent;
    }
    parts.reverse();
    Some(parts.join("."))
}

/// The compilation unit a parameter's qualified type name must be `with`ed
/// under, or `None` when no extra `with` is needed. Parser name paths may arrive
/// component-wise or as one dotted component, so normalize them first. Preserve
/// child compilation units represented by a dotted package name (`Crypto.Types.
/// Dword` -> `with Crypto.Types;`), while a true nested package represented by a
/// parent link still resolves to its with-able root (`BZip2.CRC.X` -> `BZip2`).
/// Returns `None` for an unqualified/external type or a private package that a
/// root harness cannot legally `with`.
fn param_type_unit_with(ast: &StructuralAst, name_path: &[String]) -> Option<String> {
    let parts = split_name_path(name_path);
    if parts.len() < 2 {
        return None;
    }
    let package_path = parts[..parts.len() - 1].join(".");
    let immediate = parts[parts.len() - 2].trim_matches('.');
    let pkg = ast
        .packages
        .iter()
        .find(|p| {
            p.name.eq_ignore_ascii_case(&package_path)
                || package_full_name(ast, p.id)
                    .is_some_and(|name| name.eq_ignore_ascii_case(&package_path))
        })
        // Older AST fixtures may only retain the immediate package component.
        .or_else(|| {
            ast.packages
                .iter()
                .find(|p| p.name.eq_ignore_ascii_case(immediate))
        })?;
    if pkg.is_private {
        return None;
    }
    let root = package_root(ast, pkg.id)?;
    // A private compilation unit cannot be named in a root harness's `with`.
    if root.is_private {
        return None;
    }
    if pkg.parent.is_none() && pkg.name.contains('.') {
        Some(ada_dotted_name(&pkg.name))
    } else {
        Some(ada_dotted_name(&root.name))
    }
}

/// The top-level (root) ancestor `Package` — the only `with`-able unit for a
/// nested package (`BZip2` for a target in `BZip2.CRC`).
fn package_root(ast: &StructuralAst, package_id: PackageId) -> Option<&Package> {
    let mut current = package_id;
    loop {
        let package = ast.packages.iter().find(|p| p.id == current)?;
        match package.parent {
            Some(parent) => current = parent,
            None => return Some(package),
        }
    }
}

fn package_root_name(ast: &StructuralAst, package_id: PackageId) -> Option<String> {
    package_root(ast, package_id).map(|package| package.name.clone())
}

fn display_target_name(ast: &StructuralAst, target: &Subprogram) -> String {
    qualified_target_name(ast, target).unwrap_or_else(|_| ada_name(&target.name))
}

fn ada_path(parts: &[String]) -> String {
    parts
        .iter()
        .map(|part| ada_name(part))
        .collect::<Vec<_>>()
        .join(".")
}

fn type_path_parts(type_ref: &TypeRef) -> Vec<String> {
    split_name_path(&type_ref.name_path)
}

fn split_name_path(parts: &[String]) -> Vec<String> {
    parts
        .iter()
        .map(|part| strip_inline_constraint(part))
        .flat_map(|part| {
            part.split('.')
                .filter(|part| !part.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// A name-path component can carry an inline subtype constraint, e.g.
/// `Integer_M32 range 0 .. Integer_M32'Last` (an anonymous subtype used
/// directly as a parameter or return type mark). The `..` range operator must
/// not survive into a dotted type name: splitting it on '.' corrupts it into a
/// malformed real literal (`0.`), and the constraint also blocks matching the
/// base type during resolution. Keep only the base type mark.
fn strip_inline_constraint(part: &str) -> String {
    let lower = part.to_ascii_lowercase();
    match lower.find(" range ") {
        Some(idx) => part[..idx].trim().to_owned(),
        None => part.to_owned(),
    }
}

fn ada_dotted_name(name: &str) -> String {
    name.split('.').map(ada_name).collect::<Vec<_>>().join(".")
}

/// Prefix a harness local's type with `aliased` when the formal it materializes
/// is an `aliased` formal — Ada requires the actual passed to an `aliased` formal
/// to itself be an aliased object. Read from the ORIGINAL formal's type_ref
/// aspects (the resolved type_ref drops them). `aliased` follows the colon in an
/// object declaration (`Line : aliased String := ...`), which is exactly the
/// template position `ada_type_name` occupies.
fn aliased_local_type(param: &Parameter, base_type: String) -> String {
    if param.type_ref.aspects.0.iter().any(|a| a == "aliased") {
        format!("aliased {base_type}")
    } else {
        base_type
    }
}

fn ada_name(name: &str) -> String {
    if name.chars().any(|ch| ch.is_ascii_uppercase()) {
        return name.to_owned();
    }

    let mut rendered = String::with_capacity(name.len());
    let mut capitalize_next = true;
    for ch in name.chars() {
        if ch == '_' {
            rendered.push(ch);
            capitalize_next = true;
        } else if capitalize_next {
            rendered.push(ch.to_ascii_uppercase());
            capitalize_next = false;
        } else {
            rendered.push(ch);
        }
    }
    rendered
}

fn harness_project_name(harness_id: &str) -> String {
    harness_id
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

fn target_id_hex(target: &Subprogram) -> String {
    format!("16#{:04X}#", target.id.0 & 0xFFFF)
}

fn package_id_hex(package: &Package) -> String {
    format!("16#{:04X}#", package.id.0 & 0xFFFF)
}

fn ada_runtime_gpr_path(output_dir: &Path) -> Result<String, HarnessGenError> {
    let runtime_gpr = locate_ada_runtime_dir().join("adafuzz.gpr");
    let output_dir = absolutize(output_dir)?;
    Ok(path_string(&relative_path(&output_dir, &runtime_gpr)))
}

fn project_import_paths(
    output_dir: &Path,
    project_imports: &[PathBuf],
) -> Result<Vec<String>, HarnessGenError> {
    let output_dir = absolutize(output_dir)?;
    project_imports
        .iter()
        .map(|project| {
            let abs_project = absolutize(project)?;
            Ok(path_string(&relative_path(&output_dir, &abs_project)))
        })
        .collect()
}

fn project_source_dirs(
    source_path: &Path,
    source_roots: &[PathBuf],
    include_target_source_dir: bool,
) -> Result<Vec<String>, HarnessGenError> {
    let runtime_owned = ada_runtime_owned_dirs();
    let mut dirs = vec![".".to_owned()];
    if include_target_source_dir {
        let target_dir = target_source_dir(source_path)?;
        let target_dir_abs = absolutize(Path::new(&target_dir))?;
        let target_is_runtime = runtime_owned
            .iter()
            .any(|owned| path_contains_or_equals(owned, &target_dir_abs));
        if !target_is_runtime
            && !dirs
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&target_dir))
        {
            dirs.push(target_dir);
        }
    }
    for root in source_roots {
        let abs_root = normalize_path(&absolutize(root)?);
        if runtime_owned
            .iter()
            .any(|owned| path_contains_or_equals(owned, &abs_root))
        {
            continue;
        }
        let rendered = path_string(&abs_root);
        if !dirs
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&rendered))
        {
            dirs.push(rendered);
        }
    }
    Ok(dirs)
}

fn ada_runtime_owned_dirs() -> Vec<PathBuf> {
    vec![locate_ada_runtime_dir()]
}

fn locate_ada_runtime_dir() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent().map(Path::to_path_buf);
        for _ in 0..6 {
            if let Some(d) = &dir {
                let cand = d.join("ada_runtime");
                if cand.join("adafuzz.gpr").is_file() {
                    return normalize_path(&cand);
                }
                dir = d.parent().map(Path::to_path_buf);
            }
        }
    }
    normalize_path(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).join("ada_runtime")
}

fn path_contains_or_equals(parent: &Path, candidate: &Path) -> bool {
    let parent = normalize_path(parent);
    let candidate = normalize_path(candidate);
    candidate == parent || candidate.starts_with(&parent)
}

fn target_source_dir(source_path: &Path) -> Result<String, HarnessGenError> {
    let source_dir = source_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    Ok(path_string(&normalize_path(&absolutize(&source_dir)?)))
}

fn absolutize(path: &Path) -> Result<PathBuf, HarnessGenError> {
    if path.is_absolute() {
        Ok(normalize_path(path))
    } else {
        Ok(normalize_path(&std::env::current_dir()?.join(path)))
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push("..");
                }
            }
            Component::Normal(part) => normalized.push(part),
            Component::RootDir | Component::Prefix(_) => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

fn relative_path(from_dir: &Path, target: &Path) -> PathBuf {
    let from_abs = from_dir.is_absolute();
    let target_abs = target.is_absolute();
    if from_abs != target_abs {
        return target.to_path_buf();
    }

    let from_parts = normal_components(from_dir);
    let target_parts = normal_components(target);
    let common = from_parts
        .iter()
        .zip(target_parts.iter())
        .take_while(|(left, right)| left == right)
        .count();

    let mut relative = PathBuf::new();
    for _ in common..from_parts.len() {
        relative.push("..");
    }
    for part in target_parts.iter().skip(common) {
        relative.push(part);
    }

    if relative.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        relative
    }
}

fn normal_components(path: &Path) -> Vec<OsString> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_os_string()),
            _ => None,
        })
        .collect()
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::{
        generate_direct_harness, generate_servant_direct_harness, out_param_receiver_matches,
        GenerateDirectArgs, GenerateServantDirectArgs,
    };
    use crate::HarnessGenError;
    use ada_parser::ast::{
        AdaStandard, Aspects, Constraints, Expr, Package, PackageId, ParamMode, Parameter,
        ScalarKind, Span, StructuralAst, Subprogram, SubprogramId, SubprogramKind, SubprogramOwner,
        TypeId, TypeKind, TypeOwner, TypeRef, Unit, UnitId, UnitKind, UnitRef, Visibility,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-harness-gen-{name}-{nonce}"));
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

    #[test]
    fn external_base_scalar_kind_recognizes_interfaces_c_size_offset_types() {
        // `File_Size is new Interfaces.C.size_t` / `... ptrdiff_t` must be treated
        // as a derived integer scalar (keeping its own name `File_Size`), not
        // rewritten to the base `Interfaces.C.Size_T` which mismatches the call.
        use ada_parser::ast::ScalarKind;
        assert_eq!(
            super::external_base_scalar_kind(&["Interfaces".into(), "C".into(), "size_t".into()]),
            Some(ScalarKind::Integer)
        );
        assert_eq!(
            super::external_base_scalar_kind(&[
                "Interfaces".into(),
                "C".into(),
                "ptrdiff_t".into()
            ]),
            Some(ScalarKind::Integer)
        );
        assert_eq!(
            super::external_base_scalar_kind(&["System".into(), "Address".into()]),
            None
        );
    }

    #[test]
    fn standard_library_parent_unit_derives_with_clause() {
        // A qualified standard-library type needs its parent unit `with`ed
        // (gnatcoll base64_encode returns Ada.Strings.Unbounded.Unbounded_String
        // but the harness never `with Ada.Strings.Unbounded;`).
        assert_eq!(
            super::standard_library_parent_unit("Ada.Strings.Unbounded.Unbounded_String"),
            Some("Ada.Strings.Unbounded".to_owned())
        );
        assert_eq!(
            super::standard_library_parent_unit("Interfaces.C.Size_T"),
            Some("Interfaces.C".to_owned())
        );
        // In-tree / Standard types contribute no library with.
        assert_eq!(super::standard_library_parent_unit("Integer"), None);
        assert_eq!(
            super::standard_library_parent_unit("Sdpcm.Packets.Packet"),
            None
        );
    }

    #[test]
    fn nested_package_type_is_qualified_for_root_harness() {
        let root = package(1, "GNATCOLL.OS.Process");
        let mut nested = package(2, "Arg_Lists");
        nested.parent = Some(PackageId(1));
        let mut ast = StructuralAst::new();
        ast.packages = vec![root, nested];
        let mut vector = type_ref("Arg_Lists.Vector", TypeKind::Unknown);

        super::qualify_nested_package_type(&ast, &mut vector);

        assert_eq!(
            vector.name_path,
            vec!["GNATCOLL", "OS", "Process", "Arg_Lists", "Vector"]
        );
    }

    #[test]
    fn local_generic_container_type_is_qualified_through_target_package() {
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(1)),
            "Run",
            Vec::new(),
            None,
        );
        let mut ast = StructuralAst::new();
        ast.packages = vec![package(1, "GNATCOLL.OS.Process")];
        let mut vector = type_ref("Arg_Lists.Vector", TypeKind::Unknown);

        super::qualify_local_container_instance_type(&ast, &target, &mut vector);

        assert_eq!(
            vector.name_path,
            vec!["GNATCOLL", "OS", "Process", "Arg_Lists", "Vector"]
        );
    }

    #[test]
    fn local_generic_instance_is_default_declared() {
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(1)),
            "Validate",
            vec![param(
                "Table",
                "Simple_Type_Tables.Instance",
                TypeKind::Unknown,
            )],
            None,
        );
        let ast = ast_with(
            target.clone(),
            Vec::new(),
            vec![package(1, "Schema.Simple_Types")],
        );
        let output_dir = temp_dir("generic-instance").join("H-GENERIC-INSTANCE");

        let main_adb =
            fs::read_to_string(generate_for(&ast, &target, &output_dir).unwrap().main_adb).unwrap();

        assert!(main_adb.contains("Table : Schema.Simple_Types.Simple_Type_Tables.Instance;"));
        assert!(main_adb.contains("Schema.Simple_Types.Validate (Table);"));
    }

    #[test]
    fn instance_qualified_name_path_rewrites_generic_local_types() {
        // A type declared inside the synthesised generic package must be named via
        // the instance (`Govfuzz_Generic_Instance.Word`), not the generic package
        // itself ("prefix must not be a generic package").
        let mut word = type_ref("Sdpcm.Generic_Spi.Word", TypeKind::Unknown);
        word.owner = TypeOwner::Package(PackageId(7));
        assert_eq!(
            super::instance_qualified_name_path(&word, PackageId(7)),
            Some(vec![
                "Govfuzz_Generic_Instance".to_owned(),
                "Word".to_owned()
            ])
        );
        // A type owned by a different package (the generic's parent, say) is left
        // alone — it is reached through its own `with`/`use`.
        let mut other = type_ref("Sdpcm.Packets.Frame_Tag", TypeKind::Unknown);
        other.owner = TypeOwner::Package(PackageId(3));
        assert_eq!(
            super::instance_qualified_name_path(&other, PackageId(7)),
            None
        );
    }

    #[test]
    fn instance_qualified_constructor_path_rewrites_generic_owned_ctors() {
        // A constructor declared in the instantiated generic package
        // (`Json.Types.Create_Null`) must be named through the instance — Ada
        // rejects naming it through the uninstantiated generic ("prefix must not
        // be a generic package"). Casing differs because the parser records the
        // generic unit lowercase but the ctor owner mixed-case; the match folds.
        assert_eq!(
            super::instance_qualified_constructor_path("Json.Types.Create_Null", "json.types"),
            Some("Govfuzz_Generic_Instance.Create_Null".to_owned())
        );
        // A constructor in a nested package under the generic keeps the trailing
        // path, only the generic prefix is swapped.
        assert_eq!(
            super::instance_qualified_constructor_path("Json.Types.Sub.Make", "Json.Types"),
            Some("Govfuzz_Generic_Instance.Sub.Make".to_owned())
        );
        // A constructor owned by a DIFFERENT package (the generic's parent, a
        // sibling) is left alone — it is reached through its own with/use.
        assert_eq!(
            super::instance_qualified_constructor_path("Json.Streams.Create", "json.types"),
            None
        );
        // The generic name must be a STRICT prefix: an exact match (no surviving
        // constructor leaf) is not a constructor path and must not be rewritten.
        assert_eq!(
            super::instance_qualified_constructor_path("Json.Types", "json.types"),
            None
        );
        // A library-level constructor (no package qualification) is untouched.
        assert_eq!(
            super::instance_qualified_constructor_path("Create_Null", "json.types"),
            None
        );
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

    fn ast_with(target: Subprogram, withs: Vec<&str>, packages: Vec<Package>) -> StructuralAst {
        StructuralAst {
            units: vec![Unit {
                id: UnitId(0),
                path: PathBuf::from("pkg.adb"),
                kind: UnitKind::Body,
                ada_standard: AdaStandard::Ada2012,
                withs: withs
                    .into_iter()
                    .map(|name| UnitRef {
                        name: name.to_owned(),
                    })
                    .collect(),
                uses: Vec::new(),
                packages: packages.iter().map(|package| package.id).collect(),
                pragmas: Vec::new(),
            }],
            packages,
            subprograms: vec![target],
            ..StructuralAst::new()
        }
    }

    fn generate_for(
        ast: &StructuralAst,
        target: &Subprogram,
        output_dir: &Path,
    ) -> Result<super::GeneratedFiles, HarnessGenError> {
        generate_direct_harness(GenerateDirectArgs {
            ast,
            target_subprogram: target,
            harness_id: "H-0042".to_owned(),
            output_dir: output_dir.to_path_buf(),
            source_path: PathBuf::from("src/pkg.adb"),
            source_roots: Vec::new(),
            project_imports: Vec::new(),
            generic_instance: None,
            generic_call: None,
            generic_suppress_params: false,
            child_harness_unit: None,
        })
    }

    #[test]
    fn generate_writes_main_adb_and_gpr() {
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Parse",
            vec![param("S", "String", TypeKind::Unknown)],
            Some(type_ref("Integer", TypeKind::Scalar(ScalarKind::Integer))),
        );
        let ast = ast_with(target.clone(), Vec::new(), vec![package(7, "Pkg")]);
        let output_dir = temp_dir("writes").join("H-0042");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();

        assert!(generated.main_adb.exists());
        assert!(generated.gpr.exists());
    }

    #[test]
    fn aliased_formal_local_is_declared_aliased() {
        // `procedure Run (Line : aliased String; ...)` (ada_drivers Command_Line.Run):
        // the harness local must be `Line : aliased String := ...`, else gprbuild
        // rejects "actual for aliased formal must be aliased object".
        let mut line = param("Line", "String", TypeKind::Unknown);
        line.type_ref.aspects.0.push("aliased".to_owned());
        let target = subprogram(1, SubprogramOwner::LibraryLevel, "Run", vec![line], None);
        let ast = ast_with(target.clone(), Vec::new(), Vec::new());
        let output_dir = temp_dir("aliased").join("H-0042");

        generate_for(&ast, &target, &output_dir).unwrap();
        let main = std::fs::read_to_string(output_dir.join("main.adb")).unwrap();
        assert!(
            main.contains("Line : aliased String :="),
            "expected an aliased local, got:\n{main}"
        );
    }

    #[test]
    fn generate_creates_output_dir_if_missing() {
        let target = subprogram(1, SubprogramOwner::LibraryLevel, "Run", Vec::new(), None);
        let ast = ast_with(target.clone(), Vec::new(), Vec::new());
        let output_dir = temp_dir("missing").join("nested").join("H-0042");

        generate_for(&ast, &target, &output_dir).unwrap();

        assert!(output_dir.is_dir());
    }

    #[test]
    fn generate_returns_unsupported_for_private_param_without_constructor() {
        // A private type with no constructor in the parsed set is genuinely
        // un-synthesizable. (An empty record, which used to land here, is now
        // decodable as `T'(null record)`.)
        let target = subprogram(
            1,
            SubprogramOwner::LibraryLevel,
            "Run",
            vec![param("H", "Opaque_Handle", TypeKind::Private)],
            None,
        );
        let ast = ast_with(target.clone(), Vec::new(), Vec::new());
        let output_dir = temp_dir("unsupported").join("H-0042");

        let error = generate_for(&ast, &target, &output_dir).unwrap_err();

        assert!(matches!(error, HarnessGenError::UnsupportedParamType(_)));
        assert!(error.to_string().contains("Opaque_Handle"));
    }

    #[test]
    fn generate_unsupported_param_error_names_target_param_and_recovery_paths() {
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Run",
            vec![param(
                "Parser",
                "Gnatcoll.Json.Json_Parser",
                TypeKind::Tagged {
                    base: TypeId(2),
                    is_abstract: false,
                },
            )],
            None,
        );
        let ast = ast_with(target.clone(), Vec::new(), vec![package(7, "Pkg")]);
        let output_dir = temp_dir("unsupported-param-context").join("H-0042");

        let error = generate_for(&ast, &target, &output_dir).unwrap_err();
        let message = error.to_string();

        assert!(matches!(error, HarnessGenError::UnsupportedParamType(_)));
        assert!(message.contains("target 'Pkg.Run'"));
        assert!(message.contains("parameter 'Parser'"));
        assert!(message.contains("Gnatcoll.Json.Json_Parser"));
        assert!(message.contains("constructor"));
        assert!(message.contains("source roots"));
        assert!(message.contains("sequence or servant harness"));
    }

    #[test]
    fn generate_with_array_param_emits_setup_lines_in_template() {
        let target = subprogram(
            1,
            SubprogramOwner::LibraryLevel,
            "Run",
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
        let ast = ast_with(target.clone(), Vec::new(), Vec::new());
        let output_dir = temp_dir("array-setup").join("H-0042");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(main_adb.contains(
            "Len_Items : constant Natural := AdaFuzz.Decode.Bounded_Length (Cur, 0, 16);"
        ));
        assert!(main_adb.contains("Items : Int_Array := Decode_Items;"));
    }

    #[test]
    fn generate_direct_harness_initializes_class_wide_stream_param_from_byte_initializer() {
        // A target taking `Root_Zipstream_Type'Class` (recorded by the parser as
        // a path ending in "class") is harnessed by declaring the concrete
        // Memory_Zipstream and loading it from the fuzz input via Set.
        let stream_param = Parameter {
            name: "Stream".to_owned(),
            mode: ParamMode::InOut,
            type_ref: TypeRef {
                id: TypeId(9),
                name_path: vec!["root_zipstream_type.".to_owned(), "class".to_owned()],
                visibility: Visibility::Public,
                owner: TypeOwner::LibraryLevel,
                kind: TypeKind::Unknown,
                constraints: Constraints(String::new()),
                aspects: Aspects(Vec::new()),
            },
            default: None,
        };
        let target = subprogram(
            1,
            SubprogramOwner::LibraryLevel,
            "Read_And_Check",
            vec![stream_param],
            None,
        );
        let concrete = TypeRef {
            id: TypeId(10),
            name_path: vec!["zip_streams".to_owned(), "memory_zipstream".to_owned()],
            visibility: Visibility::Public,
            owner: TypeOwner::LibraryLevel,
            kind: TypeKind::Derived { base: TypeId(0) },
            constraints: Constraints("Root_Zipstream_Type".to_owned()),
            aspects: Aspects(Vec::new()),
        };
        let set = subprogram(
            2,
            SubprogramOwner::Package(PackageId(0)),
            "Set",
            vec![
                param_with_mode(
                    "Str",
                    "memory_zipstream",
                    TypeKind::Unknown,
                    ParamMode::InOut,
                ),
                param_with_mode(
                    "Unb",
                    "ada.strings.unbounded.unbounded_string",
                    TypeKind::Unknown,
                    ParamMode::In,
                ),
            ],
            None,
        );
        let ast = StructuralAst {
            packages: vec![package(0, "zip_streams")],
            subprograms: vec![target.clone(), set],
            types: vec![concrete],
            ..StructuralAst::new()
        };
        let output_dir = temp_dir("class-wide-stream").join("H-0042");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(
            main_adb.contains("Stream : Zip_Streams.Memory_Zipstream;"),
            "should declare concrete stream without initializer:\n{main_adb}"
        );
        assert!(
            main_adb.contains("Zip_Streams.Set (Stream, Ada.Strings.Unbounded.To_Unbounded_String"),
            "should load the stream from the fuzz input before the call:\n{main_adb}"
        );
        assert!(
            main_adb.contains("with Zip_Streams;"),
            "should with the concrete type's package:\n{main_adb}"
        );
        assert!(
            main_adb.contains("Read_And_Check (Stream)"),
            "should pass the concrete stream to the target:\n{main_adb}"
        );
    }

    #[test]
    fn generate_with_no_compound_params_omits_setup_section() {
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
        let ast = ast_with(target.clone(), Vec::new(), Vec::new());
        let output_dir = temp_dir("no-setup").join("H-0042");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(!main_adb.contains("Tmp_Count"));
        assert!(!main_adb.contains("Len_Count"));
    }

    #[test]
    fn generate_direct_harness_initializes_out_and_inout_by_mode() {
        let target = subprogram(
            1,
            SubprogramOwner::LibraryLevel,
            "Run",
            vec![
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
        let ast = ast_with(target.clone(), Vec::new(), Vec::new());
        let output_dir = temp_dir("direct-param-modes").join("H-0042");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(main_adb.contains("Out_Count : Integer := Integer'First;"));
        assert!(main_adb.contains("Inout_Count : Integer := Integer (AdaFuzz.Decode.I32 (Cur));"));
        assert!(main_adb.contains("Run (Out_Count, Inout_Count);"));
    }

    #[test]
    fn generate_direct_harness_initializes_out_array_with_neutral_buffer() {
        let target = subprogram(
            1,
            SubprogramOwner::LibraryLevel,
            "Fill",
            vec![param_with_mode(
                "B",
                "Bool_Array",
                TypeKind::Array {
                    idx_types: vec![TypeId(2)],
                    elem_type: TypeId(3),
                    bounds: "Positive range <>".to_owned(),
                    elem_name: String::new(),
                },
                ParamMode::Out,
            )],
            None,
        );
        let ast = ast_with(target.clone(), Vec::new(), Vec::new());
        let output_dir = temp_dir("out-array-unsupported").join("H-0042");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(main_adb.contains("function Decode_B return Bool_Array is"));
        assert!(main_adb.contains("Tmp_B : Bool_Array (1 .. 16) := (others => 0);"));
    }

    #[test]
    fn generate_servant_direct_accepts_inout_receiver_and_out_param() {
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
                param_with_mode("Self", "Servant", TypeKind::Unknown, ParamMode::InOut),
                param_with_mode(
                    "Out_Count",
                    "Integer",
                    TypeKind::Scalar(ScalarKind::Integer),
                    ParamMode::Out,
                ),
            ],
            None,
        );
        let mut ast = ast_with(target.clone(), Vec::new(), vec![bar_impl]);
        ast.types.push(servant_type);
        let output_dir = temp_dir("servant-param-modes").join("H-M12");

        let generated = generate_servant_direct_harness(GenerateServantDirectArgs {
            ast: &ast,
            target_subprogram: &target,
            harness_id: "H-M12".to_owned(),
            output_dir,
            source_path: PathBuf::from("src/bar_impl.adb"),
            source_roots: Vec::new(),
            project_imports: Vec::new(),
        })
        .unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(main_adb.contains("Server : Bar_Impl.Servant;"));
        assert!(main_adb.contains("Out_Count : Integer := Integer'First;"));
        assert!(main_adb.contains("Bar_Impl.Compute (Server, Out_Count);"));
    }

    #[test]
    fn generate_with_multiple_compound_params_concatenates_setup() {
        let target = subprogram(
            1,
            SubprogramOwner::LibraryLevel,
            "Run",
            vec![
                param(
                    "Items",
                    "Int_Array",
                    TypeKind::Array {
                        idx_types: vec![TypeId(2)],
                        elem_type: TypeId(3),
                        bounds: "Positive range <>".to_owned(),
                        elem_name: String::new(),
                    },
                ),
                param("Node", "Node_Ptr", TypeKind::Access { target: TypeId(4) }),
            ],
            None,
        );
        let ast = ast_with(target.clone(), Vec::new(), Vec::new());
        let output_dir = temp_dir("multi-setup").join("H-0042");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        let array_pos = main_adb.find("Len_Items : constant Natural").unwrap();
        let access_pos = main_adb.find("Slots_Node : array (1 .. 4)").unwrap();
        assert!(array_pos < access_pos);
        assert!(main_adb.contains("Items : Int_Array := Decode_Items;"));
        assert!(main_adb.contains("Node : Node_Ptr := Decode_Node;"));
    }

    /// An access TypeRef carrying the designated subtype mark in its constraint,
    /// the way the parser records `type T_Access is access [all] Designated;`.
    fn access_type_ref(name: &str, designated: &str) -> TypeRef {
        let mut tr = type_ref(name, TypeKind::Access { target: TypeId(0) });
        tr.constraints = Constraints(designated.to_owned());
        tr
    }

    #[test]
    fn access_handle_with_lifecycle_emits_create_call_destroy_sequence() {
        // #457: a target taking an access-type opaque handle (`Feed (H :
        // Widget_Access; ..)`) whose type has a Create/Destroy lifecycle must build
        // the handle through Create, pass it, and tear it down with Destroy —
        // instead of passing the null/slot value.
        let target = subprogram(
            1,
            SubprogramOwner::LibraryLevel,
            "Feed",
            vec![
                access_param("Handle", "Widget_Access", "Widget", ParamMode::In),
                param(
                    "B",
                    "Interfaces.Unsigned_8",
                    TypeKind::Scalar(ScalarKind::Modular),
                ),
            ],
            None,
        );
        let create = subprogram(
            2,
            SubprogramOwner::LibraryLevel,
            "Create",
            Vec::new(),
            Some(access_type_ref("Widget_Access", "Widget")),
        );
        let mut destroy = subprogram(
            3,
            SubprogramOwner::LibraryLevel,
            "Destroy",
            vec![Parameter {
                name: "H".to_owned(),
                mode: ParamMode::InOut,
                type_ref: access_type_ref("Widget_Access", "Widget"),
                default: None,
            }],
            None,
        );
        destroy.kind = ada_parser::ast::SubprogramKind::Procedure;
        let mut ast = ast_with(target.clone(), Vec::new(), Vec::new());
        ast.subprograms.push(create);
        ast.subprograms.push(destroy);
        let output_dir = temp_dir("access-lifecycle").join("H-0042");

        let main_adb =
            fs::read_to_string(generate_for(&ast, &target, &output_dir).unwrap().main_adb).unwrap();

        // The handle is declared bare (not `:= <null/slot decoder>`) and constructed
        // via Create before the call.
        assert!(
            main_adb.contains("Handle : Widget_Access;"),
            "handle must be declared bare for lifecycle construction:\n{main_adb}"
        );
        assert!(
            !main_adb.contains("Slots_Handle"),
            "the null/slot decoder must not be used when a lifecycle exists:\n{main_adb}"
        );
        let create_pos = main_adb.find("Handle := Create;").expect("Create init");
        let call_pos = main_adb.find("Feed (Handle, ").expect("target call");
        let destroy_pos = main_adb.find("Destroy (Handle);").expect("Destroy cleanup");
        assert!(
            create_pos < call_pos && call_pos < destroy_pos,
            "expected Create -> call -> Destroy ordering; create={create_pos} call={call_pos} \
             destroy={destroy_pos}:\n{main_adb}"
        );
    }

    #[test]
    fn access_handle_lifecycle_pairs_via_designated_base_across_aliases() {
        // #457 designated-base resolution: the target parameter is spelled with a
        // DIFFERENT access alias (`Widget_Handle`) than the lifecycle's
        // (`Widget_Access`), but both designate `Widget` — they must still pair.
        let target = subprogram(
            1,
            SubprogramOwner::LibraryLevel,
            "Use_Handle",
            vec![access_param("H", "Widget_Handle", "Widget", ParamMode::In)],
            None,
        );
        let create = subprogram(
            2,
            SubprogramOwner::LibraryLevel,
            "Create",
            Vec::new(),
            Some(access_type_ref("Widget_Access", "Widget")),
        );
        let mut ast = ast_with(target.clone(), Vec::new(), Vec::new());
        ast.subprograms.push(create);
        let output_dir = temp_dir("access-lifecycle-base").join("H-0042");

        let main_adb =
            fs::read_to_string(generate_for(&ast, &target, &output_dir).unwrap().main_adb).unwrap();

        assert!(
            main_adb.contains("H := Create;"),
            "a cross-alias handle must still pair via its designated base:\n{main_adb}"
        );
    }

    #[test]
    fn type_name_strips_inline_range_constraint_so_dotdot_is_not_corrupted() {
        // An anonymous constrained subtype used as a type mark, e.g. a function
        // returning `Integer_M32 range 0 .. Integer_M32'Last`. Splitting the
        // name path on '.' would turn the `..` range operator into `.`, leaving
        // `0.` — a malformed real literal GNAT rejects. Only the base type mark
        // must survive into the rendered type name.
        let type_ref = TypeRef {
            id: TypeId(1),
            name_path: vec!["Integer_M32 range 0 .. Integer_M32'Last".to_owned()],
            visibility: Visibility::Public,
            owner: TypeOwner::LibraryLevel,
            kind: TypeKind::Unknown,
            constraints: Constraints(String::new()),
            aspects: Aspects(Vec::new()),
        };
        let rendered = super::ada_type_name(&type_ref);
        assert_eq!(rendered, "Integer_M32");
        assert!(
            !rendered.contains("0."),
            "range operator must not collapse into a real literal: {rendered}"
        );
    }

    #[test]
    fn derived_base_name_strips_null_exclusion_from_subtype_mark() {
        assert_eq!(
            super::derived_base_name("not null General_Option_Ptr"),
            Some(vec!["General_Option_Ptr".to_owned()])
        );
    }

    #[test]
    fn generate_decodes_type_derived_from_external_discrete() {
        // `type File_Mode is new Ada.Streams.Stream_IO.File_Mode` - a distinct
        // discrete type whose base is external. The decoder must emit a 'Val
        // decode on the *local* type (not skip, and not rewrite to the external
        // base, which would break the call's type).
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Open",
            vec![param("Mode", "File_Mode", TypeKind::Unknown)],
            None,
        );
        let mut ast = ast_with(target.clone(), Vec::new(), vec![package(7, "Streams")]);
        ast.types.push(TypeRef {
            id: TypeId(10),
            name_path: vec!["File_Mode".to_owned()],
            visibility: Visibility::Public,
            owner: TypeOwner::Package(PackageId(7)),
            kind: TypeKind::Derived { base: TypeId(11) },
            constraints: Constraints("Ada.Streams.Stream_IO.File_Mode".to_owned()),
            aspects: Aspects(Vec::new()),
        });
        let output_dir = temp_dir("ext-discrete").join("H-FM");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(
            main_adb.contains("File_Mode'Val") && !main_adb.contains("Stream_IO.File_Mode'Val"),
            "derived external-discrete type must decode on its local name: {main_adb}"
        );
    }

    #[test]
    fn generate_uses_out_param_constructor_for_stateful_type() {
        // `procedure Use_It (Info : Zip_Info)` where Zip_Info is private and the
        // decoder cannot build it. A sibling `procedure Load (Info : out
        // Zip_Info; Seed : Integer)` is the out-parameter constructor: the
        // harness must declare the object, fill it via Load from the fuzz
        // input, and pass it to the target instead of skipping.
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Use_It",
            vec![param("Info", "Zip_Info", TypeKind::Private)],
            None,
        );
        let loader = subprogram(
            2,
            SubprogramOwner::Package(PackageId(7)),
            "Load",
            vec![
                param_with_mode("Info", "Zip_Info", TypeKind::Private, ParamMode::Out),
                param_with_mode(
                    "Seed",
                    "Integer",
                    TypeKind::Scalar(ScalarKind::Integer),
                    ParamMode::In,
                ),
            ],
            None,
        );
        let mut ast = ast_with(target.clone(), Vec::new(), vec![package(7, "Zip")]);
        ast.subprograms.push(loader);
        let output_dir = temp_dir("out-param-ctor").join("H-CTOR");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(
            main_adb.contains("Zip.Load (Info, Integer (AdaFuzz.Decode.I32 (Cur)));"),
            "expected out-parameter constructor call before target: {main_adb}"
        );
        assert!(
            main_adb.contains("Use_It (Info)") || main_adb.contains("Zip.Use_It (Info)"),
            "target must be called with the constructed object: {main_adb}"
        );
    }

    #[test]
    fn generate_default_initializes_nonabstract_tagged_receiver() {
        // A definite tagged state holder does not need a factory. In particular,
        // `type Argument_Parser is new Limited_Controlled with private` has a
        // language-defined default initialization and is intended to be declared
        // before its mutators are called.
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Set_Prologue",
            vec![
                param_with_mode(
                    "A",
                    "Argument_Parser",
                    TypeKind::Tagged {
                        base: TypeId(0),
                        is_abstract: false,
                    },
                    ParamMode::InOut,
                ),
                param("Prologue", "String", TypeKind::Unknown),
            ],
            None,
        );
        let mut ast = ast_with(target.clone(), Vec::new(), vec![package(7, "Parse_Args")]);
        let mut argument_parser = type_ref(
            "Argument_Parser",
            TypeKind::Tagged {
                base: TypeId(0),
                is_abstract: false,
            },
        );
        argument_parser.owner = TypeOwner::Package(PackageId(7));
        ast.types.push(argument_parser);
        let output_dir = temp_dir("default-tagged-receiver").join("H-DEFAULT-TAGGED");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(
            main_adb.contains("A : Argument_Parser;")
                || main_adb.contains("A : Parse_Args.Argument_Parser;"),
            "expected a bare, default-initialized tagged receiver: {main_adb}"
        );
        assert!(
            main_adb.contains("Set_Prologue (A, Prologue)"),
            "expected the target call to use the fresh receiver: {main_adb}"
        );
    }

    #[test]
    fn generate_uses_nonabstract_root_for_class_wide_receiver() {
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(8)),
            "Set_Option_Argument",
            vec![param_with_mode(
                "A",
                "Argument_Parser.Class",
                TypeKind::Unknown,
                ParamMode::InOut,
            )],
            None,
        );
        let mut ast = ast_with(
            target.clone(),
            Vec::new(),
            vec![package(7, "Parse_Args"), package(8, "Parse_Args.Concrete")],
        );
        ast.types.push(TypeRef {
            id: TypeId(10),
            name_path: vec!["Argument_Parser".to_owned()],
            visibility: Visibility::Public,
            owner: TypeOwner::Package(PackageId(7)),
            kind: TypeKind::Tagged {
                base: TypeId(0),
                is_abstract: false,
            },
            constraints: Constraints("Ada.Finalization.Limited_Controlled".to_owned()),
            aspects: Aspects(Vec::new()),
        });
        let output_dir = temp_dir("class-wide-concrete-root").join("H-CLASS-ROOT");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(
            main_adb.contains("A : Parse_Args.Argument_Parser;"),
            "expected the class-wide formal to use a concrete root object: {main_adb}"
        );
        assert!(main_adb.contains("with Parse_Args;"));
    }

    #[test]
    fn generate_backs_anonymous_access_to_tagged_with_aliased_object() {
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Parse_Grammar",
            vec![param_with_mode(
                "Handler",
                "Validating_Reader",
                TypeKind::Tagged {
                    base: TypeId(0),
                    is_abstract: false,
                },
                ParamMode::AccessMode,
            )],
            None,
        );
        let mut ast = ast_with(
            target.clone(),
            Vec::new(),
            vec![package(7, "Schema.Readers")],
        );
        ast.types.push(TypeRef {
            id: TypeId(10),
            name_path: vec!["Validating_Reader".to_owned()],
            visibility: Visibility::Public,
            owner: TypeOwner::Package(PackageId(7)),
            kind: TypeKind::Tagged {
                base: TypeId(0),
                is_abstract: false,
            },
            constraints: Constraints("Base_Reader".to_owned()),
            aspects: Aspects(Vec::new()),
        });
        let output_dir = temp_dir("access-tagged-backing").join("H-ACCESS-TAGGED");

        let main_adb =
            fs::read_to_string(generate_for(&ast, &target, &output_dir).unwrap().main_adb).unwrap();

        assert!(main_adb.contains("Handler_Backing : aliased Schema.Readers.Validating_Reader;"));
        assert!(main_adb.contains(
            "Handler : constant access Schema.Readers.Validating_Reader := Handler_Backing'Access;"
        ));
        assert!(main_adb.contains("Schema.Readers.Parse_Grammar (Handler);"));
    }

    #[test]
    fn external_string_subtype_resolves_to_string_decode_kind() {
        let mut ast = StructuralAst::new();
        ast.types.push(TypeRef {
            id: TypeId(10),
            name_path: vec!["Byte_Sequence".to_owned()],
            visibility: Visibility::Public,
            owner: TypeOwner::Package(PackageId(7)),
            kind: TypeKind::Derived { base: TypeId(0) },
            constraints: Constraints("String".to_owned()),
            aspects: Aspects(Vec::new()),
        });
        ast.packages.push(package(7, "Unicode.CES"));
        let unresolved = param("URI", "Unicode.CES.Byte_Sequence", TypeKind::Unknown);

        let resolved = super::resolve_param_type(&ast, &unresolved);

        assert_eq!(resolved.type_ref.name_path, vec!["String"]);
        assert_eq!(resolved.type_ref.kind, TypeKind::Unknown);
    }

    #[test]
    fn qualified_type_lookup_does_not_cross_package_on_shared_leaf() {
        let mut ast = StructuralAst::new();
        ast.packages = vec![package(1, "Left"), package(2, "Right")];
        ast.types.push(TypeRef {
            id: TypeId(10),
            name_path: vec!["Object_Access".to_owned()],
            visibility: Visibility::Public,
            owner: TypeOwner::Package(PackageId(1)),
            kind: TypeKind::Private,
            constraints: Constraints(String::new()),
            aspects: Aspects(Vec::new()),
        });
        ast.types.push(TypeRef {
            id: TypeId(11),
            name_path: vec!["Object_Access".to_owned()],
            visibility: Visibility::Public,
            owner: TypeOwner::Package(PackageId(2)),
            kind: TypeKind::Access { target: TypeId(9) },
            constraints: Constraints(String::new()),
            aspects: Aspects(Vec::new()),
        });
        let unresolved = param("Value", "Right.Object_Access", TypeKind::Unknown);

        let resolved = super::resolve_param_type(&ast, &unresolved);

        assert_eq!(resolved.type_ref.name_path, vec!["Right", "Object_Access"]);
        assert!(matches!(resolved.type_ref.kind, TypeKind::Access { .. }));
    }

    #[test]
    fn out_param_constructor_accepts_in_out_receiver_with_constructor_name() {
        // `procedure Open (File : in out Zipped_File_Type; Name : String)` is
        // the limited-stream init idiom: an `in out` receiver, but a
        // constructor-like name. It must be used to build the stateful param.
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Read_Byte",
            vec![param_with_mode(
                "File",
                "Zipped_File_Type",
                TypeKind::Private,
                ParamMode::InOut,
            )],
            None,
        );
        let opener = subprogram(
            2,
            SubprogramOwner::Package(PackageId(7)),
            "Open",
            vec![
                param_with_mode(
                    "File",
                    "Zipped_File_Type",
                    TypeKind::Private,
                    ParamMode::InOut,
                ),
                param_with_mode("Name", "String", TypeKind::Unknown, ParamMode::In),
            ],
            None,
        );
        // A same-shaped mutator must NOT be chosen over the constructor.
        let mutator = subprogram(
            3,
            SubprogramOwner::Package(PackageId(7)),
            "Advance",
            vec![param_with_mode(
                "File",
                "Zipped_File_Type",
                TypeKind::Private,
                ParamMode::InOut,
            )],
            None,
        );
        let mut ast = ast_with(target.clone(), Vec::new(), vec![package(7, "Streams")]);
        ast.subprograms.push(mutator);
        ast.subprograms.push(opener);
        let output_dir = temp_dir("in-out-ctor").join("H-INOUT");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(
            main_adb.contains("Streams.Open (File,"),
            "in-out constructor Open must initialise the stateful param: {main_adb}"
        );
        assert!(
            !main_adb.contains("Advance"),
            "a mutator must not be used as a constructor: {main_adb}"
        );
    }

    #[test]
    fn constructor_named_target_bare_declares_its_own_inout_receiver() {
        // `procedure Open (File : in out Zipped_File_Type)` fuzzed directly: Open
        // is its own (only) constructor, so there is no sibling to find. Its
        // constructor-like name lets the harness declare the receiver bare and
        // let the call fill it, instead of skipping (Unzip.Streams.Open).
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Open",
            vec![param_with_mode(
                "File",
                "Zipped_File_Type",
                TypeKind::Private,
                ParamMode::InOut,
            )],
            None,
        );
        let ast = ast_with(target.clone(), Vec::new(), vec![package(7, "Unzip")]);
        let output_dir = temp_dir("ctor-self-inout").join("H-OPEN");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();
        assert!(
            main_adb.contains("Unzip.Open (File)") || main_adb.contains("Open (File)"),
            "constructor-named target must bare-declare and pass its receiver: {main_adb}"
        );
    }

    #[test]
    fn mutator_named_target_skips_its_inout_private_receiver() {
        // `procedure Add_File (Info : in out Zip_Create_Info)` is a mutator, not
        // a constructor: bare-declaring its receiver would pass uninitialised
        // state, so it must skip rather than emit a misleading harness.
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Add_File",
            vec![param_with_mode(
                "Info",
                "Zip_Create_Info",
                TypeKind::Private,
                ParamMode::InOut,
            )],
            None,
        );
        let ast = ast_with(target.clone(), Vec::new(), vec![package(7, "Zip")]);
        let output_dir = temp_dir("mutator-self-inout").join("H-ADD");

        assert!(generate_for(&ast, &target, &output_dir).is_err());
    }

    #[test]
    fn out_param_constructor_synthesizes_stream_argument() {
        // `procedure Make (W : out Widget; S : Stream_Access)` where
        // Stream_Access is `access all Root_Stream_Type'Class`: the constructor
        // for the stateful Widget needs a stream argument. The harness backs it
        // with a concrete stream and passes it, instead of rejecting the
        // constructor (the `Zip.Create.Create_Archive` Z_Stream pattern).
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Use_It",
            vec![param("W", "Widget", TypeKind::Private)],
            None,
        );
        let maker = subprogram(
            2,
            SubprogramOwner::Package(PackageId(7)),
            "Make",
            vec![
                param_with_mode("W", "Widget", TypeKind::Private, ParamMode::Out),
                param_with_mode(
                    "S",
                    "Stream_Access",
                    TypeKind::Access { target: TypeId(9) },
                    ParamMode::In,
                ),
            ],
            None,
        );
        let mut stream_access =
            type_ref("Pkg.Stream_Access", TypeKind::Access { target: TypeId(9) });
        stream_access.constraints =
            Constraints("all Ada.Streams.Root_Stream_Type'Class".to_owned());
        let mut ast = ast_with(target.clone(), Vec::new(), vec![package(7, "Pkg")]);
        ast.subprograms.push(maker);
        ast.types.push(stream_access);
        let output_dir = temp_dir("ctor-stream-arg").join("H-STREAM");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();
        assert!(
            main_adb.contains("Gf_Ctor_Stream_1"),
            "constructor stream arg must be backed by a declared stream: {main_adb}"
        );
        assert!(
            main_adb.contains("Make (W, Gf_Ctor_Stream_1)")
                || main_adb.contains("Pkg.Make (W, Gf_Ctor_Stream_1)"),
            "constructor must pass the backing stream: {main_adb}"
        );
    }

    #[test]
    fn out_param_constructor_receiver_does_not_cross_sibling_packages() {
        let mut ast = StructuralAst::new();
        ast.packages
            .push(package(1, "Agpl.Streams.Bandwidth_Throttle"));
        ast.packages.push(package(2, "Agpl.Streams.Controlled"));
        let controlled_init = subprogram(
            1,
            SubprogramOwner::Package(PackageId(2)),
            "Initialize",
            vec![param_with_mode(
                "This",
                "Stream_Type",
                TypeKind::Private,
                ParamMode::InOut,
            )],
            None,
        );
        assert!(!out_param_receiver_matches(
            &ast,
            &controlled_init,
            &controlled_init.params[0],
            "Agpl.Streams.Bandwidth_Throttle.Stream_Type"
        ));
        assert!(out_param_receiver_matches(
            &ast,
            &controlled_init,
            &controlled_init.params[0],
            "Agpl.Streams.Controlled.Stream_Type"
        ));

        // A child package may initialize a type declared by its parent.
        ast.packages.push(package(3, "Zip.Create"));
        let child_load = subprogram(
            2,
            SubprogramOwner::Package(PackageId(3)),
            "Load",
            vec![param_with_mode(
                "Info",
                "Zip_Info",
                TypeKind::Private,
                ParamMode::Out,
            )],
            None,
        );
        assert!(out_param_receiver_matches(
            &ast,
            &child_load,
            &child_load.params[0],
            "Zip.Zip_Info"
        ));
    }

    #[test]
    fn anonymous_access_classwide_stream_uses_persistent_fuzz_stream() {
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Create",
            vec![param_with_mode(
                "Back",
                "Ada.Streams.Root_Stream_Type.Class",
                TypeKind::Private,
                ParamMode::AccessMode,
            )],
            None,
        );
        let ast = ast_with(target.clone(), Vec::new(), vec![package(7, "Pkg")]);
        let output_dir = temp_dir("access-source-stream").join("H-STREAM-ACCESS");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();
        assert!(main_adb.contains("with Gf_Source_Streams;"), "{main_adb}");
        assert!(
            main_adb.contains("Back_Backing : aliased Gf_Source_Streams.Fuzz_Stream;"),
            "{main_adb}"
        );
        assert!(
            main_adb.contains("Back_Backing'Access;")
                && main_adb.contains("Gf_Source_Streams.Set (Back_Backing")
                && main_adb.contains("Pkg.Create (Back);"),
            "{main_adb}"
        );
    }

    #[test]
    fn out_param_constructor_skips_abstract_receiver_types() {
        // An abstract tagged type (e.g. `Root_Zipstream_Type`) cannot be
        // declared as a bare object, so the out-parameter constructor path must
        // not fire for it - the target stays skipped rather than emitting a
        // harness that fails to compile on the illegal declaration.
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Set_Flag",
            vec![param_with_mode(
                "S",
                "Root_Stream",
                TypeKind::Tagged {
                    is_abstract: true,
                    base: TypeId(0),
                },
                ParamMode::Out,
            )],
            None,
        );
        let mut ast = ast_with(target.clone(), Vec::new(), vec![package(7, "Streams")]);
        ast.types.push(TypeRef {
            id: TypeId(10),
            name_path: vec!["Root_Stream".to_owned()],
            visibility: Visibility::Public,
            owner: TypeOwner::Package(PackageId(7)),
            kind: TypeKind::Tagged {
                is_abstract: true,
                base: TypeId(0),
            },
            constraints: Constraints(String::new()),
            aspects: Aspects(Vec::new()),
        });
        let output_dir = temp_dir("abstract-receiver").join("H-ABS");

        let result = generate_for(&ast, &target, &output_dir);
        assert!(
            result.is_err(),
            "abstract receiver must not be constructed via out-param init"
        );
    }

    #[test]
    fn generate_resolves_range_constrained_enum_subtype_to_base_enum() {
        // `subtype Reduction_Method is Compression_Method range Reduce_1 ..
        // Reduce_4` - a constrained subtype of an enumeration. The derived
        // chain must follow the constraint's base mark (ignoring the ` range `
        // clause) to the enum so the param decodes via 'Val rather than being
        // skipped as an unconstructible Unknown type.
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Reduce",
            vec![param("Method", "Reduction_Method", TypeKind::Unknown)],
            None,
        );
        let mut ast = ast_with(target.clone(), Vec::new(), vec![package(7, "Compressor")]);
        ast.types.push(TypeRef {
            id: TypeId(10),
            name_path: vec!["Reduction_Method".to_owned()],
            visibility: Visibility::Public,
            owner: TypeOwner::Package(PackageId(7)),
            kind: TypeKind::Derived { base: TypeId(11) },
            constraints: Constraints("Compression_Method range Reduce_1 .. Reduce_4".to_owned()),
            aspects: Aspects(Vec::new()),
        });
        ast.types.push(TypeRef {
            id: TypeId(11),
            name_path: vec!["Compression_Method".to_owned()],
            visibility: Visibility::Public,
            owner: TypeOwner::Package(PackageId(7)),
            kind: TypeKind::Enum(vec![
                "Store".to_owned(),
                "Reduce_1".to_owned(),
                "Reduce_4".to_owned(),
            ]),
            constraints: Constraints(String::new()),
            aspects: Aspects(Vec::new()),
        });
        let output_dir = temp_dir("enum-subtype").join("H-ENUM");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(
            main_adb.contains("'Val (") && main_adb.contains("'Pos ("),
            "constrained enum subtype must decode via 'Val/'Pos attributes: {main_adb}"
        );
    }

    #[test]
    fn generate_resolves_param_type_kind_from_ast_type_declarations() {
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Process",
            vec![param("Node", "Node_Ptr", TypeKind::Unknown)],
            None,
        );
        let mut ast = ast_with(target.clone(), Vec::new(), vec![package(7, "Access_Param")]);
        ast.types.push(TypeRef {
            id: TypeId(9),
            name_path: vec!["Node_Ptr".to_owned()],
            visibility: Visibility::Public,
            owner: TypeOwner::Package(PackageId(7)),
            kind: TypeKind::Access { target: TypeId(8) },
            constraints: Constraints(String::new()),
            aspects: Aspects(Vec::new()),
        });
        let output_dir = temp_dir("resolved-param-type").join("H-0042");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(main_adb.contains("function Decode_Node return Access_Param.Node_Ptr is"));
        assert!(main_adb.contains("Node : Access_Param.Node_Ptr := Decode_Node;"));
    }

    #[test]
    fn generate_resolves_derived_array_alias_chain_for_param_decoder() {
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Crypto_Box",
            vec![param("N", "Stream.HSalsa20_Nonce", TypeKind::Unknown)],
            None,
        );
        let mut ast = ast_with(
            target.clone(),
            Vec::new(),
            vec![package(7, "Tweetnacl_Api"), package(9, "Stream")],
        );
        ast.types.push(TypeRef {
            id: TypeId(20),
            name_path: vec!["Byte_Seq".to_owned()],
            visibility: Visibility::Public,
            owner: TypeOwner::LibraryLevel,
            kind: TypeKind::Array {
                idx_types: vec![TypeId(21)],
                elem_type: TypeId(22),
                bounds: "N32 range <>".to_owned(),
                elem_name: String::new(),
            },
            constraints: Constraints(String::new()),
            aspects: Aspects(Vec::new()),
        });
        ast.types.push(TypeRef {
            id: TypeId(23),
            name_path: vec!["Bytes_24".to_owned()],
            visibility: Visibility::Public,
            owner: TypeOwner::LibraryLevel,
            kind: TypeKind::Derived { base: TypeId(20) },
            constraints: Constraints("Byte_Seq".to_owned()),
            aspects: Aspects(Vec::new()),
        });
        ast.types.push(TypeRef {
            id: TypeId(24),
            name_path: vec!["HSalsa20_Nonce".to_owned()],
            visibility: Visibility::Public,
            owner: TypeOwner::Package(PackageId(9)),
            kind: TypeKind::Derived { base: TypeId(23) },
            constraints: Constraints("Bytes_24".to_owned()),
            aspects: Aspects(Vec::new()),
        });
        let output_dir = temp_dir("derived-array-alias").join("H-0042");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(main_adb.contains("function Decode_N return Stream.HSalsa20_Nonce is"));
        assert!(main_adb.contains("N : Stream.HSalsa20_Nonce := Decode_N;"));
    }

    #[test]
    fn generate_qualifies_target_with_package_name() {
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Parse",
            vec![param("S", "String", TypeKind::Unknown)],
            None,
        );
        let ast = ast_with(target.clone(), Vec::new(), vec![package(7, "Pkg")]);
        let output_dir = temp_dir("qualified").join("H-0042");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(main_adb.contains("Pkg.Parse (S);"));
    }

    #[test]
    fn generate_unit_with_clauses_propagated_to_harness() {
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Parse",
            vec![param("S", "String", TypeKind::Unknown)],
            None,
        );
        let ast = ast_with(
            target.clone(),
            vec!["Ada.Text_IO", "Interfaces"],
            vec![package(7, "Pkg")],
        );
        let output_dir = temp_dir("withs").join("H-0042");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(main_adb.contains("with Ada.Text_IO;"));
        assert!(main_adb.contains("with Interfaces;"));
        assert!(main_adb.contains("with Pkg;"));
    }

    #[test]
    fn generate_unit_with_clauses_canonicalizes_dotted_names() {
        let target = subprogram(1, SubprogramOwner::LibraryLevel, "Run", Vec::new(), None);
        let ast = ast_with(target.clone(), vec!["ada.text_io"], Vec::new());
        let output_dir = temp_dir("with-case").join("H-0042");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(main_adb.contains("with Ada.Text_Io;"));
    }

    #[test]
    fn generate_lowercase_package_target_uses_conventional_ada_casing() {
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "parse",
            vec![param("s", "string", TypeKind::Unknown)],
            Some(type_ref("integer", TypeKind::Scalar(ScalarKind::Integer))),
        );
        let ast = ast_with(target.clone(), Vec::new(), vec![package(7, "pkg")]);
        let output_dir = temp_dir("lowercase").join("H-0042");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(main_adb.contains("with Pkg;"));
        assert!(main_adb.contains("S : String := AdaFuzz.Decode.Ada_String"));
        assert!(main_adb.contains("Gf_Result : constant Integer := Pkg.Parse (S);"));
    }

    #[test]
    fn generate_set_target_uses_subprogram_id_hex() {
        let target = subprogram(66, SubprogramOwner::LibraryLevel, "Run", Vec::new(), None);
        let ast = ast_with(target.clone(), Vec::new(), Vec::new());
        let output_dir = temp_dir("target-id").join("H-0042");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(main_adb.contains("AdaFuzz.Probe.Set_Target (16#0042#);"));
    }

    #[test]
    fn generate_gpr_project_name_replaces_harness_id_punctuation() {
        let target = subprogram(1, SubprogramOwner::LibraryLevel, "Run", Vec::new(), None);
        let ast = ast_with(target.clone(), Vec::new(), Vec::new());
        let output_dir = temp_dir("project-name").join("H-TEST");

        let generated = generate_direct_harness(GenerateDirectArgs {
            ast: &ast,
            target_subprogram: &target,
            harness_id: "H-TEST".to_owned(),
            output_dir,
            source_path: PathBuf::from("src/pkg.adb"),
            source_roots: Vec::new(),
            project_imports: Vec::new(),
            generic_instance: None,
            generic_call: None,
            generic_suppress_params: false,
            child_harness_unit: None,
        })
        .unwrap();
        let gpr = fs::read_to_string(&generated.gpr).unwrap();

        assert!(generated.gpr.ends_with("H_TEST.gpr"));
        assert!(gpr.contains("project H_TEST is"));
    }

    #[test]
    fn generate_zero_param_procedure_omits_empty_parentheses() {
        let target = subprogram(1, SubprogramOwner::LibraryLevel, "Run", Vec::new(), None);
        let ast = ast_with(target.clone(), Vec::new(), Vec::new());
        let output_dir = temp_dir("zero-param").join("H-0042");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(main_adb.contains("Run;"));
        assert!(!main_adb.contains("Run ();"));
    }

    #[test]
    fn generate_qualifies_package_owned_return_type() {
        let package = package(7, "Pkg");
        let model_type = TypeRef {
            id: TypeId(91),
            name_path: vec!["Model".to_owned()],
            visibility: Visibility::Public,
            owner: TypeOwner::Package(PackageId(7)),
            kind: TypeKind::Private,
            constraints: Constraints(String::new()),
            aspects: Aspects(Vec::new()),
        };
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Make",
            Vec::new(),
            Some(TypeRef {
                id: TypeId(0),
                name_path: vec!["Model".to_owned()],
                visibility: Visibility::Public,
                owner: TypeOwner::LibraryLevel,
                kind: TypeKind::Unknown,
                constraints: Constraints(String::new()),
                aspects: Aspects(Vec::new()),
            }),
        );
        let mut ast = ast_with(target.clone(), Vec::new(), vec![package]);
        ast.types.push(model_type);
        let output_dir = temp_dir("qualified-return").join("H-0042");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(main_adb.contains("Gf_Result : constant Pkg.Model := Pkg.Make;"));
    }

    #[test]
    fn generate_uses_harness_id_in_filenames() {
        let target = subprogram(1, SubprogramOwner::LibraryLevel, "Run", Vec::new(), None);
        let ast = ast_with(target.clone(), Vec::new(), Vec::new());
        let output_dir = temp_dir("id").join("H-0042");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();

        assert_eq!(generated.harness_id, "H-0042");
        assert!(generated.main_adb.ends_with("main.adb"));
        assert!(generated.gpr.ends_with("H_0042.gpr"));
    }

    #[test]
    fn generate_sequence_harness_emits_bounded_operation_loop() {
        let package = package(7, "State");
        let push = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Push",
            vec![param("X", "Integer", TypeKind::Scalar(ScalarKind::Integer))],
            None,
        );
        let pop = subprogram(
            2,
            SubprogramOwner::Package(PackageId(7)),
            "Pop",
            Vec::new(),
            None,
        );
        let mut ast = ast_with(push.clone(), Vec::new(), vec![package.clone()]);
        ast.subprograms.push(pop);
        let output_dir = temp_dir("sequence-loop").join("H-M9");

        let generated = super::generate_sequence_harness(super::GenerateSequenceArgs {
            ast: &ast,
            target_package: &package,
            harness_id: "H-M9".to_owned(),
            output_dir,
            source_path: PathBuf::from("src/state.adb"),
            source_roots: Vec::new(),
            project_imports: Vec::new(),
        })
        .unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(main_adb.contains("Max_Steps : constant Natural := 32;"));
        assert!(main_adb.contains(
            "Step_Count : constant Natural := AdaFuzz.Decode.Bounded_Length (Cur, 1, Max_Steps);"
        ));
        assert!(main_adb.contains("case Op is"));
        assert!(main_adb.contains("when 0 =>"));
        assert!(main_adb.contains("when 1 =>"));
        assert!(main_adb.contains("State.Push (X);"));
        assert!(main_adb.contains("State.Pop;"));
    }

    #[test]
    fn generate_sequence_harness_ignores_function_result() {
        let package = package(7, "State");
        let top = subprogram(
            3,
            SubprogramOwner::Package(PackageId(7)),
            "Top",
            Vec::new(),
            Some(type_ref("Integer", TypeKind::Scalar(ScalarKind::Integer))),
        );
        let ast = ast_with(top.clone(), Vec::new(), vec![package.clone()]);
        let output_dir = temp_dir("sequence-function").join("H-M9");

        let generated = super::generate_sequence_harness(super::GenerateSequenceArgs {
            ast: &ast,
            target_package: &package,
            harness_id: "H-M9".to_owned(),
            output_dir,
            source_path: PathBuf::from("src/state.adb"),
            source_roots: Vec::new(),
            project_imports: Vec::new(),
        })
        .unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(main_adb.contains("R_Top : Integer;"));
        assert!(main_adb.contains("pragma Unreferenced (R_Top);"));
        assert!(main_adb.contains("R_Top := State.Top;"));
    }

    #[test]
    fn generate_sequence_harness_initializes_out_and_inout_by_mode() {
        let package = package(7, "State");
        let push = subprogram(
            4,
            SubprogramOwner::Package(PackageId(7)),
            "Push",
            vec![
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
        let ast = ast_with(push, Vec::new(), vec![package.clone()]);
        let output_dir = temp_dir("sequence-param-modes").join("H-M9");

        let generated = super::generate_sequence_harness(super::GenerateSequenceArgs {
            ast: &ast,
            target_package: &package,
            harness_id: "H-M9".to_owned(),
            output_dir,
            source_path: PathBuf::from("src/state.adb"),
            source_roots: Vec::new(),
            project_imports: Vec::new(),
        })
        .unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(main_adb.contains("Out_Count : Integer := Integer'First;"));
        assert!(main_adb.contains("Inout_Count : Integer := Integer (AdaFuzz.Decode.I32 (Cur));"));
        assert!(main_adb.contains("State.Push (Out_Count, Inout_Count);"));
    }

    #[test]
    fn generate_sequence_harness_excludes_package_body_helper_not_declared_in_spec() {
        let package = package(7, "State");
        let mut push_body = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Push",
            vec![param("X", "Integer", TypeKind::Scalar(ScalarKind::Integer))],
            None,
        );
        push_body.visibility = Visibility::Local;
        let mut pop_body = subprogram(
            2,
            SubprogramOwner::Package(PackageId(7)),
            "Pop",
            Vec::new(),
            None,
        );
        pop_body.visibility = Visibility::Local;
        let mut helper_body = subprogram(
            3,
            SubprogramOwner::Package(PackageId(7)),
            "Helper",
            Vec::new(),
            None,
        );
        helper_body.visibility = Visibility::Local;
        let mut push_spec = push_body.clone();
        push_spec.id = SubprogramId(4);
        push_spec.body_span = None;
        push_spec.visibility = Visibility::Public;
        let mut pop_spec = pop_body.clone();
        pop_spec.id = SubprogramId(5);
        pop_spec.body_span = None;
        pop_spec.visibility = Visibility::Public;
        let mut ast = ast_with(push_body, Vec::new(), vec![package.clone()]);
        ast.subprograms
            .extend([pop_body, helper_body, push_spec, pop_spec]);
        let output_dir = temp_dir("sequence-helper").join("H-M9");

        let generated = super::generate_sequence_harness(super::GenerateSequenceArgs {
            ast: &ast,
            target_package: &package,
            harness_id: "H-M9".to_owned(),
            output_dir,
            source_path: PathBuf::from("src/state.adb"),
            source_roots: Vec::new(),
            project_imports: Vec::new(),
        })
        .unwrap();
        let main_adb = fs::read_to_string(generated.main_adb).unwrap();

        assert!(main_adb.contains("State.Push (X);"));
        assert!(main_adb.contains("State.Pop;"));
        assert!(!main_adb.contains("State.Helper;"));
    }

    #[test]
    fn generate_sequence_harness_rejects_package_without_operations() {
        let package = package(7, "State");
        let ast = StructuralAst {
            packages: vec![package.clone()],
            ..StructuralAst::new()
        };
        let output_dir = temp_dir("sequence-empty").join("H-M9");

        let error = super::generate_sequence_harness(super::GenerateSequenceArgs {
            ast: &ast,
            target_package: &package,
            harness_id: "H-M9".to_owned(),
            output_dir,
            source_path: PathBuf::from("src/state.adb"),
            source_roots: Vec::new(),
            project_imports: Vec::new(),
        })
        .unwrap_err();

        assert!(error.to_string().contains("State"));
    }

    #[test]
    fn generate_returns_target_not_found_when_subprogram_is_not_in_ast() {
        let target = subprogram(1, SubprogramOwner::LibraryLevel, "Run", Vec::new(), None);
        let ast = StructuralAst::new();
        let output_dir = temp_dir("missing-target").join("H-0042");

        let error = generate_for(&ast, &target, &output_dir).unwrap_err();

        assert!(matches!(error, HarnessGenError::TargetNotFound(_)));
        assert!(error.to_string().contains("Run"));
    }

    /// An access-to-array parameter with the designated subtype mark in its
    /// constraint text (as `parse_access_type` records it).
    fn access_param(name: &str, type_name: &str, designated: &str, mode: ParamMode) -> Parameter {
        let mut tr = type_ref(type_name, TypeKind::Access { target: TypeId(0) });
        tr.constraints = Constraints(designated.to_owned());
        Parameter {
            name: name.to_owned(),
            mode,
            type_ref: tr,
            default: None,
        }
    }

    #[test]
    fn out_access_constant_to_string_gets_initialized_buffer_no_free() {
        // `type String_Access is access constant String; X : String_Access`
        // (ada_drivers Command_Line.Create). An access-to-constant allocator must
        // be INITIALIZED (`new String'(...)`, not `new String (...)`), and it must
        // NOT be freed (Unchecked_Deallocation needs access-to-variable).
        let target = subprogram(
            1,
            SubprogramOwner::LibraryLevel,
            "Render",
            vec![access_param(
                "Dst",
                "String_Ptr",
                "constant String",
                ParamMode::In,
            )],
            None,
        );
        let ast = ast_with(target.clone(), Vec::new(), Vec::new());
        let output_dir = temp_dir("sink-const-string").join("H-0042");
        let main_adb =
            fs::read_to_string(generate_for(&ast, &target, &output_dir).unwrap().main_adb).unwrap();
        assert!(
            main_adb.contains("Dst : String_Ptr := new String'(1 .. 1 + 1048576 - 1 => ' ');"),
            "expected an initialized access-constant allocator, got:\n{main_adb}"
        );
        assert!(
            !main_adb.contains("Unchecked_Deallocation") && !main_adb.contains("Gf_Free_Dst"),
            "access-constant must not be freed, got:\n{main_adb}"
        );
    }

    #[test]
    fn out_access_to_stream_element_array_gets_bounded_heap_sink() {
        let target = subprogram(
            1,
            SubprogramOwner::LibraryLevel,
            "Fill",
            vec![access_param(
                "Out_Buf",
                "P_Stream_Element_Array",
                "Stream_Element_Array",
                ParamMode::Out,
            )],
            None,
        );
        let ast = ast_with(target.clone(), Vec::new(), Vec::new());
        let output_dir = temp_dir("sink-sea").join("H-0042");

        let main_adb =
            fs::read_to_string(generate_for(&ast, &target, &output_dir).unwrap().main_adb).unwrap();

        // Allocated ONCE (heap, leak-free under the persistent fork-server) with a
        // real bounded backing buffer, and passed to the call instead of null.
        assert!(main_adb.contains(
            "Out_Buf : P_Stream_Element_Array := new Ada.Streams.Stream_Element_Array \
             (0 .. 0 + 1048576 - 1);"
        ));
        assert!(main_adb.contains("Fill (Out_Buf);"));
        // The allocator appears exactly once — not re-allocated per input.
        assert_eq!(main_adb.matches(":= new Ada.Streams").count(), 1);
        // And it is NOT re-declared inside the per-input declare block.
        assert!(!main_adb.contains("Out_Buf : P_Stream_Element_Array;"));
        // Freed after the loop (paired Unchecked_Deallocation) so LeakSanitizer
        // does not report the deliberate fixed allocation as a leak.
        assert!(main_adb.contains("with Ada.Unchecked_Deallocation;"));
        assert!(main_adb.contains(
            "procedure Gf_Free_Out_Buf is new Ada.Unchecked_Deallocation\n     \
             (Ada.Streams.Stream_Element_Array, P_Stream_Element_Array);"
        ));
        assert!(main_adb.contains("Gf_Free_Out_Buf (Out_Buf);"));
    }

    #[test]
    fn out_access_to_string_gets_one_based_sink() {
        let target = subprogram(
            1,
            SubprogramOwner::LibraryLevel,
            "Render",
            vec![access_param("Dst", "String_Ptr", "String", ParamMode::Out)],
            None,
        );
        let ast = ast_with(target.clone(), Vec::new(), Vec::new());
        let output_dir = temp_dir("sink-string").join("H-0042");

        let main_adb =
            fs::read_to_string(generate_for(&ast, &target, &output_dir).unwrap().main_adb).unwrap();

        assert!(main_adb.contains("Dst : String_Ptr := new String (1 .. 1 + 1048576 - 1);"));
        assert!(main_adb.contains("Render (Dst);"));
    }

    #[test]
    fn out_access_to_local_unconstrained_array_uses_index_first() {
        let array_decl = TypeRef {
            id: TypeId(9),
            name_path: vec!["Buf_Array".to_owned()],
            visibility: Visibility::Public,
            owner: TypeOwner::LibraryLevel,
            kind: TypeKind::Array {
                idx_types: vec![TypeId(0)],
                elem_type: TypeId(0),
                bounds: "Positive range <>".to_owned(),
                elem_name: "Interfaces.Unsigned_8".to_owned(),
            },
            constraints: Constraints("Positive range <>".to_owned()),
            aspects: Aspects(Vec::new()),
        };
        let target = subprogram(
            1,
            SubprogramOwner::LibraryLevel,
            "Emit",
            vec![access_param("P", "Buf_Ptr", "Buf_Array", ParamMode::Out)],
            None,
        );
        let mut ast = ast_with(target.clone(), Vec::new(), Vec::new());
        ast.types = vec![array_decl];
        let output_dir = temp_dir("sink-local").join("H-0042");

        let main_adb =
            fs::read_to_string(generate_for(&ast, &target, &output_dir).unwrap().main_adb).unwrap();

        assert!(main_adb.contains(
            "P : Buf_Ptr := new Buf_Array (Positive'First .. Positive'First + 1048576 - 1);"
        ));
        assert!(main_adb.contains("Emit (P);"));
    }

    #[test]
    fn access_to_root_stream_class_gets_discard_stream_sink() {
        let target = subprogram(
            1,
            SubprogramOwner::LibraryLevel,
            "Emit",
            vec![access_param(
                "Out_Stream",
                "P_Stream",
                "all Ada.Streams.Root_Stream_Type'Class",
                ParamMode::In,
            )],
            None,
        );
        let ast = ast_with(target.clone(), Vec::new(), Vec::new());
        let output_dir = temp_dir("sink-stream").join("H-0042");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(&generated.main_adb).unwrap();

        // Backed by a generated discard stream, allocated once + freed, not null.
        assert!(main_adb.contains("with Gf_Sink_Streams;"));
        assert!(main_adb.contains("Out_Stream : P_Stream := new Gf_Sink_Streams.Null_Stream;"));
        assert!(main_adb.contains("Gf_Free_Out_Stream (Out_Stream);"));
        assert!(!main_adb.contains("Out_Stream : P_Stream := null"));
        // The discard-stream package is emitted beside the harness.
        let pkg = output_dir.join("gf_sink_streams.ads");
        assert!(pkg.exists(), "Gf_Sink_Streams spec must be emitted");
        let pkg_body = fs::read_to_string(output_dir.join("gf_sink_streams.adb")).unwrap();
        assert!(pkg_body.contains("null;  --  discard"));
    }

    #[test]
    fn access_to_custom_stream_root_allocates_inmemory_derivation() {
        // A custom class-wide stream root (not Ada.Streams.Root_Stream_Type) with
        // a concrete in-memory derivation in the tree (zip-ada
        // Root_Zipstream_Type'Class -> Memory_Zipstream) is backed by
        // `new <that derivation>`, not null and not the discard-stream package.
        let target = subprogram(
            1,
            SubprogramOwner::LibraryLevel,
            "Create",
            vec![access_param(
                "Z",
                "Stream_Ptr",
                "all My_Streams.Root_My_Stream'Class",
                ParamMode::In,
            )],
            None,
        );
        let mut ast = ast_with(target.clone(), Vec::new(), vec![package(7, "My_Streams")]);
        ast.types = vec![TypeRef {
            id: TypeId(9),
            name_path: vec!["My_Streams".to_owned(), "Memory_My_Stream".to_owned()],
            visibility: Visibility::Public,
            owner: TypeOwner::Package(PackageId(7)),
            kind: TypeKind::Derived { base: TypeId(0) },
            constraints: Constraints("Root_My_Stream with private".to_owned()),
            aspects: Aspects(Vec::new()),
        }];
        let output_dir = temp_dir("sink-custom-stream").join("H-0042");

        let main_adb =
            fs::read_to_string(generate_for(&ast, &target, &output_dir).unwrap().main_adb).unwrap();

        assert!(
            main_adb.contains("Z : Stream_Ptr := new My_Streams.Memory_My_Stream;"),
            "expected a concrete in-memory derivation allocation, got:\n{main_adb}"
        );
        assert!(main_adb.contains("with My_Streams;"));
        assert!(main_adb.contains("Gf_Free_Z (Z);"));
        // No discard-stream package for a custom root.
        assert!(!output_dir.join("gf_sink_streams.ads").exists());
        assert!(!main_adb.contains("Gf_Sink_Streams"));
    }

    #[test]
    fn param_type_unit_with_resolves_package_root_and_skips_external() {
        use super::param_type_unit_with;
        let mut ast = StructuralAst::new();
        ast.packages.push(package(1, "Zip_Streams"));
        ast.packages.push(package(5, "Crypto.Types"));
        // Nested package CRC inside root BZip2.
        let mut bzip2 = package(2, "BZip2");
        bzip2.parent = None;
        let mut crc = package(3, "CRC");
        crc.parent = Some(PackageId(2));
        ast.packages.push(bzip2);
        ast.packages.push(crc);

        // A type from a parsed package -> `with` that package.
        assert_eq!(
            param_type_unit_with(
                &ast,
                &[
                    "Zip_Streams".to_owned(),
                    "Zipstream_Class_Access".to_owned()
                ]
            ),
            Some("Zip_Streams".to_owned())
        );
        // A dotted child compilation unit is itself with-able, and parser paths
        // may preserve the entire qualified type as one component.
        assert_eq!(
            param_type_unit_with(&ast, &["Crypto.Types.Dword".to_owned()]),
            Some("Crypto.Types".to_owned())
        );
        // A nested package -> `with` the ROOT compilation unit, not the nested one.
        assert_eq!(
            param_type_unit_with(
                &ast,
                &["BZip2".to_owned(), "CRC".to_owned(), "X".to_owned()]
            ),
            Some("BZip2".to_owned())
        );
        // External package not in the tree -> no guessed `with` (never `with Standard;`).
        assert_eq!(
            param_type_unit_with(
                &ast,
                &[
                    "Ada".to_owned(),
                    "Strings".to_owned(),
                    "Unbounded".to_owned(),
                    "Unbounded_String".to_owned()
                ]
            ),
            None
        );
        // Unqualified type -> nothing to `with`.
        assert_eq!(param_type_unit_with(&ast, &["Integer".to_owned()]), None);

        // A type in a PRIVATE child unit cannot be `with`ed from a root harness,
        // so no `with` is emitted (the private-child harness path handles it).
        let mut priv_pkg = package(4, "Unzip.Decompress.Huffman");
        priv_pkg.is_private = true;
        ast.packages.push(priv_pkg);
        assert_eq!(
            param_type_unit_with(
                &ast,
                &[
                    "Unzip.Decompress.Huffman".to_owned(),
                    "Length_Array".to_owned()
                ]
            ),
            None
        );
    }

    #[test]
    fn out_access_to_unknown_designated_is_not_sunk() {
        // An access to a type we cannot size (not a standard array, not a local
        // array decl) must NOT be sunk — emitting `new Opaque_Thing (...)` would
        // not compile. It falls through to the existing null-pointer decoder
        // (the only safe option for a truly opaque access), unchanged.
        let target = subprogram(
            1,
            SubprogramOwner::LibraryLevel,
            "Take",
            vec![access_param(
                "X",
                "Opaque_Ptr",
                "Opaque_Thing",
                ParamMode::Out,
            )],
            None,
        );
        let ast = ast_with(target.clone(), Vec::new(), Vec::new());
        let output_dir = temp_dir("sink-opaque").join("H-0042");

        let main_adb =
            fs::read_to_string(generate_for(&ast, &target, &output_dir).unwrap().main_adb).unwrap();
        assert!(main_adb.contains("X : Opaque_Ptr := null;"));
        assert!(!main_adb.contains("new Opaque_Thing"));
    }

    #[test]
    fn callback_profile_maps_to_canonical_subprogram() {
        use super::callback_subprogram_for_profile;
        assert_eq!(
            callback_subprogram_for_profile("procedure (c : out character)"),
            Some("Src_Char")
        );
        assert_eq!(
            callback_subprogram_for_profile("procedure (b : out interfaces.unsigned_8)"),
            Some("Src_Byte")
        );
        assert_eq!(
            callback_subprogram_for_profile("procedure (c : character)"),
            Some("Snk_Char")
        );
        assert_eq!(
            callback_subprogram_for_profile("procedure (c : in character)"),
            Some("Snk_Char")
        );
        assert_eq!(callback_subprogram_for_profile("procedure"), Some("Noop"));
        assert_eq!(
            callback_subprogram_for_profile("procedure (item : out string; last : out natural)"),
            Some("Src_String")
        );
        assert_eq!(
            callback_subprogram_for_profile("procedure (item : in string)"),
            Some("Snk_String")
        );
        assert_eq!(
            callback_subprogram_for_profile("function return character"),
            Some("Fn_Char")
        );
        assert_eq!(
            callback_subprogram_for_profile("function return boolean"),
            Some("Fn_Boolean")
        );
        // Profiles with no fixed backing are skipped (None), so the parameter
        // falls back to the null decoder rather than emitting non-conformant code.
        assert_eq!(
            callback_subprogram_for_profile("procedure (c : in out character)"),
            None
        );
        assert_eq!(
            callback_subprogram_for_profile("procedure (a : integer; b : integer)"),
            None
        );
        assert_eq!(
            callback_subprogram_for_profile("function (x : integer) return boolean"),
            None
        );
        assert_eq!(
            callback_subprogram_for_profile("procedure (h : out some_handle)"),
            None
        );
    }

    #[test]
    fn access_to_subprogram_param_backed_by_callback() {
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Receive",
            vec![access_param(
                "Get",
                "Getchar_Ptr",
                "procedure (C : out Character)",
                ParamMode::In,
            )],
            None,
        );
        let ast = ast_with(target.clone(), Vec::new(), vec![package(7, "Pkg")]);
        let output_dir = temp_dir("callback").join("H-0042");

        let generated = generate_for(&ast, &target, &output_dir).unwrap();
        let main_adb = fs::read_to_string(&generated.main_adb).unwrap();

        // The callback parameter is backed by the generated source subprogram,
        // not a bare null, and the fuzz buffer is installed before the call.
        assert!(main_adb.contains("with Gf_Callbacks;"));
        assert!(main_adb.contains("Get : Getchar_Ptr := Gf_Callbacks.Src_Char'Access;"));
        assert!(main_adb.contains("Gf_Callbacks.Set (Buf'Unchecked_Access, Last);"));
        // GF_Fuzz_EOF is the normal end-of-input, caught silently (not a finding).
        assert!(main_adb.contains("when Gf_Callbacks.GF_Fuzz_EOF =>"));
        // The callback package is emitted beside the harness.
        assert!(output_dir.join("gf_callbacks.ads").exists());
        assert!(output_dir.join("gf_callbacks.adb").exists());
    }

    #[test]
    fn unsupported_optional_callback_omits_trailing_defaulted_params() {
        let mut callback_type = type_ref("", TypeKind::Access { target: TypeId(0) });
        callback_type.name_path.clear();
        callback_type.constraints =
            Constraints("function (Recipient : Email_Address) return Boolean".to_owned());
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Reply_To",
            vec![
                param("Msg", "Integer", TypeKind::Scalar(ScalarKind::Integer)),
                Parameter {
                    name: "Reply_Filter".to_owned(),
                    mode: ParamMode::AccessMode,
                    type_ref: callback_type,
                    default: Some(Expr("null".to_owned())),
                },
                Parameter {
                    name: "Charset".to_owned(),
                    mode: ParamMode::In,
                    type_ref: type_ref("String", TypeKind::Unknown),
                    default: Some(Expr("ASCII".to_owned())),
                },
            ],
            None,
        );
        let ast = ast_with(target.clone(), Vec::new(), vec![package(7, "Pkg")]);
        let output_dir = temp_dir("optional-callback").join("H-OPTIONAL-CB");

        let main_adb =
            fs::read_to_string(generate_for(&ast, &target, &output_dir).unwrap().main_adb).unwrap();

        assert!(main_adb.contains("Pkg.Reply_To (Msg);"));
        assert!(!main_adb.contains("Reply_Filter :"));
        assert!(!main_adb.contains("Charset :"));
    }

    #[test]
    fn unsupported_defaulted_suffix_is_omitted() {
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Configure",
            vec![
                param("Value", "Integer", TypeKind::Scalar(ScalarKind::Integer)),
                Parameter {
                    name: "Policy".to_owned(),
                    mode: ParamMode::In,
                    type_ref: type_ref("External.Policy", TypeKind::Unknown),
                    default: Some(Expr("Default_Policy".to_owned())),
                },
                Parameter {
                    name: "Label".to_owned(),
                    mode: ParamMode::In,
                    type_ref: type_ref("String", TypeKind::Unknown),
                    default: Some(Expr("\"\"".to_owned())),
                },
            ],
            None,
        );
        let ast = ast_with(target.clone(), Vec::new(), vec![package(7, "Pkg")]);
        let output_dir = temp_dir("defaulted-suffix").join("H-DEFAULT-SUFFIX");

        let main_adb =
            fs::read_to_string(generate_for(&ast, &target, &output_dir).unwrap().main_adb).unwrap();

        assert!(main_adb.contains("Pkg.Configure (Value);"));
        assert!(!main_adb.contains("Policy :"));
        assert!(!main_adb.contains("Label :"));
    }

    #[test]
    fn access_to_object_param_is_not_treated_as_callback() {
        // An access-to-object parameter (`access all Thing`) must NOT be backed
        // by a callback — only access-to-subprogram profiles are.
        let target = subprogram(
            1,
            SubprogramOwner::Package(PackageId(7)),
            "Use_Ptr",
            vec![access_param("P", "Thing_Ptr", "all Thing", ParamMode::In)],
            None,
        );
        let ast = ast_with(target.clone(), Vec::new(), vec![package(7, "Pkg")]);
        let output_dir = temp_dir("not-callback").join("H-0042");

        let main_adb =
            fs::read_to_string(generate_for(&ast, &target, &output_dir).unwrap().main_adb).unwrap();
        assert!(!main_adb.contains("Gf_Callbacks"));
    }
}
