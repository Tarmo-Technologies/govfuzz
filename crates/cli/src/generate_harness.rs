// SPDX-License-Identifier: Apache-2.0

use ada_parser::ast::{
    Package, PackageId, StructuralAst, Subprogram, SubprogramId, SubprogramKind, SubprogramOwner,
    TypeKind, TypeOwner, TypeRef, Visibility,
};
use anyhow::{bail, Context, Result};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

const BUILD_CONTEXT_PROVENANCE_PREFIX: &str = "@govfuzz-build-context-provenance=";
const BUILD_CONTEXT_DROPPED_PREFIX: &str = "@govfuzz-build-context-dropped=";
const BUILD_CONTEXT_CONFIDENCE_PREFIX: &str = "@govfuzz-build-context-confidence=";
const BUILD_CONTEXT_RECOVERY_PREFIX: &str = "@govfuzz-build-context-recovery=";
const BUILD_CONTEXT_LDFLAG_PREFIX: &str = "@govfuzz-build-context-ldflag=";
const BUILD_CONTEXT_CXX_STANDARD_PREFIX: &str = "@govfuzz-build-context-cxx-standard=";
const BUILD_CONTEXT_COMPILER_PREFIX: &str = "@govfuzz-build-context-compiler=";
pub(crate) const BLOCKED_BY_NON_SELF_CONTAINED_HEADER: &str =
    "blocked_by_non_self_contained_header:";

#[derive(Debug, Clone, clap::Args, PartialEq)]
pub struct GenerateHarnessArgs {
    /// Path to the Ada, C, or C++ source file containing the target subprogram.
    pub source: PathBuf,

    /// Subprogram name to harness. If omitted, harness the highest-ranked target.
    #[arg(long)]
    pub target: Option<String>,

    /// Disambiguate duplicate definitions: generate for the definition
    /// at exactly this 1-based line (as printed by list-targets / auto
    /// discovery). Falls back to name matching when the line no longer
    /// matches any definition.
    #[arg(long = "target-line")]
    pub target_line: Option<u32>,

    /// Output directory. Default: generated_harnesses/<harness_id>/.
    #[arg(long, default_value = "generated_harnesses")]
    pub output: PathBuf,

    /// Harness id. Default: stable hash derived from source path and target id.
    #[arg(long)]
    pub id: Option<String>,

    /// Harness type. Default: direct.
    #[arg(long, default_value = "direct")]
    pub kind: String,

    /// Additional Ada source root to include in the generated harness project.
    #[arg(long = "source-root")]
    pub source_roots: Vec<PathBuf>,

    /// GPR project file whose source directories should be included in the generated harness project.
    #[arg(long)]
    pub project: Option<PathBuf>,

    /// Ada source tree to expand into source directories for the generated harness project.
    #[arg(long = "source-tree")]
    pub source_trees: Vec<PathBuf>,

    /// Additional C/C++ source files to link into the generated harness
    /// (resolves multi-file libraries like bzip2 / libxml2 / mbedtls).
    /// Repeatable.
    #[arg(long = "extra-source")]
    pub extra_sources: Vec<PathBuf>,

    /// Additional include directory for the generated C/C++ harness.
    /// Repeatable.
    #[arg(long = "extra-include")]
    pub extra_includes: Vec<PathBuf>,

    /// Cleanup expression to emit after the C/C++ target call. The variable
    /// `R` refers to the target's return value. Example:
    /// `--cleanup "if (R) json_value_free(R)"`. Overrides the built-in
    /// auto-detection (cJSON / libxml2 / parson / expat / ...).
    #[arg(long = "cleanup")]
    pub cleanup: Option<String>,

    /// Concrete type arguments used to instantiate a templated C++ target whose
    /// call sites offered no observed specialization (#455 / §27.5 phase 3).
    /// Comma-separated, positionally aligned with the template's type parameters:
    /// `--template-instantiate int,std::string`. Ignored for a non-template
    /// target, and a call-site-detected instantiation takes precedence.
    #[arg(long = "template-instantiate", value_delimiter = ',')]
    pub template_instantiate: Vec<String>,

    /// Tree-wide type definitions used as a low-priority fallback when a
    /// parameter type is left opaque by the target's own include closure (e.g.
    /// an arch/config-gated typedef like seL4's `word_t`). Populated by the auto
    /// loop from the cross-tree declaration index; empty for direct CLI use.
    #[arg(skip)]
    pub tree_type_defs: Option<TreeTypeDefs>,

    /// Configurable C/C++ decoder synthesis caps (§27.11).
    #[command(flatten)]
    pub decoder_limits: DecoderLimitArgs,

    /// Force-fuzz mode (`auto --force`). When set, a C/C++ parameter the
    /// type-directed decoders would reject is given a best-effort compiling
    /// driver so the target is still built and fuzzed instead of being skipped
    /// `unsupported_params`. Threaded from the `auto` loop; not a standalone
    /// `generate-harness` CLI flag. Default `false` leaves emission unchanged.
    #[arg(skip)]
    pub force: bool,
}

/// CLI overrides for the C and C++ harness decoder synthesis caps (§27.11),
/// flattened into both `govfuzz auto` and `govfuzz generate-harness`. Each flag
/// is optional; an unset flag keeps the historical default
/// ([`harness_gen::c_decoders::DecoderLimits::default`] /
/// [`harness_gen::cpp_decoders::CppDecoderLimits::default`]), so omitting them
/// all reproduces the pre-§27.11 emission byte-for-byte. These tune how deep /
/// wide a single parameter's typed decoder is allowed to grow before a field is
/// left zeroed (C depth), an array is fill-count-fuzzed (C array elems), a
/// parameter is rejected (C decl bytes), or a container/bitset/array is capped
/// (C++). A per-parameter ~1 MiB OOM byte budget is always enforced on top of
/// the C++ caps so a large configured value can't blow memory.
#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
pub struct DecoderLimitArgs {
    /// C: max recursion depth for nested struct/union/array decoder synthesis;
    /// past it a field is left zeroed. Default 4.
    #[arg(long = "max-decode-depth", value_name = "N")]
    pub max_decode_depth: Option<usize>,

    /// C: max array elements decoded per fixed array (a larger array fuzzes its
    /// fill count 0..cap instead of every slot). Default 64.
    #[arg(long = "max-array-elems", value_name = "N")]
    pub max_array_elems: Option<usize>,

    /// C: byte ceiling on a single parameter's synthesised decoder body; a
    /// larger body rejects the parameter. Default 65536.
    #[arg(long = "max-decl-bytes", value_name = "BYTES")]
    pub max_decl_bytes: Option<usize>,

    /// C++: upper bound on a dynamic container's fuzzed element count
    /// (`vector`/`set`/`map`/`span`/…). Default 16. Clamped further by the ~1 MiB
    /// per-parameter OOM budget for known-size elements.
    #[arg(long = "container-size-max", value_name = "N")]
    pub container_size_max: Option<usize>,

    /// C++: largest `std::bitset<N>` whose N bits are decoded individually
    /// before the parameter is skipped. Default 4096.
    #[arg(long = "bitset-max-size", value_name = "N")]
    pub bitset_max_size: Option<usize>,

    /// C++: largest `std::array<T, N>` element count accepted when T's byte size
    /// is unknown at codegen time (a known-size T is bounded by the ~1 MiB
    /// budget instead). Default 4096.
    #[arg(long = "array-max-size", value_name = "N")]
    pub array_max_size: Option<usize>,
}

impl DecoderLimitArgs {
    /// Resolve the C decoder caps, applying defaults for unset flags.
    pub fn c_limits(&self) -> harness_gen::c_decoders::DecoderLimits {
        let d = harness_gen::c_decoders::DecoderLimits::default();
        harness_gen::c_decoders::DecoderLimits {
            depth: self.max_decode_depth.unwrap_or(d.depth),
            array_elems: self.max_array_elems.unwrap_or(d.array_elems),
            decl_bytes: self.max_decl_bytes.unwrap_or(d.decl_bytes),
        }
    }

    /// Resolve the C++ decoder caps, applying defaults for unset flags.
    pub fn cpp_limits(&self) -> harness_gen::cpp_decoders::CppDecoderLimits {
        let d = harness_gen::cpp_decoders::CppDecoderLimits::default();
        harness_gen::cpp_decoders::CppDecoderLimits {
            container_size_max: self.container_size_max.unwrap_or(d.container_size_max),
            bitset_max_size: self.bitset_max_size.unwrap_or(d.bitset_max_size),
            array_max_size: self.array_max_size.unwrap_or(d.array_max_size),
        }
    }
}

/// Tree-wide C and C++ type-definition fallbacks, held behind `Arc` so threading
/// them per-target is a handle clone rather than a deep copy.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TreeTypeDefs {
    pub c: std::sync::Arc<c_parser::CTypeDefs>,
    pub cpp: std::sync::Arc<c_parser::CTypeDefs>,
    /// Tree-wide C opaque-handle lifecycle pairs (§27.2): init/destroy pairs found
    /// across ALL translation units in the tree, computed ONCE in `decl_index`.
    /// Merged into the per-target lifecycle table so a handle whose constructor is
    /// declared in a header the target does NOT directly `#include` is still paired
    /// (instead of being skipped "needs lifecycle support").
    pub c_lifecycle: std::sync::Arc<Vec<harness_gen::c_generate::CHandleLifecycle>>,
}

pub fn run(args: GenerateHarnessArgs) -> Result<()> {
    if !matches!(args.kind.as_str(), "direct" | "sequence" | "servant_direct") {
        bail!("unsupported harness kind '{}'", args.kind);
    }

    match detect_c_family_source(&args.source)? {
        Some(CFamilySource::C) => return run_c_direct(&args),
        Some(CFamilySource::Cpp) => return run_cpp_direct(&args),
        None => {}
    }

    let source = crate::source_text::read_source_text(&args.source)
        .with_context(|| format!("read Ada source {}", args.source.display()))?;
    let source_plan = harness_source_plan(&args)?;
    let ast = build_harness_ast(&source, &args.source, &source_plan.analysis_roots)?;
    if let Some(summary) = ada_concurrency_block_summary(&source) {
        bail!(
            "blocked_by_concurrency: Ada task/protected constructs found ({summary}); direct harness generation requires an explicit wrapper that can wrap scheduling assumptions before fuzzing"
        );
    }
    if let Some(unit) = ada_private_child_unit(&source) {
        // A private child unit can't be named by a separate `procedure Main`.
        // For a direct harness we generate the harness as a private child
        // subprogram of the parent (see `generate_private_child_bridge_direct`);
        // other harness kinds still bail. `<generic child unit>` has no usable
        // dotted name.
        if args.kind == "direct" && unit.contains('.') {
            return generate_private_child_bridge_direct(&args, &ast, &source_plan, &unit);
        }
        bail!(
            "blocked_by_private_child: '{unit}' is a private child unit; it is visible only inside its parent subsystem and cannot be named by a separately compiled harness (GNAT: \"unit in with clause is private child unit\"). Fuzzing it requires a child-unit harness, not a direct-call one"
        );
    }

    match args.kind.as_str() {
        "direct" => generate_direct(&args, &ast, &source_plan),
        "sequence" => generate_sequence(&args, &ast, &source_plan),
        "servant_direct" => generate_servant_direct(&args, &ast, &source_plan),
        _ => unreachable!("harness kind was validated before parsing source"),
    }
}

#[derive(serde::Serialize)]
struct GenerationMetadata<'a> {
    schema_version: u32,
    language: &'a str,
    requested_line_present: bool,
    exact_line_match: bool,
    name_fallback: bool,
    requested_kind: &'a str,
    emitted_path: &'a str,
}

fn write_generation_metadata(
    output_dir: &Path,
    language: &str,
    requested_line: Option<u32>,
    selected_line: u32,
    requested_kind: &str,
    emitted_path: &str,
) -> Result<()> {
    let metadata = GenerationMetadata {
        schema_version: 1,
        language,
        requested_line_present: requested_line.is_some(),
        exact_line_match: requested_line.is_some_and(|line| line == selected_line),
        name_fallback: requested_line.is_some_and(|line| line != selected_line),
        requested_kind,
        emitted_path,
    };
    let bytes = serde_json::to_vec(&metadata)?;
    crate::auto::report::atomic_write(&output_dir.join("generation-metadata.json"), &bytes)?;
    Ok(())
}

/// Programmatic shim around `run()` used by `govfuzz auto`'s attempt
/// loop. The auto loop already knows the source path, target name,
/// output dir, and stable harness id - this wrapper saves it from
/// constructing the full clap-derived args struct.
#[allow(clippy::too_many_arguments)]
pub fn generate_for_path(
    source: &Path,
    target: &str,
    target_line: Option<u32>,
    output: &Path,
    id: &str,
    cleanup: Option<&str>,
    source_tree: Option<&Path>,
    ada_dep_dirs: &[PathBuf],
    tree_type_defs: Option<TreeTypeDefs>,
    decoder_limits: DecoderLimitArgs,
    force: bool,
) -> Result<()> {
    generate_for_path_with_kind(
        source,
        target,
        target_line,
        output,
        id,
        "direct",
        cleanup,
        source_tree,
        ada_dep_dirs,
        tree_type_defs,
        decoder_limits,
        force,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn generate_for_path_with_kind(
    source: &Path,
    target: &str,
    target_line: Option<u32>,
    output: &Path,
    id: &str,
    kind: &str,
    cleanup: Option<&str>,
    source_tree: Option<&Path>,
    ada_dep_dirs: &[PathBuf],
    tree_type_defs: Option<TreeTypeDefs>,
    decoder_limits: DecoderLimitArgs,
    force: bool,
) -> Result<()> {
    let args = GenerateHarnessArgs {
        source: source.to_path_buf(),
        target: Some(target.to_owned()),
        target_line,
        output: output.to_path_buf(),
        id: Some(id.to_owned()),
        kind: kind.to_owned(),
        source_roots: Vec::new(),
        project: None,
        // The whole scanned tree is a source tree: legacy projects spread
        // withed units across sibling directories (`src/`, `src-checkers/`),
        // so the harness project must see all of them to resolve them.
        // `--ada-deps` directories (e.g. SweetAda's `core/`, holding `Bits`)
        // join the trees so a parameter typed with a dependency package's type
        // (`Bits.Byte_Array`) resolves to its real array definition instead of
        // falling through to unsupported_params.
        source_trees: source_tree
            .map(Path::to_path_buf)
            .into_iter()
            .chain(ada_dep_dirs.iter().filter(|p| p.is_dir()).cloned())
            .collect(),
        extra_sources: Vec::new(),
        extra_includes: Vec::new(),
        cleanup: cleanup.map(str::to_owned),
        template_instantiate: Vec::new(),
        tree_type_defs,
        decoder_limits,
        force,
    };
    run(args)
}

/// Direct harness for a target in a private child unit, reached through a
/// generated public-child bridge (see `crate::ada_bridge`). The bridge files
/// are written into the harness dir (a build source root) and the harness
/// targets the bridge's re-export as an ordinary public subprogram.
fn generate_private_child_bridge_direct(
    args: &GenerateHarnessArgs,
    ast: &StructuralAst,
    source_plan: &HarnessSourcePlan,
    child_unit: &str,
) -> Result<()> {
    let target = select_subprogram(ast, args.target.as_deref(), args.target_line)?;
    if !crate::ada_bridge::target_is_bridgeable(target) {
        bail!(
            "blocked_by_private_child: target '{}' in private child '{child_unit}' is not a plain subprogram; a bridge re-export is not applicable",
            target.name
        );
    }
    // A private child unit (which is what put us on this path) cannot be reached
    // by a separately compiled public bridge: Ada visibility (RM 10.1.2) makes a
    // private child visible only to its parent's body/private part and to other
    // PRIVATE descendants, so a public `<parent>.Gf_Bridge` body may not `with`
    // it to forward the call. Generate the harness itself as a *private child
    // subprogram* of the parent instead — its own `private procedure` status lets
    // its body `with` the private child (and see the parent's private part). This
    // covers both private-part-typed profiles (UnZip.Decompress.Decompress_Data)
    // and targets declared in a private child package (UnZip.Decompress.Huffman's
    // HufT_build).
    generate_private_child_subprogram_direct(args, ast, source_plan, child_unit, target)
}

/// Harness for a private-child target whose signature uses parent-private types
/// (so a public bridge can't re-export it). The harness IS a *private child
/// subprogram* of the parent (`private procedure UnZip.Gf_Harness`): its body
/// sees the parent's private part (e.g. `UnZip.P_Stream`) and may `with` the
/// private child it calls. The build picks the child harness file as Main.
fn generate_private_child_subprogram_direct(
    args: &GenerateHarnessArgs,
    ast: &StructuralAst,
    source_plan: &HarnessSourcePlan,
    child_unit: &str,
    target: &Subprogram,
) -> Result<()> {
    let parent = child_unit.rsplit_once('.').map(|(p, _)| p).ok_or_else(|| {
        anyhow::anyhow!("blocked_by_private_child: '{child_unit}' has no parent unit")
    })?;
    let harness_unit = format!("{parent}.Gf_Harness");
    // Virtual package named after the private child unit (full dotted, no
    // parent) so the harness `with`s `UnZip.Decompress` and qualifies the call
    // as `UnZip.Decompress.Decompress_Data`.
    let (virtual_ast, virtual_target) =
        crate::ada_bridge::virtual_bridge_target(ast, target, child_unit);

    let id = args
        .id
        .clone()
        .unwrap_or_else(|| compute_default_id(&args.source, target));
    let output_dir = args.output.join(&id);
    std::fs::create_dir_all(&output_dir)
        .with_context(|| format!("create harness dir {}", output_dir.display()))?;

    let result = harness_gen::generate_direct_harness(harness_gen::GenerateDirectArgs {
        ast: &virtual_ast,
        target_subprogram: &virtual_target,
        harness_id: id,
        output_dir: output_dir.clone(),
        source_path: args.source.clone(),
        source_roots: source_plan.gpr_roots.clone(),
        project_imports: source_plan.project_imports.clone(),
        generic_instance: None,
        generic_call: None,
        generic_suppress_params: false,
        child_harness_unit: Some(harness_unit),
        force: args.force,
    })?;

    write_project_profile_if_requested(args, &output_dir, &result.gpr, source_plan, ast)?;
    write_ada_dictionary(args, ast, &output_dir)?;
    write_generation_metadata(
        &output_dir,
        "ada",
        args.target_line,
        target.decl_span.start_line,
        &args.kind,
        "private_child_direct",
    )?;
    print_generated(&result, &output_dir);
    Ok(())
}

fn generate_direct(
    args: &GenerateHarnessArgs,
    ast: &StructuralAst,
    source_plan: &HarnessSourcePlan,
) -> Result<()> {
    let target = select_subprogram(ast, args.target.as_deref(), args.target_line)?;
    let (generic_instance, generic_call, generic_suppress_params) =
        resolve_generic_instance(ast, target, &args.source)?;
    let id = args
        .id
        .clone()
        .unwrap_or_else(|| compute_default_id(&args.source, target));
    let output_dir = args.output.join(&id);
    let result = harness_gen::generate_direct_harness(harness_gen::GenerateDirectArgs {
        ast,
        target_subprogram: target,
        harness_id: id,
        output_dir: output_dir.clone(),
        source_path: args.source.clone(),
        source_roots: source_plan.gpr_roots.clone(),
        project_imports: source_plan.project_imports.clone(),
        generic_instance,
        generic_call,
        generic_suppress_params,
        child_harness_unit: None,
        force: args.force,
    })?;

    write_project_profile_if_requested(args, &output_dir, &result.gpr, source_plan, ast)?;
    write_ada_dictionary(args, ast, &output_dir)?;
    write_generation_metadata(
        &output_dir,
        "ada",
        args.target_line,
        target.decl_span.start_line,
        &args.kind,
        "direct",
    )?;
    print_generated(&result, &output_dir);

    Ok(())
}

fn generate_servant_direct(
    args: &GenerateHarnessArgs,
    ast: &StructuralAst,
    source_plan: &HarnessSourcePlan,
) -> Result<()> {
    let target = select_subprogram(ast, args.target.as_deref(), args.target_line)?;
    ensure_target_not_in_generic_package(ast, target)?;
    let id = args
        .id
        .clone()
        .unwrap_or_else(|| compute_default_id(&args.source, target));
    let output_dir = args.output.join(&id);
    let result =
        harness_gen::generate_servant_direct_harness(harness_gen::GenerateServantDirectArgs {
            ast,
            target_subprogram: target,
            harness_id: id,
            output_dir: output_dir.clone(),
            source_path: args.source.clone(),
            source_roots: source_plan.gpr_roots.clone(),
            project_imports: source_plan.project_imports.clone(),
        })?;

    write_project_profile_if_requested(args, &output_dir, &result.gpr, source_plan, ast)?;
    write_ada_dictionary(args, ast, &output_dir)?;
    write_generation_metadata(
        &output_dir,
        "ada",
        args.target_line,
        target.decl_span.start_line,
        &args.kind,
        "servant_direct",
    )?;
    print_generated(&result, &output_dir);

    Ok(())
}

fn generate_sequence(
    args: &GenerateHarnessArgs,
    ast: &StructuralAst,
    source_plan: &HarnessSourcePlan,
) -> Result<()> {
    let target_package = select_sequence_package(ast, args.target.as_deref())?;
    let id = args
        .id
        .clone()
        .unwrap_or_else(|| compute_default_package_id(&args.source, target_package));
    let output_dir = args.output.join(&id);
    let result = harness_gen::generate_sequence_harness(harness_gen::GenerateSequenceArgs {
        ast,
        target_package,
        harness_id: id,
        output_dir: output_dir.clone(),
        source_path: args.source.clone(),
        source_roots: source_plan.gpr_roots.clone(),
        project_imports: source_plan.project_imports.clone(),
    })?;

    write_project_profile_if_requested(args, &output_dir, &result.gpr, source_plan, ast)?;
    write_ada_dictionary(args, ast, &output_dir)?;
    write_generation_metadata(&output_dir, "ada", None, 0, &args.kind, "sequence")?;
    print_generated(&result, &output_dir);

    Ok(())
}

fn write_ada_dictionary(
    args: &GenerateHarnessArgs,
    ast: &StructuralAst,
    output_dir: &Path,
) -> Result<()> {
    let source = crate::source_text::read_source_text(&args.source)
        .with_context(|| format!("read Ada source {}", args.source.display()))?;
    let tokens = collect_ada_dictionary_tokens(ast, &source);
    write_harness_dictionary(output_dir, &tokens)
}

fn collect_ada_dictionary_tokens(ast: &StructuralAst, source: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let dialect = ast
        .units
        .first()
        .map(|unit| unit.ada_standard)
        .unwrap_or(ada_parser::ast::AdaStandard::Ada2012);
    let lexical_tokens = ada_parser::lexer::lex(source, dialect);
    collect_ada_enum_literals_from_tokens(source, &lexical_tokens, &mut tokens);

    for ty in &ast.types {
        if let TypeKind::Enum(literals) = &ty.kind {
            for literal in literals {
                push_unique_dictionary_token(&mut tokens, literal.clone());
            }
        }
    }

    for token in lexical_tokens {
        if let ada_parser::lexer::TokenKind::StringLiteral(value) = token.kind {
            push_unique_dictionary_token(&mut tokens, value);
        }
    }
    tokens
}

fn collect_ada_enum_literals_from_tokens(
    source: &str,
    lexical_tokens: &[ada_parser::lexer::Token],
    tokens: &mut Vec<String>,
) {
    use ada_parser::lexer::TokenKind;

    let mut index = 0;
    while index < lexical_tokens.len() {
        if lexical_tokens[index].kind != TokenKind::KwType {
            index += 1;
            continue;
        }
        let Some(mut cursor) =
            (index + 1..lexical_tokens.len()).find(|i| lexical_tokens[*i].kind == TokenKind::KwIs)
        else {
            break;
        };
        cursor += 1;
        if lexical_tokens.get(cursor).map(|token| &token.kind) != Some(&TokenKind::LParen) {
            index += 1;
            continue;
        }
        cursor += 1;
        while cursor < lexical_tokens.len() && lexical_tokens[cursor].kind != TokenKind::RParen {
            match &lexical_tokens[cursor].kind {
                TokenKind::Identifier(_) => {
                    if let Some(literal) = ada_token_source_text(source, &lexical_tokens[cursor]) {
                        push_unique_dictionary_token(tokens, literal);
                    }
                }
                TokenKind::CharLiteral(ch) => {
                    push_unique_dictionary_token(tokens, ch.to_string());
                }
                TokenKind::StringLiteral(value) => {
                    push_unique_dictionary_token(tokens, value.clone());
                }
                _ => {}
            }
            cursor += 1;
        }
        index = cursor.saturating_add(1);
    }
}

fn ada_token_source_text(source: &str, token: &ada_parser::lexer::Token) -> Option<String> {
    source
        .get(token.text_span.start as usize..token.text_span.end as usize)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn push_unique_dictionary_token(tokens: &mut Vec<String>, token: String) {
    if !token.is_empty() && !tokens.contains(&token) {
        tokens.push(token);
    }
}

fn write_project_profile_if_requested(
    args: &GenerateHarnessArgs,
    output_dir: &Path,
    gpr_path: &Path,
    source_plan: &HarnessSourcePlan,
    ast: &StructuralAst,
) -> Result<()> {
    let Some(project) = &args.project else {
        return Ok(());
    };
    let profile = ada_project_profile(project, source_plan, ast)?;
    let profile_path = output_dir.join("govfuzz-project-profile.json");
    fs::write(&profile_path, serde_json::to_vec_pretty(&profile)?)
        .with_context(|| format!("write {}", profile_path.display()))?;
    annotate_gpr_with_project_profile(gpr_path, project)?;
    Ok(())
}

fn annotate_gpr_with_project_profile(gpr_path: &Path, project: &Path) -> Result<()> {
    let original =
        fs::read_to_string(gpr_path).with_context(|| format!("read {}", gpr_path.display()))?;
    if original.contains("-- GovFuzz project profile: govfuzz-project-profile.json") {
        return Ok(());
    }
    let annotated = format!(
        "-- GovFuzz project profile: govfuzz-project-profile.json\n-- GPR provenance: {}\n{}",
        project.display(),
        original
    );
    fs::write(gpr_path, annotated).with_context(|| format!("write {}", gpr_path.display()))
}

fn ada_project_profile(
    project: &Path,
    source_plan: &HarnessSourcePlan,
    ast: &StructuralAst,
) -> Result<serde_json::Value> {
    let text = fs::read_to_string(project)
        .with_context(|| format!("read GPR project {}", project.display()))?;
    let project_dir = project
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let gpr = strip_gpr_comments(&text);
    let (source_dirs, unsupported_constructs) = gpr_source_dir_profile(&gpr);
    let subunits = collect_project_subunits(&project_dir, &source_plan.analysis_roots)?;
    let standards = ast
        .units
        .iter()
        .map(|unit| unit.ada_standard.to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    Ok(json!({
        "schema_version": "govfuzz.ada_project_profile.v1",
        "project": {
            "path": project.display().to_string(),
            "provenance": "gpr",
        },
        "project_variables": gpr_project_variables(&gpr),
        "source_dirs": source_dirs,
        "unsupported_constructs": unsupported_constructs,
        "subunits": subunits,
        "compatibility": {
            "ada_standards": if standards.is_empty() { vec!["ada_2012".to_owned()] } else { standards },
        },
    }))
}

fn gpr_project_variables(gpr: &str) -> Vec<serde_json::Value> {
    let type_values = gpr_type_values(gpr);
    let mut variables = Vec::new();
    for statement in gpr.split(';') {
        let normalized = statement.to_ascii_lowercase();
        if !normalized.contains("external") || !statement.contains(':') || !statement.contains(":=")
        {
            continue;
        }
        let Some((name, rest)) = statement.split_once(':') else {
            continue;
        };
        let Some((type_name, _)) = rest.split_once(":=") else {
            continue;
        };
        let strings = quoted_strings(statement);
        let external_name = strings.first().cloned().unwrap_or_default();
        let default = strings.get(1).cloned().unwrap_or_default();
        let type_key = type_name.trim().to_ascii_lowercase();
        variables.push(json!({
            "name": name.trim(),
            "type": type_name.trim(),
            "external_name": external_name,
            "default": default,
            "values": type_values.get(&type_key).cloned().unwrap_or_default(),
        }));
    }
    variables
}

fn gpr_type_values(gpr: &str) -> BTreeMap<String, Vec<String>> {
    let mut values = BTreeMap::new();
    for line in gpr.lines() {
        let statement = line.trim();
        let normalized = statement.to_ascii_lowercase();
        if !normalized.starts_with("type ") || !normalized.contains(" is ") {
            continue;
        }
        let without_type = statement[5..].trim_start();
        let Some((name, _)) = without_type.split_once(" is ") else {
            continue;
        };
        values.insert(name.trim().to_ascii_lowercase(), quoted_strings(statement));
    }
    values
}

fn gpr_source_dir_profile(gpr: &str) -> (Vec<serde_json::Value>, Vec<serde_json::Value>) {
    let mut source_dirs = Vec::new();
    let mut unsupported = Vec::new();
    for statement in gpr.split(';') {
        let normalized = statement.to_ascii_lowercase();
        if !(normalized.contains("for sourcedirs") || normalized.contains("for source_dirs")) {
            continue;
        }
        if !normalized.contains(" use ") {
            continue;
        }
        let strings = quoted_strings(statement);
        if statement.contains('&') {
            if let Some(first_static) = strings.first() {
                source_dirs.push(json!({
                    "path": first_static,
                    "confidence": "high",
                    "provenance": "gpr_source_dirs",
                }));
            }
            unsupported.push(json!({
                "kind": "dynamic_source_dir",
                "statement": statement.trim(),
                "hint": "materialize the selected scenario or pass --source-tree/--source-root for the resolved directory",
            }));
        } else {
            for dir in strings {
                source_dirs.push(json!({
                    "path": dir,
                    "confidence": "high",
                    "provenance": "gpr_source_dirs",
                }));
            }
        }
    }
    (source_dirs, unsupported)
}

fn collect_project_subunits(
    project_dir: &Path,
    roots: &[PathBuf],
) -> Result<Vec<serde_json::Value>> {
    let mut files = BTreeSet::new();
    files.insert(project_dir.to_path_buf());
    for root in roots {
        files.insert(root.clone());
    }
    let mut source_files = Vec::new();
    for root in files {
        collect_ada_files(&root, &mut source_files)?;
    }
    source_files.sort();
    source_files.dedup();

    let mut subunits = Vec::new();
    for path in source_files {
        // Latin-1 fallback keeps non-UTF-8 legacy subunits visible.
        let source = crate::source_text::read_source_text(&path)
            .with_context(|| format!("read {}", path.display()))?;
        if let Some(parent) = ada_subunit_parent(&source) {
            subunits.push(json!({
                "path": relative_project_path(project_dir, &path),
                "parent": parent,
            }));
        }
    }
    Ok(subunits)
}

fn collect_ada_files(root: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    if root.is_file() {
        if is_ada_source(root) {
            files.push(root.to_path_buf());
        }
        return Ok(());
    }
    if !root.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(root).with_context(|| format!("read directory {}", root.display()))? {
        let entry = entry.with_context(|| format!("read directory entry in {}", root.display()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_ada_files(&path, files)?;
        } else if is_ada_source(&path) {
            files.push(path);
        }
    }
    Ok(())
}

fn relative_project_path(project_dir: &Path, path: &Path) -> String {
    path.strip_prefix(project_dir)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn ada_subunit_parent(source: &str) -> Option<String> {
    let folded = source.to_ascii_lowercase();
    let separate = folded.find("separate")?;
    let after = &source[separate..];
    let open = after.find('(')?;
    let close = after[open + 1..].find(')')?;
    let parent = after[open + 1..open + 1 + close].trim();
    if parent.is_empty() {
        None
    } else {
        Some(parent.to_owned())
    }
}

/// Detect a private child compilation unit: its declaration begins with the
/// reserved word `private` followed by a unit keyword (and, for non-generic
/// units, a dotted child name). Such units are visible only inside their parent
/// subsystem, so an external harness cannot `with` them. Returns the unit's
/// dotted name when found.
fn ada_private_child_unit(source: &str) -> Option<String> {
    for raw in source.lines() {
        let line = raw.trim_start();
        // Skip comments; only a real declaration line matters.
        if line.starts_with("--") {
            continue;
        }
        let Some(rest) = line.strip_prefix("private ").or_else(|| {
            line.strip_prefix("private\t")
                .or_else(|| (line == "private").then_some(""))
        }) else {
            continue;
        };
        let rest = rest.trim_start();
        // `private generic ...` heads a private generic child unit.
        if rest.starts_with("generic") && rest[7..].starts_with(|c: char| c.is_whitespace()) {
            return Some("<generic child unit>".to_owned());
        }
        for keyword in ["package", "procedure", "function"] {
            if let Some(after) = rest.strip_prefix(keyword) {
                if !after.starts_with(|c: char| c.is_whitespace()) {
                    continue;
                }
                let name: String = after
                    .trim_start()
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
                    .collect();
                // A child unit's defining name is dotted (`Parent.Child`); a
                // root unit named here would be a false positive.
                if name.contains('.') {
                    return Some(name);
                }
            }
        }
    }
    None
}

pub(crate) fn ada_concurrency_block_summary(source: &str) -> Option<String> {
    let mut tasks = 0usize;
    let mut protected = 0usize;
    let mut entries = 0usize;
    for line in source.lines() {
        let folded = line
            .split_once("--")
            .map_or(line, |(code, _)| code)
            .trim()
            .to_ascii_lowercase();
        if folded.starts_with("task type ") || folded.starts_with("task ") {
            tasks += 1;
        }
        if folded.starts_with("protected type ") || folded.starts_with("protected ") {
            protected += 1;
        }
        if folded.starts_with("entry ") || folded.starts_with("accept ") {
            entries += 1;
        }
    }
    if tasks == 0 && protected == 0 && entries == 0 {
        None
    } else {
        Some(format!("task/protected summary: tasks={tasks}, protected_objects={protected}, entries_or_accepts={entries}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HarnessSourcePlan {
    analysis_roots: Vec<PathBuf>,
    gpr_roots: Vec<PathBuf>,
    project_imports: Vec<PathBuf>,
}

fn harness_source_plan(args: &GenerateHarnessArgs) -> Result<HarnessSourcePlan> {
    let mut analysis_roots = args.source_roots.clone();
    let mut gpr_roots = args.source_roots.clone();
    let mut project_imports = Vec::new();

    if let Some(project) = &args.project {
        project_imports.push(project.clone());
        analysis_roots.extend(project_source_dirs(project, &args.source_trees)?);
    }

    for tree in &args.source_trees {
        let tree_roots = expand_source_tree(tree)?;
        analysis_roots.extend(tree_roots.clone());
        if project_imports.is_empty() {
            gpr_roots.extend(tree_roots);
        }
    }

    // Always treat the target source file's own directory as a root. In a flat
    // source tree (e.g. zip-ada's `zip_lib/`) this lets sibling, parent, and
    // transitively-withed units resolve for type analysis and compile even when
    // no explicit roots/trees were given — which is how `govfuzz auto` invokes
    // generation. Without this, abstract-stream and named-array parameters
    // can't be resolved and the target is skipped as un-harnessable.
    if let Some(parent) = args.source.parent() {
        let parent = parent.to_path_buf();
        analysis_roots.push(parent.clone());
        if project_imports.is_empty() {
            gpr_roots.push(parent);
        }
    }

    Ok(HarnessSourcePlan {
        analysis_roots: dedup_paths(analysis_roots),
        gpr_roots: dedup_paths(gpr_roots),
        project_imports: dedup_paths(project_imports),
    })
}

fn expand_source_tree(tree: &Path) -> Result<Vec<PathBuf>> {
    if !tree.is_dir() {
        bail!(
            "source tree '{}' does not exist or is not a directory; use --source-root for exact source directories",
            tree.display()
        );
    }

    let mut dirs = BTreeSet::new();
    collect_ada_source_dirs(tree, &mut dirs)
        .with_context(|| format!("scan source tree {}", tree.display()))?;
    Ok(dirs.into_iter().collect())
}

fn collect_ada_source_dirs(dir: &Path, dirs: &mut BTreeSet<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("read directory {}", dir.display()))? {
        let entry = entry.with_context(|| format!("read directory entry in {}", dir.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("read file type {}", path.display()))?;
        if file_type.is_dir() {
            collect_ada_source_dirs(&path, dirs)?;
        } else if file_type.is_file() && is_ada_source(&path) {
            if let Some(parent) = path.parent() {
                dirs.insert(parent.to_path_buf());
            }
        }
    }
    Ok(())
}

fn is_ada_source(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext.to_ascii_lowercase().as_str(), "adb" | "ads"))
}

/// Decide how to reach a target that lives in a generic package: synthesise an
/// instantiation when the generic's formal part is a stereotyped codec shape
/// (`with function Read_Byte return Byte;` etc.), so the fuzz input flows
/// through the instantiated callbacks. Returns `(None, None)` for an ordinary
/// (non-generic) target. Bails `blocked_by_generic` when the generic cannot yet
/// be instantiated - a generic subprogram, a parametered generic operation, or
/// a formal we cannot synthesise - so the auto loop records a clean skip.
type GenericResolution = (
    Option<harness_gen::generic_instance::GenericInstance>,
    Option<String>,
    bool,
);

fn resolve_generic_instance(
    ast: &StructuralAst,
    target: &Subprogram,
    source_path: &Path,
) -> Result<GenericResolution> {
    use harness_gen::generic_instance::{synthesize, GenericUnit, INSTANCE_NAME};

    let read_source = || {
        crate::source_text::read_source_text(source_path)
            .with_context(|| format!("read Ada source {}", source_path.display()))
    };
    let owner_name = |target: &Subprogram| match &target.owner {
        SubprogramOwner::Package(pkg_id) => ast
            .packages
            .iter()
            .find(|pkg| pkg.id == *pkg_id)
            .map(|pkg| pkg.name.clone()),
        SubprogramOwner::LibraryLevel => None,
    };

    // Case 1: the target is itself a generic subprogram (e.g. the codecs'
    // `LZMA.Encoding.Encode`). Instantiate it and call with no arguments, so
    // every one of its own parameters must carry a default.
    if target.is_generic {
        if target.params.iter().any(|param| param.default.is_none()) {
            bail!(
                "blocked_by_generic: generic subprogram '{}' has a parameter without a default; it cannot be called from a no-argument instantiation",
                target.name
            );
        }
        let keyword = if target.return_type.is_some() {
            "function"
        } else {
            "procedure"
        };
        let owner = owner_name(target);
        let instance_of = match &owner {
            Some(pkg) => format!("{pkg}.{}", target.name),
            None => target.name.clone(),
        };
        // The shared formal types (e.g. `Byte`) live in the owner's parent
        // package; `use` it so the stubs compile.
        let use_parent = owner
            .as_ref()
            .and_then(|pkg| pkg.rsplit_once('.').map(|(parent, _)| parent.to_owned()))
            .or(owner);
        let unit = GenericUnit {
            keyword,
            decl_search: format!("{keyword} {}", target.name),
            instance_of,
            use_parent,
        };
        return match synthesize(&read_source()?, &unit) {
            Ok(instance) => Ok((Some(instance), Some(INSTANCE_NAME.to_owned()), true)),
            Err(reason) => bail!(
                "blocked_by_generic: generic subprogram '{}' cannot be instantiated: {reason}",
                target.name
            ),
        };
    }

    // Case 2: the target is an operation of a generic package (e.g.
    // `BZip2.Decoding.Decompress`).
    let SubprogramOwner::Package(pkg_id) = &target.owner else {
        return Ok((None, None, false));
    };
    let Some(pkg) = ast
        .packages
        .iter()
        .find(|pkg| pkg.id == *pkg_id)
        .filter(|pkg| pkg.is_generic)
    else {
        return Ok((None, None, false));
    };
    // A parametered operation of a generic package (e.g.
    // `LZMA.Decoding.Decompress (hints : LZMA_Hints)`) is fuzzable: the
    // instantiation exposes the operation *and* every concrete type declared in
    // the generic package as `<instance>.<name>`, so the direct decoder can
    // synthesise the arguments. `build_context` qualifies any param whose type
    // is declared in this generic package with the instance name. Params whose
    // types are genuinely unbuildable still skip cleanly via the decoder's
    // `UnsupportedParamType` path. (`synthesize` below bails when the generic
    // has a formal *type*, so by here all param types are concrete.)
    // `pkg.name` is the dotted unit name (lower case, which Ada accepts).
    let unit = GenericUnit {
        keyword: "package",
        decl_search: format!("package {}", pkg.name),
        instance_of: pkg.name.clone(),
        use_parent: pkg
            .name
            .rsplit_once('.')
            .map(|(parent, _)| parent.to_owned()),
    };
    match synthesize(&read_source()?, &unit) {
        Ok(instance) => {
            let call = format!("{}.{}", INSTANCE_NAME, target.name);
            Ok((Some(instance), Some(call), false))
        }
        Err(reason) => bail!(
            "blocked_by_generic: generic package '{}' cannot be instantiated: {reason}",
            pkg.name
        ),
    }
}

/// Generic subprograms - whether a generic subprogram itself (`generic
/// procedure Traverse (...)`) or any subprogram declared inside a generic
/// package - cannot be called by a direct-call harness: the generic must first
/// be instantiated with concrete actuals, and GNAT rejects the uninstantiated
/// call ("prefix must not be a generic package" / "must instantiate generic
/// ... before call"). Surface this as a clean skip (mirroring the
/// `blocked_by_concurrency` guard) instead of emitting a harness that can only
/// fail to build.
fn ensure_target_not_in_generic_package(ast: &StructuralAst, target: &Subprogram) -> Result<()> {
    if target.is_generic {
        bail!(
            "blocked_by_generic: target '{}' is a generic subprogram; a generic must be instantiated with concrete actuals before it can be called - direct harness generation cannot name an uninstantiated generic",
            target.name
        );
    }
    let SubprogramOwner::Package(pkg_id) = &target.owner else {
        return Ok(());
    };
    if let Some(pkg) = ast
        .packages
        .iter()
        .find(|pkg| pkg.id == *pkg_id)
        .filter(|pkg| pkg.is_generic)
    {
        bail!(
            "blocked_by_generic: target '{}' is declared in generic package '{}'; a generic package must be instantiated with concrete actuals before its subprograms can be called - direct harness generation cannot name an uninstantiated generic",
            target.name,
            pkg.name
        );
    }
    Ok(())
}

fn select_subprogram<'a>(
    ast: &'a StructuralAst,
    requested: Option<&str>,
    target_line: Option<u32>,
) -> Result<&'a Subprogram> {
    match requested {
        Some(name) => {
            let mut matches = ast
                .subprograms
                .iter()
                .filter(|subprogram| subprogram.name.eq_ignore_ascii_case(name))
                .collect::<Vec<_>>();
            matches.sort_by_key(|subprogram| subprogram.decl_span.start_line);
            if let Some(line) = target_line {
                if let Some(exact) = matches
                    .iter()
                    .find(|subprogram| subprogram.decl_span.start_line == line)
                {
                    return Ok(*exact);
                }
            }
            matches
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("subprogram '{}' not found", name))
        }
        None => target_rank::rank_targets(ast)
            .into_iter()
            .next()
            .and_then(|ranked| {
                ast.subprograms
                    .iter()
                    .find(|subprogram| subprogram.id == ranked.subprogram_id)
            })
            .ok_or_else(|| anyhow::anyhow!("no subprograms found in source")),
    }
}

/// Silences the "Generated <lang> harness '<id>' at <dir>" banners. The
/// `generate-harness` SUBCOMMAND wants them, but the `auto` sweep silences them:
/// its live progress line owns the terminal, and interleaving these stdout
/// banners with the in-place stderr progress line garbled the output (e.g.
/// "generating harnessGenerated C++ harness"). Per-target harness dirs stay in
/// the run report.
static GENERATION_BANNER_SILENCED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Suppress (or re-enable) the generation banners; `auto` calls this with `true`.
pub fn silence_generation_banner(silent: bool) {
    GENERATION_BANNER_SILENCED.store(silent, std::sync::atomic::Ordering::Relaxed);
}

fn generation_banner_enabled() -> bool {
    !GENERATION_BANNER_SILENCED.load(std::sync::atomic::Ordering::Relaxed)
}

fn print_generated(result: &harness_gen::GeneratedFiles, output_dir: &Path) {
    if !generation_banner_enabled() {
        return;
    }
    println!(
        "Generated harness '{}' at {}",
        result.harness_id,
        output_dir.display()
    );
    println!("  main.adb -> {}", result.main_adb.display());
    println!("  gpr      -> {}", result.gpr.display());
}

fn project_source_dirs(project: &Path, search_roots: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut visited = HashSet::new();
    collect_project_source_dirs(project, search_roots, &mut visited)
}

fn collect_project_source_dirs(
    project: &Path,
    search_roots: &[PathBuf],
    visited: &mut HashSet<PathBuf>,
) -> Result<Vec<PathBuf>> {
    let project = normalize_path(project);
    if !visited.insert(project.clone()) {
        return Ok(Vec::new());
    }

    let text = fs::read_to_string(&project)
        .with_context(|| format!("read GPR project {}", project.display()))?;
    let project_dir = project
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let gpr = strip_gpr_comments(&text);

    let mut roots = Vec::new();
    for import in gpr_import_paths(&gpr) {
        let Some(import) = resolve_project_import(&project_dir, &import, search_roots)? else {
            continue;
        };
        roots.extend(collect_project_source_dirs(&import, search_roots, visited)?);
    }
    for dir in gpr_source_dirs(&gpr) {
        roots.push(project_dir.join(dir));
    }

    Ok(dedup_paths(roots))
}

fn resolve_project_import(
    project_dir: &Path,
    import: &Path,
    search_roots: &[PathBuf],
) -> Result<Option<PathBuf>> {
    let path = project_dir.join(import);
    if path.is_file() {
        return Ok(Some(path));
    }

    if path.extension().is_none() {
        let gpr_path = path.with_extension("gpr");
        if gpr_path.is_file() {
            return Ok(Some(gpr_path));
        }
    }

    if let Some(found) = find_project_import_in_roots(import, search_roots)? {
        return Ok(Some(found));
    }

    if search_roots.is_empty() {
        return Ok(Some(path));
    }

    eprintln!(
        "warning: skipped unresolved GPR import '{}' from {}",
        import.display(),
        project_dir.display()
    );
    Ok(None)
}

fn find_project_import_in_roots(
    import: &Path,
    search_roots: &[PathBuf],
) -> Result<Option<PathBuf>> {
    let mut matches = Vec::new();
    for root in search_roots {
        let direct = root.join(import);
        push_existing_project_path(&direct, &mut matches);
        collect_project_import_matches(root, import, &mut matches)
            .with_context(|| format!("search GPR imports under {}", root.display()))?;
    }
    let matches = dedup_paths(matches);
    if matches.len() == 1 {
        Ok(matches.into_iter().next())
    } else if matches.is_empty() {
        Ok(None)
    } else {
        eprintln!(
            "warning: skipped ambiguous GPR import '{}' with {} matches",
            import.display(),
            matches.len()
        );
        Ok(None)
    }
}

fn collect_project_import_matches(
    dir: &Path,
    import: &Path,
    matches: &mut Vec<PathBuf>,
) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(dir).with_context(|| format!("read directory {}", dir.display()))? {
        let entry = entry.with_context(|| format!("read directory entry in {}", dir.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("read file type {}", path.display()))?;
        if file_type.is_dir() {
            collect_project_import_matches(&path, import, matches)?;
        } else if file_type.is_file() && project_import_file_matches(&path, import) {
            matches.push(path);
        }
    }
    Ok(())
}

fn push_existing_project_path(path: &Path, matches: &mut Vec<PathBuf>) {
    if path.is_file() {
        matches.push(path.to_path_buf());
    }
    if path.extension().is_none() {
        let gpr_path = path.with_extension("gpr");
        if gpr_path.is_file() {
            matches.push(gpr_path);
        }
    }
}

fn project_import_file_matches(path: &Path, import: &Path) -> bool {
    let Some(file_name) = import.file_name() else {
        return false;
    };
    if path.file_name() == Some(file_name) {
        return true;
    }
    if import.extension().is_none() {
        let mut with_ext = file_name.to_os_string();
        with_ext.push(".gpr");
        return path.file_name().is_some_and(|name| name == with_ext);
    }
    false
}

fn gpr_import_paths(gpr: &str) -> Vec<PathBuf> {
    gpr.split(';')
        .filter(|statement| {
            let normalized = statement.trim_start().to_ascii_lowercase();
            normalized.starts_with("with ") || normalized.starts_with("limited with ")
        })
        .flat_map(quoted_strings)
        .map(PathBuf::from)
        .collect()
}

fn gpr_source_dirs(gpr: &str) -> Vec<PathBuf> {
    gpr.split(';')
        .filter(|statement| {
            let normalized = statement.to_ascii_lowercase();
            normalized.contains("for source_dirs") && normalized.contains(" use ")
        })
        .flat_map(quoted_strings)
        .map(PathBuf::from)
        .collect()
}

fn quoted_strings(statement: &str) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut chars = statement.chars().peekable();

    while let Some(ch) = chars.next() {
        if !in_string {
            if ch == '"' {
                in_string = true;
                current.clear();
            }
            continue;
        }

        if ch == '"' {
            if chars.peek() == Some(&'"') {
                current.push('"');
                chars.next();
            } else {
                strings.push(current.clone());
                current.clear();
                in_string = false;
            }
        } else {
            current.push(ch);
        }
    }

    strings
}

fn strip_gpr_comments(text: &str) -> String {
    text.lines()
        .map(|line| line.split_once("--").map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n")
}

fn dedup_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for path in paths {
        let normalized = normalize_path(&path);
        let key = normalized.to_string_lossy().to_ascii_lowercase();
        if seen.insert(key) {
            deduped.push(normalized);
        }
    }
    deduped
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push("..");
                }
            }
            std::path::Component::Normal(part) => normalized.push(part),
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

fn build_harness_ast(
    source: &str,
    source_path: &Path,
    source_roots: &[PathBuf],
) -> Result<StructuralAst> {
    let mut ast = ada_parser::reconcile::build_structural_ast(source, None, source_path)
        .with_context(|| format!("scan Ada source {}", source_path.display()))?;

    if let Some(spec_path) = sibling_spec_path(source_path) {
        if spec_path.is_file() {
            // Latin-1 fallback: the sibling spec is often legacy-encoded; failing
            // here would block harnessing every body whose .ads is non-UTF-8.
            let spec = crate::source_text::read_source_text(&spec_path)
                .with_context(|| format!("read Ada spec {}", spec_path.display()))?;
            let spec_ast = ada_parser::reconcile::build_structural_ast(&spec, None, &spec_path)
                .with_context(|| format!("scan Ada spec {}", spec_path.display()))?;
            merge_spec_withs(&mut ast, &spec_ast);
            merge_spec_types(&mut ast, &spec_ast);
            merge_spec_subprograms(&mut ast, &spec_ast);
            merge_spec_constants(&mut ast, &spec_ast);
        }
    }

    merge_withed_dependency_types(&mut ast, source_roots)?;

    Ok(ast)
}

fn merge_withed_dependency_types(ast: &mut StructuralAst, source_roots: &[PathBuf]) -> Result<()> {
    // Seed the worklist with directly-withed units, the harness's own packages,
    // and their dotted parents.
    let mut pending: Vec<String> = ast
        .units
        .iter()
        .flat_map(|unit| unit.withs.iter().map(|unit_ref| unit_ref.name.clone()))
        .collect();
    pending.extend(ast.packages.iter().map(|package| package.name.clone()));
    let seed_parents: Vec<String> = pending
        .iter()
        .flat_map(|name| dotted_parents(name))
        .collect();
    pending.extend(seed_parents);

    // Transitive closure: a child package (e.g. `Zip.Headers`) reaches types
    // through its parent's context (`with Zip_Streams` on `Zip`), so merging a
    // dependency must also follow that dependency's own withs — not just the
    // units the harness unit names directly.
    let mut visited: BTreeSet<String> = BTreeSet::new();
    while let Some(unit_name) = pending.pop() {
        if !visited.insert(unit_name.clone()) {
            continue;
        }
        let Some(path) = find_ada_unit_source(&unit_name, source_roots) else {
            continue;
        };
        // Latin-1 fallback: a legacy non-UTF-8 dependency unit still carries the
        // type and package declarations the harness needs for stubbing.
        let source = crate::source_text::read_source_text(&path)
            .with_context(|| format!("read dependency Ada source {}", path.display()))?;
        let dep_ast = ada_parser::reconcile::build_structural_ast(&source, None, &path)
            .with_context(|| format!("scan dependency Ada source {}", path.display()))?;
        for unit in &dep_ast.units {
            for unit_ref in &unit.withs {
                pending.push(unit_ref.name.clone());
                pending.extend(dotted_parents(&unit_ref.name));
            }
        }
        merge_dependency_types(ast, &dep_ast);
        merge_dependency_packages_and_subprograms(ast, &dep_ast);
    }

    Ok(())
}

fn dotted_parents(name: &str) -> Vec<String> {
    let parts: Vec<&str> = name.split('.').collect();
    let mut parents = Vec::new();
    for end in 1..parts.len() {
        parents.push(parts[..end].join("."));
    }
    parents
}

fn merge_dependency_packages_and_subprograms(ast: &mut StructuralAst, dep_ast: &StructuralAst) {
    let mut next_package_id = ast
        .packages
        .iter()
        .map(|package| package.id.0)
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    let mut package_id_map: HashMap<PackageId, PackageId> = HashMap::new();
    let mut newly_added: Vec<PackageId> = Vec::new();

    for dep_package in &dep_ast.packages {
        if let Some(existing) = ast
            .packages
            .iter()
            .find(|package| package.name.eq_ignore_ascii_case(&dep_package.name))
        {
            package_id_map.insert(dep_package.id, existing.id);
        } else {
            let new_id = PackageId(next_package_id);
            next_package_id = next_package_id.saturating_add(1);
            let mut merged = dep_package.clone();
            merged.id = new_id;
            // Keep the dep-space `parent` for now; remap it below once the whole
            // batch has IDs. (Hard-nulling it dropped a nested package's parent —
            // `Zip_Streams.Calendar` became a bare `Calendar`, so a constructor in
            // it was emitted unqualified as `Calendar.Time_Of` and didn't compile.)
            package_id_map.insert(dep_package.id, new_id);
            ast.packages.push(merged);
            newly_added.push(new_id);
        }
    }
    // Remap each newly-added package's parent from dep-space to main-space (an
    // unknown parent resolves to None — a genuinely top-level package).
    for package in ast.packages.iter_mut() {
        if newly_added.contains(&package.id) {
            package.parent = package
                .parent
                .and_then(|dep_parent| package_id_map.get(&dep_parent).copied());
        }
    }

    let mut next_subprogram_id = ast
        .subprograms
        .iter()
        .map(|subprogram| subprogram.id.0)
        .max()
        .unwrap_or(0)
        .saturating_add(1);

    for dep_subprogram in &dep_ast.subprograms {
        if dep_subprogram.visibility != Visibility::Public {
            continue;
        }
        let new_owner = match &dep_subprogram.owner {
            SubprogramOwner::LibraryLevel => SubprogramOwner::LibraryLevel,
            SubprogramOwner::Package(package_id) => {
                let Some(remapped) = package_id_map.get(package_id) else {
                    continue;
                };
                SubprogramOwner::Package(*remapped)
            }
        };

        if ast.subprograms.iter().any(|existing| {
            existing.owner == new_owner
                && existing.name.eq_ignore_ascii_case(&dep_subprogram.name)
                && existing.kind == dep_subprogram.kind
                && existing.params.len() == dep_subprogram.params.len()
                && existing
                    .params
                    .iter()
                    .zip(dep_subprogram.params.iter())
                    .all(|(left, right)| same_type_name(&left.type_ref, &right.type_ref))
                && match (&existing.return_type, &dep_subprogram.return_type) {
                    (Some(left), Some(right)) => same_type_name(left, right),
                    (None, None) => true,
                    _ => false,
                }
        }) {
            continue;
        }

        let mut merged = dep_subprogram.clone();
        merged.id = SubprogramId(next_subprogram_id);
        merged.owner = new_owner;
        next_subprogram_id = next_subprogram_id.saturating_add(1);
        ast.subprograms.push(merged);
    }

    // A public constant of a withed dependency (zip-ada `Zip_Streams.default_time`)
    // is the neutral that lets a target taking that private type build. Carry it
    // over with its owner package id remapped to the merged AST.
    for dep_constant in &dep_ast.constants {
        let new_owner = match &dep_constant.owner {
            TypeOwner::Package(package_id) => match package_id_map.get(package_id) {
                Some(remapped) => TypeOwner::Package(*remapped),
                None => continue,
            },
            other => other.clone(),
        };
        if ast.constants.iter().any(|existing| {
            existing.name.eq_ignore_ascii_case(&dep_constant.name) && existing.owner == new_owner
        }) {
            continue;
        }
        let mut merged = dep_constant.clone();
        merged.owner = new_owner;
        ast.constants.push(merged);
    }
}

fn find_ada_unit_source(unit_name: &str, source_roots: &[PathBuf]) -> Option<PathBuf> {
    let basename = unit_name.to_ascii_lowercase().replace('.', "-");
    for extension in ["ads", "adb"] {
        let file_name = format!("{basename}.{extension}");
        for root in source_roots {
            let candidate = root.join(&file_name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn merge_dependency_types(ast: &mut StructuralAst, dep_ast: &StructuralAst) {
    for dep_type in &dep_ast.types {
        let mut dep_type = dep_type.clone();
        if let TypeOwner::Package(package_id) = &dep_type.owner {
            if let Some(package) = dep_ast
                .packages
                .iter()
                .find(|package| package.id == *package_id)
            {
                dep_type.name_path =
                    qualify_dependency_type_name(&package.name, &dep_type.name_path);
            }
        }
        dep_type.owner = TypeOwner::LibraryLevel;
        if !ast
            .types
            .iter()
            .any(|existing| same_type_name(existing, &dep_type))
        {
            ast.types.push(dep_type);
        }
    }
}

fn qualify_dependency_type_name(package_name: &str, type_name_path: &[String]) -> Vec<String> {
    let package_parts = dotted_parts(package_name);
    let type_parts = type_name_path
        .iter()
        .flat_map(|part| dotted_parts(part))
        .collect::<Vec<_>>();

    if type_parts
        .iter()
        .take(package_parts.len())
        .zip(package_parts.iter())
        .all(|(left, right)| left.eq_ignore_ascii_case(right))
        && type_parts.len() >= package_parts.len()
    {
        return type_parts;
    }

    package_parts
        .into_iter()
        .chain(type_parts)
        .collect::<Vec<_>>()
}

fn dotted_parts(name: &str) -> Vec<String> {
    name.split('.')
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

fn sibling_spec_path(source_path: &Path) -> Option<PathBuf> {
    source_path
        .extension()
        .and_then(|extension| extension.to_str())
        .filter(|extension| extension.eq_ignore_ascii_case("adb"))
        .map(|_| source_path.with_extension("ads"))
}

fn merge_spec_withs(ast: &mut StructuralAst, spec_ast: &StructuralAst) {
    let Some(body_unit) = ast.units.first_mut() else {
        return;
    };
    for unit_ref in spec_ast.units.iter().flat_map(|unit| unit.withs.iter()) {
        if !body_unit
            .withs
            .iter()
            .any(|existing| existing.name.eq_ignore_ascii_case(&unit_ref.name))
        {
            body_unit.withs.push(unit_ref.clone());
        }
    }
}

fn merge_spec_types(ast: &mut StructuralAst, spec_ast: &StructuralAst) {
    for spec_type in &spec_ast.types {
        let mut spec_type = spec_type.clone();
        if let TypeOwner::Package(spec_package_id) = &spec_type.owner {
            if let Some(spec_package) = spec_ast
                .packages
                .iter()
                .find(|package| package.id == *spec_package_id)
            {
                if let Some(body_package) = ast
                    .packages
                    .iter()
                    .find(|package| package.name.eq_ignore_ascii_case(&spec_package.name))
                {
                    spec_type.owner = TypeOwner::Package(body_package.id);
                }
            }
        }

        if !ast
            .types
            .iter()
            .any(|existing| same_type_name(existing, &spec_type))
        {
            ast.types.push(spec_type);
        }
    }
}

fn same_type_name(left: &TypeRef, right: &TypeRef) -> bool {
    !left.name_path.is_empty()
        && left.name_path.len() == right.name_path.len()
        && left
            .name_path
            .iter()
            .zip(right.name_path.iter())
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn merge_spec_subprograms(ast: &mut StructuralAst, spec_ast: &StructuralAst) {
    let mut next_id = ast
        .subprograms
        .iter()
        .map(|subprogram| subprogram.id.0)
        .max()
        .unwrap_or(0)
        .saturating_add(1);

    for spec_subprogram in &spec_ast.subprograms {
        if spec_subprogram.visibility != Visibility::Public {
            continue;
        }

        let mut spec_subprogram = spec_subprogram.clone();
        if let Some(owner) = remap_spec_subprogram_owner(ast, spec_ast, &spec_subprogram) {
            spec_subprogram.owner = owner;
        } else {
            continue;
        }

        if ast.subprograms.iter().any(|existing| {
            existing.body_span.is_none() && same_subprogram_signature(existing, &spec_subprogram)
        }) {
            continue;
        }

        spec_subprogram.id = SubprogramId(next_id);
        next_id = next_id.saturating_add(1);
        ast.subprograms.push(spec_subprogram);
    }
}

fn merge_spec_constants(ast: &mut StructuralAst, spec_ast: &StructuralAst) {
    // Public constants live in the spec; when harnessing a body, carry the spec's
    // visible constants over (owner package id remapped by name) so a private-type
    // neutral like `Zip_Streams.default_time` is available.
    for spec_constant in &spec_ast.constants {
        if spec_constant.visibility != Visibility::Public {
            continue;
        }
        let new_owner = match &spec_constant.owner {
            TypeOwner::Package(spec_package_id) => {
                let Some(spec_package) = spec_ast
                    .packages
                    .iter()
                    .find(|package| package.id == *spec_package_id)
                else {
                    continue;
                };
                let Some(body_package) = ast
                    .packages
                    .iter()
                    .find(|package| package.name.eq_ignore_ascii_case(&spec_package.name))
                else {
                    continue;
                };
                TypeOwner::Package(body_package.id)
            }
            other => other.clone(),
        };
        if ast.constants.iter().any(|existing| {
            existing.name.eq_ignore_ascii_case(&spec_constant.name) && existing.owner == new_owner
        }) {
            continue;
        }
        let mut merged = spec_constant.clone();
        merged.owner = new_owner;
        ast.constants.push(merged);
    }
}

fn remap_spec_subprogram_owner(
    body_ast: &StructuralAst,
    spec_ast: &StructuralAst,
    spec_subprogram: &Subprogram,
) -> Option<SubprogramOwner> {
    match &spec_subprogram.owner {
        SubprogramOwner::LibraryLevel => Some(SubprogramOwner::LibraryLevel),
        SubprogramOwner::Package(spec_package_id) => {
            let spec_package = spec_ast
                .packages
                .iter()
                .find(|package| package.id == *spec_package_id)?;
            body_ast
                .packages
                .iter()
                .find(|package| package.name.eq_ignore_ascii_case(&spec_package.name))
                .map(|package| SubprogramOwner::Package(package.id))
        }
    }
}

fn same_subprogram_signature(left: &Subprogram, right: &Subprogram) -> bool {
    left.owner == right.owner
        && left.kind == right.kind
        && left.name.eq_ignore_ascii_case(&right.name)
        && left.params.len() == right.params.len()
        && left
            .params
            .iter()
            .zip(right.params.iter())
            .all(|(left, right)| same_type_name(&left.type_ref, &right.type_ref))
        && match (&left.return_type, &right.return_type) {
            (Some(left), Some(right)) => same_type_name(left, right),
            (None, None) => true,
            _ => false,
        }
}

fn compute_default_id(source: &Path, target: &ada_parser::ast::Subprogram) -> String {
    let mut hash = FNV_OFFSET_BASIS;
    for byte in source.to_string_lossy().as_bytes() {
        hash = fnv1a(hash, *byte);
    }
    for byte in target.id.0.to_le_bytes() {
        hash = fnv1a(hash, byte);
    }

    format!("H-{:04X}", (hash & 0xFFFF) as u16)
}

fn select_sequence_package<'a>(
    ast: &'a StructuralAst,
    requested: Option<&str>,
) -> Result<&'a Package> {
    if let Some(name) = requested {
        return ast
            .packages
            .iter()
            .find(|package| package.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| anyhow::anyhow!("package '{name}' not found"));
    }

    ast.packages
        .iter()
        .find(|package| package_has_sequence_operations(ast, package))
        .ok_or_else(|| anyhow::anyhow!("no package with sequence operations found"))
}

fn package_has_sequence_operations(ast: &StructuralAst, package: &Package) -> bool {
    let public_signatures = public_sequence_signatures(ast, package);
    ast.subprograms
        .iter()
        .any(|subprogram| is_sequence_operation(subprogram, package, &public_signatures))
}

fn is_sequence_operation(
    subprogram: &Subprogram,
    package: &Package,
    public_signatures: &[&Subprogram],
) -> bool {
    subprogram.owner == SubprogramOwner::Package(package.id)
        && matches!(
            subprogram.kind,
            SubprogramKind::Procedure | SubprogramKind::Function
        )
        && !subprogram.is_abstract
        && subprogram.body_span.is_some()
        && (subprogram.visibility == Visibility::Public
            || public_signatures
                .iter()
                .any(|signature| same_subprogram_signature(signature, subprogram)))
}

fn public_sequence_signatures<'a>(
    ast: &'a StructuralAst,
    package: &Package,
) -> Vec<&'a Subprogram> {
    ast.subprograms
        .iter()
        .filter(|subprogram| subprogram.owner == SubprogramOwner::Package(package.id))
        .filter(|subprogram| subprogram.visibility == Visibility::Public)
        .filter(|subprogram| {
            matches!(
                subprogram.kind,
                SubprogramKind::Procedure | SubprogramKind::Function
            )
        })
        .collect()
}

fn compute_default_package_id(source: &Path, package: &Package) -> String {
    let mut hash = FNV_OFFSET_BASIS;
    for byte in source.to_string_lossy().as_bytes() {
        hash = fnv1a(hash, *byte);
    }
    for byte in package.id.0.to_le_bytes() {
        hash = fnv1a(hash, byte);
    }

    format!("H-{:04X}", (hash & 0xFFFF) as u16)
}

const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

fn fnv1a(hash: u64, byte: u8) -> u64 {
    (hash ^ u64::from(byte)).wrapping_mul(FNV_PRIME)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CFamilySource {
    C,
    Cpp,
}

fn detect_c_family_source(path: &Path) -> Result<Option<CFamilySource>> {
    let Some(ext) = path.extension().and_then(|ext| ext.to_str()) else {
        return Ok(None);
    };
    if ext == "C" {
        return Ok(Some(CFamilySource::Cpp));
    }
    match ext.to_ascii_lowercase().as_str() {
        "c" => Ok(Some(CFamilySource::C)),
        "h" => classify_c_header_source(path),
        "cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx" => Ok(Some(CFamilySource::Cpp)),
        _ => Ok(None),
    }
}

fn classify_c_header_source(path: &Path) -> Result<Option<CFamilySource>> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("read C/C++ header {}", path.display()))?;
    let c_count = c_parser::parse_c_functions(&source)
        .map(|fns| fns.len())
        .unwrap_or(0);
    let cpp_count = cpp_parser::parse_cpp_functions(&source)
        .map(|fns| fns.len())
        .unwrap_or(0);
    let has_c_impl = path.with_extension("c").is_file();
    let has_cpp_impl = ["cpp", "cc", "cxx", "C"]
        .iter()
        .any(|ext| path.with_extension(ext).is_file());
    if cpp_count > c_count || header_looks_like_cpp(&source) || (has_cpp_impl && !has_c_impl) {
        Ok(Some(CFamilySource::Cpp))
    } else {
        Ok(Some(CFamilySource::C))
    }
}

fn header_looks_like_cpp(source: &str) -> bool {
    [
        "namespace ",
        "template <",
        "template<",
        "class ",
        "typename ",
        "public:",
        "private:",
        "protected:",
        "constexpr",
        "noexcept",
        "operator",
    ]
    .iter()
    .any(|marker| source.contains(marker))
}

fn is_c_family_header(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "h" | "hpp" | "hh" | "hxx"
            )
        })
}

/// True when `text` declares the function `name`: a `name` identifier token
/// immediately followed (after whitespace) by `(`. A header declares prototypes
/// rather than calling functions, so this reliably distinguishes a declaration —
/// enough to know the harness must NOT emit its own (possibly mismatched) forward
/// `extern` for a target the included header already declares.
fn text_declares_function(text: &str, name: &str) -> bool {
    let code = mask_c_comments_and_literals(text);
    let text = code.as_str();
    let bytes = text.as_bytes();
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut search_from = 0;
    while let Some(rel) = text[search_from..].find(name) {
        let start = search_from + rel;
        let end = start + name.len();
        let before_ok = start == 0 || !is_ident(bytes[start - 1]);
        let mut j = end;
        while j < bytes.len() && matches!(bytes[j], b' ' | b'\t' | b'\r' | b'\n') {
            j += 1;
        }
        if before_ok && j < bytes.len() && bytes[j] == b'(' {
            return true;
        }
        search_from = end;
    }
    false
}

/// Replace C/C++ comments and string/character literals with spaces while
/// preserving byte offsets and newlines for cheap token scans.
fn mask_c_comments_and_literals(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        let end = if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'/') {
            let mut j = i + 2;
            while j < bytes.len() && bytes[j] != b'\n' {
                j += 1;
            }
            j
        } else if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            let mut j = i + 2;
            while j + 1 < bytes.len() && !(bytes[j] == b'*' && bytes[j + 1] == b'/') {
                j += 1;
            }
            (j + 2).min(bytes.len())
        } else if matches!(bytes[i], b'"' | b'\'') {
            let quote = bytes[i];
            let mut j = i + 1;
            while j < bytes.len() {
                if bytes[j] == b'\\' {
                    j = (j + 2).min(bytes.len());
                } else if bytes[j] == quote {
                    j += 1;
                    break;
                } else {
                    j += 1;
                }
            }
            j
        } else {
            i += 1;
            continue;
        };
        for byte in &mut out[i..end] {
            if *byte != b'\n' && *byte != b'\r' {
                *byte = b' ';
            }
        }
        i = end;
    }
    String::from_utf8(out).expect("masking valid UTF-8 with ASCII spaces preserves UTF-8")
}

/// True when one of the harness's included headers declares the target function,
/// so the harness's own forward `extern` is redundant and risks a "conflicting
/// types" error (cJSON `CreateStringArray`: the parser-normalized
/// `const char **` extern clashes with the header's `const char *const *`).
fn included_header_declares_target(
    source_path: &Path,
    header_names: &[String],
    include_dirs: &[PathBuf],
    target_name: &str,
) -> bool {
    let mut search_dirs: Vec<PathBuf> = Vec::new();
    if let Some(dir) = source_path.parent() {
        search_dirs.push(dir.to_path_buf());
    }
    search_dirs.extend(include_dirs.iter().cloned());
    for header in header_names {
        for dir in &search_dirs {
            let candidate = dir.join(header);
            if let Ok(text) = std::fs::read_to_string(&candidate) {
                if text_declares_function(&text, target_name) {
                    return true;
                }
                break; // resolved the header; don't probe other dirs for this name
            }
        }
    }
    false
}

fn find_project_header_declaring_target(
    include_dirs: &[PathBuf],
    target_name: &str,
) -> Option<String> {
    fn collect_headers(dir: &Path, depth: usize, remaining: &mut usize, out: &mut Vec<PathBuf>) {
        if depth > 3 || *remaining == 0 {
            return;
        }
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            if *remaining == 0 {
                break;
            }
            let path = entry.path();
            if path.is_dir() {
                let name = entry.file_name();
                if !name.to_string_lossy().starts_with('.') {
                    collect_headers(&path, depth + 1, remaining, out);
                }
            } else if is_c_family_header(&path) {
                *remaining -= 1;
                out.push(path);
            }
        }
    }

    let mut matches: Vec<(usize, String)> = Vec::new();
    for root in include_dirs {
        let mut headers = Vec::new();
        let mut remaining = 512;
        collect_headers(root, 0, &mut remaining, &mut headers);
        for header in headers {
            let Ok(text) = crate::source_text::read_source_text(&header) else {
                continue;
            };
            if !text_declares_function(&text, target_name) {
                continue;
            }
            let Ok(relative) = header.strip_prefix(root) else {
                continue;
            };
            let name = relative.to_string_lossy().replace('\\', "/");
            let depth = relative.components().count();
            matches.push((depth, name));
        }
    }
    matches.sort();
    matches.into_iter().map(|(_, name)| name).next()
}

/// Whether a C function signature needs a project declaration to make its types
/// visible to the harness. A definition using only language and standard-library
/// types is self-contained: pulling in an arbitrary tree-wide declaration header
/// can import a large, damaged umbrella even though an exact generated prototype
/// is sufficient (Redis's standalone `crc16` was paired with `cluster.h`).
fn c_signature_needs_project_header<'a>(
    return_type: &'a str,
    param_types: impl IntoIterator<Item = &'a str>,
) -> bool {
    std::iter::once(return_type)
        .chain(param_types)
        .any(c_type_needs_project_header)
}

fn c_type_needs_project_header(ty: &str) -> bool {
    c_type_identifiers(ty)
        .into_iter()
        .any(|identifier| !is_standard_c_type_identifier(identifier))
}

fn c_type_identifiers(ty: &str) -> Vec<&str> {
    let bytes = ty.as_bytes();
    let mut identifiers = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if !bytes[index].is_ascii_alphabetic() && bytes[index] != b'_' {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
        {
            index += 1;
        }
        identifiers.push(&ty[start..index]);
    }
    identifiers
}

fn is_standard_c_type_identifier(identifier: &str) -> bool {
    if matches!(
        identifier,
        "void"
            | "char"
            | "short"
            | "int"
            | "long"
            | "signed"
            | "unsigned"
            | "float"
            | "double"
            | "const"
            | "volatile"
            | "restrict"
            | "_Atomic"
            | "_Bool"
            | "bool"
            | "struct"
            | "union"
            | "enum"
            | "size_t"
            | "ssize_t"
            | "ptrdiff_t"
            | "intptr_t"
            | "uintptr_t"
            | "intmax_t"
            | "uintmax_t"
            | "wchar_t"
            | "wint_t"
            | "FILE"
            | "va_list"
    ) {
        return true;
    }
    let Some(width) = identifier
        .strip_prefix("uint")
        .or_else(|| identifier.strip_prefix("int"))
        .and_then(|rest| rest.strip_suffix("_t"))
    else {
        return false;
    };
    matches!(width, "8" | "16" | "32" | "64")
}

fn target_compile_sources(source_path: &Path) -> Vec<PathBuf> {
    if is_c_family_header(source_path) {
        Vec::new()
    } else {
        vec![source_path.to_path_buf()]
    }
}

/// Feature macros a library source defines specifically to expose its private
/// static-linking declarations from public headers. The harness includes those
/// headers in a separate translation unit, so it needs the same visibility
/// define (LZ4's `LZ4F_STATIC_LINKING_ONLY`).
fn source_header_visibility_flags(source: &str) -> Vec<String> {
    let mut flags = Vec::new();
    for line in source.lines() {
        let Some(rest) = line
            .trim_start()
            .strip_prefix('#')
            .map(str::trim_start)
            .and_then(|directive| directive.strip_prefix("define"))
            .map(str::trim_start)
        else {
            continue;
        };
        let name = rest
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_end_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_');
        if name.ends_with("_STATIC_LINKING_ONLY")
            && name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            let flag = format!("-D{name}");
            if !flags.contains(&flag) {
                flags.push(flag);
            }
        }
    }
    flags
}

fn run_c_direct(args: &GenerateHarnessArgs) -> Result<()> {
    if !matches!(args.kind.as_str(), "direct" | "sequence") {
        bail!("C harness emitter supports --kind direct or --kind sequence");
    }

    // Canonicalize the source so the generated Makefile records an absolute
    // path. `make` runs from the harness output dir, not from the CLI's
    // working directory, so relative paths like `cJSON/cJSON.c` would break.
    let source_path = absolutize(&args.source)
        .with_context(|| format!("resolve C source {}", args.source.display()))?;
    let source = crate::source_text::read_source_text(&source_path)
        .with_context(|| format!("read C source {}", source_path.display()))?;
    let functions = c_parser::parse_c_functions(&source)
        .with_context(|| format!("parse C source {}", source_path.display()))?;
    let target_name = args
        .target
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--target is required for C sources"))?;
    let (function, warning) = pick_c_target(
        &source_path,
        functions.clone(),
        target_name,
        args.target_line,
    )?;
    if let Some(warning) = warning {
        eprintln!("{warning}");
    }

    // A `va_list` is compiler ABI state, not fuzz bytes. When the same TU
    // provides the conventional variadic wrapper (`json_vunpack_ex` ->
    // `json_unpack_ex`), drive that wrapper instead: it creates a valid
    // `va_list` and immediately calls the selected target. This preserves real
    // target execution without inventing a non-portable decoder for `va_list`.
    let invocation_function = if args.kind == "direct" {
        c_va_list_variadic_wrapper(&function, &functions).unwrap_or_else(|| function.clone())
    } else {
        function.clone()
    };

    let id = args
        .id
        .clone()
        .unwrap_or_else(|| format!("H-C{:04X}", function.line));
    let output_dir = args.output.join(&id);
    let params = invocation_function
        .params
        .iter()
        .map(|p| harness_gen::c_generate::CParameter {
            name: p.name.clone(),
            c_type: p.c_type.clone(),
        })
        .collect();
    let c_runtime_include = locate_c_runtime();

    let target_dir = source_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let result_cleanup = args
        .cleanup
        .clone()
        .or_else(|| {
            auto_detect_c_result_cleanup(
                &invocation_function.return_type,
                &invocation_function.name,
            )
        })
        .or_else(|| {
            let param_types: Vec<String> = invocation_function
                .params
                .iter()
                .map(|p| p.c_type.clone())
                .collect();
            detect_paired_deallocator(
                &invocation_function.return_type,
                &invocation_function.name,
                &param_types,
                &target_dir,
                &source_path,
            )
        })
        .or_else(|| {
            detect_strdup_family_free(&invocation_function.return_type, &invocation_function.name)
        });
    let mut compile_flags = c_build_flags_for_source(&source_path);
    for flag in source_header_visibility_flags(&source) {
        if !compile_flags.contains(&flag) {
            compile_flags.push(flag);
        }
    }
    let mut target_includes_dirs = vec![target_dir.clone()];
    for project_inc in auto_detect_project_includes(&source_path) {
        if !target_includes_dirs.contains(&project_inc) {
            target_includes_dirs.push(project_inc);
        }
    }
    // Self-prefixed includes (`libde265/de265.cc` -> `#include "libde265/vps.h"`):
    // add the dir containing the prefix so the build doesn't fail "file not found"
    // before the AddSource link-closure can run.
    for self_inc in self_prefixed_include_roots(&source_path) {
        if !target_includes_dirs.contains(&self_inc) {
            target_includes_dirs.push(self_inc);
        }
    }
    for compile_inc in include_dirs_from_compile_flags(&compile_flags) {
        if !target_includes_dirs.contains(&compile_inc) {
            target_includes_dirs.push(compile_inc);
        }
    }
    // §26.8: CMake-generated export/config headers (miniz's `miniz_export.h` from
    // `generate_export_header`, a configure-written `config.h`) land in the probe/
    // build dir, but the per-file compile_commands `-I` set can miss them, so the
    // harness build fails "<gen>.h: No such file or directory". Add the build/probe
    // dirs that hold generated headers to the harness include path.
    for gen_inc in probe_generated_header_dirs(&source_path) {
        if !target_includes_dirs.contains(&gen_inc) {
            target_includes_dirs.push(gen_inc);
        }
    }
    for extra in &args.extra_includes {
        let abs = absolutize(extra).unwrap_or_else(|_| extra.clone());
        if !target_includes_dirs.contains(&abs) {
            target_includes_dirs.push(abs);
        }
    }
    let sequence_cluster = if args.kind == "sequence" {
        Some(c_lifecycle_steps(&function, &functions)?)
    } else {
        None
    };
    let static_direct_target =
        args.kind == "direct" && invocation_function.is_static && !is_c_family_header(&source_path);
    let static_sequence_target = sequence_cluster
        .as_ref()
        .is_some_and(|cluster| cluster.requires_source_include)
        && !is_c_family_header(&source_path);
    // A non-static target whose defining TU ALSO contains `int main` — a
    // single-file legacy tool or benchmark (http-parser's bench.c defines both
    // `bench` and `main`) — cannot be LINKED beside the harness driver: two
    // `main` symbols collide at link time ("multiple definition of `main'"). Route
    // it through the same whole-TU `#include` path the static case uses, which
    // renames the source's `main`; the target is then defined IN the harness TU
    // (no separate link of that source), so there is no collision. Any
    // library sources the TU needs are still added by the link-closure repair.
    let direct_main_tu = args.kind == "direct"
        && !invocation_function.is_static
        && !is_c_family_header(&source_path)
        && functions.iter().any(|f| f.name == "main");
    // The project headers feed type resolution (decoder/dictionary synthesis),
    // and normally also become the harness's `#include` list. But when the
    // harness `#include`s the target source `.c` itself (static targets), that
    // source already pulls in its own headers transitively — re-including them
    // in the harness double-includes any without an include guard (jansson's
    // lookup3.h -> "redefinition of 'hashlittle'"). So keep the full header set
    // for type resolution but emit *only* the source there.
    let includes_target_source = static_direct_target || static_sequence_target || direct_main_tu;
    let mut header_includes =
        ordered_c_harness_headers(&source_path, &target_dir, &source, &target_includes_dirs);
    // A C harness is compiled as C; a C++-only header pulled in transitively —
    // libfixmath's `fix16.h` does `#ifdef __cplusplus` / `#include "fix16.hpp"`,
    // and the include scanner doesn't evaluate the guard — would inject
    // `class`/templates into a C TU ("unknown type name 'class'"). Drop C++ header
    // extensions: a real C target's declarations live in a `.h`; a declaration that
    // exists only in a `.hpp` belongs to the C++ harness path, not here.
    header_includes.retain(|header| {
        !is_cpp_only_header(header)
            && !is_partial_impl_header(header)
            && !is_translation_unit_include(header)
    });
    if is_c_family_header(&source_path) {
        header_includes = standalone_header_include_plan(
            &source_path,
            &header_includes,
            &target_includes_dirs,
            &compile_flags,
            false,
        )?;
    }
    // A deleted private umbrella header can hide an otherwise surviving public
    // API header from the source's include closure (libyaml's yaml_private.h ->
    // yaml.h). Recover the public declaration by name from bounded project
    // include roots. Besides the prototype, that header supplies the complete
    // public handle layout needed by lifecycle harness generation.
    if !included_header_declares_target(
        &source_path,
        &header_includes,
        &target_includes_dirs,
        &invocation_function.name,
    ) && c_signature_needs_project_header(
        &invocation_function.return_type,
        invocation_function
            .params
            .iter()
            .map(|param| param.c_type.as_str()),
    ) {
        if let Some(header) =
            find_project_header_declaring_target(&target_includes_dirs, &invocation_function.name)
        {
            if !header_includes.contains(&header) {
                header_includes.push(header);
            }
        }
    }
    // GAP #6 (tidwall/hashmap.c): a sequence harness stack-allocates + zero-fills the
    // cluster handle and drives it through `&_gf_handle`, which is only valid when the
    // handle's struct is fully defined in a HEADER the harness includes. When the
    // cluster requires force-including the target `.c` (here, only to reach static
    // helpers), the struct becomes visible to the build BUT the library deliberately
    // keeps it OPAQUE in its public headers because it must be constructed via its API
    // (`hashmap_new`, which needs caller-supplied hash/compare function pointers govfuzz
    // cannot synthesize) — a zero-filled `struct hashmap` is invalid. Judge completeness
    // against the HEADERS only and, when the handle is header-opaque, bail so `auto`
    // falls back to the direct path, which then skips it cleanly (instead of emitting a
    // sequence harness that either fails to build or fuzzes an invalid handle).
    if args.kind == "sequence" {
        if let Some(cluster) = &sequence_cluster {
            if !c_handle_defined_in_headers(
                &cluster.handle_type,
                &source_path,
                &header_includes,
                &target_includes_dirs,
            ) {
                bail!(
                    "C sequence handle '{}' is not fully defined in any included header \
                     (an opaque API handle); it cannot be zero-constructed, only built via \
                     its constructor",
                    cluster.handle_type
                );
            }
        }
    }
    let target_includes = if includes_target_source {
        let source_include = source_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("C source path is not valid UTF-8"))?
            .to_owned();
        vec![source_include]
    } else {
        header_includes.clone()
    };
    let mut target_sources = if static_direct_target || static_sequence_target || direct_main_tu {
        Vec::new()
    } else {
        target_compile_sources(&source_path)
    };
    for extra in &args.extra_sources {
        target_sources.push(absolutize(extra).unwrap_or_else(|_| extra.clone()));
    }
    let per_tu_contexts = partition_per_tu_compile_contexts(&mut target_sources);
    // Parse the target source's own struct/enum typedefs when the harness can
    // name them: static targets (the harness `#include`s the `.c`) OR a
    // single-header target (the harness `#include`s the header itself, so a
    // struct defined there — e.g. QOA's `qoa_desc`, used as a decoder out-param
    // — is fully visible). Without the header case, a single-header library's
    // own structs were treated as opaque and any function taking one by pointer
    // was skipped ("needs lifecycle support"), even though `#include`-ing the
    // header makes the type nameable. (A `.c`-only struct stays opaque-and-skip:
    // the harness never sees its definition.)
    let parse_target_source_types = includes_target_source || is_c_family_header(&source_path);
    let mut type_defs = collect_c_type_defs_for_harness(
        &source_path,
        &source,
        &header_includes,
        &target_includes_dirs,
        parse_target_source_types,
    );
    // Tree-wide fallback: appended last so `TypeRegistry::from_defs` (first-wins)
    // keeps any in-scope definition and only uses the tree-wide one to resolve a
    // type the include closure left opaque (e.g. an arch-gated `word_t`).
    if let Some(tree) = &args.tree_type_defs {
        type_defs.push((*tree.c).clone());
    }
    let dictionary_tokens = collect_c_dictionary_tokens_for_harness(
        &source_path,
        &source,
        &header_includes,
        &target_includes_dirs,
    );
    // If an included header already declares the target, skip the harness's own
    // forward `extern` — it is redundant and a parser-normalized signature can
    // conflict with the header's (cJSON `CreateStringArray`).
    let target_in_included_header = included_header_declares_target(
        &source_path,
        &header_includes,
        &target_includes_dirs,
        &invocation_function.name,
    );
    let result = if args.kind == "sequence" {
        let cluster = sequence_cluster.expect("sequence cluster built for sequence harness");
        harness_gen::c_generate::generate_c_sequence_harness(
            harness_gen::c_generate::GenerateCSequenceArgs {
                harness_id: id,
                output_dir: output_dir.clone(),
                source_path: source_path.clone(),
                target: function.clone(),
                handle_type: cluster.handle_type,
                init_step: cluster.init_step,
                op_steps: cluster.op_steps,
                end_step: cluster.end_step,
                target_includes,
                target_includes_dirs,
                target_sources,
                compile_flags,
                target_declared_in_header: is_c_family_header(&source_path)
                    || static_sequence_target
                    || target_in_included_header,
                c_runtime_include,
                type_defs,
                decoder_limits: args.decoder_limits.c_limits(),
            },
        )
    } else {
        // Built before the args literal so it can borrow target_includes /
        // _dirs (the literal moves them when it sets those fields).
        let mut lifecycle = c_direct_lifecycle_table(
            &functions,
            &collect_c_declarations_for_harness(
                &source_path,
                &source,
                &target_includes,
                &target_includes_dirs,
            ),
            &type_model::TypeRegistry::from_defs(type_defs.iter()),
        );
        // GAP-L: free a `T **out` output handle (cgltf_parse's `cgltf_data **`)
        // via its discovered deallocator so a successful parse does not leak on
        // every valid input. Added as a delete-only entry, and only if the type
        // has no real input-handle lifecycle already (don't shadow it).
        if let Some(out_handle) =
            detect_out_handle_lifecycle(&invocation_function, &target_dir, &source_path)
        {
            if !lifecycle
                .iter()
                .any(|h| h.handle_type == out_handle.handle_type)
            {
                lifecycle.push(out_handle);
            }
        }
        // §27.2: fold in the tree-wide lifecycle pairs computed ONCE by `decl_index`
        // (scanning ALL translation units, not just this target's include closure),
        // so a handle whose constructor/destructor is declared in a header the
        // target does NOT directly `#include` is still paired. The local table wins
        // (it is target-specific); tree-wide entries only FILL a missing init/delete
        // or ADD a handle the local pass never saw.
        if let Some(tree) = &args.tree_type_defs {
            merge_tree_c_lifecycle(&mut lifecycle, &tree.c_lifecycle);
        }
        // When the target is a constructor returning an opaque handle built from
        // the fuzz bytes, the plain harness only calls the constructor — the
        // decode/read state machine (where decoder bugs live) is never run.
        // Driving the pumps reaches that code, BUT each input then pays the full
        // decode cost: an A/B on pl_mpeg showed ~6x lower throughput and roughly
        // half the edge coverage in a fixed budget, because the fuzzer explores
        // far fewer inputs and most mutations never reach a valid stream. So the
        // drive loop is OFF by default (no regression to the common case) and
        // opt-in via GOVFUZZ_DRIVE_DECODERS for targets where the caller has
        // structurally-valid seeds and specifically wants decoder depth.
        let drive_plan = if std::env::var_os("GOVFUZZ_DRIVE_DECODERS").is_some() {
            c_constructor_drive_plan(&invocation_function, &functions)
        } else {
            None
        };
        harness_gen::c_generate::generate_c_direct_harness(
            harness_gen::c_generate::GenerateCDirectArgs {
                harness_id: id,
                output_dir: output_dir.clone(),
                source_path: source_path.clone(),
                target: invocation_function.clone(),
                params,
                return_type: invocation_function.return_type.clone(),
                target_includes,
                target_includes_dirs,
                target_sources,
                compile_flags,
                target_declared_in_header: is_c_family_header(&source_path)
                    || static_direct_target
                    || target_in_included_header,
                c_runtime_include,
                type_defs,
                result_cleanup,
                lifecycle,
                drive_plan,
                decoder_limits: args.decoder_limits.c_limits(),
                force: args.force,
            },
        )
    }?;
    write_c_per_tu_context(&output_dir, &per_tu_contexts)?;
    write_harness_dictionary(&output_dir, &dictionary_tokens)?;
    write_generation_metadata(
        &output_dir,
        "c",
        args.target_line,
        function.line,
        &args.kind,
        if args.kind == "sequence" {
            "sequence"
        } else {
            "direct"
        },
    )?;
    if generation_banner_enabled() {
        println!(
            "Generated C harness '{}' at {}",
            result.harness_id,
            output_dir.display()
        );
        println!("  main.c   -> {}", result.main_c.display());
        println!("  Makefile -> {}", result.makefile.display());
    }
    Ok(())
}

fn collect_c_dictionary_tokens_for_harness(
    source_path: &Path,
    source: &str,
    target_includes: &[String],
    include_dirs: &[PathBuf],
) -> Vec<String> {
    let mut tokens = Vec::new();
    if let Ok(source_tokens) = c_parser::extract_c_dictionary_tokens(source) {
        push_unique_dictionary_tokens(&mut tokens, source_tokens);
    }
    for include in target_includes {
        for dir in include_dirs {
            let header = dir.join(include);
            if header == source_path {
                continue;
            }
            let Ok(header_source) = fs::read_to_string(&header) else {
                continue;
            };
            if let Ok(header_tokens) = c_parser::extract_c_dictionary_tokens(&header_source) {
                push_unique_dictionary_tokens(&mut tokens, header_tokens);
            }
            break;
        }
    }
    tokens
}

fn collect_cpp_dictionary_tokens_for_harness(
    source_path: &Path,
    source: &str,
    target_includes: &[String],
    include_dirs: &[PathBuf],
) -> Vec<String> {
    let mut tokens = Vec::new();
    if let Ok(source_tokens) = cpp_parser::extract_cpp_dictionary_tokens(source) {
        push_unique_dictionary_tokens(&mut tokens, source_tokens);
    }
    for include in target_includes {
        for dir in include_dirs {
            let header = dir.join(include);
            if header == source_path {
                continue;
            }
            let Ok(header_source) = fs::read_to_string(&header) else {
                continue;
            };
            if let Ok(header_tokens) = cpp_parser::extract_cpp_dictionary_tokens(&header_source) {
                push_unique_dictionary_tokens(&mut tokens, header_tokens);
            }
            break;
        }
    }
    tokens
}

fn push_unique_dictionary_tokens(tokens: &mut Vec<String>, incoming: Vec<String>) {
    for token in incoming {
        push_unique_dictionary_token(tokens, token);
    }
}

pub(crate) fn write_harness_dictionary(output_dir: &Path, tokens: &[String]) -> Result<()> {
    if tokens.is_empty() {
        return Ok(());
    }
    let mut out = String::new();
    for token in tokens {
        out.push('"');
        out.push_str(&escape_afl_dictionary_token(token.as_bytes()));
        out.push_str("\"\n");
        // #379: also emit the raw little- and big-endian bytes of a numeric
        // magic constant so the dictionary matches the bytes the target
        // compares, not the ASCII spelling of the literal.
        for raw in numeric_token_byte_encodings(token) {
            out.push('"');
            out.push_str(&escape_afl_dictionary_token(&raw));
            out.push_str("\"\n");
        }
    }
    fs::write(output_dir.join("dictionary.txt"), out)
        .with_context(|| format!("write dictionary in {}", output_dir.display()))
}

/// Parse a C integer literal (hex `0x..`, octal `0..`, or decimal), tolerating
/// a `u`/`l` suffix. Returns `None` for non-integer tokens.
fn parse_c_integer_literal_value(token: &str) -> Option<u64> {
    let t = token.trim().trim_end_matches(['u', 'U', 'l', 'L']);
    if t.is_empty() {
        return None;
    }
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if t.len() > 1 && t.starts_with('0') && t.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        u64::from_str_radix(t, 8).ok()
    } else {
        t.parse::<u64>().ok()
    }
}

/// #379: a numeric magic constant mined from a comparison (`== 0x55`) is stored
/// as the text "0x55", but the parser reads the *byte* 0x55 — the ASCII "0x55"
/// never matches. Expand an integer-literal token into its raw little- and
/// big-endian width-sized byte encodings so the dictionary token matches the
/// bytes the target actually compares. Non-integer tokens yield nothing.
fn numeric_token_byte_encodings(token: &str) -> Vec<Vec<u8>> {
    let Some(value) = parse_c_integer_literal_value(token) else {
        return Vec::new();
    };
    let width = if value <= 0xFF {
        1
    } else if value <= 0xFFFF {
        2
    } else if value <= 0xFFFF_FFFF {
        4
    } else {
        8
    };
    let le = value.to_le_bytes()[..width].to_vec();
    let be = value.to_be_bytes()[8 - width..].to_vec();
    if le == be {
        vec![le]
    } else {
        vec![le, be]
    }
}

fn escape_afl_dictionary_token(token: &[u8]) -> String {
    let mut out = String::new();
    for byte in token {
        match *byte {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(char::from(*byte)),
            other => out.push_str(&format!("\\x{other:02x}")),
        }
    }
    out
}

/// Parse type definitions from the transitive `#include` closure of
/// `target_includes`, appending each header's defs to `defs`. Following includes
/// transitively (not just the directly-included headers) is what lets a typedef
/// chain spanning several headers — seL4's `word_t -> seL4_Word -> seL4_Uint64
/// -> unsigned long` — resolve to a scalar instead of collapsing to an opaque
/// type. Sound because the harness's translation unit already sees every header
/// its includes pull in. Bounded by a visited-set and a header cap.
fn collect_type_defs_from_include_closure(
    source_path: &Path,
    target_includes: &[String],
    include_dirs: &[PathBuf],
    defs: &mut Vec<c_parser::CTypeDefs>,
    parse: impl Fn(&str) -> Option<c_parser::CTypeDefs>,
) {
    const MAX_TRANSITIVE_HEADERS: usize = 256;
    let mut queue: Vec<String> = target_includes.to_vec();
    let mut visited: HashSet<PathBuf> = HashSet::new();
    let mut parsed = 0usize;
    while let Some(include) = queue.pop() {
        if parsed >= MAX_TRANSITIVE_HEADERS {
            break;
        }
        let Some(header) = include_dirs
            .iter()
            .map(|dir| dir.join(&include))
            .find(|path| path.is_file())
        else {
            continue;
        };
        if header == source_path || !visited.insert(header.clone()) {
            continue;
        }
        let Ok(header_source) = fs::read_to_string(&header) else {
            continue;
        };
        parsed += 1;
        if let Some(header_defs) = parse(&header_source) {
            defs.push(header_defs);
        }
        for nested in harness_project_includes(&header_source, include_dirs) {
            queue.push(nested);
        }
    }
}

/// Resolve the `member_access` of C++ methods the target `.cpp` left unresolved.
/// An out-of-line member definition (`bool C::foo() { ... }`) carries no access
/// specifier, so `parse_cpp_functions` on the `.cpp` reports `member_access = None`;
/// the `public:`/`private:` lives in the class declaration in a HEADER. Walk the
/// target's include closure, harvest each header's in-class method access, and fill
/// the gaps — the member-access analogue of `collect_type_defs_from_include_closure`.
/// Without this a stateful C++ class whose methods are defined out-of-line yields a
/// harness "without setup methods" (every lifecycle step looks non-public), so e.g.
/// basis_universal's transcoder is never `start_transcoding`'d before the target call.
fn resolve_cpp_member_access_from_headers(
    functions: &mut [cpp_parser::CppFunction],
    source_path: &Path,
    target_includes: &[String],
    include_dirs: &[PathBuf],
) {
    if functions.iter().all(|function| !function.api.is_method) {
        return;
    }
    const MAX_TRANSITIVE_HEADERS: usize = 256;
    let mut access: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    let mut static_methods = std::collections::BTreeSet::new();
    let mut queue: Vec<String> = target_includes.to_vec();
    let mut visited: HashSet<PathBuf> = HashSet::new();
    let mut parsed = 0usize;
    while let Some(include) = queue.pop() {
        if parsed >= MAX_TRANSITIVE_HEADERS {
            break;
        }
        let Some(header) = include_dirs
            .iter()
            .map(|dir| dir.join(&include))
            .find(|path| path.is_file())
        else {
            continue;
        };
        if header == source_path || !visited.insert(header.clone()) {
            continue;
        }
        let Ok(text) = fs::read_to_string(&header) else {
            continue;
        };
        parsed += 1;
        for (key, acc) in cpp_parser::parse_cpp_method_access_signatures(&text) {
            access.entry(key).or_insert(acc);
        }
        static_methods.extend(cpp_parser::parse_cpp_static_method_signatures(&text));
        for nested in harness_project_includes(&text, include_dirs) {
            queue.push(nested);
        }
    }
    for function in functions.iter_mut() {
        if function.api.class_name.is_some() {
            let access_key = cpp_parser::cpp_function_access_signature(function);
            if function.api.member_access.is_none() {
                if let Some(acc) = access.get(&access_key) {
                    function.api.member_access = Some(acc.clone());
                }
            }
            if static_methods.contains(&access_key) {
                function.is_static = true;
            }
        }
    }
}

/// Merge callable declarations/definitions from the resolved header and
/// build-context source closure into the target TU's function set. Constructor
/// and factory selection used to inspect only the file containing the selected
/// method, so the normal legacy layout (declaration in a header, definition in a
/// sibling `.cpp`) looked as though it had no construction path.
///
/// The overload-sensitive parser signature is the identity. When the same
/// callable appears as both a declaration and definition, retain one entry and
/// union the declaration-only facts that matter to harness safety: access,
/// static dispatch, foreign guards, and unsupported markers.
fn extend_cpp_functions_from_closure(
    functions: &mut Vec<cpp_parser::CppFunction>,
    closure_texts: &[String],
) {
    let mut positions = BTreeMap::<String, usize>::new();
    for (index, function) in functions.iter().enumerate() {
        positions
            .entry(cpp_parser::cpp_function_access_signature(function))
            .or_insert(index);
    }
    for text in closure_texts {
        let Ok(parsed) = cpp_parser::parse_cpp_functions(text) else {
            continue;
        };
        for candidate in parsed {
            let key = cpp_parser::cpp_function_access_signature(&candidate);
            if let Some(index) = positions.get(&key).copied() {
                let existing = &mut functions[index];
                if candidate.api.member_access.is_some() {
                    existing.api.member_access = candidate.api.member_access.clone();
                }
                existing.is_static |= candidate.is_static;
                if existing.foreign_guard.is_none() {
                    existing.foreign_guard = candidate.foreign_guard.clone();
                }
                for unsupported in &candidate.api.unsupported {
                    if !existing.api.unsupported.contains(unsupported) {
                        existing.api.unsupported.push(unsupported.clone());
                    }
                }
                continue;
            }
            positions.insert(key, functions.len());
            functions.push(candidate);
        }
    }
}

fn resolve_cpp_namespace_qualified_free_functions(
    functions: &mut [cpp_parser::CppFunction],
    header_texts: &[String],
) {
    let namespaces: HashSet<Vec<String>> = header_texts
        .iter()
        .flat_map(|source| cpp_parser::parse_cpp_namespace_paths(source).unwrap_or_default())
        .collect();
    for function in functions {
        if !function.api.is_method || !namespaces.contains(&function.qualifier_path) {
            continue;
        }
        function.api.api_kind = if function.api.is_template {
            "template_function".to_owned()
        } else {
            "function".to_owned()
        };
        function.api.namespace_path = function.qualifier_path.clone();
        function.api.class_name = None;
        function.api.member_access = None;
        function.api.is_method = false;
        function.api.is_constructor = false;
        function.api.is_destructor = false;
    }
}

fn collect_c_type_defs_for_harness(
    source_path: &Path,
    source: &str,
    target_includes: &[String],
    include_dirs: &[PathBuf],
    parse_source: bool,
) -> Vec<c_parser::CTypeDefs> {
    let mut defs = Vec::new();
    // Only resolve types from the target `.c` when the harness actually
    // `#include`s it (static targets). For a non-static target the harness sees
    // only the headers, so decoding a param against a struct defined solely in
    // the `.c` (tinyexpr's lexer `state`) emits a reference to a type the
    // harness can't name -> "missing_type". Restricting to header types makes
    // such a param resolve as opaque and skip cleanly instead.
    if parse_source {
        if let Ok(source_defs) = c_parser::parse_c_type_defs(source) {
            defs.push(source_defs);
        }
    } else if let Ok(source_defs) = c_parser::parse_c_type_defs(source) {
        // Even for a non-static target (where the harness sees only headers,
        // so a `.c`-only struct/enum must stay opaque-and-skip), keep
        // *function-pointer* typedefs from the `.c`. A callback parameter is
        // satisfied by a synthesized no-op trampoline that needs only the
        // pointer's signature, not a nameable definition — so the
        // missing-type concern that gates the source parse does not apply.
        // Without this the func-ptr typedef is misclassified as an opaque
        // handle and the whole target is skipped (Phase C callback gap).
        let func_ptr_typedefs: Vec<_> = source_defs
            .typedefs
            .into_iter()
            .filter(|typedef| typedef.underlying.contains("(*"))
            .collect();
        if !func_ptr_typedefs.is_empty() {
            defs.push(c_parser::CTypeDefs {
                structs: Vec::new(),
                enums: Vec::new(),
                typedefs: func_ptr_typedefs,
            });
        }
    }
    collect_type_defs_from_include_closure(
        source_path,
        target_includes,
        include_dirs,
        &mut defs,
        |header_source| c_parser::parse_c_type_defs(header_source).ok(),
    );
    defs
}

/// Function declarations visible to the harness: the target source plus its
/// included headers. Used to find cross-file lifecycle (`init`/`delete`)
/// functions — e.g. a target in scanner.c whose handle's constructor lives in
/// api.c but is declared in the shared <yaml.h> the harness includes.
fn collect_c_declarations_for_harness(
    source_path: &Path,
    source: &str,
    target_includes: &[String],
    include_dirs: &[PathBuf],
) -> Vec<c_parser::CDeclaration> {
    let mut decls = Vec::new();
    if let Ok(source_decls) = c_parser::parse_c_declarations(source) {
        decls.extend(source_decls);
    }
    for include in target_includes {
        for dir in include_dirs {
            let header = dir.join(include);
            if header == source_path {
                continue;
            }
            let Ok(header_source) = fs::read_to_string(&header) else {
                continue;
            };
            if let Ok(header_decls) = c_parser::parse_c_declarations(&header_source) {
                decls.extend(header_decls);
            }
            break;
        }
    }
    decls
}

fn collect_cpp_type_defs_for_harness(
    source_path: &Path,
    source: &str,
    target_includes: &[String],
    include_dirs: &[PathBuf],
) -> Vec<c_parser::CTypeDefs> {
    let mut defs = Vec::new();
    if let Ok(source_defs) = cpp_parser::parse_cpp_type_defs(source) {
        defs.push(source_defs);
    }
    collect_type_defs_from_include_closure(
        source_path,
        target_includes,
        include_dirs,
        &mut defs,
        |header_source| cpp_parser::parse_cpp_type_defs(header_source).ok(),
    );
    defs
}

/// A parsed C++ `class`/`struct` is only a field-wise decoder candidate when
/// value-initializing it is legal without selecting a user-declared constructor.
/// The C-shaped type registry otherwise treats every class body as an aggregate:
/// `class Options { Options() = delete; };` becomes an empty visible struct and
/// codegen emits `Options value{}`, moving a deterministic unsupported signature
/// into `failed_build`. Classes with a user-declared constructor are handled by
/// the separately verified default-constructor registry; abstract classes cannot
/// be instantiated at all.
fn suppress_non_aggregate_cpp_class_defs(
    defs: &mut [c_parser::CTypeDefs],
    class_infos: &[cpp_parser::CppClassInfo],
) {
    let non_aggregates = class_infos
        .iter()
        .filter(|info| info.is_abstract || !info.constructors.is_empty())
        .map(|info| info.qualified_name.as_str())
        .collect::<HashSet<_>>();
    for unit in defs {
        unit.structs
            .retain(|definition| !non_aggregates.contains(definition.name.as_str()));
    }
}

fn include_dirs_from_compile_flags(flags: &[String]) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let mut i = 0;
    while i < flags.len() {
        match flags[i].as_str() {
            "-I" | "-isystem" | "-iquote" | "-idirafter" => {
                if let Some(dir) = flags.get(i + 1) {
                    let path = PathBuf::from(dir);
                    if !dirs.contains(&path) {
                        dirs.push(path);
                    }
                    i += 2;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }
    dirs
}

struct CLifecycleCluster {
    handle_type: String,
    init_step: Option<harness_gen::c_generate::CLifecycleStep>,
    op_steps: Vec<harness_gen::c_generate::CLifecycleStep>,
    end_step: Option<harness_gen::c_generate::CLifecycleStep>,
    requires_source_include: bool,
}

/// Whether a sequence cluster's handle type has a COMPLETE struct/union definition
/// reachable through the harness's included HEADERS (its transitive `#include`
/// closure), as opposed to being merely forward-declared there and defined only in a
/// `.c`. A header-only [`TypeRegistry`] resolves an API-opaque handle (tidwall/hashmap
/// `struct hashmap`) to [`Opaque`](type_model::TypeShape::Opaque); only a header that
/// actually carries the body resolves it to a concrete shape. Used to gate the
/// sequence path (GAP #6): a header-opaque handle cannot be soundly zero-constructed.
fn c_handle_defined_in_headers(
    handle_type: &str,
    source_path: &Path,
    header_includes: &[String],
    include_dirs: &[PathBuf],
) -> bool {
    let mut defs = Vec::new();
    collect_type_defs_from_include_closure(
        source_path,
        header_includes,
        include_dirs,
        &mut defs,
        |header_source| c_parser::parse_c_type_defs(header_source).ok(),
    );
    c_type_has_complete_definition(handle_type, &defs)
}

/// Follow header typedefs to a concrete struct/union and require its body, not
/// merely a forward declaration. `TypeRegistry::resolve` intentionally models a
/// forward-declared tag as struct-shaped in some paths, which is sufficient for
/// type identity but not for the sequence harness's stack allocation.
fn c_type_has_complete_definition(handle_type: &str, defs: &[c_parser::CTypeDefs]) -> bool {
    let mut current = canonical_c_lifecycle_type(handle_type);
    for _ in 0..16 {
        current = current.trim_end_matches(" *").trim().to_owned();
        let tag = current
            .strip_prefix("struct ")
            .or_else(|| current.strip_prefix("union "))
            .unwrap_or(&current)
            .trim();
        if defs
            .iter()
            .flat_map(|set| set.structs.iter())
            .any(|item| item.name == tag && item.complete)
        {
            return true;
        }
        let Some(next) = defs
            .iter()
            .flat_map(|set| set.typedefs.iter())
            .find(|item| item.name == tag)
            .map(|item| item.underlying.clone())
        else {
            return false;
        };
        let next = canonical_c_lifecycle_type(&next);
        if next == current {
            return false;
        }
        current = next;
    }
    false
}

fn c_lifecycle_steps(
    target: &c_parser::CFunction,
    functions: &[c_parser::CFunction],
) -> Result<CLifecycleCluster> {
    let Some(handle_type) = c_handle_base_type(target) else {
        bail!("C --kind sequence requires a first-parameter struct handle target");
    };
    let Some(target_handle) = target
        .params
        .first()
        .map(|p| canonical_c_lifecycle_type(&p.c_type))
    else {
        bail!("C --kind sequence requires a first-parameter struct handle target");
    };

    let mut cluster = functions
        .iter()
        .filter(|function| {
            let same_target = function.name == target.name && function.line == target.line;
            let static_lifecycle_boundary = function.is_static
                && (is_c_lifecycle_init(&function.name) || is_c_lifecycle_end(&function.name));
            (!function.is_static || same_target || static_lifecycle_boundary)
                && function
                    .params
                    .first()
                    .is_some_and(|param| canonical_c_lifecycle_type(&param.c_type) == target_handle)
        })
        .collect::<Vec<_>>();
    cluster.sort_by_key(|function| function.line);
    let requires_source_include = cluster.iter().any(|function| function.is_static);

    let init_step = cluster
        .iter()
        .find(|function| is_c_lifecycle_init(&function.name))
        .map(|function| c_lifecycle_function_to_step(function));
    if init_step.is_none() {
        eprintln!(
            "warning: generated C lifecycle harness for '{}' without init function",
            target.name
        );
    }

    let end_step = cluster
        .iter()
        .find(|function| is_c_lifecycle_end(&function.name))
        .map(|function| c_lifecycle_function_to_step(function));
    if end_step.is_none() {
        eprintln!(
            "warning: generated C lifecycle harness for '{}' without end function",
            target.name
        );
    }

    let mut op_functions = cluster
        .into_iter()
        .filter(|function| {
            !is_c_lifecycle_init(&function.name) && !is_c_lifecycle_end(&function.name)
        })
        .collect::<Vec<_>>();
    if let Some(pos) = op_functions
        .iter()
        .position(|function| function.line == target.line && function.name == target.name)
    {
        let target_function = op_functions.remove(pos);
        op_functions.insert(0, target_function);
    }
    let op_steps = op_functions
        .into_iter()
        .take(8)
        .map(c_lifecycle_function_to_step)
        .collect::<Vec<_>>();
    if op_steps.is_empty() {
        bail!(
            "C --kind sequence requires at least one operation sharing first parameter '{}'",
            target_handle
        );
    }

    Ok(CLifecycleCluster {
        handle_type,
        init_step,
        op_steps,
        end_step,
        requires_source_include,
    })
}

fn c_lifecycle_function_to_step(
    function: &c_parser::CFunction,
) -> harness_gen::c_generate::CLifecycleStep {
    harness_gen::c_generate::CLifecycleStep {
        name: function.name.clone(),
        params: function
            .params
            .iter()
            .skip(1)
            .map(|param| harness_gen::c_generate::CParameter {
                name: param.name.clone(),
                c_type: param.c_type.clone(),
            })
            .collect(),
        return_type: function.return_type.clone(),
    }
}

/// Discover constructor/destructor pairs for opaque handle types among the
/// target file's functions, so the direct C harness can build a handle that
/// can't be value-synthesised (e.g. libyaml `yaml_parser_t` via
/// `yaml_parser_initialize` / `yaml_parser_delete`). Only single-argument,
/// non-static init/delete functions qualify: the harness must be able to call
/// them with just `&handle` and link them across translation units.
/// Merge the tree-wide lifecycle pairs (§27.2) into a target's local lifecycle
/// table. The LOCAL table is authoritative — it was built from the target's own
/// functions + included headers and is specific to this target. A tree-wide entry
/// only: (a) FILLS a missing `init`/`delete` on a handle the local table already
/// knows (the §27.2 case: the constructor is declared in a header the target does
/// not `#include`), or (b) ADDS a handle the local pass never saw at all. It never
/// overrides a local init/delete.
pub(crate) fn merge_tree_c_lifecycle(
    local: &mut Vec<harness_gen::c_generate::CHandleLifecycle>,
    tree: &[harness_gen::c_generate::CHandleLifecycle],
) {
    for tw in tree {
        let tree_key = harness_gen::c_decoders::normalize_handle_key(&tw.handle_type);
        match local
            .iter_mut()
            .find(|h| harness_gen::c_decoders::normalize_handle_key(&h.handle_type) == tree_key)
        {
            Some(existing) => {
                if existing.init.is_none() && tw.init.is_some() {
                    existing.init = tw.init.clone();
                    existing.init_returns_handle = tw.init_returns_handle;
                    existing.init_args = tw.init_args.clone();
                }
                if existing.delete.is_none() && tw.delete.is_some() {
                    existing.delete = tw.delete.clone();
                }
            }
            None => local.push(tw.clone()),
        }
    }
}

pub(crate) fn c_direct_lifecycle_table(
    functions: &[c_parser::CFunction],
    decls: &[c_parser::CDeclaration],
    registry: &type_model::TypeRegistry,
) -> Vec<harness_gen::c_generate::CHandleLifecycle> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut inits: BTreeMap<String, String> = BTreeMap::new();
    let mut deletes: BTreeMap<String, String> = BTreeMap::new();
    let mut delete_candidates: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut init_args: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut handles: BTreeSet<String> = BTreeSet::new();

    // A function defined `static` has internal linkage: its forward declaration
    // is collected from the target .c by `parse_c_declarations` (which loses
    // static-ness), but it can't be called from the harness's separate
    // translation unit. Exclude such names from the cross-file declaration path
    // so an internal initializer (expat's `static initializeEncoding(XML_Parser)`)
    // never shadows the public constructor.
    let static_names: BTreeSet<&str> = functions
        .iter()
        .filter(|f| f.is_static)
        .map(|f| f.name.as_str())
        .collect();

    // Single-argument lifecycle functions from two sources: same-file
    // definitions (non-static) and declarations in the harness's included
    // headers (cross-file — e.g. libyaml's yaml_parser_initialize lives in
    // api.c but is declared in <yaml.h> which a scanner.c target includes).
    // A cross-file definition is linked in by the UndefinedSymbol->AddSource
    // closure. Header declarations are non-static by nature.
    // Guard `params[0]` indexing with the `len() == 1` filter.
    let same_file = functions
        .iter()
        .filter(|f| !f.is_static && f.params.len() == 1)
        .map(|f| {
            (
                f.name.as_str(),
                f.params[0].c_type.as_str(),
                f.return_type.as_str(),
            )
        });
    let cross_file = decls
        .iter()
        .filter(|d| !static_names.contains(d.name.as_str()) && d.param_types.len() == 1)
        .map(|d| {
            (
                d.name.as_str(),
                d.param_types[0].as_str(),
                d.return_type.as_str(),
            )
        });

    for (name, param_type, return_type) in same_file.chain(cross_file) {
        // A single-arg function that *returns* a handle pointer is a returning
        // constructor (`XML_Parser XML_ParserCreate(const XML_Char *)`); its one
        // argument is a config arg, not the handle. Leave it to the returning
        // pass below so it isn't mis-registered as an in-place initializer of
        // the config arg's type.
        if c_lifecycle_handle_key(return_type, registry).is_some() {
            continue;
        }
        let Some(base) = c_lifecycle_handle_key(param_type, registry) else {
            continue;
        };
        if is_c_lifecycle_init(name) {
            // An in-place initializer (`void foo_init(T *)`) returns nothing or a
            // status scalar — never a pointer or aggregate. A single-arg function
            // taking a TYPEDEF-HIDDEN pointer handle by value cannot construct
            // that handle; it is an accessor the verb whitelist mis-matched
            // (redis `sdsAllocSize(sds)` / `sdsAllocPtr(sds)` via the `alloc`
            // token). Registering it as the handle's init shadows the real
            // returning constructor (found structurally below), so leave such
            // by-value handle functions to the structural pass.
            let ret = canonical_c_lifecycle_type(return_type);
            let init_shaped = (ret == "void" || is_c_scalar_type(&ret))
                && !is_c_bare_pointer_typedef_value(param_type, registry);
            if init_shaped {
                inits.entry(base.clone()).or_insert_with(|| name.to_owned());
                handles.insert(base);
            }
        } else if is_c_lifecycle_end(name) {
            let candidates = delete_candidates.entry(base.clone()).or_default();
            if !candidates.iter().any(|candidate| candidate == name) {
                candidates.push(name.to_owned());
            }
            match deletes.get_mut(&base) {
                Some(existing) if c_lifecycle_end_rank(name) < c_lifecycle_end_rank(existing) => {
                    *existing = name.to_owned();
                }
                None => {
                    deletes.insert(base.clone(), name.to_owned());
                }
                _ => {}
            }
            handles.insert(base);
        }
    }

    // Returning constructors: the handle is the return value, not a pointer
    // argument (xmlNewParserCtxt, archive_read_new, cJSON_CreateObject,
    // XML_ParserCreate, ...). Zero-argument constructors qualify, as do
    // constructors whose parameters are *all* pointers — those are called with
    // the neutral "use defaults" value `NULL` for each (`XML_ParserCreate(NULL)`).
    // An in-place initializer already found for the same base takes precedence;
    // among returning candidates the one with the fewest arguments wins. The
    // matching destructor `foo_free(T *)` is captured by the single-arg loop.
    let mut returning: BTreeSet<String> = BTreeSet::new();
    let ret_same_file = functions.iter().filter(|f| !f.is_static).filter_map(|f| {
        c_neutral_ctor_args(f.params.iter().map(|p| p.c_type.as_str()))
            .map(|args| (f.name.as_str(), f.return_type.as_str(), args))
    });
    let ret_cross_file = decls
        .iter()
        .filter(|d| !static_names.contains(d.name.as_str()))
        .filter_map(|d| {
            c_neutral_ctor_args(d.param_types.iter().map(|s| s.as_str()))
                .map(|args| (d.name.as_str(), d.return_type.as_str(), args))
        });
    for (name, ret_type, args) in ret_same_file.chain(ret_cross_file) {
        if !is_c_lifecycle_init(name) {
            continue;
        }
        let Some(base) = c_lifecycle_handle_key(ret_type, registry) else {
            continue;
        };
        // A strong in-place initializer (`init`/`setup`) wins. A weak
        // open-like operation on an already-created handle does not: libarchive
        // exposes `archive_read_open1(archive *)` beside the actual returning
        // constructor `archive_read_new()`, and treating open1 as construction
        // makes an opaque handle impossible to allocate.
        if let Some(existing) = inits.get(&base) {
            if !returning.contains(&base)
                && !existing.starts_with('_')
                && is_strong_c_inplace_lifecycle_init(existing)
            {
                continue;
            }
        }
        // Among returning candidates prefer the fewest arguments.
        if let Some(existing) = init_args.get(&base) {
            if existing.len() <= args.len() {
                continue;
            }
        }
        inits.insert(base.clone(), name.to_owned());
        init_args.insert(base.clone(), args);
        returning.insert(base.clone());
        handles.insert(base);
    }

    // Structural (verb-independent) constructor/destructor detection. Rescues
    // handle types whose API uses a naming convention the verb whitelist can't
    // see: lowercase-glued names (`sdsnew`/`sdsempty`/`sdsfree`, tokenized as ONE
    // word so is_c_lifecycle_init never matches) or simply non-verb names
    // (`json_object`/`json_decref`). Without it these opaque / interior-pointer
    // handles (redis `sds`, jansson `json_t`) are fabricated field-by-field from
    // raw fuzz bytes and crash on their first accessor — the dominant campaign FP
    // class. Rule: a function RETURNING handle H that does NOT take H as any
    // parameter, with neutrally-suppliable args, is a constructor; a single-param
    // `void` function TAKING H is a destructor. Gated to handle keys with NO
    // verb-detected init, so the verb-named lifecycle found above is never
    // overridden, and only for keys actually USED as a handle (taken as some
    // function's first parameter) so a plain factory output isn't mistaken for one.
    {
        struct UFn<'a> {
            name: &'a str,
            params: Vec<&'a str>,
            ret: &'a str,
        }
        let mut all: Vec<UFn> = Vec::new();
        for f in functions.iter().filter(|f| !f.is_static) {
            all.push(UFn {
                name: f.name.as_str(),
                params: f.params.iter().map(|p| p.c_type.as_str()).collect(),
                ret: f.return_type.as_str(),
            });
        }
        for d in decls
            .iter()
            .filter(|d| !static_names.contains(d.name.as_str()))
        {
            all.push(UFn {
                name: d.name.as_str(),
                params: d.param_types.iter().map(|s| s.as_str()).collect(),
                ret: d.return_type.as_str(),
            });
        }
        let key_of = |ty: &str| c_lifecycle_handle_key(ty, registry);
        // Types taken as some function's first parameter — i.e. used AS a handle.
        let mut taken_first: BTreeSet<String> = BTreeSet::new();
        for f in &all {
            if let Some(k) = f.params.first().and_then(|t| key_of(t)) {
                taken_first.insert(k);
            }
        }
        // Best structural constructor per handle key (fewest neutral args).
        let mut struct_ctor: BTreeMap<String, (&str, Vec<String>)> = BTreeMap::new();
        for f in &all {
            let Some(rkey) = key_of(f.ret) else { continue };
            // Skip when a constructor (in-place verb-init or returning) was already
            // found for this key, or the type isn't used as a handle. The accessor
            // false-positives that used to shadow the real constructor (sdsAllocPtr)
            // are now rejected at the verb pass above (an init returns void/status,
            // not a pointer), so a genuine in-place init still wins here.
            if inits.contains_key(&rkey) || !taken_first.contains(&rkey) {
                continue;
            }
            // A constructor must not itself TAKE the handle (excludes accessors /
            // mutators like `json_t *json_object_get(json_t *, const char *)`).
            if f.params
                .iter()
                .any(|t| key_of(t).as_deref() == Some(rkey.as_str()))
            {
                continue;
            }
            let Some(args) = c_neutral_ctor_args(f.params.iter().copied()) else {
                continue;
            };
            match struct_ctor.get(&rkey) {
                Some((_, existing)) if existing.len() <= args.len() => {}
                _ => {
                    struct_ctor.insert(rkey, (f.name, args));
                }
            }
        }
        // Best structural destructor per handle key: single-param `void` fn taking
        // H, preferring a free-ish name (verb tokenization missed it, so match by
        // substring as a tiebreak: free/decref/destroy/release/del/close/unref).
        let dtor_rank = |name: &str| -> u8 {
            let l = name.to_ascii_lowercase();
            if ["free", "decref", "destroy", "release", "unref", "dispose"]
                .iter()
                .any(|n| l.contains(n))
            {
                0
            } else if ["del", "close", "fini", "deinit", "cleanup"]
                .iter()
                .any(|n| l.contains(n))
            {
                1
            } else {
                2
            }
        };
        let mut struct_dtor: BTreeMap<String, (&str, u8)> = BTreeMap::new();
        for f in &all {
            if f.params.len() != 1 || canonical_c_lifecycle_type(f.ret) != "void" {
                continue;
            }
            let Some(k) = key_of(f.params[0]) else {
                continue;
            };
            if deletes.contains_key(&k) || !struct_ctor.contains_key(&k) {
                continue;
            }
            let rank = dtor_rank(f.name);
            match struct_dtor.get(&k) {
                Some((_, r)) if *r <= rank => {}
                _ => {
                    struct_dtor.insert(k, (f.name, rank));
                }
            }
        }
        for (key, (ctor, args)) in struct_ctor {
            inits.insert(key.clone(), ctor.to_owned());
            init_args.insert(key.clone(), args);
            returning.insert(key.clone());
            if let Some((dtor, _)) = struct_dtor.get(&key) {
                deletes.insert(key.clone(), (*dtor).to_owned());
            }
            handles.insert(key);
        }
    }

    // Some libraries reuse one opaque type for distinct API families. libarchive,
    // for example, returns `struct archive *` from both `archive_read_new` and
    // `archive_write_new`; pairing the selected read constructor with a write-side
    // free corrupts the harness and often pulls in an unrelated implementation TU.
    // Prefer the public destructor whose name shares the longest token prefix with
    // the selected constructor, then fall back to the existing lifecycle rank.
    for (handle, candidates) in delete_candidates {
        let init_tokens = inits
            .get(&handle)
            .map(|name| c_lifecycle_name_tokens(name))
            .unwrap_or_default();
        if let Some(best) = candidates.into_iter().min_by_key(|name| {
            let end_tokens = c_lifecycle_name_tokens(name);
            let shared_prefix = init_tokens
                .iter()
                .zip(&end_tokens)
                .take_while(|(left, right)| left == right)
                .count();
            (
                usize::MAX - shared_prefix,
                name.starts_with('_'),
                c_lifecycle_end_rank(name),
                name.clone(),
            )
        }) {
            deletes.insert(handle, best);
        }
    }

    // Emit every handle that has a constructor *or* a destructor: a
    // destructor-only type is an output struct the callee fills (libyaml
    // yaml_token_t / yaml_event_t / yaml_document_t), handled by the decoder's
    // zero-init + delete path.
    handles
        .into_iter()
        .map(|handle_type| harness_gen::c_generate::CHandleLifecycle {
            init: inits.get(&handle_type).cloned(),
            delete: deletes.get(&handle_type).cloned(),
            init_returns_handle: returning.contains(&handle_type),
            init_args: init_args.get(&handle_type).cloned().unwrap_or_default(),
            handle_type,
        })
        .collect()
}

/// The canonical opaque-pointee key for a handle pointer type, matching the key
/// the decoder looks up in the lifecycle table. Resolves both spelled pointers
/// (`widget_t *` -> `widget_t`) and typedef-hidden pointers
/// (`typedef struct S *Handle` -> `struct S`). Returns `None` for non-pointers,
/// `void *`, and scalar / `char` buffers (which are decode inputs, not handles).
///
/// Tolerates calling-convention / export macros that tree-sitter can't
/// preprocess away and so remain glued onto the type string
/// (`XML_Parser XMLCALL`, `XMLIMPORT FILE *`, `CURL_EXTERN CURL *`): when the
/// whole string doesn't resolve, each identifier token is tried against the
/// registry and the unique one that is itself a pointer/handle typedef wins.
/// C++ counterpart of [`c_direct_lifecycle_table`] for the cpp DIRECT path: find
/// FREE-function init/delete lifecycles (`de265_new_decoder` / `de265_free_decoder`)
/// for an opaque-handle parameter, so a C-ABI decode entry living in a `.cc` file
/// (libde265 `de265_decode_data(de265_decoder_context *, ...)`) can build its handle
/// instead of being skipped "needs lifecycle support". Same-file FREE functions only
/// — a class method belongs to the sequence path; this is the C-style pattern where
/// the lifecycle lives beside the decode entry. Reuses the C-side handle-key /
/// init-verb / delete-verb / neutral-arg heuristics.
fn cpp_direct_lifecycle_table(
    functions: &[cpp_parser::CppFunction],
    registry: &type_model::TypeRegistry,
) -> Vec<harness_gen::c_generate::CHandleLifecycle> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut inits: BTreeMap<String, String> = BTreeMap::new();
    let mut deletes: BTreeMap<String, String> = BTreeMap::new();
    let mut init_args: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut returning: BTreeSet<String> = BTreeSet::new();
    let mut handles: BTreeSet<String> = BTreeSet::new();

    let is_free = |f: &&cpp_parser::CppFunction| !f.api.is_method && !f.is_static;

    // Single-arg delete (`de265_free_decoder(de265_decoder_context *)`). A single-arg
    // function that RETURNS a handle is a returning constructor (handled below), not
    // an in-place initializer of its argument type.
    for f in functions
        .iter()
        .filter(is_free)
        .filter(|f| f.params.len() == 1)
    {
        if c_lifecycle_handle_key(&f.return_type, registry).is_some() {
            continue;
        }
        let Some(base) = c_lifecycle_handle_key(&f.params[0].cpp_type, registry) else {
            continue;
        };
        if is_c_lifecycle_init(&f.name) {
            inits.entry(base.clone()).or_insert_with(|| f.name.clone());
            handles.insert(base);
        } else if is_c_lifecycle_end(&f.name) {
            deletes
                .entry(base.clone())
                .or_insert_with(|| f.name.clone());
            handles.insert(base);
        }
    }

    // Returning constructors (`de265_decoder_context* de265_new_decoder(void)`): the
    // handle is the return value; zero-arg or all-pointer-arg ("use NULL defaults").
    for f in functions.iter().filter(is_free) {
        let Some(args) = c_neutral_ctor_args(f.params.iter().map(|p| p.cpp_type.as_str())) else {
            continue;
        };
        if !is_c_lifecycle_init(&f.name) {
            continue;
        }
        let Some(base) = c_lifecycle_handle_key(&f.return_type, registry) else {
            continue;
        };
        if inits.contains_key(&base) && !returning.contains(&base) {
            continue;
        }
        if let Some(existing) = init_args.get(&base) {
            if existing.len() <= args.len() {
                continue;
            }
        }
        inits.insert(base.clone(), f.name.clone());
        init_args.insert(base.clone(), args);
        returning.insert(base.clone());
        handles.insert(base);
    }

    handles
        .into_iter()
        .map(|handle_type| harness_gen::c_generate::CHandleLifecycle {
            init: inits.get(&handle_type).cloned(),
            delete: deletes.get(&handle_type).cloned(),
            init_returns_handle: returning.contains(&handle_type),
            init_args: init_args.get(&handle_type).cloned().unwrap_or_default(),
            handle_type,
        })
        .collect()
}

fn c_lifecycle_handle_key(raw: &str, registry: &type_model::TypeRegistry) -> Option<String> {
    fn accept(base: Option<String>) -> Option<String> {
        let base = base?;
        let base = base.trim();
        (!base.is_empty() && base != "void" && !is_c_scalar_type(base)).then(|| base.to_owned())
    }

    // Collapse a typedef alias to its canonical underlying type so two spellings of
    // the SAME handle (`struct widget *` and a `typedef struct widget widget_t`'s
    // `widget_t *`) pair under one key (#453). An opaque `typedef void`/scalar alias
    // keeps its TYPEDEF NAME — resolving it would collapse distinct opaque handles
    // (`de265_decoder_context`, `de265_image`) to "void". A pointer-typed alias
    // target is left alone (already a handle spelling).
    let canonicalize = |base: String| -> String {
        match registry.alias_target_spelling(&base) {
            Some(target) => {
                let t = target.trim();
                if t.is_empty() || t == "void" || is_c_scalar_type(t) || t.contains('*') {
                    base
                } else {
                    t.to_owned()
                }
            }
            None => base,
        }
    };

    // Collapse a leading elaborated tag (`struct X`/`union X`/`enum X`) to its
    // bare name AFTER alias resolution, so the table key matches the decoder's
    // lookup key and a handle the parser spelled WITH the tag in one position
    // (a destructor's `struct T *` parameter) and WITHOUT it in another (a
    // returning constructor whose return type lost the `struct` keyword during
    // prototype normalization, `T *`) pairs under ONE table entry.
    let finalize = |key: String| -> String {
        harness_gen::c_decoders::normalize_handle_key(&canonicalize(key)).to_owned()
    };

    // A typedef NAME used as an interior/opaque handle: a single-identifier
    // spelling (no `*`) that aliases a POINTER to a scalar or `void`. redis's
    // `typedef char *sds` is the canonical case — the pointer points INTO a
    // malloc'd `{header; data}` block, so accessors read `s[-1]`; feeding a raw
    // `gf_c_string` buffer underflows that header (a guaranteed GF-201 OOB FP).
    // Key it by the typedef name so its constructor family (found structurally
    // below) pairs with its accessors. A BARE scalar pointer (`const char *`, no
    // typedef) carries a `*` in the spelling and is NOT matched here, so it stays
    // a string decode input (cJSON_CreateString(const char *)).
    let canonical = canonical_c_lifecycle_type(raw);
    let raw = canonical.as_str();
    let bare = raw
        .trim()
        .trim_start_matches("const ")
        .trim_start_matches("volatile ")
        .trim();
    if !bare.is_empty()
        && bare.chars().all(|c| c.is_alphanumeric() || c == '_')
        && registry.alias_target_spelling(bare).is_some_and(|target| {
            target
                .trim()
                .strip_suffix('*')
                .map(|pointee| {
                    let pointee = pointee
                        .trim()
                        .trim_start_matches("const ")
                        .trim_start_matches("volatile ")
                        .trim();
                    pointee == "void" || is_c_scalar_type(pointee)
                })
                .unwrap_or(false)
        })
    {
        return Some(bare.to_owned());
    }

    if let Some(key) = accept(registry.pointer_base_spelling(raw)) {
        let direct_type = key.starts_with("struct ")
            || key.starts_with("union ")
            || key.starts_with("enum ")
            || !key.contains(char::is_whitespace)
            || registry.alias_target_spelling(&key).is_some();
        if direct_type {
            return Some(finalize(key));
        }
    }
    // Fallback: resolve through noise tokens. Accept only the unique token the
    // registry already knows to be a pointer/handle typedef — macros like
    // `XMLCALL` aren't registered types, so they're ignored; an ambiguous match
    // (two distinct handle typedefs) yields None rather than a guess.
    let mut found: Option<String> = None;
    for token in raw.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
        if token.is_empty() {
            continue;
        }
        if let Some(key) = accept(registry.pointer_base_spelling(token)).map(&finalize) {
            match &found {
                Some(existing) if *existing != key => return None,
                _ => found = Some(key),
            }
        }
    }
    found
}

fn is_c_bare_pointer_typedef_value(raw: &str, registry: &type_model::TypeRegistry) -> bool {
    let bare = raw
        .trim()
        .trim_start_matches("const ")
        .trim_start_matches("volatile ")
        .trim();
    !bare.is_empty()
        && bare.chars().all(|c| c.is_alphanumeric() || c == '_')
        && registry
            .alias_target_spelling(bare)
            .is_some_and(|target| canonical_c_lifecycle_type(&target).ends_with('*'))
}

/// Neutral argument expressions for calling a returning constructor, or `None`
/// if the constructor's parameters can't be supplied neutrally. A zero-arg or
/// `(void)` constructor yields `Some(vec![])`; a constructor whose parameters
/// are all pointers yields `Some(vec!["NULL"; n])` (the "use defaults" idiom).
/// Any non-pointer parameter (a size, a flag, a by-value struct) returns `None`
/// so such constructors are left alone rather than called with a bogus value.
pub(crate) fn c_neutral_ctor_args<'a>(types: impl Iterator<Item = &'a str>) -> Option<Vec<String>> {
    let types: Vec<&str> = types.collect();
    if types.is_empty() {
        return Some(Vec::new());
    }
    if types.len() == 1 && canonical_c_lifecycle_type(types[0]) == "void" {
        return Some(Vec::new());
    }
    let mut args = Vec::with_capacity(types.len());
    for ty in types {
        let canonical = canonical_c_lifecycle_type(ty);
        let lower = canonical.to_ascii_lowercase();
        if canonical.ends_with('*')
            || lower.ends_with("_func")
            || lower.ends_with("_fn")
            || lower.ends_with("_callback")
            || lower.ends_with("_cb")
        {
            args.push("NULL".to_owned());
        } else {
            return None;
        }
    }
    Some(args)
}

fn c_handle_base_type(function: &c_parser::CFunction) -> Option<String> {
    let first = function.params.first()?;
    let canonical = canonical_c_lifecycle_type(&first.c_type);
    let base = canonical.strip_suffix(" *")?.trim();
    // Scalar/buffer pointers (`char *`, `uint8_t *`) are decode inputs, not
    // opaque handles — never the basis for a lifecycle sequence.
    (!base.is_empty() && !is_c_scalar_type(base)).then(|| base.to_owned())
}

/// True when a canonical pointer type (`T *`, const/volatile already stripped)
/// is a lifecycle handle — an opaque/struct object driven by init/op/end calls
/// — rather than a data buffer. Shared by the auto eligibility gate
/// (`crate::auto::attempt`) and the generator so they never disagree.
pub(crate) fn is_c_lifecycle_handle_type(canonical: &str) -> bool {
    let Some(base) = canonical.strip_suffix(" *") else {
        return false;
    };
    let base = base.trim();
    !base.is_empty() && base != "void" && !is_c_scalar_type(base)
}

/// Whole C scalar / fixed-width integer spellings whose pointers are data
/// buffers, not opaque lifecycle handles. `const`/`volatile` are already
/// stripped by [`canonical_c_lifecycle_type`]. Treating `char *` as a handle
/// spuriously clustered string/buffer functions into sequence harnesses (e.g.
/// cJSON's `cJSON_CreateString(const char *)` mis-read as a `char`-handle init).
pub(crate) fn is_c_scalar_type(base: &str) -> bool {
    let normalized = base.split_whitespace().collect::<Vec<_>>().join(" ");
    matches!(
        normalized.as_str(),
        "char"
            | "signed char"
            | "unsigned char"
            | "short"
            | "short int"
            | "unsigned short"
            | "int"
            | "unsigned"
            | "unsigned int"
            | "long"
            | "long int"
            | "unsigned long"
            | "long long"
            | "unsigned long long"
            | "float"
            | "double"
            | "long double"
            | "_Bool"
            | "bool"
            | "size_t"
            | "ssize_t"
            | "ptrdiff_t"
            | "intptr_t"
            | "uintptr_t"
            | "wchar_t"
            | "char16_t"
            | "char32_t"
            | "int8_t"
            | "int16_t"
            | "int32_t"
            | "int64_t"
            | "uint8_t"
            | "uint16_t"
            | "uint32_t"
            | "uint64_t"
    )
}

pub(crate) fn canonical_c_lifecycle_type(raw: &str) -> String {
    let unwrapped = c_stub_gen::unwrap_export_macro(raw);
    let mut type_text = unwrapped.trim();
    while type_text.starts_with('(') && type_text.ends_with(')') {
        let mut depth = 0usize;
        let mut encloses_all = false;
        for (index, byte) in type_text.bytes().enumerate() {
            match byte {
                b'(' => depth += 1,
                b')' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        encloses_all = index + 1 == type_text.len();
                        break;
                    }
                }
                _ => {}
            }
        }
        if !encloses_all {
            break;
        }
        type_text = type_text[1..type_text.len() - 1].trim();
    }
    type_text
        .replace('*', " * ")
        .split_whitespace()
        .filter(|token| !matches!(*token, "const" | "volatile" | "restrict" | "register"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Split a function name into lowercase word tokens at snake_case and
/// camelCase boundaries. Lifecycle needles must match whole tokens:
/// substring matching classified "buffer_append" as an end step ("end")
/// and "renew" as an init step ("new"), wiring ops as teardown in
/// generated sequence harnesses.
fn c_lifecycle_name_tokens(name: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut prev_is_lower = false;
    for ch in name.chars() {
        if ch.is_ascii_alphabetic() {
            if ch.is_ascii_uppercase() && prev_is_lower {
                tokens.push(std::mem::take(&mut current));
            }
            prev_is_lower = ch.is_ascii_lowercase();
            current.push(ch.to_ascii_lowercase());
        } else {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            prev_is_lower = false;
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Lifecycle verbs that C constructor/destructor conventions GLUE to a type noun in
/// one lowercase token — lua's `luaL_newstate` tokenizes to `newstate`, which
/// whole-token matching misses, leaving `lua_State` unconstructable and silently
/// skipping the whole Lua C API (#17). These verbs may match as a PREFIX of a
/// longer token. `renew`/`deinit` stay excluded because they don't START with the
/// verb (`new`/`init` appear mid-token).
const C_INIT_GLUE_VERBS: &[&str] = &["new", "create", "open"];
const C_END_GLUE_VERBS: &[&str] = &["free", "destroy", "close", "delete", "release"];

/// True when `token` is the lifecycle `verb`, or — for a glue-capable verb — a
/// longer token that STARTS WITH it (`newstate` matches `new`). Non-glue verbs
/// (`init`, `setup`, `cleanup`, ...) keep strict whole-token matching so a partial
/// hit can't over-classify.
fn token_matches_lifecycle_verb(token: &str, verb: &str, glue: &[&str]) -> bool {
    token == verb || (glue.contains(&verb) && token.len() > verb.len() && token.starts_with(verb))
}

pub(crate) fn is_c_lifecycle_init(name: &str) -> bool {
    let tokens = c_lifecycle_name_tokens(name);
    // Whole-token needles (substring matching mis-classified "renew" as
    // "new"); spell out longer forms like "initialize" since "init" won't
    // match them under exact-token comparison. The glue verbs (new/create/open)
    // additionally match a longer token that starts with them (luaL_newstate).
    [
        "init",
        "initialize",
        "initialise",
        "create",
        "open",
        "new",
        "alloc",
        "setup",
    ]
    .iter()
    .any(|needle| {
        tokens
            .iter()
            .any(|token| token_matches_lifecycle_verb(token, needle, C_INIT_GLUE_VERBS))
    })
}

pub(crate) fn is_c_lifecycle_end(name: &str) -> bool {
    let tokens = c_lifecycle_name_tokens(name);
    [
        "end", "free", "close", "destroy", "delete", "release", "cleanup", "fini", "deinit",
        "dispose", "shutdown",
    ]
    .iter()
    .any(|needle| {
        tokens
            .iter()
            .any(|token| token_matches_lifecycle_verb(token, needle, C_END_GLUE_VERBS))
    })
}

fn is_strong_c_inplace_lifecycle_init(name: &str) -> bool {
    let tokens = c_lifecycle_name_tokens(name);
    ["init", "initialize", "initialise", "setup"]
        .iter()
        .any(|needle| tokens.iter().any(|token| token == needle))
}

fn c_lifecycle_end_rank(name: &str) -> u8 {
    let tokens = c_lifecycle_name_tokens(name);
    if ["free", "destroy", "delete", "release", "dispose", "deinit"]
        .iter()
        .any(|needle| {
            tokens
                .iter()
                .any(|token| token_matches_lifecycle_verb(token, needle, C_END_GLUE_VERBS))
        })
    {
        0
    } else if tokens
        .iter()
        .any(|token| token == "cleanup" || token == "fini")
    {
        1
    } else {
        2
    }
}

/// True when a function name reads like a stream "pump" — a call that advances a
/// decode/read state machine and is worth driving in a loop after construction.
/// Deliberately a verb whitelist (not "any non-init/non-end"): it excludes
/// getters (`plm_get_framerate`, `plm_has_ended`) so the drive loop spends its
/// budget on the parser, not on side-effect-free accessors.
fn is_c_drive_pump_name(name: &str) -> bool {
    let tokens = c_lifecycle_name_tokens(name);
    [
        "decode", "read", "next", "step", "advance", "process", "poll", "render", "run", "pump",
        "iterate", "demux", "parse",
    ]
    .iter()
    .any(|needle| tokens.iter().any(|token| token == needle))
}

/// Plan a constructor drive loop for a direct target that RETURNS an opaque
/// handle built from the fuzz bytes (e.g. `plm_t *plm_create_with_memory(
/// uint8_t *, size_t, int)`). The plain direct harness only calls the
/// constructor, leaving the decode/read state machine — where parser bugs live —
/// unfuzzed. This finds sibling functions that consume the same handle so the
/// harness can pump them after construction.
///
/// Conservative on purpose, so it never fabricates arguments or drives the wrong
/// thing:
///   * the target must return a non-scalar handle pointer AND have a
///     constructor-shaped name (so we don't drive a borrowed-handle accessor);
///   * pumps and the destroy must take EXACTLY the handle as their sole
///     argument (no other parameters to invent, hence no spurious-argument
///     crashes), be non-`static` (linkable from the harness TU), and match the
///     pump/destroy verb sets;
///   * a destroy is REQUIRED — without one each persistent-mode iteration would
///     leak the handle and eventually trip a false OOM.
///
/// Returns `None` (keep the plain create-only harness) unless all hold.
fn c_constructor_drive_plan(
    target: &c_parser::CFunction,
    functions: &[c_parser::CFunction],
) -> Option<harness_gen::c_generate::CDrivePlan> {
    let return_canonical = canonical_c_lifecycle_type(&target.return_type);
    if !is_c_lifecycle_handle_type(&return_canonical) || !is_c_lifecycle_init(&target.name) {
        return None;
    }
    let handle = return_canonical.strip_suffix(" *")?.trim().to_owned();

    let handle_is_sole_param = |function: &c_parser::CFunction| {
        function.params.len() == 1
            && canonical_c_lifecycle_type(&function.params[0].c_type)
                .strip_suffix(" *")
                .map(str::trim)
                == Some(handle.as_str())
    };

    let mut steps = Vec::new();
    let mut destroy: Option<String> = None;
    for function in functions {
        if function.name == target.name && function.line == target.line {
            continue; // the constructor itself
        }
        if function.is_static || !handle_is_sole_param(function) {
            continue;
        }
        if is_c_lifecycle_end(&function.name) {
            destroy.get_or_insert_with(|| function.name.clone());
        } else if is_c_drive_pump_name(&function.name) && !is_c_lifecycle_init(&function.name) {
            steps.push(harness_gen::c_generate::CDriveStep {
                name: function.name.clone(),
                // A pointer-returning pump yields NULL at end-of-stream, so the
                // loop can stop early instead of spinning to the cap.
                breaks_on_null: canonical_c_lifecycle_type(&function.return_type).ends_with(" *"),
            });
        }
    }

    let destroy = destroy?;
    if steps.is_empty() {
        return None;
    }
    steps.sort_by(|a, b| a.name.cmp(&b.name));
    steps.truncate(4);
    Some(harness_gen::c_generate::CDrivePlan {
        steps,
        destroy: Some(destroy),
    })
}

fn c_va_list_variadic_wrapper(
    target: &c_parser::CFunction,
    functions: &[c_parser::CFunction],
) -> Option<c_parser::CFunction> {
    let last = target.params.last()?;
    let last_type = canonical_c_lifecycle_type(&last.c_type);
    if !matches!(last_type.as_str(), "va_list" | "__builtin_va_list") {
        return None;
    }

    let expected_name = if let Some(index) = target.name.rfind("_v") {
        format!("{}_{}", &target.name[..index], &target.name[index + 2..])
    } else {
        target.name.strip_prefix('v')?.to_owned()
    };
    let fixed_params = &target.params[..target.params.len() - 1];
    functions
        .iter()
        .find(|candidate| {
            candidate.name == expected_name
                && candidate.variadic
                && canonical_c_lifecycle_type(&candidate.return_type)
                    == canonical_c_lifecycle_type(&target.return_type)
                && candidate.params.len() == fixed_params.len()
                && candidate
                    .params
                    .iter()
                    .zip(fixed_params)
                    .all(|(left, right)| {
                        canonical_c_lifecycle_type(&left.c_type)
                            == canonical_c_lifecycle_type(&right.c_type)
                    })
        })
        .cloned()
}

/// Find the C function the user asked for, surfacing overload
/// ambiguity. When more than one function in the translation unit
/// shares the requested name (C doesn't technically permit this
/// but `#ifdef` ladders / static helpers in different blocks /
/// merged-file libraries hit it constantly), pick the first by
/// source line AND tell the user about the others. The user can
/// follow up with a different `--id` plus a more specific target
/// if needed; today we don't accept `name@line` syntax so picking
/// silently would hide the others.
/// Pick the C definition to harness. A discovery-provided line wins;
/// a stale line falls back to name matching. Identical-signature
/// duplicates (mutually-exclusive #ifdef ladders) pick the first
/// silently — calling any of them is equivalent at link time. Only
/// genuinely ambiguous (differing-signature) matches produce the
/// returned warning.
fn pick_c_target(
    source_path: &Path,
    functions: Vec<c_parser::CFunction>,
    target_name: &str,
    target_line: Option<u32>,
) -> Result<(c_parser::CFunction, Option<String>)> {
    let mut matches: Vec<c_parser::CFunction> = functions
        .into_iter()
        .filter(|f| f.name == target_name)
        .collect();
    if matches.is_empty() {
        return Err(anyhow::anyhow!(
            "function '{target_name}' not found in {}",
            source_path.display()
        ));
    }
    matches.sort_by_key(|f| f.line);
    if let Some(line) = target_line {
        if let Some(pos) = matches.iter().position(|f| f.line == line) {
            return Ok((matches.swap_remove(pos), None));
        }
    }
    let identical = matches
        .windows(2)
        .all(|w| w[0].return_type == w[1].return_type && w[0].params == w[1].params);
    let warning = (matches.len() > 1 && !identical).then(|| {
        let lines: Vec<String> = matches.iter().map(|f| f.line.to_string()).collect();
        format!(
            "warning: target '{target_name}' matches {} definitions with differing \
             signatures in {} at line(s) {}; picking line {}. Pass --target-line to \
             disambiguate.",
            matches.len(),
            source_path.display(),
            lines.join(", "),
            matches[0].line
        )
    });
    let picked = matches.into_iter().next().expect("at least one match");
    Ok((picked, warning))
}

/// Same as `pick_c_target` for C++ functions. C++ legitimately
/// permits overloading, so a `name` match is even more likely to be
/// ambiguous (and that's what tripped real-world dogfood against a
/// half-extracted XmlReader::parse).
fn pick_cpp_target(
    source_path: &Path,
    functions: Vec<cpp_parser::CppFunction>,
    target_name: &str,
    target_line: Option<u32>,
) -> Result<(cpp_parser::CppFunction, Option<String>)> {
    let mut matches: Vec<cpp_parser::CppFunction> = functions
        .into_iter()
        .filter(|f| cpp_target_matches(f, target_name))
        .collect();
    if matches.is_empty() {
        return Err(anyhow::anyhow!(
            "function '{target_name}' not found in {}",
            source_path.display()
        ));
    }
    matches.sort_by_key(|f| f.line);
    if let Some(line) = target_line {
        if let Some(pos) = matches.iter().position(|f| f.line == line) {
            return Ok((matches.swap_remove(pos), None));
        }
    }
    let identical = matches.windows(2).all(|w| {
        w[0].return_type == w[1].return_type
            && w[0].params == w[1].params
            && w[0].qualifier_path == w[1].qualifier_path
    });
    let warning = (matches.len() > 1 && !identical).then(|| {
        let summaries: Vec<String> = matches
            .iter()
            .map(|f| {
                let params: Vec<String> = f.params.iter().map(|p| p.cpp_type.clone()).collect();
                format!(
                    "line {} {}({})",
                    f.line,
                    cpp_qualified_target_name(f),
                    params.join(", ")
                )
            })
            .collect();
        format!(
            "warning: target '{target_name}' is overloaded in {} ({} candidates: {}); \
             picking the first. Pass --target-line or --id to disambiguate.",
            source_path.display(),
            matches.len(),
            summaries.join("; ")
        )
    });
    let picked = matches.into_iter().next().expect("at least one match");
    Ok((picked, warning))
}

fn cpp_target_matches(function: &cpp_parser::CppFunction, target_name: &str) -> bool {
    if function.name == target_name {
        return true;
    }
    let qualified = cpp_qualified_target_name(function);
    if qualified == target_name {
        return true;
    }
    cpp_signature_target_name(function, &function.name) == target_name
        || cpp_signature_target_name(function, &qualified) == target_name
        || (!function.api.overload_key.is_empty() && function.api.overload_key == target_name)
}

fn cpp_qualified_target_name(function: &cpp_parser::CppFunction) -> String {
    if function.qualifier_path.is_empty() {
        function.name.clone()
    } else {
        format!("{}::{}", function.qualifier_path.join("::"), function.name)
    }
}

fn cpp_signature_target_name(function: &cpp_parser::CppFunction, base: &str) -> String {
    format!(
        "{}({})",
        base,
        function
            .params
            .iter()
            .map(|param| param.cpp_type.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Resolve a possibly-relative path against the current working directory
/// and canonicalize when the path exists. `make` runs from the harness
/// output dir, so anything we bake into the generated Makefile must be
/// absolute. Falls back to a manually-joined absolute path when the
/// canonicalization fails (e.g. for include dirs that haven't been
/// created yet).
fn absolutize(p: &Path) -> std::io::Result<PathBuf> {
    if p.is_absolute() {
        return p.canonicalize().or_else(|_| Ok(p.to_path_buf()));
    }
    let cwd = std::env::current_dir()?;
    let joined = cwd.join(p);
    joined.canonicalize().or(Ok(joined))
}

/// Locate the `c_runtime` directory (holding `govfuzz_decode.h` +
/// `govfuzz_driver.c`). Installed distributions should prefer the runtime staged
/// beside the executable; dev builds fall back to the source tree via
/// `CARGO_MANIFEST_DIR`. Mirrors `rust_build::locate_c_runtime_dir`.
pub(crate) fn locate_c_runtime() -> PathBuf {
    crate::runtime_assets::locate("c_runtime", "govfuzz_decode.h").unwrap_or_else(|| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("c_runtime")
    })
}

/// Pattern-match common library return types to a matching deallocator so
/// the harness doesn't leak the parsed result on every iteration (and
/// doesn't surface spurious LSan findings). Falls back to None when no
/// safe cleanup is known.
/// True when `stripped` is a pointer whose pointee spelling is exactly `base`
/// (e.g. `cJSON *` -> base "cJSON"), so a value typedef like `cJSON_bool` that
/// merely contains the name is not mistaken for an owning handle.
fn return_is_pointer_to(stripped: &str, base: &str) -> bool {
    match stripped.split_once('*') {
        Some((lhs, _)) => lhs.split_whitespace().collect::<Vec<_>>().join(" ") == base,
        None => false,
    }
}

fn auto_detect_c_result_cleanup(return_type: &str, target_name: &str) -> Option<String> {
    // Only free the result of a target that hands the caller a FRESH, owned object.
    // A borrowing accessor that returns a pointer INTO its input graph (cJSON
    // `get_item_from_pointer` / `GetObjectItem`, libxml node getters) returns a
    // NON-owned, often input-aliasing pointer; `cJSON_Delete(R)` on it is an
    // invalid/double free (R may alias a stack-fabricated input object) — a
    // harness-induced ASAN crash, not a target bug.
    if !c_return_is_owned(target_name) {
        return None;
    }
    let normalized = return_type.split_whitespace().collect::<Vec<_>>().join(" ");
    // Strip `CJSON_PUBLIC(...)` / `LIBXML_DLL_IMPORT(...)` / similar macro
    // wrappers so the inner type is visible to the matcher.
    let stripped_macro = match (normalized.find('('), normalized.rfind(')')) {
        (Some(open), Some(close)) if close > open => {
            let inner = &normalized[open + 1..close];
            inner.trim().to_owned()
        }
        _ => normalized,
    };
    let stripped = stripped_macro
        .trim_start_matches("const ")
        .trim()
        .to_owned();
    // Only a pointer-to-cJSON return owns a cJSON object to free. `cJSON_bool`
    // (typedef int) also *contains* "cJSON" but is a value, not a handle —
    // `cJSON_Delete(R)` on it is a type error (cJSON's parse_value/print_value
    // internals return cJSON_bool).
    if return_is_pointer_to(&stripped, "cJSON") {
        return Some("if (R) cJSON_Delete(R)".to_owned());
    }
    if stripped.contains("xmlDocPtr") {
        return Some("if (R) xmlFreeDoc(R)".to_owned());
    }
    if stripped.contains("xmlNodePtr") {
        return Some("if (R) xmlFreeNode(R)".to_owned());
    }
    // parson - JSON_Value is the only allocated handle. parson exposes
    // json_value_free for cleanup.
    if stripped.contains("JSON_Value") {
        return Some("if (R) json_value_free(R)".to_owned());
    }
    // expat parser handles are heap-allocated and must be freed by hand.
    if stripped.contains("XML_Parser") {
        return Some("if (R) XML_ParserFree(R)".to_owned());
    }
    // libpng row buffers, libjpeg structures - skip for now: their free
    // functions take a struct context, not a raw pointer.
    None
}

/// Base type identifier of a C return type, for deallocator pairing:
/// `toml_table_t *` -> `toml_table_t`, `toml_table_t` -> `toml_table_t`,
/// `const struct foo *` -> `foo`, `CJSON_PUBLIC(cJSON *)` -> `cJSON`. The `*` may
/// be absent here because the C parser can attach it to the declarator rather
/// than the return type; the owning-vs-value decision is made by the caller
/// (primitive skip-list + the target being an allocator + a matching `<type>_free`
/// existing), so this only needs the bare type name.
fn c_return_pointee_ident(return_type: &str) -> Option<String> {
    let normalized = return_type.split_whitespace().collect::<Vec<_>>().join(" ");
    // Unwrap a macro export wrapper (`CJSON_PUBLIC(...)`) to the inner type.
    let inner = match (normalized.find('('), normalized.rfind(')')) {
        (Some(o), Some(c)) if c > o => normalized[o + 1..c].trim().to_owned(),
        _ => normalized,
    };
    // Take the text before any `*` (no `*` => the whole type), then the last
    // type token, dropping qualifiers/aggregate keywords.
    let before_star = inner.split('*').next()?.trim();
    let tok = before_star.split_whitespace().rfind(|t| {
        !matches!(
            *t,
            "const" | "struct" | "union" | "enum" | "unsigned" | "signed"
        )
    })?;
    if tok.is_empty() {
        None
    } else {
        Some(tok.to_owned())
    }
}

/// True when a function's RETURN value is a fresh, caller-owned object (so freeing
/// it is correct). Stricter than [`c_name_is_allocator`], which also pairs
/// deallocators for out-params and tolerates `from_`/`open`/`load`: a return
/// deallocator wrongly applied to a borrowing accessor is an INVALID free (the
/// returned pointer aliases the input graph), so this excludes getter-shaped names
/// outright — including `get_item_from_pointer`, where `c_name_is_allocator` is
/// fooled by the `from_` substring — and requires a fresh-allocation verb.
/// True when a name reads like a BORROWING accessor — it returns a pointer INTO an
/// existing graph (cJSON `get_item_from_pointer`, libxml node getters), never a
/// fresh owned object. Freeing such a return is an INVALID/double free, so it is
/// excluded from BOTH the owning-return check and the structural deallocator pairing.
fn c_name_is_borrowing_accessor(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "get", "find", "lookup", "peek", "item", "element", "contains", "has",
    ]
    .iter()
    .any(|v| n.contains(v))
}

fn c_return_is_owned(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    // A borrowing accessor returns a pointer into an existing graph — never owned.
    if c_name_is_borrowing_accessor(name) {
        return false;
    }
    [
        "create",
        "new",
        "alloc",
        "make",
        "build",
        "parse",
        "load",
        "read",
        "dup",
        "duplicate",
        "clone",
        "copy",
        "decode",
        "import",
    ]
    .iter()
    .any(|v| n.contains(v))
}

/// True when a target function name reads like an allocator that hands ownership
/// to the caller (so freeing its result is correct). Guards against pairing a
/// borrowed-pointer getter with a deallocator (which would double/invalid-free).
fn c_name_is_allocator(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        // `read` is an owning-parse verb for the document-reader idiom
        // (yyjson_read -> yyjson_doc*, released by yyjson_doc_free).
        "parse", "new", "create", "alloc", "make", "build", "open", "load", "read", "dup", "clone",
        "decode", "import", "from_",
    ]
    .iter()
    .any(|verb| n.contains(verb))
}

/// General fallback for [`auto_detect_c_result_cleanup`] (the hardcoded list only
/// covers cJSON/libxml/parson/expat): when the target returns an owning pointer
/// and the library follows the conventional `<thing>_free`/`_delete`/`_destroy(
/// <thing> *)` deallocator pattern, emit `if (R) <dealloc>(R)` so the harness
/// releases the parsed result. Without it LeakSanitizer flags the parser's own
/// allocation on EVERY input — a harness artifact reported as a CWE-401 leak in
/// the target (false positive), which also masks genuine internal leaks. Found
/// fuzzing tomlc99: `toml_parse` returns `toml_table_t *` whose paired
/// `toml_free` the harness never called.
///
/// Scans the target translation unit plus sibling `.h` headers for a one-argument
/// function whose name carries a deallocation verb and whose sole parameter is a
/// pointer to the return type. A declaration is enough (header-only libraries
/// work). Conservative: skips primitive/`void`/`char` pointers (not owning
/// handles) and requires the parameter type to match the return type exactly, so
/// a call site (`toml_free(tab)`) is never mistaken for the declaration.
/// Final cleanup fallback (after the library-specific list and the paired
/// `<type>_free` search): the strdup family. A function whose name ends in `dup`
/// (`strdup`, `strndup`, utf8.h's `utf8dup`/`utf8ndup`) returns a FRESH buffer
/// the standard library releases with plain `free()` — there is no `<type>_free`
/// for the paired search to find, so the result was dropped and LeakSanitizer
/// flagged the library's own `malloc` on every input: a CWE-401 leak FALSE
/// POSITIVE. Emit `if (R) free((void *)R)` (the `void *` cast keeps a
/// `const`-qualified return legal in the C++ lane). Gated to names ending in
/// `dup` so a `*_dup` returning a complex handle (cJSON_Duplicate — already
/// handled by the paired-deallocator search above) and non-allocating returns
/// are untouched. Known custom-allocator families use their public deallocator
/// instead of the host libc's `free()`.
fn detect_strdup_family_free(return_type: &str, target_name: &str) -> Option<String> {
    let normalized_name = target_name.to_ascii_lowercase();
    if !normalized_name.ends_with("dup") {
        return None;
    }
    if !return_type.trim_end().ends_with('*') {
        return None;
    }
    // mimalloc's strdup family allocates from mimalloc (and the `mi_heap_*`
    // variants may use an explicit non-default heap). Passing that pointer to
    // the host libc's `free` aborts; the public cross-heap release API is
    // `mi_free`.
    if matches!(
        normalized_name.as_str(),
        "mi_strdup" | "mi_strndup" | "mi_heap_strdup" | "mi_heap_strndup"
    ) {
        return Some("if (R) mi_free((void *)R)".to_owned());
    }
    Some("if (R) free((void *)R)".to_owned())
}

fn detect_paired_deallocator(
    return_type: &str,
    target_name: &str,
    param_types: &[String],
    target_dir: &Path,
    source_path: &Path,
) -> Option<String> {
    let ret_ident = c_return_pointee_ident(return_type)?;
    // #18: a target that also CONSUMES a handle of the returned type may return one
    // of its inputs (a self-returning builder / borrowed transform — mpc_define),
    // so freeing the result would double-free. Such a target is paired ONLY when its
    // name carries an explicit allocator verb; verb-less ownership inference is
    // suppressed for it.
    let consumes_return_type = param_types
        .iter()
        .any(|t| c_return_pointee_ident(t).as_deref() == Some(ret_ident.as_str()));
    find_paired_deallocator_name(
        &ret_ident,
        target_name,
        consumes_return_type,
        target_dir,
        source_path,
    )
    .map(|(nm, double_ptr)| {
        // A refcount/double-pointer releaser (`cbor_decref(cbor_item_t **)`)
        // takes the address of the owning pointer.
        if double_ptr {
            format!("if (R) {nm}(&R)")
        } else {
            format!("if (R) {nm}(R)")
        }
    })
}

/// Core of [`detect_paired_deallocator`]: find the NAME of a public deallocator
/// for `pointee_ident` (`toml_table` -> `toml_free`) that shares the target's
/// library prefix. Returns the bare function name so callers can wrap it for a
/// return value (`if (R) free(R)`) or free an out-handle parameter (GAP-L: the
/// `T **out` of a `parse(data, size, T **out)` entry). Conservative: only for
/// allocator-like targets, never for primitive / `void` / `char` pointees.
fn find_paired_deallocator_name(
    pointee_ident: &str,
    target_name: &str,
    consumes_return_type: bool,
    target_dir: &Path,
    source_path: &Path,
) -> Option<(String, bool)> {
    // A getter returning a borrowed pointer must never be freed (invalid/double free).
    if c_name_is_borrowing_accessor(target_name) {
        return None;
    }
    // #18: an explicit allocator verb is a direct ownership signal. A verb-LESS name
    // (mpc combinators mpc_or/mpc_and) is owned ONLY by structural proof — the
    // prefix-matched, return-type-specific deallocator found below (mpc_delete). But
    // if the target also consumes a handle of the returned type it may return one of
    // its inputs, so verb-less inference is suppressed there to avoid a double-free.
    if !c_name_is_allocator(target_name) && consumes_return_type {
        return None;
    }
    // Primitive / non-handle pointee types never have a `<type>_free`.
    if matches!(
        pointee_ident,
        "char" | "void" | "int" | "long" | "short" | "float" | "double" | "FILE"
    ) || pointee_ident.starts_with("uint")
        || pointee_ident.starts_with("int")
    {
        return None;
    }
    // Verbs include refcount releasers (decref/deref/unref): libcbor's owning
    // returns are released by `cbor_decref(cbor_item_t **)`. Capture group 2 is
    // the pointer stars so a `T **` deallocator is called as `dealloc(&R)`.
    let pattern = format!(
        r"(?m)\b([A-Za-z_]\w*(?:[Ff]ree|[Dd]elete|[Dd]estroy|[Rr]elease|[Dd]ispose|[Uu]nref|[Dd]ecref|[Dd]eref)\w*)\s*\(\s*(?:const\s+)?(?:struct\s+)?{}\b\s*(\*\s*\*?)[^,;()]*\)",
        regex::escape(pointee_ident)
    );
    let re = regex::Regex::new(&pattern).ok()?;
    // The harness can only call a PUBLIC deallocator, so prefer header
    // declarations (the public API) over the `.c` — tomlc99 defines an internal
    // `static void xfree_tab(toml_table_t *)` that the regex also matches but
    // which the harness can't link. Headers first, then the source as fallback
    // for header-less single-file libraries.
    let mut texts: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(target_dir) {
        let mut headers: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("h")))
            .collect();
        headers.sort();
        for p in headers {
            if let Ok(t) = crate::source_text::read_source_text(&p) {
                texts.push(t);
            }
        }
    }
    if let Ok(t) = crate::source_text::read_source_text(source_path) {
        texts.push(t);
    }
    // Require the deallocator to share the target's library prefix (`toml_parse`
    // -> `toml_free`, both `toml`), which rejects unrelated/internal helpers
    // (`xfree_tab`) that merely match the verb+type shape.
    let prefix = target_name
        .split('_')
        .next()
        .filter(|p| !p.is_empty())
        .unwrap_or(target_name);
    for text in &texts {
        for c in re.captures_iter(text) {
            if let Some(name) = c.get(1) {
                let nm = name.as_str();
                if nm != target_name && nm.starts_with(prefix) {
                    let double_ptr = c
                        .get(2)
                        .is_some_and(|s| s.as_str().matches('*').count() >= 2);
                    return Some((nm.to_owned(), double_ptr));
                }
            }
        }
    }
    None
}

/// GAP-L: for a parser entry `parse(.., T **out)` whose element type `T` has a
/// discoverable public deallocator, express that deallocator as a delete-only
/// lifecycle entry for `T`. The harness's out-handle scratch
/// (`out_param_handle_scratch`) then frees the heap-allocated result after the
/// call — otherwise the canonical out-handle parser shape leaks the result on
/// EVERY valid input (a successful parse), a CWE-401 false positive that is the
/// out-param analog of an unfreed return value. `handle_type` strips one pointer
/// level to match the harness's own `inner_base`, while the deallocator search
/// uses the bare pointee ident (so `struct foo **` finds `foo_free`).
fn detect_out_handle_lifecycle(
    function: &c_parser::CFunction,
    target_dir: &Path,
    source_path: &Path,
) -> Option<harness_gen::c_generate::CHandleLifecycle> {
    for p in &function.params {
        let t = p.c_type.trim();
        // An OUTPUT handle is writable: a const pointee is an input, never an
        // owning result the harness should free.
        if t.split_whitespace().any(|w| w == "const") {
            continue;
        }
        // Pointer-to-pointer: strip one `*`; the remainder must still be a
        // pointer (`T **`, not `T *`).
        let Some(inner) = t.strip_suffix('*') else {
            continue;
        };
        let inner = inner.trim();
        if !inner.ends_with('*') {
            continue;
        }
        let handle_type = inner.trim_end_matches('*').trim();
        if handle_type.is_empty() {
            continue;
        }
        let Some(pointee_ident) = c_return_pointee_ident(inner) else {
            continue;
        };
        // This path frees the OUT-HANDLE produced through a `T **out` param, not the
        // actual return value; the self-returning-builder guard (#18) does not apply,
        // so `consumes_return_type = false`.
        if let Some((dealloc, double_ptr)) = find_paired_deallocator_name(
            &pointee_ident,
            &function.name,
            false,
            target_dir,
            source_path,
        ) {
            // The out-handle delete scratch frees the produced handle directly
            // (`delete(handle)`); a double-pointer refcount releaser would need
            // `&handle` and is not modeled on this path — skip it rather than
            // emit a wrong call.
            if double_ptr {
                continue;
            }
            return Some(harness_gen::c_generate::CHandleLifecycle {
                handle_type: handle_type.to_owned(),
                init: None,
                delete: Some(dealloc),
                init_returns_handle: false,
                init_args: Vec::new(),
            });
        }
    }
    None
}

/// Scan a header for top-level `namespace X { ... }` blocks so the C++
/// harness can emit `using namespace X;` and let unqualified class names
/// from the header resolve. Best-effort regex; nested namespaces and
/// `namespace X::Y { }` are not handled — they're rare enough in real
/// codebases that the cost/benefit isn't worth it yet.
/// Map `<X>_NAMESPACE_BEGIN` / `<X>_NS_BEGIN` macros to the PLAIN namespace(s) their
/// body opens. Such macros open a real top-level namespace, but (1) the per-line
/// namespace scan skips `#define` bodies and (2) the def often lives in a different
/// header than the invocation (nlohmann's `NLOHMANN_JSON_NAMESPACE_BEGIN` is defined
/// in `abi_macros.hpp` and invoked everywhere). So gather them across the whole
/// include set up front. Only plain `namespace <ident>` is taken — an
/// `inline namespace MACRO(...)` (nlohmann's ABI-version tag) is skipped (its members
/// are reachable through the enclosing namespace anyway).
fn cpp_namespace_begin_macros(texts: &[String]) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut out: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for text in texts {
        let mut lines = text.lines();
        while let Some(line) = lines.next() {
            let Some(after_hash) = line.trim_start().strip_prefix('#') else {
                continue;
            };
            let after_hash = after_hash.trim_start();
            let Some(rest) = after_hash.strip_prefix("define") else {
                continue;
            };
            if !rest.chars().next().is_some_and(char::is_whitespace) {
                continue;
            }
            let rest = rest.trim_start();
            let macro_name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !(macro_name.ends_with("_NAMESPACE_BEGIN")
                || macro_name.ends_with("_BEGIN_NAMESPACE")
                || macro_name.ends_with("_NS_BEGIN"))
            {
                continue;
            }
            // Accumulate the macro body across `\`-continuation lines.
            let mut body = rest[macro_name.len()..].to_owned();
            let mut more = line.trim_end().ends_with('\\');
            while more {
                let Some(next) = lines.next() else { break };
                body.push('\n');
                body.push_str(next);
                more = next.trim_end().ends_with('\\');
            }
            let mut namespaces = Vec::new();
            let mut from = 0;
            while let Some(pos) = body[from..].find("namespace ") {
                let name_at = from + pos + "namespace ".len();
                let name: String = body[name_at..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                from = name_at + name.len().max(1);
                // Skip `inline namespace MACRO(...)` (name immediately followed by `(`).
                let after = body[name_at + name.len()..].trim_start();
                if !name.is_empty() && !after.starts_with('(') && !namespaces.contains(&name) {
                    namespaces.push(name);
                }
            }
            if !namespaces.is_empty() {
                out.insert(macro_name, namespaces);
            }
        }
    }
    out
}

/// Namespaces to bring in with `using namespace` so the harness's unqualified
/// references resolve. Macro-opened TOP-LEVEL namespaces (e.g. nlohmann's
/// `NLOHMANN_JSON_NAMESPACE_BEGIN` -> `nlohmann`) come FIRST so the nested ones
/// (`detail`, `literals`) resolve transitively — `using namespace nlohmann;` makes
/// `nlohmann::detail` visible as `detail`, so the later `using namespace detail;`
/// is valid. Then the literal `namespace X {` names the per-line scan finds.
fn collect_cpp_using_namespaces(
    texts: &[String],
    begin_macros: &std::collections::BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    // Pass 1: macro-opened top-level namespaces, in invocation order.
    for text in texts {
        let mut in_macro = false;
        for line in text.lines() {
            let trimmed = line.trim_start();
            let line_in_macro = in_macro || trimmed.starts_with('#');
            in_macro = line_in_macro && line.trim_end().ends_with('\\');
            if line_in_macro {
                continue;
            }
            let invoked: String = trimmed
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if let Some(namespaces) = begin_macros.get(&invoked) {
                for ns in namespaces {
                    if !found.contains(ns) {
                        found.push(ns.clone());
                    }
                }
            }
        }
    }
    // Pass 2: literal `namespace X {` (appended after the top-level macro ones).
    for text in texts {
        for ns in detect_top_level_namespaces_in_text(text) {
            if !found.contains(&ns) {
                found.push(ns);
            }
        }
    }
    found
}

fn detect_top_level_namespaces_in_text(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    // Track `#define` line-continuation so a `namespace X {` written inside a
    // multi-line macro body (harfbuzz's HB_* table macros) is not mistaken for a
    // real top-level namespace.
    let mut in_macro = false;
    // Only collect namespaces opened at literal brace depth 0. A `using namespace`
    // at the harness's global scope can name a TOP-LEVEL namespace (`nlohmann`,
    // `tinyxml2`, `pugi`) but NOT one nested inside another (nlohmann buries
    // `utility_internal`/`dtoa_impl`/`container_input_adapter_factory_impl` inside
    // `detail`). Emitting `using namespace utility_internal;` at file scope is
    // "expected namespace name". Depth is literal `{`/`}` only: macro-opened
    // namespaces (`NLOHMANN_JSON_NAMESPACE_BEGIN`) leave no brace, so `detail` reads
    // as depth 0 here and resolves transitively after `using namespace nlohmann;`,
    // while the genuinely-nested impl namespaces read as depth >=1 and are dropped.
    let mut depth: i32 = 0;
    let mut in_block_comment = false;
    for line in text.lines() {
        let trimmed = line.trim_start();
        let line_in_macro = in_macro || trimmed.starts_with('#');
        in_macro = line_in_macro && line.trim_end().ends_with('\\');
        if line_in_macro {
            // Preprocessor / macro-body lines: never a real top-level namespace, and
            // their braces (single-line `#define X { ... }`) must not skew depth.
            continue;
        }
        if depth == 0 && !in_block_comment {
            if let Some(rest) = trimmed.strip_prefix("namespace ") {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                // Skip namespace ALIASES (`namespace std_fs = std::filesystem;`): an
                // alias is not a namespace you can `using namespace` at global scope.
                let after = rest[name.len()..].trim_start();
                let is_alias = after.starts_with('=');
                if !name.is_empty() && !is_alias && !found.contains(&name) {
                    found.push(name);
                }
            }
        }
        depth = (depth + net_brace_delta(line, &mut in_block_comment)).max(0);
    }
    found
}

/// Net `{` minus `}` on a line of C++ source, ignoring braces inside `//` and
/// `/* */` comments and `"…"` / `'…'` literals. `in_block_comment` carries the
/// `/* */` state across lines. Approximate (no raw-string handling), but enough to
/// keep namespace-nesting depth honest for header scanning.
fn net_brace_delta(line: &str, in_block_comment: &mut bool) -> i32 {
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut delta = 0i32;
    let mut in_string = false;
    let mut in_char = false;
    while i < bytes.len() {
        let c = bytes[i];
        if *in_block_comment {
            if c == b'*' && bytes.get(i + 1) == Some(&b'/') {
                *in_block_comment = false;
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if in_string {
            match c {
                b'\\' => i += 2,
                b'"' => {
                    in_string = false;
                    i += 1;
                }
                _ => i += 1,
            }
            continue;
        }
        if in_char {
            match c {
                b'\\' => i += 2,
                b'\'' => {
                    in_char = false;
                    i += 1;
                }
                _ => i += 1,
            }
            continue;
        }
        match c {
            b'/' if bytes.get(i + 1) == Some(&b'/') => break,
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                *in_block_comment = true;
                i += 2;
                continue;
            }
            b'"' => in_string = true,
            b'\'' => in_char = true,
            b'{' => delta += 1,
            b'}' => delta -= 1,
            _ => {}
        }
        i += 1;
    }
    delta
}

/// Walk upward from the source dir looking for sibling `include/` or `inc/`
/// directories that hold the project's public headers. Real C libraries
/// (libxml2, mbedtls, openssl, libpng, libsodium, expat, ...) store
/// headers in a separate directory from their .c sources; adding that
/// directory to the harness include path lets the auto-included sibling
/// header resolve project-side typedefs without the caller having to pass
/// `--extra-include` by hand. Caps the walk at 3 levels to avoid
/// accidentally adding `/usr/include`.
/// Include roots for SELF-PREFIXED includes: a source at `.../X/file.cc` that does
/// `#include "X/other.h"` needs the dir CONTAINING `X` on the include path, not
/// just its own dir. Common in single-tree libraries — libde265's
/// `libde265/de265.cc` does `#include "libde265/vps.h"`, which only resolves with
/// `-I .../src/libde265` (the parent of the `libde265/` dir). Without it the build
/// fails "file not found" before the AddSource link-closure can even begin.
///
/// Scans the source's quoted includes; for each first path component that names an
/// ancestor directory of the source, adds that ancestor's PARENT so the prefixed
/// path resolves. Bounded ancestor walk; only adds a dir whose child matches.
fn self_prefixed_include_roots(source: &Path) -> Vec<PathBuf> {
    // Scan the target source AND its sibling project headers: the self-prefixed
    // include often lives in a transitively-included header, not the `.cc` itself
    // (libde265's `de265.cc` includes `"decctx.h"`, and `decctx.h` is what does
    // `#include "libde265/vps.h"`).
    let mut texts: Vec<String> = Vec::new();
    if let Ok(t) = std::fs::read_to_string(source) {
        texts.push(t);
    }
    if let Some(dir) = source.parent() {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for entry in rd.flatten().take(1000) {
                let p = entry.path();
                let is_header = p
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| matches!(e, "h" | "hpp" | "hh" | "hxx" | "H"));
                if is_header {
                    if let Ok(t) = std::fs::read_to_string(&p) {
                        texts.push(t);
                    }
                }
            }
        }
    }
    let mut prefixes: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for text in &texts {
        for line in text.lines() {
            let l = line.trim_start();
            let Some(rest) = l.strip_prefix('#') else {
                continue;
            };
            let Some(rest) = rest.trim_start().strip_prefix("include") else {
                continue;
            };
            let Some(rest) = rest.trim_start().strip_prefix('"') else {
                continue; // angle-bracket includes resolve via -I, not this heuristic
            };
            let Some(end) = rest.find('"') else {
                continue;
            };
            if let Some((comp, _)) = rest[..end].split_once('/') {
                if !comp.is_empty() && comp != "." && comp != ".." {
                    prefixes.insert(comp.to_owned());
                }
            }
        }
    }
    if prefixes.is_empty() {
        return Vec::new();
    }
    let mut roots = Vec::new();
    let mut cursor = source.parent();
    let mut steps = 0;
    while let Some(dir) = cursor {
        if steps >= 6 {
            break;
        }
        if let Some(name) = dir.file_name().and_then(|n| n.to_str()) {
            if prefixes.contains(name) {
                if let Some(parent) = dir.parent() {
                    let p = parent.to_path_buf();
                    if !roots.contains(&p) {
                        roots.push(p);
                    }
                }
            }
        }
        cursor = dir.parent();
        steps += 1;
    }
    roots
}

fn auto_detect_project_includes(source: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let mut cursor = source.parent().map(Path::to_path_buf);
    let mut steps = 0;
    while let Some(dir) = cursor {
        for candidate in ["include", "inc"] {
            let p = dir.join(candidate);
            if p.is_dir() && !dirs.contains(&p) {
                dirs.push(p);
            }
        }
        steps += 1;
        if steps >= 3 {
            break;
        }
        cursor = dir.parent().map(Path::to_path_buf);
    }
    dirs
}

#[derive(Debug, serde::Deserialize)]
struct CompileCommandEntry {
    directory: PathBuf,
    file: PathBuf,
    #[serde(default)]
    arguments: Option<Vec<String>>,
    #[serde(default)]
    command: Option<String>,
}

pub(crate) fn compile_database_flags_for_source(source_path: &Path) -> Vec<String> {
    match try_compile_database_flags_for_source(source_path) {
        Ok(flags) => flags,
        Err(error) => {
            eprintln!(
                "warning: skipped compile_commands.json flags for {}: {error:#}",
                source_path.display()
            );
            Vec::new()
        }
    }
}

/// Recover C compile flags from the strongest available project evidence.
/// A checked-in/probe compile database remains authoritative. Without one, only
/// portable standard-header capability macros are safe to infer from CMake;
/// optional project features remain diagnostic-driven repairs.
fn c_build_flags_for_source(source_path: &Path) -> Vec<String> {
    let mut flags = compile_database_flags_for_source(source_path);
    if !flags.is_empty() {
        flags.push(format!(
            "{BUILD_CONTEXT_PROVENANCE_PREFIX}{}",
            if is_c_family_header(source_path) {
                "associated_header_compile_database"
            } else {
                "exact_tu_compile_database"
            }
        ));
        return flags;
    }
    if let Some(cmake) = find_upward_build_file(source_path, &["CMakeLists.txt"]) {
        let mut flags = infer_cmake_c_build_context(source_path, &cmake).compile_flags;
        flags.retain(|flag| {
            matches!(
                flag.as_str(),
                "-DHAVE_STDBOOL_H"
                    | "-DHAVE__BOOL"
                    | "-DHAVE_STDINT_H"
                    | "-DHAVE_INTTYPES_H"
                    | "-DHAVE_STRUCT_TIMEVAL"
                    | "-DHAVE_STRUCT_SOCKADDR_IN6"
                    | "-DHAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID"
            )
        });
        for flag in cmake_checked_host_capability_flags(source_path) {
            push_unique_string(&mut flags, flag);
        }
        for flag in cmake_config_template_host_capability_flags(source_path) {
            push_unique_string(&mut flags, flag);
        }
        flags.push(format!("{BUILD_CONTEXT_PROVENANCE_PREFIX}cmake"));
        return flags;
    }
    vec![format!("{BUILD_CONTEXT_PROVENANCE_PREFIX}none")]
}

/// Materialize a small set of native host capabilities that an ancestor CMake
/// file explicitly probes for a generated config header. This is not general
/// feature inference: each emitted macro describes a standard header, socket
/// constant, or POSIX ABI type, and only appears when the project itself names
/// the corresponding check. Nested component CMakeLists are scanned together
/// with the project root because configure checks commonly live only at the root
/// (c-ares).
fn cmake_checked_host_capability_flags(source_path: &Path) -> Vec<String> {
    let mut flags = Vec::new();
    let mut cursor = source_path.parent();
    for _ in 0..6 {
        let Some(dir) = cursor else {
            break;
        };
        let cmake = dir.join("CMakeLists.txt");
        if cmake.is_file() {
            let Ok(source) = crate::source_text::read_source_text(&cmake) else {
                cursor = dir.parent();
                continue;
            };
            let lower = source.to_ascii_lowercase();
            let mut checked = |macro_name: &str, evidence: &str, supported: bool| {
                if supported && source.contains(macro_name) && lower.contains(evidence) {
                    push_unique_string(&mut flags, format!("-D{macro_name}"));
                }
            };
            checked("HAVE_STDINT_H", "stdint.h", true);
            checked("HAVE_INTTYPES_H", "inttypes.h", true);
            checked("HAVE_STDBOOL_H", "stdbool.h", true);
            for (macro_name, header) in [
                ("HAVE_ARPA_INET_H", "arpa/inet.h"),
                ("HAVE_ASSERT_H", "assert.h"),
                ("HAVE_ERRNO_H", "errno.h"),
                ("HAVE_FCNTL_H", "fcntl.h"),
                ("HAVE_IFADDRS_H", "ifaddrs.h"),
                ("HAVE_NETDB_H", "netdb.h"),
                ("HAVE_NET_IF_H", "net/if.h"),
                ("HAVE_NETINET_IN_H", "netinet/in.h"),
                ("HAVE_NETINET_TCP_H", "netinet/tcp.h"),
                ("HAVE_POLL_H", "poll.h"),
                ("HAVE_SIGNAL_H", "signal.h"),
                ("HAVE_LIMITS_H", "limits.h"),
                ("HAVE_MEMORY_H", "memory.h"),
                ("HAVE_STDLIB_H", "stdlib.h"),
                ("HAVE_STRING_H", "string.h"),
                ("HAVE_STRINGS_H", "strings.h"),
                ("HAVE_SYS_IOCTL_H", "sys/ioctl.h"),
                ("HAVE_SYS_SELECT_H", "sys/select.h"),
                ("HAVE_SYS_SOCKET_H", "sys/socket.h"),
                ("HAVE_SYS_STAT_H", "sys/stat.h"),
                ("HAVE_SYS_TIME_H", "sys/time.h"),
                ("HAVE_SYS_TYPES_H", "sys/types.h"),
                ("HAVE_SYS_UIO_H", "sys/uio.h"),
                ("HAVE_TIME_H", "time.h"),
                ("HAVE_UNISTD_H", "unistd.h"),
            ] {
                checked(macro_name, header, cfg!(unix));
            }
            checked(
                "HAVE_SYS_RANDOM_H",
                "sys/random.h",
                cfg!(target_os = "linux"),
            );
            checked("HAVE_AF_INET6", "check_symbol_exists (af_inet6", cfg!(unix));
            checked("HAVE_PF_INET6", "check_symbol_exists (pf_inet6", cfg!(unix));
            checked(
                "HAVE_GETTIMEOFDAY",
                "check_symbol_exists (gettimeofday",
                cfg!(unix),
            );
            checked("HAVE_SOCKLEN_T", "socklen_t", cfg!(unix));
            checked("HAVE_SSIZE_T", "ssize_t", cfg!(unix));
            checked("HAVE_STRUCT_ADDRINFO", "struct addrinfo", cfg!(unix));
            checked("HAVE_STRUCT_IN6_ADDR", "struct in6_addr", cfg!(unix));
            checked("HAVE_STRUCT_TIMEVAL", "struct timeval", cfg!(unix));
            checked(
                "HAVE_STRUCT_SOCKADDR_IN6",
                "struct sockaddr_in6",
                cfg!(unix),
            );
            checked(
                "HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID",
                "sin6_scope_id",
                cfg!(unix),
            );
            checked(
                "HAVE_STRUCT_SOCKADDR_STORAGE",
                "struct sockaddr_storage",
                cfg!(unix),
            );
        }
        cursor = dir.parent();
    }
    flags
}

/// Recover host-safe capability names from generated CMake config-header
/// templates. Projects commonly prefix these (`EVENT__HAVE_GETTIMEOFDAY`) even
/// though the underlying check is the same POSIX capability. Only capabilities
/// guaranteed by the current host family are materialized; optional library or
/// product features remain unset.
fn cmake_config_template_host_capability_flags(source_path: &Path) -> Vec<String> {
    let unix_capabilities = [
        "HAVE_ARC4RANDOM",
        "HAVE_ARC4RANDOM_BUF",
        "HAVE_ARPA_INET_H",
        "HAVE_ASSERT_H",
        "HAVE_ERRNO_H",
        "HAVE_FCNTL_H",
        "HAVE_IFADDRS_H",
        "HAVE_LIMITS_H",
        "HAVE_MEMORY_H",
        "HAVE_NETDB_H",
        "HAVE_NET_IF_H",
        "HAVE_NETINET_IN_H",
        "HAVE_NETINET_TCP_H",
        "HAVE_POLL_H",
        "HAVE_SIGNAL_H",
        "HAVE_SIGACTION",
        "HAVE_STDARG_H",
        "HAVE_STDDEF_H",
        "HAVE_STDLIB_H",
        "HAVE_STRING_H",
        "HAVE_STRINGS_H",
        "HAVE_SYS_IOCTL_H",
        "HAVE_SYS_SELECT_H",
        "HAVE_SYS_SIGNALFD_H",
        "HAVE_SYS_SOCKET_H",
        "HAVE_SYS_STAT_H",
        "HAVE_SYS_TIME_H",
        "HAVE_SYS_TYPES_H",
        "HAVE_SYS_UIO_H",
        "HAVE_SYS_UN_H",
        "HAVE_TIME_H",
        "HAVE_UNISTD_H",
        "HAVE_GETIFADDRS",
        "HAVE_GETTIMEOFDAY",
        "HAVE_NANOSLEEP",
        "HAVE_USLEEP",
        "HAVE_SA_FAMILY_T",
        "HAVE_SOCKLEN_T",
        "HAVE_SSIZE_T",
        "HAVE_STRNDUP",
        "HAVE_STRSEP",
        "HAVE_STRTOK_R",
        "HAVE_STRTOLL",
        "HAVE_STRUCT_ADDRINFO",
        "HAVE_STRUCT_IN6_ADDR",
        "HAVE_STRUCT_LINGER",
        "HAVE_STRUCT_SOCKADDR_IN6",
        "HAVE_STRUCT_SOCKADDR_STORAGE",
        "HAVE_STRUCT_SOCKADDR_STORAGE_SS_FAMILY",
        "HAVE_STRUCT_SOCKADDR_UN",
    ];
    let portable_capabilities = [
        "HAVE_INTTYPES_H",
        "HAVE_STDBOOL_H",
        "HAVE_STDINT_H",
        "HAVE_UINT8_T",
        "HAVE_UINT16_T",
        "HAVE_UINT32_T",
        "HAVE_UINT64_T",
        "HAVE_UINTPTR_T",
    ];
    let host_size_capabilities = [
        ("SIZEOF_SIZE_T", std::mem::size_of::<usize>()),
        ("SIZEOF_VOID_P", std::mem::size_of::<*const ()>()),
    ];
    let mut flags = Vec::new();
    let mut cursor = source_path.parent();
    for _ in 0..6 {
        let Some(dir) = cursor else {
            break;
        };
        if dir.join("CMakeLists.txt").is_file() {
            let Ok(entries) = std::fs::read_dir(dir) else {
                cursor = dir.parent();
                continue;
            };
            for entry in entries.flatten().take(128) {
                let path = entry.path();
                let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if !(name.ends_with(".h.cmake") || name.ends_with(".h.in")) {
                    continue;
                }
                let Ok(template) = crate::source_text::read_source_text(&path) else {
                    continue;
                };
                for line in template
                    .lines()
                    .filter(|line| line.contains("cmakedefine") || line.contains("#undef"))
                {
                    for token in line.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_') {
                        let supported = portable_capabilities
                            .iter()
                            .any(|capability| token.ends_with(capability))
                            || (cfg!(unix)
                                && unix_capabilities
                                    .iter()
                                    .any(|capability| token.ends_with(capability)));
                        if supported {
                            push_unique_string(&mut flags, format!("-D{token}"));
                        }
                    }
                }
                for line in template
                    .lines()
                    .filter(|line| line.trim_start().starts_with("#define"))
                {
                    for token in line.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_') {
                        if let Some((_, size)) = host_size_capabilities
                            .iter()
                            .find(|(capability, _)| token.ends_with(capability))
                        {
                            push_unique_string(&mut flags, format!("-D{token}={size}"));
                        }
                    }
                }
            }
        }
        cursor = dir.parent();
    }
    flags
}

fn try_compile_database_flags_for_source(source_path: &Path) -> Result<Vec<String>> {
    for db_path in compile_database_candidates(source_path) {
        if !db_path.is_file() {
            continue;
        }
        let bytes = fs::read(&db_path)
            .with_context(|| format!("read compile database {}", db_path.display()))?;
        let entries: Vec<CompileCommandEntry> = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse compile database {}", db_path.display()))?;
        for entry in &entries {
            if compile_command_matches_source(entry, source_path) {
                return Ok(extract_compile_database_flags(entry, source_path));
            }
        }
        if is_c_family_header(source_path) {
            if let Some(entry) = compile_database_entry_for_header(&entries, source_path) {
                let owner = compile_command_source_path(entry);
                return Ok(extract_compile_database_flags(entry, &owner));
            }
        }
    }
    Ok(Vec::new())
}

#[derive(Debug, Clone)]
struct PerTuCompileContext {
    source: PathBuf,
    compiler: Option<String>,
    flags: Vec<String>,
}

/// Remove sources with authoritative compile-database rows from the shared
/// single-command source list. They are compiled separately with their own
/// flags and linked as objects, avoiding an impossible union of mutually
/// exclusive per-file defines/standards. Sources without exact rows stay on the
/// established confidence-labelled fallback path.
fn partition_per_tu_compile_contexts(
    target_sources: &mut Vec<PathBuf>,
) -> Vec<PerTuCompileContext> {
    let mut contexts = Vec::new();
    target_sources.retain(|source| {
        let Ok(mut flags) = try_compile_database_flags_for_source(source) else {
            return true;
        };
        if flags.is_empty() {
            return true;
        }
        let compiler = flags
            .iter()
            .find_map(|flag| flag.strip_prefix(BUILD_CONTEXT_COMPILER_PREFIX))
            .map(str::to_owned);
        flags.retain(|flag| !flag.starts_with('@'));
        contexts.push(PerTuCompileContext {
            source: source.clone(),
            compiler,
            flags,
        });
        false
    });
    contexts
}

fn discard_cpp_context_for_included_target(
    contexts: &mut Vec<PerTuCompileContext>,
    main_cpp: &Path,
    target_source: &Path,
) -> Result<()> {
    if contexts.is_empty() || !is_cpp_only_translation_unit(target_source) {
        return Ok(());
    }
    let Some(file_name) = target_source.file_name().and_then(|name| name.to_str()) else {
        return Ok(());
    };
    let source = fs::read_to_string(main_cpp)
        .with_context(|| format!("read generated C++ harness {}", main_cpp.display()))?;
    let include = format!("#include \"{file_name}\"");
    if source.lines().any(|line| line.trim() == include) {
        let target_key = normalized_path_key(target_source);
        contexts.retain(|context| normalized_path_key(&context.source) != target_key);
    }
    Ok(())
}

fn write_cpp_per_tu_context(output_dir: &Path, contexts: &[PerTuCompileContext]) -> Result<()> {
    if contexts.is_empty() {
        remove_stale_per_tu_context(output_dir, "build_context_objects.mk")?;
        return Ok(());
    }
    write_per_tu_context(
        output_dir,
        "build_context_objects.mk",
        "CONTEXT",
        "context_objs",
        contexts,
        &[
            ("MAIN", "$(CXX)", "$(CXXFLAGS)", true),
            ("AFL", "$(AFLPP_CXX)", "$(AFLPP_CXXFLAGS)", false),
            ("DIFF", "$(DIFF_CXX)", "$(DIFF_CXXFLAGS)", true),
        ],
        true,
    )
}

fn write_c_per_tu_context(output_dir: &Path, contexts: &[PerTuCompileContext]) -> Result<()> {
    if contexts.is_empty() {
        remove_stale_per_tu_context(output_dir, "build_context_objects.mk")?;
        return Ok(());
    }
    write_per_tu_context(
        output_dir,
        "build_context_objects.mk",
        "CONTEXT",
        "context_objs",
        contexts,
        &[
            ("MAIN", "$(CC)", "$(CFLAGS)", true),
            ("AFL", "$(AFLPP_CC)", "$(AFLPP_CFLAGS)", false),
            ("MSAN", "$(MSAN_CC)", "$(MSAN_CFLAGS)", true),
            ("TSAN", "$(TSAN_CC)", "$(TSAN_CFLAGS)", true),
            ("COV", "$(COV_CC)", "$(COV_CFLAGS)", true),
            ("DIFF", "$(DIFF_CC)", "$(DIFF_CFLAGS)", true),
            ("PROV", "$(CC)", "$(CFLAGS)", true),
        ],
        false,
    )
}

fn remove_stale_per_tu_context(output_dir: &Path, fragment_name: &str) -> Result<()> {
    let fragment = output_dir.join(fragment_name);
    match fs::remove_file(&fragment) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("remove stale per-TU context {}", fragment.display())),
    }
}

fn write_per_tu_context(
    output_dir: &Path,
    fragment_name: &str,
    variable_prefix: &str,
    object_dir: &str,
    contexts: &[PerTuCompileContext],
    variants: &[(&str, &str, &str, bool)],
    cpp: bool,
) -> Result<()> {
    for context in contexts {
        harness_gen::build_safety::ensure_build_input_safe(
            "per-TU source path",
            &context.source.to_string_lossy(),
        )?;
        if let Some(compiler) = &context.compiler {
            harness_gen::build_safety::ensure_build_input_safe("per-TU compiler", compiler)?;
        }
        harness_gen::build_safety::ensure_all_build_inputs_safe(
            "per-TU compile flag",
            context.flags.iter().map(String::as_str),
        )?;
    }

    let mut fragment = String::from(
        "# Generated from exact compile_commands.json rows; do not edit.\n\
         BUILD_CONTEXT_TU_MODE = per_translation_unit_compile_database\n\
         .PHONY: FORCE_CONTEXT_OBJECTS\n\
         FORCE_CONTEXT_OBJECTS:\n",
    );
    for (variant, _, _, _) in variants {
        let objects = (0..contexts.len())
            .map(|index| format!("{object_dir}/{}_{}.o", variant.to_ascii_lowercase(), index))
            .collect::<Vec<_>>()
            .join(" ");
        fragment.push_str(&format!(
            "{variable_prefix}_{variant}_OBJECTS = {objects}\n"
        ));
    }
    fragment.push('\n');

    for (variant, default_compiler, variant_flags, external_driver) in variants {
        for (index, context) in contexts.iter().enumerate() {
            let object = format!("{object_dir}/{}_{}.o", variant.to_ascii_lowercase(), index);
            let compiler = if *variant == "MAIN" || *variant == "PROV" {
                context.compiler.as_deref().unwrap_or(default_compiler)
            } else {
                default_compiler
            };
            let flags = context
                .flags
                .iter()
                .map(|flag| flag.replace('"', "\\\""))
                .collect::<Vec<_>>()
                .join(" ");
            let compat = if cpp { "" } else { " $(C_COMPAT_FLAGS)" };
            let driver_define = if *external_driver {
                " -DGOVFUZZ_EXTERNAL_DRIVER"
            } else {
                ""
            };
            fragment.push_str(&format!(
                "{object}: FORCE_CONTEXT_OBJECTS\n\t@mkdir -p {object_dir}\n\t{compiler} {variant_flags} $(SECTION_FLAGS){compat} {flags} $(INCLUDES) $(AUTO_EXTRA_INCLUDES){driver_define} -c {} -o {object}\n\n",
                harness_gen::build_safety::make_path(&context.source)
            ));
        }
    }
    fs::write(output_dir.join(fragment_name), fragment).with_context(|| {
        format!(
            "write per-translation-unit build context in {}",
            output_dir.display()
        )
    })
}

/// Split sources discovered by a later undefined-symbol repair into (a) exact
/// compile-database rows, emitted as a separate object graph, and (b) sources
/// for which only the established shared-command fallback is available.
///
/// Generation-time sources use `build_context_objects.mk`; repair-time sources
/// cannot be known until the linker identifies a missing definition, so this
/// fragment is regenerated before every make invocation. Keeping the graphs
/// separate avoids parsing or incrementally mutating generated make syntax and
/// guarantees that a source added in repair round N retains its own compiler,
/// defines, include order, language dialect, packing, and ABI flags.
pub(crate) fn prepare_repair_per_tu_context(
    output_dir: &Path,
    extra_sources: &[PathBuf],
    cpp: bool,
) -> Result<Vec<PathBuf>> {
    let mut fallback_sources = extra_sources.to_vec();
    let contexts = partition_per_tu_compile_contexts(&mut fallback_sources);
    let fragment_path = output_dir.join("repair_context_objects.mk");
    if contexts.is_empty() {
        if fragment_path.exists() {
            fs::remove_file(&fragment_path).with_context(|| {
                format!(
                    "remove stale repair translation-unit context {}",
                    fragment_path.display()
                )
            })?;
        }
        return Ok(fallback_sources);
    }

    let variants: &[(&str, &str, &str, bool)] = if cpp {
        &[
            ("MAIN", "$(CXX)", "$(CXXFLAGS)", true),
            ("AFL", "$(AFLPP_CXX)", "$(AFLPP_CXXFLAGS)", false),
            ("DIFF", "$(DIFF_CXX)", "$(DIFF_CXXFLAGS)", true),
        ]
    } else {
        &[
            ("MAIN", "$(CC)", "$(CFLAGS)", true),
            ("AFL", "$(AFLPP_CC)", "$(AFLPP_CFLAGS)", false),
            ("MSAN", "$(MSAN_CC)", "$(MSAN_CFLAGS)", true),
            ("TSAN", "$(TSAN_CC)", "$(TSAN_CFLAGS)", true),
            ("COV", "$(COV_CC)", "$(COV_CFLAGS)", true),
            ("DIFF", "$(DIFF_CC)", "$(DIFF_CFLAGS)", true),
            ("PROV", "$(CC)", "$(CFLAGS)", true),
        ]
    };
    write_per_tu_context(
        output_dir,
        "repair_context_objects.mk",
        "REPAIR_CONTEXT",
        "repair_context_objs",
        &contexts,
        variants,
        cpp,
    )?;
    Ok(fallback_sources)
}

/// Out-of-source build subdirectories that build systems conventionally drop a
/// `compile_commands.json` into. Searched (alongside the in-place location) at
/// every ancestor of the source file so a database handed over by an integrator
/// — the offline-defense norm — is consumed with no build execution. Order is
/// preference order; `build/` (CMake) wins over the rest.
const COMPILE_DB_BUILD_SUBDIRS: &[&str] = &[
    "build",               // CMake convention; also many hand-rolled builds.
    "builddir",            // Meson's default build directory.
    "cmake-build-debug",   // CLion default (Debug).
    "cmake-build-release", // CLion default (Release).
    "out",                 // Generic out-of-source convention (e.g. GN, custom).
];

fn compile_database_candidates(source_path: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let mut cursor = source_path.parent().map(Path::to_path_buf);
    while let Some(dir) = cursor {
        push_unique_path(&mut candidates, dir.join("compile_commands.json"));
        for sub in COMPILE_DB_BUILD_SUBDIRS {
            push_unique_path(&mut candidates, dir.join(sub).join("compile_commands.json"));
        }
        // The `--probe-build` step writes the recovered database here.
        push_unique_path(
            &mut candidates,
            dir.join(crate::auto::build_probe::PROBE_DIR)
                .join("compile_commands.json"),
        );
        cursor = dir.parent().map(Path::to_path_buf);
    }
    candidates
}

fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

/// Upper bound on the number of translation units the §26.1 secondary
/// whole-library fallback ([`recover_library_translation_units`]) will sweep, so a
/// pathological source tree cannot blow up a single harness link.
const MAX_LIBRARY_TRANSLATION_UNITS: usize = 40;

/// Small inferred CMake/Make libraries are cheap enough to link eagerly. Larger
/// target source sets are deferred until a failed link proves the target needs
/// them; otherwise a self-contained helper in a large library (LevelDB `Hash`)
/// recompiles dozens of unrelated TUs on every dialect/repair attempt.
const MAX_EAGER_BUILD_CONTEXT_SOURCES: usize = 16;

/// Directory walk depth bound for the sibling-source tier of the whole-library
/// fallback.
const SIBLING_TU_MAX_DEPTH: u32 = 6;

/// Whether `path` names a C/C++ translation unit (`.c`/`.cc`/`.cpp`/`.cxx`/
/// `.c++`/`.C`) — the files eligible for the §26.1 secondary whole-library link.
fn is_c_or_cpp_translation_unit(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("c" | "cc" | "cpp" | "cxx" | "c++" | "C")
    )
}

/// Whether a source file declares/defines a `main` entry point. A test/tool/
/// example `main` that a full project build also compiled must stay OUT of the
/// whole-library link — it would collide with the harness's own `main` ("multiple
/// definition of `main'"). Conservative: a textual word-boundaried `main(` match
/// drops the TU, so a false positive only loses one sibling source (still
/// recoverable by the per-symbol `AddSource` cascade) rather than mis-link a
/// second `main`.
fn source_defines_main(path: &Path) -> bool {
    crate::source_text::read_source_text(path)
        .map(|text| text_declares_function(&text, "main"))
        .unwrap_or(false)
}

/// Whether a source file is a C++20 module interface/implementation unit (`export
/// module …;` / `module …;`). Such a unit cannot be compiled as a plain
/// translation unit by the standalone harness clang++ (it needs the modules
/// pipeline govfuzz deliberately disables — see [`is_harness_incompatible_flag`]),
/// so it must be excluded from the whole-library link (fmt ships `src/fmt.cc` as a
/// module unit alongside its classic `src/*.cc`). Cheap textual scan.
fn source_is_cpp_module_unit(path: &Path) -> bool {
    let Ok(text) = crate::source_text::read_source_text(path) else {
        return false;
    };
    text.lines().any(|line| {
        let line = line.trim_start();
        line.starts_with("export module ") || line.starts_with("module ") || line == "module;"
    })
}

/// A translation unit whose basename identifies non-library code even when the
/// project keeps it directly in `src/` or the repository root (classic projects
/// often ship `testheap.c` beside `heap.c`, without a `tests/` directory).
fn source_basename_is_non_library(path: &Path) -> bool {
    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return false;
    };
    let stem = stem.to_ascii_lowercase();
    let prefixed = ["test", "example", "demo", "benchmark", "bench", "fuzz"]
        .iter()
        .any(|prefix| {
            stem == *prefix
                || stem.starts_with(&format!("{prefix}_"))
                || (prefix == &"test"
                    && stem
                        .strip_prefix(prefix)
                        .and_then(|rest| rest.chars().next())
                        .is_some_and(|c| c.is_ascii_alphanumeric()))
        });
    let suffixed = [
        "_test",
        "_tests",
        "_unittest",
        "_unittests",
        "_benchmark",
        "_benchmarks",
        "_bench",
        "_fuzz",
        "_fuzzer",
    ]
    .iter()
    .any(|suffix| stem.ends_with(suffix));
    prefixed || suffixed
}

/// A source basename that is explicitly for a different host operating system.
/// This covers old flat layouts (`linux.c`, `darwin.c`, `ae_kqueue.c`) where the
/// path has no platform directory for [`path_in_non_library_dir`] to filter.
fn source_basename_is_foreign_platform(path: &Path) -> bool {
    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return false;
    };
    let lower = stem.to_ascii_lowercase();
    let tokens: Vec<&str> = lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    let has = |names: &[&str]| tokens.iter().any(|token| names.contains(token));

    if cfg!(target_os = "windows") {
        has(&[
            "linux", "darwin", "macos", "osx", "freebsd", "openbsd", "netbsd", "sunos", "solaris",
            "aix",
        ])
    } else if cfg!(target_os = "macos") {
        has(&[
            "linux", "windows", "win32", "win64", "freebsd", "openbsd", "netbsd", "sunos",
            "solaris", "aix",
        ])
    } else if cfg!(target_os = "linux") {
        has(&[
            "windows", "win32", "win64", "darwin", "macos", "osx", "freebsd", "openbsd", "netbsd",
            "sunos", "solaris", "aix", "kqueue", "evport",
        ]) || lower.contains("iocp")
            || lower == "wepoll"
            || lower.starts_with("win32")
            || lower == "devpoll"
    } else {
        false
    }
}

/// Whether a source path names an implementation for a platform other than the
/// build host. Directory layouts (`src/prim/wasi/prim.c`, `src/osx/foo.c`) need
/// the same treatment as flat basenames (`win32.c`, `ae_kqueue.c`): compiling a
/// foreign backend can satisfy a symbol name while introducing an incompatible
/// implementation and its platform-only dependencies.
pub(crate) fn source_path_is_foreign_platform(path: &Path) -> bool {
    if source_basename_is_foreign_platform(path) {
        return true;
    }
    let tokens: Vec<String> = path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .flat_map(|component| {
            component
                .to_ascii_lowercase()
                .split(|ch: char| !ch.is_ascii_alphanumeric())
                .filter(|token| !token.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect();
    let has = |names: &[&str]| tokens.iter().any(|token| names.contains(&token.as_str()));

    let foreign_os = if cfg!(target_os = "windows") {
        has(&[
            "linux", "darwin", "macos", "osx", "freebsd", "openbsd", "netbsd", "sunos", "solaris",
            "aix", "vxworks", "qnx", "zos",
        ])
    } else if cfg!(target_os = "macos") {
        has(&[
            "linux", "win", "windows", "win32", "win64", "mingw", "mingw32", "mingw64", "msvc",
            "freebsd", "openbsd", "netbsd", "sunos", "solaris", "aix",
        ])
    } else if cfg!(target_os = "linux") {
        has(&[
            "win", "windows", "win32", "win64", "mingw", "mingw32", "mingw64", "msvc", "darwin",
            "macos", "osx", "freebsd", "openbsd", "netbsd", "sunos", "solaris", "aix", "vxworks",
            "qnx", "zos",
        ])
    } else {
        false
    };
    foreign_os
        || (!cfg!(target_arch = "wasm32") && has(&["wasi", "wasm", "emscripten"]))
        || (!cfg!(target_os = "android") && has(&["android"]))
}

/// Whether a source file unconditionally includes a backend header for another
/// platform. Guarded includes in portable files are allowed; an unguarded IOCP,
/// WinSock, kqueue, or similar backend include means the real build selects the
/// entire translation unit conditionally and it must not enter a native sweep.
pub(crate) fn source_path_has_unconditional_foreign_platform_include(path: &Path) -> bool {
    let mut visited = std::collections::HashSet::new();
    source_path_has_unconditional_foreign_platform_include_inner(path, &mut visited)
}

fn expression_has_positive_guard_token(expression: &str, tokens: &[&str]) -> bool {
    let compact = expression
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>();
    tokens.iter().any(|token| {
        let token = token.to_ascii_lowercase();
        let without_negated = compact
            .replace(&format!("!defined({token})"), "")
            .replace(&format!("!defined{token}"), "");
        without_negated.contains(&token)
    })
}

fn source_path_has_unconditional_foreign_platform_include_inner(
    path: &Path,
    visited: &mut std::collections::HashSet<String>,
) -> bool {
    if !visited.insert(normalized_path_key(path)) {
        return false;
    }
    let Ok(source) = crate::source_text::read_source_text(path) else {
        return false;
    };
    let foreign_system_tokens: &[&str] = if cfg!(target_os = "windows") {
        &["sys/epoll.h", "sys/event.h"]
    } else {
        &["windows.h", "winsock", "winerror.h", "ws2tcpip.h"]
    };
    let foreign_backend_tokens: &[&str] = if cfg!(target_os = "windows") {
        &["epoll", "kqueue"]
    } else {
        &["iocp", "wepoll"]
    };
    let foreign_code_tokens: &[&str] = if cfg!(target_os = "windows") {
        &["epoll_", "kevent(", "kqueue("]
    } else {
        &[
            "event_overlapped",
            "error_io_pending",
            "event_get_win32_extension_fns_",
            "wsaget",
            "wsae",
        ]
    };
    let guard_tokens: &[&str] = if cfg!(target_os = "windows") {
        &["__linux__", "linux", "kqueue"]
    } else {
        &["_win32", "win32", "_windows", "iocp"]
    };
    let mut foreign_guards = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim_start();
        if let Some(directive) = trimmed.strip_prefix('#').map(str::trim_start) {
            if directive.starts_with("ifdef ") || directive.starts_with("if ") {
                let lower = directive.to_ascii_lowercase();
                foreign_guards.push(expression_has_positive_guard_token(&lower, guard_tokens));
                continue;
            }
            if directive.starts_with("ifndef ") {
                foreign_guards.push(false);
                continue;
            }
            if directive.starts_with("elif ") {
                let lower = directive.to_ascii_lowercase();
                if let Some(branch) = foreign_guards.last_mut() {
                    *branch = expression_has_positive_guard_token(&lower, guard_tokens);
                }
                continue;
            }
            if directive == "else" {
                if let Some(branch) = foreign_guards.last_mut() {
                    *branch = false;
                }
                continue;
            }
            if directive == "endif" {
                foreign_guards.pop();
                continue;
            }
            if directive.starts_with("include") && !foreign_guards.iter().any(|guard| *guard) {
                let lower = directive.to_ascii_lowercase();
                if foreign_system_tokens
                    .iter()
                    .any(|token| lower.contains(token))
                {
                    return true;
                }
                if foreign_backend_tokens
                    .iter()
                    .any(|token| lower.contains(token))
                {
                    let include = directive
                        .strip_prefix("include")
                        .map(str::trim_start)
                        .and_then(|rest| rest.strip_prefix('"'))
                        .and_then(|quoted| quoted.find('"').map(|end| &quoted[..end]));
                    let local_header = include
                        .and_then(|include| path.parent().map(|parent| parent.join(include)));
                    if let Some(local_header) = local_header.filter(|header| header.is_file()) {
                        if source_path_has_unconditional_foreign_platform_include_inner(
                            &local_header,
                            visited,
                        ) {
                            return true;
                        }
                        continue;
                    }
                    return true;
                }
            }
        } else if is_c_or_cpp_translation_unit(path) && !foreign_guards.iter().any(|guard| *guard) {
            let lower = trimmed.to_ascii_lowercase();
            if foreign_code_tokens
                .iter()
                .any(|token| lower.contains(token))
            {
                return true;
            }
        }
    }
    false
}

fn source_basename_is_optional_dependency_backend(path: &Path) -> bool {
    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return false;
    };
    let tokens: Vec<String> = stem
        .to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    tokens
        .iter()
        .any(|token| matches!(token.as_str(), "openssl" | "mbedtls" | "ssl"))
}

fn source_is_ineligible_library_tu(path: &Path) -> bool {
    source_basename_is_non_library(path)
        || source_path_is_foreign_platform(path)
        || source_path_has_unconditional_foreign_platform_include(path)
        || source_basename_is_optional_dependency_backend(path)
        || source_path_has_missing_translation_unit_include(path)
}

/// Whether a source file textually includes a C/C++ implementation file that
/// is absent from the damaged tree. Such a source cannot be compiled as a
/// repair TU: preprocessing it would replace the missing implementation with
/// GovFuzz's placeholder header and expose only a misleading partial program.
pub(crate) fn source_path_has_missing_translation_unit_include(path: &Path) -> bool {
    included_translation_unit_paths(path)
        .iter()
        .any(|included| !included.is_file())
}

/// Directory names holding non-library code (tests/examples/benchmarks/tools/
/// fuzzers/third-party) whose TUs must not be swept into the whole-library link —
/// they carry their own `main`/unrelated symbols. Mirrors discovery's example/test
/// exclusions.
fn is_non_library_dir(name: &str) -> bool {
    matches!(
        name,
        "test"
            | "tests"
            | "testing"
            | "api_test"
            | "api_tests"
            | "unittest"
            | "unittests"
            | "example"
            | "examples"
            | "demo"
            | "demos"
            | "benchmark"
            | "benchmarks"
            | "bench"
            | "fuzz"
            | "fuzzing"
            | "fuzzer"
            | "fuzzers"
            | "tool"
            | "tools"
            | "util"
            | "utils"
            | "sample"
            | "samples"
            | "build"
            | "builddir"
            | "out"
            | "cmake-build-debug"
            | "cmake-build-release"
            | "third_party"
            | "thirdparty"
            | "vendor"
            | "extern"
            | "external"
            | "deps"
            | "node_modules"
            | "target"
    )
}

/// §26.1 SECONDARY fallback — the target library's full translation-unit set, to
/// compile+link beside the harness when NO prebuilt `*.a` exists and the harness
/// link fails with undefined externals spread across many sibling TUs (yaml-cpp:
/// header + 30 `src/*.cpp`, gathered by a CMake `file(GLOB)` the static
/// CMakeLists-inference cannot expand, with no archive on disk). The per-symbol
/// `AddSource` cascade can converge here but is slow (one TU per build/repair
/// round) and stalls when the declaration index mis-attributes a sibling symbol to
/// the target's own source; linking the whole library in one shot resolves every
/// sibling symbol at once.
///
/// Recovered, in preference order, from:
///   1. a `compile_commands.json` discoverable from `target_source` (the
///      documented compile-DB path — present after `--probe-build`, or when an
///      integrator ships a DB): every C/C++ `file` entry; else
///   2. the sibling C/C++ sources under the target's own source-directory subtree
///      (the library's `src/`), so a default `govfuzz auto` (no probe) still links
///      the whole library.
///
/// The target's own source and any `main`-defining TU are excluded; the result is
/// deduplicated and deterministically sorted. An application-sized set above
/// [`MAX_LIBRARY_TRANSLATION_UNITS`] is rejected wholesale rather than truncated:
/// an arbitrary partial link is both expensive and almost certainly incorrect,
/// while the normal per-symbol source-repair cascade remains available.
pub(crate) fn recover_library_translation_units(
    target_source: &Path,
    cpp_target: bool,
) -> Vec<PathBuf> {
    let target_key = normalized_path_key(target_source);
    let mut tus = library_translation_units_from_compile_db(target_source, &target_key, cpp_target);
    if tus.is_empty() {
        tus = find_upward_build_file(target_source, &["CMakeLists.txt"])
            .map(|cmake| infer_cmake_build_context(target_source, &cmake).extra_sources)
            .unwrap_or_default()
            .into_iter()
            .filter(|file| {
                normalized_path_key(file) != target_key
                    && file.is_file()
                    && !source_defines_main(file)
                    && !source_is_cpp_module_unit(file)
                    && !source_is_ineligible_library_tu(file)
                    && (cpp_target || !is_cpp_only_translation_unit(file))
                    && !path_in_non_library_dir(file)
            })
            .collect();
    }
    if tus.is_empty() {
        tus = sibling_library_translation_units(target_source, &target_key, cpp_target);
    }
    tus.sort();
    tus.dedup();
    if tus.len() > MAX_LIBRARY_TRANSLATION_UNITS {
        Vec::new()
    } else {
        tus
    }
}

/// A C++-only translation unit (`.cpp`/`.cc`/`.cxx`/`.c++`/`.C`). A C target's
/// harness is built with a single `clang -std=c<NN>` recipe that cannot compile
/// C++, so sweeping one of these into a C library-recovery link (cmark's
/// `api_test/cplusplus.cpp`) breaks the build — a false failed_build (#3).
fn is_cpp_only_translation_unit(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("cc" | "cpp" | "cxx" | "c++" | "C")
    )
}

/// Whether any path component is a conventional non-library directory
/// (tests/examples/…). The compile-DB TU recovery did not apply this filter, so a
/// test TU listed in `compile_commands.json` was linked into the library (#3).
fn path_in_non_library_dir(path: &Path) -> bool {
    path.components()
        .any(|c| c.as_os_str().to_str().is_some_and(is_non_library_dir))
}

/// Tier 1 of [`recover_library_translation_units`]: every C/C++ `file` entry of the
/// first `compile_commands.json` discoverable from `target_source`, excluding the
/// target itself and any `main`-defining TU.
fn library_translation_units_from_compile_db(
    target_source: &Path,
    target_key: &str,
    cpp_target: bool,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for db_path in compile_database_candidates(target_source) {
        if !db_path.is_file() {
            continue;
        }
        let Ok(bytes) = fs::read(&db_path) else {
            continue;
        };
        let Ok(entries) = serde_json::from_slice::<Vec<CompileCommandEntry>>(&bytes) else {
            continue;
        };
        for entry in entries {
            let file = if entry.file.is_absolute() {
                entry.file.clone()
            } else {
                entry.directory.join(&entry.file)
            };
            let file = normalize_path(&file);
            if !is_c_or_cpp_translation_unit(&file)
                || normalized_path_key(&file) == target_key
                || !file.is_file()
                || source_defines_main(&file)
                || source_is_cpp_module_unit(&file)
                || source_is_ineligible_library_tu(&file)
                // #3: a C target's harness builds with a C-only `clang -std=c<NN>`
                // recipe, so never sweep a C++ TU into its library link; and skip
                // test/example TUs the compile DB happens to list.
                || (!cpp_target && is_cpp_only_translation_unit(&file))
                || path_in_non_library_dir(&file)
            {
                continue;
            }
            if !out.contains(&file) {
                out.push(file);
            }
        }
        // The first existing+parseable DB wins (preference order); do not union a
        // shallower-and-deeper DB.
        break;
    }
    out
}

/// Tier 2 of [`recover_library_translation_units`]: the sibling C/C++ sources under
/// the target's own source-directory subtree, used when no compile database is
/// available. Excludes the target itself, `main`-defining TUs, and conventional
/// non-library directories (tests/examples/tools/third-party).
fn sibling_library_translation_units(
    target_source: &Path,
    target_key: &str,
    cpp_target: bool,
) -> Vec<PathBuf> {
    let Some(root) = target_source.parent() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let max_depth = if source_directory_is_project_root(root) {
        0
    } else {
        SIBLING_TU_MAX_DEPTH
    };
    collect_sibling_translation_units(root, 0, max_depth, target_key, cpp_target, &mut out);
    // An amalgamation that includes the selected target cannot be linked beside
    // that target without duplicate definitions (mimalloc's `static.c` includes
    // `alloc.c`). Drop such containers before using includes to suppress their
    // standalone leaves; those leaves must remain available as normal siblings.
    out.retain(|source| {
        !included_translation_unit_paths(source)
            .iter()
            .any(|included| normalized_path_key(included) == target_key)
    });
    // Some old C libraries split one logical translation unit across files with
    // a `.c` suffix (Expat's `xcsinc.c`, `xmltok_impl.c`, and `xmltok_ns.c`).
    // Compiling those include fragments independently loses the declarations and
    // feature macros established by the including TU. A real compile database is
    // authoritative and bypasses this fallback; for the sibling heuristic, drop
    // every candidate that another recovered TU (or the target itself) includes
    // textually.
    let mut included_source_paths = std::collections::HashSet::new();
    for source in std::iter::once(target_source).chain(out.iter().map(PathBuf::as_path)) {
        included_source_paths.extend(
            included_translation_unit_paths(source)
                .into_iter()
                .map(|included| normalized_path_key(&included)),
        );
    }
    out.retain(|path| !included_source_paths.contains(&normalized_path_key(path)));
    out
}

/// A target that lives directly in a checkout/source-drop root (zlib's
/// `uncompr.c`) owns the root-level siblings, not every independent library under
/// `contrib/`. Nested source directories may still recurse to collect one
/// component's internal layout.
fn source_directory_is_project_root(dir: &Path) -> bool {
    dir.join(".git").exists()
        || dir.join(".hg").exists()
        || dir.join(".svn").exists()
        || [
            "configure",
            "configure.ac",
            "configure.in",
            "CMakeLists.txt",
            "meson.build",
            "WORKSPACE",
            "WORKSPACE.bazel",
        ]
        .iter()
        .any(|marker| dir.join(marker).is_file())
}

fn included_translation_unit_paths(path: &Path) -> Vec<PathBuf> {
    let Ok(source) = crate::source_text::read_source_text(path) else {
        return Vec::new();
    };
    let Some(parent) = path.parent() else {
        return Vec::new();
    };
    source
        .lines()
        .filter_map(|line| {
            let rest = line.trim_start().strip_prefix('#')?.trim_start();
            let rest = rest.strip_prefix("include")?.trim_start();
            let include = rest.strip_prefix('"')?;
            let end = include.find('"')?;
            let include = Path::new(&include[..end]);
            is_c_or_cpp_translation_unit(include).then(|| normalize_path(&parent.join(include)))
        })
        .collect()
}

fn collect_sibling_translation_units(
    dir: &Path,
    depth: u32,
    max_depth: u32,
    target_key: &str,
    cpp_target: bool,
    out: &mut Vec<PathBuf>,
) {
    // Collect one past the cap so the caller can reject the entire oversized
    // set; stopping at exactly the cap would silently return an arbitrary prefix.
    if out.len() > MAX_LIBRARY_TRANSLATION_UNITS {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut subdirs: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with('.') && !is_non_library_dir(&name) {
                subdirs.push(path);
            }
        } else if is_c_or_cpp_translation_unit(&path) {
            let norm = normalize_path(&path);
            if normalized_path_key(&norm) == target_key
                || source_defines_main(&norm)
                || source_is_cpp_module_unit(&norm)
                || source_is_ineligible_library_tu(&norm)
                // #3: don't link a C++ TU into a C target's C-only build.
                || (!cpp_target && is_cpp_only_translation_unit(&norm))
            {
                continue;
            }
            if !out.contains(&norm) {
                out.push(norm);
            }
        }
    }
    if depth < max_depth {
        subdirs.sort();
        for sub in subdirs {
            if out.len() > MAX_LIBRARY_TRANSLATION_UNITS {
                break;
            }
            collect_sibling_translation_units(
                &sub,
                depth + 1,
                max_depth,
                target_key,
                cpp_target,
                out,
            );
        }
    }
}

/// Build/probe directories holding CMake-generated headers for `source_path`'s
/// project (§26.8). Walks the source's ancestors and, at each, collects the
/// generated-header dirs under that ancestor's probe/build dirs (see
/// `build_probe::generated_header_dirs`). The project root — where the probe
/// dropped `miniz_export.h` / a generated `config.h` — is one of those ancestors,
/// so its build dir surfaces no matter how deeply the target source is nested.
fn probe_generated_header_dirs(source_path: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut cursor = source_path.parent().map(Path::to_path_buf);
    while let Some(dir) = cursor {
        for gen in crate::auto::build_probe::generated_header_dirs(&dir) {
            push_unique_path(&mut out, gen);
        }
        cursor = dir.parent().map(Path::to_path_buf);
    }
    out
}

fn compile_command_matches_source(entry: &CompileCommandEntry, source_path: &Path) -> bool {
    let entry_file = compile_command_source_path(entry);
    normalized_path_key(&entry_file) == normalized_path_key(source_path)
}

fn compile_command_source_path(entry: &CompileCommandEntry) -> PathBuf {
    if entry.file.is_absolute() {
        entry.file.clone()
    } else {
        entry.directory.join(&entry.file)
    }
}

/// Select the translation-unit compile command that directly includes a header.
/// Compile databases almost never contain header rows, so exact-only lookup
/// discarded precisely the flags non-self-contained legacy headers need. Keep
/// the association conservative (direct include evidence only), then choose the
/// nearest TU deterministically when several entries include the same header.
fn compile_database_entry_for_header<'a>(
    entries: &'a [CompileCommandEntry],
    header: &Path,
) -> Option<&'a CompileCommandEntry> {
    let header_key = normalized_path_key(header);
    let mut matches = Vec::new();
    for entry in entries {
        let owner = compile_command_source_path(entry);
        if !is_c_or_cpp_translation_unit(&owner) {
            continue;
        }
        let Ok(source) = crate::source_text::read_source_text(&owner) else {
            continue;
        };
        let flags = extract_compile_database_flags(entry, &owner);
        let mut include_dirs = owner
            .parent()
            .map(Path::to_path_buf)
            .into_iter()
            .collect::<Vec<_>>();
        for directory in include_dirs_from_compile_flags(&flags) {
            if !include_dirs.contains(&directory) {
                include_dirs.push(directory);
            }
        }
        let directly_includes_header =
            direct_project_includes(&source, &include_dirs)
                .iter()
                .any(|spelling| {
                    include_dirs.iter().any(|directory| {
                        normalized_path_key(&directory.join(spelling)) == header_key
                    })
                });
        if directly_includes_header {
            matches.push((
                path_distance(&owner, header),
                normalized_path_key(&owner),
                entry,
            ));
        }
    }
    matches.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    matches.into_iter().next().map(|(_, _, entry)| entry)
}

fn path_distance(left: &Path, right: &Path) -> usize {
    let left = left.components().collect::<Vec<_>>();
    let right = right.components().collect::<Vec<_>>();
    let common = left.iter().zip(&right).take_while(|(a, b)| a == b).count();
    left.len() - common + right.len() - common
}

fn normalized_path_key(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| normalize_path(path))
        .to_string_lossy()
        .to_string()
}

/// A flag recovered from a project's build wiring (`compile_commands.json`,
/// CMakeLists, Makefile) that must NOT be forwarded to govfuzz's standalone
/// single-translation-unit harness compile.
///
/// Each harness is built as ONE self-contained `clang`/`clang++` invocation, so
/// flags that assume a C++-modules build graph or a precompiled-header pipeline
/// either make clang reject the command outright — fmt's CMake
/// `target_compile_options(... -fmodules-ts)` aborts the harness `clang++` with
/// `error: unknown argument: '-fmodules-ts'`, which broke ALL of fmt's harness
/// builds — or silently look for a module/PCH artifact that the harness build
/// never produced. The predicate is deliberately CONSERVATIVE: it only matches
/// flags known to break or be meaningless for a single-TU build; everything else
/// (`-I`/`-D`/`-std=`/`-isystem`/`-include`/…) passes through untouched.
fn is_harness_incompatible_flag(flag: &str) -> bool {
    // C++20/23 modules: the harness has no module map, prebuilt-module path, or
    // `.pcm` build graph, so any modules flag is at best meaningless and at worst
    // a hard `unknown argument` from the harness frontend.
    flag == "-fmodules-ts"
        || flag == "-fmodules"
        // `-fmodule-map-file=…`, `-fmodule-name=…`, `-fmodule-file=…`, …
        || flag.starts_with("-fmodule-")
        || flag.starts_with("-fprebuilt-module-path")
        // Precompiled headers: the harness compiles no PCH, so an `-include-pch`
        // (and its `.pch` operand) or a `-fpch-*` knob has nothing to bind to.
        || flag == "-include-pch"
        || flag.starts_with("-fpch-")
}

/// Tokenize a GCC/Clang `@response-file`: whitespace-separated arguments, with
/// single/double quoting to group whitespace and a backslash to escape the next
/// character. Newlines are whitespace. Covers the common subset a build system
/// emits (`-I/abs/path`, `-DFOO=bar`, one per line or space-separated).
fn tokenize_response_file(contents: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_token = false;
    let mut quote: Option<char> = None;
    let mut chars = contents.chars();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else if c == '\\' {
                    if let Some(next) = chars.next() {
                        cur.push(next);
                    }
                } else {
                    cur.push(c);
                }
            }
            None => {
                if c == '\'' || c == '"' {
                    quote = Some(c);
                    in_token = true;
                } else if c == '\\' {
                    if let Some(next) = chars.next() {
                        cur.push(next);
                        in_token = true;
                    }
                } else if c.is_whitespace() {
                    if in_token {
                        tokens.push(std::mem::take(&mut cur));
                        in_token = false;
                    }
                } else {
                    cur.push(c);
                    in_token = true;
                }
            }
        }
    }
    if in_token || !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

/// Expand `@response-file` arguments (offline-legacy audit / #93 AC5) into their
/// tokens so the `-I`/`-D`/`-isystem` context a build system spilled into a
/// response file is not silently dropped — which otherwise fails the offline
/// harness build with missing-header errors. A response file's own `@nested`
/// references resolve relative to that file's directory (GCC behavior). An
/// unreadable file (or one nested too deep) keeps the literal `@arg`, so it is
/// still recorded as a dropped `response_file` family — no silent loss, no
/// regression versus the previous behavior.
fn expand_response_files(args: &[String], base_dir: &Path, depth: usize) -> Vec<String> {
    const MAX_RESPONSE_FILE_DEPTH: usize = 8;
    let mut out = Vec::with_capacity(args.len());
    for arg in args {
        match arg.strip_prefix('@') {
            Some(rel) if depth < MAX_RESPONSE_FILE_DEPTH && !rel.is_empty() => {
                let path = base_dir.join(rel);
                match std::fs::read_to_string(&path) {
                    Ok(contents) => {
                        let nested_base = path.parent().unwrap_or(base_dir);
                        out.extend(expand_response_files(
                            &tokenize_response_file(&contents),
                            nested_base,
                            depth + 1,
                        ));
                    }
                    Err(_) => out.push(arg.clone()),
                }
            }
            _ => out.push(arg.clone()),
        }
    }
    out
}

fn extract_compile_database_flags(entry: &CompileCommandEntry, source_path: &Path) -> Vec<String> {
    let Some(raw_args) = compile_command_arguments(entry) else {
        return Vec::new();
    };
    let args = expand_response_files(&raw_args, &entry.directory, 0);
    let mut flags = Vec::new();
    if let Some(compiler) = compile_command_compiler(&args) {
        flags.push(format!("{BUILD_CONTEXT_COMPILER_PREFIX}{compiler}"));
    }
    let mut i = 1_usize; // skip compiler executable
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "-I" => {
                if let Some(value) = args.get(i + 1) {
                    flags.push("-I".to_owned());
                    flags.push(resolve_compile_database_path(&entry.directory, value));
                    i += 2;
                    continue;
                }
            }
            "-isystem" | "-iquote" | "-idirafter" | "-isysroot" | "--sysroot" | "-imacros" => {
                if let Some(value) = args.get(i + 1) {
                    flags.push(arg.clone());
                    flags.push(resolve_compile_database_path(&entry.directory, value));
                    i += 2;
                    continue;
                }
            }
            "-D" | "-U" => {
                if let Some(value) = args.get(i + 1) {
                    // Drop MSVC CRT-model selection (_DLL/_MT/_DEBUG); see
                    // is_msvc_crt_model_define — inheriting them breaks the
                    // static-CRT harness link with `__imp_*` unresolved externals.
                    if arg == "-D" && is_msvc_crt_model_define(&format!("-D{value}")) {
                        i += 2;
                        continue;
                    }
                    flags.push(arg.clone());
                    flags.push(value.clone());
                    i += 2;
                    continue;
                }
            }
            "-include" => {
                if let Some(value) = args.get(i + 1) {
                    flags.push(arg.clone());
                    flags.push(resolve_compile_database_path(&entry.directory, value));
                    i += 2;
                    continue;
                }
            }
            "--gcc-install-dir" | "--gcc-toolchain" => {
                if let Some(value) = args.get(i + 1) {
                    flags.push(arg.clone());
                    flags.push(resolve_compile_database_path(&entry.directory, value));
                    i += 2;
                    continue;
                }
            }
            "--target" | "-target" => {
                if let Some(value) = args.get(i + 1) {
                    flags.push(arg.clone());
                    flags.push(value.clone());
                    i += 2;
                    continue;
                }
            }
            "-x" => {
                if let Some(value) = args.get(i + 1).filter(|value| {
                    matches!(
                        value.as_str(),
                        "c" | "c++" | "objective-c" | "objective-c++" | "assembler-with-cpp"
                    )
                }) {
                    flags.push(arg.clone());
                    flags.push(value.clone());
                    i += 2;
                    continue;
                }
            }
            "-o" | "-MF" | "-MT" | "-MQ" | "-MJ" | "-dependency-file" => {
                i += 2;
                continue;
            }
            // Precompiled-header include carries its `.pch` operand in the next
            // token; drop BOTH so neither reaches the (PCH-less) harness compile.
            "-include-pch" => {
                i += 2;
                continue;
            }
            "-c" | "--" | "-M" | "-MM" | "-MD" | "-MMD" | "-MP" => {
                i += 1;
                continue;
            }
            _ => {}
        }

        if let Some(value) = arg.strip_prefix("-I").filter(|value| !value.is_empty()) {
            flags.push("-I".to_owned());
            flags.push(resolve_compile_database_path(&entry.directory, value));
        } else if (arg.starts_with("-D") && !is_msvc_crt_model_define(arg))
            || arg.starts_with("-U")
            || arg.starts_with("-std=")
            || arg == "-pthread"
            || arg.starts_with("--gcc-install-dir=")
            || arg.starts_with("--gcc-toolchain=")
            || arg.starts_with("--sysroot=")
            || arg.starts_with("--target=")
            || compile_database_single_flag_is_safe(arg)
        {
            flags.push(arg.clone());
        } else if !arg.starts_with('-')
            && normalized_path_key(&entry.directory.join(arg)) == normalized_path_key(source_path)
        {
            // Source file argument; already compiled into target_sources.
        }
        i += 1;
    }
    // Belt-and-suspenders: even though the allowlist above keeps only known
    // compile-relevant flags, strip any harness-incompatible one that slipped
    // through (e.g. a future allowlisted family that happens to overlap), so the
    // single-TU harness compile never sees `-fmodules-ts` and friends.
    flags.retain(|flag| !is_harness_incompatible_flag(flag));
    let dropped = dropped_compile_flag_families(&args);
    if !dropped.is_empty() {
        flags.push(format!(
            "{BUILD_CONTEXT_DROPPED_PREFIX}{}",
            dropped.into_iter().collect::<Vec<_>>().join(",")
        ));
    }
    flags
}

fn dropped_compile_flag_families(args: &[String]) -> BTreeSet<&'static str> {
    let mut families = BTreeSet::new();
    for arg in args.iter().skip(1) {
        if matches!(arg.as_str(), "-o" | "-c" | "--") {
            families.insert("output_control");
        } else if matches!(arg.as_str(), "-M" | "-MM" | "-MD" | "-MMD" | "-MP")
            || arg.starts_with("-MF")
            || arg.starts_with("-MT")
            || arg.starts_with("-MQ")
        {
            families.insert("dependency_output");
        } else if is_harness_incompatible_flag(arg) {
            families.insert("module_or_pch");
        } else if arg.starts_with("-Wl,") || arg.starts_with("-Xlinker") {
            families.insert("linker_only");
        } else if arg.starts_with("-fplugin") || arg.starts_with("-fprofile-") {
            families.insert("plugin_or_profile");
        } else if arg.starts_with('@') {
            families.insert("response_file");
        }
    }
    families
}

fn compile_command_compiler(args: &[String]) -> Option<String> {
    let mut index = 0;
    while let Some(argument) = args.get(index) {
        let leaf = Path::new(argument)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(argument)
            .to_ascii_lowercase();
        if matches!(leaf.as_str(), "ccache" | "sccache" | "distcc" | "icecc") {
            index += 1;
            continue;
        }
        let recognized = leaf.contains("clang")
            || leaf == "gcc"
            || leaf.starts_with("gcc-")
            || leaf == "g++"
            || leaf.starts_with("g++-");
        return recognized.then(|| argument.clone());
    }
    None
}

/// Compile-relevant single-token families that are safe and meaningful in the
/// standalone harness. Deliberately exclude linker forwarding, compiler plugins,
/// profile/PCH/module state, output/dependency generation, and response files.
fn compile_database_single_flag_is_safe(flag: &str) -> bool {
    if is_harness_incompatible_flag(flag)
        || flag.starts_with("-fplugin")
        || flag.starts_with("-fprofile-")
        || flag.starts_with("-save-temps")
        || flag.starts_with("-Wl,")
        || flag.starts_with("-Xlinker")
        || flag.starts_with('@')
    {
        return false;
    }
    flag.starts_with("-m")
        || flag.starts_with("-W")
        || flag.starts_with("-fms-")
        || flag.starts_with("-fvisibility=")
        || flag.starts_with("-fabi-version=")
        || flag.starts_with("-fpack-struct=")
        || flag.starts_with("-fno-builtin-")
        || matches!(
            flag,
            "-nostdinc"
                | "-nostdinc++"
                | "-ansi"
                | "-fdeclspec"
                | "-fpermissive"
                | "-fpack-struct"
                | "-fshort-enums"
                | "-funsigned-char"
                | "-fsigned-char"
                | "-fno-exceptions"
                | "-fexceptions"
                | "-fno-rtti"
                | "-frtti"
                | "-fno-strict-aliasing"
                | "-fstrict-aliasing"
                | "-fwrapv"
                | "-fno-builtin"
                | "-ffreestanding"
                | "-fPIC"
                | "-fpic"
                | "-fcommon"
                | "-fno-common"
                | "-fopenmp"
        )
}

fn compile_command_arguments(entry: &CompileCommandEntry) -> Option<Vec<String>> {
    if let Some(arguments) = &entry.arguments {
        return Some(arguments.clone());
    }
    entry.command.as_deref().map(split_compile_command)
}

fn resolve_compile_database_path(directory: &Path, value: &str) -> String {
    let path = Path::new(value);
    let resolved = if path.is_absolute() {
        normalize_path(path)
    } else {
        normalize_path(&directory.join(path))
    };
    harness_gen::build_safety::make_path(&resolved)
}

fn split_compile_command(command: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut chars = command.chars().peekable();
    let mut quote: Option<char> = None;
    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), '\\') => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            (Some(_), c) => current.push(c),
            (None, '\'' | '"') => quote = Some(ch),
            (None, '\\') => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            (None, c) if c.is_whitespace() => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            (None, c) => current.push(c),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

/// Surface project headers in the order the real translation unit establishes
/// them. Source-written includes come first and retain their order; only then do
/// we append an otherwise-missing same-stem API header (`foo.c` -> `foo.h`).
/// Promoting that convenient same-stem guess ahead of `config.h`/an umbrella
/// include changes the language seen by legacy headers and commonly produces
/// misleading declarator syntax errors.
pub(crate) fn auto_detect_c_headers(source: &Path, dir: &Path) -> Vec<String> {
    let stem = source.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let mut headers = Vec::new();
    if let Ok(text) = std::fs::read_to_string(source) {
        for header in quoted_local_includes(&text) {
            if !is_partial_impl_header(&header)
                && dir.join(&header).is_file()
                && !is_openmp_translation_unit(&dir.join(&header))
                && !headers.contains(&header)
            {
                headers.push(header);
            }
        }
    }
    let candidates = [
        format!("{stem}.h"),
        format!("{stem}.hpp"),
        format!("{stem}.hh"),
        format!("{stem}.hxx"),
    ];
    for candidate in &candidates {
        if dir.join(candidate).is_file() && !headers.contains(candidate) {
            headers.push(candidate.clone());
        }
    }
    headers
}

/// True for a partial-implementation include (`.inl`, `.tcc`, `.ipp`) that is
/// meant to be textually pulled *inside* another header, not compiled
/// standalone — `#include`-ing it directly into a harness fails (it references
/// names the enclosing header defines first, e.g. jsoncpp's
/// `json_valueiterator.inl`).
/// A non-standalone implementation/inline FRAGMENT header — meant to be textually
/// `#include`d after its dependencies, not compiled or included on its own
/// (`*.inl`/`*.tcc`/`*.ipp`/`*.inc`, and the `*-inl.h` / `*_inl.hpp` / `*.inc.h`
/// conventions used by simdjson, ctre, harfbuzz). `*.inc` is the table-data
/// convention (basis_universal's `basisu_transcoder_tables_*.inc` are raw array
/// initializer fragments pulled in *inside* a definition); pulling one into the
/// harness at file scope fails with "expected unqualified-id".
/// A C++-only header by extension (`.hpp`/`.hh`/`.hxx`/`.h++`/`.hp`). Such a header
/// holds C++ constructs (`class`, templates, `namespace`) that a C harness — built
/// with the C compiler — cannot parse. A C target's declarations live in a `.h`;
/// one reachable only through a `.hpp` belongs to the C++ harness path. Plain `.h`
/// returns false (the common C++ convention of declaring in `.h` is handled by the
/// C++ path's own header set, not by excluding `.h` here).
pub(crate) fn is_cpp_only_header(header: &str) -> bool {
    matches!(
        Path::new(header).extension().and_then(|e| e.to_str()),
        Some("hpp") | Some("hh") | Some("hxx") | Some("h++") | Some("hp")
    )
}

pub(crate) fn is_partial_impl_header(header: &str) -> bool {
    let p = Path::new(header);
    if matches!(
        p.extension().and_then(|e| e.to_str()),
        Some("inl") | Some("tcc") | Some("ipp") | Some("inc")
    ) {
        return true;
    }
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    stem.ends_with("-inl") || stem.ends_with("_inl") || stem.ends_with(".inc")
}

fn is_translation_unit_include(path: &str) -> bool {
    matches!(
        Path::new(path).extension().and_then(|ext| ext.to_str()),
        Some("c") | Some("cc") | Some("cpp") | Some("cxx") | Some("c++") | Some("C")
    )
}

/// Whether a single line is an OpenMP directive: `#pragma omp ...` or an
/// `#include` of `<omp.h>`/`"omp.h"`. Tolerates leading whitespace and a space
/// after `#` (`# pragma omp`).
/// True when `text` references an OpenMP RUNTIME symbol — a word-bounded `omp_`
/// token followed by an identifier (`omp_get_num_threads`, `omp_in_parallel`, …).
/// This is the precise signal for "won't link without `-fopenmp`": a call to an
/// `omp_*` library function is the only thing that produces an undefined symbol.
/// A bare `#pragma omp ...` is silently IGNORED without `-fopenmp` (the loop runs
/// serially and links fine), and a bare `#include <omp.h>` only DECLARES the
/// functions — so neither alone justifies pruning the TU. The word boundary keeps
/// `comp_`/`stomp_state` from matching.
fn references_openmp_runtime(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(rel) = text[from..].find("omp_") {
        let abs = from + rel;
        let left_boundary =
            abs == 0 || !matches!(bytes[abs - 1], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_');
        let has_ident = bytes
            .get(abs + 4)
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
        if left_boundary && has_ident {
            return true;
        }
        from = abs + 4;
    }
    false
}

/// A SOURCE translation unit (`.c`/`.cc`/`.cpp`/`.cxx`/`.cu`/`.c++`/`.C`) that
/// CALLS an OpenMP runtime function (`omp_*`). Such a call is what fails to link
/// without `-fopenmp` (which also predefines `_OPENMP`); govfuzz builds harnesses
/// with a plain `-O1` and never enables OpenMP, so pulling such a TU into the
/// harness as a whole-TU `#include` yields "undefined symbol 'omp_get_num_threads'"
/// and friends. These TUs are OPTIONAL parallel wrappers a project compiles only
/// when OpenMP is detected (base64's `lib_openmp.c`, reached only through `#ifdef
/// _OPENMP #include "lib_openmp.c"`); the core codec builds without them, so they
/// are excluded from the harness source set. A bare `#pragma omp` (silently
/// ignored without `-fopenmp`, links fine) or a lone `#include <omp.h>`
/// (declarations only) does NOT qualify — only an actual `omp_*` runtime
/// reference, so a TU that merely parallelises a loop is never dropped. Only
/// SOURCE files are checked — a header is kept (it may declare needed types).
fn is_openmp_translation_unit(path: &Path) -> bool {
    let is_source = matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("c") | Some("cc") | Some("cpp") | Some("cxx") | Some("cu") | Some("c++") | Some("C")
    );
    if !is_source {
        return false;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    references_openmp_runtime(&text)
}

/// Project-local headers a harness should `#include`: both `"quoted"` and
/// `<angle>` includes from the target source that resolve to a file under one
/// of the project include dirs. System headers (`<vector>`) don't resolve in
/// project dirs and are skipped. Partial-implementation files (`.inl`, `.tcc`,
/// `.ipp`) are skipped too — they are meant to be textually included *inside*
/// another header (e.g. jsoncpp's `json_valueiterator.inl`), so pulling them
/// into the harness standalone fails to compile; the public header that
/// includes them (e.g. `<json/value.h>`) is what the harness needs.
/// The project `#include`s written directly in `source` that resolve in
/// `include_dirs` (skipping partial-impl `*-inl.h` fragments).
/// For a preprocessor conditional directive (text after `#`), return whether the
/// `#if` branch and the `#else` branch each compile ONLY on a foreign (non-host)
/// OS. `#ifdef _WIN32` -> (if=foreign, else=host); `#ifndef _WIN32` -> (if=host,
/// else=foreign); a guard that also names the host (`|| defined(__linux__)`) or
/// any guard not clearly Windows-only -> (false, false) so its includes are kept.
/// Lets the harness include-closure drop a Windows-only `#include
/// "../extra/win32cond.h"` (which pulls `<windows.h>`) when fuzzing on Linux.
fn foreign_guard_branches(directive_after_hash: &str) -> (bool, bool) {
    let d = directive_after_hash.trim();
    const FOREIGN: &[&str] = &[
        "_WIN32",
        "_WIN64",
        "_MSC_VER",
        "__MINGW32__",
        "__MINGW64__",
        "WIN32",
        "_WINDOWS",
        "__CYGWIN__",
    ];
    const HOST: &[&str] = &[
        "__linux__",
        "__unix__",
        "__unix",
        "__APPLE__",
        "__GNUC__",
        "__clang__",
        "_POSIX",
    ];
    let mentions_foreign = FOREIGN.iter().any(|m| d.contains(m));
    let mentions_host = HOST.iter().any(|m| d.contains(m));
    if !mentions_foreign || mentions_host {
        return (false, false);
    }

    // A negated FOREIGN term does not negate a positive sibling term:
    // `defined(_WIN32) && !defined(__CYGWIN__)` is still Windows-only. The old
    // `d.contains('!')` shortcut inverted that whole expression and pulled
    // libarchive's archive_windows.h into a Linux harness. Remove only explicitly
    // negated occurrences, then see whether any positive foreign selector remains.
    let compact: String = d.chars().filter(|c| !c.is_whitespace()).collect();
    let mut positive_expr = compact.clone();
    for name in FOREIGN {
        positive_expr = positive_expr.replace(&format!("!defined({name})"), "");
        positive_expr = positive_expr.replace(&format!("!{name}"), "");
    }
    let has_positive_foreign = FOREIGN.iter().any(|name| positive_expr.contains(name));

    // `#ifndef WIN` / `#if !defined(WIN)` select the host branch in `#if` when
    // there is no other positive foreign selector.
    if d.starts_with("ifndef") || !has_positive_foreign {
        (false, true)
    } else {
        (true, false)
    }
}

fn direct_project_includes(source: &str, include_dirs: &[PathBuf]) -> Vec<String> {
    let mut includes = Vec::new();
    // (skip-current-branch, skip-else-branch) per open `#if`. An include inside a
    // foreign-OS-only branch is dropped: it never compiles on the host, and pulling
    // it into the harness textually (ignoring the guard) drags in headers like
    // `windows.h` that do not exist here.
    let mut guards: Vec<(bool, bool)> = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim_start();
        if let Some(after_hash) = trimmed.strip_prefix('#') {
            let d = after_hash.trim_start();
            if d.starts_with("ifdef") || d.starts_with("ifndef") || d.starts_with("if") {
                guards.push(foreign_guard_branches(d));
                continue;
            } else if d.starts_with("elif") {
                if let Some(top) = guards.last_mut() {
                    *top = foreign_guard_branches(d);
                }
                continue;
            } else if d.starts_with("else") {
                if let Some(top) = guards.last_mut() {
                    top.0 = top.1;
                }
                continue;
            } else if d.starts_with("endif") {
                guards.pop();
                continue;
            }
        }
        if guards.iter().any(|g| g.0) {
            continue; // inside a foreign-OS-only branch — not compiled on the host
        }
        let Some(rest) = trimmed.strip_prefix("#include") else {
            continue;
        };
        let rest = rest.trim_start();
        let header = if let Some(q) = rest.strip_prefix('"') {
            q.find('"').map(|end| &q[..end])
        } else if let Some(a) = rest.strip_prefix('<') {
            a.find('>').map(|end| &a[..end])
        } else {
            None
        };
        let Some(header) = header.map(str::trim).filter(|h| !h.is_empty()) else {
            continue;
        };
        // A source may textually include implementation fragments under setup
        // macros (mimalloc's alloc.c includes alloc-override.c/free.c). The real
        // target TU already pulls them in at the correct point; emitting them as
        // standalone harness includes loses that context and triggers their
        // defensive `#error` guards or duplicate definitions.
        if is_partial_impl_header(header) || is_translation_unit_include(header) {
            continue;
        }
        let header = header.to_owned();
        if includes.contains(&header) {
            continue;
        }
        let Some(resolved) = include_dirs
            .iter()
            .map(|dir| dir.join(&header))
            .find(|p| p.is_file())
        else {
            continue;
        };
        // A feature-gated OpenMP source TU (`#pragma omp` / `<omp.h>`) only compiles
        // with `-fopenmp`; the harness never enables it, so dropping it from the
        // include closure keeps the core target buildable (base64 `lib_openmp.c`).
        if is_openmp_translation_unit(&resolved) {
            continue;
        }
        includes.push(header);
    }
    includes
}

/// Cap on transitive header-closure traversal (mirrors the type-def closure).
const MAX_TRANSITIVE_HEADERS: usize = 256;

/// Project `#include`s for the harness, expanded to the TRANSITIVE closure and
/// ordered dependencies-first: a non-self-contained leaf header (mavlink's
/// `common/mavlink_msg_attitude.h`) needs the umbrella/types header it includes
/// to be `#include`d BEFORE it, or neither the types nor the target resolve.
fn harness_project_includes(source: &str, include_dirs: &[PathBuf]) -> Vec<String> {
    let mut ordered = Vec::new();
    let mut visited = std::collections::HashSet::new();
    for header in direct_project_includes(source, include_dirs) {
        visit_include_closure(&header, include_dirs, &mut ordered, &mut visited, true);
    }
    ordered
}

fn ordered_c_harness_headers(
    source_path: &Path,
    target_dir: &Path,
    source: &str,
    include_dirs: &[PathBuf],
) -> Vec<String> {
    // Emit the target source's direct includes in their original order. Nested
    // headers must be left to their parent so they are processed in the same
    // macro/type context as the real translation unit. Flattening a transitive
    // closure here can move a late include ahead of definitions in its parent
    // (Chocolate Doom's h2def.h defines mobj_t before including p_action.h).
    // Type discovery still walks the transitive closure separately.
    let mut headers = direct_project_includes(source, include_dirs);
    for header in auto_detect_c_headers(source_path, target_dir) {
        if !headers.contains(&header) {
            headers.push(header);
        }
    }
    headers
}

/// Post-order DFS: push a header's own resolvable includes (its dependencies)
/// before the header itself, so the emitted include list compiles top-to-bottom.
fn visit_include_closure(
    header: &str,
    include_dirs: &[PathBuf],
    ordered: &mut Vec<String>,
    visited: &mut std::collections::HashSet<String>,
    is_root: bool,
) {
    if ordered.len() >= MAX_TRANSITIVE_HEADERS || !visited.insert(header.to_owned()) {
        return;
    }
    if let Some(path) = include_dirs
        .iter()
        .map(|dir| dir.join(header))
        .find(|p| p.is_file())
    {
        if let Ok(src) = crate::source_text::read_source_text(&path) {
            // Umbrella-only headers deliberately fail when included directly
            // (XZ's lzma/*.h children require lzma.h to define LZMA_H_INTERNAL).
            // Their umbrella already includes them in the correct macro context;
            // emitting them dependencies-first defeats that contract.
            if header_rejects_direct_include(&src) {
                return;
            }
            // A transitive legacy header without an include guard must be left to
            // its parent. Emitting it here and then emitting the parent includes
            // it twice (Chocolate Doom's h2def.h -> generated info.h), producing
            // duplicate enums/definitions before recovery can reach the target.
            if !is_root && !header_has_include_guard(&src) {
                return;
            }
            for dep in direct_project_includes(&src, include_dirs) {
                if dep != header {
                    visit_include_closure(&dep, include_dirs, ordered, visited, false);
                }
            }
        }
    }
    if !ordered.contains(&header.to_owned()) {
        ordered.push(header.to_owned());
    }
}

fn header_has_include_guard(source: &str) -> bool {
    if source
        .lines()
        .any(|line| line.trim_start().starts_with("#pragma once"))
    {
        return true;
    }

    let mut guard = None;
    for line in source.lines().take(80) {
        let directive = line.trim_start().strip_prefix('#').map(str::trim_start);
        if let Some(name) = directive.and_then(|d| d.strip_prefix("ifndef")) {
            guard = name.split_whitespace().next().map(str::to_owned);
            continue;
        }
        if let (Some(expected), Some(name)) = (
            guard.as_deref(),
            directive.and_then(|d| d.strip_prefix("define")),
        ) {
            if name.split_whitespace().next() == Some(expected) {
                return true;
            }
        }
    }
    false
}

pub(crate) fn header_rejects_direct_include(source: &str) -> bool {
    source.lines().any(|line| {
        let Some(message) = line
            .trim_start()
            .strip_prefix('#')
            .map(str::trim_start)
            .and_then(|directive| directive.strip_prefix("error"))
        else {
            return false;
        };
        let message = message.to_ascii_lowercase();
        (message.contains("include") && message.contains("direct"))
            || (message.contains("only") && message.contains("internal"))
    })
}

/// Prove that a header target can be consumed by the independent translation
/// unit emitted for a harness. A compile database can tell us which flags an
/// owning TU used, but those flags do not reproduce declarations or macro state
/// established *inside* that TU before it included the header. When the direct
/// include fails, prefer a project umbrella that includes the target in its
/// intended context. If no such include compiles, stop before harness emission:
/// repair-loop typedef/macro guesses cannot make an owner-TU fragment into a
/// public standalone interface.
fn standalone_header_include_plan(
    target: &Path,
    direct_includes: &[String],
    include_dirs: &[PathBuf],
    compile_flags: &[String],
    cpp: bool,
) -> Result<Vec<String>> {
    debug_assert!(is_c_family_header(target));
    match preflight_header_includes(direct_includes, include_dirs, compile_flags, cpp) {
        HeaderPreflight::Passed | HeaderPreflight::Unavailable => {
            return Ok(direct_includes.to_vec());
        }
        HeaderPreflight::Failed(_) => {}
    }

    for umbrella in umbrella_headers_for_target(target, include_dirs) {
        match preflight_header_includes(
            std::slice::from_ref(&umbrella),
            include_dirs,
            compile_flags,
            cpp,
        ) {
            HeaderPreflight::Passed => return Ok(vec![umbrella]),
            HeaderPreflight::Failed(_) | HeaderPreflight::Unavailable => {}
        }
    }

    let diagnostic =
        match preflight_header_includes(direct_includes, include_dirs, compile_flags, cpp) {
            HeaderPreflight::Failed(diagnostic) => diagnostic,
            HeaderPreflight::Passed | HeaderPreflight::Unavailable => {
                "preflight unavailable".to_owned()
            }
        };
    bail!(
        "{BLOCKED_BY_NON_SELF_CONTAINED_HEADER} '{}' cannot be included by an independent {} \
         harness translation unit under its recovered build flags, and no compiling project \
         umbrella was found; it likely depends on declarations or macro state established by \
         an owning source file before inclusion. Compiler preflight: {}",
        target.display(),
        if cpp { "C++" } else { "C" },
        diagnostic
    )
}

#[derive(Debug, PartialEq, Eq)]
enum HeaderPreflight {
    Passed,
    Failed(String),
    Unavailable,
}

fn preflight_header_includes(
    includes: &[String],
    include_dirs: &[PathBuf],
    compile_flags: &[String],
    cpp: bool,
) -> HeaderPreflight {
    let mut compiler = if cpp { "clang++" } else { "clang" }.to_owned();
    let mut flags = Vec::new();
    let mut index = 0;
    while let Some(flag) = compile_flags.get(index) {
        if let Some(value) = flag.strip_prefix(BUILD_CONTEXT_COMPILER_PREFIX) {
            compiler = value.to_owned();
        } else if let Some(value) = flag.strip_prefix(BUILD_CONTEXT_CXX_STANDARD_PREFIX) {
            flags.push(format!("-std={value}"));
        } else if flag.starts_with('@') {
            // Remaining @govfuzz entries are Makefile/report metadata, never
            // compiler arguments.
        } else if flag == "-x" {
            // The preflight's explicit language below is authoritative.
            index += 1;
        } else {
            flags.push(flag.clone());
        }
        index += 1;
    }
    for include_dir in include_dirs {
        flags.push("-I".to_owned());
        flags.push(include_dir.to_string_lossy().to_string());
    }
    if cpp {
        // The real build repairs mixed Clang/GCC installations whose clang++
        // cannot find the installed libstdc++ headers by default. Apply the
        // same recovery here; otherwise a self-contained project header is
        // falsely rejected on `<string>` before harness generation starts.
        flags.extend(crate::build::detect_cpp_stdlib_include_flags_for(
            &compiler, &flags,
        ));
    }
    flags.extend([
        "-fsyntax-only".to_owned(),
        "-x".to_owned(),
        if cpp { "c++" } else { "c" }.to_owned(),
        "-".to_owned(),
    ]);

    let mut command = std::process::Command::new(&compiler);
    command
        .args(&flags)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    let Ok(mut child) = command.spawn() else {
        return HeaderPreflight::Unavailable;
    };
    let mut source = if cpp {
        // Mirror the essential defensive prelude emitted before project
        // headers in direct_harness.cpp.tera. Legacy header-only libraries may
        // intentionally rely on these transitive standard declarations (for
        // example std::numeric_limits and std::size_t), so testing the header
        // without the prelude would reject a harness that actually compiles.
        "#include <limits>\n#include <cstddef>\n".to_owned()
    } else {
        String::new()
    };
    source.push_str(
        &includes
            .iter()
            .map(|include| format!("#include \"{include}\"\n"))
            .collect::<String>(),
    );
    let Some(mut stdin) = child.stdin.take() else {
        return HeaderPreflight::Unavailable;
    };
    if std::io::Write::write_all(&mut stdin, source.as_bytes()).is_err() {
        return HeaderPreflight::Unavailable;
    }
    drop(stdin);
    let Ok(output) = child.wait_with_output() else {
        return HeaderPreflight::Unavailable;
    };
    if output.status.success() {
        HeaderPreflight::Passed
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let diagnostic = stderr
            .lines()
            .filter(|line| !line.trim().is_empty())
            .take(6)
            .collect::<Vec<_>>()
            .join(" | ");
        HeaderPreflight::Failed(if diagnostic.is_empty() {
            format!("{compiler} exited with {}", output.status)
        } else {
            diagnostic
        })
    }
}

/// Locate bounded, deterministic umbrella candidates that directly include the
/// target header. Returning spellings relative to an actual include root means
/// the exact string proven here is the one emitted in the harness.
fn umbrella_headers_for_target(target: &Path, include_dirs: &[PathBuf]) -> Vec<String> {
    fn collect(dir: &Path, depth: usize, remaining: &mut usize, out: &mut Vec<PathBuf>) {
        if depth > 3 || *remaining == 0 {
            return;
        }
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        let mut entries = entries.flatten().collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            if *remaining == 0 {
                return;
            }
            let path = entry.path();
            if path.is_dir() {
                if !entry.file_name().to_string_lossy().starts_with('.') {
                    collect(&path, depth + 1, remaining, out);
                }
            } else if is_c_family_header(&path) {
                *remaining -= 1;
                out.push(path);
            }
        }
    }

    let target_key = normalized_path_key(target);
    let mut matches = Vec::<(usize, String)>::new();
    let mut seen = HashSet::new();
    for root in include_dirs {
        let mut candidates = Vec::new();
        let mut remaining = 512;
        collect(root, 0, &mut remaining, &mut candidates);
        for candidate in candidates {
            let candidate_key = normalized_path_key(&candidate);
            if candidate_key == target_key || !seen.insert(candidate_key) {
                continue;
            }
            let Ok(text) = crate::source_text::read_source_text(&candidate) else {
                continue;
            };
            let mut resolution_dirs = candidate
                .parent()
                .map(Path::to_path_buf)
                .into_iter()
                .collect::<Vec<_>>();
            for directory in include_dirs {
                if !resolution_dirs.contains(directory) {
                    resolution_dirs.push(directory.clone());
                }
            }
            if !direct_project_includes(&text, &resolution_dirs)
                .iter()
                .any(|spelling| {
                    resolution_dirs.iter().any(|directory| {
                        normalized_path_key(&directory.join(spelling)) == target_key
                    })
                })
            {
                continue;
            }
            let Some(relative) = root
                .canonicalize()
                .ok()
                .and_then(|canonical_root| {
                    candidate.canonicalize().ok().map(|p| (canonical_root, p))
                })
                .and_then(|(canonical_root, candidate)| {
                    candidate
                        .strip_prefix(canonical_root)
                        .ok()
                        .map(Path::to_path_buf)
                })
            else {
                continue;
            };
            matches.push((
                relative.components().count(),
                relative.to_string_lossy().replace('\\', "/"),
            ));
        }
    }
    matches.sort();
    matches.dedup_by(|left, right| left.1 == right.1);
    matches.into_iter().map(|(_, spelling)| spelling).collect()
}

fn quoted_local_includes(source: &str) -> Vec<String> {
    let mut includes = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("#include") else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(quoted) = rest.strip_prefix('"') else {
            continue;
        };
        let Some(end) = quoted.find('"') else {
            continue;
        };
        let header = quoted[..end].trim();
        if header.is_empty() {
            continue;
        }
        let header = header.to_owned();
        if !includes.contains(&header) {
            includes.push(header);
        }
    }
    includes
}

fn run_cpp_direct(args: &GenerateHarnessArgs) -> Result<()> {
    if !matches!(args.kind.as_str(), "direct" | "sequence") {
        bail!("C++ harness emitter supports --kind direct or --kind sequence");
    }

    let source_path = absolutize(&args.source)
        .with_context(|| format!("resolve C++ source {}", args.source.display()))?;
    let source = crate::source_text::read_source_text(&source_path)
        .with_context(|| format!("read C++ source {}", source_path.display()))?;
    let mut functions = cpp_parser::parse_cpp_functions(&source)
        .with_context(|| format!("parse C++ source {}", source_path.display()))?;
    let target_name = args
        .target
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--target is required for C++ sources"))?;
    let (mut function, warning) = pick_cpp_target(
        &source_path,
        functions.clone(),
        target_name,
        args.target_line,
    )?;
    if let Some(warning) = warning {
        eprintln!("{warning}");
    }

    // §27.5 phase 3: steer a templated target with no call-site-detected
    // instantiation via `--template-instantiate int,std::string`. A call-site
    // instantiation (resolved by the parser) takes precedence; the flag only
    // fills in when the parser found none. Arity must match the template's
    // declared type parameters so the substitution is well-formed.
    if function.api.is_template
        && function.instantiation_args.is_empty()
        && !args.template_instantiate.is_empty()
    {
        if args.template_instantiate.len() == function.template_type_params.len() {
            function.instantiation_args = args.template_instantiate.clone();
        } else {
            bail!(
                "--template-instantiate expects {} type argument(s) for template '{}' \
                 (its type parameters are {:?}), got {}: {:?}",
                function.template_type_params.len(),
                target_name,
                function.template_type_params,
                args.template_instantiate.len(),
                args.template_instantiate
            );
        }
    }

    let id = args
        .id
        .clone()
        .unwrap_or_else(|| format!("H-CPP{:04X}", function.line));
    let output_dir = args.output.join(&id);
    let params = function
        .params
        .iter()
        .map(|p| harness_gen::cpp_generate::CppParameter {
            name: p.name.clone(),
            cpp_type: p.cpp_type.clone(),
        })
        .collect();
    let c_runtime_include = locate_c_runtime();
    let target_dir = source_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let static_direct_target = args.kind == "direct"
        && function.is_static
        && !function.api.is_method
        && !is_c_family_header(&source_path);
    let mut target_includes = auto_detect_c_headers(&source_path, &target_dir);
    let mut target_sources = if static_direct_target {
        Vec::new()
    } else {
        target_compile_sources(&source_path)
    };
    let build_context = cpp_build_context_for_source(&source_path);
    let compile_flags = build_context.encoded_flags();
    let eager_context_sources =
        if build_context.extra_sources.len() <= MAX_EAGER_BUILD_CONTEXT_SOURCES {
            build_context.extra_sources.as_slice()
        } else {
            &[]
        };
    for inferred in eager_context_sources {
        if static_direct_target && inferred == &source_path {
            continue;
        }
        if !target_sources.contains(inferred) {
            target_sources.push(inferred.clone());
        }
    }
    for extra in &args.extra_sources {
        target_sources.push(absolutize(extra).unwrap_or_else(|_| extra.clone()));
    }
    let mut target_includes_dirs = vec![target_dir.clone()];
    for project_inc in auto_detect_project_includes(&source_path) {
        if !target_includes_dirs.contains(&project_inc) {
            target_includes_dirs.push(project_inc);
        }
    }
    // Self-prefixed includes (`libde265/de265.cc` -> `#include "libde265/vps.h"`):
    // add the dir containing the prefix so the build doesn't fail "file not found"
    // before the AddSource link-closure can run.
    for self_inc in self_prefixed_include_roots(&source_path) {
        if !target_includes_dirs.contains(&self_inc) {
            target_includes_dirs.push(self_inc);
        }
    }
    for compile_inc in include_dirs_from_compile_flags(&compile_flags) {
        if !target_includes_dirs.contains(&compile_inc) {
            target_includes_dirs.push(compile_inc);
        }
    }
    // §26.8: CMake-generated export/config headers land in the probe/build dir,
    // which the per-file compile_commands `-I` set can miss; add the build/probe
    // dirs that hold generated headers to the harness include path.
    for gen_inc in probe_generated_header_dirs(&source_path) {
        if !target_includes_dirs.contains(&gen_inc) {
            target_includes_dirs.push(gen_inc);
        }
    }
    for extra in &args.extra_includes {
        let abs = absolutize(extra).unwrap_or_else(|_| extra.clone());
        if !target_includes_dirs.contains(&abs) {
            target_includes_dirs.push(abs);
        }
    }
    for header in harness_project_includes(&source, &target_includes_dirs) {
        if !target_includes.contains(&header) {
            target_includes.push(header);
        }
    }
    if static_direct_target {
        let source_include = source_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("static C++ source path is not valid UTF-8"))?
            .to_owned();
        if !target_includes.contains(&source_include) {
            target_includes.push(source_include);
        }
    }
    if is_c_family_header(&source_path) {
        target_includes = standalone_header_include_plan(
            &source_path,
            &target_includes,
            &target_includes_dirs,
            &compile_flags,
            true,
        )?;
    }
    // Read the included header texts once, so `<X>_NAMESPACE_BEGIN` macros can be
    // resolved ACROSS the set (nlohmann's is defined in `abi_macros.hpp` and invoked
    // everywhere else). The macro-opened top-level namespace (`nlohmann`) is emitted
    // before the nested ones (`detail`) so they resolve transitively.
    let header_texts: Vec<String> = target_includes
        .iter()
        .filter_map(|h| {
            target_includes_dirs.iter().find_map(|dir| {
                let header = dir.join(h);
                header
                    .is_file()
                    .then(|| std::fs::read_to_string(&header).ok())
                    .flatten()
            })
        })
        .collect();
    let begin_macros = cpp_namespace_begin_macros(&header_texts);
    let using_namespaces = collect_cpp_using_namespaces(&header_texts, &begin_macros);
    let mut closure_texts = collect_cpp_inheritance_texts(
        &source_path,
        &source,
        &target_includes,
        &target_includes_dirs,
    );
    for context_source in &target_sources {
        if normalized_path_key(context_source) == normalized_path_key(&source_path) {
            continue;
        }
        if let Ok(text) = crate::source_text::read_source_text(context_source) {
            closure_texts.push(text);
        }
    }
    extend_cpp_functions_from_closure(&mut functions, &closure_texts);
    resolve_cpp_namespace_qualified_free_functions(&mut functions, &header_texts);
    // Out-of-line member definitions in this `.cpp` have no access specifier, so
    // their `member_access` came back None; resolve it from the class declarations
    // in the header include closure before building lifecycle setup steps.
    resolve_cpp_member_access_from_headers(
        &mut functions,
        &source_path,
        &target_includes,
        &target_includes_dirs,
    );
    if let Some(resolved) = functions.iter().find(|candidate| {
        candidate.name == function.name
            && candidate.line == function.line
            && candidate.qualifier_path == function.qualifier_path
    }) {
        function.api = resolved.api.clone();
        function.is_static = resolved.is_static;
    }
    let mut type_defs = collect_cpp_type_defs_for_harness(
        &source_path,
        &source,
        &target_includes,
        &target_includes_dirs,
    );
    // Tree-wide fallback (see the C path): resolve types the include closure
    // left opaque, without overriding any in-scope definition.
    if let Some(tree) = &args.tree_type_defs {
        type_defs.push((*tree.cpp).clone());
    }
    let class_infos = collect_cpp_class_info_for_harness(&closure_texts);
    suppress_non_aggregate_cpp_class_defs(&mut type_defs, &class_infos);
    // Judge the receiver's constructor against the FULL include-closure type defs:
    // a project typedef alias used in a ctor parameter (libE57Format's reader takes
    // `const ustring &filePath`, `using ustring = std::string;`) is declared in a
    // header, not the target `.cpp`, so the receiver is only seen as constructible
    // once the header's aliases are in the registry.
    let cpp_lookup_scopes = (1..=function.qualifier_path.len())
        .rev()
        .map(|length| function.qualifier_path[..length].join("::"))
        .collect::<Vec<_>>();
    let ctor_registry = type_model::TypeRegistry::from_defs(type_defs.iter())
        .with_cpp_lookup_scopes(cpp_lookup_scopes.clone());
    let (
        constructor_params,
        _receiver_constructor_default_classes,
        receiver_class_override,
        factory_plan,
    ) = if function.api.class_name.is_some() && !function.is_static {
        // #456 / §27.4: the abstract base + its concrete subclass commonly live
        // in headers, so resolve them across the include closure, not just the
        // target `.cpp`.
        cpp_receiver_constructor_params(&function, &functions, &closure_texts, &ctor_registry)?
    } else {
        (
            Vec::<harness_gen::cpp_generate::CppParameter>::new(),
            Vec::<String>::new(),
            None::<String>,
            None::<harness_gen::cpp_generate::CppFactoryPlan>,
        )
    };
    // Register default-constructible classes used by the TARGET call as well as
    // receiver/setup/factory calls. Previously this list was populated only from
    // receiver-constructor arguments, so a perfectly ordinary
    // `parse(const ns::Options &)` was rejected as an opaque Phase-C parameter.
    // Facts come from parsed class declarations across the full include closure;
    // private/deleted/abstract classes and same-leaf namespace ambiguities are
    // intentionally not registered.
    let mut parameter_types = function
        .params
        .iter()
        .map(|parameter| parameter.cpp_type.clone())
        .chain(
            constructor_params
                .iter()
                .map(|parameter| parameter.cpp_type.clone()),
        )
        .collect::<Vec<_>>();
    if let Some(factory) = &factory_plan {
        parameter_types.extend(
            factory
                .factory_params
                .iter()
                .map(|parameter| parameter.cpp_type.clone()),
        );
    }
    // Sequence setup candidates are filtered later, but registering a class is
    // harmless and lets that filter use the same safe declaration-level fact.
    if args.kind == "sequence" {
        parameter_types.extend(
            functions
                .iter()
                .flat_map(|candidate| candidate.params.iter())
                .map(|parameter| parameter.cpp_type.clone()),
        );
    }
    let default_constructible_classes = cpp_default_constructible_parameter_classes(
        &parameter_types,
        &function.api.namespace_path,
        &class_infos,
    );
    // #99: resolve construction recipes for opaque class parameters that are not
    // default-constructible but can be built via a public factory or parameterized
    // constructor from the include closure. Computed before `type_defs` is moved
    // into `common`, against the same registry the emitter uses (minus recipes).
    let param_construction_registry = type_model::TypeRegistry::from_defs(type_defs.iter())
        .with_cpp_lookup_scopes(cpp_lookup_scopes.clone())
        .with_default_constructible_classes(default_constructible_classes.iter().cloned());
    let parameter_constructions = resolve_cpp_parameter_constructions(
        &function,
        &functions,
        &closure_texts,
        &class_infos,
        &param_construction_registry,
        &args.decoder_limits.cpp_limits(),
        &crate::auto::recipe_mining::for_source(&source_path),
    );
    let dictionary_tokens = collect_cpp_dictionary_tokens_for_harness(
        &source_path,
        &source,
        &target_includes,
        &target_includes_dirs,
    );
    // Auto-detect a result cleanup for the C++ lane too (the C path does the
    // same): a C library compiled as C++ (utf8.h's `utf8dup`/`utf8ndup` return a
    // malloc'd buffer) otherwise leaks its result on every input — a CWE-401
    // false positive. An explicit `--cleanup` still wins; genuine C++ factories
    // returning a `new`'d object need `--cleanup "delete R"` (these heuristics
    // only recognize C-style `free`/`<type>_free` deallocators).
    let cpp_target_dir = source_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let result_cleanup = args
        .cleanup
        .clone()
        .or_else(|| auto_detect_c_result_cleanup(&function.return_type, &function.name))
        .or_else(|| {
            let param_types: Vec<String> =
                function.params.iter().map(|p| p.cpp_type.clone()).collect();
            detect_paired_deallocator(
                &function.return_type,
                &function.name,
                &param_types,
                &cpp_target_dir,
                &source_path,
            )
        })
        .or_else(|| detect_strdup_family_free(&function.return_type, &function.name));
    let mut per_tu_contexts = partition_per_tu_compile_contexts(&mut target_sources);
    let emitted_path = if args.kind == "sequence" {
        "sequence"
    } else if factory_plan.is_some() {
        "factory_receiver"
    } else if function.api.class_name.is_some() {
        "constructed_receiver"
    } else {
        "free_direct"
    };
    let common = CppHarnessGenerationCommon {
        harness_id: id,
        output_dir: output_dir.clone(),
        source_path: source_path.clone(),
        target: function.clone(),
        params,
        return_type: function.return_type.clone(),
        target_includes,
        target_includes_dirs,
        target_sources,
        compile_flags,
        c_runtime_include,
        using_namespaces,
        result_cleanup,
        type_defs,
    };
    let result = if args.kind == "sequence" {
        let lifecycle_registry = type_model::TypeRegistry::from_defs(common.type_defs.iter())
            .with_cpp_lookup_scopes(cpp_lookup_scopes)
            .with_default_constructible_classes(default_constructible_classes.iter().cloned());
        let lifecycle_steps = cpp_lifecycle_steps(
            &function,
            &functions,
            &lifecycle_registry,
            &args.decoder_limits.cpp_limits(),
        )?;
        if lifecycle_steps.is_empty() && constructor_params.is_empty() && factory_plan.is_none() {
            // A target-only "sequence" is just a more fragile direct harness.
            // In auto mode, returning an error activates generate_harness_for's
            // direct fallback immediately instead of compiling an empty sequence
            // first. Keep parameterized-constructor/factory sequences: their
            // receiver setup is itself meaningful lifecycle state.
            bail!(
                "no callable public C++ lifecycle setup methods found for '{}::{}'",
                function.api.class_name.as_deref().unwrap_or("<unknown>"),
                function.name
            );
        }
        harness_gen::cpp_generate::generate_cpp_sequence_harness(
            harness_gen::cpp_generate::GenerateCppSequenceArgs {
                harness_id: common.harness_id,
                output_dir: common.output_dir,
                source_path: common.source_path,
                target: common.target,
                params: common.params,
                return_type: common.return_type,
                target_includes: common.target_includes,
                target_includes_dirs: common.target_includes_dirs,
                target_sources: common.target_sources,
                compile_flags: common.compile_flags,
                c_runtime_include: common.c_runtime_include,
                using_namespaces: common.using_namespaces,
                result_cleanup: common.result_cleanup,
                constructor_params,
                lifecycle_steps,
                type_defs: common.type_defs,
                default_constructible_classes,
                parameter_constructions,
                receiver_class_override: receiver_class_override.clone(),
                factory_plan: factory_plan.clone(),
                decoder_limits: args.decoder_limits.cpp_limits(),
            },
        )
    } else {
        // GAP-R: discover FREE-function init/delete lifecycles so an opaque-handle
        // decode entry (libde265 `de265_decode_data(de265_decoder_context *, const
        // void *, int)`) can build its handle via `de265_new_decoder` /
        // `de265_free_decoder` instead of being skipped "needs lifecycle support".
        let handle_lifecycle = cpp_direct_lifecycle_table(
            &functions,
            &type_model::TypeRegistry::from_defs(common.type_defs.iter()),
        );
        harness_gen::cpp_generate::generate_cpp_direct_harness_with_lifecycle(
            harness_gen::cpp_generate::GenerateCppDirectArgs {
                harness_id: common.harness_id,
                output_dir: common.output_dir,
                source_path: common.source_path,
                target: common.target,
                params: common.params,
                return_type: common.return_type,
                target_includes: common.target_includes,
                target_includes_dirs: common.target_includes_dirs,
                target_sources: common.target_sources,
                compile_flags: common.compile_flags,
                c_runtime_include: common.c_runtime_include,
                using_namespaces: common.using_namespaces,
                result_cleanup: common.result_cleanup,
                constructor_params,
                type_defs: common.type_defs,
                default_constructible_classes,
                parameter_constructions,
                receiver_class_override: receiver_class_override.clone(),
                factory_plan,
                decoder_limits: args.decoder_limits.cpp_limits(),
                force: args.force,
            },
            &handle_lifecycle,
        )
    }?;
    // The C++ emitter may include a header-less implementation file directly in
    // `main.cpp` when its exact type declaration is required (references, STL
    // aliases, receivers, or templates). `target_sources` is moved into the
    // emitter, which removes that source from its shared link list, but the
    // per-TU graph was partitioned before that decision. Drop the same target
    // here or it is defined once through the include and once through the object,
    // producing a false multiple-definition linker failure.
    discard_cpp_context_for_included_target(&mut per_tu_contexts, &result.main_cpp, &source_path)?;
    write_cpp_per_tu_context(&output_dir, &per_tu_contexts)?;
    write_harness_dictionary(&output_dir, &dictionary_tokens)?;
    write_generation_metadata(
        &output_dir,
        "cpp",
        args.target_line,
        function.line,
        &args.kind,
        emitted_path,
    )?;
    if generation_banner_enabled() {
        println!(
            "Generated C++ harness '{}' at {}",
            result.harness_id,
            output_dir.display()
        );
        println!("  main.cpp -> {}", result.main_cpp.display());
        println!("  Makefile -> {}", result.makefile.display());
    }
    Ok(())
}

struct CppHarnessGenerationCommon {
    harness_id: String,
    output_dir: PathBuf,
    source_path: PathBuf,
    target: cpp_parser::CppFunction,
    params: Vec<harness_gen::cpp_generate::CppParameter>,
    return_type: String,
    target_includes: Vec<String>,
    target_includes_dirs: Vec<PathBuf>,
    target_sources: Vec<PathBuf>,
    compile_flags: Vec<String>,
    c_runtime_include: PathBuf,
    using_namespaces: Vec<String>,
    result_cleanup: Option<String>,
    type_defs: Vec<c_parser::CTypeDefs>,
}

fn cpp_lifecycle_steps(
    target: &cpp_parser::CppFunction,
    functions: &[cpp_parser::CppFunction],
    registry: &type_model::TypeRegistry,
    decoder_limits: &harness_gen::cpp_generate::CppDecoderLimits,
) -> Result<Vec<harness_gen::cpp_generate::CppLifecycleStep>> {
    let Some(class_name) = target.api.class_name.as_deref() else {
        bail!("C++ --kind sequence requires a class method target");
    };
    let namespace_path = &target.api.namespace_path;

    let mut steps = Vec::new();
    for function in functions {
        if function.line == target.line && function.name == target.name {
            continue;
        }
        if function.api.class_name.as_deref() != Some(class_name)
            || &function.api.namespace_path != namespace_path
        {
            continue;
        }
        if function.api.is_constructor || function.api.is_destructor || function.api.is_template {
            continue;
        }
        // Robustness (campaign: tinyobjloader): never select a step the emitter
        // could only render as an uncompilable `receiver.<step>(...)` — a
        // non-identifier name or a parse-artifact return type (`namespace` from a
        // mis-recovered `namespace X {`). The parser reconciliation normally evicts
        // these upstream; drop any residual so the lifecycle harness still builds.
        if !harness_gen::cpp_generate::cpp_callable_member_name(&function.name)
            || !harness_gen::cpp_generate::cpp_return_type_emittable(&function.return_type)
        {
            eprintln!(
                "warning: skipped C++ lifecycle step '{}': not a validly callable member \
                 (parse-recovery artifact)",
                function.name
            );
            continue;
        }
        // A lifecycle setup method must be KNOWN-public to be safely callable
        // from the harness. Require `Some("public")` rather than merely "not
        // known-private": an out-of-line member definition (e.g.
        // `bool C::validate_header_quick(...) const { ... }` in the .cpp) has no
        // enclosing access specifier, so its access comes from the in-class
        // declaration via the member-access map — and when that lookup misses,
        // `member_access` is None. Treating None as callable leaked private
        // methods (basis_universal's `validate_header_quick`,
        // `read_slice_offset_len_global_data`, …) into the harness, breaking the
        // build with "is a private member". Public methods like
        // `start_transcoding` resolve correctly, so requiring known-public drops
        // only the unsafe/unknown steps and still builds a working lifecycle.
        if function.api.member_access.as_deref() != Some("public") {
            eprintln!(
                "warning: skipped C++ lifecycle step '{}': {} method is not known to be public",
                function.name,
                function
                    .api
                    .member_access
                    .as_deref()
                    .unwrap_or("unresolved")
            );
            continue;
        }
        if let Some(unsupported) = function
            .params
            .iter()
            .find(|param| {
                !harness_gen::cpp_generate::cpp_parameter_type_supported_with_registry(
                    &param.cpp_type,
                    registry,
                    decoder_limits,
                )
            })
            .map(|param| param.cpp_type.clone())
        {
            eprintln!(
                "warning: skipped C++ lifecycle step '{}': unsupported parameter type '{}'",
                function.name, unsupported
            );
            continue;
        }
        steps.push(harness_gen::cpp_generate::CppLifecycleStep {
            name: function.name.clone(),
            params: function
                .params
                .iter()
                .map(|param| harness_gen::cpp_generate::CppParameter {
                    name: param.name.clone(),
                    cpp_type: param.cpp_type.clone(),
                })
                .collect(),
            return_type: function.return_type.clone(),
        });
        if steps.len() >= 8 {
            break;
        }
    }
    Ok(steps)
}

fn collect_cpp_class_info_for_harness(texts: &[String]) -> Vec<cpp_parser::CppClassInfo> {
    let mut by_qualified = std::collections::BTreeMap::<String, cpp_parser::CppClassInfo>::new();
    for text in texts {
        for info in cpp_parser::parse_cpp_class_info(text).unwrap_or_default() {
            match by_qualified.get(&info.qualified_name) {
                Some(existing) if existing.complete || !info.complete => {}
                _ => {
                    by_qualified.insert(info.qualified_name.clone(), info);
                }
            }
        }
    }
    by_qualified.into_values().collect()
}

/// Extract the class spelling the decoder must initialize. References and
/// output pointers both use a live default-constructed object; templates and
/// function pointers are handled by dedicated decoders and are not class facts.
fn cpp_parameter_class_spelling(cpp_type: &str) -> Option<String> {
    let mut spelling = cpp_type.split_whitespace().collect::<Vec<_>>().join(" ");
    if spelling.contains('<') || spelling.contains('(') || spelling.contains('[') {
        return None;
    }
    loop {
        let before = spelling.clone();
        spelling = spelling
            .trim()
            .trim_start_matches("const ")
            .trim_start_matches("volatile ")
            .trim_start_matches("class ")
            .trim_start_matches("struct ")
            .trim_end_matches(" const")
            .trim_end_matches(" volatile")
            .trim_end_matches('&')
            .trim_end_matches('*')
            .trim()
            .to_owned();
        if spelling == before {
            break;
        }
    }
    let spelling = spelling.trim_start_matches("::").trim().to_owned();
    (!spelling.is_empty()
        && spelling.split("::").all(|segment| {
            let mut chars = segment.chars();
            chars
                .next()
                .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
                && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        }))
    .then_some(spelling)
}

pub(crate) fn cpp_default_constructible_parameter_classes(
    parameter_types: &[String],
    target_namespace: &[String],
    class_infos: &[cpp_parser::CppClassInfo],
) -> Vec<String> {
    let mut registered = std::collections::BTreeSet::new();
    for parameter_type in parameter_types {
        let Some(spelling) = cpp_parameter_class_spelling(parameter_type) else {
            continue;
        };
        let leaf = spelling.rsplit("::").next().unwrap_or(&spelling);
        let resolved = if spelling.contains("::") {
            class_infos
                .iter()
                .find(|info| info.qualified_name == spelling)
        } else {
            let in_target_namespace = if target_namespace.is_empty() {
                spelling.clone()
            } else {
                format!("{}::{spelling}", target_namespace.join("::"))
            };
            class_infos
                .iter()
                .find(|info| info.qualified_name == in_target_namespace)
                .or_else(|| {
                    let mut leaf_matches = class_infos.iter().filter(|info| info.name == leaf);
                    let only = leaf_matches.next()?;
                    leaf_matches.next().is_none().then_some(only)
                })
        };
        if resolved.is_some_and(cpp_parser::CppClassInfo::has_public_default_constructor) {
            // Store the spelling that appears in the signature: the decoder's
            // registry lookup is performed after cv/ref/pointer stripping.
            registered.insert(spelling);
        }
    }
    registered.into_iter().collect()
}

/// Known-unbuildable C++ signatures for discovery ranking. This uses the same
/// local include/type/default-constructor context as generation, but only returns
/// a negative verdict when the type is actually declared (or is an explicitly
/// unsupported function/template shape). Missing external include context stays
/// "unknown" and is not demoted.
pub(crate) fn cpp_known_blocked_signatures_for_discovery(
    source_path: &Path,
    source: &str,
    functions: &[cpp_parser::CppFunction],
) -> std::collections::HashSet<(u32, String)> {
    let target_dir = source_path.parent().unwrap_or_else(|| Path::new("."));
    let mut include_dirs = vec![target_dir.to_path_buf()];
    for include in auto_detect_project_includes(source_path) {
        if !include_dirs.contains(&include) {
            include_dirs.push(include);
        }
    }
    let mut target_includes = auto_detect_c_headers(source_path, target_dir);
    for include in harness_project_includes(source, &include_dirs) {
        if !target_includes.contains(&include) {
            target_includes.push(include);
        }
    }
    let mut type_defs =
        collect_cpp_type_defs_for_harness(source_path, source, &target_includes, &include_dirs);
    let closure_texts =
        collect_cpp_inheritance_texts(source_path, source, &target_includes, &include_dirs);
    let class_infos = collect_cpp_class_info_for_harness(&closure_texts);
    suppress_non_aggregate_cpp_class_defs(&mut type_defs, &class_infos);
    let mut blocked = std::collections::HashSet::new();
    for function in functions {
        let parameter_types = function
            .params
            .iter()
            .map(|parameter| parameter.cpp_type.clone())
            .collect::<Vec<_>>();
        let defaults = cpp_default_constructible_parameter_classes(
            &parameter_types,
            &function.api.namespace_path,
            &class_infos,
        );
        let scopes = (1..=function.qualifier_path.len())
            .rev()
            .map(|length| function.qualifier_path[..length].join("::"))
            .collect::<Vec<_>>();
        // #99: the preflight must use the SAME declaration-aware construction
        // recipes as generation, or an opaque parameter that generation can build
        // via a resolved factory/constructor (use_baz/use_bar) would be wrongly
        // pre-demoted as "known blocked" while a genuinely opaque one is correctly
        // flagged. Resolve the recipes against the identical closure/type context
        // (a base registry without recipes), then re-key the probe registry WITH
        // them so the preflight verdict matches generation.
        let base_registry = type_model::TypeRegistry::from_defs(type_defs.iter())
            .with_cpp_lookup_scopes(scopes.clone())
            .with_default_constructible_classes(defaults.clone());
        let recipes = resolve_cpp_parameter_constructions(
            function,
            functions,
            &closure_texts,
            &class_infos,
            &base_registry,
            &Default::default(),
            &crate::auto::recipe_mining::for_source(source_path),
        );
        let registry = type_model::TypeRegistry::from_defs(type_defs.iter())
            .with_cpp_lookup_scopes(scopes)
            .with_default_constructible_classes(defaults)
            .with_class_constructions(recipes);
        let known_blocked = function.params.iter().any(|parameter| {
            if harness_gen::cpp_generate::cpp_parameter_type_supported_with_registry(
                &parameter.cpp_type,
                &registry,
                &Default::default(),
            ) {
                return false;
            }
            if parameter.cpp_type.contains("(*") || parameter.cpp_type.contains('<') {
                return true;
            }
            let Some(spelling) = cpp_parameter_class_spelling(&parameter.cpp_type) else {
                return false;
            };
            let leaf = spelling.rsplit("::").next().unwrap_or(&spelling);
            let scoped = if function.api.namespace_path.is_empty() {
                spelling.clone()
            } else {
                format!("{}::{spelling}", function.api.namespace_path.join("::"))
            };
            class_infos.iter().any(|info| {
                info.qualified_name == spelling
                    || info.qualified_name == scoped
                    || (class_infos
                        .iter()
                        .filter(|other| other.name == leaf)
                        .count()
                        == 1
                        && info.name == leaf)
            })
        });
        if known_blocked {
            blocked.insert((function.line, target_rank::cpp_target_name(function)));
        }
    }
    blocked
}

/// Returns `(constructor params, default-constructible class spellings)`. The
/// second list names the class-typed args that should be default-constructed by
/// the decoder layer (#353); it is empty for default/no-arg construction.
/// True when a constructor parameter is fuzzable: directly supported, a
/// default-constructible class arg, OR supported once a project typedef alias is
/// resolved. libE57Format's reader ctor is `Reader(const ustring &filePath, …)`
/// with `using ustring = std::string;` declared in a header — registry-less
/// `cpp_parameter_type_supported` can't see through the alias, so the receiver was
/// wrongly judged unconstructible. (The actual ctor-arg decoding already resolves
/// the alias via `select_cpp_decoder_with_registry`; this aligns the gate with it.)
/// Record the class-typed arguments a chosen recipe still needs, so the producer
/// graph knows what to resolve next.
///
/// Only `Constructor` recipes have unresolved needs: an `Expression` is
/// self-contained by construction.
fn note_recipe_dependencies(
    construction: &type_model::ClassConstruction,
    registry: &type_model::TypeRegistry,
    wanted: &mut Vec<String>,
) {
    let type_model::ClassConstruction::Constructor { param_types } = construction else {
        return;
    };
    for param_type in param_types {
        let Some(mut key) = harness_gen::cpp_decoders::cpp_parameter_class_key(param_type) else {
            continue;
        };
        if let Some(target) = registry.alias_target_spelling(&key) {
            if let Some(resolved) = harness_gen::cpp_decoders::cpp_parameter_class_key(&target) {
                key = resolved;
            }
        }
        wanted.push(key);
    }
}

/// Record the class-typed arguments of every public constructor of `key`,
/// whether or not one was accepted.
///
/// This is what lets the producer graph move at all. A constructor is refused
/// when a single argument is unobtainable, so if dependencies were only noted
/// from ACCEPTED recipes, the very type standing in the way would never be
/// asked about and `Parser(Config)` could never become buildable no matter how
/// buildable a `Config` is.
fn note_candidate_dependencies(
    key: &str,
    class_infos: &[cpp_parser::CppClassInfo],
    registry: &type_model::TypeRegistry,
    wanted: &mut Vec<String>,
) {
    let leaf = key.rsplit("::").next().unwrap_or(key);
    for info in class_infos
        .iter()
        .filter(|info| info.qualified_name == key || info.name == leaf)
    {
        for constructor in &info.constructors {
            if constructor.access != "public" || constructor.is_deleted {
                continue;
            }
            for param_type in &constructor.param_types {
                let Some(mut dependency) =
                    harness_gen::cpp_decoders::cpp_parameter_class_key(param_type)
                else {
                    continue;
                };
                if let Some(target) = registry.alias_target_spelling(&dependency) {
                    if let Some(resolved) =
                        harness_gen::cpp_decoders::cpp_parameter_class_key(&target)
                    {
                        dependency = resolved;
                    }
                }
                // A constructor taking its own class is a copy constructor; it
                // produces nothing new and would make the graph chase itself.
                if dependency != key && dependency != leaf {
                    wanted.push(dependency);
                }
            }
        }
    }
}

/// Whether a constructor argument can be OBTAINED — decoded from bytes directly,
/// or produced by a recipe already resolved for its own type.
///
/// `producible` carries the class keys that already have a recipe. It is what
/// turns a one-level check into a producer graph: `Parser(Config)` is buildable
/// once `Config` is, even though a `Config` is not decodable from bytes. The
/// decoder already recurses through `TypeRegistry::class_construction`; what was
/// missing was populating a recipe for anything but the target's direct
/// parameters, so the recursion had nothing to find.
fn cpp_ctor_param_obtainable(
    param_type: &str,
    registry: &type_model::TypeRegistry,
    namespace_path: &[String],
    class_infos: &[cpp_parser::CppClassInfo],
    producible: &std::collections::HashSet<String>,
) -> bool {
    if cpp_ctor_param_supported(param_type, registry, namespace_path, class_infos) {
        return true;
    }
    harness_gen::cpp_decoders::cpp_parameter_class_key(param_type)
        .is_some_and(|key| producible.contains(&key))
}

fn cpp_ctor_param_supported(
    param_type: &str,
    registry: &type_model::TypeRegistry,
    namespace_path: &[String],
    class_infos: &[cpp_parser::CppClassInfo],
) -> bool {
    if harness_gen::cpp_generate::cpp_parameter_type_supported(param_type)
        || !cpp_default_constructible_parameter_classes(
            &[param_type.to_owned()],
            namespace_path,
            class_infos,
        )
        .is_empty()
    {
        return true;
    }
    let stripped = param_type
        .trim()
        .trim_start_matches("const ")
        .trim()
        .trim_end_matches('&')
        .trim();
    if let Some(target) = registry.alias_target_spelling(stripped) {
        let mut rebuilt = String::new();
        if param_type.trim_start().starts_with("const ") {
            rebuilt.push_str("const ");
        }
        rebuilt.push_str(&target);
        if param_type.trim_end().ends_with('&') {
            rebuilt.push_str(" &");
        }
        if harness_gen::cpp_generate::cpp_parameter_type_supported(&rebuilt) {
            return true;
        }
    }
    false
}

/// Return type for `cpp_receiver_constructor_params`: `(constructor_params,
/// default_constructible_classes, receiver_class_override, factory_plan)`.
type CppReceiverPlan = (
    Vec<harness_gen::cpp_generate::CppParameter>,
    Vec<String>,
    Option<String>,
    Option<harness_gen::cpp_generate::CppFactoryPlan>,
);

fn cpp_receiver_constructor_params(
    target: &cpp_parser::CppFunction,
    functions: &[cpp_parser::CppFunction],
    closure_texts: &[String],
    registry: &type_model::TypeRegistry,
) -> Result<CppReceiverPlan> {
    let Some(class_name) = target.api.class_name.as_deref() else {
        bail!("C++ --kind sequence requires a class method target");
    };
    let qualified_class = qualified_cpp_class_name(target, class_name);
    let class_infos = collect_cpp_class_info_for_harness(closure_texts);
    let receiver_default_constructible = cpp_default_constructible_parameter_classes(
        std::slice::from_ref(&qualified_class),
        &target.api.namespace_path,
        &class_infos,
    )
    .iter()
    .any(|registered| registered == &qualified_class);

    // An abstract receiver (a class with a pure-virtual member) cannot be
    // instantiated directly. #456: substitute a concrete subclass we can
    // default-construct, so the virtual method dispatches to its implementation;
    // only if no usable subclass exists do we skip honestly (rather than emitting
    // `Abstract _gf_receiver;` which fails "variable type is an abstract class").
    // The abstract base + its concrete subclass are looked up across the include
    // closure, since they commonly live in headers (ROADMAP §27.4).
    if closure_texts.iter().any(|t| {
        cpp_parser::parse_cpp_abstract_classes(t)
            .unwrap_or_default()
            .contains(class_name)
    }) {
        // Phase 1 (#456): a concrete, DEFAULT-constructible subclass — `Subclass
        // _gf_receiver;` and the virtual call dispatches to its override.
        if let Some(subclass) = resolve_concrete_subclass(class_name, functions, closure_texts) {
            return Ok((
                Vec::new(),
                Vec::new(),
                Some(subclass_qualified(&qualified_class, &subclass)),
                None,
            ));
        }
        // Phase 2 (§27.4a): a concrete subclass whose only public constructor takes
        // ARGS — resolve that ctor (like the base's) and construct it with decoded
        // arguments: `Subclass _gf_receiver(args); _gf_receiver.method(..)`.
        if let Some((subclass, ctor_params, default_constructible_classes)) =
            resolve_subclass_with_ctor(
                class_name,
                functions,
                closure_texts,
                registry,
                &target.api.namespace_path,
                &class_infos,
            )
        {
            return Ok((
                ctor_params,
                default_constructible_classes,
                Some(subclass_qualified(&qualified_class, &subclass)),
                None,
            ));
        }
        // Phase 3 (§27.4b): no constructible subclass — fall back to a FACTORY that
        // returns the base (`create_*`/`new_*`/`make_*` -> `Base *` / smart ptr).
        // The factory MUST return a pointer/reference for an abstract base (a
        // by-value `Base` return is impossible to instantiate, so any such match is
        // spurious); the factory path then null-guards and calls through `->`.
        if let Some(factory) =
            find_cpp_factory_for_class(class_name, functions, closure_texts, registry, &class_infos)
        {
            if factory.receiver_is_pointer {
                return Ok((Vec::new(), Vec::new(), None, Some(factory)));
            }
        }
        bail!(
            "cannot construct abstract C++ class '{qualified_class}' (it declares a pure-virtual member): no concrete default-constructible subclass, no subclass with a supported public constructor, and no factory returning a '{qualified_class} *' were found; harness a concrete subclass or a factory that returns '{qualified_class}'",
        );
    }

    let declared_constructors = functions
        .iter()
        .filter(|function| {
            function.api.is_constructor
                && function.api.class_name.as_deref() == Some(class_name)
                && function.api.namespace_path == target.api.namespace_path
        })
        .collect::<Vec<_>>();
    let mut constructors = declared_constructors
        .iter()
        .copied()
        .filter(
            |constructor| match constructor.api.member_access.as_deref() {
                Some("public") => true,
                Some(_) => false,
                None => class_infos.iter().any(|info| {
                    (info.qualified_name == qualified_class || info.name == class_name)
                        && info.constructors.iter().any(|declared| {
                            declared.access == "public"
                                && !declared.is_deleted
                                && declared.param_types
                                    == constructor
                                        .params
                                        .iter()
                                        .map(|parameter| parameter.cpp_type.clone())
                                        .collect::<Vec<_>>()
                        })
                }),
            },
        )
        .collect::<Vec<_>>();
    constructors.sort_by_key(|constructor| (constructor.params.len(), constructor.line));
    // Prefer default construction (`T obj;`) whenever the class is no-arg
    // constructible: a parsed empty-param ctor, or a ctor whose parameters are
    // all defaulted (e.g. jsoncpp's `Value(ValueType type = nullValue)`). A
    // default-constructed receiver is unambiguous and avoids overload-resolution
    // pitfalls of a parameterized ctor (jsoncpp's `Value(char const*)` drags in
    // the private nested `CZString`). It also covers the original case where the
    // source declares a default ctor that wasn't parsed as a constructor.
    if constructors
        .iter()
        .any(|constructor| constructor.params.is_empty())
        || receiver_default_constructible
    {
        return Ok((Vec::new(), Vec::new(), None, None));
    }
    if constructors.is_empty() {
        // No PUBLIC parameterized constructor parsed from the target source.
        // Default-construct (`T _gf_receiver;`) ONLY when the class is actually
        // default-constructible — a public default ctor (possibly inline in a
        // header with an init-list, e.g. tinyxml2's `StrPair() : _flags(0) {}`), or
        // no user-declared ctor at all (the implicit default). Otherwise fall
        // through to factory search instead of bailing immediately (tinyxml2's
        // `XMLElement` has no public ctor but is created via
        // `XMLDocument::NewElement`). The check scans the whole include closure,
        // since ctors usually live in headers the target only `#include`s.
        if receiver_default_constructible {
            return Ok((Vec::new(), Vec::new(), None, None));
        }
        // Fall through to factory search below.
    } else {
        // A constructor is usable when every parameter is either a directly
        // supported type OR a default-constructible class arg (#353) we can
        // default-construct and pass.
        if let Some(constructor) = constructors.iter().find(|constructor| {
            !constructor.api.is_template
                && constructor.params.iter().all(|param| {
                    cpp_ctor_param_supported(
                        &param.cpp_type,
                        registry,
                        &target.api.namespace_path,
                        &class_infos,
                    )
                })
        }) {
            let default_constructible_classes = cpp_default_constructible_parameter_classes(
                &constructor
                    .params
                    .iter()
                    .map(|param| param.cpp_type.clone())
                    .collect::<Vec<_>>(),
                &target.api.namespace_path,
                &class_infos,
            );
            return Ok((
                constructor
                    .params
                    .iter()
                    .map(|param| harness_gen::cpp_generate::CppParameter {
                        name: param.name.clone(),
                        cpp_type: param.cpp_type.clone(),
                    })
                    .collect(),
                default_constructible_classes,
                None,
                None,
            ));
        }
        // No supported public constructor — fall through to factory search.
    }

    // Factory fallback: when no usable direct constructor exists, search for a
    // public method or free function whose return type is `C*`/`C&`/`C`/
    // `unique_ptr<C>`/`shared_ptr<C>` (matched by the leaf class name). Prefer
    // factory-named methods (`New*`/`Create*`/`Make*`/`build*`/`Get*Instance`),
    // fewest parameters, earliest source line — for determinism across parses.
    // The factory's owner is stack-allocated so `_gf_owner` outlives the
    // call to the target method; the receiver's memory remains valid.
    if let Some(factory) =
        find_cpp_factory_for_class(class_name, functions, closure_texts, registry, &class_infos)
    {
        return Ok((Vec::new(), Vec::new(), None, Some(factory)));
    }

    bail!(
        "cannot construct C++ class '{qualified_class}' to harness '{}': it has no \
         public default constructor, no supported public constructor, and no factory \
         method or free function returning '{qualified_class}' was found. \
         Add a small wrapper or factory harness that constructs the object and calls \
         '{}', or expose a public fuzzable constructor.",
        target.name,
        target.name
    )
}

/// #99: resolve declaration-aware construction recipes for the target's opaque
/// class PARAMETERS. A parameter whose type is a by-value/reference class that is
/// NOT default-constructible and has no byte-buffer decoder is normally rejected
/// as `unsupported_params`. When the owning header/include closure declares a
/// public parameterized constructor (all arguments directly decodable) or a public
/// static by-value factory, build a recipe so the decoder emits a genuine
/// lifecycle construction for that parameter instead of skipping the target.
///
/// Recipes are only produced for the target's DIRECT parameters, so a
/// constructor's own arguments are always directly decodable — the decoder's
/// recursive argument decode never re-enters a construction recipe. A genuinely
/// opaque by-value type (no public constructor or factory) yields no recipe and
/// keeps its existing precise unsupported reason.
/// `registry` must mirror what the emitter builds MINUS the recipes (default
/// constructible classes + lookup scopes, no `class_constructions`), so a
/// parameter that is already decodable (visible aggregate, alias, default-
/// constructible class, scalar/string) keeps its existing path and is never given
/// a recipe.
fn resolve_cpp_parameter_constructions(
    function: &cpp_parser::CppFunction,
    functions: &[cpp_parser::CppFunction],
    closure_texts: &[String],
    class_infos: &[cpp_parser::CppClassInfo],
    registry: &type_model::TypeRegistry,
    limits: &harness_gen::cpp_decoders::CppDecoderLimits,
    mined: &crate::auto::recipe_mining::MinedRecipes,
) -> Vec<(String, type_model::ClassConstruction)> {
    let namespace_path = function.api.namespace_path.as_slice();
    let mut recipes: Vec<(String, type_model::ClassConstruction)> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Types that can be OBTAINED: everything a recipe has been resolved for.
    // Grown by the fixed-point pass below, which is what makes this a producer
    // graph rather than a one-level lookup.
    let mut producible: std::collections::HashSet<String> = std::collections::HashSet::new();
    // The class keys still owed a recipe because some chosen constructor takes
    // one as an argument.
    let mut wanted: Vec<String> = Vec::new();
    // Direct parameters that no strategy could build on the first pass. A
    // constructor is refused when ONE argument is unobtainable, so these are
    // exactly the ones worth re-offering once the graph has grown.
    let mut refused: Vec<String> = Vec::new();
    for param in &function.params {
        let Some(mut key) = harness_gen::cpp_decoders::cpp_parameter_class_key(&param.cpp_type)
        else {
            continue;
        };
        // Resolve a project alias to the underlying class so the recipe is keyed
        // exactly as the decoder will look it up (mirrors the decoder's own alias
        // resolution).
        if let Some(target) = registry.alias_target_spelling(&key) {
            if let Some(resolved) = harness_gen::cpp_decoders::cpp_parameter_class_key(&target) {
                key = resolved;
            }
        }
        if !seen.insert(key.clone()) {
            continue;
        }
        if registry.is_default_constructible_class(&key) {
            continue;
        }
        if harness_gen::cpp_generate::cpp_parameter_type_supported_with_registry(
            &param.cpp_type,
            registry,
            limits,
        ) {
            continue;
        }
        // 1) A public, non-deleted parameterized constructor whose arguments are
        //    all directly decodable (verified by the same check the receiver path
        //    uses). Prefer the fewest arguments for a deterministic, small decode.
        if let Some(construction) = resolve_cpp_parameter_ctor_recipe(
            &key,
            class_infos,
            registry,
            namespace_path,
            &producible,
        ) {
            note_recipe_dependencies(&construction, registry, &mut wanted);
            producible.insert(key.clone());
            recipes.push((key, construction));
            continue;
        }
        // 2) A public STATIC by-value factory resolved from the include closure
        //    (`Owner::create()`), yielding a self-contained construction expression.
        let leaf = key.rsplit("::").next().unwrap_or(&key);
        if let Some(factory) =
            find_cpp_factory_for_class(leaf, functions, closure_texts, registry, class_infos)
        {
            if !factory.receiver_is_pointer
                && factory.owner_method_is_static
                && factory.factory_params.is_empty()
            {
                if let Some(owner) = factory.owner_type.as_deref() {
                    recipes.push((
                        key,
                        type_model::ClassConstruction::Expression(format!(
                            "{owner}::{}()",
                            factory.factory_method
                        )),
                    ));
                    continue;
                }
            }
        }
        // 3) A construction the PROJECT ITSELF wrote down, in the directories
        //    discovery skips as targets. A test or example is where somebody has
        //    already worked out how to build this object; only literal-only
        //    expressions are mined, so what is lifted out compiles on its own.
        //    Last, so a declared constructor or factory always wins over an
        //    observed usage.
        if let Some(expression) = mined
            .get(&key)
            .or_else(|| mined.get(key.rsplit("::").next().unwrap_or(&key)))
        {
            recipes.push((
                key,
                type_model::ClassConstruction::Expression(expression.clone()),
            ));
            continue;
        }
        // No recipe yet. It may still become buildable once the producer graph
        // below resolves whatever its constructors wanted, so record those needs
        // and re-offer it rather than concluding it is opaque here.
        note_candidate_dependencies(&key, class_infos, registry, &mut wanted);
        refused.push(key);
    }
    // Producer graph. A recipe chosen above may itself take a class-typed
    // argument that is not decodable from bytes; the decoder already recurses
    // through the registry looking for a recipe, but nothing ever populated one
    // beyond the target's DIRECT parameters, so the recursion had nothing to
    // find and the whole constructor was rejected one level up.
    //
    // Resolve what those arguments need, then re-offer the parameters that were
    // refused — a constructor rejected because one argument was unobtainable
    // becomes viable the moment that argument is producible. Repeat to a fixed
    // point, bounded: the graph is cyclic (`A(B)`, `B(A)`), so depth is what
    // guarantees termination rather than any property of the project.
    const MAX_PRODUCER_DEPTH: usize = 3;
    for _ in 0..MAX_PRODUCER_DEPTH {
        let mut pending: Vec<String> = std::mem::take(&mut wanted);
        pending.append(&mut std::mem::take(&mut refused));
        pending.retain(|key| !producible.contains(key));
        pending.dedup();
        let mut progressed = false;
        for key in pending {
            if producible.contains(&key) {
                continue;
            }
            if registry.is_default_constructible_class(&key) {
                producible.insert(key);
                continue;
            }
            if let Some(construction) = resolve_cpp_parameter_ctor_recipe(
                &key,
                class_infos,
                registry,
                namespace_path,
                &producible,
            ) {
                note_recipe_dependencies(&construction, registry, &mut wanted);
                producible.insert(key.clone());
                recipes.push((key, construction));
                progressed = true;
                continue;
            }
            if let Some(expression) = mined
                .get(&key)
                .or_else(|| mined.get(key.rsplit("::").next().unwrap_or(&key)))
            {
                producible.insert(key.clone());
                recipes.push((
                    key,
                    type_model::ClassConstruction::Expression(expression.clone()),
                ));
                progressed = true;
                continue;
            }
            note_candidate_dependencies(&key, class_infos, registry, &mut wanted);
            refused.push(key);
        }
        // Nothing new became producible, so another round would ask the same
        // questions and get the same answers.
        if !progressed {
            break;
        }
    }
    recipes
}

/// A public, non-deleted, non-templated parameterized constructor of `key` whose
/// argument types are all directly decodable (never themselves needing
/// construction), if one is declared in the parsed class info. Prefers the fewest
/// arguments. `key` is a canonical class spelling.
fn resolve_cpp_parameter_ctor_recipe(
    key: &str,
    class_infos: &[cpp_parser::CppClassInfo],
    registry: &type_model::TypeRegistry,
    namespace_path: &[String],
    producible: &std::collections::HashSet<String>,
) -> Option<type_model::ClassConstruction> {
    let leaf = key.rsplit("::").next().unwrap_or(key);
    let mut candidates: Vec<&Vec<String>> = class_infos
        .iter()
        .filter(|info| info.qualified_name == key || info.name == leaf)
        .flat_map(|info| info.constructors.iter())
        .filter(|constructor| {
            constructor.access == "public"
                && !constructor.is_deleted
                // A no-arg ctor is the default-constructible path, not this one.
                && !constructor.param_types.is_empty()
                && constructor.param_types.iter().all(|param_type| {
                    cpp_ctor_param_obtainable(
                        param_type,
                        registry,
                        namespace_path,
                        class_infos,
                        producible,
                    )
                })
        })
        .map(|constructor| &constructor.param_types)
        .collect();
    candidates.sort_by_key(|param_types| param_types.len());
    candidates
        .first()
        .map(|param_types| type_model::ClassConstruction::Constructor {
            param_types: (*param_types).clone(),
        })
}

/// Search `functions` (which already includes header-resolved methods) for a
/// public factory that can yield an instance of `class_name`.  A factory is a
/// non-constructor, non-destructor, non-template, PUBLIC method or free function
/// whose return type resolves to `C*`, `C&`, `C`, `std::unique_ptr<C>`, or
/// `std::shared_ptr<C>` (by leaf name), and whose own parameters are all
/// individually decodable (same decodability check used for direct constructors).
///
/// For an instance-method factory (e.g. `XMLDocument::NewElement`), the owner
/// class must itself be default-constructible; otherwise that factory is skipped
/// (we cannot construct the owner either).  A factory that is the same class as
/// `class_name` is also skipped (would be circular).
///
/// Sorting preference: factory-named (`New*`/`Create*`/`Make*`/etc.) first,
/// then fewest parameters, then earliest line — deterministic across re-parses.
fn find_cpp_factory_for_class(
    class_name: &str,
    functions: &[cpp_parser::CppFunction],
    closure_texts: &[String],
    registry: &type_model::TypeRegistry,
    class_infos: &[cpp_parser::CppClassInfo],
) -> Option<harness_gen::cpp_generate::CppFactoryPlan> {
    let is_factory_return = |return_type: &str| -> bool {
        let rt = return_type.trim();
        // Smart-pointer wrappers first (they contain `<ClassName>`).
        if rt.contains(&format!("unique_ptr<{class_name}>"))
            || rt.contains(&format!("unique_ptr<{class_name} >"))
            || rt.contains(&format!("shared_ptr<{class_name}>"))
            || rt.contains(&format!("shared_ptr<{class_name} >"))
        {
            return true;
        }
        // Strip const / pointer / reference to get the bare type name, then
        // compare by leaf (handles namespace-qualified spellings like
        // `tinyxml2::XMLElement *`).
        let bare = rt
            .trim_start_matches("const ")
            .trim()
            .trim_end_matches('*')
            .trim()
            .trim_end_matches('&')
            .trim();
        bare == class_name || bare.ends_with(&format!("::{class_name}"))
    };

    let is_pointer_return = |return_type: &str| -> bool {
        let rt = return_type.trim();
        rt.contains('*') || rt.contains("unique_ptr<") || rt.contains("shared_ptr<")
    };

    let is_factory_name = |name: &str| -> bool {
        let lower = name.to_ascii_lowercase();
        lower.starts_with("new")
            || lower.starts_with("create")
            || lower.starts_with("make")
            || lower.starts_with("build")
            || (lower.starts_with("get") && lower.contains("instance"))
    };

    let mut candidates: Vec<&cpp_parser::CppFunction> = functions
        .iter()
        .filter(|f| {
            !f.api.is_constructor
                && !f.api.is_destructor
                && !f.api.is_template
                // Public or unspecified access (unspecified = often parsed from
                // a header where access wasn't inlined by the parser).
                && f.api
                    .member_access
                    .as_deref()
                    .is_none_or(|a| a == "public")
                && is_factory_return(&f.return_type)
                && f.params.iter().all(|parameter| {
                    cpp_ctor_param_supported(
                        &parameter.cpp_type,
                        registry,
                        &f.api.namespace_path,
                        class_infos,
                    )
                })
        })
        .collect();

    // Sort: factory-named first (0), then fewest params, then earliest line.
    candidates.sort_by_key(|f| {
        let name_prio = if is_factory_name(&f.name) { 0u8 } else { 1u8 };
        (name_prio, f.params.len(), f.line)
    });

    for factory_fn in candidates {
        let owner_class = factory_fn.api.class_name.as_deref();

        // An INSTANCE factory on the class being constructed is circular. A
        // static `C::Create()` is precisely the construction path we want and
        // requires no receiver.
        if owner_class == Some(class_name) && !factory_fn.is_static {
            continue;
        }

        // For an instance-method factory, the owner must be default-constructible.
        // A static owner method is called with `Owner::Factory` and has no such
        // requirement.
        if let Some(owner) = owner_class {
            if !factory_fn.is_static
                && !cpp_class_is_default_constructible(owner, functions, closure_texts)
            {
                continue;
            }
        }

        let owner_type = owner_class.map(|owner| {
            // Build the fully-qualified owner type: namespace_path + owner class.
            if factory_fn.api.namespace_path.is_empty() {
                owner.to_owned()
            } else {
                format!("{}::{}", factory_fn.api.namespace_path.join("::"), owner)
            }
        });

        return Some(harness_gen::cpp_generate::CppFactoryPlan {
            owner_type,
            owner_method_is_static: factory_fn.is_static,
            factory_method: factory_fn.name.clone(),
            factory_params: factory_fn
                .params
                .iter()
                .map(|p| harness_gen::cpp_generate::CppParameter {
                    name: p.name.clone(),
                    cpp_type: p.cpp_type.clone(),
                })
                .collect(),
            receiver_is_pointer: is_pointer_return(&factory_fn.return_type),
        });
    }
    None
}

/// #456: the leaf name of a concrete, default-constructible DIRECT subclass of the
/// abstract `base` (declared in `source`), or `None`. A subclass is usable when it
/// is not itself abstract and is default-constructible (no declared ctor, an
/// empty-param public ctor, or a source-declared default ctor). Deterministic
/// (first by name) when several qualify.
fn resolve_concrete_subclass(
    base: &str,
    functions: &[cpp_parser::CppFunction],
    texts: &[String],
) -> Option<String> {
    // #456 / ROADMAP §27.4: scan the target source AND its include closure, since an
    // abstract base and its concrete subclass commonly live in headers the target
    // only `#include`s (libE57Format's Reader / a concrete reader subclass).
    let mut abstract_classes = std::collections::HashSet::new();
    let mut subclasses: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for text in texts {
        abstract_classes.extend(cpp_parser::parse_cpp_abstract_classes(text).unwrap_or_default());
        for (base_leaf, derived) in cpp_parser::parse_cpp_subclasses(text).unwrap_or_default() {
            subclasses.entry(base_leaf).or_default().extend(derived);
        }
    }
    let mut derived = subclasses.get(base).cloned().unwrap_or_default();
    derived.sort();
    derived.dedup();
    derived.into_iter().find(|sub| {
        !abstract_classes.contains(sub) && cpp_class_is_default_constructible(sub, functions, texts)
    })
}

/// §27.4a: the first concrete DIRECT subclass of abstract `base` that is NOT
/// default-constructible but exposes a public, non-template constructor whose
/// parameters are all decodable, returned as `(subclass_leaf, ctor_params,
/// default_constructible_class_args)`. Used when no default-constructible
/// subclass exists: construct the subclass with decoded constructor arguments so
/// the virtual method still dispatches to its override. Deterministic — subclasses
/// are sorted by name and each subclass's constructors by (arity, line).
fn resolve_subclass_with_ctor(
    base: &str,
    functions: &[cpp_parser::CppFunction],
    texts: &[String],
    registry: &type_model::TypeRegistry,
    namespace_path: &[String],
    class_infos: &[cpp_parser::CppClassInfo],
) -> Option<(
    String,
    Vec<harness_gen::cpp_generate::CppParameter>,
    Vec<String>,
)> {
    let mut abstract_classes = std::collections::HashSet::new();
    let mut subclasses: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for text in texts {
        abstract_classes.extend(cpp_parser::parse_cpp_abstract_classes(text).unwrap_or_default());
        for (base_leaf, derived) in cpp_parser::parse_cpp_subclasses(text).unwrap_or_default() {
            subclasses.entry(base_leaf).or_default().extend(derived);
        }
    }
    let mut derived = subclasses.get(base).cloned().unwrap_or_default();
    derived.sort();
    derived.dedup();
    for sub in derived {
        if abstract_classes.contains(&sub) {
            continue;
        }
        let mut ctors: Vec<&cpp_parser::CppFunction> = functions
            .iter()
            .filter(|f| {
                f.api.is_constructor
                    && f.api.class_name.as_deref() == Some(sub.as_str())
                    && !f.api.is_template
                    && f.api
                        .member_access
                        .as_deref()
                        .is_none_or(|access| access == "public")
            })
            .collect();
        ctors.sort_by_key(|c| (c.params.len(), c.line));
        if let Some(ctor) = ctors.iter().find(|c| {
            !c.params.is_empty()
                && c.params.iter().all(|p| {
                    cpp_ctor_param_supported(&p.cpp_type, registry, namespace_path, class_infos)
                })
        }) {
            let default_constructible_classes = cpp_default_constructible_parameter_classes(
                &ctor
                    .params
                    .iter()
                    .map(|parameter| parameter.cpp_type.clone())
                    .collect::<Vec<_>>(),
                namespace_path,
                class_infos,
            );
            let ctor_params = ctor
                .params
                .iter()
                .map(|p| harness_gen::cpp_generate::CppParameter {
                    name: p.name.clone(),
                    cpp_type: p.cpp_type.clone(),
                })
                .collect::<Vec<_>>();
            return Some((sub, ctor_params, default_constructible_classes));
        }
    }
    None
}

/// Whether `class` can be default-constructed, considering the whole include
/// closure (`texts`): an empty-param public constructor, a default constructor
/// declared in any text, or no user-declared constructor anywhere (the implicit
/// default) that isn't `= delete`d. The "no ctor declared ANYWHERE" check uses the
/// closure texts so a header subclass with only a parameterised/private ctor is
/// not mistaken for implicitly default-constructible.
fn cpp_class_is_default_constructible(
    class: &str,
    _functions: &[cpp_parser::CppFunction],
    texts: &[String],
) -> bool {
    let infos = collect_cpp_class_info_for_harness(texts);
    if let Some(exact) = infos.iter().find(|info| info.qualified_name == class) {
        return exact.has_public_default_constructor();
    }
    let leaf = class.rsplit("::").next().unwrap_or(class);
    let mut matches = infos.iter().filter(|info| info.name == leaf);
    let Some(only) = matches.next() else {
        return false;
    };
    matches.next().is_none() && only.has_public_default_constructor()
}

/// The target `.cpp` source text plus every header in its include closure
/// (bounded), for cross-file inheritance discovery (#456 / ROADMAP §27.4).
fn collect_cpp_inheritance_texts(
    source_path: &Path,
    source: &str,
    target_includes: &[String],
    include_dirs: &[PathBuf],
) -> Vec<String> {
    const MAX_TRANSITIVE_HEADERS: usize = 256;
    let mut texts = vec![source.to_owned()];
    let mut queue: Vec<String> = target_includes.to_vec();
    let mut visited: HashSet<PathBuf> = HashSet::new();
    let mut parsed = 0usize;
    while let Some(include) = queue.pop() {
        if parsed >= MAX_TRANSITIVE_HEADERS {
            break;
        }
        let Some(header) = include_dirs
            .iter()
            .map(|dir| dir.join(&include))
            .find(|path| path.is_file())
        else {
            continue;
        };
        if header == source_path || !visited.insert(header.clone()) {
            continue;
        }
        let Ok(text) = fs::read_to_string(&header) else {
            continue;
        };
        parsed += 1;
        for nested in harness_project_includes(&text, include_dirs) {
            queue.push(nested);
        }
        texts.push(text);
    }
    texts
}

/// Re-qualify a subclass leaf into the base's namespace (`e57::Reader` +
/// `MemoryReader` -> `e57::MemoryReader`), so the emitted receiver type resolves.
fn subclass_qualified(qualified_base: &str, subclass_leaf: &str) -> String {
    match qualified_base.rsplit_once("::") {
        Some((namespace, _)) => format!("{namespace}::{subclass_leaf}"),
        None => subclass_leaf.to_owned(),
    }
}

fn qualified_cpp_class_name(target: &cpp_parser::CppFunction, class_name: &str) -> String {
    if target.api.namespace_path.is_empty() {
        class_name.to_owned()
    } else {
        format!("{}::{}", target.api.namespace_path.join("::"), class_name)
    }
}

#[derive(Debug, Clone)]
struct CppBuildContext {
    provenance: String,
    confidence: String,
    compile_flags: Vec<String>,
    link_flags: Vec<String>,
    extra_sources: Vec<PathBuf>,
    recovery: Vec<String>,
}

impl CppBuildContext {
    fn none() -> Self {
        Self {
            provenance: "none".to_owned(),
            confidence: "none".to_owned(),
            compile_flags: Vec::new(),
            link_flags: Vec::new(),
            extra_sources: Vec::new(),
            recovery: Vec::new(),
        }
    }

    fn encoded_flags(&self) -> Vec<String> {
        let mut flags = self.compile_flags.clone();
        // A recovered `-std=` must control the Makefile's single CXX_STD knob,
        // not remain later in COMPILE_DB_FLAGS where it overrides every dialect
        // ladder retry. Last one wins, matching compiler command-line semantics.
        let recovered_standard = flags
            .iter()
            .filter_map(|flag| flag.strip_prefix("-std="))
            .rfind(|standard| standard.contains("++"))
            .map(str::to_owned);
        flags.retain(|flag| {
            !flag
                .strip_prefix("-std=")
                .is_some_and(|standard| standard.contains("++"))
        });
        if let Some(standard) = recovered_standard {
            flags.push(format!("{BUILD_CONTEXT_CXX_STANDARD_PREFIX}{standard}"));
        }
        flags.push(format!(
            "{BUILD_CONTEXT_PROVENANCE_PREFIX}{}",
            self.provenance
        ));
        flags.push(format!(
            "{BUILD_CONTEXT_CONFIDENCE_PREFIX}{}",
            self.confidence
        ));
        let recovery = if self.recovery.is_empty() {
            "none".to_owned()
        } else {
            self.recovery.join(",")
        };
        flags.push(format!("{BUILD_CONTEXT_RECOVERY_PREFIX}{recovery}"));
        flags.extend(
            self.link_flags
                .iter()
                .map(|flag| format!("{BUILD_CONTEXT_LDFLAG_PREFIX}{flag}")),
        );
        flags
    }
}

fn cpp_build_context_for_source(source_path: &Path) -> CppBuildContext {
    match try_compile_database_flags_for_source(source_path) {
        Ok(flags) if !flags.is_empty() => {
            // compile_commands.json carries the real per-file COMPILE flags
            // (`-I`/`-D`, generated-header dirs) but NOT the library's link source
            // set, so a multi-file library would link only the target's own `.cpp`
            // and fail with undefined references to every sibling. Still collect the
            // sibling sources from the project's CMake `target_sources`/`add_library`
            // so flags and sources combine (libE57Format: compile_commands provides
            // the `-DREVISION_ID=...`/CRCpp/`build/` includes, CMake the 43-file list).
            let extra_sources = find_upward_build_file(source_path, &["CMakeLists.txt"])
                .map(|cmake| infer_cmake_build_context(source_path, &cmake).extra_sources)
                .unwrap_or_default();
            return CppBuildContext {
                provenance: if is_c_family_header(source_path) {
                    "associated_header_compile_database".to_owned()
                } else {
                    "exact_tu_compile_database".to_owned()
                },
                confidence: "high".to_owned(),
                compile_flags: flags,
                link_flags: Vec::new(),
                extra_sources,
                recovery: Vec::new(),
            };
        }
        Ok(_) => {}
        Err(error) => eprintln!(
            "warning: skipped compile_commands.json flags for {}: {error:#}",
            source_path.display()
        ),
    }

    if let Some(cmake) = find_upward_build_file(source_path, &["CMakeLists.txt"]) {
        return infer_cmake_build_context(source_path, &cmake);
    }
    if let Some(makefile) =
        find_upward_build_file(source_path, &["Makefile", "makefile", "GNUmakefile"])
    {
        return infer_make_build_context(source_path, &makefile);
    }
    CppBuildContext::none()
}

fn find_upward_build_file(source_path: &Path, names: &[&str]) -> Option<PathBuf> {
    let mut cursor = source_path.parent().map(Path::to_path_buf);
    let mut steps = 0;
    while let Some(dir) = cursor {
        for name in names {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        steps += 1;
        if steps >= 5 {
            break;
        }
        cursor = dir.parent().map(Path::to_path_buf);
    }
    None
}

fn infer_cmake_build_context(source_path: &Path, cmake_path: &Path) -> CppBuildContext {
    infer_cmake_build_context_with_policy(source_path, cmake_path, true)
}

/// C has no eager CMake source-set link path, so an unresolved target owner must
/// not union every target's mutually exclusive compile definitions. Global flags
/// remain valid; target-scoped flags are included when ownership is explicit.
fn infer_cmake_c_build_context(source_path: &Path, cmake_path: &Path) -> CppBuildContext {
    infer_cmake_build_context_with_policy(source_path, cmake_path, false)
}

fn infer_cmake_build_context_with_policy(
    source_path: &Path,
    cmake_path: &Path,
    union_unowned_targets: bool,
) -> CppBuildContext {
    let base_dir = cmake_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let mut context = CppBuildContext {
        provenance: "cmake".to_owned(),
        confidence: "medium".to_owned(),
        compile_flags: Vec::new(),
        link_flags: Vec::new(),
        extra_sources: Vec::new(),
        recovery: Vec::new(),
    };
    let Ok(text) = fs::read_to_string(cmake_path) else {
        context
            .recovery
            .push(format!("unreadable_context:{}", cmake_path.display()));
        return context;
    };
    // Track `if/elseif/else/endif` nesting and statically-known variables so the
    // inference honors the project's DEFAULT configuration instead of unioning
    // every mutually-exclusive branch. CMake selects exactly one arm of an
    // if-chain; collecting all of them produces a flag set that matches no real
    // build — e.g. libde265 gates `DE265_LOG_ERROR/INFO/DEBUG/TRACE` on a
    // `DE265_LOG_LEVEL` CACHE var defaulting to "error", so the union wrongly
    // enables DEBUG/TRACE logging (which references private members and then
    // can't even compile). We only ever PRUNE a branch we can prove dead; an
    // indeterminate condition keeps its body (no regression vs. the old union).
    let commands = cmake_commands(&text);
    let owning_targets = cmake_targets_for_source(&commands, source_path, &base_dir);
    let mut vars: HashMap<String, String> = HashMap::new();
    let mut branches: Vec<CmakeBranch> = Vec::new();
    for command in commands {
        match command.name.as_str() {
            "if" => {
                let parent_active = branches.last().is_none_or(|b| b.active);
                let (active, taken) = if parent_active {
                    match eval_cmake_condition(&command.args, &vars) {
                        Some(true) => (true, true),
                        Some(false) => (false, false),
                        None => (true, false),
                    }
                } else {
                    (false, false)
                };
                branches.push(CmakeBranch {
                    parent_active,
                    taken,
                    active,
                });
                continue;
            }
            "elseif" => {
                if let Some(branch) = branches.last_mut() {
                    if !branch.parent_active || branch.taken {
                        branch.active = false;
                    } else {
                        match eval_cmake_condition(&command.args, &vars) {
                            Some(true) => {
                                branch.active = true;
                                branch.taken = true;
                            }
                            Some(false) => branch.active = false,
                            None => branch.active = true,
                        }
                    }
                }
                continue;
            }
            "else" => {
                if let Some(branch) = branches.last_mut() {
                    branch.active = branch.parent_active && !branch.taken;
                }
                continue;
            }
            "endif" => {
                branches.pop();
                continue;
            }
            _ => {}
        }
        if !branches.last().is_none_or(|b| b.active) {
            continue;
        }
        match command.name.as_str() {
            "set" => {
                record_cmake_var(&command.args, &mut vars);
                infer_cmake_set(&command.args, &mut context);
            }
            "option" => record_cmake_option(&command.args, &mut vars),
            "include_directories" | "target_include_directories" => {
                if command.name.starts_with("target_")
                    && !cmake_command_targets_source(
                        &command,
                        &owning_targets,
                        union_unowned_targets,
                    )
                {
                    continue;
                }
                for value in cmake_values_without_scopes(
                    &command.args,
                    usize::from(command.name.starts_with("target_")),
                ) {
                    if cmake_token_is_dynamic(value) {
                        continue;
                    }
                    push_include_flag(&mut context.compile_flags, &base_dir, value);
                }
            }
            "add_definitions" | "add_compile_definitions" | "target_compile_definitions" => {
                if command.name.starts_with("target_")
                    && !cmake_command_targets_source(
                        &command,
                        &owning_targets,
                        union_unowned_targets,
                    )
                {
                    continue;
                }
                for value in cmake_values_without_scopes(
                    &command.args,
                    usize::from(command.name.starts_with("target_")),
                ) {
                    // An unexpanded `${VAR}` / `$<...>` / `$(...)` define
                    // (FlatBuffers' `-DFLATBUFFERS_MAX_PARSING_DEPTH=${...}`) is
                    // not a real value, and carrying it forward trips the
                    // build-safety metacharacter check and blocks every harness.
                    let Some(value) = expand_known_cmake_token(value, &vars) else {
                        continue;
                    };
                    // A `*_USE_STD_MODULE` define switches a header-only library to
                    // `import std;` (C++23 standard-library modules) instead of
                    // classic `#include`s. The harness compiles with a plain
                    // clang++ invocation that has no precompiled `std` module, so
                    // `import std;` / `using std::optional;` fails ("no member named
                    // 'optional' in namespace 'std'"). Such a toggle is a build
                    // VARIANT (magic_enum sets MAGIC_ENUM_USE_STD_MODULE PRIVATE on a
                    // dedicated module-test target); never carry it into the harness.
                    if cmake_define_enables_std_module(&value) {
                        continue;
                    }
                    if value.starts_with('-') {
                        // Already a compiler flag. Some CMakeLists wrongly put
                        // compile flags in add_definitions() (json11's
                        // `add_definitions(-std=c++11)`); `-D`-prefixing a `-std=`/
                        // `-f`/`-W` value yields an invalid macro name
                        // (`-D-std=c++11` -> "macro name must be an identifier", a
                        // failed build). Pass `-D…` defines and other flags through
                        // verbatim.
                        push_unique_string(&mut context.compile_flags, value);
                    } else {
                        push_unique_string(&mut context.compile_flags, format!("-D{value}"));
                    }
                }
            }
            "target_compile_options" => {
                if !cmake_command_targets_source(&command, &owning_targets, union_unowned_targets) {
                    continue;
                }
                for value in cmake_values_without_scopes(&command.args, 1) {
                    push_build_compile_flag(&mut context.compile_flags, &base_dir, value);
                }
            }
            "target_link_libraries" => {
                if !cmake_command_targets_source(&command, &owning_targets, union_unowned_targets) {
                    continue;
                }
                for value in cmake_values_without_scopes(&command.args, 1) {
                    if let Some(flag) = link_flag_from_build_token(&base_dir, value) {
                        push_unique_string(&mut context.link_flags, flag);
                    }
                }
            }
            // `add_library`/`target_sources` name the translation units of a
            // LIBRARY — the kind of sibling sources a harness may need to resolve
            // the target's symbols. `add_executable` names a PROGRAM's sources:
            // each carries (or pulls in) a `main()` plus unrelated app/tool/example
            // code. Linking those into a harness collides with libFuzzer's own
            // `main` and drags in undefined symbols — basis_universal's
            // `basisu`/`example`/`example_capi`/`example_transcoding` executables
            // referenced `basisu::basis_free_data` and other encoder symbols not in
            // the harness link, failing the build. Never link executable sources.
            "add_library" | "target_sources" => {
                if !cmake_command_targets_source(&command, &owning_targets, union_unowned_targets) {
                    continue;
                }
                for value in cmake_values_without_scopes(&command.args, 1) {
                    maybe_push_context_source(
                        source_path,
                        &base_dir,
                        value,
                        &mut context.extra_sources,
                        &mut context.recovery,
                    );
                }
            }
            _ => {}
        }
    }
    context
}

/// CMake target(s) whose explicit source list contains `source_path`. When this
/// succeeds, target-scoped compile/link/source commands for every other target
/// must be ignored. Without the ownership filter, a default-enabled test target
/// causes its entire source set and flags to be unioned into the library harness
/// (LevelDB's `leveldb_tests` added 20+ `*_test.cc` files).
fn cmake_targets_for_source(
    commands: &[BuildCommand],
    source_path: &Path,
    base_dir: &Path,
) -> HashSet<String> {
    let source_key = normalized_path_key(source_path);
    let mut targets = HashSet::new();
    for command in commands {
        if !matches!(
            command.name.as_str(),
            "add_library" | "add_executable" | "target_sources"
        ) {
            continue;
        }
        let Some(target) = command.args.first() else {
            continue;
        };
        if cmake_token_is_dynamic(target) {
            continue;
        }
        let owns_source = cmake_values_without_scopes(&command.args, 1).any(|token| {
            if cmake_token_is_dynamic(token) || !looks_like_cpp_source_token(token) {
                return false;
            }
            let resolved = if Path::new(token).is_absolute() {
                normalize_path(Path::new(token))
            } else {
                normalize_path(&base_dir.join(token))
            };
            normalized_path_key(&resolved) == source_key
        });
        if owns_source {
            targets.insert(target.trim_matches(['"', '\'']).to_owned());
        }
    }
    targets
}

fn cmake_command_targets_source(
    command: &BuildCommand,
    owning_targets: &HashSet<String>,
    union_unowned_targets: bool,
) -> bool {
    if owning_targets.is_empty() {
        // Source ownership can be hidden behind an unexpanded CMake variable.
        // The C++ context preserves the prior conservative union behavior; the
        // C fallback keeps only global commands because unioning platform/config
        // variants produces a flag set no real C target uses.
        return union_unowned_targets;
    }
    command
        .args
        .first()
        .map(|target| target.trim_matches(['"', '\'']))
        .is_some_and(|target| owning_targets.contains(target))
}

/// True for a CMake compile define that enables C++23 standard-library modules
/// (`import std;`) in place of classic `#include`s — `<LIB>_USE_STD_MODULE`, the
/// established convention (magic_enum, fmt, …). The harness build has no
/// precompiled `std` module, so such a define only breaks it. Accepts the value
/// with or without a leading `-D` and an optional `=value`.
fn cmake_define_enables_std_module(value: &str) -> bool {
    let name = value
        .trim_start_matches("-D")
        .split('=')
        .next()
        .unwrap_or("");
    name == "USE_STD_MODULE" || name.ends_with("_USE_STD_MODULE")
}

fn infer_cmake_set(args: &[String], context: &mut CppBuildContext) {
    let Some(name) = args.first() else {
        return;
    };
    if name.eq_ignore_ascii_case("CMAKE_CXX_STANDARD") {
        if let Some(version) = args
            .get(1)
            .filter(|value| value.chars().all(|ch| ch.is_ascii_digit()))
        {
            push_unique_string(&mut context.compile_flags, format!("-std=c++{version}"));
        }
    }
}

/// One frame of CMake `if/elseif/else/endif` state while scanning a CMakeLists.
/// `active` already incorporates the parent scope (so the effective state is just
/// the top frame's `active`); `taken` records whether a *proven-true* arm of this
/// chain has fired, which closes the chain to later `elseif`/`else`.
struct CmakeBranch {
    parent_active: bool,
    taken: bool,
    active: bool,
}

/// Record a `set(VAR value ...)` (including `set(VAR value CACHE ...)` defaults)
/// into the statically-known variable map used for condition pruning. Dynamic
/// (`${...}`/`$<...>`) and value-less (`set(VAR CACHE ...)`) forms are skipped.
fn record_cmake_var(args: &[String], vars: &mut HashMap<String, String>) {
    let Some(name) = args.first() else {
        return;
    };
    let Some(value) = args.get(1) else {
        return;
    };
    if value == "CACHE" || cmake_token_is_dynamic(value) {
        return;
    }
    vars.insert(name.clone(), value.clone());
}

/// Record an `option(VAR "doc" [initial])` default (defaulting to `OFF`) into the
/// variable map so boolean-gated branches resolve to their default configuration.
fn record_cmake_option(args: &[String], vars: &mut HashMap<String, String>) {
    let Some(name) = args.first() else {
        return;
    };
    let initial = args.get(2).map(String::as_str).unwrap_or("OFF");
    if cmake_token_is_dynamic(initial) {
        return;
    }
    vars.insert(name.clone(), initial.to_owned());
}

/// Expand `${NAME}` references whose values were established by an earlier
/// literal `set()`/`option()`. Generator expressions and unknown variables stay
/// unsupported and return `None`; this remains conservative while preserving
/// host selectors such as LevelDB's `${LEVELDB_PLATFORM_NAME}=1`.
fn expand_known_cmake_token(token: &str, vars: &HashMap<String, String>) -> Option<String> {
    if token.contains("$<") || token.contains("$(") {
        return None;
    }
    let mut expanded = token.to_owned();
    while let Some(start) = expanded.find("${") {
        let rest = &expanded[start + 2..];
        let end = rest.find('}')?;
        let name = &rest[..end];
        let value = vars.get(name)?;
        expanded.replace_range(start..start + 3 + end, value);
    }
    Some(expanded)
}

/// Tri-state evaluation of a CMake `if`/`elseif` condition for branch pruning.
/// `Some(true)`/`Some(false)` only when the outcome is determinable from
/// statically-known variables and host platform predicates; `None` (indeterminate)
/// when it is not — callers KEEP an indeterminate branch, so this can only ever
/// prune a branch proven dead. Handles the common shapes (single token, `NOT`,
/// `DEFINED`, `MATCHES`/`STREQUAL`/`EQUAL`, simple `AND`/`OR`); anything more
/// complex stays indeterminate.
fn eval_cmake_condition(args: &[String], vars: &HashMap<String, String>) -> Option<bool> {
    let toks: Vec<&str> = args.iter().map(String::as_str).collect();
    match toks.as_slice() {
        [] => None,
        [single] => cmake_eval_single(single, vars),
        ["NOT", rest] => cmake_eval_single(rest, vars).map(|b| !b),
        ["DEFINED", name] => {
            if vars.contains_key(*name) {
                Some(true)
            } else {
                None
            }
        }
        [lhs, op, rhs] => match op.to_ascii_uppercase().as_str() {
            "MATCHES" => cmake_matches(vars.get(*lhs)?, rhs),
            "STREQUAL" => {
                let l = vars.get(*lhs)?;
                let r = vars.get(*rhs).map(String::as_str).unwrap_or(rhs);
                Some(l == r)
            }
            "EQUAL" => {
                let l = vars.get(*lhs)?.parse::<i64>().ok()?;
                let r = vars
                    .get(*rhs)
                    .map(String::as_str)
                    .unwrap_or(rhs)
                    .parse::<i64>()
                    .ok()?;
                Some(l == r)
            }
            "AND" => match (cmake_eval_single(lhs, vars), cmake_eval_single(rhs, vars)) {
                (Some(false), _) | (_, Some(false)) => Some(false),
                (Some(true), Some(true)) => Some(true),
                _ => None,
            },
            "OR" => match (cmake_eval_single(lhs, vars), cmake_eval_single(rhs, vars)) {
                (Some(true), _) | (_, Some(true)) => Some(true),
                (Some(false), Some(false)) => Some(false),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

/// Evaluate a single CMake condition token: host platform predicates (the build
/// context describes the HOST build, so `WIN32`/`APPLE`/… are false and `UNIX` is
/// true), known variables (by CMake truthiness), and bare boolean constants.
fn cmake_eval_single(token: &str, vars: &HashMap<String, String>) -> Option<bool> {
    match token {
        "WIN32" | "MSVC" | "MSVC_IDE" | "WINCE" | "WINDOWS_PHONE" | "WINDOWS_STORE" | "MSYS"
        | "CYGWIN" | "APPLE" | "IOS" | "ANDROID" | "BORLAND" | "WATCOM" | "MINGW"
        | "EMSCRIPTEN" | "QNX" | "VXWORKS" | "ZOS" | "OS390" | "OPENVMS" | "HAIKU" | "SUNOS" => {
            return Some(false)
        }
        "UNIX" => return Some(true),
        _ => {}
    }
    if let Some(value) = vars.get(token) {
        return Some(cmake_truthy(value));
    }
    let up = token.to_ascii_uppercase();
    match up.as_str() {
        "ON" | "TRUE" | "YES" | "Y" | "1" => Some(true),
        "OFF" | "FALSE" | "NO" | "N" | "0" | "" | "IGNORE" | "NOTFOUND" => Some(false),
        _ if up.ends_with("-NOTFOUND") => Some(false),
        _ => None,
    }
}

/// CMake truthiness of a variable's value (the documented false-constant set).
fn cmake_truthy(value: &str) -> bool {
    let up = value.trim().to_ascii_uppercase();
    !matches!(
        up.as_str(),
        "" | "OFF" | "FALSE" | "NO" | "N" | "0" | "IGNORE" | "NOTFOUND"
    ) && !up.ends_with("-NOTFOUND")
}

/// `value MATCHES pattern` for *simple* (anchors + literal) patterns only — a
/// pattern using real regex syntax is left indeterminate (`None`) rather than
/// mis-evaluated. The common gating case (`LEVEL MATCHES "error"`) is a literal.
fn cmake_matches(value: &str, pattern: &str) -> Option<bool> {
    let p = pattern.trim_start_matches('^').trim_end_matches('$');
    if p.is_empty()
        || p.chars()
            .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ' ')))
    {
        return None;
    }
    Some(value.contains(p))
}

#[derive(Debug)]
struct BuildCommand {
    name: String,
    args: Vec<String>,
}

fn cmake_commands(text: &str) -> Vec<BuildCommand> {
    // CMake commands frequently span multiple lines — a `target_sources(E57Format
    // PRIVATE BlobNode.cpp ... )` source list, a multi-line `set(VAR a b c)` — so a
    // line-by-line parse (requiring `(` and `)` on the same line) silently drops
    // them, and with them the library's real source/define list. Strip line
    // comments, then scan for `name( ... )` with a paren-balanced body that may
    // cross newlines. Both operations must respect quoted arguments: XZ's
    // version-extraction regex contains literal `#define` text and capture
    // parentheses, neither of which is CMake syntax at that point.
    let buf = strip_cmake_line_comments(text);
    let bytes = buf.as_bytes();
    let mut commands = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !(bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
            i += 1;
            continue;
        }
        let name_start = i;
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            i += 1;
        }
        let name = buf[name_start..i].to_ascii_lowercase();
        let mut j = i;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != b'(' {
            continue; // a bare identifier, not a command invocation
        }
        let args_start = j + 1;
        let mut depth = 1usize;
        let mut k = args_start;
        let mut in_quote = false;
        let mut escaped = false;
        while k < bytes.len() && depth > 0 {
            if escaped {
                escaped = false;
                k += 1;
                continue;
            }
            match bytes[k] {
                b'\\' => escaped = true,
                b'"' => in_quote = !in_quote,
                b'(' if !in_quote => depth += 1,
                b')' if !in_quote => depth -= 1,
                _ => {}
            }
            k += 1;
        }
        if depth != 0 {
            break; // unterminated command; give up rather than loop
        }
        commands.push(BuildCommand {
            name,
            args: split_build_tokens(&buf[args_start..k - 1]),
        });
        i = k;
    }
    commands
}

fn strip_cmake_line_comments(text: &str) -> String {
    let mut out = Vec::with_capacity(text.len());
    let mut in_quote = false;
    let mut in_comment = false;
    let mut escaped = false;
    for byte in text.bytes() {
        if in_comment {
            if byte == b'\n' {
                out.push(byte);
                in_comment = false;
            }
            continue;
        }
        if escaped {
            out.push(byte);
            escaped = false;
            continue;
        }
        match byte {
            b'\\' => {
                out.push(byte);
                escaped = true;
            }
            b'"' => {
                out.push(byte);
                in_quote = !in_quote;
            }
            b'#' if !in_quote => in_comment = true,
            _ => out.push(byte),
        }
    }
    String::from_utf8(out).expect("removing ASCII comments preserves UTF-8")
}

fn cmake_values_without_scopes(args: &[String], skip_prefix: usize) -> impl Iterator<Item = &str> {
    args.iter()
        .skip(skip_prefix)
        .map(String::as_str)
        .filter(|value| {
            !matches!(
                value.to_ascii_uppercase().as_str(),
                "PRIVATE"
                    | "PUBLIC"
                    | "INTERFACE"
                    | "SYSTEM"
                    | "BEFORE"
                    | "STATIC"
                    | "SHARED"
                    | "MODULE"
                    | "OBJECT"
                    | "EXCLUDE_FROM_ALL"
            )
        })
}

fn infer_make_build_context(source_path: &Path, makefile_path: &Path) -> CppBuildContext {
    let base_dir = makefile_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let mut context = CppBuildContext {
        provenance: "make".to_owned(),
        confidence: "low".to_owned(),
        compile_flags: Vec::new(),
        link_flags: Vec::new(),
        extra_sources: Vec::new(),
        recovery: Vec::new(),
    };
    let Ok(text) = fs::read_to_string(makefile_path) else {
        context
            .recovery
            .push(format!("unreadable_context:{}", makefile_path.display()));
        return context;
    };
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = split_make_assignment(line) else {
            continue;
        };
        let tokens = split_build_tokens(value);
        match key {
            "CPPFLAGS" | "CXXFLAGS" => {
                for token in tokens {
                    push_build_compile_flag(&mut context.compile_flags, &base_dir, &token);
                }
            }
            "LDFLAGS" | "LDLIBS" | "LIBS" => {
                for token in tokens {
                    if let Some(flag) = link_flag_from_build_token(&base_dir, &token) {
                        push_unique_string(&mut context.link_flags, flag);
                    }
                }
            }
            "SRCS" | "SOURCES" | "CXX_SRCS" | "CPP_SRCS" => {
                for token in tokens {
                    maybe_push_context_source(
                        source_path,
                        &base_dir,
                        &token,
                        &mut context.extra_sources,
                        &mut context.recovery,
                    );
                }
            }
            _ => {}
        }
    }
    context
}

fn split_make_assignment(line: &str) -> Option<(&str, &str)> {
    for op in ["+=", ":=", "="] {
        if let Some((key, value)) = line.split_once(op) {
            return Some((key.trim(), value.trim()));
        }
    }
    None
}

fn split_build_tokens(value: &str) -> Vec<String> {
    split_compile_command(value)
        .into_iter()
        .map(|token| token.trim_matches('"').trim_matches('\'').to_owned())
        .filter(|token| !token.is_empty())
        .collect()
}

fn push_build_compile_flag(flags: &mut Vec<String>, base_dir: &Path, token: &str) {
    if cmake_token_is_dynamic(token) || is_msvc_crt_model_define(token) {
        return;
    }
    // The `-f…` arm below is a broad catch-all (it forwards any `-f` flag a
    // project's `target_compile_options`/`CXXFLAGS` declares); drop the modules /
    // precompiled-header flags it would otherwise pass verbatim to the single-TU
    // harness compile. fmt's CMake `target_compile_options(... -fmodules-ts)` is
    // the canonical case — clang++ rejects `-fmodules-ts` with `unknown argument`.
    if is_harness_incompatible_flag(token) {
        return;
    }
    if let Some(value) = token.strip_prefix("-I").filter(|value| !value.is_empty()) {
        push_include_flag(flags, base_dir, value);
    } else if matches!(token, "-I" | "-isystem" | "-iquote" | "-idirafter")
        || token.starts_with("-D")
        || token.starts_with("-U")
        || token.starts_with("-std=")
        || token == "-pthread"
        || token.starts_with("-f")
    {
        push_unique_string(flags, token.to_owned());
    }
}

/// MSVC C-runtime *model* selection macros recovered from a Windows/CMake compile
/// database: `-D_DLL`, `-D_MT`, `-D_DEBUG`. These are set by the compiler's
/// `/MD[d]` / `/MT[d]` runtime-library flag, never by hand. `_DLL` in particular
/// makes the CRT headers declare every libc symbol `__declspec(dllimport)`
/// (referenced as `__imp_*`), which only resolves against the *dynamic* CRT import
/// library — but govfuzz links each harness against the static CRT (clang's default,
/// alongside the static ASan runtime). Inheriting these defines therefore yields
/// `unresolved external symbol __imp_strtod/__imp_fopen/...` at link time on Windows.
/// The harness owns its CRT model, so drop them; clang re-defines whatever its
/// chosen (static) model needs.
fn is_msvc_crt_model_define(token: &str) -> bool {
    token
        .strip_prefix("-D")
        .map(|m| m.split('=').next().unwrap_or(m))
        .is_some_and(|name| matches!(name, "_DLL" | "_MT" | "_DEBUG"))
}

fn push_include_flag(flags: &mut Vec<String>, base_dir: &Path, value: &str) {
    let resolved = resolve_build_context_path(base_dir, value);
    if !include_pair_exists(flags, &resolved) {
        flags.push("-I".to_owned());
        flags.push(resolved);
    }
}

fn include_pair_exists(flags: &[String], include_dir: &str) -> bool {
    flags
        .windows(2)
        .any(|pair| pair[0] == "-I" && pair[1] == include_dir)
}

fn maybe_push_context_source(
    source_path: &Path,
    base_dir: &Path,
    token: &str,
    extra_sources: &mut Vec<PathBuf>,
    recovery: &mut Vec<String>,
) {
    if cmake_token_is_dynamic(token) || !looks_like_cpp_source_token(token) {
        return;
    }
    let resolved = if Path::new(token).is_absolute() {
        normalize_path(Path::new(token))
    } else {
        normalize_path(&base_dir.join(token))
    };
    if normalized_path_key(&resolved) == normalized_path_key(source_path) {
        return;
    }
    if resolved.is_file() {
        if !extra_sources.contains(&resolved) {
            extra_sources.push(resolved);
        }
    } else {
        let note = format!("skipped_missing_source:{token}");
        if !recovery.contains(&note) {
            recovery.push(note);
        }
    }
}

fn looks_like_cpp_source_token(token: &str) -> bool {
    Path::new(token)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension == "C"
                || matches!(
                    extension.to_ascii_lowercase().as_str(),
                    "cc" | "cpp" | "cxx"
                )
        })
}

fn link_flag_from_build_token(base_dir: &Path, token: &str) -> Option<String> {
    if cmake_token_is_dynamic(token) {
        return None;
    }
    if token == "pthread" || token == "-pthread" {
        return Some("-pthread".to_owned());
    }
    if token.starts_with("-l") || token.starts_with("-L") || token.starts_with("-Wl,") {
        return Some(token.to_owned());
    }
    if token.ends_with(".a") || token.ends_with(".so") || token.ends_with(".dylib") {
        return Some(resolve_build_context_path(base_dir, token));
    }
    if token
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        // A bare library name from a build context (`target_link_libraries`) is
        // just as often a project-internal CMake target as a real system
        // library: PX4's `nuttx_fs` / `prebuild_targets` have no installed
        // `lib*.so/.a`, so forwarding `-lnuttx_fs` fails the entire isolated
        // harness link with "cannot find -lnuttx_fs". Only forward a bare name
        // that actually resolves to a linkable library; a self-contained parser
        // does not need the project's own link targets, and any symbol it
        // genuinely references degrades to a recoverable undefined-reference
        // (stub / added source) at link time instead of an unrecoverable
        // missing-library error.
        if !bare_library_resolves(token) {
            return None;
        }
        return Some(format!("-l{token}"));
    }
    None
}

/// Whether a bare library name resolves to an actual linkable library in the
/// standard system search paths (`lib<name>.so` or `lib<name>.a`). A runtime-only
/// `lib<name>.so.N` is deliberately insufficient: the linker cannot resolve
/// `-l<name>` without the development symlink or archive. Used to drop project-internal CMake
/// targets that masquerade as link libraries (see `link_flag_from_build_token`).
fn bare_library_resolves(name: &str) -> bool {
    const LIB_DIRS: &[&str] = &[
        "/usr/lib",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib64",
        "/lib",
        "/lib/x86_64-linux-gnu",
        "/usr/local/lib",
    ];
    let dirs: Vec<PathBuf> = LIB_DIRS.iter().map(PathBuf::from).collect();
    bare_library_resolves_in(name, &dirs)
}

fn bare_library_resolves_in(name: &str, dirs: &[PathBuf]) -> bool {
    let exact_so = format!("lib{name}.so");
    let archive = format!("lib{name}.a");
    dirs.iter()
        .any(|dir| dir.join(&exact_so).exists() || dir.join(&archive).exists())
}

fn resolve_build_context_path(base_dir: &Path, value: &str) -> String {
    let path = Path::new(value);
    let resolved = if path.is_absolute() {
        normalize_path(path)
    } else {
        normalize_path(&base_dir.join(path))
    };
    harness_gen::build_safety::make_path(&resolved)
}

fn cmake_token_is_dynamic(token: &str) -> bool {
    token.contains("${") || token.contains("$<") || token.contains("$(")
}

fn push_unique_string(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        auto_detect_c_headers, auto_detect_c_result_cleanup, auto_detect_project_includes,
        bare_library_resolves, build_harness_ast, c_build_flags_for_source,
        c_constructor_drive_plan, c_direct_lifecycle_table, c_signature_needs_project_header,
        c_va_list_variadic_wrapper, cmake_define_enables_std_module,
        collect_c_type_defs_for_harness, collect_cpp_using_namespaces, compile_database_candidates,
        compute_default_id, cpp_default_constructible_parameter_classes,
        cpp_namespace_begin_macros, detect_strdup_family_free, detect_top_level_namespaces_in_text,
        extract_compile_database_flags, find_project_header_declaring_target, generate_for_path,
        infer_cmake_build_context, infer_cmake_c_build_context, is_c_lifecycle_end,
        is_c_lifecycle_handle_type, is_c_lifecycle_init, is_c_scalar_type,
        is_harness_incompatible_flag, is_msvc_crt_model_define, is_non_library_dir,
        link_flag_from_build_token, locate_c_runtime, merge_dependency_packages_and_subprograms,
        merge_tree_c_lifecycle, numeric_token_byte_encodings, pick_c_target, pick_cpp_target,
        preflight_header_includes, push_build_compile_flag, recover_library_translation_units,
        resolve_cpp_member_access_from_headers, resolve_cpp_namespace_qualified_free_functions,
        run, select_subprogram, self_prefixed_include_roots, source_defines_main,
        source_header_visibility_flags, source_path_is_foreign_platform, CompileCommandEntry,
        CppBuildContext, DecoderLimitArgs, GenerateHarnessArgs, HeaderPreflight,
        BLOCKED_BY_NON_SELF_CONTAINED_HEADER,
    };
    use ada_parser::ast::{Package, PackageId, StructuralAst as StructuralAstForMerge};
    use ada_parser::ast::{
        Span, Subprogram, SubprogramId, SubprogramKind, SubprogramOwner, Visibility,
    };
    use clap::Parser;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn compile_database_candidates_includes_well_known_build_dirs() {
        let candidates = compile_database_candidates(Path::new("/proj/src/foo.c"));
        let has = |rel: &str| candidates.iter().any(|p| p == Path::new(rel));
        // Already supported: in-place and the conventional CMake `build/` dir.
        assert!(has("/proj/src/compile_commands.json"));
        assert!(has("/proj/build/compile_commands.json"));
        // Meson's default out-of-source build directory.
        assert!(has("/proj/builddir/compile_commands.json"));
        // CLion's default out-of-source build directories.
        assert!(has("/proj/cmake-build-debug/compile_commands.json"));
        assert!(has("/proj/cmake-build-release/compile_commands.json"));
        // Generic out-of-source convention used by many hand-rolled builds.
        assert!(has("/proj/out/compile_commands.json"));
        // Searched at every ancestor level, not just the project root.
        assert!(has("/proj/src/builddir/compile_commands.json"));
    }

    #[test]
    fn short_win_directory_is_foreign_on_unix_hosts() {
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            assert!(source_path_is_foreign_platform(Path::new(
                "/project/src/win/thread.c"
            )));
            assert!(!source_path_is_foreign_platform(Path::new(
                "/project/src/unix/thread.c"
            )));
        }
    }

    #[test]
    fn rtos_and_zos_directories_are_foreign_on_linux_hosts() {
        if cfg!(target_os = "linux") {
            assert!(source_path_is_foreign_platform(Path::new(
                "/project/builds/vxworks/platform.hpp"
            )));
            assert!(source_path_is_foreign_platform(Path::new(
                "/project/builds/qnx/platform.hpp"
            )));
            assert!(source_path_is_foreign_platform(Path::new(
                "/project/builds/zos/platform.hpp"
            )));
            assert!(source_path_is_foreign_platform(Path::new(
                "/project/builds/mingw32/platform.hpp"
            )));
        }
    }

    #[test]
    fn project_header_lookup_recovers_public_target_declaration() {
        let root = temp_dir("public-target-header");
        let include = root.join("include");
        fs::create_dir_all(include.join("yaml")).unwrap();
        fs::write(
            include.join("yaml/api.h"),
            "int yaml_parser_set_input_string(void *parser, const char *input);\n",
        )
        .unwrap();
        fs::write(
            include.join("unrelated.h"),
            "int yaml_parser_set_input_file(void *parser);\n",
        )
        .unwrap();

        assert_eq!(
            find_project_header_declaring_target(
                std::slice::from_ref(&include),
                "yaml_parser_set_input_string"
            )
            .as_deref(),
            Some("yaml/api.h")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn primitive_c_signature_does_not_require_project_header() {
        assert!(!c_signature_needs_project_header(
            "uint16_t",
            ["const char *", "int"]
        ));
        assert!(c_signature_needs_project_header(
            "int",
            ["struct redisCommand *", "client *"]
        ));
    }

    #[test]
    fn header_metadata_marks_out_of_line_static_member() {
        let root = temp_dir("cpp-static-member");
        let source_path = root.join("parse.cc");
        fs::write(
            &source_path,
            "class Regexp;\nRegexp* Regexp::Parse(const char* text) { return nullptr; }\n",
        )
        .unwrap();
        fs::write(
            root.join("regexp.h"),
            "class Regexp { public: static Regexp* Parse(const char* text); };\n",
        )
        .unwrap();
        let source = fs::read_to_string(&source_path).unwrap();
        let mut functions = cpp_parser::parse_cpp_functions(&source).unwrap();

        resolve_cpp_member_access_from_headers(
            &mut functions,
            &source_path,
            &["regexp.h".to_owned()],
            std::slice::from_ref(&root),
        );

        let parse = functions
            .iter()
            .find(|function| function.name == "Parse")
            .unwrap();
        assert!(parse.api.is_method);
        assert!(parse.is_static);
        assert_eq!(parse.api.member_access.as_deref(), Some("public"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn header_member_access_resolution_is_namespace_and_overload_exact() {
        let root = temp_dir("cpp-member-access-signature");
        let source_path = root.join("parse.cc");
        fs::write(
            &source_path,
            "void one::Parser::reset(int) {}\n\
             void one::Parser::reset(const char *) {}\n\
             void two::Parser::reset(const char *) {}\n",
        )
        .unwrap();
        fs::write(
            root.join("parser.h"),
            "namespace one { class Parser { public: void reset(int); private: void reset(const char *); }; }\n\
             namespace two { class Parser { public: void reset(const char *); }; }\n",
        )
        .unwrap();
        let source = fs::read_to_string(&source_path).unwrap();
        let mut functions = cpp_parser::parse_cpp_functions(&source).unwrap();

        resolve_cpp_member_access_from_headers(
            &mut functions,
            &source_path,
            &["parser.h".to_owned()],
            std::slice::from_ref(&root),
        );

        let access = |namespace: &str, parameter: &str| {
            functions
                .iter()
                .find(|function| {
                    function.qualifier_path.first().map(String::as_str) == Some(namespace)
                        && function.params[0].cpp_type == parameter
                })
                .and_then(|function| function.api.member_access.as_deref())
        };
        assert_eq!(access("one", "int"), Some("public"), "{functions:#?}");
        assert_eq!(
            access("one", "const char *"),
            Some("private"),
            "{functions:#?}"
        );
        assert_eq!(
            access("two", "const char *"),
            Some("public"),
            "{functions:#?}"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn header_namespace_marks_out_of_line_free_function() {
        let mut functions = cpp_parser::parse_cpp_functions(
            "const char *zmq::errno_to_string(int value) { return nullptr; }\n",
        )
        .unwrap();
        assert!(functions[0].api.is_method);

        resolve_cpp_namespace_qualified_free_functions(
            &mut functions,
            &["namespace zmq { const char *errno_to_string(int); }\n".to_owned()],
        );

        let function = &functions[0];
        assert!(!function.api.is_method);
        assert_eq!(function.api.namespace_path, vec!["zmq"]);
        assert_eq!(function.api.class_name, None);
    }

    #[test]
    fn target_source_static_linking_visibility_reaches_harness_headers() {
        let source = r#"
            #define LZ4F_STATIC_LINKING_ONLY
            #define ordinary_local_macro 1
            #define OTHER_STATIC_LINKING_ONLY 1
        "#;
        assert_eq!(
            source_header_visibility_flags(source),
            vec![
                "-DLZ4F_STATIC_LINKING_ONLY".to_owned(),
                "-DOTHER_STATIC_LINKING_ONLY".to_owned()
            ]
        );
    }

    fn merge_pkg(id: u32, name: &str, parent: Option<u32>) -> Package {
        Package {
            id: PackageId(id),
            name: name.to_owned(),
            parent: parent.map(PackageId),
            is_generic: false,
            formals: Vec::new(),
            decls: Vec::new(),
            is_private: false,
        }
    }

    #[test]
    fn msvc_crt_model_defines_are_dropped_from_build_flags() {
        // `_DLL`/`_MT`/`_DEBUG` recovered from a Windows CMake compile DB make the
        // CRT headers use dllimport (`__imp_*`), which fails the static-CRT harness
        // link. They must be dropped; ordinary project defines must be kept.
        assert!(is_msvc_crt_model_define("-D_DLL"));
        assert!(is_msvc_crt_model_define("-D_MT"));
        assert!(is_msvc_crt_model_define("-D_DEBUG"));
        assert!(is_msvc_crt_model_define("-D_DLL=1"));
        assert!(!is_msvc_crt_model_define("-DCJSON_EXPORT_SYMBOLS"));
        assert!(!is_msvc_crt_model_define("-D_DEBUGGING")); // not an exact match
        assert!(!is_msvc_crt_model_define("-DFOO=1"));

        let base = Path::new(".");
        let mut flags = Vec::new();
        for tok in [
            "-DCJSON_EXPORT_SYMBOLS",
            "-D_DLL",
            "-D_MT",
            "-D_DEBUG",
            "-DENABLE_LOCALES",
        ] {
            push_build_compile_flag(&mut flags, base, tok);
        }
        assert_eq!(
            flags,
            vec![
                "-DCJSON_EXPORT_SYMBOLS".to_owned(),
                "-DENABLE_LOCALES".to_owned()
            ],
            "CRT-model defines dropped, project defines kept: {flags:?}"
        );

        // The real path: extract_compile_database_flags ingests compile_commands.json
        // (this is where cJSON's `-D_DLL -D_MT -D_DEBUG` actually entered the build).
        let entry = CompileCommandEntry {
            directory: PathBuf::from("."),
            file: PathBuf::from("cJSON.c"),
            arguments: Some(
                [
                    "clang",
                    "-D_DLL",
                    "-D_MT",
                    "-D_DEBUG",
                    "-DENABLE_LOCALES",
                    "-DFOO=1",
                    "-std=c89",
                    "-c",
                    "cJSON.c",
                ]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ),
            command: None,
        };
        let db_flags = extract_compile_database_flags(&entry, Path::new("./cJSON.c"));
        assert!(
            db_flags
                .iter()
                .all(|f| f != "-D_DLL" && f != "-D_MT" && f != "-D_DEBUG"),
            "CRT-model defines must be dropped from the compile DB: {db_flags:?}"
        );
        assert!(
            db_flags.contains(&"-DENABLE_LOCALES".to_owned()),
            "{db_flags:?}"
        );
        assert!(db_flags.contains(&"-DFOO=1".to_owned()), "{db_flags:?}");
    }

    #[test]
    fn response_file_args_are_expanded_not_dropped() {
        // Offline-legacy audit / #93 AC5: a `@flags.rsp` argument must have its
        // `-I`/`-D` context expanded into the harness flags, not silently dropped
        // (which fails the offline build with missing-header errors).
        let dir = temp_dir("response-file-expand");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(dir.join("include")).unwrap();
        std::fs::write(
            dir.join("flags.rsp"),
            "-Iinclude\n-DFROM_RSP=1\n\"-DWITH SPACE=x\"\n@nested.rsp\n",
        )
        .unwrap();
        std::fs::write(dir.join("nested.rsp"), "-DNESTED=2\n").unwrap();
        let entry = CompileCommandEntry {
            directory: dir.clone(),
            file: dir.join("t.c"),
            arguments: Some(
                ["clang", "@flags.rsp", "-DINLINE=3", "-c", "t.c"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            ),
            command: None,
        };
        let flags = extract_compile_database_flags(&entry, &dir.join("t.c"));
        assert!(
            flags.contains(&"-DFROM_RSP=1".to_owned()),
            "response-file define expanded: {flags:?}"
        );
        assert!(
            flags.contains(&"-DNESTED=2".to_owned()),
            "nested response-file define expanded: {flags:?}"
        );
        assert!(
            flags.contains(&"-DWITH SPACE=x".to_owned()),
            "quoted response-file token preserved: {flags:?}"
        );
        assert!(flags.contains(&"-DINLINE=3".to_owned()), "{flags:?}");
        // The -I path was resolved against the compile dir and included.
        assert!(
            flags.iter().any(|f| f == "-I") && flags.iter().any(|f| f.ends_with("include")),
            "response-file include path expanded + resolved: {flags:?}"
        );
        // A dropped-families marker must NOT record response_file (it was expanded).
        assert!(
            !flags
                .iter()
                .any(|f| f.starts_with(super::BUILD_CONTEXT_DROPPED_PREFIX)
                    && f.contains("response_file")),
            "an expanded response file must not be recorded as dropped: {flags:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn harness_incompatible_flags_drop_modules_and_pch_keep_the_rest() {
        // GAP 1 (campaign: fmt): the C++-modules and precompiled-header flags a
        // project's build wiring may declare break or mean nothing to govfuzz's
        // standalone single-TU harness compile, and must be dropped.
        for bad in [
            "-fmodules-ts",
            "-fmodules",
            "-fmodule-map-file=/x/module.modulemap",
            "-fmodule-name=fmt",
            "-fmodule-file=fmt=/x/fmt.pcm",
            "-fprebuilt-module-path=/x/pcm",
            "-include-pch",
            "-fpch-preprocess",
            "-fpch-instantiate-templates",
        ] {
            assert!(
                is_harness_incompatible_flag(bad),
                "{bad} must be treated as harness-incompatible"
            );
        }
        // Ordinary compile-relevant flags must be KEPT (never matched).
        for good in [
            "-I/proj/include",
            "-isystem",
            "-DFMT_HEADER_ONLY=1",
            "-std=c++20",
            "-pthread",
            "-fno-exceptions", // an unrelated -f flag must pass through
            "-fvisibility=hidden",
        ] {
            assert!(
                !is_harness_incompatible_flag(good),
                "{good} must NOT be treated as harness-incompatible"
            );
        }

        // The CMake `target_compile_options(... -fmodules-ts)` path (the actual
        // fmt break) is filtered: `-fmodules-ts` is dropped while a sibling
        // `-std=c++20` / `-DFOO` / `-fno-exceptions` survives.
        let base = Path::new(".");
        let mut flags = Vec::new();
        for tok in [
            "-fmodules-ts",
            "-std=c++20",
            "-DFMT_USE_X=1",
            "-fno-exceptions",
        ] {
            push_build_compile_flag(&mut flags, base, tok);
        }
        assert!(
            !flags.iter().any(|f| f == "-fmodules-ts"),
            "CMake/Make -fmodules-ts must be dropped: {flags:?}"
        );
        assert!(
            flags.contains(&"-std=c++20".to_owned())
                && flags.contains(&"-DFMT_USE_X=1".to_owned())
                && flags.contains(&"-fno-exceptions".to_owned()),
            "sibling compile flags must be kept: {flags:?}"
        );

        // The compile_commands.json path drops `-fmodules-ts` (and the
        // `-include-pch <file>` two-token form) while keeping `-I`/`-D`/`-std`.
        let entry = CompileCommandEntry {
            directory: PathBuf::from("/proj"),
            file: PathBuf::from("src/fmt.cc"),
            arguments: Some(
                [
                    "clang++",
                    "-I/proj/include",
                    "-DFMT_HEADER_ONLY=1",
                    "-std=c++20",
                    "-fmodules-ts",
                    "-include-pch",
                    "/proj/build/fmt.pch",
                    "-c",
                    "src/fmt.cc",
                ]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ),
            command: None,
        };
        let db_flags = extract_compile_database_flags(&entry, Path::new("/proj/src/fmt.cc"));
        assert!(
            !db_flags.iter().any(|f| f == "-fmodules-ts"),
            "compile DB -fmodules-ts must be dropped: {db_flags:?}"
        );
        assert!(
            !db_flags
                .iter()
                .any(|f| f.ends_with(".pch") || f == "-include-pch"),
            "compile DB -include-pch + its operand must be dropped: {db_flags:?}"
        );
        assert!(
            db_flags.iter().any(|f| f == "-std=c++20")
                && db_flags.iter().any(|f| f == "-DFMT_HEADER_ONLY=1")
                && db_flags.iter().any(|f| f == "/proj/include"),
            "compile-relevant flags must survive: {db_flags:?}"
        );
    }

    #[test]
    fn compile_database_preserves_compiler_abi_and_extension_context() {
        let entry = CompileCommandEntry {
            directory: PathBuf::from("/project/build"),
            file: PathBuf::from("../src/legacy.cpp"),
            arguments: Some(
                [
                    "/opt/toolchain/bin/g++-12",
                    "-fms-extensions",
                    "-fpermissive",
                    "-fpack-struct=1",
                    "-fshort-enums",
                    "-mms-bitfields",
                    "--sysroot",
                    "/opt/sysroot",
                    "--target=x86_64-linux-gnu",
                    "-include",
                    "../include/config.h",
                    "-fplugin=/tmp/execute.so",
                    "-fmodules-ts",
                    "-MJ",
                    "deps.json",
                    "-c",
                    "../src/legacy.cpp",
                ]
                .iter()
                .map(|value| value.to_string())
                .collect(),
            ),
            command: None,
        };
        let flags = extract_compile_database_flags(&entry, Path::new("/project/src/legacy.cpp"));
        for expected in [
            "@govfuzz-build-context-compiler=/opt/toolchain/bin/g++-12",
            "-fms-extensions",
            "-fpermissive",
            "-fpack-struct=1",
            "-fshort-enums",
            "-mms-bitfields",
            "--sysroot",
            "/opt/sysroot",
            "--target=x86_64-linux-gnu",
            "-include",
            "/project/include/config.h",
        ] {
            assert!(
                flags.iter().any(|flag| flag == expected),
                "missing {expected}: {flags:?}"
            );
        }
        assert!(!flags.iter().any(|flag| {
            flag.starts_with("-fplugin")
                || flag == "-fmodules-ts"
                || flag == "-MJ"
                || flag.ends_with("deps.json")
        }));
    }

    #[test]
    fn recover_library_tus_uses_compile_db_then_sibling_fallback() {
        // GAP 2 (campaign: yaml-cpp): a multi-TU library with no prebuilt archive
        // must have its full translation-unit set recovered so the harness link
        // closes in one shot — from compile_commands.json when present, else the
        // sibling sources in the target's own src/ subtree. The target itself and
        // any `main`-defining TU (a test/tool entrypoint) are always excluded.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let src = root.join("src");
        let tests = root.join("tests");
        std::fs::create_dir_all(src.join("contrib")).unwrap();
        std::fs::create_dir_all(src.join("dispatch/one")).unwrap();
        std::fs::create_dir_all(src.join("dispatch/two")).unwrap();
        std::fs::create_dir_all(src.join("prim/wasi")).unwrap();
        std::fs::create_dir_all(src.join("prim/osx")).unwrap();
        std::fs::create_dir_all(src.join("prim/unix")).unwrap();
        std::fs::create_dir_all(&tests).unwrap();
        // The target + two library siblings + a tool main + a test main.
        std::fs::write(src.join("emitter.cpp"), "int emit() { return 0; }\n").unwrap();
        std::fs::write(src.join("emitterstate.cpp"), "int state() { return 1; }\n").unwrap();
        std::fs::write(src.join("linux.cpp"), "int platform() { return 1; }\n").unwrap();
        std::fs::write(src.join("darwin.cpp"), "int platform() { return 2; }\n").unwrap();
        std::fs::write(src.join("event_iocp.cpp"), "int iocp() { return 2; }\n").unwrap();
        std::fs::write(
            src.join("async_backend.cpp"),
            "#include \"iocp-backend.h\"\nint async_backend() { return 2; }\n",
        )
        .unwrap();
        std::fs::write(
            src.join("iocp-internal.h"),
            "struct event_overlapped;\n\
             #ifdef _WIN32\n#include <windows.h>\n#endif\n",
        )
        .unwrap();
        std::fs::write(
            src.join("core_event.cpp"),
            "#include \"iocp-internal.h\"\nint evutil_closesocket(int);\n\
             int core_event() { return evutil_closesocket(1); }\n",
        )
        .unwrap();
        std::fs::write(
            src.join("bufferevent_async.cpp"),
            "#include \"iocp-internal.h\"\nstruct event_overlapped pending;\n",
        )
        .unwrap();
        std::fs::write(
            src.join("portable_time.cpp"),
            "#ifdef _WIN32\n#include <windows.h>\n#endif\nint portable_time() { return 1; }\n",
        )
        .unwrap();
        std::fs::write(
            src.join("prim/wasi/prim.cpp"),
            "int wasi_backend() { return 2; }\n",
        )
        .unwrap();
        std::fs::write(
            src.join("prim/osx/zone.cpp"),
            "int osx_backend() { return 2; }\n",
        )
        .unwrap();
        std::fs::write(
            src.join("prim/unix/prim.cpp"),
            "int unix_backend() { return 1; }\n",
        )
        .unwrap();
        std::fs::write(
            src.join("bufferevent_mbedtls.cpp"),
            "int optional_tls() { return 2; }\n",
        )
        .unwrap();
        std::fs::write(
            src.join("testhelpers.cpp"),
            "int test_only() { return 3; }\n",
        )
        .unwrap();
        std::fs::write(
            src.join("emitter_test.cpp"),
            "int suffix_test_only() { return 4; }\n",
        )
        .unwrap();
        std::fs::write(src.join("detail.cpp"), "int detail() { return 5; }\n").unwrap();
        std::fs::write(
            src.join("included_fragment.cpp"),
            "int fragment() { return 6; }\n",
        )
        .unwrap();
        std::fs::write(
            src.join("unity.cpp"),
            "#include \"included_fragment.cpp\"\nint unity() { return fragment(); }\n",
        )
        .unwrap();
        std::fs::write(
            src.join("target_unity.cpp"),
            "#include \"emitter.cpp\"\n#include \"emitterstate.cpp\"\n",
        )
        .unwrap();
        std::fs::write(
            src.join("broken_optional.cpp"),
            "#include \"deleted_impl.cpp\"\nint broken_optional() { return 0; }\n",
        )
        .unwrap();
        std::fs::write(
            src.join("dispatch/prim.cpp"),
            "#include \"one/prim.cpp\"\n#include \"two/prim.cpp\"\n",
        )
        .unwrap();
        std::fs::write(
            src.join("dispatch/one/prim.cpp"),
            "int one() { return 1; }\n",
        )
        .unwrap();
        std::fs::write(
            src.join("dispatch/two/prim.cpp"),
            "int two() { return 2; }\n",
        )
        .unwrap();
        std::fs::write(
            src.join("contrib/graphbuilder.cpp"),
            "int g() { return 2; }\n",
        )
        .unwrap();
        std::fs::write(
            src.join("yaml_tool.cpp"),
            "int main(int c, char** v){return 0;}\n",
        )
        .unwrap();
        std::fs::write(tests.join("test_main.cpp"), "int main(){return 0;}\n").unwrap();
        let target = src.join("emitter.cpp");

        // --- Tier 2: no compile DB -> sibling sources in src/ (and src/contrib),
        // excluding the target, the `main`-defining tool, and the tests/ dir. ---
        let siblings = recover_library_translation_units(&target, true);
        assert!(
            siblings.contains(&src.join("emitterstate.cpp")),
            "sibling library TU must be recovered: {siblings:?}"
        );
        assert!(
            siblings.contains(&src.join("contrib/graphbuilder.cpp")),
            "nested library TU must be recovered: {siblings:?}"
        );
        assert!(
            !siblings.contains(&target),
            "the target source must be excluded: {siblings:?}"
        );
        assert!(
            !siblings.iter().any(|p| p.ends_with("yaml_tool.cpp")),
            "a `main`-defining TU must be excluded: {siblings:?}"
        );
        assert!(
            !siblings.iter().any(|p| p.ends_with("test_main.cpp")),
            "a tests/ TU must be excluded: {siblings:?}"
        );
        assert!(
            !siblings.iter().any(|p| p.ends_with("testhelpers.cpp")),
            "a root-level test*.cpp TU must be excluded: {siblings:?}"
        );
        assert!(
            !siblings.iter().any(|p| p.ends_with("emitter_test.cpp")),
            "a root-level *_test.cpp TU must be excluded: {siblings:?}"
        );
        assert!(
            siblings.iter().any(|p| p.ends_with("unity.cpp"))
                && !siblings
                    .iter()
                    .any(|p| p.ends_with("included_fragment.cpp")),
            "a textually included .cpp fragment must not also compile standalone: {siblings:?}"
        );
        assert!(
            !siblings.iter().any(|p| p.ends_with("target_unity.cpp"))
                && siblings.iter().any(|p| p.ends_with("emitterstate.cpp")),
            "an amalgamation containing the target must be excluded without suppressing its standalone siblings: {siblings:?}"
        );
        assert!(
            !siblings.iter().any(|p| p.ends_with("broken_optional.cpp")),
            "a sibling with a missing textual implementation include must be excluded: {siblings:?}"
        );
        assert!(
            siblings.contains(&src.join("dispatch/prim.cpp"))
                && !siblings.contains(&src.join("dispatch/one/prim.cpp"))
                && !siblings.contains(&src.join("dispatch/two/prim.cpp")),
            "include suppression must compare resolved paths when dispatcher and leaves share a basename: {siblings:?}"
        );
        if cfg!(target_os = "linux") {
            assert!(siblings.iter().any(|p| p.ends_with("linux.cpp")));
            assert!(
                siblings.iter().any(|p| p.ends_with("prim/unix/prim.cpp")),
                "the host-compatible Unix backend must remain: {siblings:?}"
            );
            assert!(
                !siblings.iter().any(|p| p.ends_with("darwin.cpp")),
                "a foreign flat-layout platform TU must be excluded: {siblings:?}"
            );
            assert!(
                !siblings.iter().any(|p| p.ends_with("event_iocp.cpp")),
                "a flat-layout IOCP backend must be excluded on Linux: {siblings:?}"
            );
            assert!(
                !siblings.iter().any(|p| p.ends_with("async_backend.cpp")),
                "an unconditionally IOCP-backed TU must be excluded on Linux: {siblings:?}"
            );
            assert!(
                siblings.iter().any(|p| p.ends_with("core_event.cpp")),
                "a portable TU may include a locally guarded IOCP header: {siblings:?}"
            );
            assert!(
                !siblings
                    .iter()
                    .any(|p| p.ends_with("bufferevent_async.cpp")),
                "unguarded foreign backend types make the TU host-ineligible: {siblings:?}"
            );
            assert!(
                siblings.iter().any(|p| p.ends_with("portable_time.cpp")),
                "a portable TU with a guarded Windows include must remain: {siblings:?}"
            );
        }
        if !cfg!(target_arch = "wasm32") {
            assert!(
                !siblings.iter().any(|p| p.ends_with("prim/wasi/prim.cpp")),
                "a WASI directory backend must be excluded on a native host: {siblings:?}"
            );
        }
        if !cfg!(target_os = "macos") {
            assert!(
                !siblings.iter().any(|p| p.ends_with("prim/osx/zone.cpp")),
                "an OSX directory backend must be excluded off macOS: {siblings:?}"
            );
        }
        assert!(
            !siblings
                .iter()
                .any(|p| p.ends_with("bufferevent_mbedtls.cpp")),
            "an optional external TLS backend must not enter a default library sweep: {siblings:?}"
        );

        // --- Tier 1: a compile_commands.json takes precedence and yields exactly
        // its non-target, non-main C/C++ entries. ---
        let db = format!(
            r#"[
              {{"directory":"{root}","file":"src/emitter.cpp","arguments":["clang++","-c","src/emitter.cpp"]}},
              {{"directory":"{root}","file":"src/emitterstate.cpp","arguments":["clang++","-c","src/emitterstate.cpp"]}},
              {{"directory":"{root}","file":"src/contrib/graphbuilder.cpp","arguments":["clang++","-c","src/contrib/graphbuilder.cpp"]}},
              {{"directory":"{root}","file":"src/emitter_test.cpp","arguments":["clang++","-c","src/emitter_test.cpp"]}},
              {{"directory":"{root}","file":"src/yaml_tool.cpp","arguments":["clang++","-c","src/yaml_tool.cpp"]}}
            ]"#,
            root = root.display()
        );
        std::fs::write(root.join("compile_commands.json"), db).unwrap();
        let from_db = recover_library_translation_units(&target, true);
        assert!(
            from_db.contains(&src.join("emitterstate.cpp"))
                && from_db.contains(&src.join("contrib/graphbuilder.cpp")),
            "compile-DB TUs must be recovered: {from_db:?}"
        );
        assert!(
            !from_db.contains(&target)
                && !from_db.iter().any(|p| p.ends_with("yaml_tool.cpp"))
                && !from_db.iter().any(|p| p.ends_with("emitter_test.cpp")),
            "compile-DB path must exclude the target, tests, and `main` TUs: {from_db:?}"
        );

        // Predicate spot-checks.
        assert!(source_defines_main(&src.join("yaml_tool.cpp")));
        assert!(!source_defines_main(&src.join("emitterstate.cpp")));
        assert!(is_non_library_dir("tests") && is_non_library_dir("third_party"));
        assert!(!is_non_library_dir("contrib") && !is_non_library_dir("src"));
    }

    #[test]
    fn recover_library_tus_rejects_application_sized_sets() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        let target = src.join("target.c");
        std::fs::write(&target, "int target(void) { return 0; }\n").unwrap();
        for i in 0..41 {
            std::fs::write(
                src.join(format!("component_{i:03}.c")),
                format!("int component_{i:03}(void) {{ return {i}; }}\n"),
            )
            .unwrap();
        }

        let tus = recover_library_translation_units(&target, false);
        assert!(
            tus.is_empty(),
            "an oversized application tree must fall back to per-symbol recovery, not an arbitrary partial link: {tus:?}"
        );
    }

    #[test]
    fn recover_library_tus_does_not_cross_project_root_into_contrib() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(root.join("contrib/other")).unwrap();
        let target = root.join("codec.c");
        std::fs::write(&target, "int codec(void) { return helper(); }\n").unwrap();
        std::fs::write(root.join("helper.c"), "int helper(void) { return 1; }\n").unwrap();
        std::fs::write(
            root.join("contrib/other/read.c"),
            "int read(void) { return 2; }\n",
        )
        .unwrap();

        let tus = recover_library_translation_units(&target, false);
        assert!(tus.iter().any(|path| path.ends_with("helper.c")));
        assert!(
            !tus.iter().any(|path| path.ends_with("read.c")),
            "project-root recovery crossed into an independent contrib component: {tus:?}"
        );
    }

    #[test]
    fn c_target_tu_recovery_excludes_cpp_and_test_translation_units() {
        // #3 (cmark): a C target's harness builds with a C-only `clang -std=c<NN>`
        // recipe. A compile DB that lists a C++ test TU (cmark's
        // `api_test/cplusplus.cpp`) must NOT be swept into the C library link —
        // doing so produced a false failed_build. The C sibling stays; the C++ and
        // the test-dir TUs are excluded.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let src = root.join("src");
        std::fs::create_dir_all(src.join("api_test")).unwrap();
        std::fs::write(src.join("cmark.c"), "int cmark_parse(void){return 0;}\n").unwrap();
        std::fs::write(src.join("blocks.c"), "int blocks(void){return 1;}\n").unwrap();
        std::fs::write(
            src.join("api_test/cplusplus.cpp"),
            "extern \"C\" int cpptest(){return 0;}\n",
        )
        .unwrap();
        let target = src.join("cmark.c");
        let db = format!(
            r#"[
              {{"directory":"{root}","file":"src/cmark.c","arguments":["clang","-c","src/cmark.c"]}},
              {{"directory":"{root}","file":"src/blocks.c","arguments":["clang","-c","src/blocks.c"]}},
              {{"directory":"{root}","file":"src/api_test/cplusplus.cpp","arguments":["clang++","-c","src/api_test/cplusplus.cpp"]}}
            ]"#,
            root = root.display()
        );
        std::fs::write(root.join("compile_commands.json"), db).unwrap();

        // C target (cpp_target = false).
        let tus = recover_library_translation_units(&target, false);
        assert!(
            tus.contains(&src.join("blocks.c")),
            "the C sibling must be recovered: {tus:?}"
        );
        assert!(
            !tus.iter().any(|p| p.ends_with("cplusplus.cpp")),
            "a C++ TU must NOT be linked into a C target (extension + api_test dir): {tus:?}"
        );
    }

    #[test]
    fn text_declares_function_detects_prototype_not_substring() {
        use super::text_declares_function;
        let header =
            "CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count);";
        assert!(text_declares_function(header, "cJSON_CreateStringArray"));
        // Whitespace between name and `(` still counts.
        assert!(text_declares_function(
            "int parse (const char *s);",
            "parse"
        ));
        // A longer identifier ending in the name is NOT a match.
        assert!(!text_declares_function(
            "int my_parse(const char *s);",
            "parse"
        ));
        // The name not followed by `(` (a field / typedef use) is NOT a decl.
        assert!(!text_declares_function("struct { int parse; } x;", "parse"));
        assert!(!text_declares_function(
            "// the main (exit) thread\nconst char *s = \"main()\";\n/* main (also) */\n",
            "main"
        ));
    }

    #[test]
    fn merging_a_dependency_remaps_nested_package_parent() {
        // Regression: merging a dependency's packages used to hard-null `parent`,
        // so a nested package (zip-ada `Zip_Streams.Calendar`) became a bare
        // `Calendar` and its constructor emitted unqualified (`Calendar.Time_Of`).
        // The parent must be remapped into the main AST's id space.
        let mut ast = StructuralAstForMerge {
            packages: vec![merge_pkg(0, "Zip_Streams", None)],
            ..StructuralAstForMerge::new()
        };
        // Dependency AST: Zip_Streams (id 0) + nested Calendar (id 1, parent 0).
        let dep = StructuralAstForMerge {
            packages: vec![
                merge_pkg(0, "Zip_Streams", None),
                merge_pkg(1, "Calendar", Some(0)),
            ],
            ..StructuralAstForMerge::new()
        };
        merge_dependency_packages_and_subprograms(&mut ast, &dep);

        let zs = ast
            .packages
            .iter()
            .find(|p| p.name == "Zip_Streams")
            .expect("Zip_Streams present");
        let cal = ast
            .packages
            .iter()
            .find(|p| p.name == "Calendar")
            .expect("Calendar merged in");
        assert_eq!(
            cal.parent,
            Some(zs.id),
            "nested Calendar's parent must remap to the main-AST Zip_Streams"
        );
    }

    #[test]
    fn detect_top_level_namespaces_ignores_macro_body_namespaces() {
        // harfbuzz declares `namespace Namespace { ... }` ONLY inside multi-line
        // `#define` bodies (hb-null.hh, hb-ot-face.hh). A continuation line that
        // happens to start with `namespace Namespace {` must not be mistaken for a
        // real top-level namespace (it produced a bogus `using namespace Namespace;`).
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-ns-macro-{nonce}"));
        fs::create_dir_all(&dir).unwrap();
        let header = dir.join("hb-algs.hh");
        fs::write(
            &header,
            "namespace hb {\n\
             #define HB_DEFINE_TABLE(name) \\\n\
             namespace Namespace { \\\n\
                 struct name {}; \\\n\
             }\n\
             int fasthash64(int x) { return x; }\n\
             }\n",
        )
        .unwrap();
        let text = fs::read_to_string(&header).unwrap();
        let found = detect_top_level_namespaces_in_text(&text);
        assert!(
            found.contains(&"hb".to_owned()),
            "real namespace hb: {found:?}"
        );
        assert!(
            !found.contains(&"Namespace".to_owned()),
            "macro-body namespace must be ignored: {found:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolves_begin_namespace_macro_spelling() {
        let config = r#"#  define FMT_BEGIN_NAMESPACE \\
namespace fmt { \\
inline namespace v12 {
"#;
        let format = "FMT_BEGIN_NAMESPACE\nnamespace detail { struct value {}; }\n";
        let texts = vec![config.to_owned(), format.to_owned()];
        let macros = cpp_namespace_begin_macros(&texts);

        assert_eq!(
            macros.get("FMT_BEGIN_NAMESPACE"),
            Some(&vec!["fmt".to_owned(), "v12".to_owned()])
        );
        let namespaces = collect_cpp_using_namespaces(&texts, &macros);
        assert_eq!(namespaces.first().map(String::as_str), Some("fmt"));
        assert!(namespaces.iter().any(|namespace| namespace == "detail"));
    }

    #[test]
    fn build_token_drops_unresolvable_project_internal_libs() {
        let base = Path::new("/tmp");
        // A project-internal CMake target with no installed library is dropped,
        // so it cannot poison the isolated harness link (PX4 `nuttx_fs`).
        assert_eq!(
            link_flag_from_build_token(base, "nuttx_fs_no_such_lib_xyz"),
            None
        );
        assert!(!bare_library_resolves("nuttx_fs_no_such_lib_xyz"));
        // A real system library is still forwarded.
        assert!(bare_library_resolves("c"));
        assert_eq!(
            link_flag_from_build_token(base, "c"),
            Some("-lc".to_owned())
        );
        // pthread keeps its canonical `-pthread` form regardless of resolution.
        assert_eq!(
            link_flag_from_build_token(base, "pthread"),
            Some("-pthread".to_owned())
        );
        // Explicit `-l`/`-L` flags pass through untouched.
        assert_eq!(
            link_flag_from_build_token(base, "-lwhatever"),
            Some("-lwhatever".to_owned())
        );
    }

    #[test]
    fn runtime_only_versioned_library_is_not_linkable_by_bare_name() {
        let root = temp_dir("runtime-only-lib");
        fs::write(root.join("liboptional.so.7"), "not a real library").unwrap();
        assert!(!super::bare_library_resolves_in(
            "optional",
            std::slice::from_ref(&root)
        ));
        fs::write(root.join("liboptional.so"), "linker name").unwrap();
        assert!(super::bare_library_resolves_in(
            "optional",
            std::slice::from_ref(&root)
        ));
    }

    #[test]
    fn c_lifecycle_detection_matches_whole_name_tokens_only() {
        // Substring matching misclassified ordinary operations as
        // lifecycle steps: "append"/"send" contain "end", "renew"
        // contains "new", "deinit" contains "init".
        assert!(!is_c_lifecycle_end("buffer_append"));
        assert!(!is_c_lifecycle_end("msg_send"));
        assert!(!is_c_lifecycle_init("renew"));
        assert!(!is_c_lifecycle_init("zip_writer_deinit"));

        assert!(is_c_lifecycle_init("mz_zip_reader_init"));
        assert!(is_c_lifecycle_init("buffer_create"));
        assert!(is_c_lifecycle_init("CreateBuffer"));
        assert!(is_c_lifecycle_end("mz_zip_writer_end"));
        assert!(is_c_lifecycle_end("bufferFree"));
        assert!(is_c_lifecycle_end("ctx_destroy"));

        // Longer whole-token spellings (libyaml-style) that exact-token
        // matching missed before: "initialize" != "init", "delete" not listed.
        assert!(is_c_lifecycle_init("yaml_parser_initialize"));
        assert!(is_c_lifecycle_init("yaml_emitter_initialise"));
        assert!(is_c_lifecycle_end("yaml_parser_delete"));
        assert!(is_c_lifecycle_end("ctx_cleanup"));
        assert!(is_c_lifecycle_end("session_dispose"));
        // "initialize" must still not read as an end, nor "delete" as init.
        assert!(!is_c_lifecycle_end("yaml_parser_initialize"));
        assert!(!is_c_lifecycle_init("yaml_parser_delete"));

        // #17: a library-prefix+verb GLUE (lua `luaL_newstate` -> token `newstate`)
        // must be recognized so lua_State is constructable; lua_close is already a
        // whole-token end. A glued destructor (freestate) is also recognized.
        assert!(is_c_lifecycle_init("luaL_newstate"));
        assert!(is_c_lifecycle_init("lua_newstate"));
        assert!(is_c_lifecycle_init("ctx_opendir"));
        assert!(is_c_lifecycle_end("lua_close"));
        assert!(is_c_lifecycle_end("obj_freestate"));
        // ...but the glue must be a real PREFIX: renew/deinit stay excluded, and a
        // non-glue verb (init/setup) is not prefix-matched.
        assert!(!is_c_lifecycle_init("renew"));
        assert!(!is_c_lifecycle_init("foo_initializer_count")); // 'init' is non-glue
    }

    #[test]
    fn callback_typedef_constructor_args_use_null_defaults() {
        let args = super::c_neutral_ctor_args(
            ["brotli_alloc_func", "brotli_free_func", "void *"].into_iter(),
        )
        .expect("callback and pointer constructor args are nullable");
        assert_eq!(args, vec!["NULL", "NULL", "NULL"]);
        assert!(super::c_neutral_ctor_args(["size_t"].into_iter()).is_none());
    }

    #[test]
    fn ada_param_typed_with_dependency_package_array_resolves_via_ada_deps() {
        // A parameter typed with a *dependency* package's array type
        // (`Compute (Data : Bits.Byte_Array)`, with Bits supplied through
        // `--ada-deps`) must resolve to its real array definition so the
        // byte-buffer decoder fires — not fall through to unsupported_params.
        // Regression for SweetAda modules/crc (Compute went 0 -> built_and_fuzzed
        // once the dep dir reached the harness analysis roots).
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-ada-dep-array-{nonce}"));
        let proj = root.join("modules").join("crc");
        let core = root.join("core");
        let out = root.join("out");
        fs::create_dir_all(&proj).unwrap();
        fs::create_dir_all(&core).unwrap();
        fs::create_dir_all(&out).unwrap();
        fs::write(
            core.join("bits.ads"),
            "with Interfaces;\npackage Bits is\n   type Byte_Array is array (Natural range <>) of Interfaces.Unsigned_8;\nend Bits;\n",
        )
        .unwrap();
        fs::write(
            proj.join("crc.ads"),
            "with Bits;\npackage Crc is\n   function Compute (Data : Bits.Byte_Array) return Natural;\nend Crc;\n",
        )
        .unwrap();
        fs::write(
            proj.join("crc.adb"),
            "package body Crc is\n   function Compute (Data : Bits.Byte_Array) return Natural is\n   begin\n      return Data'Length;\n   end Compute;\nend Crc;\n",
        )
        .unwrap();
        let body = proj.join("crc.adb");

        // Without the dependency dir, Bits.Byte_Array is unresolved -> the target
        // is un-harnessable.
        let without = generate_for_path(
            &body,
            "Compute",
            None,
            &out,
            "H-CRC-WITHOUT",
            None,
            Some(proj.as_path()),
            &[],
            None,
            DecoderLimitArgs::default(),
            false,
        );
        assert!(
            without.is_err(),
            "without the dep dir, Bits.Byte_Array should be unresolved",
        );

        // With Bits supplied via --ada-deps, the array type resolves and the
        // harness generates.
        generate_for_path(
            &body,
            "Compute",
            None,
            &out,
            "H-CRC-WITH",
            None,
            Some(proj.as_path()),
            std::slice::from_ref(&core),
            None,
            DecoderLimitArgs::default(),
            false,
        )
        .expect("Bits.Byte_Array should resolve when its package is on --ada-deps");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn collect_c_type_defs_follows_includes_transitively() {
        // seL4's `word_t -> seL4_Word -> seL4_Uint64 -> unsigned long` typedef
        // chain spans several headers, each pulled in only transitively. Parsing
        // just the directly-included header leaves the chain's leaves unknown, so
        // a `word_t` parameter collapses to an opaque type and the target is
        // skipped. The collector must follow `#include`s across the project's
        // header closure.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-transitive-typedef-{nonce}"));
        let inc = root.join("include");
        fs::create_dir_all(&inc).unwrap();
        fs::write(
            inc.join("top.h"),
            "#include \"mid.h\"\ntypedef seL4_Word word_t;\n",
        )
        .unwrap();
        fs::write(
            inc.join("mid.h"),
            "#include \"leaf.h\"\ntypedef seL4_Uint64 seL4_Word;\n",
        )
        .unwrap();
        fs::write(inc.join("leaf.h"), "typedef unsigned long seL4_Uint64;\n").unwrap();

        let src_dir = root.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let source = "#include \"top.h\"\nvoid f(word_t x) { (void)x; }\n";
        let source_path = src_dir.join("k.c");
        fs::write(&source_path, source).unwrap();

        let defs = collect_c_type_defs_for_harness(
            &source_path,
            source,
            &["top.h".to_owned()],
            std::slice::from_ref(&inc),
            false,
        );

        let names: Vec<&str> = defs
            .iter()
            .flat_map(|d| d.typedefs.iter().map(|t| t.name.as_str()))
            .collect();
        assert!(
            names.contains(&"seL4_Word"),
            "transitive typedef from mid.h missing: {names:?}"
        );
        assert!(
            names.contains(&"seL4_Uint64"),
            "transitive typedef from leaf.h missing: {names:?}"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cjson_delete_cleanup_only_for_pointer_return_not_cjson_bool() {
        // cJSON * return from an ALLOCATOR owns an object -> cJSON_Delete.
        assert_eq!(
            auto_detect_c_result_cleanup("cJSON *", "cJSON_Parse").as_deref(),
            Some("if (R) cJSON_Delete(R)")
        );
        assert_eq!(
            auto_detect_c_result_cleanup("CJSON_PUBLIC(cJSON *)", "cJSON_CreateObject").as_deref(),
            Some("if (R) cJSON_Delete(R)")
        );
        // cJSON_bool (typedef int) is a value, not a handle — no cleanup.
        assert_eq!(
            auto_detect_c_result_cleanup("cJSON_bool", "cJSON_IsTrue"),
            None
        );
        assert_eq!(
            auto_detect_c_result_cleanup("CJSON_PUBLIC(cJSON_bool)", "cJSON_Compare"),
            None
        );
    }

    #[test]
    fn strdup_family_return_is_freed_with_plain_free() {
        // utf8.h's `utf8dup`/`utf8ndup` return a malloc'd buffer freed with plain
        // free(); there is no `<type>_free`, so the result was dropped and
        // LeakSanitizer flagged the library's malloc every input (CWE-401 FP).
        assert_eq!(
            detect_strdup_family_free("utf8_int8_t *", "utf8dup").as_deref(),
            Some("if (R) free((void *)R)")
        );
        assert_eq!(
            detect_strdup_family_free("char *", "strndup").as_deref(),
            Some("if (R) free((void *)R)")
        );
        assert_eq!(
            detect_strdup_family_free("char *", "mi_heap_strndup").as_deref(),
            Some("if (R) mi_free((void *)R)")
        );
        // Not a dup-family name -> no plain free (a paired `<type>_free` or the
        // library-specific list handles real handles; never guess).
        assert_eq!(
            detect_strdup_family_free("toml_table_t *", "toml_parse"),
            None
        );
        // A dup-family name with a non-pointer return -> nothing to free.
        assert_eq!(detect_strdup_family_free("int", "checkdup"), None);
        // `cJSON_Duplicate` does NOT end in "dup" -> left to the paired/library
        // path (which frees it with cJSON_Delete, not a shallow free).
        assert_eq!(
            detect_strdup_family_free("cJSON *", "cJSON_Duplicate"),
            None
        );
    }

    #[test]
    fn cjson_delete_not_emitted_for_borrowing_accessor_return() {
        // A borrowing accessor returns a pointer INTO its input graph (often aliasing
        // a stack-fabricated input object): `cJSON_Delete(R)` would be an invalid free.
        // Gate the cleanup on an allocator-like name, matching detect_paired_deallocator.
        assert_eq!(
            auto_detect_c_result_cleanup("cJSON *", "get_item_from_pointer"),
            None
        );
        assert_eq!(
            auto_detect_c_result_cleanup("cJSON *", "cJSON_GetObjectItem"),
            None
        );
        // Even the macro-wrapped form is gated by name.
        assert_eq!(
            auto_detect_c_result_cleanup("CJSON_PUBLIC(cJSON *)", "cJSON_GetArrayItem"),
            None
        );
    }

    #[test]
    fn paired_deallocator_detected_from_header_for_owning_pointer_return() {
        use super::{c_return_pointee_ident, detect_paired_deallocator};
        // Return-type pointee extraction.
        assert_eq!(
            c_return_pointee_ident("toml_table_t *").as_deref(),
            Some("toml_table_t")
        );
        assert_eq!(
            c_return_pointee_ident("const struct foo *").as_deref(),
            Some("foo")
        );
        // `*` may be absent (parsed into the declarator) — still extract the ident.
        assert_eq!(
            c_return_pointee_ident("toml_table_t").as_deref(),
            Some("toml_table_t")
        );
        assert_eq!(c_return_pointee_ident("int").as_deref(), Some("int"));

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-dealloc-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("toml.c");
        // The `.c` defines an INTERNAL static `xfree_tab` (matches the verb+type
        // shape) BEFORE the public `toml_free`. The harness must pick the public,
        // prefix-matching `toml_free` — not the unlinkable static helper.
        fs::write(
            &source,
            "#include \"toml.h\"\nstatic void xfree_tab(toml_table_t *t){ (void)t; }\ntoml_table_t *toml_parse(char *c){ return 0; }\nvoid toml_free(toml_table_t *t){ xfree_tab(t); }\n",
        )
        .unwrap();
        // Header declares the public deallocator (scanned first as the public API).
        fs::write(
            root.join("toml.h"),
            "typedef struct toml_table_t toml_table_t;\nextern toml_table_t *toml_parse(char *);\nextern void toml_free(toml_table_t *tab);\n",
        )
        .unwrap();

        // toml_parse returns toml_table_t* -> harness must free via toml_free
        // (regression for the tomlc99 false-positive LeakSanitizer findings).
        // Return type WITHOUT the `*` (declarator-attached) must still pair.
        assert_eq!(
            detect_paired_deallocator("toml_table_t", "toml_parse", &[], &root, &source).as_deref(),
            Some("if (R) toml_free(R)"),
            "owning-pointer return of an allocator must pair with its <type>_free deallocator"
        );
        assert_eq!(
            detect_paired_deallocator("toml_table_t *", "toml_parse", &[], &root, &source)
                .as_deref(),
            Some("if (R) toml_free(R)")
        );
        // A getter returning a BORROWED pointer must NOT be freed (no allocator verb).
        assert_eq!(
            detect_paired_deallocator("toml_table_t *", "toml_table_get", &[], &root, &source),
            None,
            "a non-allocator (getter) must not be paired with a deallocator"
        );
        // A value return owns nothing -> no cleanup.
        assert_eq!(
            detect_paired_deallocator("int", "toml_parse", &[], &root, &source),
            None
        );
        // char* is not an owning library handle -> no spurious pairing.
        assert_eq!(
            detect_paired_deallocator("char *", "toml_parse", &[], &root, &source),
            None
        );

        // Campaign fix: a refcount releaser taking a DOUBLE pointer
        // (libcbor `cbor_decref(cbor_item_t **)`) must pair with the owning return
        // of `cbor_load` and be called as `cbor_decref(&R)`.
        let cbor_root = std::env::temp_dir().join(format!("govfuzz-cbor-{nonce}"));
        fs::create_dir_all(&cbor_root).unwrap();
        let cbor_src = cbor_root.join("cbor.c");
        fs::write(&cbor_src, "#include \"cbor.h\"\n").unwrap();
        fs::write(
            cbor_root.join("cbor.h"),
            "typedef struct cbor_item_t cbor_item_t;\nextern cbor_item_t *cbor_load(const unsigned char *, size_t, void *);\nextern void cbor_decref(cbor_item_t **item);\n",
        )
        .unwrap();
        assert_eq!(
            detect_paired_deallocator("cbor_item_t *", "cbor_load", &[], &cbor_root, &cbor_src)
                .as_deref(),
            Some("if (R) cbor_decref(&R)"),
            "a double-pointer refcount releaser must be called with the address of R"
        );
        let _ = fs::remove_dir_all(&cbor_root);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn owning_returns_pair_via_read_verb_and_structural_inference() {
        use super::detect_paired_deallocator;
        // Campaign #18: owning returns were leaked (CWE-401 FP) when the constructor
        // name had no recognized verb (mpc combinators) or an unlisted verb
        // (yyjson_read). `read` is now an allocator verb, and a verb-less name pairs
        // via the structural existence of a prefix-matched type-specific deallocator
        // — while a self-returning/transform target (consumes the return type) and a
        // borrowing accessor stay unpaired to avoid an invalid/double free.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        // yyjson: `read` verb + yyjson_doc_free.
        let yroot = std::env::temp_dir().join(format!("govfuzz-yyjson-{nonce}"));
        fs::create_dir_all(&yroot).unwrap();
        let ysrc = yroot.join("yyjson.c");
        fs::write(&ysrc, "#include \"yyjson.h\"\n").unwrap();
        fs::write(
            yroot.join("yyjson.h"),
            "typedef struct yyjson_doc yyjson_doc;\n\
             extern yyjson_doc *yyjson_read(const char *dat, size_t len, unsigned flg);\n\
             extern void yyjson_doc_free(yyjson_doc *doc);\n",
        )
        .unwrap();
        assert_eq!(
            detect_paired_deallocator(
                "yyjson_doc *",
                "yyjson_read",
                &[
                    "const char *".to_owned(),
                    "size_t".to_owned(),
                    "unsigned".to_owned()
                ],
                &yroot,
                &ysrc
            )
            .as_deref(),
            Some("if (R) yyjson_doc_free(R)"),
            "yyjson_read owns its doc; the `read` verb must pair the deallocator"
        );
        let _ = fs::remove_dir_all(&yroot);

        // mpc: a VERB-LESS combinator (mpc_or) paired by structural inference, but a
        // self-returning mutator (mpc_define consumes mpc_parser_t*) must NOT pair.
        let mroot = std::env::temp_dir().join(format!("govfuzz-mpc-{nonce}"));
        fs::create_dir_all(&mroot).unwrap();
        let msrc = mroot.join("mpc.c");
        fs::write(&msrc, "#include \"mpc.h\"\n").unwrap();
        fs::write(
            mroot.join("mpc.h"),
            "typedef struct mpc_parser_t mpc_parser_t;\n\
             extern mpc_parser_t *mpc_or(int n);\n\
             extern mpc_parser_t *mpc_define(mpc_parser_t *p, mpc_parser_t *a);\n\
             extern void mpc_delete(mpc_parser_t *p);\n",
        )
        .unwrap();
        assert_eq!(
            detect_paired_deallocator(
                "mpc_parser_t *",
                "mpc_or",
                &["int".to_owned()],
                &mroot,
                &msrc
            )
            .as_deref(),
            Some("if (R) mpc_delete(R)"),
            "a verb-less owning combinator must pair via structural deallocator inference"
        );
        assert_eq!(
            detect_paired_deallocator(
                "mpc_parser_t *",
                "mpc_define",
                &["mpc_parser_t *".to_owned(), "mpc_parser_t *".to_owned()],
                &mroot,
                &msrc
            ),
            None,
            "a self-returning mutator (consumes its return type) must not be freed"
        );
        let _ = fs::remove_dir_all(&mroot);
    }

    #[test]
    fn scalar_pointers_are_not_lifecycle_handles() {
        // Struct handles: yes.
        assert!(is_c_lifecycle_handle_type("yaml_parser_t *"));
        assert!(is_c_lifecycle_handle_type("cJSON *"));
        // Data buffers / scalars: no — these are decode inputs.
        assert!(!is_c_lifecycle_handle_type("char *"));
        assert!(!is_c_lifecycle_handle_type("unsigned char *"));
        assert!(!is_c_lifecycle_handle_type("uint8_t *"));
        assert!(!is_c_lifecycle_handle_type("int *"));
        assert!(!is_c_lifecycle_handle_type("void *"));
        assert!(!is_c_lifecycle_handle_type("int")); // not a pointer
        assert!(is_c_scalar_type("size_t"));
        assert!(!is_c_scalar_type("cJSON"));
    }

    #[test]
    fn c_direct_lifecycle_table_pairs_single_arg_init_and_delete() {
        use c_parser::{CFunction, CParamDescriptor};
        let handle = |name: &str| CParamDescriptor {
            name: name.to_owned(),
            c_type: "yaml_parser_t *".to_owned(),
        };
        let f = |name: &str, params: Vec<CParamDescriptor>, is_static: bool| CFunction {
            name: name.to_owned(),
            line: 1,
            return_type: "int".to_owned(),
            params,
            is_static,
            ..Default::default()
        };
        let functions = vec![
            f("yaml_parser_initialize", vec![handle("p")], false),
            f("yaml_parser_delete", vec![handle("p")], false),
            // multi-arg init must be ignored (can't call with just &handle)
            f(
                "yaml_parser_init_ex",
                vec![
                    handle("p"),
                    CParamDescriptor {
                        name: "flags".to_owned(),
                        c_type: "int".to_owned(),
                    },
                ],
                false,
            ),
            // static lifecycle fns can't be linked across TUs -> ignored
            f(
                "other_init",
                vec![CParamDescriptor {
                    name: "o".to_owned(),
                    c_type: "other_t *".to_owned(),
                }],
                true,
            ),
            f(
                "yaml_parser_scan",
                vec![
                    handle("p"),
                    CParamDescriptor {
                        name: "t".to_owned(),
                        c_type: "yaml_token_t *".to_owned(),
                    },
                ],
                false,
            ),
        ];

        let table = c_direct_lifecycle_table(&functions, &[], &type_model::TypeRegistry::default());
        assert_eq!(table.len(), 1, "{table:?}");
        let entry = &table[0];
        assert_eq!(entry.handle_type, "yaml_parser_t");
        assert_eq!(entry.init.as_deref(), Some("yaml_parser_initialize"));
        assert_eq!(entry.delete.as_deref(), Some("yaml_parser_delete"));
        assert!(!entry.init_returns_handle, "in-place init");
    }

    #[test]
    fn tree_lifecycle_fills_equivalent_elaborated_tag_entry() {
        use harness_gen::c_generate::CHandleLifecycle;

        let mut local = vec![CHandleLifecycle {
            handle_type: "struct mi_heap_s".to_owned(),
            init: None,
            delete: Some("mi_heap_delete".to_owned()),
            init_returns_handle: false,
            init_args: Vec::new(),
        }];
        let tree = vec![CHandleLifecycle {
            handle_type: "mi_heap_s".to_owned(),
            init: Some("mi_heap_new".to_owned()),
            delete: None,
            init_returns_handle: true,
            init_args: Vec::new(),
        }];

        merge_tree_c_lifecycle(&mut local, &tree);

        assert_eq!(local.len(), 1, "equivalent tag spellings must merge");
        assert_eq!(local[0].init.as_deref(), Some("mi_heap_new"));
        assert!(local[0].init_returns_handle);
        assert_eq!(local[0].delete.as_deref(), Some("mi_heap_delete"));
    }

    #[test]
    fn c_direct_lifecycle_table_finds_returning_constructor() {
        use c_parser::{CFunction, CParamDescriptor};
        let param = |c_type: &str| CParamDescriptor {
            name: "p".to_owned(),
            c_type: c_type.to_owned(),
        };
        let f = |name: &str, ret: &str, params: Vec<CParamDescriptor>| CFunction {
            name: name.to_owned(),
            line: 1,
            return_type: ret.to_owned(),
            params,
            is_static: false,
            ..Default::default()
        };
        let functions = vec![
            // Returning constructor: 0-arg, returns the handle pointer.
            f("gizmo_new", "gizmo_t *", vec![]),
            // Destructor: single pointer arg (captured by the in-place pass).
            f("gizmo_free", "void", vec![param("gizmo_t *")]),
            // A `(void)` prototype constructor must also be recognized.
            f("widget_create", "widget_t *", vec![param("void")]),
            // In-place init must take precedence over a returning constructor
            // for the same base.
            f("blob_init", "int", vec![param("blob_t *")]),
            f("blob_new", "blob_t *", vec![]),
        ];

        let table = c_direct_lifecycle_table(&functions, &[], &type_model::TypeRegistry::default());

        let gizmo = table
            .iter()
            .find(|e| e.handle_type == "gizmo_t")
            .expect("gizmo_t present");
        assert_eq!(gizmo.init.as_deref(), Some("gizmo_new"));
        assert!(gizmo.init_returns_handle);
        assert_eq!(gizmo.delete.as_deref(), Some("gizmo_free"));

        let widget = table
            .iter()
            .find(|e| e.handle_type == "widget_t")
            .expect("widget_t (void) ctor present");
        assert_eq!(widget.init.as_deref(), Some("widget_create"));
        assert!(widget.init_returns_handle);

        let blob = table
            .iter()
            .find(|e| e.handle_type == "blob_t")
            .expect("blob_t present");
        assert_eq!(blob.init.as_deref(), Some("blob_init"));
        assert!(!blob.init_returns_handle, "in-place init wins");
    }

    #[test]
    fn c_direct_lifecycle_pairs_matching_opaque_api_family() {
        let declarations = c_parser::parse_c_declarations(
            "struct archive *archive_read_new(void);\n\
             struct archive *archive_write_new(void);\n\
             int _archive_write_free(struct archive *a);\n\
             int _archive_read_free(struct archive *a);\n\
             int archive_write_free(struct archive *a);\n\
             int archive_read_free(struct archive *a);\n",
        )
        .expect("libarchive declarations parse");

        let table =
            c_direct_lifecycle_table(&[], &declarations, &type_model::TypeRegistry::default());
        let archive = table
            .iter()
            .find(|entry| entry.handle_type == "archive")
            .expect("archive lifecycle found");
        assert_eq!(archive.init.as_deref(), Some("archive_read_new"));
        assert_eq!(archive.delete.as_deref(), Some("archive_read_free"));
    }

    #[test]
    fn c_direct_lifecycle_table_parses_attribute_decorated_handle_apis() {
        let mimalloc = c_parser::parse_c_declarations(
            "typedef struct mi_heap_s mi_heap_t;\n\
             mi_decl_nodiscard mi_decl_export mi_heap_t* mi_heap_new(void);\n\
             int _mi_heap_guarded_init(mi_heap_t* heap);\n\
             mi_decl_export void mi_heap_delete(mi_heap_t* heap);\n",
        )
        .expect("mimalloc declarations parse");
        let defs = c_parser::parse_c_type_defs("typedef struct mi_heap_s mi_heap_t;")
            .expect("mimalloc typedef parses");
        let registry = type_model::TypeRegistry::from_defs([&defs]);
        let table = c_direct_lifecycle_table(&[], &mimalloc, &registry);
        let heap = table
            .iter()
            .find(|entry| entry.init.as_deref() == Some("mi_heap_new"))
            .expect("attribute-decorated returning constructor is found");
        assert!(heap.init_returns_handle, "{heap:?}");
        assert_eq!(heap.delete.as_deref(), Some("mi_heap_delete"));
        let decoded = harness_gen::c_decoders::select_c_decoder_with_lifecycle(
            "mi_heap_t *",
            "heap",
            &registry,
            &table,
        )
        .expect("canonical lifecycle key drives the public heap typedef");
        assert!(decoded.decl.contains("mi_heap_new()"), "{}", decoded.decl);

        let xz = c_parser::parse_c_declarations(
            "typedef struct lzma_index_hash_s lzma_index_hash;\n\
             extern LZMA_API(lzma_index_hash *) lzma_index_hash_init(\n\
                 lzma_index_hash *index_hash, const void *allocator);\n\
             extern LZMA_API(void) lzma_index_hash_end(\n\
                 lzma_index_hash *index_hash, const void *allocator);\n",
        )
        .expect("xz declarations parse");
        let defs = c_parser::parse_c_type_defs("typedef struct lzma_index_hash_s lzma_index_hash;")
            .expect("xz typedef parses");
        let registry = type_model::TypeRegistry::from_defs([&defs]);
        let table = c_direct_lifecycle_table(&[], &xz, &registry);
        assert!(
            table
                .iter()
                .any(|entry| entry.init.as_deref() == Some("lzma_index_hash_init")),
            "function-like API macro constructor must be found: decls={xz:?}, table={table:?}"
        );
    }

    #[test]
    fn c_direct_lifecycle_table_finds_libarchive_macro_declarations() {
        let declarations = c_parser::parse_c_declarations(
            "__LA_DECL struct archive *archive_read_new(void);\n\
             __LA_DECL int archive_read_open1(struct archive *);\n\
             __LA_DECL int archive_read_close(struct archive *);\n\
             __LA_DECL int archive_read_free(struct archive *);\n\
             __LA_DECL int archive_read_open_memory2(struct archive *, const void *, size_t, size_t);\n",
        )
        .expect("libarchive declarations parse");
        let table =
            c_direct_lifecycle_table(&[], &declarations, &type_model::TypeRegistry::default());
        let archive = table
            .iter()
            .find(|entry| entry.handle_type == "archive")
            .unwrap_or_else(|| {
                panic!("archive lifecycle missing: {table:?}; decls={declarations:?}")
            });
        assert_eq!(archive.init.as_deref(), Some("archive_read_new"));
        assert!(archive.init_returns_handle);
        assert_eq!(archive.delete.as_deref(), Some("archive_read_free"));
    }

    #[test]
    fn c_direct_lifecycle_table_merges_struct_tag_spelling_variants() {
        // Campaign reproduction (libdeflate): the parser drops the `struct`
        // keyword from a returning constructor's return type
        // (`struct libdeflate_decompressor *libdeflate_alloc_decompressor(void)`
        // is seen as returning `libdeflate_decompressor *`) while the destructor
        // parameter and the target parameter keep it. The constructor and
        // destructor must still pair under ONE handle entry — without the
        // elaborated-tag canonicalization they split into two entries and the
        // handle is skipped as having "no returning-constructor lifecycle".
        use c_parser::CDeclaration;
        let decls = vec![
            CDeclaration {
                name: "libdeflate_alloc_decompressor".to_owned(),
                return_type: "libdeflate_decompressor *".to_owned(), // tag dropped
                param_types: vec![],
                ..Default::default()
            },
            CDeclaration {
                name: "libdeflate_free_decompressor".to_owned(),
                return_type: "void".to_owned(),
                param_types: vec!["struct libdeflate_decompressor *".to_owned()], // tag kept
                ..Default::default()
            },
        ];

        let table = c_direct_lifecycle_table(&[], &decls, &type_model::TypeRegistry::default());
        let entries: Vec<_> = table
            .iter()
            .filter(|e| e.handle_type.contains("libdeflate_decompressor"))
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "constructor + destructor must merge into ONE entry, not split by `struct` tag: {table:?}"
        );
        let entry = entries[0];
        assert_eq!(entry.init.as_deref(), Some("libdeflate_alloc_decompressor"));
        assert_eq!(
            entry.delete.as_deref(),
            Some("libdeflate_free_decompressor")
        );
        assert!(
            entry.init_returns_handle,
            "the handle is built by a returning constructor"
        );
    }

    #[test]
    fn c_constructor_drive_plan_pumps_decode_siblings_and_destroys() {
        use c_parser::{CFunction, CParamDescriptor};
        let param = |c_type: &str| CParamDescriptor {
            name: "p".to_owned(),
            c_type: c_type.to_owned(),
        };
        let f = |name: &str, ret: &str, params: Vec<CParamDescriptor>, line: u32| CFunction {
            name: name.to_owned(),
            line,
            return_type: ret.to_owned(),
            params,
            is_static: false,
            ..Default::default()
        };
        // pl_mpeg shape: a from-memory constructor returning an opaque handle,
        // single-arg decode pumps, getters, and a destroy.
        let target = f(
            "plm_create_with_memory",
            "plm_t *",
            vec![param("uint8_t *"), param("size_t"), param("int")],
            10,
        );
        let functions = vec![
            target.clone(),
            f(
                "plm_decode_video",
                "plm_frame_t *",
                vec![param("plm_t *")],
                20,
            ),
            f(
                "plm_decode_audio",
                "plm_samples_t *",
                vec![param("plm_t *")],
                30,
            ),
            // Getter: single-arg handle, but not a pump verb — must be excluded.
            f("plm_get_framerate", "double", vec![param("plm_t *")], 40),
            // Different handle type — must be ignored.
            f(
                "plm_buffer_tell",
                "size_t",
                vec![param("plm_buffer_t *")],
                50,
            ),
            f("plm_destroy", "void", vec![param("plm_t *")], 60),
        ];

        let plan = c_constructor_drive_plan(&target, &functions).expect("drive plan");
        let names: Vec<&str> = plan.steps.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["plm_decode_audio", "plm_decode_video"]);
        // Pointer-returning pumps break early on NULL (end-of-stream).
        assert!(plan.steps.iter().all(|s| s.breaks_on_null));
        assert_eq!(plan.destroy.as_deref(), Some("plm_destroy"));

        // No destroy -> no plan (would leak the handle every iteration).
        let no_destroy: Vec<CFunction> = functions
            .iter()
            .filter(|f| f.name != "plm_destroy")
            .cloned()
            .collect();
        assert!(c_constructor_drive_plan(&target, &no_destroy).is_none());

        // A target that does not return a handle is never driven.
        let scalar_target = f(
            "parse_int",
            "int",
            vec![param("uint8_t *"), param("size_t")],
            10,
        );
        assert!(c_constructor_drive_plan(&scalar_target, &functions).is_none());
    }

    #[test]
    fn type_defs_from_target_source_collected_when_nameable() {
        // A single-header library defines its structs in the SAME file as the
        // target function; the harness `#include`s that header, so a struct used
        // as a decoder out-param (QOA's `qoa_desc`) IS nameable and must be
        // collected — else it is treated as opaque and the target is skipped.
        // A `.c`-only struct (not `#include`d by the harness) must stay opaque.
        let src = "typedef struct { int a; int b; } simple_t;\n\
                   short *decode(const unsigned char *b, int n, simple_t *out);";
        let path = std::path::Path::new("/tmp/single_header.h");
        let mentions = |defs: &[c_parser::CTypeDefs]| {
            defs.iter().any(|d| {
                d.structs.iter().any(|s| s.name == "simple_t")
                    || d.typedefs.iter().any(|t| t.name == "simple_t")
            })
        };
        // parse_source = true (single-header / static target): struct collected.
        let collected = collect_c_type_defs_for_harness(path, src, &[], &[], true);
        assert!(
            mentions(&collected),
            "target-source struct must be collected when the harness can name it"
        );
        // parse_source = false (.c-only, harness sees only headers): not collected.
        let dropped = collect_c_type_defs_for_harness(path, src, &[], &[], false);
        assert!(
            !mentions(&dropped),
            "a struct the harness can't name must stay opaque-and-skip"
        );
    }

    #[test]
    fn c_direct_lifecycle_table_resolves_typedef_hidden_pointer_handle() {
        use c_parser::{CFunction, CParamDescriptor, CStructDef, CTypeDefs, CTypedefDef};
        // expat idiom: `typedef struct XML_ParserStruct *XML_Parser;` — the
        // pointer is hidden behind the typedef and the constructor takes a
        // pointer config arg. Both the returning ctor (return type `XML_Parser`)
        // and the destructor (param type `XML_Parser`) must resolve to the
        // canonical opaque pointee `struct XML_ParserStruct` the decoder looks
        // up, and the ctor must be callable with the neutral arg `NULL`.
        let defs = CTypeDefs {
            structs: vec![CStructDef {
                name: "XML_ParserStruct".to_owned(),
                fields: vec![],
                line: 1,
                complete: false,
            }],
            enums: vec![],
            typedefs: vec![CTypedefDef {
                name: "XML_Parser".to_owned(),
                underlying: "struct XML_ParserStruct *".to_owned(),
                line: 1,
            }],
        };
        let registry = type_model::TypeRegistry::from_defs([&defs]);
        let f = |name: &str, ret: &str, params: Vec<CParamDescriptor>| CFunction {
            name: name.to_owned(),
            line: 1,
            return_type: ret.to_owned(),
            params,
            is_static: false,
            ..Default::default()
        };
        let functions = vec![
            f(
                "XML_ParserCreate",
                "XML_Parser",
                vec![CParamDescriptor {
                    name: "encodingName".to_owned(),
                    c_type: "const XML_Char *".to_owned(),
                }],
            ),
            f(
                "XML_ParserFree",
                "void",
                vec![CParamDescriptor {
                    name: "parser".to_owned(),
                    c_type: "XML_Parser".to_owned(),
                }],
            ),
        ];

        let table = c_direct_lifecycle_table(&functions, &[], &registry);
        let entry = table
            .iter()
            .find(|e| e.handle_type == "XML_ParserStruct")
            .expect("typedef-hidden handle resolved to canonical pointee");
        assert_eq!(entry.init.as_deref(), Some("XML_ParserCreate"));
        assert!(entry.init_returns_handle);
        assert_eq!(entry.init_args, vec!["NULL".to_owned()]);
        assert_eq!(entry.delete.as_deref(), Some("XML_ParserFree"));
    }

    #[test]
    fn c_direct_lifecycle_table_structurally_detects_interior_pointer_handle_ctor() {
        use c_parser::{CFunction, CParamDescriptor, CTypeDefs, CTypedefDef};
        // redis sds = `typedef char *sds`. Its constructor/destructor names are
        // lowercase-glued (sdsempty/sdsfree), so the verb tokenizer can't see them.
        // The structural pass must still detect: sdsempty()->sds (returns the
        // handle, doesn't take it) is the ctor, sdsfree(sds) is the dtor, because
        // sds is used as a handle (sdscatlen takes it first).
        let defs = CTypeDefs {
            structs: vec![],
            enums: vec![],
            typedefs: vec![CTypedefDef {
                name: "sds".to_owned(),
                underlying: "char *".to_owned(),
                line: 1,
            }],
        };
        let registry = type_model::TypeRegistry::from_defs([&defs]);
        let f = |name: &str, ret: &str, params: Vec<CParamDescriptor>| CFunction {
            name: name.to_owned(),
            line: 1,
            return_type: ret.to_owned(),
            params,
            is_static: false,
            ..Default::default()
        };
        let p = |n: &str, t: &str| CParamDescriptor {
            name: n.to_owned(),
            c_type: t.to_owned(),
        };
        let functions = vec![
            f("sdsempty", "sds", vec![]),
            f(
                "sdsnewlen",
                "sds",
                vec![p("init", "const void *"), p("len", "size_t")],
            ),
            f("sdsfree", "void", vec![p("s", "sds")]),
            f("sdsAllocSize", "size_t", vec![p("s", "sds")]),
            f("sdsAllocPtr", "void *", vec![p("s", "sds")]),
            f(
                "sdscatlen",
                "sds",
                vec![p("s", "sds"), p("t", "const void *"), p("len", "size_t")],
            ),
        ];

        let table = c_direct_lifecycle_table(&functions, &[], &registry);
        let entry = table
            .iter()
            .find(|e| e.handle_type == "sds")
            .expect("interior-pointer typedef handle 'sds' must be in the lifecycle table");
        // sdsempty (0 args) preferred over sdsnewlen (rejected: size_t isn't
        // neutrally-suppliable).
        assert_eq!(entry.init.as_deref(), Some("sdsempty"));
        assert!(entry.init_returns_handle);
        assert!(entry.init_args.is_empty());
        assert_eq!(entry.delete.as_deref(), Some("sdsfree"));
    }

    #[test]
    fn resolve_concrete_subclass_picks_default_constructible_derived() {
        // #456: an abstract `Reader` with a concrete, default-constructible
        // `MemoryReader` subclass resolves to it; subclass_qualified re-qualifies.
        let source = "class Reader { public: virtual void read() = 0; };\n\
                      class MemoryReader : public Reader { public: void read() override {} };\n"
            .to_owned();
        assert_eq!(
            super::resolve_concrete_subclass("Reader", &[], &[source]).as_deref(),
            Some("MemoryReader")
        );
        assert_eq!(
            super::subclass_qualified("e57::Reader", "MemoryReader"),
            "e57::MemoryReader"
        );
        assert_eq!(
            super::subclass_qualified("Reader", "MemoryReader"),
            "MemoryReader"
        );
        // A still-abstract derived class is not usable -> None.
        let abstract_only = "class Base { virtual void f() = 0; };\n\
                             class Mid : public Base { virtual void g() = 0; };\n"
            .to_owned();
        assert_eq!(
            super::resolve_concrete_subclass("Base", &[], &[abstract_only]),
            None
        );
    }

    #[test]
    fn resolve_concrete_subclass_finds_subclass_across_the_include_closure() {
        // #456 / §27.4: the abstract base is in the target source, its concrete
        // subclass in a separate header text — resolved across the closure. A header
        // subclass whose only ctor is parameterised is NOT taken (not default-
        // constructible); one with an implicit default ctor is.
        let base = "class Reader { public: virtual void read() = 0; };\n".to_owned();
        let header = "class MemoryReader : public e57::Reader { public: void read() override {} };\n\
                      class FileReader : public Reader { public: FileReader(int fd); void read() override {} };\n"
            .to_owned();
        assert_eq!(
            super::resolve_concrete_subclass("Reader", &[], &[base.clone(), header.clone()])
                .as_deref(),
            Some("MemoryReader"),
            "implicit-default-ctor header subclass is taken; the param-ctor one is skipped"
        );
        // FileReader alone (param-only ctor) -> no usable subclass.
        let only_param = "class FileReader : public Reader { public: FileReader(int fd); void read() override {} };\n".to_owned();
        assert_eq!(
            super::resolve_concrete_subclass("Reader", &[], &[base, only_param]),
            None
        );
    }

    #[test]
    fn resolve_subclass_with_ctor_constructs_a_ctor_arg_subclass() {
        // §27.4a: the abstract `Reader` has no default-constructible subclass, but
        // `BufferReader` exposes a public ctor taking a supported scalar — resolve
        // that ctor so the receiver is built with decoded args and the virtual
        // method still dispatches to the override.
        let src = "\
#include <string>
class Reader { public: virtual int decode(const std::string &s) = 0; \
  int run(const std::string &s) { return decode(s); } };
class BufferReader : public Reader { \
  public: explicit BufferReader(int base) : base_(base) {} \
    int decode(const std::string &s) override { return base_ + (int)s.size(); } \
  private: int base_; };
";
        let functions = cpp_parser::parse_cpp_functions(src).unwrap();
        let defs: Vec<c_parser::CTypeDefs> = vec![];
        let registry = type_model::TypeRegistry::from_defs(defs.iter());
        let class_infos = cpp_parser::parse_cpp_class_info(src).unwrap();
        let plan = super::resolve_subclass_with_ctor(
            "Reader",
            &functions,
            &[src.to_owned()],
            &registry,
            &[],
            &class_infos,
        )
        .expect("a ctor-arg subclass resolves");
        assert_eq!(plan.0, "BufferReader");
        assert_eq!(plan.1.len(), 1, "the int ctor param is carried");
        assert_eq!(plan.1[0].cpp_type, "int");
        // No default-constructible subclass exists, so Phase 1 declines.
        assert_eq!(
            super::resolve_concrete_subclass("Reader", &functions, &[src.to_owned()]),
            None
        );
    }

    #[test]
    fn find_cpp_factory_resolves_free_function_returning_base_pointer() {
        // §27.4b: no constructible subclass, but a free factory returns `Codec *` —
        // resolve it as a pointer-returning factory (null-guarded `->` call).
        let src = "\
#include <string>
class Codec { public: virtual ~Codec() {} virtual int run(const std::string &s) = 0; };
Codec *make_codec(int variant) { (void)variant; return nullptr; }
";
        let functions = cpp_parser::parse_cpp_functions(src).unwrap();
        let defs: Vec<c_parser::CTypeDefs> = vec![];
        let registry = type_model::TypeRegistry::from_defs(defs.iter());
        let class_infos = cpp_parser::parse_cpp_class_info(src).unwrap();
        let factory = super::find_cpp_factory_for_class(
            "Codec",
            &functions,
            &[src.to_owned()],
            &registry,
            &class_infos,
        )
        .expect("a free-function factory resolves");
        assert_eq!(factory.factory_method, "make_codec");
        assert!(factory.owner_type.is_none(), "free function has no owner");
        assert!(
            factory.receiver_is_pointer,
            "a `Codec *` return is a pointer factory"
        );
        assert_eq!(factory.factory_params.len(), 1);
    }

    #[test]
    fn c_direct_lifecycle_table_keys_opaque_void_typedef_handle() {
        use c_parser::{CFunction, CParamDescriptor, CTypeDefs, CTypedefDef};
        // libde265: `typedef void de265_decoder_context;` — an opaque void typedef.
        // Its returning ctor `de265_new_decoder()` and destructor
        // `de265_free_decoder(de265_decoder_context *)` must pair under the TYPEDEF
        // NAME (resolving to "void" would be useless and collide with real void*).
        let defs = CTypeDefs {
            structs: vec![],
            enums: vec![],
            typedefs: vec![CTypedefDef {
                name: "de265_decoder_context".to_owned(),
                underlying: "void".to_owned(),
                line: 1,
            }],
        };
        let registry = type_model::TypeRegistry::from_defs([&defs]);
        let f = |name: &str, ret: &str, params: Vec<CParamDescriptor>| CFunction {
            name: name.to_owned(),
            line: 1,
            return_type: ret.to_owned(),
            params,
            is_static: false,
            ..Default::default()
        };
        let functions = vec![
            f("de265_new_decoder", "de265_decoder_context *", vec![]),
            f(
                "de265_free_decoder",
                "void",
                vec![CParamDescriptor {
                    name: "ctx".to_owned(),
                    c_type: "de265_decoder_context *".to_owned(),
                }],
            ),
        ];

        let table = c_direct_lifecycle_table(&functions, &[], &registry);
        let entry = table
            .iter()
            .find(|e| e.handle_type == "de265_decoder_context")
            .expect("opaque void typedef handle keyed by typedef name");
        assert_eq!(entry.init.as_deref(), Some("de265_new_decoder"));
        assert!(entry.init_returns_handle);
        assert_eq!(entry.delete.as_deref(), Some("de265_free_decoder"));
    }

    #[test]
    fn c_direct_lifecycle_table_pairs_init_and_delete_across_typedef_aliases() {
        use c_parser::{CFunction, CParamDescriptor, CStructDef, CTypeDefs, CTypedefDef};
        // A handle spelled `struct widget *` by its ctor but `widget_t *` (a typedef
        // alias) by its dtor must still pair: both resolve to the same canonical
        // base. Exact-name keying left the ctor and dtor on different keys (#453).
        let defs = CTypeDefs {
            structs: vec![CStructDef {
                name: "widget".to_owned(),
                fields: vec![],
                line: 1,
                complete: false,
            }],
            enums: vec![],
            typedefs: vec![CTypedefDef {
                name: "widget_t".to_owned(),
                underlying: "struct widget".to_owned(),
                line: 1,
            }],
        };
        let registry = type_model::TypeRegistry::from_defs([&defs]);
        let f = |name: &str, ret: &str, params: Vec<CParamDescriptor>| CFunction {
            name: name.to_owned(),
            line: 1,
            return_type: ret.to_owned(),
            params,
            is_static: false,
            ..Default::default()
        };
        let functions = vec![
            f("widget_create", "struct widget *", vec![]),
            f(
                "widget_destroy",
                "void",
                vec![CParamDescriptor {
                    name: "w".to_owned(),
                    c_type: "widget_t *".to_owned(),
                }],
            ),
        ];

        let table = c_direct_lifecycle_table(&functions, &[], &registry);
        let entry = table
            .iter()
            .find(|e| e.handle_type == "widget")
            .expect("aliased handle paired under canonical base");
        assert_eq!(entry.init.as_deref(), Some("widget_create"));
        assert_eq!(entry.delete.as_deref(), Some("widget_destroy"));
    }

    #[test]
    fn c_direct_lifecycle_table_ignores_static_internal_initializer() {
        use c_parser::{
            CDeclaration, CFunction, CParamDescriptor, CStructDef, CTypeDefs, CTypedefDef,
        };
        // expat's `static enum XML_Error initializeEncoding(XML_Parser)` is an
        // internal initializer whose name matches the "initialize" needle. Its
        // forward declaration is collected from the target .c by
        // `parse_c_declarations` (which carries no static-ness), so it must be
        // filtered against the static definitions in `functions`. The public
        // returning ctor `XML_ParserCreate` — not the static, unlinkable
        // initializer — must be selected.
        let defs = CTypeDefs {
            structs: vec![CStructDef {
                name: "XML_ParserStruct".to_owned(),
                fields: vec![],
                line: 1,
                complete: false,
            }],
            enums: vec![],
            typedefs: vec![CTypedefDef {
                name: "XML_Parser".to_owned(),
                underlying: "struct XML_ParserStruct *".to_owned(),
                line: 1,
            }],
        };
        let registry = type_model::TypeRegistry::from_defs([&defs]);
        let p = |name: &str, c_type: &str| CParamDescriptor {
            name: name.to_owned(),
            c_type: c_type.to_owned(),
        };
        let f = |name: &str, ret: &str, params: Vec<CParamDescriptor>, is_static: bool| CFunction {
            name: name.to_owned(),
            line: 1,
            return_type: ret.to_owned(),
            params,
            is_static,
            ..Default::default()
        };
        let functions = vec![
            f(
                "initializeEncoding",
                "enum XML_Error",
                vec![p("parser", "XML_Parser")],
                true,
            ),
            f(
                "XML_ParserCreate",
                "XML_Parser",
                vec![p("encodingName", "const XML_Char *")],
                false,
            ),
            f(
                "XML_ParserFree",
                "void",
                vec![p("parser", "XML_Parser")],
                false,
            ),
        ];
        // `parse_c_declarations` over the target .c yields forward decls for all
        // three (static-ness lost in CDeclaration).
        let d = |name: &str, ret: &str, params: Vec<&str>| CDeclaration {
            name: name.to_owned(),
            return_type: ret.to_owned(),
            param_types: params.into_iter().map(str::to_owned).collect(),
            variadic: false,
            line: 1,
        };
        let decls = vec![
            d("initializeEncoding", "enum XML_Error", vec!["XML_Parser"]),
            d("XML_ParserCreate", "XML_Parser", vec!["const XML_Char *"]),
            d("XML_ParserFree", "void", vec!["XML_Parser"]),
        ];

        let table = c_direct_lifecycle_table(&functions, &decls, &registry);
        let entry = table
            .iter()
            .find(|e| e.handle_type == "XML_ParserStruct")
            .expect("handle present");
        assert_eq!(
            entry.init.as_deref(),
            Some("XML_ParserCreate"),
            "static initializeEncoding must not be chosen as the constructor"
        );
        assert!(entry.init_returns_handle);
        assert_eq!(entry.init_args, vec!["NULL".to_owned()]);
        assert_eq!(entry.delete.as_deref(), Some("XML_ParserFree"));
    }

    #[test]
    fn c_direct_lifecycle_table_resolves_handle_through_callconv_macro() {
        use c_parser::{CFunction, CParamDescriptor, CStructDef, CTypeDefs, CTypedefDef};
        // expat *defines* its ctor/dtor in xmlparse.c as
        // `XML_Parser XMLCALL XML_ParserCreate(...)` — the calling-convention
        // macro `XMLCALL` is glued onto the type and tree-sitter can't
        // preprocess it away. The handle key must still resolve through the
        // noise token (true of XMLCALL/XMLIMPORT/CURL_EXTERN/APIENTRY/...).
        let defs = CTypeDefs {
            structs: vec![CStructDef {
                name: "XML_ParserStruct".to_owned(),
                fields: vec![],
                line: 1,
                complete: false,
            }],
            enums: vec![],
            typedefs: vec![
                CTypedefDef {
                    name: "XML_Parser".to_owned(),
                    underlying: "struct XML_ParserStruct *".to_owned(),
                    line: 1,
                },
                CTypedefDef {
                    name: "XML_Char".to_owned(),
                    underlying: "char".to_owned(),
                    line: 2,
                },
            ],
        };
        let registry = type_model::TypeRegistry::from_defs([&defs]);
        let p = |name: &str, c_type: &str| CParamDescriptor {
            name: name.to_owned(),
            c_type: c_type.to_owned(),
        };
        let f = |name: &str, ret: &str, params: Vec<CParamDescriptor>| CFunction {
            name: name.to_owned(),
            line: 1,
            return_type: ret.to_owned(),
            params,
            is_static: false,
            ..Default::default()
        };
        let functions = vec![
            f(
                "XML_ParserCreate",
                "XML_Parser XMLCALL",
                vec![p("encodingName", "const XML_Char *")],
            ),
            f(
                "XML_ParserFree",
                "void XMLCALL",
                vec![p("parser", "XML_Parser")],
            ),
        ];

        let table = c_direct_lifecycle_table(&functions, &[], &registry);
        let entry = table
            .iter()
            .find(|e| e.handle_type == "XML_ParserStruct")
            .expect("handle resolved through XMLCALL macro");
        assert_eq!(entry.init.as_deref(), Some("XML_ParserCreate"));
        assert!(entry.init_returns_handle);
        assert_eq!(entry.init_args, vec!["NULL".to_owned()]);
        assert_eq!(entry.delete.as_deref(), Some("XML_ParserFree"));
        // The contaminated return type must not have leaked a bogus `XML_Char`
        // handle (the ctor's string arg is a decode input, not a handle).
        assert!(
            !table.iter().any(|e| e.handle_type == "XML_Char"),
            "{table:?}"
        );
    }

    #[test]
    fn c_direct_lifecycle_table_finds_cross_file_and_delete_only_handles() {
        use c_parser::CDeclaration;
        // Cross-file: target file has no lifecycle fns; the included header
        // declares the parser init/delete and a delete-only output struct.
        let decls = vec![
            CDeclaration {
                name: "yaml_parser_initialize".to_owned(),
                return_type: "int".to_owned(),
                param_types: vec!["yaml_parser_t *".to_owned()],
                variadic: false,
                line: 1,
            },
            CDeclaration {
                name: "yaml_parser_delete".to_owned(),
                return_type: "void".to_owned(),
                param_types: vec!["yaml_parser_t *".to_owned()],
                variadic: false,
                line: 2,
            },
            CDeclaration {
                name: "yaml_token_delete".to_owned(),
                return_type: "void".to_owned(),
                param_types: vec!["yaml_token_t *".to_owned()],
                variadic: false,
                line: 3,
            },
        ];
        let table = c_direct_lifecycle_table(&[], &decls, &type_model::TypeRegistry::default());
        let parser = table
            .iter()
            .find(|e| e.handle_type == "yaml_parser_t")
            .unwrap();
        assert_eq!(parser.init.as_deref(), Some("yaml_parser_initialize"));
        assert_eq!(parser.delete.as_deref(), Some("yaml_parser_delete"));
        // delete-only output struct is still emitted (no init).
        let token = table
            .iter()
            .find(|e| e.handle_type == "yaml_token_t")
            .unwrap();
        assert_eq!(token.init, None);
        assert_eq!(token.delete.as_deref(), Some("yaml_token_delete"));
    }

    #[test]
    fn auto_detect_project_includes_finds_sibling_include_dir() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-incdir-{nonce}"));
        let src_dir = root.join("library");
        let inc_dir = root.join("include");
        fs::create_dir_all(&src_dir).unwrap();
        fs::create_dir_all(&inc_dir).unwrap();
        let source = src_dir.join("parser.c");
        fs::write(&source, "// stub").unwrap();
        let dirs = auto_detect_project_includes(&source);
        assert!(
            dirs.contains(&inc_dir),
            "expected sibling include/ in {dirs:?}"
        );
    }

    #[test]
    fn auto_detect_project_includes_skips_source_dir_itself() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // Nest the source deep enough that the detector's 3-level upward walk
        // stays inside this unique root and never escapes into a shared parent
        // (e.g. /tmp) where an unrelated `include`/`inc` dir could exist.
        let root = std::env::temp_dir().join(format!("govfuzz-incnone-{nonce}"));
        let src_dir = root.join("a").join("b").join("c");
        fs::create_dir_all(&src_dir).unwrap();
        let source = src_dir.join("foo.c");
        fs::write(&source, "// stub").unwrap();
        assert!(
            auto_detect_project_includes(&source).is_empty(),
            "no include/ dirs exist under the source's project ancestry"
        );
    }

    #[test]
    fn self_prefixed_include_roots_adds_parent_of_prefix_dir() {
        // libde265 shape: `.../libde265/de265.cc` does `#include "libde265/vps.h"`,
        // which only resolves with the dir CONTAINING `libde265/` on the path.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-selfinc-{nonce}"));
        let src_dir = root.join("libde265");
        fs::create_dir_all(&src_dir).unwrap();
        let source = src_dir.join("de265.cc");
        fs::write(
            &source,
            "#include \"libde265/vps.h\"\nint de265_decode_data() { return 0; }\n",
        )
        .unwrap();
        let roots = self_prefixed_include_roots(&source);
        assert!(
            roots.contains(&root),
            "expected the parent-of-prefix dir {root:?} in {roots:?}"
        );
    }

    #[test]
    fn self_prefixed_include_roots_ignores_plain_and_angle_includes() {
        // A bare `#include "foo.h"` (no prefix) and `#include <sys/x.h>` (angle)
        // must not add a self-prefixed root.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-selfinc2-{nonce}"));
        let src_dir = root.join("lib");
        fs::create_dir_all(&src_dir).unwrap();
        let source = src_dir.join("a.c");
        fs::write(&source, "#include \"foo.h\"\n#include <sys/types.h>\n").unwrap();
        assert!(
            self_prefixed_include_roots(&source).is_empty(),
            "no self-prefixed include present"
        );
    }

    #[test]
    fn auto_detect_c_headers_includes_quoted_project_headers_from_source() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-source-headers-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("compress.c");
        fs::write(
            &source,
            "#include <stddef.h>\n#include \"zlib.h\"\nint compress(void) { return 0; }\n",
        )
        .unwrap();
        fs::write(root.join("zlib.h"), "typedef unsigned char Bytef;\n").unwrap();

        let headers = auto_detect_c_headers(&source, &root);

        assert!(
            headers.contains(&"zlib.h".to_owned()),
            "quoted local include should be carried into generated main.c: {headers:?}"
        );
        assert!(
            !headers.contains(&"stddef.h".to_owned()),
            "system includes should not be converted to quoted project headers: {headers:?}"
        );
    }

    #[test]
    fn auto_detect_c_headers_preserves_config_before_same_stem_api() {
        let root = temp_dir("source-header-order");
        let source = root.join("legacy.cpp");
        fs::write(
            &source,
            "#include \"config.h\"\n#include \"legacy.hpp\"\nint parse() { return 0; }\n",
        )
        .unwrap();
        fs::write(root.join("config.h"), "#define LEGACY_API public\n").unwrap();
        fs::write(
            root.join("legacy.hpp"),
            "#ifndef LEGACY_API\n#error config must precede API\n#endif\n",
        )
        .unwrap();

        assert_eq!(
            auto_detect_c_headers(&source, &root),
            vec!["config.h".to_owned(), "legacy.hpp".to_owned()]
        );
    }

    #[test]
    fn harness_project_includes_picks_angle_project_headers_and_skips_partials() {
        use super::{harness_project_includes, is_partial_impl_header};
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-proj-inc-{nonce}"));
        let inc = root.join("include");
        fs::create_dir_all(inc.join("json")).unwrap();
        fs::write(inc.join("json/value.h"), "// public header\n").unwrap();
        let src_dir = root.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("json_valueiterator.inl"), "// partial\n").unwrap();
        fs::write(src_dir.join("free.c"), "#error include from alloc.c only\n").unwrap();

        // jsoncpp-shaped source: angle public header + a quoted .inl partial.
        let source = "#include <vector>\n\
                      #include <json/value.h>\n\
                      #include \"json_valueiterator.inl\"\n\
                      #include \"free.c\"\n";
        let dirs = vec![inc.clone(), src_dir.clone()];
        let got = harness_project_includes(source, &dirs);

        assert!(
            got.contains(&"json/value.h".to_owned()),
            "angle project header must be included: {got:?}"
        );
        assert!(
            !got.iter().any(|h| h.ends_with(".inl")),
            ".inl partial must be skipped (not standalone-includable): {got:?}"
        );
        assert!(
            !got.iter().any(|h| h.ends_with(".c")),
            "textually included implementation TUs must not be standalone includes: {got:?}"
        );
        assert!(
            !got.contains(&"vector".to_owned()),
            "system header must not be treated as project-local: {got:?}"
        );
        assert!(is_partial_impl_header("json_valueiterator.inl"));
        assert!(is_partial_impl_header("foo.tcc"));
        assert!(!is_partial_impl_header("json/value.h"));
    }

    #[test]
    fn harness_project_includes_skips_foreign_platform_guarded_includes() {
        use super::harness_project_includes;
        // libde265 shape: `threads.h` includes `"../extra/win32cond.h"` only under
        // `#ifdef _WIN32`; on Linux clang skips it, but a textual closure scan used
        // to pull it into the harness -> `<windows.h> file not found`. The host
        // `#else` include must still be kept.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-foreign-inc-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("win32cond.h"), "#include <windows.h>\n").unwrap();
        fs::write(root.join("posix_threads.h"), "int posix_marker;\n").unwrap();
        let source = "#ifdef _WIN32\n\
                      #include \"win32cond.h\"\n\
                      #else\n\
                      #include \"posix_threads.h\"\n\
                      #endif\n";
        let got = harness_project_includes(source, std::slice::from_ref(&root));
        assert!(
            !got.contains(&"win32cond.h".to_owned()),
            "Windows-only (#ifdef _WIN32) include must be skipped on the host: {got:?}"
        );
        assert!(
            got.contains(&"posix_threads.h".to_owned()),
            "the host #else include must be kept: {got:?}"
        );

        // A guard that also names the host keeps its includes (not purely foreign).
        fs::write(root.join("shared.h"), "int shared_marker;\n").unwrap();
        let mixed = "#if defined(_WIN32) || defined(__linux__)\n\
                     #include \"shared.h\"\n\
                     #endif\n";
        assert!(
            harness_project_includes(mixed, std::slice::from_ref(&root))
                .contains(&"shared.h".to_owned()),
            "a mixed host/foreign guard must keep its includes"
        );
    }

    #[test]
    fn harness_project_includes_pulls_transitive_deps_dependencies_first() {
        use super::harness_project_includes;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-trans-inc-{nonce}"));
        let common = root.join("common");
        fs::create_dir_all(&common).unwrap();
        // mavlink-shaped: the leaf message header is not self-contained — it needs
        // the umbrella header (which defines the shared types) included first.
        fs::write(
            common.join("mavlink.h"),
            "#ifndef MAVLINK_H\n#define MAVLINK_H\n// umbrella: shared types\n#endif\n",
        )
        .unwrap();
        fs::write(
            common.join("mavlink_msg_attitude.h"),
            "#include \"mavlink.h\"\nstatic inline int decode(const void *m){return 0;}\n",
        )
        .unwrap();
        let dirs = vec![common.clone()];
        let source = "#include \"mavlink_msg_attitude.h\"\n";
        let got = harness_project_includes(source, &dirs);
        assert_eq!(
            got,
            vec!["mavlink.h".to_owned(), "mavlink_msg_attitude.h".to_owned()],
            "umbrella dependency must precede the non-self-contained leaf: {got:?}"
        );
    }

    #[test]
    fn inferred_sibling_headers_do_not_precede_source_ordered_public_headers() {
        use super::ordered_c_harness_headers;

        let root = temp_dir("public-before-internal-headers");
        let include = root.join("include");
        fs::create_dir_all(&include).unwrap();
        let source_path = root.join("http.c");
        let source = "#include \"api.h\"\n#include \"http-internal.h\"\n";
        fs::write(&source_path, source).unwrap();
        fs::write(include.join("api.h"), "typedef int callback_t;\n").unwrap();
        fs::write(
            root.join("http-internal.h"),
            "struct state { callback_t callback; };\n",
        )
        .unwrap();

        let got = ordered_c_harness_headers(&source_path, &root, source, &[include, root.clone()]);
        let public = got.iter().position(|header| header == "api.h").unwrap();
        let internal = got
            .iter()
            .position(|header| header == "http-internal.h")
            .unwrap();
        assert!(
            public < internal,
            "the target source's public-header order must win: {got:?}"
        );
    }

    #[test]
    fn c_harness_does_not_flatten_contextual_transitive_headers() {
        use super::ordered_c_harness_headers;

        let root = temp_dir("contextual-transitive-headers");
        let source_path = root.join("save.c");
        let source = "#include \"h2def.h\"\n";
        fs::write(&source_path, source).unwrap();
        fs::write(
            root.join("h2def.h"),
            "#ifndef H2DEF_H\n#define H2DEF_H\n\
             typedef struct mobj_s { int x; } mobj_t;\n\
             #include \"p_action.h\"\n#endif\n",
        )
        .unwrap();
        fs::write(
            root.join("p_action.h"),
            "#ifndef P_ACTION_H\n#define P_ACTION_H\nvoid act(mobj_t *);\n#endif\n",
        )
        .unwrap();

        let got =
            ordered_c_harness_headers(&source_path, &root, source, std::slice::from_ref(&root));
        assert_eq!(got, vec!["h2def.h".to_owned()]);
    }

    #[test]
    fn harness_project_includes_leaves_umbrella_only_children_to_the_umbrella() {
        use super::harness_project_includes;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-umbrella-inc-{nonce}"));
        let api = root.join("api");
        fs::create_dir_all(api.join("lzma")).unwrap();
        fs::write(
            api.join("lzma.h"),
            "#define LZMA_H_INTERNAL 1\n#include \"lzma/version.h\"\n",
        )
        .unwrap();
        fs::write(
            api.join("lzma/version.h"),
            "#ifndef LZMA_H_INTERNAL\n# error Never include this file directly. Use <lzma.h> instead.\n#endif\n",
        )
        .unwrap();

        let got = harness_project_includes("#include <lzma.h>\n", &[api]);
        assert_eq!(got, vec!["lzma.h".to_owned()]);
    }

    #[test]
    fn harness_project_includes_does_not_emit_unguarded_transitive_header_twice() {
        use super::harness_project_includes;
        let root = temp_dir("unguarded-transitive-header");
        fs::write(
            root.join("h2def.h"),
            "#ifndef H2DEF_H\n#define H2DEF_H\n#include \"info.h\"\n#endif\n",
        )
        .unwrap();
        fs::write(root.join("info.h"), "enum { SPR_MAN1, SPR_ACLO };\n").unwrap();

        let got = harness_project_includes("#include \"h2def.h\"\n", &[root]);
        assert_eq!(got, vec!["h2def.h".to_owned()]);
    }

    #[test]
    fn is_openmp_translation_unit_detects_omp_runtime_calls() {
        use super::is_openmp_translation_unit;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-omp-tu-{nonce}"));
        fs::create_dir_all(&root).unwrap();

        // base64's lib_openmp.c shape: a `.c` TU that CALLS `omp_*` runtime
        // functions (the only thing that won't link without -fopenmp).
        let omp_tu = root.join("lib_openmp.c");
        fs::write(
            &omp_tu,
            "static int worker(void) {\n\t#pragma omp parallel\n\t{\n\t\tint n = omp_get_num_threads();\n\t\t(void)n;\n\t}\n\treturn 0;\n}\n",
        )
        .unwrap();
        assert!(
            is_openmp_translation_unit(&omp_tu),
            "a .c TU that calls an omp_* runtime function is an OpenMP TU"
        );

        // A bare `#pragma omp` loop with NO omp_* call links fine without -fopenmp
        // (the pragma is silently ignored) — must NOT be pruned.
        let pragma_only = root.join("hot.c");
        fs::write(
            &pragma_only,
            "int sum(const int *a, int n){int s=0;\n#pragma omp parallel for reduction(+:s)\nfor(int i=0;i<n;i++) s+=a[i];\nreturn s;}\n",
        )
        .unwrap();
        assert!(
            !is_openmp_translation_unit(&pragma_only),
            "a bare `#pragma omp` TU (no omp_* call) links fine and must NOT be pruned"
        );

        // An <omp.h>-including TU with no omp_* call only pulls in declarations —
        // also link-safe, must NOT be pruned.
        let header_only = root.join("parallel.c");
        fs::write(&header_only, "#include <omp.h>\nint p(void){return 0;}\n").unwrap();
        assert!(
            !is_openmp_translation_unit(&header_only),
            "a TU that only #includes <omp.h> (no omp_* call) links fine and must NOT be pruned"
        );

        // A plain `.c` TU is NOT OpenMP — and must never be pruned from the build.
        // Guard the word-boundary: `decompress_` contains `omp_` but is not a call.
        let plain = root.join("lib.c");
        fs::write(
            &plain,
            "int decompress_get_size(void){return 0;}\nint base64_decode(void){return 0;}\n",
        )
        .unwrap();
        assert!(
            !is_openmp_translation_unit(&plain),
            "`decompress_` must not match `omp_` (word boundary); plain codec is not OpenMP"
        );

        // A HEADER is kept (it may declare needed types); only SOURCE TUs are
        // whole-TU compiled into the harness.
        let hdr = root.join("omp_decls.h");
        fs::write(&hdr, "int x(void){return omp_get_num_threads();}\n").unwrap();
        assert!(
            !is_openmp_translation_unit(&hdr),
            "a .h header is not a whole-TU source include and is never pruned here"
        );
    }

    #[test]
    fn auto_detect_c_headers_excludes_openmp_translation_unit() {
        // base64 shape: lib.c does `#ifdef _OPENMP #include "lib_openmp.c" #endif`.
        // The harness builds WITHOUT -fopenmp, so the OpenMP wrapper TU must NOT be
        // pulled into the harness include set (it would `#include` a `.c` whose
        // `omp_get_num_threads()` calls are undeclared/unlinkable). The portable
        // companion header must still be carried.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-omp-headers-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("lib.c");
        fs::write(
            &source,
            "#include <omp.h>\n#include \"codecs.h\"\nint base64_decode(void){\n#ifdef _OPENMP\n#include \"lib_openmp.c\"\n#endif\nreturn 0;\n}\n",
        )
        .unwrap();
        fs::write(root.join("codecs.h"), "int codec_marker;\n").unwrap();
        fs::write(
            root.join("lib_openmp.c"),
            "int base64_decode_openmp(void){\n\t#pragma omp parallel\n\treturn omp_get_num_threads();\n}\n",
        )
        .unwrap();

        let headers = auto_detect_c_headers(&source, &root);
        assert!(
            !headers.contains(&"lib_openmp.c".to_owned()),
            "feature-gated OpenMP TU must be excluded from the harness include set: {headers:?}"
        );
        assert!(
            headers.contains(&"codecs.h".to_owned()),
            "a normal companion header must still be carried: {headers:?}"
        );
    }

    #[test]
    fn harness_project_includes_excludes_openmp_translation_unit() {
        use super::harness_project_includes;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-omp-proj-inc-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("lib_openmp.c"),
            "void w(void){\n#pragma omp parallel\n{ omp_set_num_threads(1); }\n}\n",
        )
        .unwrap();
        fs::write(root.join("env.h"), "int env_marker;\n").unwrap();
        // A source whose closure references both a normal header and the OpenMP TU.
        let source = "#include \"env.h\"\n#include \"lib_openmp.c\"\n";
        let got = harness_project_includes(source, std::slice::from_ref(&root));
        assert!(
            !got.contains(&"lib_openmp.c".to_owned()),
            "OpenMP TU must be skipped by the project-include closure: {got:?}"
        );
        assert!(
            got.contains(&"env.h".to_owned()),
            "the normal companion header must be kept: {got:?}"
        );
    }

    #[test]
    fn cleanup_flag_overrides_auto_detect_in_emitted_harness() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-cleanup-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("custom.c");
        // Return type doesn't match any built-in pattern, but the user
        // tells us how to free it via --cleanup.
        fs::write(
            &source,
            "typedef struct MyHandle MyHandle;\n\
             MyHandle * custom_parse(const char *str) { (void)str; return 0; }\n",
        )
        .unwrap();
        let out = root.join("generated_harnesses");
        let args = GenerateHarnessArgs {
            source: source.clone(),
            target: Some("custom_parse".to_owned()),
            target_line: None,
            output: out.clone(),
            id: Some("H-CUSTOM".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: Some("custom_handle_free(R)".to_owned()),
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };
        run(args).unwrap();
        let main_c = fs::read_to_string(out.join("H-CUSTOM/main.c")).unwrap();
        assert!(
            main_c.contains("custom_handle_free(R)"),
            "expected --cleanup expression in generated harness: {main_c}"
        );
    }

    /// §27.11: the `--container-size-max` flag threads all the way to the
    /// emitted C++ harness — a tighter cap shrinks the per-container element
    /// count bound (`gf_bounded_length(&Cur, 0, N)`). Exercises the full CLI
    /// path: clap flag -> GenerateHarnessArgs -> CppContextInput -> decoder ->
    /// main.cpp. (The C array cap is proved at the decoder-unit level, where it
    /// is not masked by the harness's by-value-struct type collection.)
    #[test]
    fn container_size_max_flag_shrinks_emitted_cpp_container_decode() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-ctrcap-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("vec.cpp");
        fs::write(
            &source,
            "#include <vector>\n#include <cstdint>\n\
             int vec_sum(const std::vector<std::uint32_t>& items) { int s = 0; for (auto x : items) s += (int)x; return s; }\n",
        )
        .unwrap();
        let out = root.join("generated_harnesses");

        let base = GenerateHarnessArgs {
            source: source.clone(),
            target: Some("vec_sum".to_owned()),
            target_line: None,
            output: out.clone(),
            id: Some("H-CTRCAP".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: DecoderLimitArgs::default(),
            force: false,
        };

        // Default cap (16): the historical container element-count bound.
        run(base.clone()).unwrap();
        let default_main = fs::read_to_string(out.join("H-CTRCAP/main.cpp")).unwrap();
        assert!(
            default_main.contains("gf_bounded_length(&Cur, 0, 16)"),
            "default container cap must emit `0, 16`: {default_main}"
        );

        // `--container-size-max 8`: the bound shrinks to 8.
        let capped = GenerateHarnessArgs {
            decoder_limits: DecoderLimitArgs {
                container_size_max: Some(8),
                ..DecoderLimitArgs::default()
            },
            ..base
        };
        run(capped).unwrap();
        let capped_main = fs::read_to_string(out.join("H-CTRCAP/main.cpp")).unwrap();
        assert!(
            capped_main.contains("gf_bounded_length(&Cur, 0, 8)"),
            "--container-size-max 8 must shrink the emitted bound to `0, 8`: {capped_main}"
        );
        assert!(
            !capped_main.contains(", 16)"),
            "the historical 16 cap must be gone from the harness: {capped_main}"
        );
    }

    /// §27.11: the six decoder-cap flags parse and resolve to the right
    /// `DecoderLimits` / `CppDecoderLimits` fields; unset flags keep defaults.
    #[test]
    fn decoder_limit_flags_parse_and_resolve() {
        use clap::Parser;
        #[derive(Parser)]
        struct Probe {
            #[command(flatten)]
            limits: DecoderLimitArgs,
        }
        let p = Probe::try_parse_from([
            "probe",
            "--max-decode-depth",
            "2",
            "--max-array-elems",
            "4",
            "--max-decl-bytes",
            "1024",
            "--container-size-max",
            "8",
            "--bitset-max-size",
            "64",
            "--array-max-size",
            "128",
        ])
        .expect("decoder-cap flags must parse");
        let c = p.limits.c_limits();
        assert_eq!((c.depth, c.array_elems, c.decl_bytes), (2, 4, 1024));
        let cpp = p.limits.cpp_limits();
        assert_eq!(
            (
                cpp.container_size_max,
                cpp.bitset_max_size,
                cpp.array_max_size
            ),
            (8, 64, 128)
        );

        // No flags -> historical defaults on both lanes.
        let d = Probe::try_parse_from(["probe"]).expect("no flags parse");
        assert_eq!(
            d.limits.c_limits(),
            harness_gen::c_decoders::DecoderLimits::default()
        );
        assert_eq!(
            d.limits.cpp_limits(),
            harness_gen::cpp_decoders::CppDecoderLimits::default()
        );
    }

    #[test]
    fn generic_package_target_is_blocked_with_clear_reason() {
        // A subprogram inside a generic package cannot be direct-called: GNAT
        // rejects `Gen_Pkg.Op` with "prefix must not be a generic package".
        // We must skip it cleanly rather than emit a harness that fails build.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-generic-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("gen_pkg.ads");
        fs::write(
            &source,
            "generic\n   type Element is private;\n\
             package Gen_Pkg is\n   procedure Op (E : Element);\nend Gen_Pkg;\n",
        )
        .unwrap();
        let args = GenerateHarnessArgs {
            source: source.clone(),
            target: Some("op".to_owned()),
            target_line: None,
            output: root.join("generated_harnesses"),
            id: Some("H-GEN".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };
        let err = run(args).expect_err("generic-package target must be refused");
        assert!(
            err.to_string().contains("blocked_by_generic"),
            "expected blocked_by_generic skip reason, got: {err}"
        );
    }

    #[test]
    fn private_child_direct_target_uses_child_subprogram_harness() {
        // A direct harness for a target in a private child package is reached
        // through a private-child-subprogram harness of the parent (a public
        // bridge can't `with` the private child to forward the call).
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-privchild-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("parent.ads"), "package Parent is\nend Parent;\n").unwrap();
        let source = root.join("parent-secret.ads");
        fs::write(
            &source,
            "private package Parent.Secret is\n   procedure Op (X : Integer);\nend Parent.Secret;\n",
        )
        .unwrap();
        let out = root.join("generated_harnesses");
        let args = GenerateHarnessArgs {
            source: source.clone(),
            target: Some("op".to_owned()),
            target_line: None,
            output: out.clone(),
            id: Some("H-PRIV".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };
        run(args).expect("private-child direct target must use a child harness, not be refused");
        // No public bridge; a private-child-subprogram harness spec + body. Ada is
        // case-insensitive; the parser's lowercased identifiers compile fine, so
        // compare case-insensitively.
        assert!(!out.join("H-PRIV/parent-gf_bridge.ads").exists());
        let spec = fs::read_to_string(out.join("H-PRIV/parent-gf_harness.ads"))
            .unwrap()
            .to_ascii_lowercase();
        let body = fs::read_to_string(out.join("H-PRIV/parent-gf_harness.adb"))
            .unwrap()
            .to_ascii_lowercase();
        assert!(spec.contains("private procedure parent.gf_harness;"));
        assert!(body.contains("procedure parent.gf_harness is"));
        assert!(body.contains("with parent.secret;"));
        assert!(body.contains("parent.secret.op"));
    }

    #[test]
    fn private_child_target_with_private_type_param_uses_child_subprogram_harness() {
        // The target's signature uses a parent-private type, so a public bridge
        // can't re-export it; the harness is generated as a private child
        // subprogram of the parent (whose body sees the private part).
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-privtype-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("pp.ads"),
            "package PP is\nprivate\n   type Secret_Ptr is access all Integer;\nend PP;\n",
        )
        .unwrap();
        let source = root.join("pp-inner.ads");
        fs::write(
            &source,
            "private package PP.Inner is\n   procedure Work (P : PP.Secret_Ptr);\nend PP.Inner;\n",
        )
        .unwrap();
        let out = root.join("generated_harnesses");
        let args = GenerateHarnessArgs {
            source: source.clone(),
            target: Some("work".to_owned()),
            target_line: None,
            output: out.clone(),
            id: Some("H-PT".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };
        run(args).expect("private-type-sig private-child target must use a child harness");
        // No bridge; instead a private-child-subprogram harness spec + body.
        assert!(!out.join("H-PT/pp-gf_bridge.ads").exists());
        let spec = fs::read_to_string(out.join("H-PT/pp-gf_harness.ads"))
            .unwrap()
            .to_ascii_lowercase();
        let body = fs::read_to_string(out.join("H-PT/pp-gf_harness.adb"))
            .unwrap()
            .to_ascii_lowercase();
        assert!(spec.contains("private procedure pp.gf_harness;"));
        assert!(body.contains("procedure pp.gf_harness is"));
        assert!(body.contains("with pp.inner;"));
        assert!(body.contains("pp.inner.work"));
        // The parent-private type is named (visible in the child body).
        assert!(body.contains("pp.secret_ptr"));
    }

    #[test]
    fn private_child_sequence_kind_is_still_blocked() {
        // Only the direct path bridges; other kinds still skip cleanly.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-privchild-seq-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("parent-secret.ads");
        fs::write(
            &source,
            "private package Parent.Secret is\n   procedure Op (X : Integer);\nend Parent.Secret;\n",
        )
        .unwrap();
        let args = GenerateHarnessArgs {
            source: source.clone(),
            target: Some("op".to_owned()),
            target_line: None,
            output: root.join("generated_harnesses"),
            id: Some("H-PRIV-SEQ".to_owned()),
            kind: "sequence".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };
        let err = run(args).expect_err("non-direct private child must still be refused");
        assert!(
            err.to_string().contains("blocked_by_private_child"),
            "expected blocked_by_private_child, got: {err}"
        );
    }

    #[test]
    fn private_child_detector_ignores_private_part_of_a_spec() {
        // The `private` part of an ordinary package is not a private child.
        assert!(super::ada_private_child_unit(
            "package P is\n   procedure Op;\nprivate\n   type T is null record;\nend P;\n"
        )
        .is_none());
        assert_eq!(
            super::ada_private_child_unit("private package Parent.Child is\nend Parent.Child;\n"),
            Some("Parent.Child".to_owned())
        );
    }

    #[test]
    fn generic_codec_package_is_instantiated_with_fuzz_callbacks() {
        // A generic package with codec-shaped formals (a byte reader + a sink)
        // and a parameterless op must be instantiated - feeding fuzz bytes
        // through Read_Byte - rather than skipped.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-codec-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("codec.ads");
        fs::write(
            &source,
            "with Interfaces;\n\
             generic\n\
             \x20  with function Read_Byte return Interfaces.Unsigned_8;\n\
             \x20  with procedure Write_Byte (B : Interfaces.Unsigned_8);\n\
             package Codec is\n   procedure Run;\nend Codec;\n",
        )
        .unwrap();
        let out = root.join("generated_harnesses");
        let args = GenerateHarnessArgs {
            source: source.clone(),
            target: Some("run".to_owned()),
            target_line: None,
            output: out.clone(),
            id: Some("H-CODEC".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };
        run(args).expect("generic codec package must be instantiated, not skipped");
        let main_adb = fs::read_to_string(out.join("H-CODEC/main.adb")).unwrap();
        assert!(
            main_adb.contains("is new codec") && main_adb.contains("Read_Byte => Stub_Read_Byte"),
            "expected a generic instantiation wiring fuzz callbacks: {main_adb}"
        );
        assert!(
            main_adb.contains("Interfaces.Unsigned_8 (AdaFuzz.Decode.U8 (Cur))"),
            "Read_Byte stub must feed fuzz bytes: {main_adb}"
        );
        assert!(
            main_adb.contains("Govfuzz_Generic_Instance.run"),
            "the target must be called through the instance: {main_adb}"
        );
    }

    #[test]
    fn generic_package_operation_with_record_param_is_synthesized() {
        // A parametered op of a generic package (the shape of
        // `LZMA.Decoding.Decompress (hints : LZMA_Hints)`): the record param's
        // type is declared *inside* the generic package, so it is reachable
        // only as `<instance>.Hints`. The harness must instantiate the generic,
        // qualify the record type with the instance name, and synthesise the
        // aggregate from fuzz bytes - not skip as `blocked_by_generic`.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-codec-rec-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("codec.ads");
        fs::write(
            &source,
            "with Interfaces;\n\
             generic\n\
             \x20  with function Read_Byte return Interfaces.Unsigned_8;\n\
             \x20  with procedure Write_Byte (B : Interfaces.Unsigned_8);\n\
             package Codec is\n\
             \x20  type Hints is record\n\
             \x20     Has_Size        : Boolean;\n\
             \x20     Marker_Expected : Boolean;\n\
             \x20  end record;\n\
             \x20  procedure Decompress (H : Hints);\n\
             end Codec;\n",
        )
        .unwrap();
        let out = root.join("generated_harnesses");
        let args = GenerateHarnessArgs {
            source: source.clone(),
            target: Some("decompress".to_owned()),
            target_line: None,
            output: out.clone(),
            id: Some("H-CODEC-REC".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };
        run(args)
            .expect("generic-package op with a synthesizable record param must not be skipped");
        let main_adb = fs::read_to_string(out.join("H-CODEC-REC/main.adb")).unwrap();
        assert!(
            main_adb.contains("is new codec"),
            "expected a generic instantiation: {main_adb}"
        );
        assert!(
            main_adb.contains("Govfuzz_Generic_Instance.Hints'("),
            "the record param type must be qualified with the instance name: {main_adb}"
        );
        assert!(
            main_adb.contains("Has_Size => AdaFuzz.Decode.Bool")
                && main_adb.contains("Marker_Expected => AdaFuzz.Decode.Bool"),
            "record fields must be decoded from fuzz bytes: {main_adb}"
        );
        assert!(
            main_adb.contains("Govfuzz_Generic_Instance.decompress"),
            "the target must be called through the instance: {main_adb}"
        );
    }

    #[test]
    fn out_param_of_private_type_is_declared_bare() {
        // The shape of `LZMA.Decoding.Decode (info : out LZMA_Decoder_Info)`:
        // a pure `out` parameter of a limited-private type is the result the
        // callee constructs, so the harness declares it bare rather than
        // skipping for lack of a constructor.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-outpriv-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("dec.ads");
        fs::write(
            &source,
            "package Dec is\n\
             \x20  type State is limited private;\n\
             \x20  procedure Build (S : out State);\n\
             private\n\
             \x20  type State is record N : Integer := 0; end record;\n\
             end Dec;\n",
        )
        .unwrap();
        let out = root.join("generated_harnesses");
        let args = GenerateHarnessArgs {
            source: source.clone(),
            target: Some("build".to_owned()),
            target_line: None,
            output: out.clone(),
            id: Some("H-OUTPRIV".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };
        run(args).expect("out param of a private type must be declared bare, not skipped");
        let main_adb = fs::read_to_string(out.join("H-OUTPRIV/main.adb")).unwrap();
        assert!(
            main_adb.contains("S : Dec.State;") || main_adb.contains("S : State;"),
            "the out param must be declared bare (no initializer): {main_adb}"
        );
        assert!(
            !main_adb.contains("S : Dec.State :="),
            "the out param must not get an initializer: {main_adb}"
        );
    }

    #[test]
    fn generic_encoder_subprogram_is_instantiated_and_called_with_defaults() {
        // The encoders are generic subprograms whose own parameters are all
        // defaulted: instantiate with fuzz callbacks, call with no arguments.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-enc-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("enc.ads");
        fs::write(
            &source,
            "with Interfaces;\n\
             package Enc is\n\
             \x20  generic\n\
             \x20     with function Read_Byte return Interfaces.Unsigned_8;\n\
             \x20     with procedure Write_Byte (B : Interfaces.Unsigned_8);\n\
             \x20  procedure Encode (Level : Integer := 1);\nend Enc;\n",
        )
        .unwrap();
        let out = root.join("generated_harnesses");
        let args = GenerateHarnessArgs {
            source: source.clone(),
            target: Some("encode".to_owned()),
            target_line: None,
            output: out.clone(),
            id: Some("H-ENC".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };
        run(args).expect("generic encoder subprogram must be instantiated");
        let main_adb = fs::read_to_string(out.join("H-ENC/main.adb")).unwrap();
        assert!(
            main_adb.contains("procedure Govfuzz_Generic_Instance is new enc.encode"),
            "expected a generic-subprogram instantiation: {main_adb}"
        );
        assert!(
            main_adb.contains("Govfuzz_Generic_Instance;")
                && !main_adb.contains("Govfuzz_Generic_Instance ("),
            "the instantiated subprogram must be called with no arguments: {main_adb}"
        );
    }

    #[test]
    fn generic_subprogram_target_is_blocked_with_clear_reason() {
        // A generic subprogram in an ordinary package (e.g. zip-ada's
        // `generic ... procedure Traverse (z : Zip_Info)`) cannot be called
        // until instantiated - skip it cleanly instead of emitting a harness
        // that fails to build.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("govfuzz-genproc-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("pkg.ads");
        fs::write(
            &source,
            "package Pkg is\n   generic\n      with procedure Action (X : Integer);\n\
             \x20  procedure Traverse (N : Integer);\nend Pkg;\n",
        )
        .unwrap();
        let args = GenerateHarnessArgs {
            source: source.clone(),
            target: Some("traverse".to_owned()),
            target_line: None,
            output: root.join("generated_harnesses"),
            id: Some("H-GENPROC".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };
        let err = run(args).expect_err("generic subprogram target must be refused");
        assert!(
            err.to_string().contains("blocked_by_generic"),
            "expected blocked_by_generic skip reason, got: {err}"
        );
    }

    #[derive(Debug, Parser)]
    struct HarnessOnly {
        #[command(flatten)]
        args: GenerateHarnessArgs,
    }

    fn subprogram(id: u32, name: &str) -> Subprogram {
        Subprogram {
            id: SubprogramId(id),
            owner: SubprogramOwner::LibraryLevel,
            name: name.to_owned(),
            kind: SubprogramKind::Procedure,
            params: Vec::new(),
            return_type: None,
            is_abstract: false,
            is_dispatching: false,
            is_overriding: false,
            body_span: None,
            decl_span: Span::new(0, 1, 1, 1),
            handlers: Vec::new(),
            raises: Vec::new(),
            visibility: Visibility::Public,
            is_generic: false,
        }
    }

    #[test]
    fn ada_target_line_selects_the_exact_duplicate_named_subprogram() {
        let mut first = subprogram(1, "Decode");
        first.decl_span = Span::new(0, 1, 10, 1);
        let mut second = subprogram(2, "Decode");
        second.decl_span = Span::new(2, 3, 40, 1);
        let ast = StructuralAstForMerge {
            subprograms: vec![first, second],
            ..StructuralAstForMerge::default()
        };

        let selected = select_subprogram(&ast, Some("decode"), Some(40)).unwrap();
        assert_eq!(selected.id, SubprogramId(2));
    }

    #[test]
    fn ada_stale_target_line_falls_back_deterministically_to_first_declaration() {
        let mut later = subprogram(2, "Decode");
        later.decl_span = Span::new(2, 3, 40, 1);
        let mut earlier = subprogram(1, "Decode");
        earlier.decl_span = Span::new(0, 1, 10, 1);
        let ast = StructuralAstForMerge {
            subprograms: vec![later, earlier],
            ..StructuralAstForMerge::default()
        };

        let selected = select_subprogram(&ast, Some("Decode"), Some(99)).unwrap();
        assert_eq!(selected.id, SubprogramId(1));
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-cli-{name}-{nonce}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn ada_dependency_merge_preserves_qualified_same_leaf_access_types() {
        let dir = temp_dir("ada-qualified-access-collision");
        let target = dir.join("app.ads");
        fs::write(
            &target,
            "with Left; with Right;\n\
             package App is\n\
                procedure Create (Value : Right.Object_Access);\n\
             end App;\n",
        )
        .unwrap();
        fs::write(
            dir.join("left.ads"),
            "package Left is\n\
                type Object is tagged null record;\n\
                type Object_Access is access all Object;\n\
             end Left;\n",
        )
        .unwrap();
        fs::write(
            dir.join("right.ads"),
            "package Right is\n\
                protected type Object (Size : Positive) is\n\
                   procedure Touch;\n\
                end Object;\n\
                type Object_Access is access all Object;\n\
             end Right;\n",
        )
        .unwrap();
        let source = fs::read_to_string(&target).unwrap();

        let ast = build_harness_ast(&source, &target, std::slice::from_ref(&dir)).unwrap();
        let names = ast
            .types
            .iter()
            .map(|type_ref| type_ref.name_path.join("."))
            .collect::<Vec<_>>();

        assert!(
            names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("Left.Object_Access")),
            "{names:?}"
        );
        assert!(
            names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("Right.Object_Access")),
            "{names:?}"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn c_handle_defined_in_headers_distinguishes_opaque_from_complete() {
        use super::c_handle_defined_in_headers;
        // GAP #6 (tidwall/hashmap.c): `struct hashmap` is FORWARD-declared in the
        // header but defined (body) only in the `.c`. Judged against the HEADERS
        // alone it is opaque -> the sequence path must NOT zero-construct it.
        let dir = temp_dir("c-handle-headers");
        let header = dir.join("map.h");
        let source = dir.join("map.c");
        fs::write(
            &header,
            "struct hashmap;\n\
             typedef struct hashmap hashmap_t;\n\
             struct point { int x; int y; };\n\
             typedef struct point point_t;\n\
             const void *hashmap_set_with_hash(struct hashmap *m, const void *i, unsigned long h);\n",
        )
        .unwrap();
        fs::write(
            &source,
            "#include \"map.h\"\n\
             struct hashmap { int (*cmp)(const void *, const void *); int count; };\n",
        )
        .unwrap();
        let includes = vec!["map.h".to_owned()];
        let dirs = vec![dir.clone()];

        // Opaque in headers (body only in the `.c`) -> false.
        assert!(
            !c_handle_defined_in_headers("struct hashmap", &source, &includes, &dirs),
            "struct hashmap is forward-declared only in headers"
        );
        assert!(
            !c_handle_defined_in_headers("hashmap_t", &source, &includes, &dirs),
            "a typedef must not make a forward-declared struct complete"
        );
        // A struct whose full body IS in the header -> true (regression guard: a
        // header-complete handle, like libyaml's `yaml_parser_t`, is NOT over-skipped).
        assert!(
            c_handle_defined_in_headers("struct point", &source, &includes, &dirs),
            "struct point is fully defined in the header"
        );
        assert!(
            c_handle_defined_in_headers("point_t", &source, &includes, &dirs),
            "a typedef to a header-complete struct remains constructible"
        );
    }

    #[test]
    fn generate_harness_subcommand_parses_required_path() {
        let parsed = HarnessOnly::try_parse_from(["harness", "src/pkg.adb"])
            .unwrap()
            .args;

        assert_eq!(parsed.source, PathBuf::from("src/pkg.adb"));
    }

    #[test]
    fn generate_harness_default_kind_is_direct() {
        let parsed = HarnessOnly::try_parse_from(["harness", "src/pkg.adb"])
            .unwrap()
            .args;

        assert_eq!(parsed.kind, "direct");
    }

    #[test]
    fn generate_harness_parses_explicit_source_roots() {
        let parsed = HarnessOnly::try_parse_from([
            "harness",
            "src/base/dates/util-dates-iso8601.adb",
            "--source-root",
            "src/core",
            "--source-root",
            "src/base/dates",
        ])
        .unwrap()
        .args;

        assert_eq!(
            parsed.source_roots,
            vec![PathBuf::from("src/core"), PathBuf::from("src/base/dates")]
        );
    }

    #[test]
    fn generate_harness_parses_project_file() {
        let parsed =
            HarnessOnly::try_parse_from(["harness", "src/pkg.adb", "--project", "app.gpr"])
                .unwrap()
                .args;

        assert_eq!(parsed.project, Some(PathBuf::from("app.gpr")));
    }

    #[test]
    fn generate_harness_unsupported_kind_returns_error() {
        let args = GenerateHarnessArgs {
            source: PathBuf::from("src/pkg.adb"),
            target: None,
            target_line: None,
            output: PathBuf::from("generated_harnesses"),
            id: None,
            kind: "fake_corba".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };

        let error = run(args).unwrap_err();

        assert!(error.to_string().contains("unsupported harness kind"));
        assert!(error.to_string().contains("fake_corba"));
    }

    #[test]
    fn generate_harness_sequence_for_package_fixture() {
        let temp = temp_dir("sequence-package");
        let source = temp.join("state.adb");
        fs::write(&source, PRIVATE_STATE_BODY).unwrap();
        fs::write(temp.join("state.ads"), PRIVATE_STATE_SPEC).unwrap();

        let args = GenerateHarnessArgs {
            source,
            target: Some("State".to_owned()),
            target_line: None,
            output: temp.join("generated_harnesses"),
            id: Some("H-M9".to_owned()),
            kind: "sequence".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };

        run(args).unwrap();

        let main_adb = temp.join("generated_harnesses/H-M9/main.adb");
        let main_text = fs::read_to_string(main_adb).unwrap();
        assert!(main_text.contains("State.Push"));
        assert!(main_text.contains("State.Pop"));
        assert!(!main_text.contains("State.Helper"));
    }

    #[test]
    fn compute_default_id_is_stable_for_same_input() {
        let source = PathBuf::from("src/pkg.adb");
        let target = subprogram(1, "Run");

        assert_eq!(
            compute_default_id(&source, &target),
            compute_default_id(&source, &target)
        );
    }

    #[test]
    fn compute_default_id_differs_for_different_targets() {
        let source = PathBuf::from("src/pkg.adb");

        assert_ne!(
            compute_default_id(&source, &subprogram(1, "Run")),
            compute_default_id(&source, &subprogram(2, "Run"))
        );
    }

    #[test]
    fn end_to_end_generate_for_swallowed_constraint_error_fixture() {
        let temp = temp_dir("swallowed-constraint");
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../ada_parser/tests/golden/ada95/swallowed_constraint_error/src.adb");
        let args = GenerateHarnessArgs {
            source: source.clone(),
            target: Some("Parse".to_owned()),
            target_line: None,
            output: temp.clone(),
            id: Some("H-TEST".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };

        run(args).unwrap();

        let main_adb = temp.join("H-TEST/main.adb");
        let gpr = temp.join("H-TEST/H_TEST.gpr");
        assert!(main_adb.exists());
        assert!(gpr.exists());
        let main_text = fs::read_to_string(&main_adb).unwrap();
        assert!(main_text.contains("Pkg.Parse"));
        assert!(main_text.contains("AdaFuzz.Decode.Ada_String"));
        ada_parser::reconcile::build_structural_ast(&main_text, None, &main_adb).unwrap();
    }

    #[test]
    fn generate_ada_harness_writes_dictionary_from_enums_and_strings() {
        let temp = temp_dir("ada-dictionary");
        let source = temp.join("parser.adb");
        fs::write(
            &source,
            "package body Parser is\n\
               type Mode is (Mode_Fast, Mode_Safe);\n\
               procedure Parse (Input : in String) is\n\
               begin\n\
                  if Input = \"READY\" then\n\
                     null;\n\
                  end if;\n\
               end Parse;\n\
             end Parser;\n",
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("Parse".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-ADICT".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let dictionary = fs::read_to_string(temp.join("out/H-ADICT/dictionary.txt")).unwrap();
        assert!(dictionary.contains("\"Mode_Fast\""));
        assert!(dictionary.contains("\"Mode_Safe\""));
        assert!(dictionary.contains("\"READY\""));
    }

    #[test]
    fn generate_harness_includes_explicit_source_roots_in_gpr() {
        let temp = temp_dir("source-roots");
        let core = temp.join("src/core");
        let dates = temp.join("src/base/dates");
        fs::create_dir_all(&core).unwrap();
        fs::create_dir_all(&dates).unwrap();
        fs::write(core.join("util.ads"), "package Util is end Util;").unwrap();
        fs::write(
            dates.join("util-dates.ads"),
            "package Util.Dates is end Util.Dates;",
        )
        .unwrap();
        fs::write(
            dates.join("util-dates-iso8601.ads"),
            "with Ada.Calendar; package Util.Dates.ISO8601 is function Value (Date : in String) return Ada.Calendar.Time; end Util.Dates.ISO8601;",
        )
        .unwrap();
        let source = dates.join("util-dates-iso8601.adb");
        fs::write(
            &source,
            "package body Util.Dates.ISO8601 is function Value (Date : in String) return Ada.Calendar.Time is pragma Unreferenced (Date); begin return Ada.Calendar.Clock; end Value; end Util.Dates.ISO8601;",
        )
        .unwrap();

        let args = GenerateHarnessArgs {
            source,
            target: Some("Value".to_owned()),
            target_line: None,
            output: temp.join("generated_harnesses"),
            id: Some("H-ROOTS".to_owned()),
            kind: "direct".to_owned(),
            source_roots: vec![core.clone()],
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };

        run(args).unwrap();

        let gpr = fs::read_to_string(temp.join("generated_harnesses/H-ROOTS/H_ROOTS.gpr"))
            .expect("generated GPR is readable");
        let main = fs::read_to_string(temp.join("generated_harnesses/H-ROOTS/main.adb"))
            .expect("generated main is readable");
        assert!(gpr.contains(&format!("\"{}\"", core.display())));
        assert!(gpr.contains(&format!("\"{}\"", dates.display())));
        assert!(main.contains("with Ada.Calendar;"));
    }

    #[test]
    fn generate_harness_uses_project_sources_for_analysis_and_imports_project_in_gpr() {
        let temp = temp_dir("project-source-roots");
        let app_src = temp.join("app/src");
        let common_src = temp.join("common/src");
        fs::create_dir_all(&app_src).unwrap();
        fs::create_dir_all(&common_src).unwrap();
        fs::write(
            common_src.join("common.ads"),
            "package Common is subtype Byte is Integer range 0 .. 255; type Byte_Seq is array (Positive range <>) of Byte; end Common;",
        )
        .unwrap();
        fs::write(
            app_src.join("app.ads"),
            "with Common; use Common; package App is procedure Run (Data : in Byte_Seq); end App;",
        )
        .unwrap();
        let source = app_src.join("app.adb");
        fs::write(
            &source,
            "with Common; use Common; package body App is procedure Run (Data : in Byte_Seq) is pragma Unreferenced (Data); begin null; end Run; end App;",
        )
        .unwrap();
        fs::write(
            temp.join("common/common.gpr"),
            "project Common is for Source_Dirs use (\"src\"); end Common;",
        )
        .unwrap();
        let project = temp.join("app/app.gpr");
        fs::write(
            &project,
            "with \"../common/common.gpr\";\nproject App is\n   for Source_Dirs use (\"src\");\nend App;",
        )
        .unwrap();

        let args = GenerateHarnessArgs {
            source,
            target: Some("Run".to_owned()),
            target_line: None,
            output: temp.join("generated_harnesses"),
            id: Some("H-GPR".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: Some(project),
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };

        run(args).unwrap();

        let gpr = fs::read_to_string(temp.join("generated_harnesses/H-GPR/H_GPR.gpr"))
            .expect("generated GPR is readable");
        let main = fs::read_to_string(temp.join("generated_harnesses/H-GPR/main.adb"))
            .expect("generated main is readable");
        assert!(gpr.contains("app.gpr"));
        assert!(!gpr.contains(&format!("\"{}\"", app_src.display())));
        assert!(!gpr.contains(&format!("\"{}\"", common_src.display())));
        assert!(main.contains("function Decode_Data return Common.Byte_Seq is"));
    }

    #[test]
    fn generate_harness_imports_project_in_gpr_without_duplicating_its_source_dirs() {
        let temp = temp_dir("project-import");
        let app_src = temp.join("app/src");
        let common_src = temp.join("common/src");
        fs::create_dir_all(&app_src).unwrap();
        fs::create_dir_all(&common_src).unwrap();
        fs::write(
            common_src.join("common.ads"),
            "package Common is subtype Byte is Integer range 0 .. 255; type Byte_Seq is array (Positive range <>) of Byte; end Common;",
        )
        .unwrap();
        fs::write(
            app_src.join("app.ads"),
            "with Common; use Common; package App is procedure Run (Data : in Byte_Seq); end App;",
        )
        .unwrap();
        let source = app_src.join("app.adb");
        fs::write(
            &source,
            "with Common; use Common; package body App is procedure Run (Data : in Byte_Seq) is pragma Unreferenced (Data); begin null; end Run; end App;",
        )
        .unwrap();
        fs::write(
            temp.join("common/common.gpr"),
            "project Common is for Source_Dirs use (\"src\"); end Common;",
        )
        .unwrap();
        let project = temp.join("app/app.gpr");
        fs::write(
            &project,
            "with \"../common/common.gpr\";\nproject App is\n   for Source_Dirs use (\"src\");\nend App;",
        )
        .unwrap();

        let args = GenerateHarnessArgs {
            source,
            target: Some("Run".to_owned()),
            target_line: None,
            output: temp.join("generated_harnesses"),
            id: Some("H-GPR-IMPORT".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: Some(project),
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };

        run(args).unwrap();

        let gpr =
            fs::read_to_string(temp.join("generated_harnesses/H-GPR-IMPORT/H_GPR_IMPORT.gpr"))
                .expect("generated GPR is readable");
        assert!(gpr.contains("app.gpr"));
        assert!(!gpr.contains(&format!("\"{}\"", app_src.display())));
        assert!(!gpr.contains(&format!("\"{}\"", common_src.display())));
    }

    #[test]
    fn generate_harness_resolves_extensionless_project_imports_as_gpr_files() {
        let temp = temp_dir("project-extensionless-imports");
        let app_src = temp.join("app/src");
        let common_src = temp.join("common/src");
        fs::create_dir_all(&app_src).unwrap();
        fs::create_dir_all(&common_src).unwrap();
        fs::write(
            common_src.join("common.ads"),
            "package Common is subtype Byte is Integer range 0 .. 255; type Byte_Seq is array (Positive range <>) of Byte; end Common;",
        )
        .unwrap();
        fs::write(
            app_src.join("app.ads"),
            "with Common; use Common; package App is procedure Run (Data : in Byte_Seq); end App;",
        )
        .unwrap();
        let source = app_src.join("app.adb");
        fs::write(
            &source,
            "with Common; use Common; package body App is procedure Run (Data : in Byte_Seq) is pragma Unreferenced (Data); begin null; end Run; end App;",
        )
        .unwrap();
        fs::write(
            temp.join("common/common.gpr"),
            "project Common is for Source_Dirs use (\"src\"); end Common;",
        )
        .unwrap();
        let project = temp.join("app/app.gpr");
        fs::write(
            &project,
            "with \"../common/common\";\nproject App is\n   for Source_Dirs use (\"src\");\nend App;",
        )
        .unwrap();

        let args = GenerateHarnessArgs {
            source,
            target: Some("Run".to_owned()),
            target_line: None,
            output: temp.join("generated_harnesses"),
            id: Some("H-GPR-NOEXT".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: Some(project),
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };

        run(args).unwrap();

        let gpr = fs::read_to_string(temp.join("generated_harnesses/H-GPR-NOEXT/H_GPR_NOEXT.gpr"))
            .expect("generated GPR is readable");
        let main = fs::read_to_string(temp.join("generated_harnesses/H-GPR-NOEXT/main.adb"))
            .expect("generated main is readable");
        assert!(gpr.contains("app.gpr"));
        assert!(!gpr.contains(&format!("\"{}\"", app_src.display())));
        assert!(!gpr.contains(&format!("\"{}\"", common_src.display())));
        assert!(main.contains("function Decode_Data return Common.Byte_Seq is"));
    }

    #[test]
    fn generate_harness_resolves_project_imports_from_source_tree() {
        let temp = temp_dir("project-import-search");
        let app_src = temp.join("repo/app/src");
        let common_src = temp.join("repo/shared/common/src");
        fs::create_dir_all(&app_src).unwrap();
        fs::create_dir_all(&common_src).unwrap();
        fs::write(
            common_src.join("common.ads"),
            "package Common is subtype Byte is Integer range 0 .. 255; type Byte_Seq is array (Positive range <>) of Byte; end Common;",
        )
        .unwrap();
        fs::write(
            app_src.join("app.ads"),
            "with Common; use Common; package App is procedure Run (Data : in Byte_Seq); end App;",
        )
        .unwrap();
        let source = app_src.join("app.adb");
        fs::write(
            &source,
            "with Common; use Common; package body App is procedure Run (Data : in Byte_Seq) is pragma Unreferenced (Data); begin null; end Run; end App;",
        )
        .unwrap();
        fs::write(
            temp.join("repo/shared/common/common.gpr"),
            "project Common is for Source_Dirs use (\"src\"); end Common;",
        )
        .unwrap();
        let project = temp.join("repo/app/app.gpr");
        fs::write(
            &project,
            "with \"common.gpr\";\nproject App is\n   for Source_Dirs use (\"src\");\nend App;",
        )
        .unwrap();

        let args = GenerateHarnessArgs {
            source,
            target: Some("Run".to_owned()),
            target_line: None,
            output: temp.join("generated_harnesses"),
            id: Some("H-GPR-SEARCH".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: Some(project),
            source_trees: vec![temp.join("repo")],
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };

        run(args).unwrap();

        let gpr =
            fs::read_to_string(temp.join("generated_harnesses/H-GPR-SEARCH/H_GPR_SEARCH.gpr"))
                .expect("generated GPR is readable");
        let main = fs::read_to_string(temp.join("generated_harnesses/H-GPR-SEARCH/main.adb"))
            .expect("generated main is readable");
        assert!(gpr.contains("app.gpr"));
        assert!(!gpr.contains(&format!("\"{}\"", app_src.display())));
        assert!(!gpr.contains(&format!("\"{}\"", common_src.display())));
        assert!(main.contains("function Decode_Data return Common.Byte_Seq is"));
    }

    #[test]
    fn generate_harness_skips_missing_imports_when_source_tree_is_available() {
        let temp = temp_dir("project-missing-import");
        let app_src = temp.join("repo/app/src");
        fs::create_dir_all(&app_src).unwrap();
        fs::write(
            app_src.join("app.ads"),
            "package App is procedure Run; end App;",
        )
        .unwrap();
        let source = app_src.join("app.adb");
        fs::write(
            &source,
            "package body App is procedure Run is begin null; end Run; end App;",
        )
        .unwrap();
        let project = temp.join("repo/app/app.gpr");
        fs::write(
            &project,
            "with \"missing_external\";\nproject App is\n   for Source_Dirs use (\"src\");\nend App;",
        )
        .unwrap();

        let args = GenerateHarnessArgs {
            source,
            target: Some("Run".to_owned()),
            target_line: None,
            output: temp.join("generated_harnesses"),
            id: Some("H-GPR-MISSING".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: Some(project),
            source_trees: vec![temp.join("repo")],
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };

        run(args).unwrap();

        let gpr =
            fs::read_to_string(temp.join("generated_harnesses/H-GPR-MISSING/H_GPR_MISSING.gpr"))
                .expect("generated GPR is readable");
        assert!(gpr.contains("app.gpr"));
        assert!(!gpr.contains(&format!("\"{}\"", app_src.display())));
    }

    #[test]
    fn generate_harness_expands_source_tree_dirs_in_gpr() {
        let temp = temp_dir("source-tree");
        let core = temp.join("src/core");
        let base = temp.join("src/base");
        let dates = base.join("dates");
        fs::create_dir_all(&core).unwrap();
        fs::create_dir_all(&dates).unwrap();
        fs::write(core.join("util.ads"), "package Util is end Util;").unwrap();
        fs::write(
            base.join("util-dates.ads"),
            "package Util.Dates is end Util.Dates;",
        )
        .unwrap();
        fs::write(
            dates.join("util-dates-iso8601.ads"),
            "with Ada.Calendar; package Util.Dates.ISO8601 is function Value (Date : in String) return Ada.Calendar.Time; end Util.Dates.ISO8601;",
        )
        .unwrap();
        let source = dates.join("util-dates-iso8601.adb");
        fs::write(
            &source,
            "package body Util.Dates.ISO8601 is function Value (Date : in String) return Ada.Calendar.Time is pragma Unreferenced (Date); begin return Ada.Calendar.Clock; end Value; end Util.Dates.ISO8601;",
        )
        .unwrap();

        let args = GenerateHarnessArgs {
            source,
            target: Some("Value".to_owned()),
            target_line: None,
            output: temp.join("generated_harnesses"),
            id: Some("H-TREE".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: vec![temp.join("src")],
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };

        run(args).unwrap();

        let gpr = fs::read_to_string(temp.join("generated_harnesses/H-TREE/H_TREE.gpr"))
            .expect("generated GPR is readable");
        assert!(gpr.contains(&format!("\"{}\"", core.display())));
        assert!(gpr.contains(&format!("\"{}\"", base.display())));
        assert!(gpr.contains(&format!("\"{}\"", dates.display())));
    }

    #[test]
    fn generate_harness_uses_constructors_from_withed_dependency_specs() {
        let temp = temp_dir("with-source-root-constructors");
        let app_src = temp.join("app");
        let dep_src = temp.join("dep");
        fs::create_dir_all(&app_src).unwrap();
        fs::create_dir_all(&dep_src).unwrap();
        fs::write(
            dep_src.join("keys.ads"),
            "package Keys is\n   type Public_Key is limited private;\n   function Construct (Seed : in Integer) return Public_Key;\nprivate\n   type Public_Key is limited record\n      F : Integer;\n   end record;\nend Keys;\n",
        )
        .unwrap();
        let source = app_src.join("api.adb");
        fs::write(
            &source,
            "with Keys; use Keys; package body Api is procedure Send (Pk : in Public_Key) is begin null; end Send; end Api;",
        )
        .unwrap();
        fs::write(
            app_src.join("api.ads"),
            "with Keys; use Keys; package Api is procedure Send (Pk : in Public_Key); end Api;",
        )
        .unwrap();

        let args = GenerateHarnessArgs {
            source,
            target: Some("Send".to_owned()),
            target_line: None,
            output: temp.join("generated_harnesses"),
            id: Some("H-CTOR-DEP".to_owned()),
            kind: "direct".to_owned(),
            source_roots: vec![dep_src],
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };

        run(args).expect("harness generation finds the dependency constructor");

        let main = fs::read_to_string(temp.join("generated_harnesses/H-CTOR-DEP/main.adb"))
            .expect("generated main is readable");
        assert!(
            main.to_ascii_lowercase().contains("keys.construct"),
            "expected dep-spec Construct to be invoked, got:\n{main}",
        );
    }

    #[test]
    fn generate_harness_resolves_types_from_withed_source_roots() {
        let temp = temp_dir("with-source-root-types");
        let app_src = temp.join("app");
        let dep_src = temp.join("dep");
        fs::create_dir_all(&app_src).unwrap();
        fs::create_dir_all(&dep_src).unwrap();
        fs::write(
            dep_src.join("types.ads"),
            "package Types is subtype Byte is Integer range 0 .. 255; type Byte_Seq is array (Positive range <>) of Byte; end Types;",
        )
        .unwrap();
        let source = app_src.join("app.adb");
        fs::write(
            &source,
            "with Types; use Types; package body App is procedure Run (Data : in Byte_Seq) is begin null; end Run; end App;",
        )
        .unwrap();
        fs::write(
            app_src.join("app.ads"),
            "with Types; use Types; package App is procedure Run (Data : in Byte_Seq); end App;",
        )
        .unwrap();

        let args = GenerateHarnessArgs {
            source,
            target: Some("Run".to_owned()),
            target_line: None,
            output: temp.join("generated_harnesses"),
            id: Some("H-WITH-TYPES".to_owned()),
            kind: "direct".to_owned(),
            source_roots: vec![dep_src],
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };

        run(args).unwrap();

        let main = fs::read_to_string(temp.join("generated_harnesses/H-WITH-TYPES/main.adb"))
            .expect("generated main is readable");
        assert!(main.contains("function Decode_Data return Types.Byte_Seq is"));
    }

    #[test]
    fn generate_harness_resolves_parent_package_types_for_child_units() {
        let temp = temp_dir("child-parent-types");
        let src = temp.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(
            src.join("parent.ads"),
            "package Parent is type Thing is private; function Make return Thing; private type Thing is new Integer; end Parent;",
        )
        .unwrap();
        let source = src.join("parent-child.ads");
        fs::write(
            &source,
            "package Parent.Child is function Get return Thing; end Parent.Child;",
        )
        .unwrap();

        let args = GenerateHarnessArgs {
            source,
            target: Some("Get".to_owned()),
            target_line: None,
            output: temp.join("generated_harnesses"),
            id: Some("H-CHILD-PARENT".to_owned()),
            kind: "direct".to_owned(),
            source_roots: vec![src],
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };

        run(args).unwrap();

        let main = fs::read_to_string(temp.join("generated_harnesses/H-CHILD-PARENT/main.adb"))
            .expect("generated main is readable");
        assert!(main.contains("Gf_Result : constant Parent.Thing := Parent.Child.Get;"));
    }

    #[test]
    fn generate_c_harness_uses_nearby_compile_commands_flags() {
        let root = temp_dir("compile-db-c");
        let src = root.join("src");
        let include = root.join("include");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&include).unwrap();
        let source = src.join("parser.c");
        fs::write(
            &source,
            "int parse_packet(const unsigned char *data, unsigned long len) { return data && len ? 1 : 0; }\n",
        )
        .unwrap();
        fs::write(
            root.join("compile_commands.json"),
            format!(
                r#"[{{"directory":"{}","file":"{}","arguments":["gcc","-I","../include","-DLEGACY_MODE=1","-std=gnu11","-c","{}"]}}]"#,
                src.display(),
                source.display(),
                source.display()
            ),
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("parse_packet".to_owned()),
            target_line: None,
            output: root.join("out"),
            id: Some("H-CDB-C".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let makefile = fs::read_to_string(root.join("out/H-CDB-C/Makefile")).unwrap();
        assert!(makefile.contains("CC = gcc"));
        assert!(makefile.contains("-fsanitize-coverage=trace-pc,trace-cmp"));
        assert!(makefile.contains("COMPILE_DB_FLAGS ="));
        assert!(makefile.contains(&format!("-I {}", include.display())));
        assert!(makefile.contains("-DLEGACY_MODE=1"));
        assert!(makefile.contains("-std=gnu11"));
        if std::process::Command::new("gcc")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            let status = std::process::Command::new("make")
                .arg("-C")
                .arg(root.join("out/H-CDB-C"))
                .arg("main")
                .status()
                .unwrap();
            assert!(status.success(), "native GCC C harness must link");
        }
    }

    #[test]
    fn generate_c_harness_resolves_struct_types_from_compile_database_include_dir() {
        let root = temp_dir("compile-db-c-types");
        let src = root.join("src");
        let headers = root.join("headers/public");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&headers).unwrap();
        let source = src.join("parser.c");
        fs::write(
            headers.join("api.h"),
            "struct config { int count; const char *name; };\n\
             int run(struct config cfg);\n",
        )
        .unwrap();
        fs::write(
            &source,
            "#include \"api.h\"\n\
             int run(struct config cfg) { return cfg.count + (cfg.name != 0); }\n",
        )
        .unwrap();
        fs::write(
            root.join("compile_commands.json"),
            format!(
                r#"[{{"directory":"{}","file":"{}","arguments":["cc","-I","../headers/public","-c","{}"]}}]"#,
                src.display(),
                source.display(),
                source.display()
            ),
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("run".to_owned()),
            target_line: None,
            output: root.join("out"),
            id: Some("H-CDB-TYPES".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let main = fs::read_to_string(root.join("out/H-CDB-TYPES/main.c")).unwrap();
        assert!(main.contains("struct config cfg"));
        assert!(main.contains("cfg.count = gf_i32(&Cur)"));
        assert!(main.contains("cfg.name = gf_c_string(&Cur, 256)"));
        assert!(main.contains("free((void *)cfg.name)"));
    }

    #[test]
    fn generate_c_direct_harness_includes_static_target_source() {
        let root = temp_dir("c-static-direct-target");
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        let source = src.join("internal.c");
        fs::write(
            &source,
            "#include <stddef.h>\n\
             static int hidden_parse(const unsigned char *data, size_t len) {\n\
                 return data ? (int)len : 0;\n\
             }\n",
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("hidden_parse".to_owned()),
            target_line: None,
            output: root.join("out"),
            id: Some("H-C-STATIC-DIRECT".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let main = fs::read_to_string(root.join("out/H-C-STATIC-DIRECT/main.c")).unwrap();
        assert!(
            main.contains("#include \"internal.c\""),
            "static targets need the defining source included into main.c:\n{main}"
        );
        assert!(
            !main.contains("extern int hidden_parse"),
            "included static target should not also get an external prototype:\n{main}"
        );

        let makefile = fs::read_to_string(root.join("out/H-C-STATIC-DIRECT/Makefile")).unwrap();
        assert!(
            !makefile.contains(&source.display().to_string()),
            "static target source should not be linked as a separate translation unit:\n{makefile}"
        );
    }

    #[test]
    fn generate_c_direct_harness_keeps_header_typedefs_when_including_main_tu() {
        // redis sds.c defines a local `main`, so direct generation includes the
        // whole source TU instead of linking it. The type/lifecycle context must
        // still be collected from the source's public header; otherwise
        // `typedef char *sds` is lost, the first sds parameter decodes as a raw
        // char* string, and sds accessors read before the buffer.
        let root = temp_dir("c-main-tu-sds");
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(
            src.join("sds.h"),
            "typedef char *sds;\n\
             sds sdsempty(void);\n\
             void sdsfree(sds s);\n\
             unsigned long sdsAllocSize(sds s);\n\
             void *sdsAllocPtr(sds s);\n\
             sds sdscatlen(sds s, const void *t, unsigned long len);\n",
        )
        .unwrap();
        let source = src.join("sds.c");
        fs::write(
            &source,
            "#include \"sds.h\"\n\
             sds sdsempty(void) { return (sds)0; }\n\
             void sdsfree(sds s) { (void)s; }\n\
             unsigned long sdsAllocSize(sds s) { (void)s; return 0; }\n\
             void *sdsAllocPtr(sds s) { return (void *)s; }\n\
             sds sdscatlen(sds s, const void *t, unsigned long len) { (void)t; (void)len; return s; }\n\
             int main(void) { return 0; }\n",
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("sdscatlen".to_owned()),
            target_line: None,
            output: root.join("out"),
            id: Some("H-SDS-MAIN-TU".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let main = fs::read_to_string(root.join("out/H-SDS-MAIN-TU/main.c")).unwrap();
        assert!(
            main.contains("sds s = sdsempty()"),
            "sds input handle must be constructed via lifecycle, not raw bytes:\n{main}"
        );
        assert!(
            main.contains("if (R) sdsfree(R)"),
            "self-returning sds builder must free the live return value:\n{main}"
        );
        assert!(
            !main.contains("char *s = gf_c_string"),
            "sds must not decode as a raw C string:\n{main}"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn generate_c_sequence_harness_models_handle_lifecycle_functions() {
        let root = temp_dir("c-sequence-lifecycle");
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        let header = src.join("session.h");
        let source = src.join("session.c");
        fs::write(
            &header,
            "struct session { int seed; int total; };\n\
             int session_init(struct session *s, int seed);\n\
             int session_step(struct session *s, int delta);\n\
             int session_reset(struct session *s);\n\
             void session_end(struct session *s);\n",
        )
        .unwrap();
        fs::write(
            &source,
            "#include \"session.h\"\n\
             int session_init(struct session *s, int seed) { s->seed = seed; return 0; }\n\
             int session_step(struct session *s, int delta) { s->total += delta; return s->total; }\n\
             int session_reset(struct session *s) { s->total = 0; return 0; }\n\
             void session_end(struct session *s) { s->seed = 0; }\n",
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("session_step".to_owned()),
            target_line: None,
            output: root.join("out"),
            id: Some("H-CSEQ".to_owned()),
            kind: "sequence".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let main = fs::read_to_string(root.join("out/H-CSEQ/main.c")).unwrap();
        assert!(main.contains("struct session _gf_handle"));
        assert!(main.contains("session_init(&_gf_handle"));
        assert!(main.contains("session_step(&_gf_handle"));
        assert!(main.contains("session_reset(&_gf_handle"));
        assert!(main.contains("session_end(&_gf_handle"));
        assert!(main.contains("_gf_lifecycle_count"));

        let makefile = fs::read_to_string(root.join("out/H-CSEQ/Makefile")).unwrap();
        assert!(
            makefile.contains(&source.display().to_string()),
            "Makefile should link the project source: {makefile}"
        );

        if std::process::Command::new("clang")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping generated C sequence compile: clang not on PATH");
            return;
        }
        let obj = root.join("sequence_main.o");
        let output = std::process::Command::new("clang")
            .arg("-std=c99")
            .arg("-I")
            .arg(&src)
            .arg("-I")
            .arg(locate_c_runtime())
            .arg("-c")
            .arg(root.join("out/H-CSEQ/main.c"))
            .arg("-o")
            .arg(&obj)
            .output()
            .expect("spawn clang");
        assert!(
            output.status.success(),
            "clang failed\nstdout:\n{}\nstderr:\n{}\nmain.c:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            main
        );
    }

    #[test]
    fn generate_c_sequence_harness_excludes_static_same_handle_helpers() {
        let root = temp_dir("c-sequence-static-helper");
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        let header = src.join("session.h");
        let source = src.join("session.c");
        fs::write(
            &header,
            "struct session { int seed; int total; };\n\
             int session_init(struct session *s, int seed);\n\
             int session_step(struct session *s, int delta);\n\
             void session_end(struct session *s);\n",
        )
        .unwrap();
        fs::write(
            &source,
            "#include \"session.h\"\n\
             #define MZ_FORCEINLINE __inline__ __attribute__((__always_inline__))\n\
             struct hidden_state { int value; };\n\
             static MZ_FORCEINLINE void session_private_reset(struct session *s, struct hidden_state *h) { s->total = h->value; }\n\
             int session_init(struct session *s, int seed) { s->seed = seed; return 0; }\n\
             int session_step(struct session *s, int delta) { s->total += delta; return s->total; }\n\
             void session_end(struct session *s) { s->seed = 0; }\n",
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("session_step".to_owned()),
            target_line: None,
            output: root.join("out"),
            id: Some("H-CSEQ-STATIC".to_owned()),
            kind: "sequence".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let main = fs::read_to_string(root.join("out/H-CSEQ-STATIC/main.c")).unwrap();
        assert!(main.contains("session_step(&_gf_handle"));
        assert!(
            !main.contains("session_private_reset"),
            "static helper must not be part of external lifecycle sequence:\n{main}"
        );
    }

    #[test]
    fn generate_c_sequence_harness_includes_static_init_end_source() {
        let root = temp_dir("c-sequence-static-lifecycle");
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        let header = src.join("session.h");
        let source = src.join("session.c");
        fs::write(
            &header,
            "#pragma once\n\
             struct session { int seed; int total; };\n\
             int session_step(struct session *s, int delta);\n",
        )
        .unwrap();
        fs::write(
            &source,
            "#include \"session.h\"\n\
             static int session_init(struct session *s, int seed) { s->seed = seed; s->total = 0; return 0; }\n\
             int session_step(struct session *s, int delta) { s->total += delta; return s->total; }\n\
             static void session_end(struct session *s) { s->seed = 0; }\n",
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("session_step".to_owned()),
            target_line: None,
            output: root.join("out"),
            id: Some("H-CSEQ-STATIC-LIFE".to_owned()),
            kind: "sequence".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let main = fs::read_to_string(root.join("out/H-CSEQ-STATIC-LIFE/main.c")).unwrap();
        assert!(
            main.contains("#include \"session.c\""),
            "static lifecycle helpers need the defining source included into main.c:\n{main}"
        );
        assert!(main.contains("session_init(&_gf_handle"));
        assert!(main.contains("session_step(&_gf_handle"));
        assert!(main.contains("session_end(&_gf_handle"));
        assert!(
            !main.contains("extern int session_init"),
            "included static init should not also get an external prototype:\n{main}"
        );
        assert!(
            !main.contains("extern void session_end"),
            "included static end should not also get an external prototype:\n{main}"
        );

        let makefile = fs::read_to_string(root.join("out/H-CSEQ-STATIC-LIFE/Makefile")).unwrap();
        assert!(
            !makefile.contains(&source.display().to_string()),
            "static lifecycle source should not be linked as a separate translation unit:\n{makefile}"
        );
    }

    #[test]
    fn generate_cpp_harness_uses_compile_commands_command_string() {
        let root = temp_dir("compile-db-cpp");
        let src = root.join("src");
        let third_party = root.join("third_party/include");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&third_party).unwrap();
        let source = src.join("parser.cpp");
        fs::write(
            &source,
            "#include <string>\nint parse_packet(const std::string &input) { return (int)input.size(); }\n",
        )
        .unwrap();
        fs::write(
            root.join("compile_commands.json"),
            format!(
                r#"[{{"directory":"{}","file":"{}","command":"clang++ --gcc-install-dir=/usr/lib/gcc/x86_64-linux-gnu/13 -isystem ../third_party/include -DCPP_LEGACY=1 -std=gnu++20 -c {}" }}]"#,
                src.display(),
                source.display(),
                source.display()
            ),
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("parse_packet".to_owned()),
            target_line: None,
            output: root.join("out"),
            id: Some("H-CDB-CPP".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let makefile = fs::read_to_string(root.join("out/H-CDB-CPP/Makefile")).unwrap();
        assert!(makefile.contains("CXX = clang++"));
        assert!(makefile.contains("COMPILE_DB_FLAGS ="));
        assert!(makefile.contains(&format!("-isystem {}", third_party.display())));
        assert!(makefile.contains("-DCPP_LEGACY=1"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));
        let recovered_flags = makefile
            .lines()
            .find(|line| line.starts_with("COMPILE_DB_FLAGS ="))
            .unwrap();
        assert!(
            !recovered_flags.contains("-std="),
            "recovered standard must not override CXX_STD retries: {recovered_flags}"
        );
        assert!(makefile.contains("--gcc-install-dir=/usr/lib/gcc/x86_64-linux-gnu/13"));
    }

    #[test]
    fn cpp_build_context_extracts_last_standard_into_single_control() {
        let context = CppBuildContext {
            provenance: "test".to_owned(),
            confidence: "high".to_owned(),
            compile_flags: vec![
                "-std=gnu++17".to_owned(),
                "-DKEEP=1".to_owned(),
                "-std=c++14".to_owned(),
            ],
            link_flags: Vec::new(),
            extra_sources: Vec::new(),
            recovery: Vec::new(),
        };
        let encoded = context.encoded_flags();
        assert!(encoded.contains(&"-DKEEP=1".to_owned()));
        assert!(encoded.contains(&"@govfuzz-build-context-cxx-standard=c++14".to_owned()));
        assert!(!encoded.iter().any(|flag| flag.starts_with("-std=")));
    }

    #[test]
    fn cpp_header_inherits_directly_including_translation_unit_command() {
        let root = temp_dir("compile-db-header-owner");
        let src = root.join("src");
        let include = root.join("include");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&include).unwrap();
        let header = include.join("legacy.hpp");
        let forced = include.join("forced.hpp");
        let owner = src.join("owner.cpp");
        fs::write(&forced, "#define FORCED_VALUE 7\n").unwrap();
        fs::write(
            &header,
            "#ifndef OWNER_FEATURE\n#error owner feature missing\n#endif\n#ifndef FORCED_VALUE\n#error forced include missing\n#endif\ninline int parse_legacy(const char *text) { return text ? FORCED_VALUE : 0; }\n",
        )
        .unwrap();
        fs::write(&owner, "#include <legacy.hpp>\n").unwrap();
        fs::write(
            root.join("compile_commands.json"),
            format!(
                r#"[{{"directory":"{}","file":"{}","arguments":["g++","-I","../include","-DOWNER_FEATURE=1","-include","../include/forced.hpp","-std=gnu++17","-c","{}"]}}]"#,
                src.display(),
                owner.display(),
                owner.display()
            ),
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: header.clone(),
            target: Some("parse_legacy".to_owned()),
            target_line: None,
            output: root.join("out"),
            id: Some("H-X-HEADER-OWNER".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let makefile = fs::read_to_string(root.join("out/H-X-HEADER-OWNER/Makefile")).unwrap();
        assert!(makefile.contains("CXX = g++"));
        assert!(makefile.contains("-fsanitize-coverage=trace-pc,trace-cmp"));
        assert!(makefile.contains(&format!("-I {}", include.display())));
        assert!(makefile.contains("-DOWNER_FEATURE=1"));
        assert!(makefile.contains(&format!("-include {}", forced.display())));
        assert!(makefile.contains("CXX_STD ?= gnu++17"));

        if std::process::Command::new("g++")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            let make_status = std::process::Command::new("make")
                .arg("-C")
                .arg(root.join("out/H-X-HEADER-OWNER"))
                .arg("main")
                .status()
                .unwrap();
            assert!(
                make_status.success(),
                "native GCC-family C++ harness must link with trace-pc"
            );
            let status = std::process::Command::new("g++")
                .arg("-std=gnu++17")
                .arg("-DOWNER_FEATURE=1")
                .arg("-include")
                .arg(&forced)
                .arg("-I")
                .arg(&include)
                .arg("-DGOVFUZZ_EXTERNAL_DRIVER")
                .arg("-I")
                .arg(locate_c_runtime())
                .arg("-c")
                .arg(root.join("out/H-X-HEADER-OWNER/main.cpp"))
                .arg("-o")
                .arg(root.join("header-owner.o"))
                .status()
                .unwrap();
            assert!(status.success(), "associated header command must compile");
        }
    }

    #[test]
    fn cpp_build_compiles_each_translation_unit_with_its_own_database_flags() {
        if std::process::Command::new("g++")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping per-TU context test: g++ not on PATH");
            return;
        }
        let root = temp_dir("cpp-per-tu-build-context");
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        let header = src.join("api.hpp");
        let support = src.join("support.cpp");
        let parser = src.join("parser.cpp");
        fs::write(
            &header,
            "#pragma once\nint support_value(void);\nint parse_packet(const char *data);\n",
        )
        .unwrap();
        fs::write(
            &support,
            "#include \"api.hpp\"\n#ifndef MODE_SUPPORT\n#error support TU lost its private define\n#endif\n#ifdef MODE_PARSER\n#error parser-only define leaked into support TU\n#endif\nint support_value(void) { return 7; }\n",
        )
        .unwrap();
        fs::write(
            &parser,
            "#include \"api.hpp\"\n#ifndef MODE_PARSER\n#error parser TU lost its private define\n#endif\n#ifdef MODE_SUPPORT\n#error support-only define leaked into parser TU\n#endif\nint parse_packet(const char *data) { return data ? support_value() : 0; }\n",
        )
        .unwrap();
        fs::write(
            root.join("CMakeLists.txt"),
            "cmake_minimum_required(VERSION 3.10)\nproject(per_tu CXX)\nadd_library(per_tu src/parser.cpp src/support.cpp)\n",
        )
        .unwrap();
        fs::write(
            root.join("compile_commands.json"),
            format!(
                r#"[
{{"directory":"{}","file":"{}","arguments":["g++","-I",".","-DMODE_PARSER=1","-std=c++14","-c","{}"]}},
{{"directory":"{}","file":"{}","arguments":["g++","-I",".","-DMODE_SUPPORT=1","-std=c++17","-c","{}"]}}
]"#,
                src.display(),
                parser.display(),
                parser.display(),
                src.display(),
                support.display(),
                support.display()
            ),
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: parser,
            target: Some("parse_packet".to_owned()),
            target_line: None,
            output: root.join("out"),
            id: Some("H-CPP-PER-TU".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let harness = root.join("out/H-CPP-PER-TU");
        let fragment = fs::read_to_string(harness.join("build_context_objects.mk")).unwrap();
        assert!(fragment.contains("BUILD_CONTEXT_TU_MODE = per_translation_unit"));
        assert!(fragment.contains("-DMODE_PARSER=1"), "{fragment}");
        assert!(fragment.contains("-DMODE_SUPPORT=1"), "{fragment}");
        let status = std::process::Command::new("make")
            .arg("-C")
            .arg(&harness)
            .status()
            .unwrap();
        assert!(
            status.success() && harness.join("main").is_file(),
            "the default goal must compile and link the per-TU flag graph"
        );
    }

    #[test]
    fn cpp_header_preflight_selects_a_compiling_umbrella() {
        if std::process::Command::new("clang++")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping header preflight test: clang++ not on PATH");
            return;
        }
        let root = temp_dir("cpp-header-umbrella-preflight");
        let include = root.join("include");
        fs::create_dir_all(&include).unwrap();
        let child = include.join("legacy_child.hpp");
        fs::write(
            &child,
            "#ifndef LEGACY_UMBRELLA_ACTIVE\n#error include legacy_api.hpp instead of this internal header directly\n#endif\ninline int parse_legacy(const char *p) { return p ? 1 : 0; }\n",
        )
        .unwrap();
        fs::write(
            include.join("legacy_api.hpp"),
            "#pragma once\n#define LEGACY_UMBRELLA_ACTIVE 1\n#include \"legacy_child.hpp\"\n",
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: child,
            target: Some("parse_legacy".to_owned()),
            target_line: None,
            output: root.join("out"),
            id: Some("H-CPP-UMBRELLA".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let main = fs::read_to_string(root.join("out/H-CPP-UMBRELLA/main.cpp")).unwrap();
        assert!(main.contains("#include \"legacy_api.hpp\""), "{main}");
        assert!(!main.contains("#include \"legacy_child.hpp\""), "{main}");
    }

    #[test]
    fn cpp_header_preflight_uses_harness_prelude_and_stdlib_recovery() {
        if std::process::Command::new("clang++")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping header preflight test: clang++ not on PATH");
            return;
        }
        let root = temp_dir("cpp-header-prelude-preflight");
        let header = root.join("legacy.hpp");
        fs::write(
            &header,
            "#pragma once\n#include <string>\ninline long parse(const std::string &s) { return s.empty() ? std::numeric_limits<long>::min() : (long)std::size_t{1}; }\n",
        )
        .unwrap();

        let result = preflight_header_includes(
            &["legacy.hpp".to_owned()],
            std::slice::from_ref(&root),
            &[],
            true,
        );
        assert_eq!(result, HeaderPreflight::Passed, "{result:?}");
    }

    #[test]
    fn owner_translation_unit_only_header_is_rejected_before_harness_build() {
        if std::process::Command::new("clang++")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping header preflight test: clang++ not on PATH");
            return;
        }
        let root = temp_dir("cpp-header-owner-only-preflight");
        let header = root.join("owner_fragment.hpp");
        fs::write(
            &header,
            "inline int parse_owner_fragment(void) { return (int)sizeof(OwnerEstablishedType); }\n",
        )
        .unwrap();
        fs::write(
            root.join("owner.cpp"),
            "struct OwnerEstablishedType { int value; };\n#include \"owner_fragment.hpp\"\n",
        )
        .unwrap();

        let error = run(GenerateHarnessArgs {
            source: header,
            target: Some("parse_owner_fragment".to_owned()),
            target_line: None,
            output: root.join("out"),
            id: Some("H-CPP-OWNER-ONLY".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap_err()
        .to_string();
        assert!(
            error.contains(BLOCKED_BY_NON_SELF_CONTAINED_HEADER),
            "{error}"
        );
        assert!(!root.join("out/H-CPP-OWNER-ONLY/main.cpp").exists());
    }

    #[test]
    fn generate_cpp_harness_infers_cmake_flags_sources_libraries_and_provenance() {
        let root = temp_dir("cmake-cpp-context");
        let src = root.join("src");
        let include = root.join("include");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&include).unwrap();
        let source = src.join("parser.cpp");
        let support = src.join("support.cpp");
        fs::write(
            &source,
            "#include \"parser.hpp\"\n#include <string_view>\nint parse_packet(std::string_view input) { return helper(input); }\n",
        )
        .unwrap();
        fs::write(&support, "#include <string_view>\nint helper(std::string_view input) { return (int)input.size(); }\n").unwrap();
        fs::write(include.join("parser.hpp"), "#include <string_view>\nint helper(std::string_view input);\nint parse_packet(std::string_view input);\n").unwrap();
        fs::write(
            root.join("CMakeLists.txt"),
            r#"
            cmake_minimum_required(VERSION 3.16)
            project(LegacyParser CXX)
            set(CMAKE_CXX_STANDARD 20)
            include_directories(include)
            add_definitions(-DLEGACY_MODE=1)
            add_library(legacy src/parser.cpp src/support.cpp)
            target_link_libraries(legacy z pthread)
            "#,
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("parse_packet".to_owned()),
            target_line: None,
            output: root.join("out"),
            id: Some("H-CMAKE-CPP".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let makefile = fs::read_to_string(root.join("out/H-CMAKE-CPP/Makefile")).unwrap();
        assert!(makefile.contains("BUILD_CONTEXT_PROVENANCE = cmake"));
        assert!(makefile.contains("BUILD_CONTEXT_CONFIDENCE = medium"));
        assert!(makefile.contains(&format!("-I {}", include.display())));
        assert!(makefile.contains("-DLEGACY_MODE=1"));
        assert!(makefile.contains("CXX_STD ?= c++20"));
        assert!(!makefile.contains("COMPILE_DB_FLAGS = -std="));
        assert!(makefile.contains(support.to_str().unwrap()));
        assert!(makefile.contains("BUILD_CONTEXT_LDFLAGS = -lz -pthread"));
    }

    #[test]
    fn infer_cmake_build_context_drops_dynamic_definition_flags() {
        // FlatBuffers' CMakeLists has
        // `add_definitions(-DFLATBUFFERS_MAX_PARSING_DEPTH=${FLATBUFFERS_MAX_PARSING_DEPTH})`
        // inside an `if(DEFINED ...)` guard. The unexpanded `${VAR}` must be
        // dropped from auto-detected flags — carrying it forward trips the
        // build-safety metacharacter check and blocks every harness in the tree.
        let root = temp_dir("cmake-dynamic-define");
        let cmake = root.join("CMakeLists.txt");
        fs::write(
            &cmake,
            "add_definitions(-DSTATIC_OK=1 -DMAXDEPTH=${MAXDEPTH})\n\
             target_compile_definitions(lib PRIVATE GEN=$<CONFIG>)\n",
        )
        .unwrap();
        let ctx = infer_cmake_build_context(&root.join("src/x.cpp"), &cmake);
        assert!(
            ctx.compile_flags.iter().any(|f| f == "-DSTATIC_OK=1"),
            "static define kept: {:?}",
            ctx.compile_flags
        );
        assert!(
            !ctx.compile_flags
                .iter()
                .any(|f| f.contains("${") || f.contains("$<") || f.contains("$(")),
            "dynamic defines must be dropped, got: {:?}",
            ctx.compile_flags
        );
    }

    #[test]
    fn c_build_flags_infer_portable_cmake_capabilities_without_a_database() {
        let root = temp_dir("cmake-c-global-definitions");
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        let source = src.join("parser.c");
        fs::write(&source, "int parse(void) { return 0; }\n").unwrap();
        fs::write(
            root.join("CMakeLists.txt"),
            "string(REGEX REPLACE \"^.*\\n#define MAJOR ([0-9]+)\\n.*$\" \"\\\\1\" VERSION \"${HEADER}\")\n\
             add_compile_definitions(HAVE_STDBOOL_H HAVE__BOOL PACKAGE_NAME=legacy)\n\
             add_library(legacy src/parser.c)\n",
        )
        .unwrap();

        let flags = c_build_flags_for_source(&source);
        for expected in ["-DHAVE_STDBOOL_H", "-DHAVE__BOOL"] {
            assert!(
                flags.iter().any(|flag| flag == expected),
                "missing {expected}: {flags:?}"
            );
        }
        assert!(
            !flags.iter().any(|flag| flag.contains("PACKAGE_NAME")),
            "project metadata/features require an authoritative compile DB: {flags:?}"
        );
    }

    #[test]
    fn c_build_flags_materialize_checked_host_struct_capabilities_from_project_root() {
        let root = temp_dir("cmake-c-checked-host-capabilities");
        let src = root.join("src/lib");
        fs::create_dir_all(&src).unwrap();
        let source = src.join("resolver.c");
        fs::write(&source, "int resolve(void) { return 0; }\n").unwrap();
        fs::write(
            src.join("CMakeLists.txt"),
            "add_library(resolver resolver.c)\n",
        )
        .unwrap();
        fs::write(
            root.join("CMakeLists.txt"),
            "check_include_files(stdint.h HAVE_STDINT_H)\n\
             check_include_files(sys/socket.h HAVE_SYS_SOCKET_H)\n\
             check_include_files(netinet/in.h HAVE_NETINET_IN_H)\n\
             check_include_files(errno.h HAVE_ERRNO_H)\n\
             check_symbol_exists (AF_INET6 x HAVE_AF_INET6)\n\
             check_symbol_exists (PF_INET6 x HAVE_PF_INET6)\n\
             check_symbol_exists (gettimeofday x HAVE_GETTIMEOFDAY)\n\
             check_type_exists(socklen_t HAVE_SOCKLEN_T)\n\
             check_type_exists(\"struct addrinfo\" HAVE_STRUCT_ADDRINFO)\n\
             check_type_exists(\"struct timeval\" HAVE_STRUCT_TIMEVAL)\n\
             check_type_exists(\"struct sockaddr_in6\" HAVE_STRUCT_SOCKADDR_IN6)\n\
             check_struct_has_member(\"struct sockaddr_in6\" sin6_scope_id x HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID)\n",
        )
        .unwrap();

        let flags = c_build_flags_for_source(&source);
        assert!(
            flags.iter().any(|flag| flag == "-DHAVE_STDINT_H"),
            "{flags:?}"
        );
        if cfg!(unix) {
            for expected in [
                "-DHAVE_SYS_SOCKET_H",
                "-DHAVE_NETINET_IN_H",
                "-DHAVE_ERRNO_H",
                "-DHAVE_AF_INET6",
                "-DHAVE_PF_INET6",
                "-DHAVE_GETTIMEOFDAY",
                "-DHAVE_SOCKLEN_T",
                "-DHAVE_STRUCT_ADDRINFO",
                "-DHAVE_STRUCT_TIMEVAL",
                "-DHAVE_STRUCT_SOCKADDR_IN6",
                "-DHAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID",
            ] {
                assert!(
                    flags.iter().any(|flag| flag == expected),
                    "missing {expected}: {flags:?}"
                );
            }
        }
    }

    #[test]
    fn c_build_flags_materialize_prefixed_host_capabilities_from_cmake_template() {
        let root = temp_dir("cmake-prefixed-config-capabilities");
        let source = root.join("evutil_time.c");
        fs::write(&source, "int clock_now(void) { return 0; }\n").unwrap();
        fs::write(
            root.join("CMakeLists.txt"),
            "add_library(event evutil_time.c)\n",
        )
        .unwrap();
        fs::write(
            root.join("event-config.h.cmake"),
            "#cmakedefine EVENT__HAVE_GETTIMEOFDAY 1\n\
             #cmakedefine EVENT__HAVE_STDLIB_H 1\n\
             #cmakedefine EVENT__HAVE_ARC4RANDOM_BUF 1\n\
             #cmakedefine EVENT__HAVE_SYS_SIGNALFD_H 1\n\
             #cmakedefine EVENT__HAVE_UINT64_T 1\n\
             #cmakedefine EVENT__HAVE_STRUCT_IN6_ADDR 1\n\
             #define EVENT__SIZEOF_SIZE_T @EVENT__SIZEOF_SIZE_T@\n\
             #define EVENT__SIZEOF_VOID_P @EVENT__SIZEOF_VOID_P@\n\
             #cmakedefine EVENT__ENABLE_OPENSSL 1\n",
        )
        .unwrap();

        let flags = c_build_flags_for_source(&source);
        if cfg!(unix) {
            for expected in [
                "-DEVENT__HAVE_GETTIMEOFDAY",
                "-DEVENT__HAVE_STDLIB_H",
                "-DEVENT__HAVE_ARC4RANDOM_BUF",
                "-DEVENT__HAVE_SYS_SIGNALFD_H",
            ] {
                assert!(
                    flags.iter().any(|flag| flag == expected),
                    "missing {expected}: {flags:?}"
                );
            }
        }
        assert!(
            !flags.iter().any(|flag| flag.contains("ENABLE_OPENSSL")),
            "optional features must remain unset: {flags:?}"
        );
        for expected in [
            "-DEVENT__HAVE_UINT64_T".to_owned(),
            format!("-DEVENT__SIZEOF_SIZE_T={}", std::mem::size_of::<usize>()),
            format!(
                "-DEVENT__SIZEOF_VOID_P={}",
                std::mem::size_of::<*const ()>()
            ),
        ] {
            assert!(
                flags.iter().any(|flag| flag == &expected),
                "missing {expected}: {flags:?}"
            );
        }
        if cfg!(unix) {
            assert!(
                flags
                    .iter()
                    .any(|flag| flag == "-DEVENT__HAVE_STRUCT_IN6_ADDR"),
                "missing Unix socket capability: {flags:?}"
            );
        }
    }

    #[test]
    fn c_build_flags_do_not_union_unowned_target_variants() {
        let root = temp_dir("cmake-c-unowned-targets");
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        let source = src.join("parser.c");
        fs::write(&source, "int parse(void) { return 0; }\n").unwrap();
        fs::write(
            root.join("CMakeLists.txt"),
            "set(LIB_SOURCES src/parser.c)\n\
             add_compile_definitions(GLOBAL_ABI=1)\n\
             add_library(core ${LIB_SOURCES})\n\
             target_compile_definitions(core PRIVATE CORE_POSIX=1)\n\
             target_compile_definitions(other PRIVATE CORE_WINDOWS=1)\n",
        )
        .unwrap();

        let flags =
            infer_cmake_c_build_context(&source, &root.join("CMakeLists.txt")).compile_flags;
        assert!(flags.iter().any(|flag| flag == "-DGLOBAL_ABI=1"));
        assert!(
            !flags
                .iter()
                .any(|flag| flag.contains("CORE_POSIX") || flag.contains("CORE_WINDOWS")),
            "unresolved ownership must not combine target variants: {flags:?}"
        );
    }

    #[test]
    fn infer_cmake_build_context_drops_std_module_toggle() {
        // magic_enum's CMakeLists sets `MAGIC_ENUM_USE_STD_MODULE` PRIVATE on a
        // dedicated C++23-module test target. Applied to the harness it switches
        // magic_enum to `import std;`, and a plain clang++ build (no precompiled
        // std module) then fails on `using std::optional;`. The toggle must be
        // dropped; a normal define alongside it survives.
        let root = temp_dir("cmake-std-module");
        let cmake = root.join("CMakeLists.txt");
        fs::write(
            &cmake,
            "target_compile_definitions(magic_enum_test PRIVATE MAGIC_ENUM_USE_STD_MODULE)\n\
             add_definitions(-DKEEP_ME=1)\n",
        )
        .unwrap();
        let ctx = infer_cmake_build_context(&root.join("include/magic_enum.hpp"), &cmake);
        assert!(
            !ctx.compile_flags
                .iter()
                .any(|f| f.contains("USE_STD_MODULE")),
            "the std-module toggle must be dropped: {:?}",
            ctx.compile_flags
        );
        assert!(
            ctx.compile_flags.iter().any(|f| f == "-DKEEP_ME=1"),
            "an ordinary define alongside it survives: {:?}",
            ctx.compile_flags
        );
        // Unit-level guard on the predicate.
        assert!(cmake_define_enables_std_module("MAGIC_ENUM_USE_STD_MODULE"));
        assert!(cmake_define_enables_std_module("-DFMT_USE_STD_MODULE=1"));
        assert!(!cmake_define_enables_std_module("-DMODULE_NAME=foo"));
    }

    #[test]
    fn infer_cmake_build_context_does_not_d_prefix_compile_flags_in_add_definitions() {
        // json11's CMakeLists wrongly puts a compile FLAG in add_definitions:
        // `add_definitions(-std=c++11)`. `-D`-prefixing it yields the invalid
        // `-D-std=c++11` ("macro name must be an identifier", a failed build). A
        // value that is already a flag (`-std=`/`-f`/`-W`) must pass through; a
        // bare macro name still gets `-D`.
        let root = temp_dir("cmake-flag-in-definitions");
        let cmake = root.join("CMakeLists.txt");
        fs::write(&cmake, "add_definitions(-std=c++11 -fno-rtti ENABLE_X)\n").unwrap();
        let ctx = infer_cmake_build_context(&root.join("src/x.cpp"), &cmake);
        assert!(
            ctx.compile_flags.iter().any(|f| f == "-std=c++11"),
            "compile flag must pass through un-prefixed: {:?}",
            ctx.compile_flags
        );
        assert!(
            !ctx.compile_flags.iter().any(|f| f.starts_with("-D-")),
            "no flag should be turned into an invalid -D macro: {:?}",
            ctx.compile_flags
        );
        assert!(
            ctx.compile_flags.iter().any(|f| f == "-DENABLE_X"),
            "a bare macro name still gets -D: {:?}",
            ctx.compile_flags
        );
    }

    #[test]
    fn infer_cmake_build_context_honors_default_branch_of_if_chain() {
        // libde265 gates its log-level defines on a CACHE variable that defaults
        // to "error". Unioning every mutually-exclusive `elseif` arm wrongly
        // enables DEBUG/TRACE logging — which references private members and fails
        // to compile, AND mismatches the prebuilt library's real (error-level)
        // symbols. Only the default-selected branch's defines must be collected.
        let root = temp_dir("cmake-if-chain");
        let cmake = root.join("CMakeLists.txt");
        fs::write(
            &cmake,
            r#"
            set(DE265_LOG_LEVEL "error" CACHE STRING "Log level")
            if (DE265_LOG_LEVEL MATCHES "error")
                target_compile_definitions(de265 PRIVATE DE265_LOG_ERROR)
            elseif (DE265_LOG_LEVEL MATCHES "info")
                target_compile_definitions(de265 PRIVATE DE265_LOG_ERROR DE265_LOG_INFO)
            elseif (DE265_LOG_LEVEL MATCHES "debug")
                target_compile_definitions(de265 PRIVATE DE265_LOG_ERROR DE265_LOG_INFO DE265_LOG_DEBUG)
            elseif (DE265_LOG_LEVEL MATCHES "trace")
                target_compile_definitions(de265 PRIVATE DE265_LOG_ERROR DE265_LOG_INFO DE265_LOG_DEBUG DE265_LOG_TRACE)
            endif()
            "#,
        )
        .unwrap();
        let ctx = infer_cmake_build_context(&root.join("src/x.cpp"), &cmake);
        assert!(
            ctx.compile_flags.iter().any(|f| f == "-DDE265_LOG_ERROR"),
            "default (error) branch define kept: {:?}",
            ctx.compile_flags
        );
        for dropped in ["-DDE265_LOG_INFO", "-DDE265_LOG_DEBUG", "-DDE265_LOG_TRACE"] {
            assert!(
                !ctx.compile_flags.iter().any(|f| f == dropped),
                "non-default branch define {dropped} must be pruned, got: {:?}",
                ctx.compile_flags
            );
        }
    }

    #[test]
    fn infer_cmake_build_context_prunes_foreign_platform_branch() {
        // A `if(WIN32)` definition block describes a build this host never runs;
        // collecting its defines (here a Windows-only macro) pollutes the harness
        // flags. The host-platform predicate must prune it while keeping the
        // `else()` (UNIX) branch.
        let root = temp_dir("cmake-platform-branch");
        let cmake = root.join("CMakeLists.txt");
        fs::write(
            &cmake,
            "if(WIN32)\n  add_definitions(-DUSE_WIN32_THREADS)\nelse()\n  add_definitions(-DUSE_PTHREADS)\nendif()\n",
        )
        .unwrap();
        let ctx = infer_cmake_build_context(&root.join("src/x.cpp"), &cmake);
        assert!(
            ctx.compile_flags.iter().any(|f| f == "-DUSE_PTHREADS"),
            "host (else/UNIX) branch kept: {:?}",
            ctx.compile_flags
        );
        assert!(
            !ctx.compile_flags.iter().any(|f| f == "-DUSE_WIN32_THREADS"),
            "WIN32 branch must be pruned on a host build: {:?}",
            ctx.compile_flags
        );
    }

    #[test]
    fn infer_cmake_build_context_prunes_qnx_socket_library_on_linux() {
        let root = temp_dir("cmake-qnx-branch");
        let cmake = root.join("CMakeLists.txt");
        fs::write(
            &cmake,
            "add_library(lib target.cpp)\nif(QNX)\n  target_link_libraries(lib -lsocket)\nendif()\n",
        )
        .unwrap();
        let source = root.join("target.cpp");
        fs::write(&source, "int target() { return 0; }\n").unwrap();

        let ctx = infer_cmake_build_context(&source, &cmake);
        assert!(
            !ctx.link_flags.iter().any(|flag| flag == "-lsocket"),
            "QNX-only socket library must be pruned: {:?}",
            ctx.link_flags
        );
    }

    #[test]
    fn infer_cmake_build_context_keeps_indeterminate_branch() {
        // When the controlling variable is unknown, we cannot prove the branch
        // dead — it must be KEPT (the pre-branch-aware union behavior), so we
        // never drop a define we might need.
        let root = temp_dir("cmake-indeterminate-branch");
        let cmake = root.join("CMakeLists.txt");
        fs::write(
            &cmake,
            "if(SOME_UNKNOWN_OPTION)\n  add_definitions(-DMAYBE_NEEDED=1)\nendif()\n",
        )
        .unwrap();
        let ctx = infer_cmake_build_context(&root.join("src/x.cpp"), &cmake);
        assert!(
            ctx.compile_flags.iter().any(|f| f == "-DMAYBE_NEEDED=1"),
            "indeterminate branch kept: {:?}",
            ctx.compile_flags
        );
    }

    #[test]
    fn infer_cmake_build_context_parses_multiline_target_sources() {
        // libE57Format lists its library sources in a multi-line
        // `target_sources( E57Format PRIVATE a.cpp \n b.cpp ... )`. A line-based
        // parse drops the whole command (and the library's real source list, so the
        // harness link is missing every sibling translation unit); the multi-line
        // parse must collect each sibling .cpp.
        let root = temp_dir("cmake-multiline");
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("a.cpp"), "int a(){return 0;}\n").unwrap();
        fs::write(src.join("b.cpp"), "int b(){return 0;}\n").unwrap();
        fs::write(src.join("target.cpp"), "int t(){return 0;}\n").unwrap();
        fs::write(src.join("target_test.cpp"), "int test_t(){return 0;}\n").unwrap();
        let cmake = src.join("CMakeLists.txt");
        fs::write(
            &cmake,
            "target_sources( Lib\n    PRIVATE\n        a.cpp\n        b.cpp\n        target.cpp\n)\n\
             target_sources( LibTests PRIVATE target_test.cpp )\n\
             target_compile_definitions(Lib PRIVATE LIB_MODE=1)\n\
             target_compile_definitions(LibTests PRIVATE TEST_MODE=1)\n",
        )
        .unwrap();
        let ctx = infer_cmake_build_context(&src.join("target.cpp"), &cmake);
        let names: Vec<String> = ctx
            .extra_sources
            .iter()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        assert!(
            names.contains(&"a.cpp".to_owned()) && names.contains(&"b.cpp".to_owned()),
            "multi-line target_sources siblings must be collected, got: {names:?}"
        );
        assert!(
            !names.contains(&"target_test.cpp".to_owned()),
            "sources from a different CMake target must be excluded: {names:?}"
        );
        assert!(ctx.compile_flags.iter().any(|flag| flag == "-DLIB_MODE=1"));
        assert!(!ctx.compile_flags.iter().any(|flag| flag == "-DTEST_MODE=1"));
    }

    #[test]
    fn infer_cmake_build_context_expands_known_definition_variable() {
        let root = temp_dir("cmake-known-definition-var");
        let source = root.join("hash.cpp");
        fs::write(&source, "int hash_value() { return 0; }\n").unwrap();
        let cmake = root.join("CMakeLists.txt");
        fs::write(
            &cmake,
            "set(PLATFORM_NAME LEVELDB_PLATFORM_POSIX)\n\
             target_sources(leveldb PRIVATE hash.cpp)\n\
             target_compile_definitions(leveldb PRIVATE ${PLATFORM_NAME}=1)\n",
        )
        .unwrap();

        let ctx = infer_cmake_build_context(&source, &cmake);
        assert!(
            ctx.compile_flags
                .iter()
                .any(|flag| flag == "-DLEVELDB_PLATFORM_POSIX=1"),
            "known CMake variable was not expanded: {:?}",
            ctx.compile_flags
        );
    }

    #[test]
    fn large_cmake_source_set_is_deferred_from_initial_harness() {
        let root = temp_dir("cmake-large-deferred");
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        let target = src.join("hash.cpp");
        fs::write(
            &target,
            "unsigned hash_bytes(const char *p, unsigned n) { return p ? n : 0; }\n",
        )
        .unwrap();
        let mut cmake = String::from("target_sources(Big PRIVATE src/hash.cpp\n");
        for index in 0..=super::MAX_EAGER_BUILD_CONTEXT_SOURCES {
            let name = format!("helper_{index}.cpp");
            fs::write(
                src.join(&name),
                format!("int helper_{index}() {{ return {index}; }}\n"),
            )
            .unwrap();
            cmake.push_str(&format!("  src/{name}\n"));
        }
        cmake.push_str(")\n");
        fs::write(root.join("CMakeLists.txt"), cmake).unwrap();

        run(GenerateHarnessArgs {
            source: target,
            target: Some("hash_bytes".to_owned()),
            target_line: None,
            output: root.join("out"),
            id: Some("H-CMAKE-DEFER".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let makefile = fs::read_to_string(root.join("out/H-CMAKE-DEFER/Makefile")).unwrap();
        assert!(
            !makefile.contains("helper_0.cpp"),
            "large inferred source set must be deferred until link recovery: {makefile}"
        );
    }

    #[test]
    fn generate_cpp_harness_infers_makefile_flags_sources_libraries_and_provenance() {
        let root = temp_dir("make-cpp-context");
        let src = root.join("src");
        let include = root.join("include");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&include).unwrap();
        let source = src.join("parser.cpp");
        let helper = src.join("helper.cpp");
        fs::write(&source, "#include \"parser.hpp\"\nint parse_packet(const char *data, size_t len) { return helper(data, len); }\n").unwrap();
        fs::write(&helper, "#include <stddef.h>\nint helper(const char *data, size_t len) { return data ? (int)len : 0; }\n").unwrap();
        fs::write(include.join("parser.hpp"), "#include <stddef.h>\nint helper(const char *data, size_t len);\nint parse_packet(const char *data, size_t len);\n").unwrap();
        fs::write(
            root.join("Makefile"),
            "CPPFLAGS += -Iinclude -DMAKE_MODE=1\nCXXFLAGS += -std=gnu++17\nLDLIBS += -lm\nSRCS = src/parser.cpp src/helper.cpp\n",
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("parse_packet".to_owned()),
            target_line: None,
            output: root.join("out"),
            id: Some("H-MAKE-CPP".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let makefile = fs::read_to_string(root.join("out/H-MAKE-CPP/Makefile")).unwrap();
        assert!(makefile.contains("BUILD_CONTEXT_PROVENANCE = make"));
        assert!(makefile.contains("BUILD_CONTEXT_CONFIDENCE = low"));
        assert!(makefile.contains(&format!("-I {}", include.display())));
        assert!(makefile.contains("-DMAKE_MODE=1"));
        assert!(makefile.contains("CXX_STD ?= gnu++17"));
        assert!(!makefile.contains("COMPILE_DB_FLAGS = -std="));
        assert!(makefile.contains(helper.to_str().unwrap()));
        assert!(makefile.contains("BUILD_CONTEXT_LDFLAGS = -lm"));
    }

    #[test]
    fn generate_cpp_harness_records_recovery_for_broken_cmake_sources() {
        let root = temp_dir("cmake-cpp-broken-context");
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        let source = src.join("parser.cpp");
        fs::write(
            &source,
            "#include <string_view>\nint parse_packet(std::string_view input) { return (int)input.size(); }\n",
        )
        .unwrap();
        fs::write(
            root.join("CMakeLists.txt"),
            "project(Broken CXX)\nadd_library(broken src/parser.cpp src/missing.cpp)\n",
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source,
            target: Some("parse_packet".to_owned()),
            target_line: None,
            output: root.join("out"),
            id: Some("H-CMAKE-BROKEN".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let makefile = fs::read_to_string(root.join("out/H-CMAKE-BROKEN/Makefile")).unwrap();
        assert!(makefile.contains("BUILD_CONTEXT_PROVENANCE = cmake"));
        assert!(
            makefile.contains("BUILD_CONTEXT_RECOVERY = skipped_missing_source:src/missing.cpp")
        );
    }

    #[test]
    fn generate_c_harness_for_simple_target() {
        let temp = temp_dir("c-harness");
        let source = temp.join("source.c");
        fs::write(
            &source,
            "int parse(const char *input, size_t len) { (void)input; (void)len; return 0; }",
        )
        .unwrap();

        let args = GenerateHarnessArgs {
            source: source.clone(),
            target: Some("parse".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-C001".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };

        run(args).unwrap();
        let main = fs::read_to_string(temp.join("out/H-C001/main.c")).unwrap();
        assert!(main.contains("LLVMFuzzerTestOneInput"));
        assert!(main.contains("parse(input, len)"));
        // #399: the generated C harness now ships its own persistent framed
        // fork-server driver `main` instead of relying on libFuzzer's `main`.
        assert!(main.contains("GOVFUZZ_FRAMED"));
        assert!(main.contains("int main("));
        let makefile = fs::read_to_string(temp.join("out/H-C001/Makefile")).unwrap();
        // Driver flags: trace-pc-guard coverage, and NOT libFuzzer's main.
        assert!(makefile.contains("-fsanitize-coverage=trace-pc-guard"));
        assert!(!makefile.contains("fsanitize=fuzzer"));
    }

    #[test]
    fn generate_c_harness_for_file_pointer_target() {
        let temp = temp_dir("c-file-harness");
        let source = temp.join("stream.c");
        fs::write(
            &source,
            "#include <stdio.h>\n\
             int parse_stream(FILE *stream) { return stream ? fgetc(stream) : 0; }\n",
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("parse_stream".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-CFILE".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let main = fs::read_to_string(temp.join("out/H-CFILE/main.c")).unwrap();
        assert!(main.contains("unsigned char *_gf_file_buf_stream"));
        assert!(main.contains("fmemopen(_gf_file_buf_stream, Size, \"r+\")"));
        assert!(main.contains("parse_stream(stream)"));
        assert!(main.contains("if (stream) fclose(stream);"));
        assert!(main.contains("free(_gf_file_buf_stream);"));
    }

    #[test]
    fn c_harness_excludes_a_transitively_pulled_cpp_header() {
        // libfixmath: `fix16.h` ends with `#ifdef __cplusplus / #include
        // "fix16.hpp"`. The include scanner doesn't evaluate the guard, so the C
        // harness pulled `fix16.hpp` (a `class`-bearing C++ header) into the C TU
        // -> "unknown type name 'class'". A C harness must not include a C++ header.
        let temp = temp_dir("c-cpp-header");
        fs::write(
            temp.join("fix.h"),
            "int fix_parse(const char *s);\n#ifdef __cplusplus\n#include \"fix.hpp\"\n#endif\n",
        )
        .unwrap();
        fs::write(temp.join("fix.hpp"), "class FixCpp { int x; };\n").unwrap();
        let source = temp.join("fix.c");
        fs::write(
            &source,
            "#include \"fix.h\"\nint fix_parse(const char *s) { return s ? s[0] : 0; }\n",
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("fix_parse".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-CHPP".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let main = fs::read_to_string(temp.join("out/H-CHPP/main.c")).unwrap();
        assert!(main.contains("#include \"fix.h\""), "C header kept: {main}");
        assert!(
            !main.contains("fix.hpp"),
            "C++ header must NOT be included in a C harness: {main}"
        );
        assert!(super::is_cpp_only_header("fix.hpp"));
        assert!(super::is_cpp_only_header("a/b.hh"));
        assert!(!super::is_cpp_only_header("fix.h"));
    }

    #[test]
    fn header_closure_excludes_compound_guarded_foreign_header() {
        let temp = temp_dir("c-compound-foreign-header");
        fs::write(
            temp.join("platform.h"),
            "#if (defined(__WIN32__) || defined(_WIN32)) && !defined(__CYGWIN__)\n\
             #include \"windows_impl.h\"\n\
             #else\n\
             #include \"posix_impl.h\"\n\
             #endif\n",
        )
        .unwrap();
        fs::write(
            temp.join("windows_impl.h"),
            "#ifndef WINDOWS_IMPL_H\n#define WINDOWS_IMPL_H\nint windows_only(void);\n#endif\n",
        )
        .unwrap();
        fs::write(
            temp.join("posix_impl.h"),
            "#ifndef POSIX_IMPL_H\n#define POSIX_IMPL_H\nint posix_only(void);\n#endif\n",
        )
        .unwrap();

        let includes = super::harness_project_includes(
            "#include \"platform.h\"\n",
            std::slice::from_ref(&temp),
        );
        assert!(includes.iter().any(|header| header == "platform.h"));
        assert!(includes.iter().any(|header| header == "posix_impl.h"));
        assert!(
            !includes.iter().any(|header| header == "windows_impl.h"),
            "Windows-only transitive header leaked into host closure: {includes:?}"
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn source_filter_accepts_compound_win32_guarded_system_header() {
        let temp = temp_dir("compound-foreign-source-filter");
        let source = temp.join("portable.c");
        fs::write(
            &source,
            "#if defined(_WIN32) && !defined(__CYGWIN__)\n\
             #include <windows.h>\n\
             #endif\n\
             int portable(void) { return 1; }\n",
        )
        .unwrap();

        assert!(
            !super::source_path_has_unconditional_foreign_platform_include(&source),
            "a positive Win32 guard remains foreign even with a negated Cygwin qualifier"
        );
    }

    #[test]
    fn generate_c_harness_for_standalone_void_pointer_target() {
        let temp = temp_dir("c-void-harness");
        let source = temp.join("opaque.c");
        fs::write(
            &source,
            "int parse_opaque(void *opaque) { return opaque != 0; }\n",
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("parse_opaque".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-CVOID".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let main = fs::read_to_string(temp.join("out/H-CVOID/main.c")).unwrap();
        assert!(main.contains("void * opaque = calloc(Size ? Size : 1, 1)"));
        assert!(main.contains("if (opaque && Size) memcpy(opaque, Data, Size)"));
        assert!(main.contains("parse_opaque(opaque)"));
        assert!(main.contains("free(opaque);"));
    }

    #[test]
    fn generate_c_harness_for_callback_typedef_target() {
        let temp = temp_dir("c-callback-harness");
        let source = temp.join("walk.c");
        fs::write(
            &source,
            "typedef int (*visit_cb)(void *opaque, const char *name);\n\
             int walk(visit_cb cb, void *opaque) { return cb ? cb(opaque, \"seed\") : 0; }\n",
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("walk".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-CCB".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let main = fs::read_to_string(temp.join("out/H-CCB/main.c")).unwrap();
        assert!(main.contains("static int _gf_cb_trampoline(void *opaque, const char *name)"));
        assert!(main.contains("visit_cb cb = (visit_cb)_gf_cb_trampoline;"));
        assert!(main.contains("walk(cb, opaque)"));
        assert!(main.contains("free(opaque);"));
    }

    #[test]
    fn target_parameter_class_registration_is_qualified_and_access_safe() {
        let infos = cpp_parser::parse_cpp_class_info(
            r#"
            namespace good {
            struct Options { int mode; };
            class Private { Private() = default; };
            class Deleted { public: Deleted() = delete; };
            class Abstract { public: virtual void run() = 0; };
            }
            namespace other { struct Options { Options(int); }; }
            "#,
        )
        .unwrap();
        let types = vec![
            "const good::Options &".to_owned(),
            "good::Options *".to_owned(),
            "const good::Private &".to_owned(),
            "good::Deleted".to_owned(),
            "good::Abstract &".to_owned(),
            "Options".to_owned(),
        ];
        let registered = cpp_default_constructible_parameter_classes(&types, &[], &infos);
        assert_eq!(registered, vec!["good::Options".to_owned()]);
    }

    #[test]
    fn cpp_user_constructed_parameter_classes_fail_during_generation_not_build() {
        // #99: a class with a public parameterized constructor (`explicit
        // Blocked(int)`) is NO LONGER blocked — it is built via that constructor
        // (see `cpp_opaque_parameter_built_via_resolved_constructor_and_factory`).
        // These four remain genuinely unsynthesizable: a deleted or private
        // constructor, and an abstract class have no public way to construct a
        // value; each must stop before build with a precise reason.
        for (case, declaration) in [
            ("deleted", "class Blocked { public: Blocked() = delete; };"),
            (
                "private",
                "class Blocked { private: Blocked() = default; };",
            ),
            (
                "abstract",
                "class Blocked { public: virtual void apply() = 0; };",
            ),
        ] {
            let temp = temp_dir(&format!("cpp-blocked-target-param-{case}"));
            let source = temp.join("parser.cpp");
            fs::write(
                &source,
                format!(
                    "namespace gov {{ {declaration} int parse(Blocked value) {{ return 0; }} }}\n"
                ),
            )
            .unwrap();

            let error = run(GenerateHarnessArgs {
                source: source.clone(),
                target: Some("parse".to_owned()),
                target_line: None,
                output: temp.join("out"),
                id: Some(format!("H-X-BLOCKED-{case}")),
                kind: "direct".to_owned(),
                source_roots: Vec::new(),
                project: None,
                source_trees: Vec::new(),
                extra_sources: Vec::new(),
                extra_includes: Vec::new(),
                cleanup: None,
                template_instantiate: Vec::new(),
                tree_type_defs: None,
                decoder_limits: Default::default(),
                force: false,
            })
            .expect_err("non-synthesizable class parameter must stop before build");
            assert!(
                error.to_string().contains("no byte-buffer decoder"),
                "{case}: unexpected error: {error:#}"
            );
            assert!(
                !temp
                    .join(format!("out/H-X-BLOCKED-{case}/main.cpp"))
                    .exists(),
                "{case}: an unsupported signature must not leave a build candidate"
            );
        }
    }

    #[test]
    fn cpp_explicit_public_default_parameter_uses_verified_neutral_construction() {
        let temp = temp_dir("cpp-explicit-default-target-param");
        let source = temp.join("parser.cpp");
        fs::write(
            &source,
            "namespace gov { class Options { public: Options() = default; int mode = 0; }; int parse(const Options &value) { return value.mode; } }\n",
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("parse".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-X-EXPLICIT-DEFAULT".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let main = fs::read_to_string(temp.join("out/H-X-EXPLICIT-DEFAULT/main.cpp")).unwrap();
        assert!(main.contains("Options value;"), "{main}");
        assert!(!main.contains("value.mode ="), "{main}");
        if std::process::Command::new("g++")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            let status = std::process::Command::new("g++")
                .arg("-std=gnu++20")
                .arg("-DGOVFUZZ_EXTERNAL_DRIVER")
                .arg("-I")
                .arg(locate_c_runtime())
                .arg("-iquote")
                .arg(&temp)
                .arg("-c")
                .arg(temp.join("out/H-X-EXPLICIT-DEFAULT/main.cpp"))
                .arg("-o")
                .arg(temp.join("explicit-default.o"))
                .status()
                .unwrap();
            assert!(status.success(), "verified public default must compile");
        }
    }

    /// #99: an opaque class parameter that is not default-constructible is built
    /// via a public parameterized constructor or a public static factory resolved
    /// from the declarations — across const-qualified values, references, aliases,
    /// and nested namespaces — while a genuinely opaque (incomplete/undeclared)
    /// type keeps its precise unsupported reason and leaves no build candidate.
    #[test]
    fn cpp_opaque_parameter_built_via_resolved_constructor_and_factory() {
        fn gen(tag: &str, source_text: &str, target: &str) -> anyhow::Result<String> {
            let temp = temp_dir(&format!("cpp-p99-{tag}"));
            let source = temp.join("parser.cpp");
            fs::write(&source, source_text).unwrap();
            run(GenerateHarnessArgs {
                source: source.clone(),
                target: Some(target.to_owned()),
                target_line: None,
                output: temp.join("out"),
                id: Some(format!("H-X-P99-{tag}")),
                kind: "direct".to_owned(),
                source_roots: Vec::new(),
                project: None,
                source_trees: Vec::new(),
                extra_sources: Vec::new(),
                extra_includes: Vec::new(),
                cleanup: None,
                template_instantiate: Vec::new(),
                tree_type_defs: None,
                decoder_limits: Default::default(),
                force: false,
            })?;
            Ok(fs::read_to_string(temp.join(format!("out/H-X-P99-{tag}/main.cpp"))).unwrap())
        }

        // 1) Public parameterized constructor, passed by const reference: the
        //    argument is decoded and the object direct-initialized.
        let ctor_ref = gen(
            "ctor-ref",
            "namespace gov { class Widget { public: explicit Widget(int); int poke() const; };\n\
             int use(const Widget& w) { return w.poke(); } }\n",
            "use",
        )
        .expect("parameterized-ctor parameter must generate");
        assert!(
            ctor_ref.contains("Widget w("),
            "const-ref ctor construction missing:\n{ctor_ref}"
        );

        // 2) Same class, const-qualified BY VALUE — the equivalent spelling takes
        //    the same construction path.
        let ctor_value = gen(
            "ctor-value",
            "namespace gov { class Widget { public: explicit Widget(int); int poke() const; };\n\
             int consume(const Widget w) { return w.poke(); } }\n",
            "consume",
        )
        .expect("const-by-value ctor parameter must generate");
        assert!(
            ctor_value.contains("Widget w("),
            "const-by-value ctor construction missing:\n{ctor_value}"
        );

        // 3) Public static by-value factory, no public default constructor.
        let factory = gen(
            "factory",
            "namespace gov { class Gadget { Gadget() {} public: static Gadget make() { return Gadget(); } int poke() const { return 1; } };\n\
             int use(const Gadget& g) { return g.poke(); } }\n",
            "use",
        )
        .expect("factory parameter must generate");
        assert!(
            factory.contains("Gadget g = ") && factory.contains("make()"),
            "static-factory construction missing:\n{factory}"
        );

        // 4) A project alias of a constructible class resolves to the underlying
        //    class and takes the same construction path.
        let alias = gen(
            "alias",
            "namespace gov { class Widget { public: explicit Widget(int); int poke() const; };\n\
             using WAlias = Widget;\n\
             int use(const WAlias& w) { return w.poke(); } }\n",
            "use",
        )
        .expect("aliased constructible parameter must generate");
        assert!(
            alias.contains("Widget w(") || alias.contains("WAlias w("),
            "aliased ctor construction missing:\n{alias}"
        );

        // 5) A nested namespace qualification is resolved.
        let nested = gen(
            "nested-ns",
            "namespace a { namespace b { class Thing { public: explicit Thing(int); int poke() const; }; } }\n\
             int use(const a::b::Thing& t) { return t.poke(); }\n",
            "use",
        )
        .expect("nested-namespace ctor parameter must generate");
        assert!(
            nested.contains("Thing t("),
            "nested-namespace ctor construction missing:\n{nested}"
        );

        // 6) An incomplete/undeclared type is genuinely opaque: no recipe, a
        //    precise unsupported reason, and no build candidate left behind.
        let incomplete = gen(
            "incomplete",
            "class Never;\nint use(const Never& n) { (void)&n; return 0; }\n",
            "use",
        );
        let error = incomplete.expect_err("an incomplete type must remain unsupported");
        assert!(
            error.to_string().contains("no byte-buffer decoder"),
            "incomplete type must report a precise reason: {error:#}"
        );
    }

    #[test]
    fn generate_cpp_direct_harness_default_constructs_target_class_parameter() {
        let temp = temp_dir("cpp-target-default-class-param");
        let source = temp.join("parser.cpp");
        fs::write(
            &source,
            r#"
            #include <string_view>
            namespace other { struct Options { bool wrong_field; }; }
            namespace gov {
            struct Options { int mode = 0; };
            int parse(std::string_view input, const Options &options) {
                return (int)input.size() + options.mode;
            }
            }
            "#,
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("parse".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-X-TARGET-DEFAULT".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let main = fs::read_to_string(temp.join("out/H-X-TARGET-DEFAULT/main.cpp")).unwrap();
        assert!(main.contains("Options options{};"), "{main}");
        assert!(main.contains("options.mode = gf_i32(&Cur)"), "{main}");
        assert!(
            main.contains("int parse(std::string_view, const Options &);"),
            "the forward declaration must preserve cv/ref exactly:\n{main}"
        );
        assert!(main.contains("gov::parse(input, options)"), "{main}");

        // A generation-only assertion missed the old bug because both overloads
        // looked plausible as text. Compile the produced TU when a system GNU C++
        // compiler is present; this specifically proves the call is unambiguous.
        if std::process::Command::new("g++")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            let status = std::process::Command::new("g++")
                .arg("-std=gnu++20")
                .arg("-DGOVFUZZ_EXTERNAL_DRIVER")
                .arg("-I")
                .arg(locate_c_runtime())
                .arg("-iquote")
                .arg(&temp)
                .arg("-c")
                .arg(temp.join("out/H-X-TARGET-DEFAULT/main.cpp"))
                .arg("-o")
                .arg(temp.join("target-default.o"))
                .status()
                .unwrap();
            assert!(status.success(), "generated C++ harness must compile");
        }
    }

    #[test]
    fn numeric_token_byte_encodings_emits_raw_le_and_be_bytes() {
        // Single byte: LE == BE, one encoding (the actual compared byte).
        assert_eq!(numeric_token_byte_encodings("0x55"), vec![vec![0x55]]);
        assert_eq!(numeric_token_byte_encodings("85"), vec![vec![85]]);
        assert_eq!(numeric_token_byte_encodings("0125"), vec![vec![0o125]]); // octal
                                                                             // Multi-byte: both little- and big-endian width-sized encodings.
        let enc = numeric_token_byte_encodings("0xDEADBEEF");
        assert!(enc.contains(&vec![0xEF, 0xBE, 0xAD, 0xDE]), "LE: {enc:?}");
        assert!(enc.contains(&vec![0xDE, 0xAD, 0xBE, 0xEF]), "BE: {enc:?}");
        // Non-integer tokens (strings, char names) stay ASCII — no expansion.
        assert!(numeric_token_byte_encodings("GIF89a").is_empty());
        assert!(numeric_token_byte_encodings("P").is_empty());
    }

    #[test]
    fn generate_c_harness_writes_dictionary_from_source_and_header_constants() {
        let temp = temp_dir("c-dictionary");
        let header = temp.join("parser.h");
        let source = temp.join("parser.c");
        fs::write(
            &header,
            "#define MAGIC_TEXT \"GIF89a\"\n\
             #define MAGIC_NUM 0x504b0304\n\
             enum mode { MODE_FAST, MODE_SAFE };\n\
             int parse(const char *input);\n",
        )
        .unwrap();
        fs::write(
            &source,
            "#include \"parser.h\"\n\
             #include <string.h>\n\
             int parse(const char *input) { switch (input ? input[0] : 0) { case 'Q': return 2; default: break; } return input && !strcmp(input, \"READY\"); }\n",
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("parse".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-CDICT".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let dictionary = fs::read_to_string(temp.join("out/H-CDICT/dictionary.txt")).unwrap();
        assert!(dictionary.contains("\"GIF89a\""));
        assert!(dictionary.contains("\"0x504b0304\""));
        // #379: the numeric magic 0x504b0304 must also appear as raw bytes so it
        // actually matches the byte stream — big-endian is the ZIP "PK\x03\x04".
        assert!(
            dictionary.contains("\"PK\\x03\\x04\""),
            "raw big-endian magic bytes missing:\n{dictionary}"
        );
        assert!(dictionary.contains("\"MODE_FAST\""));
        assert!(dictionary.contains("\"MODE_SAFE\""));
        assert!(dictionary.contains("\"Q\""));
        assert!(dictionary.contains("\"READY\""));
    }

    #[test]
    fn generate_cpp_harness_writes_dictionary_from_header_constants() {
        let temp = temp_dir("cpp-dictionary");
        let header = temp.join("parser.hpp");
        let source = temp.join("parser.cpp");
        fs::write(
            &header,
            "#define MAGIC_TEXT \"GIF89a\"\n\
             #define MAGIC_NUM 0x504b0304\n\
             enum Mode { MODE_FAST, MODE_SAFE };\n",
        )
        .unwrap();
        fs::write(
            &source,
            "#include \"parser.hpp\"\n\
             #include <string_view>\n\
             namespace gov { int parse(std::string_view input) { return (int)input.size(); } }\n",
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("parse".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-CPPDICT".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let dictionary = fs::read_to_string(temp.join("out/H-CPPDICT/dictionary.txt")).unwrap();
        assert!(dictionary.contains("\"GIF89a\""));
        assert!(dictionary.contains("\"0x504b0304\""));
        assert!(dictionary.contains("\"MODE_FAST\""));
        assert!(dictionary.contains("\"MODE_SAFE\""));
    }

    #[test]
    fn generate_cpp_harness_writes_dictionary_from_cpp_source_constants() {
        let temp = temp_dir("cpp-source-dictionary");
        let source = temp.join("parser.cpp");
        fs::write(
            &source,
            "#include <string_view>\n\
             #define CPP_MAGIC_TEXT \"HELLO_CPP\"\n\
             #define CPP_MAGIC_NUM 0xC0FFEE\n\
             namespace gov {\n\
             enum class Mode { Fast, Safe };\n\
             int parse(std::string_view input, int tag) {\n\
               switch (tag) { case 0x55: return 1; case 'Q': return 2; default: break; }\n\
               return input == \"READY_CPP\" ? 1 : 0;\n\
             }\n\
             }\n",
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("parse".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-CPP-SRC-DICT".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let dictionary =
            fs::read_to_string(temp.join("out/H-CPP-SRC-DICT/dictionary.txt")).unwrap();
        for expected in [
            "\"HELLO_CPP\"",
            "\"0xC0FFEE\"",
            "\"Fast\"",
            "\"Safe\"",
            "\"0x55\"",
            "\"Q\"",
            "\"READY_CPP\"",
        ] {
            assert!(
                dictionary.contains(expected),
                "missing {expected} from {dictionary}"
            );
        }
    }

    #[test]
    fn generate_cpp_harness_accepts_latin1_source_comments() {
        let root = temp_dir("cpp-latin1-source");
        let source = root.join("legacy.cpp");
        let mut bytes = b"// Copyright 2006 Peter K".to_vec();
        bytes.push(0xFC); // Latin-1 u-umlaut, invalid as a lone UTF-8 byte.
        bytes.extend_from_slice(b"mmel\nint parse_legacy(int value) { return value + 1; }\n");
        fs::write(&source, bytes).unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("parse_legacy".to_owned()),
            target_line: None,
            output: root.join("out"),
            id: Some("H-CPP-LATIN1".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .expect("Latin-1 comments must not block C++ harness generation");

        let main = fs::read_to_string(root.join("out/H-CPP-LATIN1/main.cpp")).unwrap();
        assert!(main.contains("parse_legacy"));
    }

    #[test]
    fn generate_c_harness_for_header_only_target() {
        let temp = temp_dir("c-header-harness");
        let source = temp.join("parser.h");
        fs::write(
            &source,
            "#include <stddef.h>\n\
             static inline int parse_header(const unsigned char *input, size_t len) { \
                 return input ? (int)len : 0; \
             }\n",
        )
        .unwrap();

        let args = GenerateHarnessArgs {
            source: source.clone(),
            target: Some("parse_header".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-C-HDR".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };

        run(args).unwrap();
        let main = fs::read_to_string(temp.join("out/H-C-HDR/main.c")).unwrap();
        assert!(main.contains("#include \"parser.h\""));
        assert!(!main.contains("extern int parse_header"));
        assert!(main.contains("parse_header(input, len)"));
        let makefile = fs::read_to_string(temp.join("out/H-C-HDR/Makefile")).unwrap();
        assert!(
            !makefile.contains(source.to_str().unwrap()),
            "header-only target must not be compiled as a source:\n{makefile}"
        );
    }

    #[test]
    fn c_like_header_with_cpp_sibling_generates_cpp_harness() {
        let temp = temp_dir("cpp-sibling-header-harness");
        let source = temp.join("Hashes.h");
        fs::write(
            &source,
            "void MurmurHash1(const void *key);\ninline void MurmurHash1_test(const void *key) { MurmurHash1(key); }\n",
        )
        .unwrap();
        fs::write(
            temp.join("Hashes.cpp"),
            "#include \"Hashes.h\"\nvoid MurmurHash1(const void *) {}\n",
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source,
            target: Some("MurmurHash1_test".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-X-SIBLING-HDR".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        assert!(temp.join("out/H-X-SIBLING-HDR/main.cpp").is_file());
    }

    #[test]
    fn generate_cpp_harness_for_header_only_target() {
        let temp = temp_dir("cpp-header-harness");
        let source = temp.join("parser.hpp");
        fs::write(
            &source,
            "#include <string_view>\n\
             namespace acme { inline int parse_header_cpp(std::string_view input) { \
                 return (int)input.size(); \
             } }\n",
        )
        .unwrap();
        let owner = temp.join("parser.cpp");
        fs::write(&owner, "#include \"parser.hpp\"\n").unwrap();
        fs::write(
            temp.join("compile_commands.json"),
            serde_json::to_vec_pretty(&serde_json::json!([{
                "directory": temp,
                "file": owner,
                "arguments": ["g++", "-std=gnu++17", "-c", owner]
            }]))
            .unwrap(),
        )
        .unwrap();

        let args = GenerateHarnessArgs {
            source: source.clone(),
            target: Some("parse_header_cpp".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-X-HDR".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };

        run(args).unwrap();
        let main = fs::read_to_string(temp.join("out/H-X-HDR/main.cpp")).unwrap();
        assert!(main.contains("#include \"parser.hpp\""));
        assert!(main.contains("acme::parse_header_cpp(input)"));
        let makefile = fs::read_to_string(temp.join("out/H-X-HDR/Makefile")).unwrap();
        assert!(
            !makefile.contains(source.to_str().unwrap()),
            "header-only target must not be compiled as a source:\n{makefile}"
        );
    }

    #[test]
    fn generate_cpp_direct_harness_includes_static_target_source() {
        let temp = temp_dir("cpp-static-direct-harness");
        let source = temp.join("internal.cpp");
        fs::write(
            &source,
            "#include <cstddef>\n\
             #include <cstdint>\n\
             static int hidden_parse(const std::uint8_t *data, std::size_t len) { \
                 return data && len ? data[0] : 0; \
             }\n",
        )
        .unwrap();

        let args = GenerateHarnessArgs {
            source: source.clone(),
            target: Some("hidden_parse".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-X-STATIC-CPP".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };

        run(args).unwrap();

        let main = fs::read_to_string(temp.join("out/H-X-STATIC-CPP/main.cpp")).unwrap();
        assert!(
            main.contains("#include \"internal.cpp\""),
            "static C++ direct target must be included into the harness TU:\n{main}"
        );
        assert!(
            !main.contains("int hidden_parse("),
            "static C++ direct target must not be externally forward-declared:\n{main}"
        );
        let makefile = fs::read_to_string(temp.join("out/H-X-STATIC-CPP/Makefile")).unwrap();
        assert!(
            !makefile.contains(source.to_str().unwrap()),
            "static C++ target source must not also be compiled separately:\n{makefile}"
        );
    }

    #[test]
    fn pick_unique_cpp_target_accepts_qualified_overload_signature() {
        let functions = cpp_parser::parse_cpp_functions(
            r#"
            #include <string_view>
            namespace gov {
            class Parser {
            public:
                int parse(const char *input, size_t len) { return input ? (int)len : 0; }
                int parse(std::string_view input) { return (int)input.size(); }
            };
            }
            "#,
        )
        .unwrap();

        let (selected, warning) = pick_cpp_target(
            Path::new("parser.cpp"),
            functions,
            "gov::Parser::parse(std::string_view)",
            None,
        )
        .unwrap();

        assert_eq!(selected.params.len(), 1);
        assert_eq!(selected.params[0].cpp_type, "std::string_view");
        assert!(
            warning.is_none(),
            "signature-qualified target name is unambiguous"
        );
    }

    #[test]
    fn pick_c_target_identical_signature_duplicates_pick_silently() {
        let f = |line| c_parser::CFunction {
            name: "decode".into(),
            line,
            return_type: "int".into(),
            params: vec![],
            ..Default::default()
        };
        let (picked, warning) =
            pick_c_target(Path::new("x.c"), vec![f(10), f(20)], "decode", None).unwrap();
        assert_eq!(picked.line, 10);
        assert!(warning.is_none(), "identical signatures must not warn");
    }

    #[test]
    fn pick_c_target_line_selects_exact_definition() {
        let f = |line, ret: &str| c_parser::CFunction {
            name: "decode".into(),
            line,
            return_type: ret.into(),
            params: vec![],
            ..Default::default()
        };
        let (picked, warning) = pick_c_target(
            Path::new("x.c"),
            vec![f(10, "int"), f(20, "long")],
            "decode",
            Some(20),
        )
        .unwrap();
        assert_eq!(picked.line, 20);
        assert!(warning.is_none());
    }

    #[test]
    fn pick_c_target_differing_signatures_without_line_warn() {
        let f = |line, ret: &str| c_parser::CFunction {
            name: "decode".into(),
            line,
            return_type: ret.into(),
            params: vec![],
            ..Default::default()
        };
        let (picked, warning) = pick_c_target(
            Path::new("x.c"),
            vec![f(10, "int"), f(20, "long")],
            "decode",
            None,
        )
        .unwrap();
        assert_eq!(picked.line, 10);
        assert!(warning.unwrap().contains("differing"));
    }

    #[test]
    fn pick_c_target_stale_line_falls_back_to_name_matching() {
        let f = |line| c_parser::CFunction {
            name: "decode".into(),
            line,
            return_type: "int".into(),
            params: vec![],
            ..Default::default()
        };
        let (picked, warning) =
            pick_c_target(Path::new("x.c"), vec![f(10)], "decode", Some(99)).unwrap();
        assert_eq!(picked.line, 10, "stale line falls back to name match");
        assert!(warning.is_none());
    }

    #[test]
    fn va_list_target_uses_matching_variadic_wrapper() {
        use c_parser::{CFunction, CParamDescriptor};
        let param = |name: &str, c_type: &str| CParamDescriptor {
            name: name.to_owned(),
            c_type: c_type.to_owned(),
        };
        let target = CFunction {
            name: "json_vunpack_ex".to_owned(),
            line: 896,
            return_type: "int".to_owned(),
            params: vec![
                param("root", "json_t *"),
                param("error", "json_error_t *"),
                param("flags", "size_t"),
                param("fmt", "const char *"),
                param("ap", "va_list"),
            ],
            ..Default::default()
        };
        let wrapper = CFunction {
            name: "json_unpack_ex".to_owned(),
            line: 935,
            return_type: "int".to_owned(),
            params: target.params[..4].to_vec(),
            variadic: true,
            ..Default::default()
        };

        let selected = c_va_list_variadic_wrapper(&target, &[target.clone(), wrapper.clone()])
            .expect("matching variadic wrapper");
        assert_eq!(selected, wrapper);

        let mut wrong = wrapper;
        wrong.params[2].c_type = "unsigned".to_owned();
        assert!(c_va_list_variadic_wrapper(&target, &[wrong]).is_none());
    }

    #[test]
    fn generate_cpp_direct_harness_uses_supported_parameterized_constructor_for_method() {
        let temp = temp_dir("cpp-direct-parameterized-constructor");
        let source = temp.join("parser.cpp");
        fs::write(
            &source,
            r#"
            #include <string>
            #include <string_view>
            namespace gov {
            class Parser {
            public:
                Parser(const std::string &seed) { (void)seed; }
                int parse(std::string_view input) { return (int)input.size(); }
            };
            }
            "#,
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("parse".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-X-DIRECT-CTOR".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let main = fs::read_to_string(temp.join("out/H-X-DIRECT-CTOR/main.cpp")).unwrap();
        assert!(main.contains("std::string _gf_ctor_seed"));
        assert!(main.contains("gov::Parser _gf_receiver(_gf_ctor_seed);"));
        assert!(main.contains("int R = _gf_receiver.parse(input);"));
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_source_only_namespaced_enum_class_param() {
        let temp = temp_dir("cpp-source-enum-class");
        let source = temp.join("parser.cpp");
        fs::write(
            &source,
            r#"
            namespace gov {
            enum class Mode { Fast, Safe };
            int parse(Mode mode) { return mode == Mode::Fast ? 1 : 0; }
            }
            "#,
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("parse".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-X-SRC-ENUM".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let main = fs::read_to_string(temp.join("out/H-X-SRC-ENUM/main.cpp")).unwrap();
        assert!(main.contains("#include \"parser.cpp\""));
        assert!(main.contains("using namespace gov;"));
        assert!(main.contains("Mode mode = (Mode)gov::Mode::Fast"));
        assert!(main.contains("case 1: mode = (Mode)gov::Mode::Safe; break"));
        assert!(main.contains("gov::parse(mode);"));
    }

    #[test]
    fn generate_cpp_sequence_harness_models_object_lifecycle_methods() {
        let temp = temp_dir("cpp-lifecycle-sequence");
        let source = temp.join("parser.cpp");
        fs::write(
            &source,
            r#"
            #include <string_view>
            namespace gov {
            class Parser {
            public:
                Parser() {}
                ~Parser() {}
                void reset() {}
                void feed(std::string_view chunk) { (void)chunk; }
                int parse(std::string_view input) { return (int)input.size(); }
            };
            }
            "#,
        )
        .unwrap();

        let args = GenerateHarnessArgs {
            source: source.clone(),
            target: Some("parse".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-X-LIFE".to_owned()),
            kind: "sequence".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        };

        run(args).unwrap();

        let main = fs::read_to_string(temp.join("out/H-X-LIFE/main.cpp")).unwrap();
        let makefile = fs::read_to_string(temp.join("out/H-X-LIFE/Makefile")).unwrap();
        assert!(main.contains("#include \"parser.cpp\""));
        assert!(main.contains("try {"));
        assert!(main.contains("gov::Parser _gf_receiver;"));
        assert!(main.contains("for (size_t _gf_lifecycle_index = 0;"));
        assert!(main.contains("_gf_receiver.reset();"));
        assert!(main.contains("_gf_receiver.feed("));
        assert!(main.contains("int R = _gf_receiver.parse(input);"));
        assert!(main.contains("catch (...)"));
        assert!(main.contains("RAII destructors run when _gf_receiver leaves scope"));
        assert!(
            !makefile.contains(source.to_str().unwrap()),
            "source-local class declaration is included in main.cpp and must not be linked twice:\n{makefile}"
        );
    }

    #[test]
    fn generate_cpp_sequence_keeps_registry_decodable_setup_method() {
        let temp = temp_dir("cpp-lifecycle-registry-param");
        let source = temp.join("parser.cpp");
        fs::write(
            &source,
            r#"
            #include <string_view>
            namespace gov {
            struct Options { int mode = 0; };
            class Parser {
            public:
                Parser() = default;
                void configure(const Options &options) { mode_ = options.mode; }
                int parse(std::string_view input) { return (int)input.size() + mode_; }
            private:
                int mode_ = 0;
            };
            }
            "#,
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("parse".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-X-LIFECYCLE-REGISTRY".to_owned()),
            kind: "sequence".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let main = fs::read_to_string(temp.join("out/H-X-LIFECYCLE-REGISTRY/main.cpp")).unwrap();
        assert!(main.contains("Options _gf_step0_options{};"), "{main}");
        assert!(
            main.contains("_gf_step0_options.mode = gf_i32(&Cur)"),
            "{main}"
        );
        assert!(
            main.contains("_gf_receiver.configure(_gf_step0_options)"),
            "{main}"
        );
        if std::process::Command::new("g++")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            let status = std::process::Command::new("g++")
                .arg("-std=gnu++20")
                .arg("-DGOVFUZZ_EXTERNAL_DRIVER")
                .arg("-I")
                .arg(locate_c_runtime())
                .arg("-iquote")
                .arg(&temp)
                .arg("-c")
                .arg(temp.join("out/H-X-LIFECYCLE-REGISTRY/main.cpp"))
                .arg("-o")
                .arg(temp.join("lifecycle-registry.o"))
                .status()
                .unwrap();
            assert!(status.success(), "generated sequence harness must compile");
        }
    }

    #[test]
    fn generate_cpp_sequence_harness_excludes_private_lifecycle_methods() {
        let temp = temp_dir("cpp-lifecycle-private-method");
        let source = temp.join("parser.cpp");
        fs::write(
            &source,
            r#"
            #include <string_view>
            namespace gov {
            class Parser {
            public:
                Parser() {}
                void feed(std::string_view chunk) { (void)chunk; }
                int parse(std::string_view input) { return (int)input.size(); }
            private:
                void reset() {}
            };
            }
            "#,
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("parse".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-X-PRIVATE".to_owned()),
            kind: "sequence".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let main = fs::read_to_string(temp.join("out/H-X-PRIVATE/main.cpp")).unwrap();
        assert!(main.contains("_gf_receiver.feed("));
        assert!(
            !main.contains("_gf_receiver.reset("),
            "private methods are not externally callable and must be skipped:\n{main}"
        );
    }

    #[test]
    fn cpp_sequence_without_callable_setup_falls_back_instead_of_emitting_empty_sequence() {
        let temp = temp_dir("cpp-lifecycle-empty");
        let source = temp.join("parser.cpp");
        fs::write(
            &source,
            r#"
            #include <string_view>
            class Parser {
            public:
                int parse(std::string_view input) { return (int)input.size(); }
            private:
                void reset() {}
            };
            "#,
        )
        .unwrap();

        let error = run(GenerateHarnessArgs {
            source,
            target: Some("parse".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-X-EMPTY".to_owned()),
            kind: "sequence".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .expect_err("an empty lifecycle must route auto to the direct fallback");
        assert!(error
            .to_string()
            .contains("no callable public C++ lifecycle setup methods"));
    }

    #[test]
    fn generate_cpp_sequence_harness_uses_supported_parameterized_constructor() {
        let temp = temp_dir("cpp-lifecycle-parameterized-constructor");
        let source = temp.join("parser.cpp");
        fs::write(
            &source,
            r#"
            #include <string_view>
            #include <string>
            namespace gov {
            class Parser {
            public:
                Parser(const std::string &seed) { (void)seed; }
                int parse(std::string_view input) { return (int)input.size(); }
            };
            }
            "#,
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: source.clone(),
            target: Some("parse".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-X-CTOR".to_owned()),
            kind: "sequence".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();
        let main = fs::read_to_string(temp.join("out/H-X-CTOR/main.cpp")).unwrap();
        assert!(main.contains("std::string _gf_ctor_seed"));
        assert!(main.contains("gov::Parser _gf_receiver(_gf_ctor_seed);"));
        assert!(main.contains("int R = _gf_receiver.parse(input);"));
    }

    #[test]
    fn generate_cpp_sequence_harness_blocks_private_parameterized_constructor() {
        let temp = temp_dir("cpp-lifecycle-private-constructor");
        let source = temp.join("parser.cpp");
        fs::write(
            &source,
            r#"
            #include <string_view>
            #include <string>
            namespace gov {
            class Parser {
            public:
                int parse(std::string_view input) { return (int)input.size(); }
            private:
                Parser(const std::string &seed) { (void)seed; }
            };
            }
            "#,
        )
        .unwrap();

        let error = run(GenerateHarnessArgs {
            source,
            target: Some("parse".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-X-PRIVATE-CTOR".to_owned()),
            kind: "sequence".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("cannot construct"));
        assert!(message.contains("wrapper"));
        assert!(message.contains("factory"));
    }

    #[test]
    fn generate_cpp_harness_does_not_treat_deleted_ctor_or_temporary_as_constructible() {
        let temp = temp_dir("cpp-deleted-default-constructor");
        let source = temp.join("parser.cpp");
        fs::write(
            &source,
            r#"
            #include <string_view>
            namespace gov {
            class Parser {
            public:
                Parser() = delete;
                int parse(std::string_view input) { return (int)input.size(); }
            };
            void decoy() { (void)Parser(); }
            }
            "#,
        )
        .unwrap();

        let error = run(GenerateHarnessArgs {
            source,
            target: Some("parse".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-X-DELETED-CTOR".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap_err();
        assert!(error.to_string().contains("cannot construct"), "{error}");
        assert!(
            !temp.join("out/H-X-DELETED-CTOR/main.cpp").exists(),
            "an uncompilable deleted-constructor receiver must not be emitted"
        );
    }

    #[test]
    fn generate_cpp_harness_skips_abstract_receiver_class() {
        // capnp's `ClientHook::isBrand` has an abstract receiver (pure-virtual
        // members). It must be an honest skip, not `ClientHook _gf_receiver;`
        // which fails with "variable type is an abstract class".
        let temp = temp_dir("cpp-abstract-receiver");
        let source = temp.join("hook.cpp");
        fs::write(
            &source,
            r#"
            namespace capnp {
            class ClientHook {
            public:
                ClientHook() {}
                virtual bool isBrand(const void *other) = 0;
            };
            }
            "#,
        )
        .unwrap();

        let error = run(GenerateHarnessArgs {
            source,
            target: Some("isBrand".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-X-ABSTRACT".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("abstract"),
            "expected an abstract-class skip, got: {message}"
        );
    }

    #[test]
    fn generate_cpp_sequence_harness_constructs_receiver_from_defaultable_ctor_dependency() {
        let temp = temp_dir("cpp-lifecycle-factory-only");
        let source = temp.join("parser.cpp");
        fs::write(
            &source,
            r#"
            #include <string_view>
            namespace gov {
            class Dependency {};
            class Parser {
            public:
                Parser(Dependency &dependency) { (void)dependency; }
                int parse(std::string_view input) { return (int)input.size(); }
            };
            }
            "#,
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source,
            target: Some("parse".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-X-BLOCKED".to_owned()),
            kind: "sequence".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();
        let main = fs::read_to_string(temp.join("out/H-X-BLOCKED/main.cpp")).unwrap();
        assert!(main.contains("Dependency _gf_ctor_dependency{};"), "{main}");
        assert!(
            main.contains("gov::Parser _gf_receiver(_gf_ctor_dependency);"),
            "{main}"
        );
    }

    // ── Factory-receiver pipeline tests ───────────────────────────────────

    /// tinyxml2-like pattern: `XMLElement` has no public constructor; instances
    /// are created via `XMLDocument::NewElement(const char*)` which returns
    /// `XMLElement*`.  The harness must: default-construct the owner, call the
    /// factory, null-guard the pointer receiver, and call the target via `->`.
    #[test]
    fn generate_cpp_factory_receiver_via_owner_method_pointer_return() {
        let temp = temp_dir("cpp-factory-owner-ptr");
        let source = temp.join("xml.cpp");
        fs::write(
            &source,
            // XMLElement has a private PARAMETERISED constructor (like real tinyxml2,
            // which uses `XMLElement(XMLDocument* doc)`).  The text-scanner cannot
            // detect this as a no-arg default ctor, so cpp_class_is_default_constructible
            // correctly returns false and the factory search path activates.
            r#"
            class XMLDocument;
            class XMLElement {
                XMLElement(XMLDocument* doc) { (void)doc; }
                ~XMLElement() {}
            public:
                int IntAttribute(const char* name, int defaultValue = 0) const {
                    (void)name; return defaultValue;
                }
            };
            class XMLDocument {
            public:
                XMLDocument() {}
                XMLElement* NewElement(const char* name) { (void)name; return nullptr; }
            };
            "#,
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source,
            target: Some("IntAttribute".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-FACTORY-XML".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let main = fs::read_to_string(temp.join("out/H-FACTORY-XML/main.cpp")).unwrap();
        assert!(
            main.contains("XMLDocument _gf_owner;"),
            "owner must be stack-allocated:\n{main}"
        );
        assert!(
            main.contains("auto _gf_receiver = _gf_owner.NewElement("),
            "factory call must use owner:\n{main}"
        );
        assert!(
            main.contains("if (_gf_receiver)"),
            "pointer receiver must be null-guarded:\n{main}"
        );
        assert!(
            main.contains("_gf_receiver->IntAttribute("),
            "method on pointer receiver must use -> access:\n{main}"
        );
        // Owner stays in scope (declared before the if-guard block).
        let owner_pos = main.find("XMLDocument _gf_owner;").unwrap();
        let guard_pos = main.find("if (_gf_receiver)").unwrap();
        assert!(
            owner_pos < guard_pos,
            "owner must be declared before the null guard to outlive the call:\n{main}"
        );
    }

    #[test]
    fn cpp_receiver_uses_header_declared_static_factory_defined_in_sibling_tu() {
        let temp = temp_dir("cpp-static-factory-sibling");
        let source_dir = temp.join("src");
        fs::create_dir_all(&source_dir).unwrap();
        let header = source_dir.join("widget.hpp");
        let target = source_dir.join("widget_parse.cpp");
        let factory = source_dir.join("widget_factory.cpp");
        fs::write(
            &header,
            "#pragma once\nclass Widget {\n  Widget();\npublic:\n  static Widget *Create(int seed);\n  int Parse(const char *text);\n};\n",
        )
        .unwrap();
        fs::write(
            &target,
            "#include \"widget.hpp\"\nint Widget::Parse(const char *text) { return text ? 1 : 0; }\n",
        )
        .unwrap();
        fs::write(
            &factory,
            "#include \"widget.hpp\"\nWidget::Widget() {}\nWidget *Widget::Create(int) { return new Widget(); }\n",
        )
        .unwrap();
        fs::write(
            temp.join("CMakeLists.txt"),
            "cmake_minimum_required(VERSION 3.10)\nproject(widget CXX)\nadd_library(widget src/widget_parse.cpp src/widget_factory.cpp)\n",
        )
        .unwrap();
        fs::write(
            temp.join("compile_commands.json"),
            serde_json::to_vec_pretty(&serde_json::json!([
                {
                    "directory": source_dir,
                    "file": target,
                    "arguments": ["g++", "-std=gnu++17", "-c", target]
                },
                {
                    "directory": source_dir,
                    "file": factory,
                    "arguments": ["g++", "-std=gnu++17", "-c", factory]
                }
            ]))
            .unwrap(),
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source: target,
            target: Some("Widget::Parse".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-CPP-STATIC-FACTORY".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let harness = temp.join("out/H-CPP-STATIC-FACTORY");
        let main = fs::read_to_string(harness.join("main.cpp")).unwrap();
        assert!(
            main.contains("auto _gf_receiver = Widget::Create("),
            "{main}"
        );
        assert!(!main.contains("Widget _gf_owner"), "{main}");
        let build_context = fs::read_to_string(harness.join("build_context_objects.mk")).unwrap();
        assert!(
            build_context.contains(factory.to_str().unwrap()),
            "sibling factory definition must be linked: {build_context}"
        );

        if std::process::Command::new("make")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            let status = std::process::Command::new("make")
                .arg("-C")
                .arg(&harness)
                .arg("main")
                .status()
                .unwrap();
            assert!(status.success(), "factory closure harness must build");
        }
    }

    /// When the class is default-constructible, the factory path must NOT be
    /// taken — the existing direct construction path wins.
    #[test]
    fn generate_cpp_factory_is_not_used_when_default_ctor_exists() {
        let temp = temp_dir("cpp-factory-ctor-wins");
        let source = temp.join("item.cpp");
        fs::write(
            &source,
            r#"
            class Item {
            public:
                Item() {}
                int value() const { return 42; }
            };
            class ItemFactory {
            public:
                Item* NewItem() { return nullptr; }
            };
            "#,
        )
        .unwrap();

        run(GenerateHarnessArgs {
            source,
            target: Some("value".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-NOFACTORY-CTOR".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap();

        let main = fs::read_to_string(temp.join("out/H-NOFACTORY-CTOR/main.cpp")).unwrap();
        // Direct construction must be used (default ctor exists).
        assert!(
            main.contains("Item _gf_receiver;"),
            "default-constructible class must use direct construction:\n{main}"
        );
        // Factory path must not activate.
        assert!(
            !main.contains("_gf_owner"),
            "default ctor path must not emit a factory owner:\n{main}"
        );
        assert!(
            !main.contains("auto _gf_receiver"),
            "default ctor path must not use auto factory receiver:\n{main}"
        );
        assert!(
            main.contains("_gf_receiver.value()"),
            "value method must use . access:\n{main}"
        );
    }

    /// A class with no public constructor AND no discoverable factory must still
    /// bail with a clear error message.
    #[test]
    fn generate_cpp_class_with_no_ctor_and_no_factory_bails_with_guidance() {
        let temp = temp_dir("cpp-no-ctor-no-factory");
        let source = temp.join("opaque.cpp");
        fs::write(
            &source,
            // Opaque has a private PARAMETERISED constructor (so the text scanner
            // won't false-positive it as a no-arg default ctor) and NO factory method
            // returning Opaque*.  The generator must bail with a clear error.
            r#"
            class Opaque {
                Opaque(int secret) { (void)secret; }
            public:
                int value() const { return 0; }
            };
            "#,
        )
        .unwrap();

        let error = run(GenerateHarnessArgs {
            source,
            target: Some("value".to_owned()),
            target_line: None,
            output: temp.join("out"),
            id: Some("H-X-NO-FACTORY".to_owned()),
            kind: "direct".to_owned(),
            source_roots: Vec::new(),
            project: None,
            source_trees: Vec::new(),
            extra_sources: Vec::new(),
            extra_includes: Vec::new(),
            cleanup: None,
            template_instantiate: Vec::new(),
            tree_type_defs: None,
            decoder_limits: Default::default(),
            force: false,
        })
        .unwrap_err();

        let message = error.to_string();
        assert!(
            message.contains("cannot construct"),
            "error must explain that construction failed: {message}"
        );
        assert!(
            message.contains("wrapper") || message.contains("factory"),
            "error must guide toward a wrapper or factory harness: {message}"
        );
    }

    const PRIVATE_STATE_SPEC: &str = r#"
pragma Ada_2012;

package State is
   procedure Push (X : Integer);
   procedure Pop;
   function Top return Integer;
end State;
"#;

    const PRIVATE_STATE_BODY: &str = r#"
pragma Ada_2012;

package body State is
   Count : Natural := 0;

   procedure Push (X : Integer) is
      pragma Unreferenced (X);
   begin
      Count := Count + 1;
   end Push;

   procedure Pop is
   begin
      Count := Count - 1;
   exception
      when Constraint_Error =>
         null;
   end Pop;

   procedure Helper is
   begin
      null;
   end Helper;

   function Top return Integer is
   begin
      return Count;
   end Top;
end State;
"#;
}
