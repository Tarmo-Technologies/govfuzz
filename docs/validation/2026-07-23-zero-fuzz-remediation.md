# Zero-fuzz Ada/C/C++ remediation ledger (2026-07-23)

## Purpose and completion rule

An offline legacy Ada/C/C++ campaign discovered thousands of targets but, in a
representative top-500 sweep, had not built and fuzzed a single endpoint. The
dominant outcomes were `unsupported_params` and `failed_build`, including:

- Ada named types reported as undeclared or not constructible;
- repeated C++ opaque `const ns::Type` parameters reported as needing lifecycle
  support;
- unresolved C++ lifecycle access and lifecycle harnesses without setup;
- legacy header syntax failures and receiver constructor failures;
- cascades of Ada `missing_ada_symbol` diagnostics.

This ledger is the authoritative remediation checklist. An item is complete only
when the implementation is changed, a focused regression test demonstrates the
old failure, and an appropriate integration or campaign test demonstrates the
fixed path. A passing unit test that does not exercise the reported boundary is
not sufficient.

Status values:

- `OPEN`: confirmed issue, not yet corrected;
- `IN PROGRESS`: implementation or proof is incomplete;
- `FIXED, PROOF PENDING`: code changed but the required campaign evidence is
  incomplete;
- `CLOSED`: implementation and listed proof are complete;
- `EXPECTED`: intentional limitation, with an honest non-success outcome and
  regression coverage required.

## Primary high-impact defects

### ZF-01 — Ada target identity ignores the declaration line

- Status: `CLOSED`.
- Evidence: discovery records `decl_span.start_line`, while Ada generation calls
  `select_subprogram` with only the requested name. C and C++ both use
  `target_line`.
- Impact: overloaded generated bindings repeatedly harness the first same-named
  declaration. A viable later overload may never be attempted.
- Correction: select by exact declaration line first; retain an
  explicitly diagnosed name-only fallback only for stale/manual requests.
- Proof requirement (met; see closure matrix): parser/generator regression with two same-named profiles plus
  an Ada auto campaign in which both stable harness IDs call their own profile.

### ZF-02 — Default-constructible C++ target parameters are not registered

- Status: `CLOSED`.
- Evidence: `default_constructible_classes` is populated from receiver
  constructor parameters and then reused for the target call. The target's own
  class-typed parameters are not analyzed.
- Impact: `const ns::Options&` and similar infrastructure objects are rejected as
  opaque even when `ns::Options value; target(value);` is valid. This matches the
  largest repeated C++ unsupported cluster.
- Correction: analyze target, lifecycle, constructor, and factory
  parameter classes against the complete include closure; register only
  accessible, non-deleted, non-abstract default constructors.
- Proof requirement (met; see closure matrix): direct and sequence harness generation/build tests for value,
  const-reference, output-pointer, namespaced, private, deleted, and abstract
  classes.

### ZF-03 — The target cap is applied after viability-blind ranking

- Status: `CLOSED`.
- Evidence: Ada awards `fuzzable_params` points to every `in`, `in out`, or
  `access` parameter without testing its type. C++ ranking treats config/options
  objects as synthesizable although generation rejects many of them. The
  top-`N` cap is applied to this ordering.
- Impact: hundreds of opaque or blocked endpoints can displace simple fuzzable
  endpoints from a 500-target campaign.
- Correction: add a conservative harness-viability verdict/penalty
  derived from the same decoder/type context used by generation; blocked targets
  remain discoverable but cannot outrank proven byte channels by parameter count.
- Proof requirement (met; see closure matrix): ranking tests containing buildable and opaque signatures, and
  a capped mixed-language campaign that reaches at least one viable endpoint.

### ZF-04 — Separate IDL files overwrite reopened Ada modules

- Status: `CLOSED`.
- Evidence: `auto_generate_from_tree` emits each IDL AST independently into one
  directory; `write_generated_ada_units` unconditionally overwrites equal paths.
  Reopened modules are merged only inside a single AST.
- Impact: later IDLs erase earlier structs, typedefs, constants, operations, and
  helpers. A few truncated module specs can produce hundreds of missing-symbol
  diagnostics.
- Correction: parse all IDLs into one aggregate AST (with include
  deduplication) or merge generated units semantically before one atomic write.
  Dictionary tokens must also be unioned rather than overwritten.
- Proof requirement (met; see closure matrix): two and three-file reopened-module fixtures, cross-includes,
  repeated include guards, deterministic output, and a GNAT build of generated
  packages when GNAT is available.

### ZF-05 — Header targets cannot inherit translation-unit compile commands

- Status: `CLOSED`.
- Evidence: compile database lookup requires exact normalized path equality;
  compile databases conventionally list translation units rather than headers.
- Impact: header endpoints lose feature/export macros, generated-header paths,
  forced includes, dialect, and ABI options even when a complete database exists.
- Correction: associate a header with including translation-unit
  entries, prefer direct include evidence and nearest target context, and record
  ambiguity/confidence without exposing paths.
- Proof requirement (met; see closure matrix): multi-TU compile database fixtures proving deterministic header
  association and a header harness that requires a TU-only macro/include path.

### ZF-06 — C++ harness include order differs from the real translation unit

- Status: `CLOSED`.
- Evidence: same-stem headers are added before the source's quoted include list.
  A header target includes itself before any umbrella/config prerequisite.
- Impact: legacy headers that require `config.h`, packing declarations, calling
  convention macros, or an umbrella header fail with declarator syntax errors.
- Correction: preserve source include order; never promote a same-stem
  header ahead of preceding source includes; resolve non-self-contained header
  targets through an including TU/umbrella context.
- Proof requirement (met; see closure matrix): config-before-API and umbrella-only header build fixtures for C
  and C++.

### ZF-07 — Compile-command/compiler fidelity is insufficient

- Status: `CLOSED`.
- Evidence: compile-command extraction allowlists only a small flag subset and
  discards compiler identity. Native builds default to clang/clang++.
- Impact: legacy GCC/vendor/MS-extension, target/sysroot, packing, ABI, language,
  permissive, and per-TU builds fail despite a valid project build.
- Correction: classify and forward safe compile-relevant flags, preserve
  paired operands, select a compatible compiler from the command entry when
  available, and explicitly report every dropped flag family.
- Proof requirement (met; see closure matrix): compile DB unit tests for paired/joined flags and campaigns for
  GCC extensions, forced headers, packing/ABI, sysroot/target, and safe rejection
  of output/dependency/module/PCH flags.

### ZF-08 — Recovered `-std` defeats the dialect ladder; C++03/98 rungs are false

- Status: `CLOSED`.
- Evidence: `COMPILE_DB_FLAGS` follows `CXXFLAGS`, so its `-std=` overrides
  `CXX_STD`. The generated harness unconditionally includes/uses post-C++03
  facilities while the ladder advertises `gnu++03` and `gnu++98`.
- Impact: every retry may use the same project standard; genuinely old-only code
  cannot compile the generated driver.
- Correction: normalize the recovered standard into the explicit
  `CXX_STD` decision instead of forwarding it twice; either provide a true
  C++03-compatible driver or honestly make C++11 the minimum and route older
  dialects to `report_only`.
- Proof requirement (met; see closure matrix): command-line inspection plus build fixtures for C++98-only,
  C++11, C++14, and C++17 APIs, including a compile DB with its own `-std`.

### ZF-09 — C++ default-constructor scanning accepts deleted/private expressions

- Status: `CLOSED`.
- Evidence: any balanced empty `T()` occurrence returns true before checking
  `= delete` or class access; ordinary temporary expressions also match.
- Impact: generated receivers fail with deleted/private/no-matching-constructor
  diagnostics.
- Correction: use parsed constructor declarations keyed by qualified
  class and access/signature; textual fallback must reject deletion and require a
  declaration in the correct class body.
- Proof requirement (met; see closure matrix): public/defaulted/default-argument, private, protected, deleted,
  temporary-expression, namespace-collision, and implicit-default tests.

### ZF-10 — C++ type and member-access registries lose namespace/signature identity

- Status: `CLOSED`.
- Evidence: class/struct definitions are primarily stored by leaf name and
  qualified type resolution falls back to the leaf. Header method access is keyed
  by `Class::method`, without namespace or parameter profile.
- Impact: common generated names (`Object`, `Header`, `Options`) can resolve to
  the wrong aggregate or access declaration, producing incorrect members,
  constructor decisions, and “not known public” warnings.
- Correction: retain full namespace/class identity in parser type
  definitions and access declarations; permit leaf fallback only when unique and
  report ambiguity.
- Proof requirement (met; see closure matrix): duplicate leaf types/classes in two namespaces, overloaded
  access declarations, nested classes/enums, and complete harness builds.

### ZF-11 — Lifecycle gating uses a weaker type model than lifecycle emission

- Status: `CLOSED`.
- Evidence: setup selection calls the registry-free primitive/string support
  predicate, while emission supports aliases, aggregates, containers, and
  default-constructible classes through a `TypeRegistry`.
- Impact: valid setup methods are discarded and stateful targets are invoked
  without initialization or routed through unnecessary fallback.
- Correction: use one registry-aware support decision for candidate
  selection and emission, and retain structured reasons for rejected steps.
- Proof requirement (met; see closure matrix): lifecycle steps taking typedefs, aggregates, containers,
  infrastructure objects, private methods, and unresolved/ambiguous access.

### ZF-12 — Ada synthetic builds discard governing GPR semantics

- Status: `CLOSED`.
- Evidence: the generated project flattens sources and forwards selected import
  clauses but not governing `Source_Dirs` precedence, `Naming`, scenario values,
  configuration pragmas, compiler/binder/linker switches, or per-file rules. An
  external work directory can cause GPR discovery to inspect the wrong parent.
- Impact: code that builds under its actual project fails under govfuzz or binds
  a different unit variant.
- Correction: carry the canonical source root/governing GPR into build;
  extend/import the real project where safe, or synthesize an overlay that
  preserves its evaluated attributes and target-specific switches.
- Proof requirement (met; see closure matrix): external work directory, custom naming, ordered duplicate
  source dirs, scenario-selected body, config pragma, binder/linker switch, and
  imported-project fixtures.

## Additional systemic defects and capability gaps

### ZF-13 — Fake and real Ada units have no collision policy

- Status: `CLOSED`.
- Correction/proof (met): inventory canonical unit names before generation; prefer a
  complete real spec/body, emit fake units only for missing units, and test mixed
  checked-in bindings plus IDL without duplicate-unit builds.

### ZF-14 — Ada type resolution uses unsafe leaf-only fallback

- Status: `CLOSED`.
- Correction/proof (met): resolve exact qualified names and Ada-visible unqualified
  names; reject ambiguity. Test identical leaf types across withed packages and
  local/nested scopes.

### ZF-15 — Flattened Ada duplicate selection is traversal-order dependent

- Status: `CLOSED`.
- Correction/proof (met): derive source precedence from the governing project and sort
  all remaining walks. Test repeated runs and conflicting platform/scenario
  variants.

### ZF-16 — Discovery preprocessing and generation parsing use different worlds

- Status: `CLOSED`.
- Correction/proof (met): persist the effective conditional context and reuse it for
  selection/type parsing, or always reconcile against the exact raw declaration.
  Give C++ the same zero-result safety fallback as C. Test project-defined feature
  branches and overlapping declarations.

### ZF-17 — Discovery cache is not invalidated by a govfuzz upgrade

- Status: `CLOSED`.
- Correction/proof (met): key cache data by producer version/commit plus a discovery
  semantic version. Test same-source reuse across equal and changed producers.

### ZF-18 — Ada generated harness mirroring preserves stale files

- Status: `CLOSED`.
- Correction/proof (met): atomically refresh owned harness files on every non-resumed
  attempt while preserving corpus/results separately. Test same stable ID with
  changed generated call/profile.

### ZF-19 — Work-directory generated state is incompletely refreshed/cleaned

- Status: `CLOSED`.
- Correction/proof (met): version or clear `src_instrumented`, `fake_corba`, dialect and
  compatibility caches when their producers/inputs change; make `clean --all`
  remove every owned artifact including root-level cache files. Test upgrade,
  source deletion, and clean/re-run paths.

### ZF-20 — Project-global C++ dialect cache can be poisoned by one target

- Status: `CLOSED`.
- Correction/proof (met): cache by compatible build-context fingerprint rather than one
  project-wide value; never cache a merely “fewest errors” failed dialect. Test
  mixed C++11/C++17 translation units and repair-induced header changes.

### ZF-21 — Sequence-to-direct retry can hide the direct failure

- Status: `CLOSED`.
- Correction/proof (met): retain both attempt chains and return the most actionable
  terminal diagnostic. Test sequence build failure followed by direct generation,
  unsupported, and build failures.

### ZF-22 — Ada missing-symbol classification inflates counts and repairs the unit, not the symbol

- Status: `CLOSED`.
- Correction/proof (met): deduplicate identical GNAT diagnostics per invocation; before
  proposing `AddAdaSource`, verify that the selected spec declares the missing
  symbol, otherwise report wrong-version/incomplete-unit evidence or synthesize a
  safe declaration only where valid. Test repeated diagnostics and a wrong spec
  shadowing the correct one.

### ZF-23 — Non-self-contained header roots are attempted without an owner TU

- Status: `CLOSED`.
- Correction/proof (met): preflight direct header inclusion under associated compile
  context; use an owning/umbrella TU when available, otherwise emit an explicit
  `report_only` reason. Test fragment, umbrella-only, generated, and standalone
  headers.

### ZF-24 — Receiver constructor/factory discovery is definition-local

- Status: `CLOSED`.
- Correction/proof (met): include declarations and definitions from the resolved include
  and build-context closure, keyed by qualified signatures. Test header-declared,
  sibling-TU-defined constructors/factories and static factory overloads.

### ZF-25 — One standalone C/C++ link command cannot reproduce complex TU graphs

- Status: `CLOSED`.
- Correction/proof (met): prefer a build-system-derived target/archive or compile TUs
  with their own command contexts before linking the harness; retain the current
  single-command path only as a confidence-labelled fallback. Test per-TU defines,
  generated sources, static archive, and conflicting flags.

### ZF-26 — Custom Ada naming is assumed during dependency analysis

- Status: `CLOSED`.
- Correction/proof (met): obtain unit-to-source mappings from evaluated GPR metadata or
  parsed unit declarations rather than GNAT filenames. Test arbitrary filenames
  and child units.

### ZF-27 — IDL recovery can silently omit active declarations

- Status: `CLOSED`.
- Correction/proof (met): feed project IDL defines, distinguish inactive/unsupported
  branches, checkpoint warning categories, and refuse to call a mapping complete
  when active declarations were skipped. Test function-like macros, unsupported
  expressions, and vendor pragmas.

### ZF-28 — IDL dictionary output is last-file-wins

- Status: `CLOSED`.
- Correction/proof (met): union, normalize, and deterministically write tokens from the
  aggregate IDL AST. Test disjoint tokens across multiple files.

### ZF-29 — Old K&R C has discovery/static analysis but no fuzzing lane

- Status: `EXPECTED` capability gap.
- Correction/proof (met): either implement ANSI-wrapper generation from the existing
  synthesized profiles or retain a precise `report_only` outcome that cannot be
  counted as attempted fuzzing. Test a real K&R definition through the chosen
  path.

### ZF-30 — Ada task/protected targets require scheduling wrappers

- Status: `EXPECTED` capability gap.
- Correction/proof (met): keep the explicit concurrency block, exclude it from generic
  unsupported counts, demote it below viable targets, and document the wrapper
  contract. Test protected objects, task types, and ordinary packages.

### ZF-31 — Unsupported outcomes do not carry a uniform diagnostic ledger

- Status: `CLOSED`.
- Evidence: `UnsupportedParams` has only `reason`; `repairs` and `last_errors` are
  absent by schema, producing confusing `null` queries.
- Correction/proof (met): expose a uniform structured attempt trace containing stage,
  fallback chain, decoder/type reason, and `repairs_attempted=false`, while keeping
  backward-compatible outcome fields. Test serialization and report rendering.

### ZF-36 — C++ synthesized forward declarations erase cv/ref parameter types

- Status: `CLOSED`.
- Evidence: decoder-friendly parameter emissions were reused as declaration
  types, turning `const ns::Options &` into `ns::Options`. When the real
  declaration was also visible this created a distinct overload and an ambiguous
  target call; otherwise it changed the mangled symbol and failed at link time.
- Correction: render forward declarations from the exact parsed (and
  template-substituted) target parameter types, independently of decoder local
  types.
- Proof: generation regression plus a compiled namespaced free-function
  fixture containing value, cv-reference, pointer, and container parameters.

### ZF-37 — Qualified C++ targets lose parser metadata during discovery

- Status: `CLOSED`.
- Evidence: ranked targets use `namespace::Class::method` (and a parameter
  profile for overloads), while discovery joined parser records with the leaf
  `CppFunction::name`. Every qualified function missed that join. A line-only
  replacement would still conflate declarations in compact one-line headers.
- Impact: internal-linkage namespaced functions were treated as external and
  failed at link time; foreign-platform guards could disappear; a blocked
  overload could inherit another overload's viability verdict.
- Correction: expose one canonical ranked-function identity and join metadata by
  `(original source line, full ranked identity)` everywhere.
- Proof: same-line qualified definitions with distinct linkage plus
  overloaded viability tests and an auto build.

### ZF-38 — User-constructed C++ classes are misclassified as C aggregates

- Status: `CLOSED`.
- Evidence: the C++ type parser feeds every class body to the C-shaped aggregate
  registry. A class with `T() = delete` and no public fields therefore appears as
  an empty visible struct, and codegen emits `T value{}` despite the constructor
  verdict rejecting it.
- Impact: deterministic unsupported parameters become `failed_build` with
  deleted/private/no-matching-constructor errors; ranking also falsely treats
  those signatures as viable.
- Correction: remove abstract classes and classes with user-declared
  constructors from field-wise aggregate synthesis. They can re-enter only
  through the independently verified public default-constructor registry.
- Proof: deleted/private/parameter-only constructors are demoted before
  caps and rejected before compilation; public default construction still builds.

### ZF-39 — Native GCC coverage builds lack the `trace-pc` runtime hook

- Status: `CLOSED`.
- Evidence: GCC uses `-fsanitize-coverage=trace-pc`; the driver implemented
  `__sanitizer_cov_trace_pc` only under `_WIN32`, so a native GCC build failed to
  link with repeated undefined references as soon as compiler fidelity was fixed.
- Impact: every Linux GCC-family compile-command target failed at the final
  harness link even when its project flags and source were otherwise correct.
- Correction: provide the guard-less hook on every platform; Clang guard-mode
  builds simply leave it unused.
- Proof: native GCC C and C++ harness builds and target-entry runs.

### ZF-40 — Included per-TU make fragments replace the harness default goal

- Status: `CLOSED`.
- Evidence: `build_context_objects.mk` is included before `all`/`main`; GNU make
  therefore selected the fragment's first object-directory rule as its implicit
  default, returned success, and produced no executable. Auto recorded `built`,
  then every fuzz pass failed with “no built harness executable.”
- Correction: native C/C++ builds explicitly request the `main` goal, the CLI
  build path treats a missing expected artifact as failure, and auto accepts a
  successful make status only when the executable exists.
- Proof: `native_make_build_explicitly_requests_main_after_included_object_graph`
  reproduces the misleading exit-zero condition; `auto_full_tu_link` compiles a
  GCC per-TU object graph, links the executable, enters the endpoint, and fuzzes
  it after exact source-closure recovery.

### ZF-41 — C++ class inventory was coupled to aggregate synthesis

- Status: `CLOSED`.
- Evidence: ZF-38 correctly removed user-constructed classes from the C-shaped
  aggregate decoder registry, but declaration indexing reused that filtered
  registry as the inventory of classes that exist. Real classes consequently
  vanished from collision/reachability checks, allowing repair to force-include
  a fabricated C struct over them.
- Correction: declaration indexing inventories every parsed class declaration
  through constructor/class metadata independently of the smaller set eligible
  for field-wise aggregate decoding.
- Proof: `cpp_class_defined_only_in_cpp_is_detected_header_declared_kept` and
  `field_struct_not_force_included_for_a_tree_known_cpp_class`.

### ZF-42 — Qualified type registries stopped source-only C++ type inclusion

- Status: `CLOSED`.
- Evidence: namespace-safe type definitions now store `gov::Mode`, while a
  parameter within that namespace is spelled `Mode`. The source-inclusion gate
  compared only those exact strings, omitted the implementation source, and
  emitted a harness using an undeclared enum/class.
- Correction: the conservative source-visibility gate also compares qualified
  definitions by leaf; actual type resolution remains namespace-exact and
  ambiguity-safe.
- Proof: compiled/generated qualified and source-only namespaced enum-class
  regressions in `harness_gen` and the CLI generator.

### ZF-43 — Reconciled generic Ada types can lose their package owner

- Status: `CLOSED`.
- Evidence: generic-local type rewriting depended only on `TypeOwner::Package`.
  When reconciliation retained `Codec.Hints` but lost its owner tag, generation
  named the type through an uninstantiated generic unit instead of the local
  `Govfuzz_Generic_Instance`, producing invalid Ada.
- Correction: recover ownership from the unique type declaration in the target
  generic package and qualify the local object/aggregate through the synthesized
  instance.
- Proof: `generic_package_operation_with_record_param_is_synthesized` verifies
  the instance-qualified record and fuzz-driven fields.

### ZF-44 — Repair-added C/C++ sources lose their own compile context

- Status: `CLOSED`.
- Evidence: generation-time target sources with exact compile-database rows were
  compiled through `build_context_objects.mk`, but a source discovered later by
  undefined-symbol repair was passed through `AUTO_EXTRA_SOURCES`. It was then
  compiled and linked in the harness command under the target/header owner's
  flags. A support TU whose own row required `-DSUPPORT_TU=1` consequently failed
  with that define absent.
- Correction: every make invocation partitions the complete repair-source set
  by exact compile-database row, regenerates a separate
  `repair_context_objects.mk` graph, and removes those files from the shared
  fallback command. Native, AFL, MSan, TSan, coverage, differential, and
  provenance lanes all link their corresponding repair-context objects. A graph
  preparation error is terminal instead of silently reverting to wrong flags.
- Proof: `header_compile_database_context_fuzzes_and_support_report_is_private`
  requires distinct owner- and support-TU defines, recovers the support TU only
  after an undefined symbol, builds it with GCC under its exact context, enters
  the header endpoint, executes fuzz inputs, and reports both the general and
  repair-time per-TU graph facts, row count, GCC family, C++17 standard, and
  allowlisted flag families without leaking private identifiers.

### ZF-45 — `--target` filters are case-sensitive for Ada and qualification-blind

- Status: `CLOSED`.
- Evidence: Ada discovery normalizes identifiers to lowercase, but the CLI
  compared `--target` byte-for-byte, so the natural source spelling
  `--target Compute` discarded the discovered `compute`. The target filter also
  accepted C++ `::` leaves only and searched the whole overload profile for its
  last `::`, so a qualified parameter type could be mistaken for the function
  qualifier.
- Correction: compare Ada (and the other case-insensitive compiled languages)
  without ASCII case, remove the parameter profile before finding the leaf, and
  support both `::` and dotted qualification while preserving exact/qualified-
  family selection. Case-sensitive language filters remain case-sensitive.
- Proof: unit coverage includes dotted Ada/nested qualification and a C++ profile
  containing `std::string`; the multi-IDL checked-in servant acceptance campaign
  selects `Compute` by its documented leaf spelling and fuzzes the qualified
  endpoint.

### ZF-46 — Auto never selects servant-direct and erases concrete servant types

- Status: `CLOSED`.
- Evidence: the explicit Ada `servant_direct` generator existed, but auto routed
  every Ada candidate through the ordinary direct harness. Its parameter
  resolver followed `Bar_Impl.Servant` to the external
  `PortableServer.Servant_Base` family, declared a `PortableServer.Servant`
  access value, and passed it to an operation requiring the distinct derived
  `Bar_Impl.Servant`; GNAT rejected the call.
- Correction: auto structurally recognizes an `_Impl`/declared-servant receiver
  and selects `servant_direct`. Servant generation uses the operation's declared
  concrete receiver type for the server object while consulting the resolved
  type only as recognition evidence. A failed servant generation still records
  its diagnostic before the ordinary direct fallback.
- Proof: `checked_in_derived_servant_operation_selects_servant_direct_lane` and
  `servant_direct_declares_the_concrete_derived_servant_not_its_external_base`
  cover routing and type preservation. The fresh multi-IDL checked-in servant
  campaign compiles with GNAT, enters `Compute`, and executes fuzz inputs.

### ZF-47 — Successful generation fallbacks disappear from the attempt trace

- Status: `CLOSED`.
- Evidence: when sequence generation failed and direct generation succeeded,
  `Outcome::BuiltAndFuzzed` produced the ordinary
  `generated -> built -> fuzzed` trace. The user and support collector could not
  tell that lifecycle sequencing had been attempted or why a direct harness was
  emitted, even though failed terminal paths retained both diagnostics.
- Correction: successful servant/sequence-to-direct generation fallbacks write a
  stable identifier-only checkpoint. `AttemptResult::attempt_trace` enriches
  persisted results, run reports, and support reports with that path without
  changing the backward-compatible outcome enum.
- Proof: `empty_cpp_lifecycle_records_direct_fallback_and_fuzzes` asserts the
  full recorded chain and then proves endpoint entry and fuzz executions.

## Previously identified fixes now closed

### ZF-32 — Ada run-level staging stopped after the first target closure

- Status: `CLOSED`.
- Correction: each serialized Ada attempt extends the shared staged union.
- Proof: `parallel_auto_serializes_ada_staging_and_builds_both_targets` and the
  two-overload acceptance campaign both build and fuzz multiple Ada closures.

### ZF-33 — Legacy CORBA without shipped IDL received no base scaffold

- Status: `CLOSED`.
- Correction: CORBA-like checked-in Ada bindings trigger base generation and
  fake packages join harness type analysis.
- Proof: `auto_generate_writes_base_corba_for_generated_ada_without_idl`, the
  `m10_fake_corba` GNAT builds, and the checked-in-binding acceptance campaign.

### ZF-34 — `CORBA::Environment&` was treated as attacker data

- Status: `CLOSED`.
- Correction: the C++ decoder creates a neutral environment object.
- Proof: the legacy C++ acceptance campaign declares a real
  `CORBA::Environment&`, generates its neutral call-context object, builds,
  enters the operation, and fuzzes it.

### ZF-35 — Empty C++ lifecycle sequences compiled instead of falling back

- Status: `CLOSED`.
- Correction: empty setup sequences return to the direct path.
- Proof: `empty_cpp_lifecycle_records_direct_fallback_and_fuzzes` records
  `sequence_generation_failed -> direct_fallback -> generated -> built -> fuzzed`
  and observes endpoint entry.

## Closure proof matrix

The detailed requirements above are backed by the following focused regression
and campaign evidence. Test names are stable identifiers accepted by `cargo
test`; campaign tests create new work directories and require endpoint-entry and
nonzero fuzz-execution evidence rather than merely accepting a compiler exit.

| Issue | Focused regression evidence | Campaign/build evidence |
|---|---|---|
| ZF-01 | `ada_target_line_selects_the_exact_duplicate_named_subprogram` | `ada_overloads_each_build_enter_and_fuzz_their_exact_profile` |
| ZF-02 | `generate_cpp_direct_harness_default_constructs_target_class_parameter`; private/deleted/abstract constructor tests | legacy C++ acceptance campaign |
| ZF-03 | `viable_string_endpoint_outranks_many_opaque_parameters`; `max_targets_caps_dry_run_and_sweep_consistently` | capped selection plus Ada/C++ acceptance endpoints |
| ZF-04 | `auto_generate_merges_reopened_modules_and_duplicate_includes_once` | multi-IDL checked-in servant campaign |
| ZF-05 | `cpp_header_inherits_directly_including_translation_unit_command` | header compile-database campaign |
| ZF-06 | `auto_detect_c_headers_preserves_config_before_same_stem_api`; `cpp_header_preflight_selects_a_compiling_umbrella` | legacy C++ and header campaigns |
| ZF-07 | `compile_database_preserves_compiler_abi_and_extension_context` | GCC header/per-TU campaign |
| ZF-08 | `cpp_build_context_extracts_last_standard_into_single_control`; dialect-floor tests | C++14/C++17 campaign plus honest pre-C++98 report-only tests |
| ZF-09 | `generate_cpp_harness_does_not_treat_deleted_ctor_or_temporary_as_constructible` | legacy C++ constructor-decoy campaign |
| ZF-10 | `header_member_access_resolution_is_namespace_and_overload_exact`; namespace type-registry tests | namespace-collision campaign |
| ZF-11 | registry-aware lifecycle generation/decoder tests | legacy C++ lifecycle setup campaign |
| ZF-12 | `ada_overlay_build_inherits_governing_project_semantics_from_external_work_dir` | GNAT overlay build with custom naming/scenario/config/binder/linker semantics |
| ZF-13 | `checked_in_unit_wins_over_generated_mapping_even_with_custom_filename` | multi-IDL checked-in CORBA collision campaign |
| ZF-14 | `qualified_type_lookup_does_not_cross_package_on_shared_leaf`; ambiguity regressions | Ada overload and CORBA builds |
| ZF-15 | `declared_unit_identity_deduplicates_custom_names_deterministically`; GPR scenario tests | governing-project overlay build |
| ZF-16 | preprocessing branch/original-line and C++ zero-result fallback tests | compile-context campaigns |
| ZF-17 | `load_rejects_cache_from_a_different_govfuzz_producer_or_semantics` | incompatible-resume acceptance campaign |
| ZF-18 | `ada_harness_mirror_refreshes_an_existing_stable_id` | multi-target Ada campaign |
| ZF-19 | work-state and `clean --all` unit tests | incompatible-resume/clean/re-run acceptance campaign |
| ZF-20 | `dialect_cache_is_target_and_repair_context_scoped` | conflicting C++14/C++17 TU campaign |
| ZF-21 | both `sequence_fallback_tests` terminal-chain regressions | empty-lifecycle direct-fallback campaign |
| ZF-22 | `dedups_repeated_unresolved`; `ada_missing_symbol_adds_only_a_spec_that_declares_it` | Ada build campaigns |
| ZF-23 | header preflight and `non_self_contained_header_is_report_only_not_unsupported` | owner-TU header campaign |
| ZF-24 | `cpp_receiver_uses_header_declared_static_factory_defined_in_sibling_tu` | compiled sibling-factory object graph |
| ZF-25 | `cpp_build_compiles_each_translation_unit_with_its_own_database_flags` | repair-added support-TU acceptance campaign |
| ZF-26 | declared-unit/custom-filename identity regressions | custom-naming GPR overlay build |
| ZF-27 | IDL project-define, unsupported-macro/conditional, and vendor-pragma report tests | complete multi-IDL report campaign |
| ZF-28 | aggregate IDL dictionary regressions | multi-IDL campaign verifies all three tokens |
| ZF-29 | `knr_function_is_discovered_with_knr_dialect` | `knr_target_report_only_emits_cwe_finding` |
| ZF-30 | `ada_concurrency_units_rank_below_ordinary_fuzzable_packages` | protected/task targets retain explicit wrapper-required outcomes |
| ZF-31 | `unsupported_trace_is_structured_and_never_implies_missing_repairs` | support-report v3 decision-ledger proof |
| ZF-32 | atomic shared-staging regressions | parallel and overloaded multi-target Ada campaigns |
| ZF-33 | no-IDL base-scaffold regressions | `m10_fake_corba` GNAT builds |
| ZF-34 | neutral CORBA-environment decoder regression | legacy C++ environment-reference campaign |
| ZF-35 | empty-lifecycle generation regression | successful, checkpointed direct-fallback campaign |
| ZF-36 | exact cv/ref forward-declaration regressions | compiled qualified free-function fixtures |
| ZF-37 | canonical `(line, qualified profile)` discovery joins | same-line/overload metadata and auto-build regressions |
| ZF-38 | constructed classes excluded from aggregate synthesis | deleted/private constructor ranking and build regressions |
| ZF-39 | portable GCC `trace-pc` hook tests | native GCC C/C++ target-entry campaigns |
| ZF-40–47 | focused regressions named in each issue | full-TU, header, multi-IDL, lifecycle-fallback, and target-entry acceptance campaigns |

## Diagnostic-count interpretation and intentional outcomes

- Repeated GNAT diagnostics are deduplicated per invocation, and a symbol repair
  is proposed only when the selected unit actually declares that symbol. Counts
  now represent distinct structured diagnostics rather than raw repeated lines.
- `blocked_by_concurrency` is intentional under ZF-30 and must not be repaired by
  fabricating scheduling assumptions.
- K&R `report_only` is the intentional, tested ZF-29 outcome; it is never counted
  as attempted fuzzing.
- Backward-compatible `unsupported_params` variants still do not invent
  `repairs` or `last_errors` arrays. Their uniform `attempt_trace` explicitly
  records stage, fallback chain, stable reason category, and
  `repairs_attempted=false`, removing the earlier ambiguity.

## Bug-report collector deficiencies

### BR-01 — Campaign producer identity is not checkpointed

- Status: `CLOSED`.
- The auto-run version/commit and discovery semantic version are checkpointed in support
  context. The collector binary's current version is not a substitute when it is
  run later or after an upgrade.

### BR-02 — Cache decisions and stale-artifact state are not reported

- Status: `CLOSED`.
- Privacy-safe booleans/fingerprints report discovery cache hit/producer match,
  dialect-cache presence/context match, staged-source generation, fake-CORBA
  generation, and harness refresh. Never include paths or unit names.

### BR-03 — Build-context provenance is too coarse

- Status: `CLOSED`.
- Per-language counts cover exact TU compile DB, associated-header compile
  DB, CMake/Make inference, none, actual compiler family, effective standard,
  safe forwarded flag families, and dropped flag families.

### BR-04 — Target selection and fallback chains are absent

- Status: `CLOSED`.
- The report records whether requested/selected lines matched, name fallback occurred,
  sequence/direct/receiver/factory paths attempted, and the terminal stage.

### BR-05 — Ada/IDL collision and overwrite evidence is absent

- Status: `CLOSED`.
- Count-only facts cover IDLs parsed/partially parsed, reopened modules, generated
  unit collisions, real-vs-fake collisions, duplicate staged units, and selected
  source variants.

### BR-06 — Unsupported parameter details are only scrubbed free text

- Status: `CLOSED`.
- Stable categories cover opaque class, undeclared Ada type, ambiguous type,
  inaccessible/deleted constructor, lifecycle unavailable, concurrency, and
  legacy dialect. Preserve no identifiers.

### BR-07 — The collector cannot prove whether any real target executed

- Status: `CLOSED`.
- Counts cover generated, compiled, launched, target-entry observed, fuzz-input
  executions, coverage edges, and stub-only executions. This distinguishes “built
  a driver” from “fuzzed the endpoint.”

### BR-08 — Clean/upgrade provenance is absent

- Status: `CLOSED`.
- The report records whether the work directory was created by this run, reused
  compatibly, migrated, or found stale, and includes only generation/schema
  numbers and booleans.

### Collector closure proof

`collector_reports_offline_decision_and_execution_facts_without_identifiers`
constructs one scrubbed v3 report containing BR-01 through BR-08 fields, verifies
that mirrored harnesses are not double-counted, rejects private identifiers and
paths, and enforces the 4,000-byte cap. The fresh header campaign additionally
proves associated-header GCC context, selection, attempt, repair-time per-TU
graphs, endpoint entry, and executions. The multi-IDL campaign proves reopened-
module/collision facts, and the migration campaign proves incompatible-upgrade
and cache-decision provenance. `offline_dist_scripts` verifies that
`govfuzz-bug-report.sh` is installed and packaged in the offline release; its
output is capped and can be copied as one compact text report.

## Final campaign acceptance gate

Status: `CLOSED`. All applicable defects and collector gaps are closed; ZF-29
and ZF-30 are explicitly tested intentional outcomes. The following fresh-work-
directory campaigns pass:

1. Ada overloads plus two target-specific dependency closures: both harnesses
   build, enter their intended target, and execute fuzz inputs.
2. Multi-IDL CORBA with reopened modules and checked-in bindings: no generated
   unit collisions or missing declarations; at least one servant operation is
   fuzzed.
3. Legacy C++ class API using config-before-header ordering, namespace-colliding
   types, a default-constructible parameter, an inaccessible constructor decoy,
   and a lifecycle setup: the intended endpoint is fuzzed.
4. Compile-database campaign with a header target, GCC extension flag, forced
   include, per-TU defines, and recovered standard: effective commands match the
   safe project context and at least one endpoint is fuzzed.
5. C/K&R campaign follows the ZF-29 decision and reports its status honestly.
6. Upgrade/reuse and `clean --all` campaigns demonstrate that old discovery,
   harness, fake-Ada, staging, and dialect state cannot affect the new run.
7. `govfuzz bug-report` over the campaigns remains within its byte cap, contains
   every BR-01..BR-08 fact, and contains no source paths, filenames, target names,
   unit/type/member/variable names, harness text, or corpus bytes.

Campaigns 1–4 and 6–7 are implemented in `zero_fuzz_acceptance`; campaign 5 is
implemented in `legacy_knr_c`. All successful fuzz campaigns assert both
`target_entry_observed=true` and a positive fuzz-input execution count.

### Final validation run (2026-07-23)

- `cargo test -p govfuzz --test zero_fuzz_acceptance -- --nocapture`: 6/6
  fresh end-to-end campaigns passed.
- `cargo test -p govfuzz --test legacy_knr_c`: 2/2 passed, including the
  intentional report-only boundary.
- `auto_ada_parallel`, `auto_ada_coverage`, `auto_full_tu_link`, and
  `auto_cascade`: all passed; the cascade campaign executed 29,183 fuzz inputs
  and observed three edges.
- `m10_fake_corba`: 17/17 passed with real GNAT builds.
- `offline_dist_scripts`: 14/14 passed, including release installation and
  packaging of `govfuzz-bug-report.sh`.
- `cargo test --workspace --lib --no-fail-fast -q`: all workspace library tests
  passed (`govfuzz` 1,295/1,295 and `harness_gen` 555/555 among them).
- `cargo check --workspace --all-targets`, `cargo fmt --all -- --check`, and
  `git diff --check`: passed on the final tree.
