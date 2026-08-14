# Auto-harness parity audit — 2026-08-14

## Outcome

The current generator now builds, fuzzes, and produces a comparable expert
measurement on every project in the pinned native parser/decompressor suite.
It is not universally equal to expert manual harnessing, but the former major
harnessability and protocol gaps are closed.

- 30 pinned real projects were attempted; all 30 produced comparable
  auto/expert implementation-line measurements.
- 16/30 had no expert-only line (`expert_parity`,
  `generated_exceeds_expert`).
- 21/30 were exact or within seven expert-only lines; 26/30 were within 25.
- Generated harnesses covered 50,470 comparable implementation lines versus
  46,780 for the expert harnesses. The mean generated/expert ratio was 1.130
  and the median was 1.013.
- Ratio alone is not parity: the authoritative gap signal is the set of
  expert-only lines. The 30 comparisons contain 440 expert-only lines; 308 are
  concentrated in libxml2, libarchive, and yyjson, where the generated harness
  also reaches 2,803 implementation lines the expert harnesses do not.

The largest validated improvement in the final iteration was libpng. Before
public field-precondition mining, the zeroed `png_image` failed its version gate
and covered 44 comparable lines versus the expert's 521, with 504 expert-only
lines. Mining and declaration-checking `image.version = PNG_IMAGE_VERSION`
moved the final result to 596 versus 530, with only three expert-only lines.

The gap-closing pass added six further real-code results:

- libyaml's mined bounded output-object drain moved from 450 expert-only lines
  to generated-exceeds-expert (1,925 versus 1,890).
- SQLite's out-parameter database acquisition, prepare/finalize, and close
  sequence moved from unmeasured to generated-exceeds-expert (10,093 versus
  10,078).
- libjpeg-turbo's public decompressor/error-manager lifecycle moved from failed
  build to exact parity (368/368).
- RE2's exact Parse recipe and reproducible transitive Abseil coverage closure
  moved from failed build to exact parity (1,213/1,213).
- Bidirectional size/buffer pairing and a bounded decompressor expansion budget
  moved Brotli and Zstd to exact parity in focused reruns (1,527/1,527 and
  371/371 respectively).

The ten-project expansion exercised different API shapes rather than adding
near-duplicates: annotated image buffers, POSIX regex output objects, C++
multi-file overloads, header-inline object lifecycles, Lua VM state, streaming
CSV finalization, and parser-owned result graphs. All ten now build, enter the
selected target, fuzz, and produce comparable expert coverage. Five have no
expert-only line; their mean generated/expert ratio is 1.069. The largest
before/after movements were:

- WebP moved from callback-shaped bogus parameters and 159 covered lines to a
  coherent `(data, size, output, capacity, stride)` harness covering 1,058 lines
  versus the expert's 985.
- libcsv moved from a target-never-entered polarity inversion and 86 expert-only
  lines to 204/197 covered lines with 24 expert-only lines, including the mined
  `parse → fini → free` protocol.
- msgpack moved from an uninitialized/unreleased output object to exact parity
  through header-inline `init → target → destroy` lifecycle recovery.
- PCRE2 moved from an uncompilable return-type declaration, then an unsafe
  destructor-only sequence, to a direct zero-flag compile harness with guarded
  `regfree`: 2,813/2,696 lines and only eight expert-only lines.
- Snappy, cmark, and tomlc99 reached exact parity; Lua exceeds its expert
  baseline after unrelated lexical test calls were excluded from the protocol.

## Method

`projects.tsv` pins each upstream repository, commit, selected API, source file,
and reviewed expert harness. The runner hides maintained fuzz entrypoints from
recipe mining with `GOVFUZZ_BLIND_EXPERT_HARNESSES=1` and names the exact
baseline with `GOVFUZZ_EXPERT_HARNESS`; the auto generator cannot inspect the
baseline it is measured against.

Each auto campaign used one selected target, probe-build recovery, one
five-second fuzz-driven pass, one job, comparison-progress instrumentation, and
no sanitizers for the coverage pass. The generated corpus was replayed through
both harnesses. The oracle compares covered `source:line` coordinates only in
project-owned implementation translation units instrumented in both binaries;
expert drivers, generated harness code, and repair stubs are excluded.

This is a short, deterministic parity screen, not a claim about asymptotic bug
yield. Longer multi-seed campaigns, sanitizer findings, execution rate, and
semantic invariant quality should be a second benchmark dimension. Replaying
one common corpus isolates harness semantics, but can favor either harness when
the two map the same bytes into different argument structures.

## High-value levers implemented

- Declaration-checked C protocol traces now retain input offsets, length
  transforms, byte predicates, comparison ranges, result masks, prior-call
  values, and callback-time state transitions instead of flattening everything
  into independently decoded arguments.
- C lifecycle recovery is tree-wide and batched. Initializer signatures hidden
  in sibling headers/sources, boolean versus errno-style success polarity,
  returning handles, derived handles, teardown, and mutually exclusive input
  configuration families are modeled.
- Maintained public aggregate preconditions are mined only when they precede a
  same-family endpoint on the same receiver, use a safe literal/public constant,
  and name a field proven by the selected handle declaration.
- Multiple public callback actions observed behind one registration are emitted
  as bounded input-selected alternatives.
- Mixed K&R/ANSI C dialect classification is per function, so an old-style
  definition no longer makes normal functions in the same file report-only.
- Sequence mutation has an explicit operation layout, coverage-novelty energy,
  under-explored-lane weighting, and persisted portfolio feedback.
- Coverage replay checkpoints the exact successful build closure, uses the
  probe-built coverage archive, links common platform libraries, accepts an
  exact expert harness, and compares project implementation rather than glue.
- CMake coverage recovery now follows exact transitive archive closures,
  tolerates usable partial configurations, reuses same-relative artifacts when
  optional CMake metadata is absent, and preserves command-local linker search
  paths while appending portable system libraries.
- Expert-oracle builds recover the actual repository boundary and the generated
  Makefile's compile-context include roots, so nested source directories and
  sibling dependencies are compared under the same build context.
- Public exact protocols cover libjpeg decompression, SQLite VM preparation,
  RE2 parsing, and bounded output-object drain/cleanup loops. Generic C argument
  modeling now couples both `(buffer, size)` and `(size, buffer)` forms and gives
  expanding one-shot decompressors a fixed bounded destination budget.
- Contract annotation macros such as `*_COUNTED_BY(size)` are masked before C
  parsing without changing source positions, so byte pointers remain buffers
  rather than becoming fake callbacks.
- Arrays of pointers preserve declarator order, and both `(array, count)` and
  `(count, array)` signatures allocate storage with a coherent shared extent.
- Header-defined `static inline` lifecycle functions participate in direct
  output-object setup/cleanup. Destructor-only objects are cleaned only after a
  successful status and cannot enable an uninitialized stateful sequence.
- Mined lexical protocols retain only the selected target, declaration-checked
  configuration, target-result dependencies, and evidenced non-owning
  finalizers; a single sample-sized target call is rebound to the full fuzz span.
- Expert coverage builds recover direct source closures from the generated
  Makefile, closing multi-file oracle failures such as Snappy without adding
  project-specific source lists.
- `GOVFUZZ_EXPERT_COVERED_LINES` supplies the same oracle for any language whose
  expert runner can emit `source:line` coverage. It accepts a single file or a
  per-harness directory, so interpreted/JVM ecosystems are not forced through a
  fake C/C++ build path.

## Remaining shortcomings, ordered by value

1. **Union complementary semantic modes.** libxml2, libarchive, and yyjson
   account for 308 of the remaining 440 expert-only lines, despite a combined
   generated-only surplus of 2,803 lines. The next useful lever is a portfolio
   oracle that
   retains both argument/configuration mappings when each contributes unique
   implementation coverage, rather than choosing one winner from a scalar
   total.

2. **Derive output geometry from public probe APIs.** WebP's generated harness
   exceeds the expert's total coverage but retains 35 expert-only lines because
   it fuzzes output stride/capacity while the expert calls `GetInfo` and derives
   `stride = width * channels`, `capacity = stride * height`. Generalize this as
   a declaration-checked `probe(input, size, &dims...) → checked allocation →
   decode-into` protocol for image/media APIs.

3. **Trace control flow rather than lexical call lists.** The current miner can
   represent useful predicates, repetitions, and alternatives, but cannot yet
   retain arbitrary loop topology. A small declaration-checked CFG/SSA slice
   around the selected call would reduce residual alternative states without
   copying entire upstream harnesses.

4. **Generalize exact public recipes from declarations and documentation.** The
   narrow library recipes are intentionally signature-gated and safe, but a new
   library with the same public protocol will not automatically inherit them.
   Promote their common pieces—out-handle success predicates, macro-shaped
   constructors, output cleanup, and terminal conditions—into declaration-
   checked protocol IR.

5. **Measure semantic and bug-finding parity.** Add multiple deterministic
   seeds and 30–120 second campaigns, compare edge sets plus sanitizer/oracle
   findings, and track time-to-first unique state. Keep expert-only lines as a
   regression gate; a generated-only line surplus must never erase a distinct
   expert path.

## Audit of code pushed today

The only commit dated 2026-08-14 in the local history was `8879267` (`fix(idl):
parse the IDL projects ship, and emit Ada that GNAT accepts`). No functional
defect was found in that commit after the expanded validation below. “Bug-free”
cannot be proven by testing, but the parser/emitter changes and their GNAT-backed
paths are passing.

- The final CLI, harness-generator, and C-parser library suites passed: 1,625,
  595, and 69 tests respectively. The broader workspace library validation also
  passed its 80 runtrace-shim tests and all IDL/fake-CORBA unit tests.
- `m10_fake_corba`: 17/17 passed, including legacy/annotated IDL mapping and
  GNAT-available build paths.
- `auto_legacy_audit_fixes`: 2/2 passed, including mixed K&R/ANSI discovery and
  Ada target entry.
- `ioctl_control_plane`: 1/1 passed.
- Release build, formatter check, diff whitespace check, and benchmark-runner
  Python smoke check passed.

The exact final per-project measurements are in `results/results.tsv` and the
compact table is in `results/summary.md`.
