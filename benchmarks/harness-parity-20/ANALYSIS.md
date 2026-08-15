# Auto-harness parity audit — 2026-08-14

## Outcome

The current generator now builds, fuzzes, and produces a comparable expert
measurement on every project in the pinned native parser/decompressor suite.
It is not universally equal to expert manual harnessing, but the former major
harnessability and protocol gaps are closed.

- 30 pinned real projects were attempted; all 30 produced comparable
  auto/expert implementation-line measurements.
- 19/30 had no expert-only line (`expert_parity`,
  `generated_exceeds_expert`).
- 25/30 were exact or within seven expert-only lines; 29/30 were within 25.
- Generated harnesses covered 50,340 comparable implementation lines versus
  48,742 for the expert harnesses. The mean generated/expert ratio was 1.106
  and the median was 1.001.
- Ratio alone is not parity: the authoritative gap signal is the set of
  expert-only lines. The 30 comparisons now contain 123 expert-only lines, down
  from 440. No remaining project has more than 40, and 19 have none.

An earlier large validated improvement was libpng. Before
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

The follow-up pass measured the largest remaining deficits against the same
real expert harnesses and closed their missing semantics:

- yyjson moved from 87 expert-only lines to exact 919/919 parity by treating
  public `*_flag`/`*_flg` typedefs as scalar control domains while refusing to
  pin aggregate options.
- libxml2 moved from 123 expert-only lines to three by recognizing optional
  in-memory parser metadata (`URL`, encoding, and related context strings) and
  passing null when no independent metadata source exists.
- libarchive now preserves both useful stream-consumption modes in a two-lane
  portfolio: bounded data draining and public entry skipping. Expert-only lines
  fell from 98 to 40; both lanes found unique coverage in the focused run.
- WebP moved from 35 expert-only lines to generated-exceeds-expert
  (1,174/1,042 with no expert-only line) by probing public image dimensions and
  deriving checked output stride/capacity, with a fuzzed fallback when the probe
  rejects the input.
- libucl moved from 17 expert-only lines to exact 1,623/1,623 parity through a
  generic successful-feed completion step that acquires and releases the
  parser-owned result object.
- libcsv's lifecycle remains declaration-derived across opaque source-local
  receiver definitions: `init → parse → fini → free` is emitted and entered,
  leaving 24 short-campaign expert-only lines rather than regressing to a direct
  target call.

The ten-project expansion exercised different API shapes rather than adding
near-duplicates: annotated image buffers, POSIX regex output objects, C++
multi-file overloads, header-inline object lifecycles, Lua VM state, streaming
CSV finalization, and parser-owned result graphs. All ten now build, enter the
selected target, fuzz, and produce comparable expert coverage. Five have no
expert-only line in the initial expansion run; seven do after the follow-up.
The largest before/after movements were:

- WebP moved from callback-shaped bogus parameters and 159 covered lines to a
  coherent, public-geometry-derived decode-into harness covering 1,174 lines
  versus the expert's 1,042, with no expert-only line.
- libcsv moved from a target-never-entered polarity inversion and 86 expert-only
  lines to 193/197 covered lines with 24 expert-only lines, including the mined
  `parse → fini → free` protocol.
- libucl's parser-owned result acquisition and release now make its generated
  and expert coverage sets identical at 1,623 lines.
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
- Scalar control flags are inferred from declaration names and flag typedefs,
  including common abbreviations, without mistaking aggregate configuration
  objects for bitmasks.
- Optional metadata trailing a proven in-memory `(buffer, length)` input is
  modeled as null unless a declaration-checked source exists.
- Stream protocols may retain complementary drain and skip lanes when both are
  public, receiver-compatible, bounded, and coverage-productive.
- Successful boolean feed APIs can acquire and release a returned object graph
  through public same-family getter/destructor pairs.
- Decode-into APIs with public image-info probes derive overflow-checked output
  dimensions, stride, and capacity while retaining a safe fallback path for
  malformed inputs.
- Explicit `--sanitizers none` now disables post-campaign sanitizer replays,
  and TSan replay stops the remaining corpus when its global timeout budget is
  exhausted instead of spending a fresh timeout on every input.

## Remaining shortcomings, ordered by value

1. **Trace control flow rather than lexical call lists.** The current miner can
   represent useful predicates, repetitions, and alternatives, but cannot yet
   retain arbitrary loop topology. A small declaration-checked CFG/SSA slice
   around the selected call would reduce residual alternative states without
   copying entire upstream harnesses.

2. **Generalize exact public recipes from declarations and documentation.** The
   narrow library recipes are intentionally signature-gated and safe, but a new
   library with the same public protocol will not automatically inherit them.
   Promote their common pieces—out-handle success predicates, macro-shaped
   constructors, dimension probes, output cleanup, and terminal conditions—into
   declaration-checked protocol IR.

3. **Bootstrap format-valid corpora and measure lane stability.** libarchive's
   remaining 40 lines and libcsv's 24 fluctuate in five-second campaigns even
   though the corresponding expert operations are present. Seed each retained
   protocol lane with minimal public-format exemplars, repeat seeds, and report
   confidence intervals so corpus luck is not mistaken for a harness deficit.

4. **Model multi-plane and callback-owned output geometry.** The new checked
   geometry path covers interleaved decode-into APIs. Planar image/audio outputs,
   caller-supplied row callbacks, and APIs whose probe returns a richer public
   descriptor still need a bounded allocation graph rather than independent
   pointer guesses.

5. **Measure semantic and bug-finding parity.** Add multiple deterministic
   seeds and 30–120 second campaigns, compare edge sets plus sanitizer/oracle
   findings, and track time-to-first unique state. Keep expert-only lines as a
   regression gate; a generated-only line surplus must never erase a distinct
   expert path.

## Audit of code pushed today

The audit covered the day's functional commits: `8879267` (`fix(idl): parse the
IDL projects ship, and emit Ada that GNAT accepts`), `3533b5c` (`feat(auto):
close expert harness parity gaps`), and this follow-up. The automated dependency
updates were also included in the workspace build. “Bug-free” cannot be proven
by testing, but the changed parser/emitter, auto-harness, replay, and GNAT-backed
paths are passing.

The follow-up validation caught and fixed two regressions before publication.
The first WebP geometry version rejected malformed probe inputs before target
entry; it now retains a safe generic capacity/stride fallback. The first
typedef-aware flag rule also pinned real enum modes and Windows `BOOL` inputs;
it is now restricted to direct integers or explicitly flag-shaped scalar/enum
typedefs. Real-project reruns verify target entry for every updated row.

- The final CLI, harness-generator, and C-parser library suites passed: 1,629,
  597, and 69 tests respectively. The broader workspace library validation also
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
