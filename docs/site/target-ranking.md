<!-- SPDX-License-Identifier: Apache-2.0 -->

# Target Ranking

`govfuzz auto` can discover far more candidate functions than a time-boxed
campaign can build and fuzz. Target ranking decides attempt order. It is a
deterministic scheduling heuristic, not a prediction that a function contains a
vulnerability.

The objective is to maximize the number and value of targets that reach the
evidence gate within a fixed campaign budget. A high-priority target should have:

1. a credible attacker-controlled input channel;
2. a broad, meaningful program boundary; and
3. a signature and lifecycle the current harness generator can reasonably
   construct.

Ranking does not prove any of those properties at runtime. Build viability,
target-entry checkpoints, real-project coverage, replay, and provenance remain
authoritative. When a high-ranked target cannot proceed, the campaign backfills
from the remaining ranked candidates.

## Pipeline

```text
parse source
  → enumerate language-specific candidates
  → gate targets known to be inaccessible or non-callable
  → classify attacker-input reachability
  → add value, risk, and harnessability signals
  → subtract wrong-layer, low-value, and construction penalties
  → apply the C/C++ call-graph adjustment
  → sort by score, then deterministic identity fields
  → attempt highest priorities and backfill around failures
```

The score is therefore a campaign priority. It is not a vulnerability
probability, severity, confidence value, coverage guarantee, or replacement for
expert target selection.

## Two classes of evidence

The named score contributions answer two different questions:

### Target value

How promising is this target as attack surface? These signals include:

- an attacker-facing parser, decoder, validator, or security-sensitive action;
- a whole-artifact or general dispatch boundary;
- unsafe, exception-heavy, or otherwise risk-relevant behavior where the
  language exposes it; and
- call-graph evidence that the function orchestrates broad project behavior
  rather than duplicating a narrow operation already reached through a caller.

“Target value” means expected attack-surface relevance and breadth. It does not
mean that GovFuzz has predicted the function is vulnerable.

### Harness feasibility

How likely is the current automation to drive the target correctly? These
signals include:

- a direct byte, string, stream, or path channel;
- coherent pointer/length or self-describing input;
- manageable arity, public callability, and observable return behavior;
- a fuzz declaration or method already used by another fuzzing framework; and
- penalties for inaccessible types, pre-built state, opaque receivers, or other
  construction requirements the generator cannot safely satisfy.

Some features carry both kinds of evidence. A proven byte channel is relevant
attack surface and also easy input plumbing. The documentation assigns each
signal to its primary explanatory role and never counts it twice.

The current implementation adds named contributions into one campaign-priority
score. The two classes above are an explanatory grouping, not two independently
calibrated values emitted by the CLI.

## Identifier tokens

Function names contain weak but useful semantic evidence. GovFuzz lowercases
identifiers and splits them at:

- underscores and hyphens;
- namespace and member separators; and
- lower-to-upper camel-case boundaries.

Examples:

```text
parse_packet        → parse | packet
decodeFrame         → decode | frame
unmarshalFromString → unmarshal | from | string
Reader::readObject  → reader | read | object
```

Action stems match at the beginning of tokens. This allows related forms such as
`parse` and `parser`, or `normalize` and `normalization`, to contribute the same
kind of semantic evidence across naming conventions. A name signal never stands
alone: parameter types, input direction, call relationships, constructibility,
and runtime proof are separate checks.

Implementation: [`name_semantics.rs`](https://github.com/Tarmo-Technologies/govfuzz/blob/main/crates/target_rank/src/name_semantics.rs).

## C and C++ scoring

The C/C++ signature scorer uses named additive fields so that each score can be
explained and tested.

| Primary class | Signal | Weight | Engineering rationale |
|---|---|---:|---|
| Harness feasibility | Read-only attacker-input byte buffer | +30 | Strongest signature-level evidence that arbitrary testcase bytes can cross the target boundary directly; read-only direction helps distinguish consumed input from output storage |
| Harness feasibility | Length paired with a buffer, or self-describing input | +15 | Makes the byte channel coherent and constructible; supporting evidence rather than a target by itself |
| Harness feasibility | Error-code-shaped return | +10 | Supplies observable accept/reject behavior, but says less about target breadth |
| Target value | Parser/decoder action token | +15 | Adds semantic input-processing intent with less authority than a concrete input channel |
| Harness feasibility | Arity of 1–4 | +5 | Small constructibility tie-breaker; convenience must not dominate target value |
| Target value | Whole-artifact `from_memory`, `from_buffer`, `from_bytes`, or `from_string` entry | +30 | Strong indication of an end-to-end boundary likely to exercise more of the format pipeline |
| Target value | General `parse/load/read/decode/..._from_*` entry | +10 | Adds a breadth preference for dispatch across formats or modes |
| Target value | Helper/static marker | −20 | Softly moves likely narrow implementation helpers behind public boundaries without removing them from backfill |
| Target value | No proven attacker channel | −20 | Softly demotes caller-controlled or ambiguous surfaces until reachability can be established |
| Target value | Output serializer | −40 | Stronger demotion because the buffer direction points away from the attacker-facing parse surface |
| Harness feasibility | Requires pre-built token/AST context | −60 | Dominant construction penalty: raw fuzz bytes cannot safely recreate already-parsed state |
| Target value | Compression-direction codec | −25 | Prefers the attacker-facing decode direction while retaining the candidate |
| Harness feasibility | Static/internal opaque `void *` context special case | additional −100 | Prevents an artifact-prone target that is difficult to construct from outranking a public boundary |

Known non-callable C++ targets, including inaccessible members and unresolved
templates, are filtered before scoring. Allocator free/reallocation primitives
are also excluded because fabricating their pointer ownership would create
harness artifacts.

Why is the byte-buffer signal worth 30? A fuzzing engine fundamentally produces
bytes. A target that accepts those bytes directly gives the generator a short,
low-assumption path from testcase to project code: allocate the testcase,
preserve every byte, and pass its address. The read-only type qualifier is also
directional evidence that the function consumes the buffer; without that
evidence, a mutable pointer may instead be destination storage for a serializer.
This makes the signal more authoritative than a suggestive name (`+15`) or
convenient arity (`+5`), so it receives one of the largest base bonuses.

The 30 points do not mean that the function is vulnerable, broad, or even a
complete target. A matching length or self-describing type supplies another 15
points because the buffer still needs a coherent extent. Name, whole-artifact,
call-graph, and runtime evidence answer different questions. The implementation
also recognizes mutable in-place parser buffers, but only after additional
parser and length evidence classifies them as attacker input; an ordinary output
buffer does not receive this bonus.

Implementation: [`c_rank.rs`](https://github.com/Tarmo-Technologies/govfuzz/blob/main/crates/target_rank/src/c_rank.rs).

### C/C++ call-graph adjustment

Signature evidence cannot always distinguish a public parser from the narrow
operations below it. GovFuzz therefore constructs an approximate in-tree call
graph for C and C++ candidates:

- an attacker-input target with `fan_out >= 3` gains
  `3 × min(fan_out − 2, 12)`; and
- a target with `fan_out == 0` and at least one in-tree caller loses 20.

Fan-out is evidence that a function coordinates several parsing stages. The
bonus starts at three callees to avoid rewarding incidental delegation, grows
gradually, and is capped so project size cannot dominate the score.

A called leaf has the opposite shape. It is more likely to be a narrow operation
already reachable through a broader entry point. Directly fuzzing it can
duplicate effort and omit state established by its caller. The −20 adjustment is
a soft demotion, not a filter: the leaf remains available when higher-ranked
targets fail or the campaign has additional budget.

The graph is approximate. It uses source-level function boundaries and in-tree
call names rather than a compiler-complete interprocedural graph. Runtime
evidence can override its scheduling decision.

Implementation: [`discovery.rs`](https://github.com/Tarmo-Technologies/govfuzz/blob/main/crates/cli/src/auto/discovery.rs).

## Worked comparison

Consider two plausible targets with the same input shape:

```c
int parse_from_memory(const uint8_t *data, size_t length);
int parse_chunk(const uint8_t *data, size_t length);
```

Assume the call graph shows `parse_from_memory` calling six distinct project
functions, including `parse_chunk`, while `parse_chunk` calls no other in-tree
function.

```text
parse_from_memory                         fan_out = 6
├── validate_header
├── detect_format
├── parse_metadata
├── parse_chunk                           fan_out = 0 · callers = 1
├── validate_checksum
└── finalize_document
```

The child names other than `parse_chunk` are illustrative; the adjustment uses
the observed number of distinct in-tree callees and whether the target is a
called leaf.

| Class | Evidence | `parse_from_memory` | `parse_chunk` |
|---|---|---:|---:|
| Harness feasibility | Read-only fuzz-input buffer | +30 | +30 |
| Harness feasibility | Matching length | +15 | +15 |
| Harness feasibility | Error-code-shaped return | +10 | +10 |
| Harness feasibility | Two-argument arity | +5 | +5 |
| **Harness feasibility** | **Subtotal** | **60** | **60** |
| Target value | Parser action token | +15 | +15 |
| Target value | Whole-artifact `from_memory` boundary | +30 | 0 |
| Target value | General `parse_from_*` dispatch | +10 | 0 |
| **Target value** | **Base subtotal** | **55** | **15** |
| **Combined** | **Base score** | **115** | **75** |
| Target value | Call-graph adjustment | +12 | −20 |
| **Target value** | **Final subtotal** | **67** | **−5** |
| **Combined** | **Campaign priority** | **127** | **55** |

The harness-feasibility subtotal is identical. Both functions are equally easy
for the current generator to call. The first target ranks higher because its
target-value evidence identifies a whole-input boundary that coordinates more
of the project. Attempting it first may reach `parse_chunk` plus the validation,
dispatch, and state around it.

The lower score does not mean that `parse_chunk` is safe, unimportant, or less
vulnerable. It means that, under a limited campaign budget and the available
source evidence, the broader target should be attempted first. The leaf remains
in the ranked list for backfill.

## Language-specific scoring

The common objective is stable across languages, but each parser exposes
different evidence. One universal formula would obscure those differences.
The same target-value versus harness-feasibility distinction still applies. For
example, unsafe or security-sink signals primarily describe target value;
visibility, simple input channels, existing fuzz declarations, and constructible
receivers primarily describe harness feasibility.

### Ada

The structural Ada ranker includes public/library-level visibility `+20`, an
untrusted input parameter `+15`, a parser name `+15`, each fuzzable parameter
`+5`, swallowed `when others` in the package `+15`, each explicit raise in or
below the operation `+10`, and each handler in or below it `+8`. Serializer names
receive `−20`; an unsupported fuzz-input type receives the dominant `−1000`
harness-viability penalty. Smaller signals cover constrained scalars,
arrays/slices, variants, access types, dispatch, middleware, concurrency,
accessors, and limited-private inputs.

Implementation: [`score.rs`](https://github.com/Tarmo-Technologies/govfuzz/blob/main/crates/target_rank/src/score.rs) and [`heuristics.rs`](https://github.com/Tarmo-Technologies/govfuzz/blob/main/crates/target_rank/src/heuristics.rs).

### Rust

A `fuzz_target!` declaration used by cargo-fuzz/libFuzzer-based targets receives
`+100`; byte/string/reader channel `+30`; parser name `+15`; unsafe/raw-pointer
surface `+15`; free/associated function `+8`; arity 1–4 `+5`; getter/writer
`−20`; no byte channel `−20`; and unconstructible trait method `−60`. Private,
documentation-hidden, and test-only functions are gated out.

Implementation: [`rust_rank.rs`](https://github.com/Tarmo-Technologies/govfuzz/blob/main/crates/target_rank/src/rust_rank.rs).

### Java

A Jazzer `fuzzerTestOneInput` method receives `+100`; byte/string/stream channel
`+30`; security-sink name `+25`; parser name `+15`; directly callable static or
constructor `+10`; byte-channel method declaring checked exceptions `+8`; arity
1–4 `+5`; no byte channel `−20`; getter/writer `−20`; throwable constructor
`−40`; and low-value helper `−35`. Non-public, abstract, or enclosing-type-
inaccessible methods are gated out.

The Rust and Java bonuses recognize declarations and methods that other fuzzing
frameworks already use. These constructs explicitly declare fuzzing intent and
define an existing mutated-input boundary.

Implementation: [`java_rank.rs`](https://github.com/Tarmo-Technologies/govfuzz/blob/main/crates/target_rank/src/java_rank.rs).

### Go

Byte/string/reader channel `+30`; parser name `+25`; arity 1–3 `+10`; free
function `+8`; receiver `−10`; getter/writer `−20`; registry/callback/opaque
surface `−25`; and no byte channel `−25`. A zero-argument terminal method with a
same-receiver public byte feeder receives `+105`, allowing the lifecycle pair to
surface. Unexported functions are gated out.

Implementation: [`go_rank.rs`](https://github.com/Tarmo-Technologies/govfuzz/blob/main/crates/target_rank/src/go_rank.rs).

### Python and Perl

Python uses byte channel `+30`, parser name `+25`, arity 1–3 `+10`, callable
without receiver `+8`, receiver `−10`, getter/writer `−20`, path wrapper `−20`,
low-value helper `−35`, and no byte channel `−25`.

Perl uses string sink `+10`, parser name `+25`, callable without receiver `+8`,
receiver `−10`, getter/writer `−20`, and low-value helper `−35`. Constructors,
lifecycle hooks, and private subs are gated out.

Implementations: [`python_rank.rs`](https://github.com/Tarmo-Technologies/govfuzz/blob/main/crates/target_rank/src/python_rank.rs) and [`perl_rank.rs`](https://github.com/Tarmo-Technologies/govfuzz/blob/main/crates/target_rank/src/perl_rank.rs).

### Name-prior lanes

COBOL, Fortran, C#, JavaScript/TypeScript, Ruby, Lua, and PHP currently use a
semantic name prior. It starts at 50, adds 45 for parser/decoder/validator actions
or 25 for useful transformation actions, adds 15 for `from_*` and 10 for data-
format nouns, then demotes low-value helpers `−35`, path names `−25`, lifecycle/
registry verbs `−20`, and selected framework-host namespaces `−45`.

Implementation: [`discovery.rs`](https://github.com/Tarmo-Technologies/govfuzz/blob/main/crates/cli/src/auto/discovery.rs).

## Inspecting a ranking

Print the full ranked candidate list without building or fuzzing:

```sh
govfuzz auto path/to/src --list-targets
```

Use `--languages` to narrow the list without changing the cached discovery:

```sh
govfuzz auto path/to/src --languages c,cpp --list-targets
```

Candidates are ordered by descending score and then deterministic identity
fields. The Ada listing currently serializes its named per-signal breakdown.
Other typed rankers calculate named breakdown structures internally, but the
standalone listing currently exposes only their total score and identity.
Uniform per-lane score explanations are planned work.

`--max-targets N` applies the ranking to campaign admission. It keeps the top N
candidates after language filtering; `--list-targets` continues to show the full
ranked list.

## Testing and tuning

The weights are engineering priorities, not learned coefficients or calibrated
probabilities. Validation has four layers:

1. **Unit tests** exercise identifier splitting, individual score fields,
   eligibility gates, deterministic sorting, and language-specific rules.
2. **Ordering regressions** reproduce ranking failures found in real projects
   and assert the intended relative order, such as a public orchestrator above
   the leaf operations it invokes.
3. **Multi-project campaigns** test whether selected candidates actually build,
   accept fuzz-controlled data, enter the intended endpoint, and gain project
   coverage. Repeated high-score/build-blocked or shallow outcomes show that a
   feature is rewarding the wrong property.
4. **Expert comparisons** check whether automatic selection chooses the same
   semantic boundary and use the score breakdown and coverage evidence to
   explain differences.

The tuning procedure is conservative:

1. classify a recurring ranking failure;
2. change the smallest relevant feature or weight;
3. add a regression test;
4. rerun the broader fixture and campaign set; and
5. check that the change did not invert previously correct rankings.

Crash counts are not used as a direct weight-fitting objective. Findings are
sparse and would encourage overfitting to a small benchmark.

Useful focused tests include:

```sh
cargo test -p target_rank
cargo test -p govfuzz callgraph_ranks_orchestrator_entrypoint_above_leaf_helpers
```

## Current limitations

- The weights are hand-tuned and language-specific.
- The source-level C/C++ call graph is approximate and is not applied to every
  language lane.
- New frameworks, naming conventions, generated code, and lifecycle patterns
  continue to produce counterexamples.
- A high score does not guarantee that the project can be built in the supplied
  environment.
- Similar target entry or line coverage does not prove expert-equivalent input
  modeling or state construction.
- Score reporting is not yet equally detailed across all language lanes.

Ranking is intentionally revisable. Later build, target-entry, coverage, replay,
and expert-evidence gates can override it, and campaign failures should feed back
into the regression suite rather than be hidden behind a total score.
