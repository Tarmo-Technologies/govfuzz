<!-- SPDX-License-Identifier: Apache-2.0 -->

# govfuzz finding & report field reference

Every field `govfuzz auto` emits for a finding, what it means, and how to read it.

## Where the data lives

A run writes, under `<work-dir>/auto/`:

| Artifact | What it is |
|---|---|
| `run.md` | Human-readable run summary (targets built/fuzzed/skipped, findings, missing build deps). |
| `run.json` | The same, machine-readable. |
| `findings.csv` | One row per finding — see [findings.csv](#findingscsv). |
| `<...>/findings/F-NNNN-<sig>/finding.json` | The full per-finding record (all fields below). |
| `<...>/findings/F-NNNN-<sig>/testcase.bin` | The crashing input (the reproducer). |
| `<...>/findings/F-NNNN-<sig>/replay.py` | Standalone replay script (runs the harness on the testcase). |

The per-finding writeup in `run.md` is a rendering of `finding.json`; this doc
describes the underlying fields.

---

## Identity & deduplication

| Field | Meaning |
|---|---|
| `id` | The finding id, `F-NNNN-<short-signature>` (e.g. `F-0000-1028b5d3`). Stable within a run; the suffix is the first 8 hex of `signature`. |
| `signature` | Full SHA-256 of the dedup key (the matched `rule_id` + the normalized crash stack). Two findings with the same `signature` are the same bug. |
| `cluster_key` | Short (8-hex) crash cluster id — groups findings whose **normalized** stacks match, so 50 mutated inputs that hit the same bug collapse to one cluster. Use this to count *distinct* bugs. |
| `cluster_key_full` | The full cluster hash (`cluster_key` is its prefix). |
| `cluster_normalized_frames` | The normalized stack frames (allocator/runtime/harness frames stripped, addresses/templating removed) used to compute the cluster. This is the "shape" of the crash. |
| `cluster_fallback` | `true` when normal clustering couldn't be computed (e.g. no usable stack) and govfuzz fell back to the full signature as the cluster key (then `cluster_key` is 16-hex, not 8). A `true` here means "couldn't cluster confidently — may over-split duplicates." |

---

## What crashed

| Field | Meaning |
|---|---|
| `exception.name` | The crash class, normalized (e.g. `ASAN_HEAP_BUFFER_OVERFLOW`, `LSAN_MEMORY_LEAK`, `SIGSEGV`, `UBSAN_*`). |
| `exception.sanitizer` | Which sanitizer reported it: `asan`, `ubsan`, `lsan`, `msan`, `tsan`, or none for a raw signal. |
| `exception.message` | The first line of the sanitizer/runtime error message, verbatim. |
| `exception.stack[]` | The crash stack: `{file, function, line}` per frame (top frame first). Frames without source info show only `function`. For Ada findings, `exception.source_file`/`source_line` are remapped to the developer's original (pre-instrumentation) lines. |
| `classification` | How the fault surfaced relative to the target's own error handling: <br>• `unhandled` — the exception/crash escaped the target up to the harness top level → treat as a **real fault** (crash / DoS). <br>• `swallowed_predefined` — a built-in runtime check (sanitizer, bounds, assert) caught it inside the target → a **masked** memory-safety/DoS bug; review whether it's exploitable with checks suppressed or in a C/C++ port. <br>• `swallowed_user` — the target's *own* code caught it (a user handler). Often intended handling, sometimes a masked bug. |
| `rule_id` | The govfuzz finding **rule** that matched, `GF-NNN` (e.g. `GF-101`). Stable id you can grep; identifies the detector that fired (a sanitizer class, an OOM rule GF-209, etc.). |
| `dialect` | The language of the crashing code: `c`, `cpp`, `ada`, `rust`, `java`, or `unknown`. Drives language-specific rendering (e.g. the Ada reproducer only renders for `ada`). |
| `runtime_mode` | The execution mode that produced the finding (e.g. `reporting`). |

---

## `actionability` — is it worth your time, and where to fix it

This object is govfuzz's triage verdict. It exists to answer "should I look at this,
and where?" before you open the stack.

| Field | Meaning |
|---|---|
| `verdict` | Reachability assessment: <br>• `real_reachable` — confirmed reachable from attacker-controlled input. <br>• `likely_reachable` — reachable through the public/fuzzed entry, not independently re-confirmed. <br>• `lab_only` — only reproduced under the lab harness / with stubs; not shown reachable in a real build. <br>• `blocked` — a validator/gate is believed to block it. <br>• `unknown` — undetermined. |
| `impact` | Severity estimate: `critical` / `high` / `medium` / `low` / `info` / `unknown`. `info` = **not a defect** (e.g. the target rejecting malformed input via its own declared exception), shown for visibility; distinct from `low` (a minor *real* defect) and `unknown` (undetermined). |
| `confidence` | The **categorical** triage confidence: `high` / `medium` / `low`. Lowered when the finding leans on synthetic scaffolding (see `prosthetics`) or an unresolved fix location. **Not** the severity — it's confidence in the *assessment*. This is the coarse bucket; there is also a separate **numeric** model confidence — see [Two confidences](#two-confidences). The `findings.csv` `confidence` column is this categorical value. |
| `entry_path` | How attacker input reaches the bug: `{kind, source, target}` — e.g. `kind: "harness"`, `source: "testcase.bin"` (the input that drives it), `target: <harness_id>`. |
| `input_reachability` | How the fuzz input reaches the crashing code: `attacker_reachable` (a read-only untrusted-input buffer parameter), `output_serializer` / `reachability_unproven` (the fuzzed args are caller-controlled — a crash is a harness artifact unless separately proven), or `ipc_channel_reachable`. The last means the function has no input-buffer parameter but the run drove the crash with fuzz data read from a **virtualized IPC channel** (POSIX/System V shared memory, a POSIX message queue, or MMIO `/dev/mem`) — so it *is* input-reachable (and `verdict` is `likely_reachable`, not downgraded), attacker-controlled if that channel crosses a trust boundary. This is the common shape for RTOS / partitioned targets fuzzed through their IPC. |
| `source` | Where attacker input **enters** — the fuzzed entry point that the testcase drives. (Distinct from `sink` and `fix_location`.) |
| `sink` | Where it **goes wrong** — the top *resolved project* stack frame (allocator, sanitizer-runtime and govfuzz-harness frames are skipped): `{file, line, function}`. This is the faulting site. |
| `fix_location` | The single best place to start a fix: `{path, line, reason}`. `reason` is how it was chosen: <br>• `sanitizer_top_non_runtime_frame` — the top project frame from the sanitizer stack (the normal case). <br>• `sink_frame_no_source` — only a function name was resolvable (no source file); `path` is the function name. <br>If nothing resolves, `fix_location` is absent and the writeup/CSV say "no source location resolved" — it never points at the generated `finding.json`. |
| `explanation` | Plain-English ("In plain English") summary: what the bug is, what input triggers it, and the impact — written for a non-specialist. |
| `patch_hints` | Bug-class-specific "Suggested fix" guidance that references the sink (e.g. "bounds-check the index before the access at `<sink>`", "free the allocation on every exit path"). Advisory — not a literal diff. |
| `cwe` / `cwe_name` | The mapped CWE id(s) + name for the bug class (e.g. `CWE-416` Use After Free, `CWE-401` Missing Release of Memory). |
| `next_steps[]` | Concrete recommended actions (e.g. "Inspect `<sink>` as the primary fix location", or how to re-run under a real build). |
| `prosthetics.used` | `true` if govfuzz auto-stubbed missing dependencies / used fake resources to get the harness to build. When `true`, the finding ran against partly-synthetic code — `confidence` is lowered and you should re-confirm against a real build. |
| `mode` | The actionability profile: `reporting` (default — report what's found) or `attacking`. |

### Two confidences

There are **two** confidence ratings, and they are different things:

1. **`actionability.confidence`** (above) — a coarse `high`/`medium`/`low` bucket. This
   is what the `findings.csv` `confidence` column shows.
2. **The model confidence** — a **numeric 0.00–1.00** score from the `confidence_model`
   crate. This is what the per-finding writeup's `- Confidence:` line shows, e.g.
   `Confidence: 1.00 blend` (1.00 is maximal confidence — *not* an artifact). It has
   three components (in the finding's `confidence` object):
   - `calibrated` — the rule-based score: a weighted sum over features of the finding.
   - `learned` — an optional ML-learned score, present only when a trained model is
     loaded (`--confidence-model <path>`).
   - `blend` — `calibrated` blended with `learned` (≈ `calibrated` when no learned
     model is loaded). The writeup prints `"<blend> blend"`, or `"<calibrated> calibrated"`
     if there is no blend.

   Features feeding the score (`confidence.features` / `confidence.terms`): how much was
   stubbed (`stub_count`, `calls_through_stub`, `stubbed_call_depth` — more stubbing
   lowers it), `fake_corba_used`, `breadcrumb_density` (how well the source→sink path was
   traced), `target_score` (the discovery rank), `handler_kind` / `return_class`,
   `signature_age`, `param_shape_complexity`. `terms[]` lists each feature's
   `value`/`weight`/`contribution`, so you can see *why* the number is what it is.

So a finding can read e.g. `confidence: medium` (categorical) **and** `Confidence: 1.00 blend`
(numeric) at once — the first is the quick bucket, the second is the calibrated model.

---

## Provenance & artifacts

| Field | Meaning |
|---|---|
| `harness_id` | The stable id of the harness that produced the finding (e.g. `H-X0C65-56DA8C32`). Re-run just this one with `govfuzz auto … --harness-id <id>`. |
| `fixture_path` | The source file / fixture the harness was generated from. |
| `paths` | Artifact filenames inside the finding dir: `finding` (`finding.json`), `testcase` (`testcase.bin`, the reproducer input), `decoded` (`decoded.json`, a decoded view of the input when available). |
| `build.sandbox` | How the harness was executed: `{mode, strict}` — `mode: "none"` = ran directly; otherwise the sandbox wrapper (bwrap/firejail) and whether strict mode was on. |

---

## Reproducing a finding

```sh
# auto-resolves the harness from the finding's harness_id + work-dir:
govfuzz replay --finding F-NNNN-<sig>
# or run the standalone script:
python3 <finding-dir>/replay.py
```

`replay.py` is emitted for every finding and runs the built harness on `testcase.bin`
with the sanitizer env set, reproducing the crash.

---

## findings.csv

One row per finding (header always present; header-only when there are no findings):

| Column | Source field |
|---|---|
| `id` | `id` |
| `harness_id` | `harness_id` |
| `exception_name` | `exception.name` |
| `sanitizer` | `exception.sanitizer` |
| `classification` | `classification` |
| `impact` | `actionability.impact` |
| `confidence` | `actionability.confidence` |
| `verdict` | `actionability.verdict` |
| `cwe` | `actionability.cwe` |
| `sink_file` / `sink_line` / `sink_function` | `actionability.sink` |
| `fix_location` | `actionability.fix_location` (or `no source location resolved`) |
| `signature` | `signature` |

---

## Run-level summary (`run.md` / `run.json`)

Beyond the per-finding list:

| Field | Meaning |
|---|---|
| Targets discovered / built+fuzzed / skipped | Discovery found N fuzzable subprograms (ranked by score); of those, how many built+fuzzed vs were skipped (un-buildable / un-harnessable). With `--max-targets N`, the line shows "keeping the top N of M ranked target(s)". |
| `needed_for_build` (dependency manifest) | Headers / libraries / Ada units that were missing and had to be stubbed or are still blocking a build — the "bring these to the offline machine" list (`<work>/auto/missing-deps.txt`). `stubbed_*` = resolved by auto-stubbing; `missing_*` = still blocking. |
| Discovery cache line | Caching is on by default: "discovery loaded from cache (… source tree unchanged)" on a hit, or "discovery cache miss (… reason)" naming why it recomputed (no cache file yet / source fingerprint changed / format version bump / different root). `--fresh-discovery` forces a recompute; `--no-discovery-cache` disables it. |

---

## Quick reading guide

- **Distinct bugs?** count unique `cluster_key`.
- **Is it real / worth triaging?** `classification: unhandled` + `verdict: likely_reachable`/`real_reachable` + `prosthetics.used: false`. Treat `impact: info` and `classification: intended_rejection` as non-defects.
- **How bad?** `impact` (severity) + `cwe`. `confidence` qualifies the *verdict*, not the severity.
- **Where to fix?** `sink` (where it faults) and `fix_location` (where to start) — and read `explanation` + `patch_hints` first.
- **Reproduce?** `replay.py` or `govfuzz replay --finding <id>`.
