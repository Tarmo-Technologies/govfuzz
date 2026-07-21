<!-- SPDX-License-Identifier: Apache-2.0 -->

# LLM Assistance

GovFuzz keeps scanning, target ranking, harness validation, building, fuzzing,
replay, and minimization deterministic. An LLM is useful around those steps: it
can plan a run, draft a candidate harness, interpret evidence, explain code, and
rank diagnostic hypotheses. It must not become the source of truth for whether
a harness compiles, links, reaches its target, gains coverage, or reproduces a
finding.

The LLM surface is optional and is not part of `govfuzz auto`. GovFuzz does not
silently call a model, apply a completion to the repository, execute a
model-generated command, or promote model prose into a finding. `llm prompt`
renders a prompt, `llm assist` makes one bounded provider request, and the MCP
server exposes five read-only tools. The operator or host agent decides what to
do next, under the same command-review and sandbox policy used for any other
change.

## Current capability boundary

| Capability | Current scope |
|---|---|
| GovFuzz fuzzing lanes | Sixteen: Ada, C, C++, Rust, Java, Python, Perl, Go, COBOL, Fortran, C#, JavaScript, TypeScript, Ruby, Lua, PHP |
| `govfuzz llm` task kinds | Run planning, harness drafting, finding analysis, code explanation, error diagnosis |
| Structured LLM harness language option | Ada, C, C++ |
| MCP deterministic scan | Ada |
| MCP ranked targets and harness preflight | Ada, C, C++ |
| MCP finding loading and prompt preparation | Language-neutral normalized artifacts/evidence |
| Build, fuzz, replay, minimization through MCP | Not exposed; run the explicit CLI commands |

## Pick an integration mode

| Mode | Credentials seen by GovFuzz | Best use | Important distinction |
|---|---|---|---|
| No LLM | None | Deterministic scanning, building, fuzzing, replay, minimization, and reporting | Fully supported; every core workflow remains offline and model-free |
| MCP (`govfuzz-daemon --mcp`) | None | Interactive work in the Codex/Claude session already open | Recommended for agentic assistance: the host session reasons and calls read-only GovFuzz tools directly |
| `--provider codex` / `claude` | None; the installed CLI uses its cached login | Automation that may use an existing subscription instead of an API key | Starts a new ephemeral child session; it is not the caller's current conversation |
| `--provider openai` / `anthropic` | Key read from an environment variable | CI, services, controlled model/version evaluation | Data is sent to the configured remote API |
| `--provider local` | None by default | Air-gapped or data-residency-sensitive work | Requires an OpenAI-compatible Ollama, llama.cpp, LM Studio, or gateway endpoint |

Start with a non-secret status check, then make an actual request:

```sh
govfuzz llm status --json
govfuzz llm test --provider codex
govfuzz llm test --provider claude
```

GovFuzz never accepts an API key as a command-line value, where it would leak
into shell history or process listings. Have the shell, CI secret store, or
credential broker populate the environment; do not paste a real key into the
example below. API providers require an explicit model instead of silently
pinning a model name that will age:

```sh
# OPENAI_API_KEY is already injected into this process environment
govfuzz llm test --provider openai --model '<openai-model-id>'

# ANTHROPIC_API_KEY is already injected into this process environment
govfuzz llm test --provider anthropic --model '<anthropic-model-id>'
```

OpenAI uses the Responses API; Anthropic uses the Messages API. `--base-url`
supports an organization gateway. Use `--api-key-env NAME` when the credential
is stored under a different environment variable.

For a local server:

```sh
# Ollama's default OpenAI-compatible endpoint:
govfuzz llm test --provider local --model '<installed-model>'

# llama.cpp, LM Studio, or another endpoint:
govfuzz llm test --provider local --model '<served-model>' \
  --base-url http://127.0.0.1:8080/v1
```

Choose the strongest coding/reasoning model you have measured for harness and
root-cause work. A smaller model is usually sufficient for report summarization
and first-pass clustering. Model choice is deliberately operator-controlled:
evaluate it on representative targets and compare deterministic build,
reachability, coverage, and triage outcomes rather than prose quality.

## Recommended: use the current session through MCP

Build the daemon and register its absolute path with the client:

```sh
cargo build --release -p govfuzz-daemon --bin govfuzz-daemon

codex mcp add govfuzz -- \
  /absolute/path/to/govfuzz/target/release/govfuzz-daemon --mcp

claude mcp add --scope user govfuzz -- \
  /absolute/path/to/govfuzz/target/release/govfuzz-daemon --mcp
```

Restart or open a new client session after registration. The server uses MCP
stdio framing and exposes exactly these tools:

| MCP tool | Input | Result and boundary |
|---|---|---|
| `govfuzz_scan` | repository `path` | Deterministic Ada structure summary |
| `govfuzz_list_targets` | `path`, optional positive `top` | Ranked Ada/C/C++ targets; reports total/truncation metadata |
| `govfuzz_load_findings` | findings directory, optional positive `top` | Bounded normalized finding records for triage |
| `govfuzz_prepare_assistance` | `kind`, optional question/target/language/evidence | Injection-aware task prompt; MCP kinds use underscores (`plan_run`, `generate_harness`, `analyze_findings`, `explain_code`, `diagnose_error`) |
| `govfuzz_preflight_harness` | target symbol, Ada/C/C++ language, candidate source | Structural checks only; never claims compile, link, reachability, or coverage |

All five tools advertise read-only, non-destructive, idempotent, closed-world
annotations. Verify registration from a shell before restarting the host:

```sh
codex mcp get govfuzz
claude mcp get govfuzz
```

The MCP structured scan currently covers Ada. Ranked-target inventory and
harness preflight cover Ada, C, and C++. If `top` is omitted, target and finding
output use defaults derived from the current MCP message budget. Target
discovery retains only the best candidates as it proceeds, and both responses
report total and truncation metadata; set an explicit positive `top` when a
different breadth is useful. For the other language lanes, use the normal
explicit GovFuzz CLI commands and pass their bounded artifacts to the session
for explanation or diagnosis.

This is how the current session is used without an API token: the MCP host model
performs the reasoning. The GovFuzz server does not call a hidden model and does
not receive the host's credential. Long-running or mutating operations such as
`auto`, `build`, `fuzz`, replay, and minimization remain explicit CLI actions,
which keeps approval, logs, and resource budgets visible.

That is the current agentic boundary: an agent may read bounded evidence and
propose the next step, but GovFuzz itself does not implement an autonomous loop.
If a host agent is allowed to run CLI commands, its own approval policy—not MCP
tool metadata—governs those separate shell actions. In particular,
`--probe-build`, `--build-command`, `--run-untrusted`, and
`--unsafe-search-and-run-build-commands` can execute repository-controlled build
logic and require the same explicit trust decision whether a human or model
suggested them.

## Workflow audit

| Stage | Give the LLM | Ask it to do | Deterministic check that decides |
|---|---|---|---|
| Run planning | language/build inventory, SLOC, ranked targets, machine RAM/CPU, time budget | propose the cheapest useful sequence, concurrency, limits, stop conditions | inspect `--help`; run `scan`/`list targets`, then a bounded pilot before a whole-tree campaign |
| Harness generation | exact declaration/signature, callers, headers/specs, build command, target metadata | draft a candidate and list required compile/link inputs; identify missing facts | `generate-harness`, `build`, then a short fuzz run with observed target coverage |
| Build/link failure | exact command, stdout/stderr, generated source, symbols and libraries | quote the decisive diagnostic, rank hypotheses, propose one discriminator at a time | rerun the exact command; inspect symbols/link order; accept only a clean deterministic build |
| Harness/fuzz failure | run manifest, harness, crash/hang output, coverage progression, resource settings | distinguish harness defects, target behavior, environment gaps, and budget exhaustion | replay, coverage counters, sanitizer output, timeout/RSS evidence, and a controlled rerun |
| Finding analysis | normalized `finding.json`, minimized input, replay output, nearby code | cluster likely duplicates, explain input-to-sink flow, label uncertainty, prioritize follow-up | replay/minimize/differential results and GovFuzz reachability/actionability fields |
| Code-specific explanation | focused source around the target and its callers, not a 10M-SLOC dump | explain state, guards, dataflow, dangerous sinks, and candidate seeds/dictionaries with citations | source review plus instrumented observations; never accept invented paths or line numbers |
| Reporting | validated findings and their reproducer evidence | write audience-specific explanations and remediation context | generated report fields and reproducer artifacts remain authoritative |

The highest-yield loop is evidence-driven and iterative:

1. Let GovFuzz discover/rank or reproduce the problem.
2. Give the LLM the smallest relevant source and exact artifacts, not the whole
   repository.
3. Ask for hypotheses and a verification checklist.
4. Run one deterministic discriminator.
5. Feed the new result back, and stop when the evidence settles the question.

This reduces context cost and hallucination risk, and works on large trees where
sending the repository to a model would be slow, expensive, and potentially a
data-handling violation.

## Practical agent workflows

### Plan a large or memory-constrained run

Start with deterministic inventory and a no-build plan. Save compact artifacts
instead of sending a whole 10M+ SLOC tree to a model:

```sh
govfuzz sloc path/to/tree --out govfuzz-sloc.json
govfuzz auto path/to/tree --dry-run --max-targets 200 --jobs 1 \
  --rss-limit-mb 1536 > govfuzz-dry-run.txt
govfuzz llm prompt --task plan-run \
  --question 'Plan a one-hour pilot for an 8 GiB host; preserve discovery depth' \
  --input govfuzz-sloc.json --input govfuzz-dry-run.txt
```

The model should select explicit budgets and stop conditions from documented
flags. Confirm them with `govfuzz auto --help`, then run a bounded pilot. Do not
ask a model to infer peak memory from SLOC alone: target RSS, sanitizer cost,
compiler concurrency, and report cardinality matter.

### Generate or repair a harness

Use deterministic generation first. An LLM is most useful for a wrapper, an
unusual lifecycle, or a diagnostic the repair loop could not resolve:

```sh
govfuzz list targets path/to/source.cpp --format json --top 20 > targets.json
govfuzz generate-harness path/to/source.cpp --target parse_packet \
  --output generated_harnesses
govfuzz llm prompt --task generate-harness --language cpp \
  --target-symbol parse_packet --input targets.json \
  --input generated_harnesses/<harness-id>/main.cpp \
  --input govfuzz_work/auto/run.json
```

`llm assist` and MCP preflight return advice; they do not write the proposed
harness into the work tree. Review and integrate any candidate deliberately,
run `govfuzz_preflight_harness` when using MCP, then use the real compiler/linker
and a short fuzz run. A target reference in source is not proof that the call
survived optimization or was reached; require observed target/coverage evidence.

### Analyze findings and write code-specific explanations

Make the evidence reproducible before asking for prose:

```sh
govfuzz replay --finding govfuzz_work/findings/F-0001
govfuzz minimize --finding govfuzz_work/findings/F-0001
govfuzz explain --work-dir govfuzz_work --finding-id F-0001
govfuzz llm assist --provider local --model '<served-model>' \
  --task analyze-findings \
  --question 'Separate reproduced facts from exploitability hypotheses' \
  --input govfuzz_work/findings/F-0001/finding.json \
  --input govfuzz_work/auto/run.json
```

For `explain-code`, provide the target, its callers, relevant type declarations,
and the smallest source window that contains the observed path. Ask for citations
to evidence labels and line numbers. Treat invented symbols, paths, flags, and
line numbers as a failed answer, not as facts to repair silently.

### Root-cause GovFuzz failures

Classify the failing stage before requesting a fix:

| Stage | Evidence to capture | Useful deterministic discriminator |
|---|---|---|
| Discovery | source path/encoding, `--list-targets` output, exclusion/config flags | rerun with `--fresh-discovery`; inspect `--include-dir`/`--exclude-dir` and language filter |
| Harness generation | target signature, declarations, callers, generated source | compare the selected file/line/symbol with `list targets`; run MCP structural preflight for Ada/C/C++ |
| Compile | complete compiler command and first decisive diagnostic | rerun the exact command; check dialect, include paths, generated headers, and type completeness |
| Link | complete linker command, undefined/duplicate symbols, library order | inspect symbols and translation-unit/library inputs; add one real input at a time |
| Fuzz startup | run manifest, child stderr, exit status, timeout/RSS settings | replay the seed directly; distinguish loader/toolchain failure from target failure |
| Fuzz effectiveness | executions, coverage progression, target-reachability and stub metadata | short controlled reruns with one changed seed/dictionary/pass; reject stub-only false cleans |
| GovFuzz internal error | stderr plus generated `bug-report.json` from `--debug` | reproduce with the smallest tree/command without discarding the original report |

Ask `diagnose-error` to quote the decisive diagnostic, rank hypotheses, and
propose one discriminator at a time. If the proposed edit changes several
variables, it is poor root-cause analysis even when it happens to build.

## CLI assistance workflows

`prompt` only renders the bounded task prompt. It is useful for manual review or
copying into an existing session:

```sh
govfuzz llm prompt --task diagnose-error \
  --question 'Why is the target missing at link time?' \
  --input govfuzz-auto.stderr \
  --input govfuzz_work/harnesses/<harness-id>/main.cpp
```

Capture the exact diagnostic first with `govfuzz auto ... --verbose 2>
govfuzz-auto.stderr`. Persisted build/link outcomes live in `auto/run.json` and
per-target `harnesses/<id>/result.json`; GovFuzz does not promise a synthetic
`build/link.log` file.

`assist` renders the same prompt and sends it to a provider:

```sh
govfuzz llm assist --provider claude --task analyze-findings \
  --question 'Cluster these findings and give replay checks' \
  --input govfuzz_work/auto/run.json \
  --input govfuzz_work/findings/example/finding.json

govfuzz llm assist --provider local --model '<served-model>' \
  --task generate-harness --target-symbol parse_packet --language cpp \
  --input include/parser.hpp --input src/parser.cpp
```

Supported task names are `plan-run`, `generate-harness`, `analyze-findings`,
`explain-code`, and `diagnose-error`.

The structured `--language` option and MCP harness preflight currently recognize
Ada, C, and C++. For other GovFuzz language lanes, use focused evidence with
`explain-code` or `diagnose-error`, and keep the lane's normal deterministic
harness/build/fuzz path authoritative.

## Memory, privacy, and failure boundaries

Provider stdout/stderr, HTTP responses, CLI evidence, MCP messages, and legacy
daemon frames are bounded. Defaults scale to 1/512 of currently available
host/cgroup RAM and are clamped to 1–64 MiB; this is an input-safety budget, not
a model context-window claim. Exact positive byte overrides are available:

- `GOVFUZZ_LLM_MAX_RESPONSE_BYTES`
- `GOVFUZZ_LLM_MAX_EVIDENCE_BYTES`
- `GOVFUZZ_MCP_MAX_MESSAGE_BYTES`
- `GOVFUZZ_DAEMON_MAX_MESSAGE_BYTES`

Provider subprocesses have configurable wall-clock timeouts and timed-out
process trees are terminated. HTTP output tokens are controlled by
`--max-output-tokens`.

Cloud API and authenticated CLI modes can transmit prompts, code, logs, and
findings to their provider. Check the target repository's classification and
provider retention policy first. Use a local model or no LLM for air-gapped or
restricted data. Treat repository text, logs, and finding content as prompt-
injection-capable untrusted data, and never let a model-generated command bypass
the same review and sandboxing applied to a human-written command.

Evidence can also contain credentials that belong to the target under test.
Run the source and binary secret checks (including GF-429 verified-format
findings), review build logs and environment dumps, and redact secrets before a
cloud or authenticated-CLI request. `govfuzz llm status --json` reports only
credential presence booleans, executable paths, and limits; it does not print
credential values. Clear provider variables from the environment when the call
is complete, and never commit prompts, provider output, or MCP transcripts
without reviewing them as carefully as source artifacts.

The dated [LLM and MCP validation record](https://github.com/Tarmo-Technologies/govfuzz/blob/main/docs/validation/2026-07-20-llm-mcp-validation.md)
documents the tested Codex/Claude session paths, raw MCP protocol, local mock
HTTP transports, resource measurements, and the live-provider limitations of
that validation host.
