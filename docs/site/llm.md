<!-- SPDX-License-Identifier: Apache-2.0 -->

# LLM Assistance

GovFuzz keeps scanning, target ranking, harness validation, building, fuzzing,
replay, and minimization deterministic. An LLM is useful around those steps: it
can plan a run, draft a candidate harness, interpret evidence, explain code, and
rank diagnostic hypotheses. It must not become the source of truth for whether
a harness compiles, links, reaches its target, gains coverage, or reproduces a
finding.

## Pick an integration mode

| Mode | Credentials seen by GovFuzz | Best use | Important distinction |
|---|---|---|---|
| MCP (`govfuzz-daemon --mcp`) | None | Interactive work in the Codex/Claude session already open | Recommended: the host session reasons and calls GovFuzz tools directly |
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
into shell history or process listings. API providers require an explicit model
instead of silently pinning a model name that will age:

```sh
export OPENAI_API_KEY='...'
govfuzz llm test --provider openai --model '<openai-model-id>'

export ANTHROPIC_API_KEY='...'
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
stdio framing and exposes:

- `govfuzz_scan`, `govfuzz_list_targets`, and `govfuzz_load_findings` for
  deterministic, read-only evidence;
- `govfuzz_prepare_assistance` for task-specific prompts whose evidence blocks
  are explicitly treated as untrusted data; and
- `govfuzz_preflight_harness` for a cheap structural candidate check that
  always requires subsequent build/fuzz validation.

The MCP structured scan and ranked-target inventory currently cover Ada, C, and
C++. If `top` is omitted, target and finding output use defaults derived from
the current MCP message budget. Target discovery retains only the best
candidates as it proceeds, and both responses report total and truncation
metadata; set an explicit positive `top` when a different breadth is useful. For
the other language lanes, use the normal explicit GovFuzz CLI commands and pass
their bounded artifacts to the session for explanation or diagnosis.

This is how the current session is used without an API token: the MCP host model
performs the reasoning. The GovFuzz server does not call a hidden model and does
not receive the host's credential. Long-running or mutating operations such as
`auto`, `build`, `fuzz`, replay, and minimization remain explicit CLI actions,
which keeps approval, logs, and resource budgets visible.

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

## CLI assistance workflows

`prompt` only renders the bounded task prompt. It is useful for manual review or
copying into an existing session:

```sh
govfuzz llm prompt --task diagnose-error \
  --question 'Why is the target missing at link time?' \
  --input govfuzz_work/build/link.log \
  --input govfuzz_work/generated/harness.cpp
```

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
