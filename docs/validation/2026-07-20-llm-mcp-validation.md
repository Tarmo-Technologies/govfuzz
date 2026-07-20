<!-- SPDX-License-Identifier: Apache-2.0 -->

# LLM and MCP validation (2026-07-20)

This validation covers the optional LLM-assistance and MCP interfaces. GovFuzz's
deterministic scanning, building, fuzzing, replay, and minimization remain the
source of truth; model output is advisory.

## Environment

- Linux host: 6 logical CPUs, 13 GiB RAM, 8 GiB swap
- GovFuzz: optimized release build
- Codex CLI: 0.144.6, authenticated with the existing user session
- Claude Code: 2.1.178, authenticated with the existing user session
- No `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` was present
- `llama-server` was installed, but no local model weights or running local API
  server were present

## Connection results

| Path | Result | Wall time | Maximum resident process observed |
| --- | --- | ---: | ---: |
| `govfuzz llm test --provider codex` | connected; 15-byte sentinel | 6.73 s | 170,392 KiB |
| `govfuzz llm test --provider claude` | connected; 15-byte sentinel | 3.47 s | 319,464 KiB |
| Codex host -> GovFuzz MCP preflight | `CODEX_READONLY_ANNOTATION_OK` | 15.46 s | not recorded |
| Claude host -> GovFuzz MCP preflight | `CLAUDE_GOVFUZZ_MCP_OK` | 15.00 s | 346,204 KiB |
| Raw MCP initialize/list/preflight | five tools; `isError: false` | <0.01 s | 3,456 KiB |

The CLI measurements include the model client process. They are not the
standalone GovFuzz daemon footprint and they do not sum the resident memory of
every process in a provider's process tree.

Codex's first non-interactive read-only run exposed missing MCP read-only tool
annotations and conservatively stopped at its approval gate. After all five
tools were marked read-only, non-destructive, idempotent, and closed-world, the
final validation passed under the normal read-only sandbox without an approval
bypass. Claude was restricted to the one GovFuzz MCP preflight tool during its
approval-bypassed validation run.

## Protocol and regression coverage

- OpenAI Responses, Anthropic Messages, and OpenAI-compatible local HTTP wire
  formats are covered by local mock-server tests, including response parsing.
- Provider output, HTTP response bodies, MCP input messages, evidence files,
  and subprocess output have bounded, environment-overrideable capture.
- All five MCP tools advertise read-only/idempotent annotations. On this host,
  the ranked-target tool derived a default breadth of about 6,100 from the current
  message budget; its incremental top-K retention avoids keeping every lower-
  ranked candidate when a bound is active. Finding output has a separate
  message-budget-derived default because individual records are larger.
- Timed-out CLI provider process groups are terminated instead of leaving model
  descendants behind.
- The combined `govfuzz`, `govfuzz-daemon`, and `llm_harness_gen` all-target
  regression run passed, including 1,235 CLI library tests and compiled C, C++,
  COBOL, sanitizer, build-recovery, replay-capsule, and real miniz fixtures.
- The documentation build, SPDX check, strict-permissive license audit,
  `cargo deny check`, and release build passed.

## Coverage limitations

Live OpenAI and Anthropic token-authenticated HTTP calls were not made because
the host had no API keys. A live local-model inference call was not made because
the host had no model weights or running local server. Those three transports
were validated at the HTTP protocol boundary with local mock servers; operators
should run `govfuzz llm test` with their selected model and credentials before a
production campaign.
