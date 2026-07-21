<!-- SPDX-License-Identifier: Apache-2.0 -->

# Daemon

`govfuzz-daemon` is the JSON-RPC daemon used by IDE clients. It speaks
JSON-RPC 2.0 over LSP-style stdio framing:

```text
Content-Length: <bytes>\r\n
\r\n
<json body>
```

The same binary also supports standards-based Model Context Protocol stdio with
`govfuzz-daemon --mcp`. MCP messages are newline-delimited JSON-RPC rather than
LSP-framed. This mode lets a Codex or Claude host session use deterministic
GovFuzz tools without giving GovFuzz an API token; see
[LLM Assistance](../llm/).

The MCP mode exposes five read-only tools: Ada structure scan, Ada/C/C++ ranked
targets, bounded normalized-finding loading, task-prompt preparation, and an
Ada/C/C++ structural harness preflight. It does not expose build, fuzz, replay,
minimization, file editing, or shell execution. All five tools advertise
read-only, non-destructive, idempotent, closed-world annotations. Target and
finding defaults derive from the current MCP message budget; explicit positive
`top` values override those breadth defaults, and responses report totals and
truncation.

## Methods

- `scan` summarizes Ada files under a path.
- `listTargets` returns ranked fuzz targets (Ada, C, C++).
- `findings` loads normalized finding directories.
- `rankAt` returns the ranked target containing a source location (Ada-only).
- `instrumentPreview` returns rewritten source and probe breadcrumbs without
  writing files (Ada-only).
- `staticScan` runs the same full offline static engine as the CLI (the eight
  core static languages plus JavaScript/TypeScript and supported QML/config/IaC
  inputs), writes JSON, Markdown, and optional SARIF artifacts, and returns the
  full static report plus a CI-style `exit_code`.

`rankAt` and `instrumentPreview` are Ada-only today. The flagship CLI `auto`
command fuzzes all
sixteen current lanes; narrower manual commands state their exact language
scope in `govfuzz <command> --help`. Long-running or mutating operations remain
explicit CLI actions rather than daemon/MCP calls.

## IDE Clients

The VS Code extension and GNAT Studio plugin both use the daemon instead of
reimplementing analysis. They present findings at source locations and shell
out to the `govfuzz` CLI for replay, minimization, and reproducer workflows.

## Security Modes

The default editor path is local single-user mode and requires no token. Shared
or hosted deployments must opt into workspace-scoped security:

- `workspace_shared`: one token for one workspace.
- `multi_tenant`: one token, workspace root, and role per tenant.

Secure JSON-RPC requests use a top-level `auth` object with `tenant` and
`token`. Authorized secure responses include `govfuzzAudit`; denied requests use
GovFuzz server error codes `-32001`, `-32002`, or `-32003`.

## Continuous Daemon

`continuous_daemon` is a separate background scheduler for on-prem continuous
fuzzing. It accepts fuzz-job submissions, queues them, and dispatches them to a
worker pool that spawns `govfuzz fuzz` per job. Jobs are persisted to
`<data_dir>/jobs.jsonl` so a daemon restart recovers the known job set (jobs
that were `Running` at shutdown are reset to `Queued`, since in-flight work is
assumed lost).

The core API is `Scheduler::submit(project_dir, harness_id, time_budget)`, which
queues a job and returns a `job_id`, and `Scheduler::list_jobs()`, which returns
all jobs with their current state (`Queued`, `Running`, `Complete`, or
`Failed`). When a `webhook_url` is configured, the scheduler POSTs a
notification to it once a job reaches a terminal state (`Complete` or `Failed`)
(HTTP only in v0.1; front a `https://` endpoint with a TLS-terminating proxy).
