<!-- SPDX-License-Identifier: Apache-2.0 -->

# Daemon JSON-RPC

`crates/daemon` runs a JSON-RPC 2.0 service over LSP-style stdio framing. Each
message is encoded as:

```text
Content-Length: <bytes>\r\n
\r\n
<json body>
```

The M18 service exposes IDE-facing methods:

- `scan`: summarize Ada files under `params.path`.
- `listTargets`: return ranked fuzz targets for `params.path` in Ada, C, or C++;
  accepts optional `params.top`.
- `findings`: load normalized findings from `params.findings`, defaulting to
  `findings`.
- `rankAt`: return the ranked Ada target containing `params.line` and optional
  `params.column` in `params.path`.
- `instrumentPreview`: return rewritten instrumented Ada source and breadcrumbs
  for `params.path` without writing files.
- `staticScan`: run the same full offline static engine as the CLI for
  `params.path` (the eight core static languages plus JavaScript/TypeScript and
  supported QML/config/IaC inputs), write report artifacts under `params.out`
  or `govfuzz_work/static`, and return `summary`, `report`, and `exit_code`. It
  accepts `suppressions`, `baseline`, `policy`, `enabled_rules`,
  `disabled_rules`, `sarif`, and `fail_on` parameters matching the CLI.

Target ranking via `listTargets` covers Ada, C, and C++. The `rankAt` and
`instrumentPreview` methods are Ada-only. Harness generation, build, and
fuzzing remain exposed through the CLI rather than this JSON-RPC service.

Example request body:

```json
{"jsonrpc":"2.0","id":1,"method":"listTargets","params":{"path":"src","top":10}}
```

Static scan request body:

```json
{
  "jsonrpc": "2.0",
  "id": "static",
  "method": "staticScan",
  "params": {
    "path": "src",
    "out": "govfuzz_work/static",
    "sarif": true,
    "fail_on": "high"
  }
}
```

Responses use standard JSON-RPC success and error objects. Unknown methods
return code `-32601`; invalid params return code `-32602`.

## Model Context Protocol mode

The same executable supports newline-delimited MCP stdio with
`govfuzz-daemon --mcp`. That is a separate protocol mode from the LSP-framed
JSON-RPC service above. It exposes five read-only tools for Ada structure scan,
Ada/C/C++ ranked targets, bounded finding loading, assistance-prompt preparation,
and Ada/C/C++ structural harness preflight. Build, fuzz, replay, minimization,
file editing, and shell execution are deliberately not MCP tools.

The host model performs any reasoning, so GovFuzz receives no host API token.
See the canonical [LLM and MCP guide](site/llm.md) for registration, schemas,
provider choices, memory limits, privacy boundaries, and deterministic
verification workflows.

## Security Modes

The default stdio daemon runs in `local_single_user` mode for editor clients and
does not require an auth envelope. Shared deployments can start the daemon with
an explicit security configuration:

- `local_single_user`: no auth required; intended for a single local IDE user.
- `workspace_shared`: one token scoped to one workspace root.
- `multi_tenant`: multiple tenant tokens, each scoped to its own workspace root
  and role.

Secure requests include a top-level auth object:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "rankAt",
  "auth": { "tenant": "alpha", "token": "token-alpha" },
  "params": { "path": "src/pkg.adb", "line": 12 }
}
```

Authenticated responses include a top-level `govfuzzAudit` object with tenant,
role, method, and workspace metadata. Auth failures use GovFuzz server error
codes: `-32001` for missing or invalid auth, `-32002` for role denial, and
`-32003` for paths outside the authorized workspace.
