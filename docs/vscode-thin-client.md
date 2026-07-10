<!-- SPDX-License-Identifier: Apache-2.0 -->

# VS Code Thin Client

The GovFuzz VS Code extension lives in `editors/vscode`. It starts the M18
daemon over stdio, loads normalized findings through the `findings` JSON-RPC
method, and shows findings inline as diagnostics with CodeLens actions.

## Development

Install and test the extension package:

```sh
npm ci --prefix editors/vscode
npm test --prefix editors/vscode
```

The extension contributes Ada file associations for `.adb`, `.ads`, and `.ada`
files. It activates after startup and refreshes findings when the configured
findings directory exists.

## Settings

- `govfuzz.daemonPath`: daemon executable path. Defaults to `govfuzz-daemon`.
- `govfuzz.cliPath`: GovFuzz CLI executable path for terminal actions. Defaults
  to `govfuzz`.
- `govfuzz.findingsDir`: findings directory loaded through the daemon. Defaults
  to `findings`.
- `govfuzz.harnessPath`: optional harness path added to replay/minimize actions.
- `govfuzz.minimizeStrategy`: `bytes` or `typed`. Defaults to `bytes`.

## Actions

Each finding with a source location gets CodeLens actions:

- `Replay this finding`
- `Minimize`
- `Open repro.adb`

Replay and minimize open a `GovFuzz` terminal in the workspace root. `Open
repro.adb` resolves `generated_repro_ada` under the configured findings root
unless the finding already stores an absolute path.
