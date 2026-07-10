<!-- SPDX-License-Identifier: Apache-2.0 -->

# IDE Parity

This matrix tracks the VS Code extension and GNAT Studio plugin workflows that
use `govfuzz-daemon` and the `govfuzz` CLI.

| Workflow | VS Code | GNAT Studio | Notes |
| --- | --- | --- | --- |
| Configure daemon path | `govfuzz.daemonPath` | `GovFuzz/daemon-path` | Defaults to `govfuzz-daemon`. |
| Configure CLI path | `govfuzz.cliPath` | `GovFuzz/cli-path` | Defaults to `govfuzz`. |
| Configure findings directory | `govfuzz.findingsDir` | `GovFuzz/findings-dir` | Relative paths resolve from the workspace/project root. |
| Configure harness override | `govfuzz.harnessPath` | `GovFuzz/harness-path` | Optional; replay can use finding-provided command when unset. |
| Configure minimize strategy | `govfuzz.minimizeStrategy` | `GovFuzz/minimize-strategy` | Supports `bytes` and `typed`. |
| Refresh findings | Command palette action | `/Tools/GovFuzz/Refresh Findings` | Both call daemon `findings`. |
| Finding source display | Diagnostics | Locations/messages | Both use handler, then last breadcrumb, then explicit raise. |
| Replay finding | CodeLens and command | Message action and menu action | Both shell out to `govfuzz replay`. |
| Minimize finding | CodeLens and command | Menu action | GNAT Studio exposes replay as the single inline message action; minimize is under the finding menu. |
| Open `repro.adb` | CodeLens and command when generated | Menu action when generated | Both hide the action when `generated_repro_ada` is absent. |
| Daemon lifecycle | Long-lived stdio client restarted on config change | One daemon subprocess per refresh | GNAT Studio's Python integration keeps the lifecycle simpler and avoids background process state. |
| Findings grouping | Per-file diagnostics and CodeLens | Per-message Locations entries and per-finding menus | This follows each IDE's native UI model. |

The feature surfaces are intentionally equivalent for core finding workflows.
The remaining differences are presentation details caused by IDE APIs, not
missing GovFuzz workflows.
