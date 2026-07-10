# SPDX-License-Identifier: Apache-2.0

"""GNAT Studio plugin for GovFuzz findings."""

from __future__ import annotations

import os

try:
    import GPS  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - GNAT Studio provides GPS at runtime.
    GPS = None

from govfuzz_gnatstudio_core import (
    GovfuzzConfig,
    action_name,
    build_minimize_args,
    build_replay_args,
    diagnostic_records,
    finding_action_specs,
    load_findings,
    resolve_reproducer_path,
    safe_label,
)


CATEGORY = "GovFuzz"
PREF_DAEMON = "GovFuzz/daemon-path"
PREF_CLI = "GovFuzz/cli-path"
PREF_FINDINGS = "GovFuzz/findings-dir"
PREF_HARNESS = "GovFuzz/harness-path"
PREF_STRATEGY = "GovFuzz/minimize-strategy"


class PluginState:
    def __init__(self) -> None:
        self.findings = []
        self.dynamic_actions = []


STATE = PluginState()


def on_gps_started(_hook_name: str) -> None:
    initialize()


def initialize() -> None:
    create_preferences()
    refresh = GPS.Action("GovFuzz refresh findings")
    if not refresh.exists():
        refresh.create(
            on_activate=refresh_findings,
            category=CATEGORY,
            description="Refresh GovFuzz findings",
        )
        refresh.menu("/Tools/GovFuzz/Refresh Findings")


def create_preferences() -> None:
    create_preference(
        PREF_DAEMON,
        "Daemon executable",
        "string",
        "Path to the GovFuzz daemon executable.",
        "govfuzz-daemon",
    )
    create_preference(
        PREF_CLI,
        "CLI executable",
        "string",
        "Path to the GovFuzz CLI executable.",
        "govfuzz",
    )
    create_preference(
        PREF_FINDINGS,
        "Findings directory",
        "string",
        "Findings directory loaded through the daemon.",
        "findings",
    )
    create_preference(
        PREF_HARNESS,
        "Harness path",
        "string",
        "Optional harness path used by replay and minimize actions.",
        "",
    )
    create_preference(
        PREF_STRATEGY,
        "Minimize strategy",
        "enum",
        "Minimization strategy used by the Minimize action.",
        0,
        "bytes",
        "typed",
    )


def create_preference(name: str, label: str, kind: str, doc: str, default, *args) -> None:
    preference = GPS.Preference(name)
    try:
        preference.create(label, kind, doc, default, *args)
    except Exception:
        # Preference already exists or GNAT Studio rejected a duplicate create.
        pass


def refresh_findings() -> None:
    config = current_config()
    try:
        findings = load_findings(config)
    except Exception as error:
        console_write(f"GovFuzz refresh failed: {error}\n")
        return

    STATE.findings = findings
    clear_messages()
    clear_dynamic_actions()

    by_id = {str(finding.get("id", "unknown-finding")): finding for finding in findings}
    for record in diagnostic_records(findings, config.workspace_root):
        message = GPS.Message(
            CATEGORY,
            GPS.File(record.file),
            record.line,
            record.column,
            record.text,
            True,
            True,
            False,
            message_importance(record.importance),
        )
        register_finding_actions(by_id[record.finding_id], config)
        message.set_action(
            action_name("replay", record.finding_id),
            "gps-run",
            "Replay this finding",
        )

    console_write(f"GovFuzz loaded {len(findings)} finding(s).\n")


def register_finding_actions(finding, config: GovfuzzConfig) -> None:
    finding_id = str(finding.get("id", "unknown-finding"))
    menu_base = f"/Tools/GovFuzz/Findings/{safe_label(finding_id)}"

    for spec in finding_action_specs(finding):
        register_action(
            action_name(spec.action, finding_id),
            f"{menu_base}/{spec.menu_label}",
            spec.description,
            lambda spec=spec: run_finding_action(spec.action, finding, config, finding_id),
        )


def run_finding_action(action: str, finding, config: GovfuzzConfig, finding_id: str) -> None:
    if action == "replay":
        run_process(build_replay_args(finding, config), config, f"Replay {finding_id}")
    elif action == "minimize":
        run_process(build_minimize_args(finding, config), config, f"Minimize {finding_id}")
    elif action == "open-repro":
        open_reproducer(finding, config)


def register_action(name: str, menu_path: str, description: str, callback) -> None:
    action = GPS.Action(name)
    if action.exists():
        action.unregister()
        action = GPS.Action(name)
    action.create(on_activate=callback, category=CATEGORY, description=description)
    action.menu(menu_path)
    STATE.dynamic_actions.append(name)


def run_process(args: list[str], config: GovfuzzConfig, task_name: str) -> None:
    GPS.Process(
        args,
        task_manager=True,
        show_command=True,
        directory=config.workspace_root,
        task_manager_name=f"GovFuzz {task_name}",
    )


def open_reproducer(finding, config: GovfuzzConfig) -> None:
    path = resolve_reproducer_path(finding, config)
    if not path:
        console_write(f"GovFuzz finding {finding.get('id')} has no repro.adb.\n")
        return
    GPS.EditorBuffer.get(GPS.File(path))


def clear_messages() -> None:
    for message in GPS.Message.list(CATEGORY):
        message.remove()


def clear_dynamic_actions() -> None:
    for name in STATE.dynamic_actions:
        try:
            GPS.Action(name).unregister()
        except Exception:
            pass
    STATE.dynamic_actions = []


def current_config() -> GovfuzzConfig:
    return GovfuzzConfig(
        daemon_path=string_preference(PREF_DAEMON, "govfuzz-daemon"),
        cli_path=string_preference(PREF_CLI, "govfuzz"),
        findings_dir=string_preference(PREF_FINDINGS, "findings"),
        harness_path=string_preference(PREF_HARNESS, ""),
        minimize_strategy=strategy_preference(),
        workspace_root=workspace_root(),
    )


def string_preference(name: str, default: str) -> str:
    try:
        value = GPS.Preference(name).get()
    except Exception:
        return default
    return value if isinstance(value, str) and value else default


def strategy_preference() -> str:
    try:
        value = GPS.Preference(PREF_STRATEGY).get()
    except Exception:
        return "bytes"
    if value == 1:
        return "typed"
    if value == "typed":
        return "typed"
    return "bytes"


def workspace_root() -> str:
    try:
        project_file = GPS.Project.root().file().name()
        return os.path.dirname(project_file)
    except Exception:
        return os.getcwd()


def message_importance(name: str):
    importance = GPS.Message.Importance
    return getattr(importance, name, importance.UNSPECIFIED)


def console_write(text: str) -> None:
    GPS.Console("Messages").write(text)


if GPS is not None:
    GPS.Hook("gps_started").add(on_gps_started)
