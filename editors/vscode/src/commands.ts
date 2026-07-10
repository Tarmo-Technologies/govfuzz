// SPDX-License-Identifier: Apache-2.0

import path from "node:path";

import type { GovfuzzFinding } from "./findings";

export interface CommandConfig {
  cliPath: string;
  findingsDir: string;
  harnessPath: string;
  minimizeStrategy: "bytes" | "typed";
  workspaceRoot: string;
}

export function buildReplayCommand(
  finding: GovfuzzFinding,
  config: CommandConfig,
): string {
  if (!config.harnessPath.trim() && finding.replay?.command?.trim()) {
    return finding.replay.command;
  }

  const args = [
    config.cliPath,
    "replay",
    "--finding",
    findingPath(finding, config),
  ];
  if (config.harnessPath.trim()) {
    args.push("--harness", config.harnessPath);
  }
  return shellCommand(args);
}

export function buildMinimizeCommand(
  finding: GovfuzzFinding,
  config: CommandConfig,
): string {
  const args = [
    config.cliPath,
    "minimize",
    "--finding",
    findingPath(finding, config),
  ];
  if (config.harnessPath.trim()) {
    args.push("--harness", config.harnessPath);
  }
  args.push("--strategy", config.minimizeStrategy);
  return shellCommand(args);
}

export function resolveReproducerPath(
  finding: GovfuzzFinding,
  config: CommandConfig,
): string | undefined {
  const artifact = finding.generated_repro_ada;
  if (!artifact) {
    return undefined;
  }
  if (path.isAbsolute(artifact)) {
    return path.normalize(artifact);
  }

  const findingsRoot = path.isAbsolute(config.findingsDir)
    ? config.findingsDir
    : path.resolve(config.workspaceRoot, config.findingsDir);
  return path.normalize(path.resolve(findingsRoot, artifact));
}

export function shellCommand(args: string[]): string {
  return args.map(quoteShellArg).join(" ");
}

function findingPath(finding: GovfuzzFinding, config: CommandConfig): string {
  const findingsRoot = path.isAbsolute(config.findingsDir)
    ? config.findingsDir
    : path.resolve(config.workspaceRoot, config.findingsDir);
  return path.normalize(path.resolve(findingsRoot, finding.id));
}

export function quoteShellArg(arg: string): string {
  if (/^[A-Za-z0-9_./:=@+-]+$/.test(arg)) {
    return arg;
  }
  return `'${arg.replaceAll("'", "'\\''")}'`;
}
