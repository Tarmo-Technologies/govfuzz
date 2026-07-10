// SPDX-License-Identifier: Apache-2.0

import path from "node:path";

export interface GovfuzzFinding {
  id: string;
  severity?: string;
  classification?: string;
  signature?: string;
  exception?: FindingException;
  actionability?: FindingActionability;
  generated_repro_ada?: string;
  replay?: {
    command?: string;
  };
  [key: string]: unknown;
}

export interface FindingException {
  name?: string;
  message?: string;
  handler?: FindingLocation;
  last_breadcrumb?: FindingLocation;
  explicit_raise?: FindingLocation;
}

export interface FindingLocation {
  file?: string;
  line?: number;
  col?: number;
}

export interface FindingActionability {
  verdict?: string;
  confidence?: string;
  fix_location?: FindingLocation & { path?: string; reason?: string };
}

export interface TextPosition {
  line: number;
  character: number;
}

export interface TextRange {
  start: TextPosition;
  end: TextPosition;
}

export type DiagnosticSeverityName = "error" | "warning" | "information" | "hint";

export interface DiagnosticDescriptor {
  file: string;
  range: TextRange;
  severity: DiagnosticSeverityName;
  message: string;
  source: "govfuzz";
  code: string;
  finding: GovfuzzFinding;
}

export interface CodeLensDescriptor {
  title: string;
  command: string;
  findingId: string;
  range: TextRange;
}

export function diagnosticDescriptors(
  findings: GovfuzzFinding[],
  workspaceRoot: string,
): DiagnosticDescriptor[] {
  const diagnostics: DiagnosticDescriptor[] = [];
  for (const finding of findings) {
    const location = primaryLocation(finding);
    if (!location?.file) {
      continue;
    }
    diagnostics.push({
      file: resolveWorkspacePath(location.file, workspaceRoot),
      range: rangeForLocation(location),
      severity: severityForFinding(finding.severity),
      message: messageForFinding(finding),
      source: "govfuzz",
      code: finding.id,
      finding,
    });
  }
  return diagnostics;
}

export function codeLensDescriptors(
  findings: GovfuzzFinding[],
  documentPath: string,
  workspaceRoot: string,
): CodeLensDescriptor[] {
  const lenses: CodeLensDescriptor[] = [];
  const normalizedDocumentPath = path.normalize(documentPath);

  for (const finding of findings) {
    const location = primaryLocation(finding);
    if (!location?.file) {
      continue;
    }
    if (resolveWorkspacePath(location.file, workspaceRoot) !== normalizedDocumentPath) {
      continue;
    }

    const range = rangeForLocation(location);
    lenses.push(
      {
        title: "Replay this finding",
        command: "govfuzz.replayFinding",
        findingId: finding.id,
        range,
      },
      {
        title: "Minimize",
        command: "govfuzz.minimizeFinding",
        findingId: finding.id,
        range,
      },
    );
    if (finding.generated_repro_ada) {
      lenses.push({
        title: "Open repro.adb",
        command: "govfuzz.openReproducer",
        findingId: finding.id,
        range,
      });
    }
  }

  return lenses;
}

export function findingById(
  findings: GovfuzzFinding[],
  findingId: string,
): GovfuzzFinding | undefined {
  return findings.find((finding) => finding.id === findingId);
}

export function primaryLocation(finding: GovfuzzFinding): FindingLocation | undefined {
  const fix = finding.actionability?.fix_location;
  if (fix) {
    return usableLocation({
      file: fix.file ?? fix.path,
      line: fix.line,
      col: fix.col,
    });
  }
  const exception = finding.exception;
  return (
    usableLocation(exception?.handler) ??
    usableLocation(exception?.last_breadcrumb) ??
    usableLocation(exception?.explicit_raise)
  );
}

export function resolveWorkspacePath(file: string, workspaceRoot: string): string {
  if (path.isAbsolute(file)) {
    return path.normalize(file);
  }
  return path.normalize(path.resolve(workspaceRoot, file));
}

function usableLocation(location: FindingLocation | undefined): FindingLocation | undefined {
  if (!location?.file) {
    return undefined;
  }
  return location;
}

function rangeForLocation(location: FindingLocation): TextRange {
  const line = Math.max((location.line ?? 1) - 1, 0);
  const character = Math.max((location.col ?? 1) - 1, 0);
  return {
    start: { line, character },
    end: { line, character: character + 1 },
  };
}

function severityForFinding(severity: string | undefined): DiagnosticSeverityName {
  switch (severity?.toLowerCase()) {
    case "critical":
    case "high":
      return "error";
    case "low":
    case "info":
    case "informational":
      return "information";
    case "medium":
    case "unknown":
    default:
      return "warning";
  }
}

function messageForFinding(finding: GovfuzzFinding): string {
  const parts = [
    `GovFuzz ${finding.classification ?? "finding"}`,
    finding.id,
  ];
  if (finding.actionability?.verdict) {
    parts.push(finding.actionability.verdict);
  }
  if (finding.actionability?.confidence) {
    parts.push(finding.actionability.confidence);
  }
  if (finding.signature) {
    parts.push(finding.signature);
  }
  if (finding.exception?.name) {
    parts.push(finding.exception.name);
  }
  return parts.join(" ");
}
