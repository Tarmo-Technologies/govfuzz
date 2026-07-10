// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  codeLensDescriptors,
  diagnosticDescriptors,
  type GovfuzzFinding,
} from "../findings";

const finding: GovfuzzFinding = {
  id: "F-0001-alpha",
  severity: "high",
  classification: "swallowed_predefined",
  signature: "aabbccdd",
  exception: {
    handler: {
      file: "src/pkg.adb",
      line: 5,
      col: 7,
    },
    last_breadcrumb: {
      file: "src/pkg.adb",
      line: 3,
      col: 2,
    },
  },
  generated_repro_ada: "F-0001-alpha/repro.adb",
  replay: {
    command: "govfuzz replay --finding F-0001-alpha",
  },
};

test("diagnosticDescriptors maps a finding to a workspace source diagnostic", () => {
  const diagnostics = diagnosticDescriptors([finding], "/work/project");

  assert.equal(diagnostics.length, 1);
  assert.equal(diagnostics[0].file, "/work/project/src/pkg.adb");
  assert.deepEqual(diagnostics[0].range, {
    start: { line: 4, character: 6 },
    end: { line: 4, character: 7 },
  });
  assert.equal(diagnostics[0].severity, "error");
  assert.equal(diagnostics[0].source, "govfuzz");
  assert.match(diagnostics[0].message, /F-0001-alpha/);
  assert.match(diagnostics[0].message, /swallowed_predefined/);
  assert.match(diagnostics[0].message, /aabbccdd/);
});

test("diagnosticDescriptors prefers actionability fix location", () => {
  const diagnostics = diagnosticDescriptors(
    [
      {
        ...finding,
        actionability: {
          verdict: "real_reachable",
          confidence: "high",
          fix_location: {
            path: "src/fix.adb",
            line: 42,
            col: 4,
            reason: "explicit_raise_site",
          },
        },
      },
    ],
    "/work/project",
  );

  assert.equal(diagnostics[0].file, "/work/project/src/fix.adb");
  assert.deepEqual(diagnostics[0].range.start, { line: 41, character: 3 });
  assert.match(diagnostics[0].message, /real_reachable/);
  assert.match(diagnostics[0].message, /high/);
});

test("diagnosticDescriptors falls back to last breadcrumb when no handler exists", () => {
  const diagnostics = diagnosticDescriptors(
    [
      {
        ...finding,
        exception: {
          last_breadcrumb: {
            file: "src/pkg.adb",
            line: 3,
            col: 2,
          },
        },
      },
    ],
    "/work/project",
  );

  assert.deepEqual(diagnostics[0].range, {
    start: { line: 2, character: 1 },
    end: { line: 2, character: 2 },
  });
});

test("codeLensDescriptors creates replay minimize and repro actions", () => {
  const lenses = codeLensDescriptors(
    [finding],
    "/work/project/src/pkg.adb",
    "/work/project",
  );

  assert.deepEqual(
    lenses.map((lens) => lens.title),
    ["Replay this finding", "Minimize", "Open repro.adb"],
  );
  assert.deepEqual(
    lenses.map((lens) => lens.command),
    [
      "govfuzz.replayFinding",
      "govfuzz.minimizeFinding",
      "govfuzz.openReproducer",
    ],
  );
  assert.deepEqual(lenses[0].range.start, { line: 4, character: 6 });
  assert.equal(lenses[0].findingId, "F-0001-alpha");
});
