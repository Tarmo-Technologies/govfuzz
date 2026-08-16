// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readJson } from '../../../skills/ck/commands/shared.mjs';

export function fuzz(data) {
  const dir = mkdtempSync(join(tmpdir(), 'ecc-fuzz-'));
  const path = join(dir, 'input.json');
  try {
    writeFileSync(path, data);
    readJson(path);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
