// SPDX-License-Identifier: Apache-2.0

import { parseFilters } from '../../../src/compiler/parser/filter-parser'

export function fuzzVueFilters(data: Uint8Array): void {
  parseFilters(new TextDecoder('utf-8', { fatal: false }).decode(data))
}
