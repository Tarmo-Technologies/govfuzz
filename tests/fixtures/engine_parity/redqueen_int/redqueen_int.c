// SPDX-License-Identifier: Apache-2.0
// Engine-parity fixture for the input-to-state (RedQueen) cmplog mutator (#400).
//
// Crash only when the u32 at [0..4) equals a magic derived from the input
// LENGTH (not its content). This isolates #400's NEW capability — per-input
// capture of INTEGER comparison operands via SanitizerCoverage trace-cmp — from
// every pre-existing path:
//   * the LD_PRELOAD shim only ever hooked mem/str compares, never integer `==`,
//     so the dictionary-only path captures nothing here;
//   * the target is len-derived, so it is not a source literal the static
//     dictionary could mine, nor an echo of any input region that the
//     repetition/structured mutators could stumble onto;
//   * the +/-1 arithmetic mutator and uniform fill cannot reach a specific
//     4-byte magic, and blind mutation is 2^-32;
//   * the compare operand `v` is a RAW input region (clang keeps `v == magic`,
//     not a derived form), so one offset-aware splice (in[0..4] := magic) lands
//     it once trace-cmp has observed the pair.
// The OOB size is input-derived so it is not dead-store-eliminated at -O1.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

int redqueen_int(const unsigned char *buf, size_t len) {
    if (len < 8) {
        return 0;
    }
    uint32_t v;
    memcpy(&v, buf, 4);
    uint32_t magic = (uint32_t)len * 0x9E3779B9u;
    if (v == magic) {
        char t[2];
        memset(t, 0, (size_t)(16 + (buf[0] & 0x3f))); /* variable-size stack OOB */
        return t[0];
    }
    return 1;
}
