// SPDX-License-Identifier: Apache-2.0
// Benchmark target: an input-to-state gate — a per-input, length-derived 32-bit
// magic. Reachable only by capturing the comparison operand (cmplog/RedQueen),
// NOT by a static dictionary (the magic depends on the input length).
#include <stddef.h>
#include <string.h>
#include <stdint.h>
int target_one_input(const unsigned char *buf, size_t len) {
    if (len < 8) return 0;
    uint32_t v; memcpy(&v, buf, 4);
    uint32_t magic = (uint32_t)len * 0x9E3779B9u;
    if (v == magic) {
        char t[2];
        memset(t, 0, (size_t)(16 + (buf[0] & 0x3f))); /* variable OOB write */
        return t[0];
    }
    return 1;
}
