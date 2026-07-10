// SPDX-License-Identifier: Apache-2.0
// Minimal C fuzz target. Auto discovers `mixed_parse` by its
// (const unsigned char *, unsigned long) signature.

int mixed_parse(const unsigned char *data, unsigned long len) {
    int acc = 0;
    for (unsigned long i = 0; i < len && i < 64; i++) {
        acc ^= (int)data[i];
    }
    return acc;
}
