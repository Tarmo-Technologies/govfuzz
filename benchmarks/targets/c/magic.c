// SPDX-License-Identifier: Apache-2.0
// Benchmark target: 4-byte magic gate then an input-derived OOB write.
#include <stddef.h>
#include <string.h>
#include <stdint.h>
int target_one_input(const unsigned char *buf, size_t len) {
    if (len < 4) return 0;
    uint32_t v; memcpy(&v, buf, 4);
    if (v == 0xC0FFEE11u) {                 /* 32-bit magic gate */
        char t[2];
        memset(t, 0, (size_t)(16 + (len & 0x3f)));  /* OOB write past the gate */
        return t[0];
    }
    return 1;
}
