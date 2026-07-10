// SPDX-License-Identifier: Apache-2.0
// Engine-parity benchmark fixture: multi-byte constant gate.
// Crashes only when the first 4 bytes equal the magic u32 0xDEADBEEF — a single
// dictionary insert of the recovered constant can land it once throughput allows.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

int check_magic(const unsigned char *buf, size_t len) {
    if (len < 4) {
        return 0;
    }
    uint32_t v;
    memcpy(&v, buf, 4);
    if (v == 0xDEADBEEFu) {
        char t[2];
        /* Variable-size OOB write: the length is input-derived (the runtime
         * `len`, unrelated to the gate) so the optimizer cannot
         * dead-store-eliminate it — a constant memset of a dead array is elided
         * at -O1, which masked the planted bug. */
        memset(t, 0, (size_t)(16 + (len & 0x3f)));
        return t[0];
    }
    return 1;
}
