// SPDX-License-Identifier: Apache-2.0
// Engine-parity benchmark fixture: st24-style magic-byte + length gate.
// Crashes (stack OOB) only past the 0x55 0x55 sync AND a length byte in {0,1,2}
// — mirrors PX4 st24.cpp:146, the case libFuzzer solves cold in <1s.
#include <stddef.h>
#include <string.h>

int parse_frame(const unsigned char *buf, size_t len) {
    if (len < 3) {
        return 0;
    }
    if (buf[0] == 0x55 && buf[1] == 0x55) {
        unsigned char n = buf[2];
        if (n < 3) {
            char tmp[2];
            memset(tmp, 0, (size_t)(16 + n)); /* OOB write once gated */
            return tmp[0];
        }
    }
    return 1;
}
