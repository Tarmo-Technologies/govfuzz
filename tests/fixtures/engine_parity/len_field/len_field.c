// SPDX-License-Identifier: Apache-2.0
// Engine-parity benchmark fixture: length-field-driven OOB read.
// A 1-byte length field drives a read past a fixed 8-byte buffer.
#include <stddef.h>

int read_record(const unsigned char *buf, size_t len) {
    if (len < 1) {
        return 0;
    }
    unsigned char declared = buf[0];
    unsigned char window[8] = {0};
    int sum = 0;
    for (unsigned i = 0; i < (unsigned)declared; i++) {
        sum += window[i]; /* OOB read once declared > 8 */
    }
    return sum;
}
