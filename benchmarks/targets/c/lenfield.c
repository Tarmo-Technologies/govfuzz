// SPDX-License-Identifier: Apache-2.0
// Benchmark target: a 1-byte length field driving an OOB read.
#include <stddef.h>
int target_one_input(const unsigned char *buf, size_t len) {
    if (len < 1) return 0;
    unsigned char declared = buf[0];
    unsigned char window[8] = {0};
    int sum = 0;
    for (unsigned i = 0; i < (unsigned)declared; i++) sum += window[i]; /* OOB read once declared>8 */
    return sum;
}
