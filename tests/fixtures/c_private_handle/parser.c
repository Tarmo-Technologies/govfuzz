/* SPDX-License-Identifier: Apache-2.0 */
#include "parser.h"

/* Private: complete ONLY in this translation unit. */
struct pv_session {
    int limit;
    unsigned char seen[4];
};

int pv_session_scan(pv_session *s, const unsigned char *data, size_t len) {
    if (s == NULL || data == NULL || len < 2) {
        return 0;
    }
    if (data[0] == 'G') {
        /* Planted out-of-bounds read (GF-201/CWE-125): `seen` holds 4 bytes. */
        return s->seen[len];
    }
    return (int)len;
}
