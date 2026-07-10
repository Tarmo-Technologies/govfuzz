/* SPDX-License-Identifier: Apache-2.0 */
/* M23 Phase 3: intraprocedural def-use — uninitialized-variable use (CWE-457)
   and narrowing numeric truncation (CWE-197). */
#include <stdint.h>

int use_uninit(int flag) {
    int x;
    int y = 3;
    return x + y;              /* EXPECT GF-424 */
}

int safe_init(void) {
    int z;
    z = 7;
    return z;                  /* safe: assigned before the read */
}

unsigned char narrow(int big) {
    return (short)big; /* EXPECT GF-425 */
}
