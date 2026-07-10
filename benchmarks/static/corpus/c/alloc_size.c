// SPDX-License-Identifier: Apache-2.0
// Uncontrolled allocation size (GF-436, CWE-789): an attacker-controlled value
// drives the size argument of an allocator. Naturally precise — the taint sink
// fires only when the size is actually tainted, so a constant/sizeof allocation
// is never flagged.
#include <stdlib.h>

char *grow(const char *user_input) {
    unsigned long n = strtoul(user_input, 0, 10);
    return (char *)malloc(n);            /* EXPECT GF-436 */
}

char *fixed_alloc(void) {
    return (char *)malloc(64);           /* constant size: not tainted, no finding */
}

char *fit_copy(const char *user_input) {
    /* Allocate-to-fit: sized to the existing string, not amplified — the SAFE
       idiom, so GF-436 must NOT fire even though user_input is tainted. */
    return (char *)malloc(strlen(user_input) + 1);
}
