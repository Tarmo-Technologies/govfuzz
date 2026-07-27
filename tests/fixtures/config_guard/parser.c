/* SPDX-License-Identifier: Apache-2.0 */
#include "priv.h"
#include <stdint.h>

/* Parse a decimal count then read that many bytes. Planted out-of-bounds read. */
int parse_count(const char *text, size_t len)
{
    char buf[32];
    if (len == 0 || len >= sizeof(buf))
        return -1;
    memcpy(buf, text, len);
    buf[len] = '\0';
    unsigned long long n = proj_strtoull(buf, NULL, 10);
    if (n > 4)
        return (int)buf[n];
    return (int)n;
}
