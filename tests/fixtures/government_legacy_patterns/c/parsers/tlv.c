// SPDX-License-Identifier: Apache-2.0
#include <stdlib.h>
#include <string.h>

int parse_tlv(const char *buf, char *dst) {
    int len = atoi(buf);
    if (len > 0) {
        strcpy(dst, buf + 2);
    }
    return len;
}
