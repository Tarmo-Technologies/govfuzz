/* SPDX-License-Identifier: Apache-2.0 */
#include <stddef.h>

int dm_parse(const unsigned char *data, size_t len) {
    if (data == NULL || len == 0) {
        return 0;
    }
    return (int)data[0];
}
