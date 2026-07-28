/* SPDX-License-Identifier: Apache-2.0 */
#include <stddef.h>

int dm_scan(const unsigned char *data, size_t len) {
    return len > 1 ? (int)data[1] : 0;
}
