// SPDX-License-Identifier: Apache-2.0

int system_lib_fuzz(const unsigned char *data, unsigned long len) {
    (void)data;
    return len > 0 ? 1 : 0;
}
