// SPDX-License-Identifier: Apache-2.0
#include <stddef.h>
int target_one_input(const unsigned char *data, size_t size);
int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
    target_one_input(data, size);
    return 0;
}
