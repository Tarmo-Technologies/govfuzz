// SPDX-License-Identifier: Apache-2.0
#include <stddef.h>
int FN(const unsigned char *data, size_t size);
int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) { FN(data, size); return 0; }
