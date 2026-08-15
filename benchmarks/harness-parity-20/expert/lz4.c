/* SPDX-License-Identifier: Apache-2.0 */
#include "lz4.h"
#include <stdint.h>
#include <stdlib.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *out=(char *)malloc(1u<<20); if (out) (void)LZ4_decompress_safe_usingDict((const char *)data,out,(int)(size>0x7fffffff?0x7fffffff:size),1u<<20,NULL,0);
  free(out); return 0;
}
