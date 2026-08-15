/* SPDX-License-Identifier: Apache-2.0 */
#include <zstd.h>
#include <stdint.h>
#include <stdlib.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  void *out=malloc(1u<<20); if(out)(void)ZSTD_decompress(out,1u<<20,data,size); free(out); return 0;
}
