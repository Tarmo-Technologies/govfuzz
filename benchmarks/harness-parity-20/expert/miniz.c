#include "miniz.h"
#include <stdint.h>
#include <stdlib.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  mz_ulong out_len=1u<<20, in_len=(mz_ulong)size; unsigned char *out=(unsigned char *)malloc(out_len);
  if (out) (void)mz_uncompress2(out,&out_len,data,&in_len); free(out); return 0;
}
