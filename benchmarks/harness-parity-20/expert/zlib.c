#include <zlib.h>
#include <stdint.h>
#include <stdlib.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uLongf out_len=1u<<20, in_len=(uLong)size; Bytef *out=(Bytef *)malloc(out_len);
  if(out)(void)uncompress2(out,&out_len,data,&in_len); free(out); return 0;
}
