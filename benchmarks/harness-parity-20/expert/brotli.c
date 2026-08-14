#include <brotli/decode.h>
#include <stdint.h>
#include <stdlib.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  size_t output_size = 1u << 20;
  uint8_t *output = (uint8_t *)malloc(output_size);
  if (output) (void)BrotliDecoderDecompress(size, data, &output_size, output);
  free(output); return 0;
}
