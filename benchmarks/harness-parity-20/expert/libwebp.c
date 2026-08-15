/* SPDX-License-Identifier: Apache-2.0 */
#include <webp/decode.h>
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int width = 0;
  int height = 0;
  if (!WebPGetInfo(data, size, &width, &height)) return 0;
  if (width <= 0 || height <= 0 || width > 4096 || height > 4096) return 0;
  size_t stride = (size_t)width * 4;
  if ((size_t)height > (16u << 20) / stride) return 0;
  size_t output_size = stride * (size_t)height;
  uint8_t *output = (uint8_t *)malloc(output_size);
  if (output) {
    (void)WebPDecodeRGBAInto(data, size, output, output_size, (int)stride);
  }
  free(output);
  return 0;
}
