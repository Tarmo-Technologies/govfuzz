#include <png.h>
#include <stdint.h>
#include <stdlib.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  png_image image; png_uint_32 zero = 0; image.version = PNG_IMAGE_VERSION; image.opaque = NULL; image.width = zero; image.height = zero; image.format = zero; image.flags = zero;
  if (png_image_begin_read_from_memory(&image, data, size)) {
    image.format = PNG_FORMAT_RGBA; size_t n = PNG_IMAGE_SIZE(image); void *out = n <= (1u<<26) ? malloc(n) : NULL;
    if (out) (void)png_image_finish_read(&image, NULL, out, 0, NULL); free(out); png_image_free(&image);
  }
  return 0;
}
