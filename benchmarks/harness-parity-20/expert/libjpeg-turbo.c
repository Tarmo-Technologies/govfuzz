/* SPDX-License-Identifier: Apache-2.0 */
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <jpeglib.h>
#include <setjmp.h>
struct err { struct jpeg_error_mgr pub; jmp_buf jump; };
static void fail(j_common_ptr c) { longjmp(((struct err *)c->err)->jump, 1); }
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct jpeg_decompress_struct c; struct err e; c.err = jpeg_std_error(&e.pub); e.pub.error_exit = fail;
  if (setjmp(e.jump)) { jpeg_destroy_decompress(&c); return 0; }
  jpeg_create_decompress(&c); jpeg_mem_src(&c, data, size);
  if (jpeg_read_header(&c, TRUE) == JPEG_HEADER_OK && jpeg_start_decompress(&c)) {
    size_t stride = c.output_width * c.output_components; JSAMPARRAY row = (*c.mem->alloc_sarray)((j_common_ptr)&c, JPOOL_IMAGE, stride, 1);
    while (c.output_scanline < c.output_height) jpeg_read_scanlines(&c, row, 1);
    jpeg_finish_decompress(&c);
  }
  jpeg_destroy_decompress(&c); return 0;
}
