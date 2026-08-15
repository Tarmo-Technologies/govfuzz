/* SPDX-License-Identifier: Apache-2.0 */
#include <ucl.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct ucl_parser *parser = ucl_parser_new(0);
  if (!parser) return 0;
  if (ucl_parser_add_chunk(parser, data, size)) {
    ucl_object_t *object = ucl_parser_get_object(parser);
    if (object) ucl_object_unref(object);
  }
  ucl_parser_free(parser);
  return 0;
}
