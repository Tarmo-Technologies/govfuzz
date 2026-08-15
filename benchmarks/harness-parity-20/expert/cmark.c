/* SPDX-License-Identifier: Apache-2.0 */
#include "cmark.h"
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  cmark_node *document =
      cmark_parse_document((const char *)data, size, CMARK_OPT_DEFAULT);
  if (document) cmark_node_free(document);
  return 0;
}
