/* SPDX-License-Identifier: Apache-2.0 */
#include "src/yyjson.h"
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  yyjson_doc *doc=yyjson_read((const char *)data,size,0); yyjson_doc_free(doc); return 0;
}
