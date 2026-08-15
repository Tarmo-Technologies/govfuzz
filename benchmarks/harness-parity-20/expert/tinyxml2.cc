/* SPDX-License-Identifier: Apache-2.0 */
#include "tinyxml2.h"
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  tinyxml2::XMLDocument document; (void)document.Parse((const char *)data, size); return 0;
}
