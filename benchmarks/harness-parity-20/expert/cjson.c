/* SPDX-License-Identifier: Apache-2.0 */
#include "cJSON.h"
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const char *end = 0;
  cJSON *json = cJSON_ParseWithLengthOpts((const char *)data, size, &end, 0);
  cJSON_Delete(json); return 0;
}
