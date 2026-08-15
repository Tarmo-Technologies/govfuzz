/* SPDX-License-Identifier: Apache-2.0 */
#include "utf8proc.h"
#include <stdint.h>
#include <stdlib.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  utf8proc_uint8_t *out=NULL; (void)utf8proc_map(data,(utf8proc_ssize_t)size,&out,UTF8PROC_STABLE|UTF8PROC_COMPOSE); free(out); return 0;
}
