#include "json.h"
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct json_tokener *t = json_tokener_new(); if (!t) return 0;
  struct json_object *o = json_tokener_parse_ex(t, (const char *)data, (int)(size > 0x7fffffff ? 0x7fffffff : size));
  if (o) json_object_put(o); json_tokener_free(t); return 0;
}
