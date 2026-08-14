#include <jansson.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  json_error_t error; json_t *v = json_loadb((const char *)data, size, JSON_DECODE_ANY, &error);
  json_decref(v); return 0;
}
