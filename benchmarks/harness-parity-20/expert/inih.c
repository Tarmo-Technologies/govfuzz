#include "ini.h"
#include <stdint.h>
static int value(void *u, const char *s, const char *n, const char *v) {(void)u;(void)s;(void)n;(void)v;return 1;}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  (void)ini_parse_string_length((const char *)data, size, value, NULL); return 0;
}
