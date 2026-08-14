#include "csv.h"
#include <stdint.h>

static void field_callback(void *field, size_t size, void *context) {
  (void)field;
  (void)size;
  (void)context;
}

static void row_callback(int terminator, void *context) {
  (void)terminator;
  (void)context;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct csv_parser parser;
  if (csv_init(&parser, 0) != 0) return 0;
  (void)csv_parse(&parser, data, size, field_callback, row_callback, NULL);
  (void)csv_fini(&parser, field_callback, row_callback, NULL);
  csv_free(&parser);
  return 0;
}
