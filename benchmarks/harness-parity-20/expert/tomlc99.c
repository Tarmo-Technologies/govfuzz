#include "toml.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == SIZE_MAX) return 0;
  char *input = (char *)malloc(size + 1);
  if (!input) return 0;
  memcpy(input, data, size);
  input[size] = '\0';
  char error[256];
  toml_table_t *table = toml_parse(input, error, (int)sizeof(error));
  if (table) toml_free(table);
  free(input);
  return 0;
}
