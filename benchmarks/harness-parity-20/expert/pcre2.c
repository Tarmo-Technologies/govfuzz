#include <pcre2posix.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == SIZE_MAX) return 0;
  char *pattern = (char *)malloc(size + 1);
  if (!pattern) return 0;
  memcpy(pattern, data, size);
  pattern[size] = '\0';
  regex_t regex;
  if (pcre2_regcomp(&regex, pattern, 0) == 0) pcre2_regfree(&regex);
  free(pattern);
  return 0;
}
