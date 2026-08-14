#include <libxml/parser.h>
#include <libxml/tree.h>
#include <limits.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > INT_MAX) return 0;
  xmlDoc *doc = xmlReadMemory((const char *)data, (int)size, NULL, NULL,
                              XML_PARSE_NONET);
  if (doc) xmlFreeDoc(doc);
  return 0;
}
