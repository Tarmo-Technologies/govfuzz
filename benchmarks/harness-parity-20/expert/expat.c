/* SPDX-License-Identifier: Apache-2.0 */
#include <expat.h>
#include <stdint.h>
static void start(void *u, const XML_Char *n, const XML_Char **a) {(void)u;(void)n;(void)a;}
static void end(void *u, const XML_Char *n) {(void)u;(void)n;}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  XML_Parser p = XML_ParserCreate(NULL); if (!p) return 0;
  XML_SetElementHandler(p, start, end);
  (void)XML_Parse(p, (const char *)data, (int)(size > 0x7fffffff ? 0x7fffffff : size), 1);
  XML_ParserFree(p); return 0;
}
