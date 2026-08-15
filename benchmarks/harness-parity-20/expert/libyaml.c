/* SPDX-License-Identifier: Apache-2.0 */
#include <yaml.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  yaml_parser_t p; if (!yaml_parser_initialize(&p)) return 0;
  yaml_parser_set_input_string(&p, data, size);
  for (;;) { yaml_event_t e; if (!yaml_parser_parse(&p, &e)) break; yaml_event_type_t t=e.type; yaml_event_delete(&e); if (t==YAML_STREAM_END_EVENT) break; }
  yaml_parser_delete(&p); return 0;
}
