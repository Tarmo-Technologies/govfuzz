/* SPDX-License-Identifier: Apache-2.0 */
#include <archive.h>
#include <archive_entry.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct archive *a = archive_read_new(); if (!a) return 0;
  archive_read_support_filter_all(a); archive_read_support_format_all(a);
  if (archive_read_open_memory2(a, data, size, 10240) == ARCHIVE_OK) {
    struct archive_entry *e;
    while (archive_read_next_header(a, &e) == ARCHIVE_OK) archive_read_data_skip(a);
  }
  archive_read_free(a); return 0;
}
