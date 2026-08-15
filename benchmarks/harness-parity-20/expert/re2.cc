/* SPDX-License-Identifier: Apache-2.0 */
#include "re2/regexp.h"
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  re2::RegexpStatus status; re2::Regexp *r = re2::Regexp::Parse(absl::string_view((const char *)data,size), re2::Regexp::LikePerl, &status);
  if (r) r->Decref(); return 0;
}
