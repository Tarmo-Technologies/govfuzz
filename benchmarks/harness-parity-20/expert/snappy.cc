#include "snappy.h"
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string output;
  (void)snappy::Uncompress(reinterpret_cast<const char *>(data), size, &output);
  return 0;
}
