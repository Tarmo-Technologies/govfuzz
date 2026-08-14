#include "src/pugixml.hpp"
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  pugi::xml_document document; (void)document.load_buffer(data, size, pugi::parse_full); return 0;
}
