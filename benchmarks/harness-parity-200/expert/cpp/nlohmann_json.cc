// SPDX-License-Identifier: Apache-2.0

#include <cstddef>
#include <cstdint>
#include "single_include/nlohmann/json.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    try {
        auto value = nlohmann::json::parse(data, data + size);
        (void)value.dump();
    } catch (const nlohmann::json::exception &) {
    }
    return 0;
}
