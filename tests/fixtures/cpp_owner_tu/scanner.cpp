// SPDX-License-Identifier: Apache-2.0
// The OWNER translation unit: it establishes the context `scanner.hpp` needs
// (the include and the constant) before including it. Compiling this TU is how
// the header becomes usable.
#include <cstddef>

enum : std::size_t { ScannerLimit = 4 };

#include "scanner.hpp"

int scan_twice(const unsigned char *data, std::size_t len) {
    return scan_bytes(data, len);
}
