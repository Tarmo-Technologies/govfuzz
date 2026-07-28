// SPDX-License-Identifier: Apache-2.0
// NOT self-contained on purpose: it uses `ScannerLimit` and <cstddef> without
// including or declaring either, so an independent harness translation unit
// cannot `#include` it. Only the owning TU establishes that context first.
//
// This is the shape behind `blocked_by_non_self_contained_header`, the largest
// C++ residual class in the 500-project sweep.

inline int scan_bytes(const unsigned char *data, std::size_t len) {
    if (data == nullptr || len < 2) {
        return 0;
    }
    if (data[0] == 'G') {
        unsigned char window[ScannerLimit];
        // Planted out-of-bounds read (GF-201 / CWE-125).
        return static_cast<int>(window[len]);
    }
    return static_cast<int>(len);
}
