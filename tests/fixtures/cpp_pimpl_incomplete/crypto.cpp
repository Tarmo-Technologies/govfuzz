// SPDX-License-Identifier: Apache-2.0
#include "crypto.h"

// The definition the harness TU never sees (it only #includes crypto.h).
class EncryptionParametersImpl {
public:
    int scheme;
};

EncryptionParametersImpl load_params(const char *data, unsigned long len) {
    EncryptionParametersImpl impl;
    impl.scheme = (len > 0) ? data[0] : 0;
    return impl;
}
