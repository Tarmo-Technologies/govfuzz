// SPDX-License-Identifier: Apache-2.0
#include "stdafx.h"
namespace UtilitiesLib {
long Extract_Minutes(char *georef, long start, long length, long err, double *minutes) {
    if (!georef || start < 0) return -1;
    if (length > 3 && georef[0] == 'N') { *minutes = (double)(start + length); return 0; }
    return err;
}
}
