// util.cpp — SPDX-License-Identifier: Apache-2.0
#include "util.h"
namespace UtilitiesLib {
long Extract_Minutes(char* g, long s, long l, long e, double* m) {
    if (!g || s < 0) return -1; *m = (double)(s + l); return e;
}
}
