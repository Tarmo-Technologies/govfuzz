// SPDX-License-Identifier: Apache-2.0
// A fuzzable function that is ALSO statically weak (unsafe string copy). Used to
// verify `auto --static` runs a whole-tree static scan alongside fuzzing and
// merges its findings (classification static_scan) into the unified report.
#include <string.h>

int handle_request(const char *name) {
    char buf[64];
    strcpy(buf, name); // CWE-120: unsafe string copy (static-scan finding)
    return (int)strlen(buf);
}
