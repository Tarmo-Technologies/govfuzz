// SPDX-License-Identifier: Apache-2.0
#include <stddef.h>
#include <unistd.h>
int target_one_input(const unsigned char *data, size_t size);
__AFL_FUZZ_INIT();
int main(void) {
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(100000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;
        target_one_input(buf, len);
    }
    return 0;
}
