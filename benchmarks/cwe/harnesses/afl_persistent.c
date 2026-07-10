// SPDX-License-Identifier: Apache-2.0
#include <stddef.h>
#include <unistd.h>
int FN(const unsigned char *data, size_t size);
__AFL_FUZZ_INIT();
int main(void){ __AFL_INIT(); unsigned char*b=__AFL_FUZZ_TESTCASE_BUF;
  while(__AFL_LOOP(100000)){ size_t n=__AFL_FUZZ_TESTCASE_LEN; FN(b,n);} return 0; }
