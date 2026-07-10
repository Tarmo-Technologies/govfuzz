/* SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "govfuzz_decode.h"

int main(void) {
    const uint8_t data[] = {
        0x10, 0x00, 0x00, 0x00,   /* i32 = 16 */
        0x05, 0x00, 0x00, 0x00,   /* bounded i32 (0..9) -> 5 */
        0x05, 0x00,               /* gf_c_string length prefix = 5 */
        'h','e','l','l','o',      /* string content */
        0xAA                      /* trailing byte left over for next decode */
    };
    gf_cursor c = gf_open(data, sizeof(data));
    char *s;

    assert(gf_i32(&c) == 16);
    assert(gf_bounded_i32(&c, 0, 9) == 5);

    s = gf_c_string(&c, 64);
    assert(s);
    assert(strcmp(s, "hello") == 0);
    free(s);

    /* String consumer left the trailing byte for the next decoder. */
    assert(gf_remaining(&c) == 1);
    assert(gf_u8(&c) == 0xAA);
    return 0;
}
