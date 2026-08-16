// SPDX-License-Identifier: Apache-2.0

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libcob.h>

extern int FILE__OPS(cob_u8_t *, cob_u8_t *, cob_u8_t *, cob_u8_t *);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static int ready;
    if (!ready) { cob_init(0, NULL); ready = 1; }
    char path[] = "/tmp/webbol-fuzz-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return 0;
    for (size_t offset = 0; offset < size;) {
        ssize_t written = write(fd, data + offset, size - offset);
        if (written <= 0) break;
        offset += (size_t)written;
    }
    close(fd);
    unsigned char cobol_path[512], output[65536], output_size[8], result[8];
    memset(cobol_path, ' ', sizeof cobol_path);
    memcpy(cobol_path, path, strlen(path));
    memset(output, ' ', sizeof output);
    memset(output_size, 0, sizeof output_size);
    memset(result, 0, sizeof result);
    (void)FILE__OPS(cobol_path, output, output_size, result);
    unlink(path);
    return 0;
}
