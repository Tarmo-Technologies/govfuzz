// SPDX-License-Identifier: Apache-2.0

#include <stddef.h>
#include <stdint.h>
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int width = 0, height = 0, channels = 0;
    unsigned char *pixels = stbi_load_from_memory(data, (int)size, &width, &height, &channels, 0);
    stbi_image_free(pixels);
    return 0;
}
