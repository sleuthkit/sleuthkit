/*
 * The Sleuth Kit
 *
 * Fuzz target for the XPRESS (MS-XCA) decompressors in tsk/fs/xpress.c.
 *
 * Input layout:
 *   byte 0     : 0 -> plain LZ77, 1 -> LZ77+Huffman
 *   bytes 1-4  : uncompressed size (LE32) for the Huffman variant,
 *                ignored for the plain variant
 *   bytes 5+   : compressed stream
 *
 * The plain LZ77 variant is self-terminating; the Huffman variant
 * requires the output size, which the caller supplies.
 */

#include <stdint.h>
#include <string.h>

#include <cstdlib>

#include "tsk/fs/xpress.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 5) {
        return 0;
    }

    const uint8_t *src = data + 5;
    size_t src_size = size - 5;
    uint8_t *dst = nullptr;

    if (data[0] == 0) {
        /* Plain LZ77: decompress into a 1 MiB bound buffer. */
        dst = (uint8_t *)malloc(1024 * 1024);
        if (dst == nullptr) {
            return 0;
        }
        xpress_plain_lz77_decode(dst, 1024 * 1024, src, src_size);
        free(dst);
        return 0;
    }

    if (data[0] == 1) {
        /* LZ77+Huffman: output size comes from the input. */
        uint32_t dst_size = (uint32_t)data[1] | ((uint32_t)data[2] << 8) |
                            ((uint32_t)data[3] << 16) |
                            ((uint32_t)data[4] << 24);
        if (dst_size > 1024 * 1024) {
            return 0;
        }
        dst = (uint8_t *)malloc(dst_size == 0 ? 1 : dst_size);
        if (dst == nullptr) {
            return 0;
        }
        xpress_huffman_decode(dst, dst_size, src, src_size);
        free(dst);
        return 0;
    }

    return 0;
}
