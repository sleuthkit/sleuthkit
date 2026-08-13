/*
 * The Sleuth Kit
 *
 * XPRESS (MS-XCA) decompression: plain LZ77 and LZ77+Huffman variants.
 *
 * See xpress.c for a description of both formats. The LZ77+Huffman variant
 * requires the caller to know the uncompressed size, so both functions take
 * dst_size as the expected output length. They return the number of bytes
 * written, or -1 when the stream is corrupt or truncated.
 */
#ifndef XPRESS_H
#define XPRESS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Plain LZ77 (MS-XCA section 2.1.1). The stream is self-terminating. */
int xpress_plain_lz77_decode(void *dst, size_t dst_size,
                             const void *src, size_t src_size);

/* LZ77+Huffman (MS-XCA sections 2.1.2 and 2.1.4). */
int xpress_huffman_decode(void *dst, size_t dst_size,
                          const void *src, size_t src_size);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* XPRESS_H */