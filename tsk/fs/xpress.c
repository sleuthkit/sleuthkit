/*
 * The Sleuth Kit
 *
 * XPRESS (MS-XCA) decompression: plain LZ77 and LZ77+Huffman variants.
 *
 * Clean-room implementation written against the MS-XCA specification
 * ("Xpress Compression Algorithm", Open Specifications) and validated with
 * the worked examples in section 3.1 of that document. The plain LZ77
 * variant is the COMPRESSION_FORMAT_XPRESS format of the Windows
 * RtlCompressBuffer API (used e.g. for hibernation files); the LZ77+Huffman
 * variant is the COMPRESSION_FORMAT_XPRESS_HUFF format used in WIM images
 * and in Windows Overlay Filter (Compact OS) NTFS files.
 *
 * Plain LZ77 (MS-XCA 2.1.1):
 *   The stream is a sequence of 32-bit flag groups, each flag tested from
 *   bit 31 down. A clear bit is a literal byte. A set bit is a match: an
 *   LE16 word with (offset-1) in the top 13 bits and (length-3) in the low
 *   3 bits. A length of 7 selects the shared-nibble form: the low nibble of
 *   the next stream byte supplies the real length for this match, and the
 *   high nibble of that same byte supplies the length of the next
 *   consecutive match that also uses this form (any other token drops the
 *   pending half). A nibble of 15 selects a raw length: a byte >= 22, or if
 *   that byte is 255, an LE16, or if that is 0, an LE32. The final flag
 *   group is padded with set bits; a match flag with no input left is the
 *   end-of-data marker.
 *
 * LZ77+Huffman (MS-XCA 2.1.2/2.1.4):
 *   The first 256 bytes hold 512 4-bit code lengths (even symbol in the low
 *   nibble, odd in the high). Canonical codes are assigned in (length,
 *   symbol) order, most-significant bit first. The bit stream follows as
 *   LE16 words, MSB first, read through a 32-bit register that is refilled
 *   while fewer than 15 bits remain. Symbols 0..255 are literals. Symbol
 *   256 is end-of-data; mid-stream it decodes as a match of length 3 at
 *   distance 1 (Microsoft behavior). Symbols 257..511 are matches: the low
 *   nibble is (length-3), a value of 15 selecting a raw extension byte
 *   (length = byte + 18, or if the byte is 255, an LE16/LE32 value plus 3),
 *   and the high nibble is the position of the highest set bit of the
 *   offset, whose remaining low bits follow in the stream. The uncompressed
 *   size must be known in advance (the caller supplies it) because
 *   end-of-data is only recognized once the output is complete.
 */
#include "xpress.h"

#include <stdlib.h>

/* Number of Huffman symbols (256 literals + 256 match symbols). */
#define XPRESS_NUM_SYMBOLS 512

/* Depth of the canonical decode table (maximum code length is 15). */
#define XPRESS_TABLEBITS 15
#define XPRESS_TABLE_SIZE ((size_t)1 << XPRESS_TABLEBITS)   /* 32768 entries */

static inline uint16_t xpress_le16(const unsigned char *p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

static inline uint32_t xpress_le32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ------------------------------------------------------------------------
 * Plain LZ77
 */

int xpress_plain_lz77_decode(void *dst, size_t dst_size,
                             const void *src, size_t src_size) {
    const unsigned char *in = (const unsigned char *)src;
    const unsigned char *in_end = in + src_size;
    unsigned char *out = (unsigned char *)dst;
    unsigned char *out_end = out + dst_size;
    uint32_t flags = 0;
    int flags_left = 0;
    /* Offset of the shared-nibble byte, or (size_t)-1 when none is pending. */
    size_t pending_len = (size_t)-1;

    while (out < out_end) {
        if (flags_left == 0) {
            if (in_end - in < 4) {
                return -1;
            }
            flags = xpress_le32(in);
            in += 4;
            flags_left = 32;
        }
        --flags_left;
        if ((flags & ((uint32_t)1 << flags_left)) == 0) {
            /* Literal clears the pending shared-nibble half. */
            pending_len = (size_t)-1;
            if (in >= in_end) {
                return -1;
            }
            *out++ = *in++;
            continue;
        }
        /* A set flag with no input left is the end-of-data marker. */
        if (in >= in_end) {
            return (int)(out - (unsigned char *)dst);
        }
        if (in_end - in < 2) {
            return -1;
        }
        {
            uint16_t mb = xpress_le16(in);
            in += 2;
            size_t moff = (size_t)(mb >> 3) + 1;
            size_t mlen = (size_t)(mb & 7) + 3;

            if ((mb & 7) == 7) {
                int nib;
                if (pending_len == (size_t)-1) {
                    if (in >= in_end) {
                        return -1;
                    }
                    nib = *in & 0x0F;
                    pending_len = (size_t)(in - (const unsigned char *)src);
                    in++;
                }
                else {
                    nib = ((const unsigned char *)src)[pending_len] >> 4;
                    pending_len = (size_t)-1;
                }
                if (nib == 15) {
                    uint32_t v;
                    if (in >= in_end) {
                        return -1;
                    }
                    v = *in++;
                    if (v == 255) {
                        if (in_end - in < 2) {
                            return -1;
                        }
                        v = xpress_le16(in);
                        in += 2;
                        if (v == 0) {
                            if (in_end - in < 4) {
                                return -1;
                            }
                            v = xpress_le32(in);
                            in += 4;
                        }
                    }
                    if (v < 22) {
                        return -1;
                    }
                    mlen = (size_t)v + 3;
                }
                else {
                    mlen = (size_t)nib + 3;
                }
            }
            if (moff > 8192 ||
                    moff > (size_t)(out - (unsigned char *)dst)) {
                return -1;
            }
            if (mlen > (size_t)(out_end - out)) {
                return -1;
            }
            {
                const unsigned char *srcp = out - moff;
                while (mlen-- > 0) {
                    *out++ = *srcp++;
                }
            }
        }
    }
    return (int)(out - (unsigned char *)dst);
}

/* ------------------------------------------------------------------------
 * LZ77+Huffman
 */

int xpress_huffman_decode(void *dst, size_t dst_size,
                          const void *src, size_t src_size) {
    const unsigned char *in = (const unsigned char *)src;
    const unsigned char *in_end = in + src_size;
    unsigned char *out = (unsigned char *)dst;
    unsigned char *out_start = out;
    unsigned char *out_end = out + dst_size;
    uint16_t lens[XPRESS_NUM_SYMBOLS];
    uint16_t *table;
    size_t entry = 0;
    int l, s;
    uint32_t bits = 0;
    int nbits = 0;

    if (src_size < 256) {
        return -1;
    }

    /* 512 4-bit code lengths, even symbol in the low nibble. */
    for (l = 0; l < 256; l++) {
        lens[l * 2] = (uint16_t)(in[l] & 0x0F);
        lens[l * 2 + 1] = (uint16_t)(in[l] >> 4);
    }
    in += 256;

    /* Decode table filled in canonical (length, symbol) order. */
    table = (uint16_t *)malloc(XPRESS_TABLE_SIZE * sizeof(uint16_t));
    if (table == NULL) {
        return -1;
    }
    for (l = 1; l <= XPRESS_TABLEBITS; l++) {
        for (s = 0; s < XPRESS_NUM_SYMBOLS; s++) {
            if (lens[s] == l) {
                int k;
                for (k = 1 << (XPRESS_TABLEBITS - l); k > 0; k--) {
                    if (entry >= XPRESS_TABLE_SIZE) {
                        /* Oversubscribed codes: the table cannot hold
                         * this many entries. */
                        free(table);
                        return -1;
                    }
                    table[entry++] = (uint16_t)s;
                }
            }
        }
    }
    if (entry != XPRESS_TABLE_SIZE) {
        /* The code lengths must form a complete prefix code. */
        free(table);
        return -1;
    }

    /* Preload two LE16 words, most-significant bit first. */
    while (nbits < 32) {
        if (in_end - in < 2) {
            free(table);
            return -1;
        }
        bits |= (uint32_t)xpress_le16(in) << (16 - nbits);
        in += 2;
        nbits += 16;
    }

    while (out < out_end) {
        uint32_t sym;
        int clen;

        while (nbits < 15) {
            if (in_end - in < 2) {
                free(table);
                return -1;
            }
            bits |= (uint32_t)xpress_le16(in) << (16 - nbits);
            in += 2;
            nbits += 16;
        }
        sym = table[(bits >> 17) & 0x7FFF];
        clen = lens[sym];
        bits = (bits << clen) & 0xFFFFFFFFu;
        nbits -= clen;

        if (sym < 256) {
            *out++ = (unsigned char)sym;
            continue;
        }

        if (sym == 256) {
            /* End of data; Microsoft decodes it as match(3, 1) mid-stream. */
            if (out == out_end) {
                break;
            }
            if (out == out_start || out_end - out < 3) {
                free(table);
                return -1;
            }
            {
                unsigned char *srcp = out - 1;
                int i;
                for (i = 0; i < 3; i++) {
                    *out++ = *srcp++;
                }
            }
            continue;
        }

        {
            int hb = (int)(sym - 256) / 16;
            size_t mlen = (size_t)((sym - 256) % 16);
            size_t moff;

            if (mlen == 15) {
                uint32_t v;
                if (in >= in_end) {
                    free(table);
                    return -1;
                }
                v = *in++;
                if (v == 255) {
                    if (in_end - in < 2) {
                        free(table);
                        return -1;
                    }
                    v = xpress_le16(in);
                    in += 2;
                    if (v == 0) {
                        if (in_end - in < 4) {
                            free(table);
                            return -1;
                        }
                        v = xpress_le32(in);
                        in += 4;
                    }
                    mlen = (size_t)v + 3;
                }
                else {
                    mlen = (size_t)v + 18;
                }
            }
            else {
                mlen += 3;
            }

            while (nbits < hb) {
                if (in_end - in < 2) {
                    free(table);
                    return -1;
                }
                bits |= (uint32_t)xpress_le16(in) << (16 - nbits);
                in += 2;
                nbits += 16;
            }
            moff = hb ? ((size_t)((bits >> (32 - hb)) &
                                 (((uint32_t)1 << hb) - 1))) : 0;
            bits = (bits << hb) & 0xFFFFFFFFu;
            nbits -= hb;
            moff += (size_t)1 << hb;

            if (moff > (size_t)(out - (unsigned char *)dst)) {
                free(table);
                return -1;
            }
            if (mlen > (size_t)(out_end - out)) {
                free(table);
                return -1;
            }
            {
                const unsigned char *srcp = out - moff;
                while (mlen-- > 0) {
                    *out++ = *srcp++;
                }
            }
        }
    }
    free(table);
    return (int)(out - (unsigned char *)dst);
}