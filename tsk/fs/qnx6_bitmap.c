#include "qnx6_bitmap.h"
#include <stdlib.h>
int tsk_qnx6_bitmap_raw_bit(const TSK_QNX6_PROBE_INFO *sb,
                            const TSK_QNX6_ROOT *bitmap_tree,
                            uint64_t data_block_index,
                            TSK_QNX6_READ_BLOCK read_block, void *context,
                            int *bit_value) {
    uint64_t bitmap_logical, physical;
    uint8_t *buf;
    size_t byte_offset;
    if (!sb || !bitmap_tree || !read_block || !bit_value ||
        sb->block_size<512 || sb->block_size>65536 ||
        (sb->block_size & (sb->block_size-1)) ||
        data_block_index>=sb->block_count) return 0;
    bitmap_logical=(data_block_index/8)/sb->block_size;
    byte_offset=(size_t)((data_block_index/8)%sb->block_size);
    if (!tsk_qnx6_map_block(sb,bitmap_tree,bitmap_logical,read_block,
                            context,&physical)) return 0;
    buf=(uint8_t *)malloc(sb->block_size);
    if (!buf) return 0;
    if (!read_block(context,physical,buf,sb->block_size)) {
        free(buf);
        return 0;
    }
    *bit_value=(buf[byte_offset] >> (data_block_index%8)) & 1;
    free(buf);
    return 1;
}

/* A full bitmap census guards against assuming that one means allocated.
 * A mismatch or an ambiguous result is never silently accepted. */
int tsk_qnx6_bitmap_free_bit(const TSK_QNX6_PROBE_INFO *sb,
                              const TSK_QNX6_ROOT *bitmap_tree,
                              TSK_QNX6_READ_BLOCK read_block, void *context,
                              int *free_bit) {
    uint8_t *buf;
    uint64_t bits_done=0, ones=0, logical=0, physical;
    if (!sb || !bitmap_tree || !read_block || !free_bit ||
        sb->block_size<512 || sb->block_size>65536 ||
        (sb->block_size & (sb->block_size-1)) ||
        !sb->block_count || sb->free_blocks>sb->block_count) return 0;
    buf=(uint8_t *)malloc(sb->block_size);
    if (!buf) return 0;
    while(bits_done<sb->block_count) {
        uint64_t remaining=(uint64_t)sb->block_count-bits_done;
        uint64_t nbits=remaining<(uint64_t)sb->block_size*8
                      ? remaining:(uint64_t)sb->block_size*8;
        uint64_t i;
        if (!tsk_qnx6_map_block(sb,bitmap_tree,logical++,read_block,
                                context,&physical) ||
            !read_block(context,physical,buf,sb->block_size)) {
            free(buf);return 0;
        }
        for(i=0;i<nbits/8;i++) {
            uint8_t b=buf[i];
            while(b) {ones+=(b&1);b>>=1;}
        }
        if (nbits%8) {
            uint8_t b=(uint8_t)(buf[nbits/8] & ((1U<<(nbits%8))-1U));
            while(b) {ones+=(b&1);b>>=1;}
        }
        bits_done+=nbits;
    }
    free(buf);
    if (ones==sb->free_blocks &&
        (uint64_t)sb->block_count-ones!=sb->free_blocks) {
        *free_bit=1;return 1;
    }
    if ((uint64_t)sb->block_count-ones==sb->free_blocks &&
        ones!=sb->free_blocks) {
        *free_bit=0;return 1;
    }
    return 0;
}
