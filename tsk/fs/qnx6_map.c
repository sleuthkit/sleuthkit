#include "qnx6_map.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) |
           ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
int tsk_qnx6_parse_root(const uint8_t *sb, size_t len, size_t offset,
                        TSK_QNX6_ROOT *root) {
    size_t i;
    if (!sb || !root || offset > len || len-offset < 73) return 0;
    memset(root, 0, sizeof(*root));
    for (i=0;i<16;i++) root->ptr[i]=le32(sb+offset+8+i*4);
    root->levels=sb[offset+72];
    return root->levels <= 4;
}
int tsk_qnx6_map_block(const TSK_QNX6_PROBE_INFO *sb,
                       const TSK_QNX6_ROOT *root, uint64_t logical_block,
                       TSK_QNX6_READ_BLOCK read_block, void *context,
                       uint64_t *physical_block) {
    uint64_t fanout, span=1, index, blk, base;
    uint8_t *buf;
    unsigned int depth, i;
    if (!sb || !root || !physical_block || !read_block ||
        sb->block_size < 512 || sb->block_size > 65536 ||
        (sb->block_size & (sb->block_size-1)) || root->levels > 4) return 0;
    fanout=sb->block_size/4;
    for (i=0;i<root->levels;i++) {
        if (span > UINT64_MAX/fanout) return 0;
        span*=fanout;
    }
    index=logical_block/span;
    if (index>=16 || root->ptr[index]==0 || root->ptr[index]==UINT32_MAX) return 0;
    /* QNX6 data blocks follow the 0x2000 boot and 0x1000 superblock areas. */
    base=(0x2000U/sb->block_size)+(0x1000U/sb->block_size);
    blk=(uint64_t)root->ptr[index]+base;
    if (blk >= (uint64_t)sb->block_count+base) return 0;
    if (!root->levels) { *physical_block=blk; return 1; }
    buf=(uint8_t *)malloc(sb->block_size);
    if (!buf) return 0;
    for (depth=root->levels;depth>0;depth--) {
        uint32_t p;
        if (!read_block(context,blk,buf,sb->block_size)) { free(buf); return 0; }
        span/=fanout;
        index=(logical_block/span)%fanout;
        p=le32(buf+index*4);
        if (!p || p==UINT32_MAX) { free(buf); return 0; }
        blk=(uint64_t)p+base;
        if (blk >= (uint64_t)sb->block_count+base) { free(buf); return 0; }
    }
    free(buf);
    *physical_block=blk;
    return 1;
}
