#include "qnx6_inode.h"
#include <stdlib.h>
#include <string.h>

/* Fail-closed forensic reads: until sparse-hole and corruption status can be
 * distinguished, an unmapped logical block is an error, never fabricated
 * zero data. */
int tsk_qnx6_read_file(const TSK_QNX6_PROBE_INFO *sb,
                       const TSK_QNX6_INODE *inode, uint64_t offset,
                       uint8_t *destination, size_t capacity,
                       TSK_QNX6_READ_BLOCK read_block, void *read_context,
                       size_t *bytes_read) {
    uint8_t *block;
    size_t done=0, wanted;
    uint64_t logical, physical;
    if (bytes_read) *bytes_read=0;
    if (!sb || !inode || !bytes_read || !read_block ||
        (!destination && capacity) || sb->block_size<512 ||
        sb->block_size>65536 || (sb->block_size&(sb->block_size-1)))
        return 0;
    if (offset>=inode->size || !capacity) return 1;
    wanted=(inode->size-offset < (uint64_t)capacity)
         ? (size_t)(inode->size-offset) : capacity;
    block=(uint8_t *)malloc(sb->block_size);
    if (!block) return 0;
    while(done<wanted) {
        size_t within, take;
        uint64_t position=offset+done;
        logical=position/sb->block_size;
        within=(size_t)(position%sb->block_size);
        take=sb->block_size-within;
        if (take>wanted-done) take=wanted-done;
        if (tsk_qnx6_map_block(sb,&inode->data,logical,read_block,
                              read_context,&physical)) {
            if (!read_block(read_context,physical,block,sb->block_size)) {
                free(block); return 0;
            }
            memcpy(destination+done,block+within,take);
        } else {
            free(block);
            return 0;
        }
        done+=take;
    }
    free(block);
    *bytes_read=done;
    return 1;
}
