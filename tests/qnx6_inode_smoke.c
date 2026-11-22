#include "../tsk/fs/qnx6_inode.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>

static uint8_t inode_block[4096], directory_block[4096];
static int read_block(void *unused, uint64_t block, uint8_t *out, size_t len) {
    (void)unused;
    if (len != 4096) return 0;
    if (block == 4) memcpy(out, inode_block, len);
    else if (block == 5) memcpy(out, directory_block, len);
    else return 0;
    return 1;
}
static int entry(void *context, uint32_t ino, const char *name, size_t length) {
    unsigned *seen=(unsigned *)context;
    assert(ino==2);
    assert(length==4 && memcmp(name,"test",4)==0);
    ++*seen;
    return 1;
}
int main(void) {
    TSK_QNX6_PROBE_INFO sb={0};
    TSK_QNX6_ROOT table={0};
    TSK_QNX6_INODE inode={0};
    unsigned seen=0;
    sb.block_size=4096;
    sb.block_count=100;
    sb.inode_count=32;
    table.ptr[0]=1; /* physical 4 */
    /* inode 1 at offset zero */
    inode_block[0]=32; /* size = 32 bytes */
    inode_block[32]=0; inode_block[33]=0x40; /* directory */
    inode_block[36]=2; /* physical 5 */
    directory_block[0]=2; /* inode 2 */
    directory_block[4]=4;
    memcpy(directory_block+5,"test",4);
    assert(tsk_qnx6_read_inode(&sb,&table,1,read_block,0,&inode));
    assert(inode.size==32 && inode.mode==0040000);
    assert(tsk_qnx6_walk_directory(&sb,&inode,read_block,0,entry,&seen));
    assert(seen==1);
    assert(!tsk_qnx6_read_inode(&sb,&table,0,read_block,0,&inode));
    return 0;
}
