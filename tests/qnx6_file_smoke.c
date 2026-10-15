#include "../tsk/fs/qnx6_inode.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>
static int read_block(void *ctx, uint64_t n, uint8_t *dst, size_t sz) {
    (void)ctx;
    if (n != 4 || sz != 4096) return 0;
    memset(dst, 0x5a, sz);
    return 1;
}
int main(void) {
    TSK_QNX6_PROBE_INFO sb = {0};
    TSK_QNX6_INODE ino = {0};
    uint8_t out[32];
    size_t got = 99;
    sb.block_size=4096;
    sb.block_count=100;
    ino.size=4096;
    ino.data.ptr[0]=1; /* + 0x3000 / 4096 => physical block 4 */
    assert(tsk_qnx6_read_file(&sb,&ino,4090,out,sizeof(out),read_block,0,&got));
    assert(got==6 && out[0]==0x5a && out[5]==0x5a);
    assert(tsk_qnx6_read_file(&sb,&ino,4096,out,sizeof(out),read_block,0,&got));
    assert(got==0);
    ino.data.ptr[0]=0;
    assert(!tsk_qnx6_read_file(&sb,&ino,0,out,sizeof(out),read_block,0,&got));
    assert(got==0);
    return 0;
}
