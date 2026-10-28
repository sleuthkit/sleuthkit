#include "../tsk/fs/qnx6_bitmap.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>
typedef struct { uint8_t bitmap[512]; } Fixture;
static int read_block(void *opaque,uint64_t physical,uint8_t *dest,size_t len) {
    Fixture *f=(Fixture *)opaque;
    if (physical!=25 || len!=512) return 0;
    memcpy(dest,f->bitmap,512);
    return 1;
}
int main(void) {
    TSK_QNX6_PROBE_INFO sb;
    TSK_QNX6_ROOT tree;
    Fixture fixture;
    int bit=-1;
    memset(&sb,0,sizeof(sb));
    memset(&tree,0,sizeof(tree));
    memset(&fixture,0,sizeof(fixture));
    sb.block_size=512;
    sb.block_count=4096;
    tree.ptr[0]=1; /* mapper adds 24 filesystem header blocks at 512-byte sectors */
    fixture.bitmap[0]=0x81;
    fixture.bitmap[1]=0x02;
    assert(tsk_qnx6_bitmap_raw_bit(&sb,&tree,0,read_block,&fixture,&bit) && bit==1);
    assert(tsk_qnx6_bitmap_raw_bit(&sb,&tree,1,read_block,&fixture,&bit) && bit==0);
    assert(tsk_qnx6_bitmap_raw_bit(&sb,&tree,7,read_block,&fixture,&bit) && bit==1);
    assert(tsk_qnx6_bitmap_raw_bit(&sb,&tree,9,read_block,&fixture,&bit) && bit==1);
    assert(!tsk_qnx6_bitmap_raw_bit(&sb,&tree,4096,read_block,&fixture,&bit));
    return 0;
}
