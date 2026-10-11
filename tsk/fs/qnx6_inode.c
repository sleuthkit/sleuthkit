#include "qnx6_inode.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
static uint16_t le16(const uint8_t *p) {return (uint16_t)(p[0]|((uint16_t)p[1]<<8));}
static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static uint64_t le64(const uint8_t *p) {
    return (uint64_t)le32(p)|((uint64_t)le32(p+4)<<32);
}
int tsk_qnx6_read_inode(const TSK_QNX6_PROBE_INFO *sb,
                        const TSK_QNX6_ROOT *inode_tree, uint32_t inode_number,
                        TSK_QNX6_READ_BLOCK read_block, void *read_context,
                        TSK_QNX6_INODE *out) {
    uint8_t *buf, *raw;
    uint64_t blk;
    size_t off, i;
    if (!sb || !inode_tree || !out || !read_block || !inode_number ||
        inode_number > sb->inode_count || sb->block_size < 512 ||
        sb->block_size % 128) return 0;
    off=(size_t)(((uint64_t)(inode_number-1)*128)%sb->block_size);
    if (!tsk_qnx6_map_block(sb,inode_tree,((uint64_t)(inode_number-1)*128)/sb->block_size,
                           read_block,read_context,&blk)) return 0;
    buf=(uint8_t *)malloc(sb->block_size);
    if (!buf) return 0;
    if (!read_block(read_context,blk,buf,sb->block_size)) {free(buf);return 0;}
    raw=buf+off;
    memset(out,0,sizeof(*out));
    out->size=le64(raw);
    out->mtime=le32(raw+20);
    out->mode=le16(raw+32);
    for(i=0;i<16;i++) out->data.ptr[i]=le32(raw+36+i*4);
    out->data.levels=raw[100];
    free(buf);
    return out->data.levels<=4;
}
int tsk_qnx6_walk_directory(const TSK_QNX6_PROBE_INFO *sb,
                            const TSK_QNX6_INODE *directory,
                            const TSK_QNX6_ROOT *longfile,
                            TSK_QNX6_READ_BLOCK read_block, void *read_context,
                            TSK_QNX6_DIRENT_CB callback, void *callback_context) {
    uint8_t *buf;
    uint64_t logical, count, blk, remaining;
    size_t pos, available, name_len;
    if (!sb || !directory || !read_block || !callback ||
        (directory->mode & 0170000) != 0040000 ||
        sb->block_size < 512 || sb->block_size > 65536) return 0;
    count=directory->size/sb->block_size+
          (directory->size%sb->block_size!=0);
    if (count>sb->block_count) return 0;
    buf=(uint8_t *)malloc(sb->block_size);
    if (!buf) return 0;
    remaining=directory->size;
    for(logical=0;logical<count;logical++) {
        if (!tsk_qnx6_map_block(sb,&directory->data,logical,read_block,read_context,&blk)) {
            free(buf);return 0;
        }
        if (!read_block(read_context,blk,buf,sb->block_size)) {free(buf);return 0;}
        available=remaining<sb->block_size?(size_t)remaining:sb->block_size;
        for(pos=0;pos+32<=available;pos+=32) {
            uint32_t inode=le32(buf+pos);
            uint8_t len=buf[pos+4];
            if (!inode || !len || inode>sb->inode_count) continue;
            if (len==255) {
                uint32_t longblock=le32(buf+pos+8);
                uint64_t phys;
                uint8_t *nameblock;
                uint16_t longlen;
                if (!longfile || !tsk_qnx6_map_block(sb,longfile,longblock,
                            read_block,read_context,&phys)) {free(buf);return 0;}
                nameblock=(uint8_t *)malloc(sb->block_size);
                if (!nameblock) {free(buf);return 0;}
                if (!read_block(read_context,phys,nameblock,sb->block_size)) {
                    free(nameblock);free(buf);return 0;
                }
                longlen=le16(nameblock);
                if (!longlen || longlen>510 || longlen+2>sb->block_size) {
                    free(nameblock);free(buf);return 0;
                }
                if (!callback(callback_context,inode,(const char *)nameblock+2,longlen)) {
                    free(nameblock);free(buf);return 0;
                }
                free(nameblock);
                continue;
            }
            if (len>27) continue;
            name_len=len;
            if ((name_len==1 && buf[pos+5]=='.') ||
                (name_len==2 && buf[pos+5]=='.' && buf[pos+6]=='.')) continue;
            if (!callback(callback_context,inode,(const char *)(buf+pos+5),name_len)) {
                free(buf);return 0;
            }
        }
        remaining-=available;
    }
    free(buf);
    return 1;
}
