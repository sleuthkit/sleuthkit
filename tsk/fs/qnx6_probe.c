#include "qnx6_probe.h"
#include <string.h>

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int tsk_qnx6_probe_superblock(const uint8_t *buf, size_t len,
                             TSK_QNX6_PROBE_INFO *out)
{
    uint32_t bs, inodes, blocks, free_blocks;
    if (!buf || !out || len < 72) return 0;
    memset(out, 0, sizeof(*out));
    if (le32(buf) != 0x68191122U) return 0;
    bs = le32(buf + 48);
    inodes = le32(buf + 52);
    blocks = le32(buf + 60);
    free_blocks = le32(buf + 64);
    if (bs < 512 || bs > 65536 || (bs & (bs - 1)) != 0 ||
        inodes == 0 || blocks == 0 || free_blocks > blocks) return 0;
    out->block_size = bs;
    out->inode_count = inodes;
    out->block_count = blocks;
    out->free_blocks = free_blocks;
    out->flags = le32(buf + 24);
    return 1;
}
