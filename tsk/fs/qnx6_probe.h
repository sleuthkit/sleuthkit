/*
 * QNX6 superblock recognition for forensic triage.
 * This is deliberately NOT a TSK filesystem reader: inode, directory and
 * allocation traversal must be implemented before registration in fs_open.c.
 */
#ifndef TSK_QNX6_PROBE_H
#define TSK_QNX6_PROBE_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    uint32_t block_size;
    uint32_t inode_count;
    uint32_t block_count;
    uint32_t free_blocks;
    uint32_t flags;
} TSK_QNX6_PROBE_INFO;
/* buf points to >= 72 bytes at the candidate superblock location.
 * Returns 1 only for plausible little-endian QNX6 metadata. */
int tsk_qnx6_probe_superblock(const uint8_t *buf, size_t len,
                             TSK_QNX6_PROBE_INFO *out);
#ifdef __cplusplus
}
#endif
#endif
