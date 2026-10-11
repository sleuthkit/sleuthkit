#ifndef TSK_QNX6_INODE_H
#define TSK_QNX6_INODE_H
#include "qnx6_map.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    uint64_t size;
    uint32_t mtime;
    uint16_t mode;
    TSK_QNX6_ROOT data;
} TSK_QNX6_INODE;
typedef int (*TSK_QNX6_DIRENT_CB)(void *context, uint32_t inode,
                                    const char *name, size_t length);
/* Return 1 on success. Image callback uses absolute filesystem block indices. */
int tsk_qnx6_read_inode(const TSK_QNX6_PROBE_INFO *sb,
                        const TSK_QNX6_ROOT *inode_tree, uint32_t inode_number,
                        TSK_QNX6_READ_BLOCK read_block, void *read_context,
                        TSK_QNX6_INODE *out);
/* Reads up to capacity bytes at offset; holes are zero-filled. Returns 1 on success. */
int tsk_qnx6_read_file(const TSK_QNX6_PROBE_INFO *sb,
                       const TSK_QNX6_INODE *inode, uint64_t offset,
                       uint8_t *destination, size_t capacity,
                       TSK_QNX6_READ_BLOCK read_block, void *read_context,
                       size_t *bytes_read);
int tsk_qnx6_walk_directory(const TSK_QNX6_PROBE_INFO *sb,
                            const TSK_QNX6_INODE *directory,
                            const TSK_QNX6_ROOT *longfile,
                            TSK_QNX6_READ_BLOCK read_block, void *read_context,
                            TSK_QNX6_DIRENT_CB callback, void *callback_context);
#ifdef __cplusplus
}
#endif
#endif
