#ifndef TSK_QNX6_MAP_H
#define TSK_QNX6_MAP_H
#include <stdint.h>
#include <stddef.h>
#include "qnx6_probe.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Returns 1 on success, 0 for holes/invalid mapping. No image writes. */
typedef int (*TSK_QNX6_READ_BLOCK)(void *context, uint64_t physical_block,
                                    uint8_t *destination, size_t block_size);
typedef struct {
    uint32_t ptr[16];
    uint8_t levels;
} TSK_QNX6_ROOT;
int tsk_qnx6_parse_root(const uint8_t *sb, size_t len, size_t offset,
                        TSK_QNX6_ROOT *root);
int tsk_qnx6_map_block(const TSK_QNX6_PROBE_INFO *sb,
                       const TSK_QNX6_ROOT *root, uint64_t logical_block,
                       TSK_QNX6_READ_BLOCK read_block, void *context,
                       uint64_t *physical_block);
#ifdef __cplusplus
}
#endif
#endif
