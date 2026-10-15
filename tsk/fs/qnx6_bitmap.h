#ifndef TSK_QNX6_BITMAP_H
#define TSK_QNX6_BITMAP_H
#include "qnx6_map.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Read the on-disk allocation bitmap without assuming bit polarity.
 * bit_value: 0 or 1, bit zero is the least significant bit of its byte.
 * Caller must interpret polarity using a validated filesystem fixture.
 * This API never labels a block allocated or unallocated. */
int tsk_qnx6_bitmap_raw_bit(const TSK_QNX6_PROBE_INFO *sb,
                            const TSK_QNX6_ROOT *bitmap_tree,
                            uint64_t data_block_index,
                            TSK_QNX6_READ_BLOCK read_block, void *context,
                            int *bit_value);
/* Determine free-bit polarity only when exactly one bit value matches
 * the superblock free-block count across all filesystem data blocks. */
int tsk_qnx6_bitmap_free_bit(const TSK_QNX6_PROBE_INFO *sb,
                              const TSK_QNX6_ROOT *bitmap_tree,
                              TSK_QNX6_READ_BLOCK read_block, void *context,
                              int *free_bit);
#ifdef __cplusplus
}
#endif
#endif
