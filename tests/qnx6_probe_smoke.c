#include "../tsk/fs/qnx6_probe.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>
static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
int main(void) {
    uint8_t sb[72] = {0};
    TSK_QNX6_PROBE_INFO out;
    assert(!tsk_qnx6_probe_superblock(sb, sizeof(sb), &out));
    put32(sb, 0x68191122U);
    put32(sb+48, 4096); put32(sb+52, 100);
    put32(sb+60, 200); put32(sb+64, 50);
    assert(tsk_qnx6_probe_superblock(sb, sizeof(sb), &out));
    assert(out.block_size == 4096 && out.block_count == 200);
    assert(!tsk_qnx6_probe_superblock(sb, 71, &out));
    put32(sb+64, 201);
    assert(!tsk_qnx6_probe_superblock(sb, sizeof(sb), &out));
    return 0;
}
