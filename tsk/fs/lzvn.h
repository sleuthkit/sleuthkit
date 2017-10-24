#ifndef LZVN_H
#define LZVN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t lzvn_decode_buffer(void* dst,
                          size_t dst_size,
                          const void* src,
                          size_t src_size);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LZVN_H */
