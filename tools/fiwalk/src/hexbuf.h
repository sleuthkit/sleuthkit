#ifndef HEXBUF_H
#define HEXBUF_H

#define HEXBUF_UPPERCASE 0x01
#define HEXBUF_SPACE2    0x02
#define HEXBUF_SPACE4    0x04

#ifdef __cplusplus
extern "C" {
#endif

    const char *hexbuf(char *dst,int dst_len,const unsigned char *bin,int bytes,int flag);

#ifdef __cplusplus
}
#endif


#endif
