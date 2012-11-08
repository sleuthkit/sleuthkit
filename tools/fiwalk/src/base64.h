/*
 * Base64 conversion.
 *
 * From RFC1521 and draft-ietf-dnssec-secext-03.txt.
 *
 * Implementation (C) 1996-1999 by Internet Software Consortium.
 */



#ifndef BASE64_H
#define BASE64_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif
#ifdef NEVER_DEFINED
}
#endif
/* Convert from printable base64 to binary.
 * Returns number of bytes converted
 */
int b64_pton_slg(const char *str,int srclen,unsigned char *target,size_t targsize);

/* Convert from binary to printable base 64.
 * returns size of printable thing.
 */
int b64_ntop(const unsigned char *str,size_t srclength,char *target,size_t targsize);

#ifdef NEVER_DEFINED
{
#endif
#ifdef __cplusplus
}
#endif

#endif
