/*
 * hmac_sha1.h
 *
 * Version 1.0.0
 *
 * Written by Aaron D. Gifford <me@aarongifford.com>
 *
 * Copyright 1998, 2000 Aaron D. Gifford.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR(S) OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef HEADER_HMAC_SHA1_H
#define HEADER_HMAC_SHA1_H

/*
 * Include SHA-1 stuff - CHOOSE WHICH SOURCE to use for the SHA1 functions
 *
 * Use the below include if your system has a library with SHA1 and be sure
 * to link to the library:
 */

/* #include <sha.h> */

/*
 * Or you can use Steve Reid's public domain SHA1 implementation:
 */

#include "tsk_base_i.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define HMAC_SHA1_DIGEST_LENGTH	20
#define HMAC_SHA1_BLOCK_LENGTH	64

/* The HMAC_SHA1 structure: */
typedef struct _HMAC_SHA1_CTX {
	unsigned char	ipad[HMAC_SHA1_BLOCK_LENGTH];
	unsigned char	opad[HMAC_SHA1_BLOCK_LENGTH];
	TSK_SHA_CTX		shactx;
	unsigned char	key[HMAC_SHA1_BLOCK_LENGTH];
	unsigned int	keylen;
	unsigned int	hashkey;
} HMAC_SHA1_CTX;

#ifndef NOPROTO
void HMAC_SHA1_Init(HMAC_SHA1_CTX *ctx);
void HMAC_SHA1_UpdateKey(HMAC_SHA1_CTX *ctx, unsigned char *key, unsigned int keylen);
void HMAC_SHA1_EndKey(HMAC_SHA1_CTX *ctx);
void HMAC_SHA1_StartMessage(HMAC_SHA1_CTX *ctx);
void HMAC_SHA1_UpdateMessage(HMAC_SHA1_CTX *ctx, unsigned char *data, unsigned int datalen);
void HMAC_SHA1_EndMessage(unsigned char *out, HMAC_SHA1_CTX *ctx);
void HMAC_SHA1_Done(HMAC_SHA1_CTX *ctx);
#else
void HMAC_SHA1_Init();
void HMAC_SHA1_UpdateKey();
void HMAC_SHA1_EndKey();
void HMAC_SHA1_StartMessage();
void HMAC_SHA1_UpdateMessage();
void HMAC_SHA1_EndMessage();
void HMAC_SHA1_Done();
#endif

#ifdef	__cplusplus
}
#endif

#endif
