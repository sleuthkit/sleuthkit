/*
 * hmac_sha1.c
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

/*
 * The HMAC-SHA1 has is defined as:
 *
 *     HMAC = SHA1(K XOR opad, SHA1(K XOR ipad, message))
 *
 * "opad" is 64 bytes filled with 0x5c
 * "ipad" is 64 bytes filled with 0x36
 * "K" is the key material
 *
 * If the key material "K" is longer than 64 bytes, then the key material
 * will first be digested (K = SHA1(K)) resulting in a 20-byte hash.
 * If the key material is shorter than 64 bytes, it is padded with zero
 * bytes.
 *
 * This code precomputes "K XOR ipad" and "K XOR opad" since that just makes
 * sense.
 *
 * This code was heavily influenced by Eric A. Young's in how the interface
 * was designed and how this file is formatted.
 */

#ifndef __HMAC_SHA1_H__
#define __HMAC_SHA1_H__

#include "hmac_sha1.h"
#include <string.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* Filler bytes: */
#define IPAD_BYTE	0x36
#define OPAD_BYTE	0x5c
#define ZERO_BYTE	0x00

void HMAC_SHA1_Init(HMAC_SHA1_CTX *ctx) {
	memset(&(ctx->key[0]), ZERO_BYTE, HMAC_SHA1_BLOCK_LENGTH);
	memset(&(ctx->ipad[0]), IPAD_BYTE, HMAC_SHA1_BLOCK_LENGTH);
	memset(&(ctx->opad[0]), OPAD_BYTE, HMAC_SHA1_BLOCK_LENGTH);
	ctx->keylen = 0;
	ctx->hashkey = 0;
}

void HMAC_SHA1_UpdateKey(HMAC_SHA1_CTX *ctx, unsigned char *key, unsigned int keylen) {

	/* Do we have anything to work with?  If not, return right away. */
	if (keylen < 1)
		return;

	/*
	 * Is the total key length (current data and any previous data)
	 * longer than the hash block length?
	 */
	if (ctx->hashkey !=0 || (keylen + ctx->keylen) > HMAC_SHA1_BLOCK_LENGTH) {
		/*
		 * Looks like the key data exceeds the hash block length,
		 * so that means we use a hash of the key as the key data
		 * instead.
		 */
		if (ctx->hashkey == 0) {
			/*
			 * Ah, we haven't started hashing the key
			 * data yet, so we must init. the hash
			 * monster to begin feeding it.
			 */

			/* Set the hash key flag to true (non-zero) */
			ctx->hashkey = 1;

			/* Init. the hash beastie... */
			TSK_SHA_Init(&ctx->shactx);

			/* If there's any previous key data, use it */
			if (ctx->keylen > 0) {
				TSK_SHA_Update(&ctx->shactx, &(ctx->key[0]), ctx->keylen);
			}

			/*
			 * Reset the key length to the future true
			 * key length, HMAC_SHA1_DIGEST_LENGTH
			 */
			ctx->keylen = HMAC_SHA1_DIGEST_LENGTH;
		}
		/* Now feed the latest key data to the has monster */
		TSK_SHA_Update(&ctx->shactx, key, keylen);
	} else {
		/*
		 * Key data length hasn't yet exceeded the hash
		 * block length (HMAC_SHA1_BLOCK_LENGTH), so theres
		 * no need to hash the key data (yet).  Copy it
		 * into the key buffer.
		 */
		memcpy(&(ctx->key[ctx->keylen]), key, keylen);
		ctx->keylen += keylen;
	}
}

void HMAC_SHA1_EndKey(HMAC_SHA1_CTX *ctx) {
	unsigned char	*ipad, *opad, *key;
	int		i;

	/* Did we end up hashing the key? */
	if (ctx->hashkey) {
		memset(&(ctx->key[0]), ZERO_BYTE, HMAC_SHA1_BLOCK_LENGTH);
		/* Yes, so finish up and copy the key data */
		TSK_SHA_Final(&(ctx->key[0]), &ctx->shactx);
		/* ctx->keylen was already set correctly */
	}
	/* Pad the key if necessary with zero bytes */
	if ((i = HMAC_SHA1_BLOCK_LENGTH - ctx->keylen) > 0) {
		memset(&(ctx->key[ctx->keylen]), ZERO_BYTE, i);
	}

	ipad = &(ctx->ipad[0]);
	opad = &(ctx->opad[0]);

	/* Precompute the respective pads XORed with the key */
	key = &(ctx->key[0]);
	for (i = 0; i < ctx->keylen; i++, key++) {
		/* XOR the key byte with the appropriate pad filler byte */
		*ipad++ ^= *key;
		*opad++ ^= *key;
	}
}

void HMAC_SHA1_StartMessage(HMAC_SHA1_CTX *ctx) {
	TSK_SHA_Init(&ctx->shactx);
	TSK_SHA_Update(&ctx->shactx, &(ctx->ipad[0]), HMAC_SHA1_BLOCK_LENGTH);
}

void HMAC_SHA1_UpdateMessage(HMAC_SHA1_CTX *ctx, unsigned char *data, unsigned int datalen) {
	TSK_SHA_Update(&ctx->shactx, data, datalen);
}

void HMAC_SHA1_EndMessage(unsigned char *out, HMAC_SHA1_CTX *ctx) {
	unsigned char	buf[HMAC_SHA1_DIGEST_LENGTH];
	TSK_SHA_CTX		*c = &ctx->shactx;

	TSK_SHA_Final(&(buf[0]), c);
	TSK_SHA_Init(c);
	TSK_SHA_Update(c, &(ctx->opad[0]), HMAC_SHA1_BLOCK_LENGTH);
	TSK_SHA_Update(c, buf, HMAC_SHA1_DIGEST_LENGTH);
	TSK_SHA_Final(out, c);
}

void HMAC_SHA1_Done(HMAC_SHA1_CTX *ctx) {
	/* Just to be safe, toast all context data */
	memset(&(ctx->ipad[0]), ZERO_BYTE, HMAC_SHA1_BLOCK_LENGTH);
	memset(&(ctx->ipad[0]), ZERO_BYTE, HMAC_SHA1_BLOCK_LENGTH);
	memset(&(ctx->key[0]), ZERO_BYTE, HMAC_SHA1_BLOCK_LENGTH);
	ctx->keylen = 0;
	ctx->hashkey = 0;
} 

#ifdef  __cplusplus
}
#endif

#endif
