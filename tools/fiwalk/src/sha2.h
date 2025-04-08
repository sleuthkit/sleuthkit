/*
 * FIPS 180-2 SHA-224/256/384/512 implementation
 * Last update: 02/02/2007
 * Issue date:  04/30/2005
 *
 * Copyright (C) 2005, 2007 Olivier Gay <olivier.gay@a3.epfl.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef SHA2_H
#define SHA2_H

#include "tsk/tsk_config.h"

#ifndef HAVE_LIBCRYPTO

#define SHA224_DIGEST_LENGTH ( 224 / 8)
#define SHA256_DIGEST_LENGTH ( 256 / 8)
#define SHA384_DIGEST_LENGTH ( 384 / 8)
#define SHA512_DIGEST_LENGTH ( 512 / 8)

#define SHA256_BLOCK_SIZE  ( 512 / 8)
#define SHA512_BLOCK_SIZE  (1024 / 8)
#define SHA384_BLOCK_SIZE  SHA512_BLOCK_SIZE
#define SHA224_BLOCK_SIZE  SHA256_BLOCK_SIZE

#ifndef SHA2_TYPES
#define SHA2_TYPES
typedef unsigned char uint8;
typedef unsigned int  uint32;
typedef unsigned long long uint64;
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    unsigned int tot_len;
    unsigned int len;
    unsigned char block[2 * SHA256_BLOCK_SIZE];
    uint32 h[8];
} SHA256_CTX;

typedef struct {
    unsigned int tot_len;
    unsigned int len;
    unsigned char block[2 * SHA512_BLOCK_SIZE];
    uint64 h[8];
} SHA512_CTX;

typedef SHA512_CTX SHA384_CTX;
typedef SHA256_CTX SHA224_CTX;

void SHA224_Init(SHA224_CTX *ctx);
void SHA224_Update(SHA224_CTX *ctx, const unsigned char *message,
                   unsigned int len);
void SHA224_Final(SHA224_CTX *ctx, unsigned char *digest);
void SHA224(const unsigned char *message, unsigned int len,
            unsigned char *digest);

void SHA256_Init(SHA256_CTX * ctx);
void SHA256_Update(SHA256_CTX *ctx, const unsigned char *message,
                   unsigned int len);
void SHA256_Final(SHA256_CTX *ctx, unsigned char *digest);
void SHA256(const unsigned char *message, unsigned int len,
            unsigned char *digest);

void SHA384_Init(SHA384_CTX *ctx);
void SHA384_Update(SHA384_CTX *ctx, const unsigned char *message,
                   unsigned int len);
void SHA384_Final(SHA384_CTX *ctx, unsigned char *digest);
void SHA384(const unsigned char *message, unsigned int len,
            unsigned char *digest);

void SHA512_Init(SHA512_CTX *ctx);
void SHA512_Update(SHA512_CTX *ctx, const unsigned char *message,
                   unsigned int len);
void SHA512_Final(SHA512_CTX *ctx, unsigned char *digest);
void SHA512(const unsigned char *message, unsigned int len,
            unsigned char *digest);

#ifdef __cplusplus
}
#endif

#endif

#endif /* !SHA2_H */
