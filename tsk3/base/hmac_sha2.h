/*
 * HMAC-SHA-224/256/384/512 implementation
 * Last update: 06/15/2005
 * Issue date:  06/15/2005
 *
 * Copyright (C) 2005 Olivier Gay <olivier.gay@a3.epfl.ch>
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

#ifndef HMAC_SHA2_H
#define HMAC_SHA2_H

#include "sha2.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    SHA224_CTX ctx_inside;
    SHA224_CTX ctx_outside;

    /* for hmac_Reinit */
    SHA224_CTX ctx_inside_reinit;
    SHA224_CTX ctx_outside_reinit;

    unsigned char block_ipad[SHA224_BLOCK_SIZE];
    unsigned char block_opad[SHA224_BLOCK_SIZE];
} HMAC_SHA224_CTX;

typedef struct {
    SHA256_CTX ctx_inside;
    SHA256_CTX ctx_outside;

    /* for hmac_reinit */
    SHA256_CTX ctx_inside_reinit;
    SHA256_CTX ctx_outside_reinit;

    unsigned char block_ipad[SHA256_BLOCK_SIZE];
    unsigned char block_opad[SHA256_BLOCK_SIZE];
} HMAC_SHA256_CTX;

typedef struct {
    SHA384_CTX ctx_inside;
    SHA384_CTX ctx_outside;

    /* for hmac_reinit */
    SHA384_CTX ctx_inside_reinit;
    SHA384_CTX ctx_outside_reinit;

    unsigned char block_ipad[SHA384_BLOCK_SIZE];
    unsigned char block_opad[SHA384_BLOCK_SIZE];
} HMAC_SHA384_CTX;

typedef struct {
    SHA512_CTX ctx_inside;
    SHA512_CTX ctx_outside;

    /* for hmac_reinit */
    SHA512_CTX ctx_inside_reinit;
    SHA512_CTX ctx_outside_reinit;

    unsigned char block_ipad[SHA512_BLOCK_SIZE];
    unsigned char block_opad[SHA512_BLOCK_SIZE];
} HMAC_SHA512_CTX;

void HMAC_SHA224_Init(HMAC_SHA224_CTX *ctx, const unsigned char *key,
                      unsigned int key_size);
void HMAC_SHA224_Reinit(HMAC_SHA224_CTX *ctx);
void HMAC_SHA224_Update(HMAC_SHA224_CTX *ctx, const unsigned char *message,
                        unsigned int message_len);
void HMAC_SHA224_Final(HMAC_SHA224_CTX *ctx, unsigned char *mac,
                       unsigned int mac_size);
void HMAC_SHA224(const unsigned char *key, unsigned int key_size,
                 const unsigned char *message, unsigned int message_len,
                 unsigned char *mac, unsigned mac_size);

void HMAC_SHA256_Init(HMAC_SHA256_CTX *ctx, const unsigned char *key,
                      unsigned int key_size);
void HMAC_SHA256_Reinit(HMAC_SHA256_CTX *ctx);
void HMAC_SHA256_Update(HMAC_SHA256_CTX *ctx, const unsigned char *message,
                        unsigned int message_len);
void HMAC_SHA256_Final(HMAC_SHA256_CTX *ctx, unsigned char *mac,
                       unsigned int mac_size);
void HMAC_SHA256(const unsigned char *key, unsigned int key_size,
                 const unsigned char *message, unsigned int message_len,
                 unsigned char *mac, unsigned mac_size);

void HMAC_SHA384_Init(HMAC_SHA384_CTX *ctx, const unsigned char *key,
                      unsigned int key_size);
void HMAC_SHA384_Reinit(HMAC_SHA384_CTX *ctx);
void HMAC_SHA384_Update(HMAC_SHA384_CTX *ctx, const unsigned char *message,
                        unsigned int message_len);
void HMAC_SHA384_Final(HMAC_SHA384_CTX *ctx, unsigned char *mac,
                       unsigned int mac_size);
void HMAC_SHA384(const unsigned char *key, unsigned int key_size,
                 const unsigned char *message, unsigned int message_len,
                 unsigned char *mac, unsigned mac_size);

void HMAC_SHA512_Init(HMAC_SHA512_CTX *ctx, const unsigned char *key,
                      unsigned int key_size);
void HMAC_SHA512_Reinit(HMAC_SHA512_CTX *ctx);
void HMAC_SHA512_Update(HMAC_SHA512_CTX *ctx, const unsigned char *message,
                        unsigned int message_len);
void HMAC_SHA512_Final(HMAC_SHA512_CTX *ctx, unsigned char *mac,
                       unsigned int mac_size);
void HMAC_SHA512(const unsigned char *key, unsigned int key_size,
                 const unsigned char *message, unsigned int message_len,
                 unsigned char *mac, unsigned mac_size);

#ifdef __cplusplus
}
#endif

#endif /* !HMAC_SHA2_H */

