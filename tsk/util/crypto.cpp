/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2018-2019 BlackBag Technologies.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/* This file contains routines used by APFS code.
 * It could probably move into the 'fs' folder.
 * It is XTS wrappers around OpenSSL
 */
#include "crypto.hpp"

#ifdef HAVE_LIBCRYPTO
#include <openssl/evp.h>
#include <openssl/opensslv.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <string>

aes_xts_decryptor::aes_xts_decryptor(AES_MODE mode, const uint8_t *key1,
                                     const uint8_t *key2,
                                     size_t block_size) noexcept
    : _block_size{block_size} {
  _ctx = EVP_CIPHER_CTX_new();

  EVP_CIPHER_CTX_init(_ctx);

  if (key2 != nullptr) {
    // We have a 2 part key that must be assembled
    if (mode == AES_128) {
      uint8_t key[32];
      memcpy(key, key1, 16);
      memcpy(key + 16, key2, 16);

      EVP_DecryptInit_ex(_ctx, EVP_aes_128_xts(), nullptr, key, nullptr);
    } else {
      uint8_t key[64];
      memcpy(key, key1, 32);
      memcpy(key + 32, key2, 32);

      EVP_DecryptInit_ex(_ctx, EVP_aes_256_xts(), nullptr, key, nullptr);
    }
  } else {
    // We have a single key that's already assembled
    if (mode == AES_128) {
      EVP_DecryptInit_ex(_ctx, EVP_aes_128_xts(), nullptr, key1, nullptr);
    } else {
      EVP_DecryptInit_ex(_ctx, EVP_aes_256_xts(), nullptr, key1, nullptr);
    }
  }

  EVP_CIPHER_CTX_set_padding(_ctx, 0);
}

aes_xts_decryptor::~aes_xts_decryptor() noexcept {
  // EVP_CIPHER_CTX was made opaque in OpenSSL 1.1.0.
#if OPENSSL_VERSION_NUMBER < 0x10100000
  EVP_CIPHER_CTX_cleanup(_ctx);
  delete _ctx;
#else
  EVP_CIPHER_CTX_free(_ctx);
#endif
}

int aes_xts_decryptor::decrypt_buffer(void *buffer, size_t length,
                                      uint64_t position) noexcept {
  int total_len{0};
  auto buf = static_cast<char *>(buffer);

  while (length > 0) {
    const auto read = decrypt_block(buf, std::min(length, _block_size),
                                    position / _block_size);
    total_len += read;
    position += read;
    buf += read;
    length -= read;
  }

  return total_len;
}

int aes_xts_decryptor::decrypt_block(void *buffer, size_t length,
                                     uint64_t block) noexcept {
  uint8_t tweak[16]{};
  for (int i = 0; i < 8; i++) {
    tweak[i] = (block >> (i * 8)) & 0xFF;
  }

  int outlen;
  EVP_DecryptInit_ex(_ctx, nullptr, nullptr, nullptr, tweak);
  EVP_DecryptUpdate(_ctx, static_cast<uint8_t *>(buffer), &outlen,
                    static_cast<uint8_t *>(buffer), length);

  return outlen;
}

std::unique_ptr<uint8_t[]> pbkdf2_hmac_sha256(const std::string &password,
                                              const void *salt, size_t salt_len,
                                              int iterations,
                                              size_t key_len) noexcept {
  auto out = std::make_unique<uint8_t[]>(key_len);

  const auto ret = PKCS5_PBKDF2_HMAC(
      password.c_str(), password.length(), (const uint8_t *)salt, salt_len,
      iterations, EVP_sha256(), key_len, out.get());

  if (ret == 0) {
    return nullptr;
  }

  return out;
}

std::unique_ptr<uint8_t[]> rfc3394_key_unwrap(
  const uint8_t *key,
  [[maybe_unused]] size_t key_len,
  const void *input,
  size_t input_len,
  const void *iv) noexcept
{
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
    EVP_CIPHER_CTX_new(),
    EVP_CIPHER_CTX_free
  );

  if (!ctx) {
    return nullptr;
  }

#if OPENSSL_VERSION_NUMBER < 0x30000000
  // not needed for OpenSSL >= 3
  EVP_CIPHER_CTX_set_flags(ctx.get(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
#endif

  if (!EVP_DecryptInit_ex(
    ctx.get(),
    EVP_aes_256_wrap(),
    nullptr,
    key,
    static_cast<const uint8_t*>(iv))
  ) {
    return nullptr;
  }

  const int output_len_exp = input_len - 8;
  auto out = std::make_unique<uint8_t[]>(output_len_exp);

  int len;
  int output_len_act;

  if (!EVP_DecryptUpdate(
    ctx.get(),
    out.get(),
    &len,
    static_cast<const uint8_t*>(input),
    input_len)
  ) {
    return nullptr;
  }

  output_len_act = len;

  if (!EVP_DecryptFinal_ex(ctx.get(), out.get() + len, &len)) {
    return nullptr;
  }

  output_len_act += len;

  if (output_len_act != output_len_exp) {
    return nullptr;
  }

  return out;
}

std::unique_ptr<uint8_t[]> hash_buffer(
  const EVP_MD* hfunc,
  const void *input,
  size_t len) noexcept
{
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(
    EVP_MD_CTX_new(),
    EVP_MD_CTX_free
  );

  EVP_DigestInit_ex(ctx.get(), hfunc, nullptr);
  EVP_DigestUpdate(ctx.get(), input, len);

  auto hash = std::make_unique<uint8_t[]>(EVP_MD_CTX_size(ctx.get()));
  EVP_DigestFinal_ex(ctx.get(), hash.get(), nullptr);

  return hash;
}

std::unique_ptr<uint8_t[]> hash_buffer_md5(const void *input,
                                           size_t len) noexcept {
  return hash_buffer(EVP_md5(), input, len);
}

std::unique_ptr<uint8_t[]> hash_buffer_sha256(const void *input,
                                              size_t len) noexcept {
  return hash_buffer(EVP_sha256(), input, len);
}
#endif
