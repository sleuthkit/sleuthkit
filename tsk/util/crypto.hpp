#pragma once

/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2018-2019 BlackBag Technologies.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * This is currently being used only by APFS
 */

#if HAVE_CONFIG_H
#include "../tsk_config.h"
#endif

#ifdef HAVE_LIBCRYPTO
#include <openssl/evp.h>


#include <memory>
#include <mutex>

class aes_xts_decryptor {
  EVP_CIPHER_CTX *_ctx{};
  size_t _block_size{};

#ifdef TSK_MULTITHREAD_LIB
  std::mutex _ctx_lock{};
#endif

 public:
  enum AES_MODE { AES_128, AES_256 };

  aes_xts_decryptor(AES_MODE mode, const uint8_t *key1, const uint8_t *key2,
                    size_t block_size) noexcept;

  // Not copyable
  aes_xts_decryptor(const aes_xts_decryptor &) noexcept = delete;
  aes_xts_decryptor &operator=(const aes_xts_decryptor) noexcept = delete;

  ~aes_xts_decryptor() noexcept;

  int decrypt_buffer(void *buffer, size_t length, uint64_t position) noexcept;
  int decrypt_block(void *buffer, size_t length, uint64_t block) noexcept;
};

std::unique_ptr<uint8_t[]> pbkdf2_hmac_sha256(const std::string &password,
                                              const void *salt, size_t salt_len,
                                              int iterations,
                                              size_t key_len) noexcept;

std::unique_ptr<uint8_t[]> rfc3394_key_unwrap(
    const uint8_t *key, size_t key_len, const void *input, size_t input_len,
    const void *iv = nullptr) noexcept;

std::unique_ptr<uint8_t[]> hash_buffer_md5(const void *input,
                                           size_t len) noexcept;

std::unique_ptr<uint8_t[]> hash_buffer_sha256(const void *input,
                                              size_t len) noexcept;

#endif
