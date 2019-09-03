#include "crypto.hpp"

#ifdef HAVE_LIBOPENSSL
#include <openssl/aes.h>
#include <openssl/md5.h>
#include <openssl/opensslv.h>
#include <openssl/sha.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

// This should initialize and cleanup openssl
static struct _openssl_init {
  _openssl_init() noexcept {
    OpenSSL_add_all_algorithms();

// OpenSSL 1.1.0 removed the need for threading callbacks
#if OPENSSL_VERSION_NUMBER < 0x10100000 && defined(TSK_MULTITHREAD_LIB)
    CRYPTO_set_locking_callback([](int mode, int n, const char *, int) {
      static auto mutexes = std::make_unique<std::mutex[]>(CRYPTO_num_locks());

      auto &mutex = mutexes[n];

      if (mode & CRYPTO_LOCK) {
        mutex.lock();
      } else {
        mutex.unlock();
      }
    });

    CRYPTO_THREADID_set_callback([](CRYPTO_THREADID *id) {
      thread_local const auto thread_id =
          std::hash<std::thread::id>()(std::this_thread::get_id());
      CRYPTO_THREADID_set_numeric(id, thread_id);
    });
#endif
  }

  ~_openssl_init() noexcept { EVP_cleanup(); }
} openssl_init{};

aes_xts_decryptor::aes_xts_decryptor(AES_MODE mode, const uint8_t *key1,
                                     const uint8_t *key2,
                                     size_t block_size) noexcept
    : _block_size{block_size} {
  // EVP_CIPHER_CTX was made opaque in OpenSSL 1.1.0.
#if OPENSSL_VERSION_NUMBER < 0x10100000
  _ctx = new EVP_CIPHER_CTX();
#else
  _ctx = EVP_CIPHER_CTX_new();
#endif

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
#ifdef TSK_MULTITHREAD_LIB
  // Take decryption lock
  std::lock_guard<std::mutex> lock{_ctx_lock};
#endif

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

std::unique_ptr<uint8_t[]> rfc3394_key_unwrap(const uint8_t *key,
                                              size_t key_len, const void *input,
                                              size_t input_len,
                                              const void *iv) noexcept {
  AES_KEY aes_key;
  AES_set_decrypt_key(key, key_len * 8, &aes_key);

  const int output_len = input_len - 8;

  auto out = std::make_unique<uint8_t[]>(output_len);

  const auto ret = AES_unwrap_key(&aes_key, (const uint8_t *)iv, out.get(),
                                  (const uint8_t *)input, input_len);

  if (ret != output_len) {
    return nullptr;
  }

  return out;
}

std::unique_ptr<uint8_t[]> hash_buffer_md5(const void *input,
                                           size_t len) noexcept {
  MD5_CTX sha;
  MD5_Init(&sha);

  MD5_Update(&sha, input, len);

  auto hash = std::make_unique<uint8_t[]>(MD5_DIGEST_LENGTH);

  MD5_Final(hash.get(), &sha);

  return hash;
}

std::unique_ptr<uint8_t[]> hash_buffer_sha256(const void *input,
                                              size_t len) noexcept {
  SHA256_CTX sha;
  SHA256_Init(&sha);

  SHA256_Update(&sha, input, len);

  auto hash = std::make_unique<uint8_t[]>(SHA256_DIGEST_LENGTH);

  SHA256_Final(hash.get(), &sha);

  return hash;
}
#endif