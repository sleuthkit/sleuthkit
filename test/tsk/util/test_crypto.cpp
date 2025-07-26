#include "tsk/util/crypto.hpp"

#ifdef HAVE_LIBCRYPTO

#include <cstring>

#include "catch.hpp"
#include <iostream>
#include <fstream>

/* AES key */
static const unsigned char wrap_key[] = {
  0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92,
  0x1c, 0x04, 0x65, 0x66, 0x5f, 0x8a, 0xe6, 0xd1,
  0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
  0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};

/* Unique initialisation vector */
static const unsigned char wrap_iv[] = {
  0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0,
  0xee, 0xd0, 0x66, 0x84, 0x99, 0xaa, 0x3e, 0x68
};

/* Plaintext */
static const unsigned char wrap_pt[] = {
  0xad, 0x4f, 0xc9, 0xfc, 0x77, 0x69, 0xc9, 0xea,
  0xfc, 0xdf, 0x00, 0xac, 0x34, 0xec, 0x40, 0xbc,
  0x28, 0x3f, 0xa4, 0x5e, 0xd8, 0x99, 0xe4, 0x5d,
  0x5e, 0x7a, 0xc4, 0xe6, 0xca, 0x7b, 0xa5, 0xb7
};

/* Ciphertext */
static const unsigned char wrap_ct[] = {
  0x97, 0x99, 0x55, 0xca, 0xf6, 0x3e, 0x95, 0x54,
  0x39, 0xd6, 0xaf, 0x63, 0xff, 0x2c, 0xe3, 0x96,
  0xf7, 0x0d, 0x2c, 0x9c, 0xc7, 0x43, 0xc0, 0xb6,
  0x31, 0x43, 0xb9, 0x20, 0xac, 0x6b, 0xd3, 0x67,
  0xad, 0x01, 0xaf, 0xa7, 0x32, 0x74, 0x26, 0x92
};

TEST_CASE("rf3394_key_unwrap") {
  const auto out = rfc3394_key_unwrap(
    wrap_key, sizeof(wrap_key),
    wrap_ct, sizeof(wrap_ct),
    wrap_iv
  );
  REQUIRE(out);
  REQUIRE(!std::memcmp(out.get(), wrap_pt, sizeof(wrap_pt)));
}

TEST_CASE("aes_xts_decryptor decrypts a single encrypted block") {
  // AES-256 requires two 256-bit keys (64 bytes total)
  uint8_t key[64] = {};
  for (int i = 0; i < 64; ++i) key[i] = i;

  // Split into key1 and key2
  const uint8_t *key1 = key;
  const uint8_t *key2 = key + 32;

  uint8_t plaintext[16] = {
    0xde, 0xad, 0xbe, 0xef, 0xba, 0xad, 0xf0, 0x0d,
    0xca, 0xfe, 0xba, 0xbe, 0x00, 0x11, 0x22, 0x33
  };
  uint8_t ciphertext[16] = {};

  // Encrypt the block using OpenSSL XTS
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  uint8_t tweak[16] = {};
  uint64_t block_num = 42;
  for (int i = 0; i < 8; ++i) tweak[i] = (block_num >> (i * 8)) & 0xff;

  EVP_EncryptInit_ex(ctx, EVP_aes_256_xts(), nullptr, key, tweak);
  EVP_CIPHER_CTX_set_padding(ctx, 0);
  int len;
  EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext));
  EVP_CIPHER_CTX_free(ctx);

  // Now decrypt using aes_xts_decryptor
  aes_xts_decryptor dec(aes_xts_decryptor::AES_256, key1, key2, 16);
  uint8_t decrypted[16];
  std::memcpy(decrypted, ciphertext, 16);
  int outlen = dec.decrypt_block(decrypted, 16, block_num);

  REQUIRE(outlen == 16);
  REQUIRE(std::memcmp(plaintext, decrypted, 16) == 0);

  SECTION("Decrypt block with decrypt_block") {
    aes_xts_decryptor dec(aes_xts_decryptor::AES_256, key1, key2, 16);

    uint8_t decrypted[16];
    std::memcpy(decrypted, ciphertext, sizeof(ciphertext));
    int outlen = dec.decrypt_block(decrypted, 16, block_num);

    REQUIRE(outlen == 16);
    REQUIRE(std::memcmp(decrypted, plaintext, 16) == 0);
  }

  SECTION("Decrypt buffer with decrypt_buffer") {
    aes_xts_decryptor dec(aes_xts_decryptor::AES_256, key1, key2, 16);

    uint8_t decrypted[16];
    std::memcpy(decrypted, ciphertext, sizeof(ciphertext));
    int outlen = dec.decrypt_buffer(decrypted, 16, block_num * 16); // position in bytes

    REQUIRE(outlen == 16);
    REQUIRE(std::memcmp(decrypted, plaintext, 16) == 0);
  }

}

TEST_CASE("MD5 hash_buffer produces expected result") {
  const char *input = "hello";
  auto hash = hash_buffer_md5(input, strlen(input));

  // MD5("hello") = 5d41402abc4b2a76b9719d911017c592
  const uint8_t expected_md5[16] = {
      0x5d, 0x41, 0x40, 0x2a,
      0xbc, 0x4b, 0x2a, 0x76,
      0xb9, 0x71, 0x9d, 0x91,
      0x10, 0x17, 0xc5, 0x92
  };

  REQUIRE(std::memcmp(hash.get(), expected_md5, 16) == 0);
}

TEST_CASE("SHA-256 hash_buffer produces expected result") {
  const char *input = "hello";
  auto hash = hash_buffer_sha256(input, strlen(input));

  // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
  const uint8_t expected_sha256[32] = {
      0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e,
      0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e,
      0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e,
      0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24
  };

  REQUIRE(std::memcmp(hash.get(), expected_sha256, 32) == 0);
}

TEST_CASE("PBKDF2-HMAC-SHA256 test vector 1") {
  std::string password = "password";
  const char* salt = "salt";
  int iterations = 1;
  size_t key_len = 32;

  auto derived = pbkdf2_hmac_sha256(password, salt, strlen(salt), iterations, key_len);
  REQUIRE(derived != nullptr);

  const uint8_t expected[] = {
      0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c,
      0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
      0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48,
      0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b
  };

  REQUIRE(std::memcmp(derived.get(), expected, key_len) == 0);
}

#endif