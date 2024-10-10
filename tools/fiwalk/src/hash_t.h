/*
 * C++ covers for md5, sha1, and sha256 (and sha512 if present)
 *
 * hash representation classes: md5_t, sha1_t, sha256_t (sha512_t)
 * has generators: md5_generator(), sha1_generator(), sha256_generator()
 *
 * md = sha1_t()
 * string md.hexdigest();
 * md.SIZE                   --- the size of the hash
 * uint8_t md.digest[SIZE]   --- the buffer
 * uint8_t md.final()        --- synonym for md.digest
 */


#ifndef  HASH_T_H
#define  HASH_T_H

/**
 * For reasons that defy explaination (at the moment), this is required.
 */

#include "tsk/tsk_config.h"

#ifdef HAVE_LIBCRYPTO
#include <openssl/evp.h>
#else
#include "sha2.h"
#endif

#ifdef __APPLE__
#include <AvailabilityMacros.h>
#undef DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#define  DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#endif

#include <assert.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#ifdef HAVE_SYS_MMAP_H
#include <sys/mmap.h>
#endif

/* wish that the hash fields below could be const, but C++ doesn't
 * allow initialization of a const array.
 * See: http://stackoverflow.com/questions/161790/initialize-a-const-array-in-a-class-initializer-in-c
 */
class md5_ {
public:
  static const size_t SIZE = 16;
  uint8_t digest[SIZE];
};

class sha1_ {
public:
  static const size_t SIZE = 20;
  uint8_t digest[SIZE];
};

class sha256_ {
public:
  static const size_t SIZE = 32;
  uint8_t digest[SIZE];
};

class sha512_ {
public:
  static const size_t SIZE = 64;
  uint8_t digest[SIZE];
};

class md5_hasher {
public:
  using hash_t = md5_;

  md5_hasher(): ctx(new TSK_MD5_CTX) {
    std::memset(ctx.get(), 0, sizeof(TSK_MD5_CTX));
  }

  int init() {
    TSK_MD5_Init(ctx.get());
    return 0;
  }

  int update(const unsigned char* buf, size_t len) {
    TSK_MD5_Update(ctx.get(), buf, len);
    return 0;
  }

  int finalize(unsigned char* digest) {
    TSK_MD5_Final(digest, ctx.get());
    return 0;
  }

private:
  std::unique_ptr<TSK_MD5_CTX> ctx;
};

class sha1_hasher {
public:
  using hash_t = sha1_;

  sha1_hasher(): ctx(new TSK_SHA_CTX) {
    std::memset(ctx.get(), 0, sizeof(TSK_SHA_CTX));
  }

  int init() {
    TSK_SHA_Init(ctx.get());
    return 0;
  }

  int update(const unsigned char* buf, size_t len) {
    TSK_SHA_Update(ctx.get(), buf, len);
    return 0;
  }

  int finalize(unsigned char* digest) {
    TSK_SHA_Final(digest, ctx.get());
    return 0;
  }

private:
  std::unique_ptr<TSK_SHA_CTX> ctx;
};

class sha256_hasher {
public:
  using hash_t = sha256_;

#ifdef HAVE_LIBCRYPTO
  sha256_hasher(): ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free) {}

  int init() {
    return EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr);
  }

  int update(const unsigned char* buf, size_t len) {
    return EVP_DigestUpdate(ctx.get(), buf, len);
  }

  int finalize(unsigned char* digest) {
    return EVP_DigestFinal_ex(ctx.get(), digest, nullptr);
  }

private:
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx;

#else
  sha256_hasher(): ctx(new SHA256_CTX) {}

  int init() {
    SHA256_Init(ctx.get());
    return 0;
  }

  int update(const unsigned char* buf, size_t len) {
    SHA256_Update(ctx.get(), buf, len);
    return 0;
  }

  int finalize(unsigned char* digest) {
    SHA256_Final(ctx.get(), digest);
    return 0;
  }

private:
  std::unique_ptr<SHA256_CTX> ctx;
#endif
};

class sha512_hasher {
public:
  using hash_t = sha512_;

#ifdef HAVE_LIBCRYPTO
  sha512_hasher(): ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free) {}

  int init() {
    return EVP_DigestInit_ex(ctx.get(), EVP_sha512(), nullptr);
  }

  int update(const unsigned char* buf, size_t len) {
    return EVP_DigestUpdate(ctx.get(), buf, len);
  }

  int finalize(unsigned char* digest) {
    return EVP_DigestFinal_ex(ctx.get(), digest, nullptr);
  }

private:
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx;

#else
  sha512_hasher(): ctx(new SHA512_CTX) {}

  int init() {
    SHA512_Init(ctx.get());
    return 0;
  }

  int update(const unsigned char* buf, size_t len) {
    SHA512_Update(ctx.get(), buf, len);
    return 0;
  }

  int finalize(unsigned char* digest) {
    SHA512_Final(ctx.get(), digest);
    return 0;
  }

private:
  std::unique_ptr<SHA512_CTX> ctx;
#endif
};

template<typename T>
class hash__: public T
{
  static uint8_t hexcharval(char v) {
    switch(v) {
    case '0': return 0;
    case '1': return 1;
    case '2': return 2;
    case '3': return 3;
    case '4': return 4;
    case '5': return 5;
    case '6': return 6;
    case '7': return 7;
    case '8': return 8;
    case '9': return 9;
    case 'a': case 'A': return 0x0a;
    case 'b': case 'B': return 0x0b;
    case 'c': case 'C': return 0x0c;
    case 'd': case 'D': return 0x0d;
    case 'e': case 'E': return 0x0e;
    case 'f': case 'F': return 0x0f;
    };
    return 0;
  }

public:
  hash__() {}

  hash__(const uint8_t *provided) {
    std::memcpy(this->digest, provided, this->SIZE);
  }

  const uint8_t *final() const {
    return this->digest;
  }

  /* python like interface for hexdigest */
  const char *hexdigest(char *hexbuf,size_t bufsize) const {
    const char *hexbuf_start = hexbuf;
    for (unsigned int i = 0; i < this->SIZE && bufsize >= 3; i++) {
      snprintf(hexbuf, bufsize, "%02x", this->digest[i]);
      hexbuf += 2;
      bufsize -= 2;
    }
    return hexbuf_start;
  }

  std::string hexdigest() const {
    std::string ret;
    char buf[this->SIZE*2 + 1];
    return std::string(hexdigest(buf, sizeof(buf)));
  }

  /**
   * Convert a hex representation to binary, and return
   * the number of bits converted.
   * @param binbuf output buffer
   * @param binbuf_size size of output buffer in bytes.
   * @param hex    input buffer (in hex)
   * @return the number of converted bits.
   */
  static int hex2bin(uint8_t *binbuf, size_t binbuf_size, const char *hex) {
    int bits = 0;
    while (hex[0] && hex[1] && binbuf_size > 0) {
      *binbuf++ = (hexcharval(hex[0]) << 4) | hexcharval(hex[1]);
      hex += 2;
      bits += 8;
      binbuf_size -= 1;
    }
    return bits;
  }

  static const hash__ *new_from_hex(const char *hex) {
    hash__ *val = new hash__();
    if (hex2bin(val->digest, sizeof(val->digest), hex) != val->SIZE*8) {
      std::cerr << "invalid input " << hex << "(" << val->SIZE*8 << ")\n";
      exit(1);
    }
    return val;
  }

  bool operator<(const hash__ &s2) const {
    /* Check the first byte manually as a performance hack */
    if (this->digest[0] < s2.digest[0]) return true;
    if (this->digest[0] > s2.digest[0]) return false;
    return std::memcmp(this->digest, s2.digest, this->SIZE) < 0;
  }

  bool operator==(const hash__ &s2) const {
    if (this->digest[0] != s2.digest[0]) return false;
    return std::memcmp(this->digest, s2.digest, this->SIZE) == 0;
  }
};

typedef hash__<md5_> md5_t;
typedef hash__<sha1_> sha1_t;
typedef hash__<sha256_> sha256_t;
typedef hash__<sha512_> sha512_t;

template<typename T>
class hash_generator__: T {       /* generates the hash */
private:
  bool initialized;         /* has the context been initialized? */
  bool finalized;

public:
  int64_t hashed_bytes;

  hash_generator__(): initialized(false), finalized(false), hashed_bytes(0) {}

  void init() {
    if (initialized == false) {
      T::init();
      initialized = true;
      finalized = false;
      hashed_bytes = 0;
    }
  }

  void update(const uint8_t *buf, size_t bufsize) {
    if (!initialized) init();
    if (finalized) {
      std::cerr << "hashgen_t::update called after finalized\n";
      exit(1);
    }
    T::update(buf, bufsize);
    hashed_bytes += bufsize;
  }

  hash__<typename T::hash_t> finalize() {
    if (finalized) {
      std::cerr << "currently friendly_geneator does not cache the final value\n";
      assert(0);
      /* code below will never be executed after assert(0) */
    }
    if (!initialized) {
      init();      /* do it now! */
    }

    hash__<typename T::hash_t> val;
    T::finalize(val.digest);
    finalized = true;
    return val;
  }

  /** Compute a sha1 from a buffer and return the hash */
  static hash__<T>  hash_buf(const uint8_t *buf, size_t bufsize) {
    /* First time through find the SHA1 of 512 NULLs */
    hash_generator__ g;
    g.update(buf, bufsize);
    return g.finalize();
  }

#ifdef HAVE_MMAP
  /** Static method allocator */
  static hash__<T> hash_file(const char *fname) {
    int fd = open(fname, O_RDONLY
#ifdef O_BINARY
      |O_BINARY
#endif
    );
    if (fd < 0) throw fname;
    struct stat st;
    if (fstat(fd, &st) < 0) {
      close(fd);
      throw fname;
    }

    const uint8_t *buf = (const uint8_t *)mmap(0, st.st_size, PROT_READ, MAP_FILE|MAP_SHARED, fd, 0);
    if (buf == 0) {
      close(fd);
      throw fname;
    }
    hash__<T> s = hash_buf(buf, st.st_size);
    munmap((void *)buf, st.st_size);
    close(fd);
    return s;
  }
#endif
};

typedef hash_generator__<md5_hasher> md5_generator;
typedef hash_generator__<sha1_hasher> sha1_generator;
typedef hash_generator__<sha256_hasher> sha256_generator;
typedef hash_generator__<sha512_hasher> sha512_generator;

#endif
