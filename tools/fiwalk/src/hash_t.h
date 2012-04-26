/*
 * C++ covers for md5, sha1, and sha256 (and sha512 if present)
 *
 * hash representation classes: md5_t, sha1_t, sha256_t (sha512_t)
 * has generators: md5_generator(), sha1_generator(), sha256_generator()
 *
 * md = sha1_t()
 * string md.hexdigest();
 * md.SIZE		    --- the size of the hash 
 * uint8_t md.digest[SIZE]   --- the buffer
 * uint8_t md.final()        --- synonym for md.digest
 */


#ifndef  HASH_T_H
#define  HASH_T_H

/**
 * For reasons that defy explaination (at the moment), this is required.
 */

#include "tsk3/tsk_tools_i.h"

#ifdef __APPLE__
#include <AvailabilityMacros.h>
#undef DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER 
#define  DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <assert.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#if __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 1070
 #define COMMON_DIGEST_FOR_OPENSSL
 #include <CommonCrypto/CommonDigest.h>
 #include <CommonCrypto/CommonHMAC.h>
#else
 #include <openssl/hmac.h>
 #include <openssl/evp.h>
#endif

#include <iostream>

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
    static const size_t SIZE=16;
    uint8_t digest[SIZE];			
};

class sha1_ {
public:
    static const size_t SIZE=20;
    uint8_t digest[SIZE];
};

class sha256_ {
public:
    static const size_t SIZE=32;
    uint8_t digest[SIZE];
};

#if HAVE_EVP_SHA512 || COMMON_DIGEST_FOR_OPENSSL
class sha512_ {
public:
    static const size_t SIZE=64;
    uint8_t digest[SIZE];
};
#endif

static int hexcharvals__[256];
static int hexcharvals_init__ = 0;

template<typename T> 
class hash__:public T
{
public:
    hash__(){
    }
    hash__(const uint8_t *provided){
	memcpy(this->digest,provided,this->SIZE);
    }
    const uint8_t *final() const {
	return this->digest;
    }
    /* python like interface for hexdigest */
    const char *hexdigest(char *hexbuf,size_t bufsize) const {
	const char *hexbuf_start = hexbuf;
	for(unsigned int i=0;i<this->SIZE && bufsize>=3;i++){
	    snprintf(hexbuf,bufsize,"%02x",this->digest[i]);
	    hexbuf  += 2;
	    bufsize -= 2;
	}
	return hexbuf_start;
    }
    std::string hexdigest() const {
	std::string ret;
	char buf[this->SIZE*2+1];
	return std::string(hexdigest(buf,sizeof(buf)));
    }
    /**
     * Convert a hex representation to binary, and return
     * the number of bits converted.
     * @param binbuf output buffer
     * @param binbuf_size size of output buffer in bytes.
     * @param hex    input buffer (in hex)
     * @return the number of converted bits.
     */
    static int hex2bin(uint8_t *binbuf,size_t binbuf_size,const char *hex)
    {
	int bits = 0;
	if(hexcharvals_init__==0){
	    /* Need to initialize this */
	    int i;
	    for(i=0;i<10;i++){
		hexcharvals__['0'+i] = i;
	    }
	    for(i=10;i<16;i++){
		hexcharvals__['A'+i-10] = i;
		hexcharvals__['a'+i-10] = i;
	    }
	    hexcharvals_init__ = 1;
	}
	while(hex[0] && hex[1] && binbuf_size>0){
	    *binbuf++ = ((hexcharvals__[(uint8_t)hex[0]]<<4) |
			 hexcharvals__[(uint8_t)hex[1]]);
	    hex  += 2;
	    bits += 8;
	    binbuf_size -= 1;
	}
	return bits;
    }
    static const hash__ *new_from_hex(const char *hex) {
	hash__ *val = new hash__();
	if(hex2bin(val->digest,sizeof(val->digest),hex)!=val->SIZE*8){
	    std::cerr << "invalid input " << hex << "(" << val->SIZE*8 << ")\n";
	    exit(1);
	}
	return val;
    }
    bool operator<(const hash__ &s2) const {
	/* Check the first byte manually as a performance hack */
	if(this->digest[0] < s2.digest[0]) return true;
	if(this->digest[0] > s2.digest[0]) return false;
	return memcmp(this->digest,s2.digest, this->SIZE) < 0;
    }
    bool operator==(const hash__ &s2) const {
	if(this->digest[0] != s2.digest[0]) return false;
	return memcmp(this->digest,s2.digest, this->SIZE) == 0;
    }
};

typedef hash__<md5_> md5_t;
typedef hash__<sha1_> sha1_t;
typedef hash__<sha256_> sha256_t;
#if HAVE_EVP_SHA512 || COMMON_DIGEST_FOR_OPENSSL
typedef hash__<sha512_> sha512_t;
#endif

template<typename T> 
class hash_generator__:T { 			/* generates the hash */
    unsigned int ret;
#ifndef COMMON_DIGEST_FOR_OPENSSL
	const EVP_MD *md;
    EVP_MD_CTX mdctx;	     /* the context for computing the value */
#else
	void *mdctx;
	unsigned char *md;
//	int (*md_update) ();
//	md_update = MD5_Update;
//	md_update = &SHA_Update;
	int (*md_init)(void *);
	int (*md_update)(void *, const void *, CC_LONG);
	int (*md_final)(unsigned char *, void *);
//	 int (*md_final)();
#endif
    bool initialized;	       /* has the context been initialized? */
    bool finalized;
    /* Static function to determine if something is zero */
    static bool iszero(const uint8_t *buf,size_t bufsize){
	for(unsigned int i=0;i<bufsize;i++){
	    if(buf[i]!=0) return false;
	}
	return true;
    }
public:
    int64_t hashed_bytes;
    hash_generator__():initialized(false),finalized(false),hashed_bytes(0){
	switch(this->SIZE){
#ifdef COMMON_DIGEST_FOR_OPENSSL
	case 16:
		mdctx = malloc(sizeof(MD5_CTX));
		memset(mdctx,0,sizeof(MD5_CTX));
		md=(unsigned char *)malloc(MD5_DIGEST_LENGTH);
		memset(md,0,MD5_DIGEST_LENGTH);
//		int (*md_init)(MD5_CTX*) = &MD5_Init;
//		(int (*)(MD5_CTX*))md_init  = MD5_Init;
		md_init	 	= (int(*)(void *))&MD5_Init;
		md_update	= (int (*)(void *, const void *, CC_LONG))&MD5_Update;
		md_final	= (int (*)(unsigned char*, void *))&MD5_Final;
		break;
	case 20: 
		mdctx = malloc(sizeof(SHA_CTX));
		memset(mdctx,0,sizeof(SHA_CTX));
		md=(unsigned char *)malloc(SHA_DIGEST_LENGTH);
		memset(md,0,SHA_DIGEST_LENGTH);
		md_init		= (int(*)(void *))&SHA1_Init;
		md_update	= (int (*)(void *, const void *, CC_LONG))(void (*)())&SHA1_Update;
		md_final	= (int (*)(unsigned char*, void*))&SHA1_Final;
		break;
	case 32: 
		mdctx = malloc(sizeof(SHA256_CTX));
		md=(unsigned char *)malloc(SHA256_DIGEST_LENGTH);
		md_init		= (int(*)(void *))&SHA256_Init;
		md_update	= (int (*)(void *, const void *, CC_LONG))(void (*)())&SHA256_Update;
		md_final	= (int (*)(unsigned char*, void*))&SHA256_Final;
		break;
	case 64:
		mdctx = malloc(sizeof(SHA512_CTX));
		md=(unsigned char *)malloc(SHA512_DIGEST_LENGTH);
		md_init		= (int(*)(void *))&SHA512_Init;
		md_update	= (int (*)(void *, const void *, CC_LONG))(void (*)())&SHA512_Update;
		md_final	= (int (*)(unsigned char*, void*))&SHA512_Final;
		break;
#else
	case 16: md = EVP_md5();break;
	case 20: md = EVP_sha1();break;
	case 32: md = EVP_sha256();break;
#ifdef HAVE_EVP_SHA512
	case 64: md = EVP_sha512();break;
#endif
#endif
	default:
	    assert(0);
#ifdef __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__
	fprintf(stderr,"MacOSX version %d\n. Openssl evp fuctions are deprecated.\n Using CommonCrypto.",__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__);
#endif
	}
    }
    ~hash_generator__(){
	release();
    }
    void init(){
	if(initialized==false){
#ifdef COMMON_DIGEST_FOR_OPENSSL
		md_init(mdctx);
#else
	    EVP_MD_CTX_init(&mdctx);
	    EVP_DigestInit_ex(&mdctx, md, NULL);
#endif
	    initialized = true;
	    finalized = false;
	    hashed_bytes = 0;
	}
    }
    void update(const uint8_t *buf,size_t bufsize){
	if(!initialized) init();
	if(finalized){
	    std::cerr << "hashgen_t::update called after finalized\n";
	    exit(1);
	}
#ifndef COMMON_DIGEST_FOR_OPENSSL
	EVP_DigestUpdate(&mdctx,buf,bufsize);
#else
	md_update(mdctx, buf, bufsize);
#endif
	hashed_bytes += bufsize;
    }
    void release(){			/* free allocated memory */
	if(initialized){
#ifdef COMMON_DIGEST_FOR_OPENSSL
		free(md);
		free(mdctx);
#else
	    EVP_MD_CTX_cleanup(&mdctx);
#endif
	    initialized = false;
	    hashed_bytes = 0;
	}
    }
    hash__<T> final() {
	if(finalized){
	  std::cerr << "currently friendly_geneator does not cache the final value\n";
	  assert(0);
	  /* code below will never be executed after assert(0) */
	}
	if(!initialized){
	  init();			/* do it now! */
	}
	hash__<T> val;
#ifdef COMMON_DIGEST_FOR_OPENSSL
	md_final(val.digest, mdctx);
#else
	unsigned int len = sizeof(val.digest);
	EVP_DigestFinal(&mdctx,val.digest,&len);
#endif
	finalized = true;
	return val;
    }

    /** Compute a sha1 from a buffer and return the hash */
    static hash__<T>  hash_buf(const uint8_t *buf,size_t bufsize){
	/* First time through find the SHA1 of 512 NULLs */
#if 0
	if(sha1_ctr==0){
	    uint8_t b2[512];
	    EVP_MD_CTX ctx2;
	    unsigned int len = sizeof(sha1_512nulls);
	    memset(b2,0,sizeof(b2));
	    EVP_MD_CTX_init(&ctx2);
	    EVP_DigestInit_ex(&ctx2, EVP_sha1(), NULL);
	    EVP_DigestUpdate(&ctx2,b2,sizeof(b2));
	    EVP_DigestFinal(&ctx2,sha1_512nulls,&len);
	    sha1_ctr++;
	}

	/* If the input is 512 bytes long and all NULLs, use our SHA1 of 512 NULLs */
	if(bufsize==512 && iszero(buf,bufsize)){
	    return sha1_t(sha1_512nulls);
	}
#endif
	hash_generator__ g;
	g.update(buf,bufsize);
	return g.final();
    }
	
#ifdef HAVE_MMAP
    /** Static method allocateor */
    static hash__<T> hash_file(const char *fname){
	int fd = open(fname,O_RDONLY
#ifdef O_BINARY
		      |O_BINARY
#endif
		      );
	if(fd<0) throw fname;
	struct stat st;
	if(fstat(fd,&st)<0){
	    close(fd);
	    throw fname;
	}
	const uint8_t *buf = (const uint8_t *)mmap(0,st.st_size,PROT_READ,MAP_FILE|MAP_SHARED,fd,0);
	if(buf==0){
	    close(fd);
	    throw fname;
	}
	hash__<T> s = hash_buf(buf,st.st_size);
	munmap((void *)buf,st.st_size);
	close(fd);
	return s;
    }
#endif
};

typedef hash_generator__<md5_> md5_generator;
typedef hash_generator__<sha1_> sha1_generator;
typedef hash_generator__<sha256_> sha256_generator;

#ifdef HAVE_EVP_SHA512
typedef hash_generator__<sha512_> sha512_generator;
#endif

#endif
