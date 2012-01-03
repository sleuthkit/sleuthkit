/* The software provided here is released by the National
 * Institute of Standards and Technology (NIST), an agency of
 * the U.S. Department of Commerce, Gaithersburg MD 20899,
 * USA.  The software bears no warranty, either expressed or
 * implied. NIST does not assume legal liability nor
 * responsibility for a User's use of the software or the
 * results of such use.
 * Please note that within the United States, copyright
 * protection, under Section 105 of the United States Code,
 * Title 17, is not available for any work of the United
 * States Government and/or for any works created by United
 * States Government employees. User acknowledges that this
 * software contains work which was created by NIST employees
 * and is therefore in the public domain and not subject to
 * copyright.  The User may use, distribute, or incorporate
 * this software provided the User acknowledges this via an
 * explicit acknowledgment of NIST-related contributions to
 * the User's work. User also agrees to acknowledge, via an
 * explicit acknowledgment, that any modifications or
 * alterations have been made to this software before
 * redistribution.
 * --------------------------------------------------------------------
 *
 * Change History:
 * Simson L. Garfinkel - May 1, 2008
 *   - Major rewrite using new function
 * Simson L. Garfinkel - simsong@acm.org - August 21, 2006
 *   - Re-implemented based on Douglas White's original Perl code.
 *   - First 4096-bytes of file describes parameters
 *   - Single executable for both 128-bit and 160-bit Bloom filters.
 *   - Uses memmap() for handling 512MB bloom filters. 
 * Douglas White - douglas.white@nist.gov - June 21, 2003
 *   Original implementation in perl.
 */

#include "tsk3/tsk_tools_i.h"
//#include "config.h"			/* required for OpenSSL defs */
#include "bloom.h"

#ifdef WIN32
#include <winsock.h>
#endif

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_ERR_H
#include <err.h>
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_OPENSSL_HMAC_H
#include <openssl/hmac.h>
#endif

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include <math.h>

#ifdef _MSC_VER
#define PRId64 "I64d"
#define PRIi64 "I64i"
#define PRIu64 "I64u"
#endif


#define BLOOM_VECTOR_OFFSET 4096	/* size of one page */

#ifndef O_BINARY
#define O_BINARY 0
#endif


static uint8_t *hexcharvals = 0;
static int64_t bloom_lookups = 0;

/** Initialization function is used solely for hex output
 */
#ifdef __GNUC__
	static void nsrl_exit(int code) __attribute__ ((noreturn));
#endif
static void nsrl_exit(int code)
{
    int i;
    for(i=0;i<10;i++){
	fprintf(stderr,"****************************************************\n");
    }
    fprintf(stderr,"bloom.c: NSRL Exit Code %d\n",code);
    exit(code);
}

static void nsrl_bloom_init(void)
{
    if(hexcharvals==0){
	/* Need to initialize this */
	uint8_t i;
	hexcharvals = (uint8_t *)calloc(sizeof(uint8_t),256);
	for(i=0;i<10;i++){
	    hexcharvals['0'+i] = i;
	}
	for(i=10;i<16;i++){
	    hexcharvals['A'+i-10] = i;
	    hexcharvals['a'+i-10] = i;
	}
    }
}


/**
 * Convert a hex representation to binary, and return
 * the number of bits converted.
 * @param binbuf output buffer
 * @param binbuf_size size of output buffer in bytes.
 * @param hex    input buffer (in hex)
 * @return the number of converted bits.
 */
int nsrl_hex2bin(unsigned char *binbuf,size_t binbuf_size,const char *hex)
{
    int bits = 0;
    if(hexcharvals==0) nsrl_bloom_init();
    while(hex[0] && hex[1] && binbuf_size>0){
	*binbuf++ = (unsigned char)(((hexcharvals[(int)hex[0]]<<4) | hexcharvals[(int)hex[1]]));
	hex  += 2;
	bits += 8;
	binbuf_size -= 1;
    }
    return bits;
}

/**
 * Convert a binary blob to a hex representation
 */

const char *nsrl_hexbuf(char *dst,size_t dst_len,const unsigned char *bin,uint32_t bytes,int flag)
{
    int charcount = 0;
    const char *start = dst;		// remember where the start of the string is
    const char *fmt = (flag & NSRL_HEXBUF_UPPERCASE) ? "%02X" : "%02x";

    if(hexcharvals==0) nsrl_bloom_init();
    *dst = 0;				// begin with null termination
    while(bytes>0 && dst_len > 3){
	sprintf(dst,fmt,*bin); // convert the next byte to hex
	dst += 2;
	bin += 1;
	dst_len -= 2;
	bytes--;
	charcount++;			// how many characters
	
	if((flag & NSRL_HEXBUF_SPACE2) ||
	   ((flag & NSRL_HEXBUF_SPACE4) && charcount%2==0)){
	  *dst++ = ' ';
	  *dst   = '\000';
	  dst_len -= 1;
	}
    }
    return start;			// return the start
}


/**
 * Sets a numbered bit of the bloom filter.
 */
#ifdef MSC
#define inline 
#endif

static inline void set_bloom_bit(nsrl_bloom *b,uint32_t bit)
{
    uint8_t q = (uint8_t)(1<<(bit%8));
    b->vector[bit/8] |= q;
}

/** Gets a numbered bit of the bloom filter.
 * @param b The bloom filter
 * @param bit The numbered bit to get.
 */
static inline int get_bloom_bit(const nsrl_bloom *b,uint32_t bit)
{
    int q = 1<<(bit%8);			/* bit that we need to probe */
    return (b->vector[bit/8] & q) ? 1 : 0;
}


void nsrl_bloom_fprint_info(const nsrl_bloom *b,FILE *out)
{
    fprintf(out,"hash_bytes: %d\n",b->hash_bytes);
    fprintf(out,"M: %d\n",b->M);
    fprintf(out,"k: %d\n",b->k);
    fprintf(out,"vector_bytes: %d\n",(int)b->vector_bytes);
    fprintf(out,"vector_offset: %d\n",b->vector_offset);
    fprintf(out,"vector: %p\n",b->vector);
    fprintf(out,"# comment: %s\n",b->comment ? b->comment : "");
    fprintf(out,"added_items: %"PRId64"\n",b->added_items);
    fprintf(out,"unique_added_items: %"PRId64"\n",b->unique_added_items);
    fprintf(out,"aliased_adds: %"PRId64"\n",b->aliased_adds);
    fprintf(out,"Computed False Positive Rate: %6g\n",
	    BLOOM_CALC_P((double)(1<<b->M),(double)b->added_items,(double)b->k));
}

void nsrl_bloom_print_info(const nsrl_bloom *b)
{
    nsrl_bloom_fprint_info(b,stdout);
}

void nsrl_bloom_fprint_usage(FILE *out)
{
#ifdef HAVE_GETRUSAGE
    struct rusage ru;
    uint32_t total_msec=0;
    //memset(&ru,0,sizeof(ru));
    if(getrusage(RUSAGE_SELF,&ru)!=0) return;
    total_msec =
	(uint32_t)ru.ru_utime.tv_sec*1000 + (uint32_t)ru.ru_utime.tv_usec/1000 + 
	(uint32_t)ru.ru_stime.tv_sec*1000 + (uint32_t)ru.ru_stime.tv_usec/1000;
    
    fprintf(out,"# utime: %d.%03d  stime: %d.%03d\n",
	    (int)ru.ru_utime.tv_sec, (int)ru.ru_utime.tv_usec/1000,
	    (int)ru.ru_stime.tv_sec, (int)ru.ru_stime.tv_usec/1000);
    fprintf(out,"# maxrss: %ldMB page reclaims: %ld page faults: %ld  swaps: %ld\n",
	    ru.ru_maxrss/(1024*1024),ru.ru_minflt,ru.ru_majflt,ru.ru_nswap);
    fprintf(out,"# inputs: %ld  outputs: %ld\n",ru.ru_inblock,ru.ru_oublock);
    fprintf(out,"# total time: %"PRIu32" msec\n",total_msec);
    if(bloom_lookups){
	fprintf(out,"# average lookups per second: %.0f\n",(double)bloom_lookups * 1000.0 / (double)total_msec);
    }
#else
    (void)out;
#endif
}

void nsrl_bloom_print_usage()
{
    nsrl_bloom_fprint_usage(stdout);
}


/**
 * Converts bloom filter parameters into ascii for storage in filter.
 */
void nsrl_bloom_info(char *buf,size_t buflen, const nsrl_bloom *b)
{
    snprintf(buf,buflen,
	     "nsrl_bf_version:2\n"
	     "hash_bits:%"PRId64"\n"
	     "bloom_bits:%"PRId64"\n"
	     "k:%"PRId64"\n"
	     "added_items:%"PRId64"\n"
	     "unique_added_items:%"PRId64"\n"
	     "aliased_adds:%"PRId64"\n"
	     "comment:%s\n",
	     (int64_t)(b->hash_bytes*8), (int64_t)b->M,(int64_t)b->k,
	     (int64_t)b->added_items,(int64_t)b->unique_added_items,(int64_t)b->aliased_adds,b->comment);
}

/**
 * Histogram analysis for printing information about usage of bloom filter.
 */
void nsrl_calc_histogram(const nsrl_bloom *b,uint32_t counts[256])
{
    uint32_t i;
    uint32_t byteswbits = 0;

    memset(counts,0,sizeof(counts));
    for(i=0;i<b->vector_bytes;i++){
    	if(b->vector[i]) {
	    counts[b->vector[i]]++;
	    byteswbits++;}
    }
}

void nsrl_print_histogram(const nsrl_bloom *b,const uint32_t counts[256])
{
    uint32_t totalbits = 0;
    uint32_t bitcount = 0;
    int i,j,mask;
    float top, bottom, percent = 0.0;
    for(i=1;i<256;i++){
	if(counts[i] > 0){
	    for(j = 0; j<8; j++){
		mask = (1 << j);
		if(i&mask){ bitcount += counts[i]; } 
	    }
	}
    }
    if(b->M < 32) totalbits = (uint32_t)1<<b->M;
    else{ totalbits--;}
    printf("%u bits total, %u bits set\n",totalbits, bitcount);
    top = (float)bitcount;
    bottom = (float)totalbits;
    percent = top/bottom;
    percent *= 100;
    printf("%f percent full\n", percent);
}


static int nsrl_bloom_info_update(nsrl_bloom *b)
{
    char buf[BLOOM_VECTOR_OFFSET];
    if(b->fd==0) return 0;		/* no open file to update */
    memset(buf,0,sizeof(buf));
    nsrl_bloom_info(buf,sizeof(buf),b);
    if (lseek(b->fd,0,SEEK_SET)) return -1;
    if (write(b->fd,buf,BLOOM_VECTOR_OFFSET)!=BLOOM_VECTOR_OFFSET) return -1;
    return 0;
}

/* Return the ith bit of a blob */
static inline uint32_t get_bit(const unsigned char *buf,uint32_t bit)
{
    return (buf[bit/8] & (1<<bit%8)) ? 1 : 0;
}


/*
 * Encrypt with HMAC of hash; store the results in ebuf.
 */
static inline const unsigned char *hash_encrypt(const nsrl_bloom *b,const unsigned char *hash,unsigned char *ebuf)
{
#ifdef HAVE_OPENSSL_HMAC_H
    unsigned len = b->hash_bytes;	/* make openSSL happy */
    HMAC(b->md,b->key,(int)b->hash_bytes,hash,b->hash_bytes,ebuf,&len);
    return ebuf;
#else
    fprintf(stderr,"hash_encrypt requires OpenSSL HMAC at present.\n");
    exit(-1);
    return 0;
#endif
}

/**
 * Add a hash into the bloom filter, updating the counters.
 * @param b The bloom filter.
 * @param hash The hash to add; needs to be b->hash_bytes long.
 */
void nsrl_bloom_add(nsrl_bloom *b,const unsigned char *hash)
{
    /* Split the hash k times according to bloom_bits(M) */
    uint32_t i;				/* bit counter */
    uint32_t added_bits = 0;		/* set to 0 all of the bits have already been set */
    if (b->debug){
	char buf[1024];
	printf("nsrl_bloom_add(%s)\n",nsrl_hexbuf(buf,sizeof(buf),hash,b->hash_bytes,0));
    }
#ifdef HAVE_PTHREAD
    if (b->multithreaded){
	pthread_mutex_lock(&b->mutex);
    }
#endif
    {
	u_char ebuf[20];
	if (b->key) hash = hash_encrypt(b,hash,ebuf);
    }
    for(i=0;i<b->k;i++){		/* repeat for each hash function */
	uint32_t offset = i * b->M;	/* compute offset into provided hash */
	uint32_t v = 0;
	uint32_t j;
	
	for(j=0;j<b->M;j++){
	    v = (v<<1) | get_bit(hash,offset+j);
	}
	if(b->debug>1) { printf(" Setting bit: %08x (was %d).\n",v,get_bloom_bit(b,v)); }
	if(get_bloom_bit(b,v)==0){
	    set_bloom_bit(b,v);
	    added_bits += 1;		/* remember that we added another one */
	} 
    }
    if(added_bits==b->k) b->unique_added_items++; /* all of the bits were set */
    if(added_bits==0)    b->aliased_adds++;
    b->added_items++;
    if (b->added_items % 1000==0) nsrl_bloom_info_update(b);
    if (b->debug>1) { printf("\n"); }
#ifdef HAVE_PTHREAD
    if (b->multithreaded){
	pthread_mutex_unlock(&b->mutex);
    }
#endif
}

#ifdef WIN32
/* This code can be called multithreaded since the hProv can be used to create multiple hashes.
 */
void Win32BloomHash(nsrl_bloom *b,const char *str,u_char *buf,DWORD *buflen)
{
    if(b->hProv==0){
	fprintf(stderr,"Win32BloomHash: b->hProv==0???\n");
	nsrl_exit(1);
    }
    if (!CryptCreateHash(b->hProv, b->digest_type, 0, 0, &b->hHash)) {
        DWORD dwStatus = GetLastError();
        fprintf(stderr,"CryptCreateHash(bloom.c)(%d,%d) failed: %d\n",
		(int)b->hProv,(int)b->digest_type,(int)dwStatus); 
        CryptReleaseContext(b->hProv, 0);
	nsrl_exit(1);
    }
    if(!CryptHashData(b->hHash,(BYTE *)str,(DWORD)strlen(str),0)){
	fprintf(stderr,"CryptHashData(bloom.c): Unable to update digest context hash");
	nsrl_exit(1);
    }
    if( !CryptGetHashParam(b->hHash,HP_HASHVAL,(BYTE *)buf, buflen, 0 )) {
	fprintf(stderr, "CryptGetHashParam(bloom.c): unable to finalize digest hash.\n");
	nsrl_exit(1);
    }
    if( !CryptDestroyHash( b->hHash )){
	fprintf(stderr," CryptDestroyHash(bloom.c): failed\n");
	nsrl_exit(1);
    }
    if(b->hHash==0 || b->digest_type==0){
	fprintf(stderr,"Things got broken\n");
	nsrl_exit(1);
    }
}
#endif

int nsrl_bloom_addString(nsrl_bloom *b,const char *str)
{
    int previously_present = 0;
    //char dst[64];
#if defined(HAVE_OPENSSL_HMAC_H)
    uint32_t buflen = EVP_MAX_MD_SIZE;
    u_char buf[buflen];
    EVP_Digest((const void *)str,strlen(str),buf,&buflen,b->md,0);
#else
#if defined(WIN32)
    u_char buf[64];
    DWORD buflen = sizeof(buf);
    Win32BloomHash(b,str,buf,&buflen);
#endif
#endif
    //printf("string='%s' hash=%s\n",str,nsrl_hexbuf(dst,sizeof(dst),buf,buflen,0));
    previously_present = nsrl_bloom_query(b,buf);
    if(!previously_present) nsrl_bloom_add(b,buf);
    return previously_present;
}

/* nsrl_bloom_query:
 * Check each round of nist_function128 in the vector. If any are not set,
 * then the hash is not in the bloom filter.
 *
 * Returns: 1 if present, 0 if not present
 */
int nsrl_bloom_query( nsrl_bloom *b,const unsigned char *hash)
{
    uint32_t i,j;
    int found = 1;
#ifdef HAVE_PTHREAD
    if (b->multithreaded){
	pthread_mutex_lock(&b->mutex);
    }
#endif
    bloom_lookups += 1;
    if (b->debug){
	char buf[1024];
	printf("nsrl_bloom_query(%s) k:%d M:%d\n",
	       nsrl_hexbuf(buf,sizeof(buf),hash,b->hash_bytes,0),b->k,b->M);
    }
    {
	u_char ebuf[20];
	if (b->key) hash = hash_encrypt(b,hash,ebuf);
    }
    for(i=0;i<b->k && found;i++){		/* i is which vector function to query */
	uint32_t offset = i * b->M;
	uint32_t v = 0;		/* v is the bit in the vector that is to be queried */
	for(j=0;j<b->M;j++){
	    v = (v<<1) | get_bit(hash,offset+j);
	}
	if(b->debug>1){ printf("  %s V(0x%08x)=%d\n", (i==0?"VECTORS":"       "), v,get_bloom_bit(b,v)); }
	if(get_bloom_bit(b,v)==0){
	    found = 0;
	}
    }
    /* All of the bits were set; hash must be in the bloom filter */
    if(b->debug>1) putchar('\n');
    b->hits++;
#ifdef HAVE_PTHREAD
    if (b->multithreaded){
	pthread_mutex_unlock(&b->mutex);
    }
#endif
    return found;			
}

int nsrl_bloom_queryString(nsrl_bloom *b,const char *str)
{
#ifdef HAVE_OPENSSL_HMAC_H
    u_char buf[EVP_MAX_MD_SIZE];
    uint32_t buflen = EVP_MAX_MD_SIZE;
    EVP_Digest((const void *)str,strlen(str),buf,&buflen,b->md,0);
#else
#ifdef WIN32
    u_char buf[64];
    DWORD buflen = sizeof(buf);
    Win32BloomHash(b,str,buf,&buflen);
#endif
#endif
    return nsrl_bloom_query(b,buf);
}

/*
 * Returns the utilization from 0 to 1.0 (fraction of bits set.)
 */
double nsrl_bloom_utilization(const nsrl_bloom *b)
{
    int64_t bits_set = 0;
    uint32_t i;
    if(b->added_items==0) return 0.0;	/* optimization */
    for(i=0;i<b->vector_bytes;i++){
	/* Count the number of bits set */
	if(b->vector[i] & 0x01) bits_set++;
	if(b->vector[i] & 0x02) bits_set++;
	if(b->vector[i] & 0x04) bits_set++;
	if(b->vector[i] & 0x08) bits_set++;
	if(b->vector[i] & 0x10) bits_set++;
	if(b->vector[i] & 0x20) bits_set++;
	if(b->vector[i] & 0x40) bits_set++;
	if(b->vector[i] & 0x80) bits_set++;
    }
    return (double)bits_set / ((double)(b->vector_bytes) * 8.0);
}

/****************************************************************
 *** Routines for creating and opening bloom filters.
 ****************************************************************/

nsrl_bloom *nsrl_bloom_alloc()
{
    nsrl_bloom *b = (nsrl_bloom *)calloc(sizeof(*b),1);
    b->free_this = 1;
    return b;
}

static void nsrl_bloom_set_params(nsrl_bloom *b)
{
#ifdef HAVE_OPENSSL_HMAC_H
    OpenSSL_add_all_digests();
    switch(b->hash_bytes){
    case 16:	b->md = EVP_get_digestbyname("md5");	break;
    case 20:	b->md = EVP_get_digestbyname("sha1");	break;
    case 32:    b->md = EVP_get_digestbyname("sha256"); break;
    default:
	fprintf(stderr,"nsrl_bloom_set_params: hash_bytes=%d?\n",b->hash_bytes);
	nsrl_exit(1);
    }
#else
#ifdef WIN32
    /* Request the AES crypt provider, fail back to the RSA crypt provider
     */

    b->hProv = 0;
    b->hHash = 0;
    if(CryptAcquireContext(&b->hProv,
			   NULL,	/* pszContainer */
			   NULL,	/* pszProvider */
			   PROV_RSA_FULL, /* dwProvType */
			   CRYPT_VERIFYCONTEXT)==0) /* dwFlags */ {
	fprintf(stderr,"CryptAcquireContext(bloom.c): Cannot create RSA crypt provider");
	nsrl_exit(1);
    }
    switch(b->hash_bytes){
    case 16:	b->digest_type = CALG_MD5;break;
    case 20:	b->digest_type = CALG_SHA1;break;
    case 32:    fprintf(stderr,"bloom under windows can't handle 32-bits...\n");
	nsrl_exit(1);
    default:
	fprintf(stderr,"nsrl_bloom_set_params: hash_bytes=%d?\n",b->hash_bytes);
	nsrl_exit(1);
    }
#else
#error Need OpenSSL or WIN32
#endif
#endif
}



#define xstr(s) str(s)
#define str(s) #s
/**
 * Open a bloom filter, return 0 if successful.
 * Currently this doesn't run on WIN32; it needs the WIN32 memory map file stuff.
 */
int nsrl_bloom_open(nsrl_bloom *b,const char *fname,int mode)
{
#ifdef HAVE_MMAP
    char offset_buf[BLOOM_VECTOR_OFFSET];
    char *line,*buf;
    int version = 0;
    int  prot = 0;

    switch(mode & O_ACCMODE){
    case O_RDONLY: prot = PROT_READ;if(b->debug) printf("PROT_READ\n");break;
    case O_WRONLY: prot = PROT_WRITE;if(b->debug) printf("PROT_WRITE\n");break;
    case O_RDWR:   prot = PROT_READ|PROT_WRITE;if(b->debug) printf("PROT_READ|PROT_WRITE\n");break;
    }

    /* Open the file and get the parameters */

    b->fd = open(fname,mode|O_BINARY,0);
    if(b->fd<0) return -1;			/* could not open */

    if(read(b->fd,offset_buf,sizeof(offset_buf))!=sizeof(offset_buf)){
	errno = EINVAL;
	return -1;			/* not big enough for header? */
    }
    buf = offset_buf;
    
    while((line = strsep(&buf,"\n"))){
	char *colon = index(line,':');
	if(colon){
	    *colon = 0;			/* terminate at the colon */
	    const char *after_colon = colon + 1;
	    if(strcmp(line,str(nsrl_bf_version))==0)    version = atoi(after_colon);
	    if(strcmp(line,str(hash_bits))==0)          b->hash_bytes = (unsigned)atoi(after_colon)/8;
	    if(strcmp(line,str(bloom_bits))==0)         b->M = (unsigned)atoi(after_colon);
	    if(strcmp(line,str(k))==0)                  b->k = (unsigned)atoi(after_colon);
	    if(strcmp(line,str(added_items))==0)	b->added_items = (unsigned)atoi(after_colon);
	    if(strcmp(line,str(unique_added_items))==0) b->unique_added_items = (unsigned)atoi(after_colon);
	    if(strcmp(line,str(aliased_adds))==0)       b->aliased_adds = (unsigned)atoi(after_colon);
	    if(strcmp(line,str(comment))==0)            b->comment = strdup(after_colon);
	}
    }
    nsrl_bloom_set_params(b);

    if(version!=2){
	fprintf(stderr,"bloom: require nsrl bf vesion 2; got version %d\n",version);
	errno= EINVAL;
	return -1;
    }
    if(b->hash_bytes==0 || b->M==0 || b->k==0){
	close(b->fd);
	errno= EINVAL;
	fprintf(stderr,"bloom: invalid parameters. hash_bytes=%d bloom_bits=%d k=%d\n",
		b->hash_bytes,b->M,b->k);
	return -1;
    }
    b->vector_bytes  = (unsigned)1 << (b->M-3);
    b->vector = (uint8_t *)mmap(0,b->vector_bytes, prot, MAP_FILE|MAP_SHARED, b->fd,BLOOM_VECTOR_OFFSET);
    if(b->vector == MAP_FAILED){
	return -1;			/* ugh. */
    }
    b->memmapped = 1;
    return 0;
#else
    (void)b;
    (void)fname;
    (void)mode;
    fprintf(stderr,"Currently NSRL required mmap.\n");
    nsrl_exit(1);
    return -1;
#endif    
}

/** nsrl_bloom_write:
 * @param b - bloom filter
 * @param fname - name of file to write to
 */
int nsrl_bloom_write(nsrl_bloom *b,const char *fname)
{
    size_t written = 0;
    /* Create the file with the paremters and empty bloom filter */
    b->fd = open(fname,O_CREAT|O_RDWR|O_EXCL|O_BINARY,0666); 
    if(b->fd<0){
	return -1;		/* failed */
    }

    if(nsrl_bloom_info_update(b)){	/* try to write the parameters */
	unlink(fname);			/* erase the file */
	return -1;			/* some writing problem */
    }
    /* Tab out to where the vector starts.
     * We pre-allocate the file (avoid making it sparse) to prevent the file being
     * fragmented on the hard drive.
     * We also only write a max of 1MB at a time because the 64-bit POSIX implementation
     * doesn't like writing more than 2^31-1 bytes at a time.
     */
    lseek(b->fd,BLOOM_VECTOR_OFFSET,SEEK_SET); 
    
    while(written < b->vector_bytes){
	size_t towrite = b->vector_bytes - written;
	if(towrite>1024*1024) towrite = 1024*1024;
	if(write(b->fd,b->vector+written,towrite)!=(ssize_t)towrite){ /* write failure? */
	    unlink(fname);
	    return -1;			/* write problem */
	}
	written += towrite;
    }
    return 0;
}


/** nsrl_bloom_create:
 * @param fname - name of the filter to create; 0 if in-memory
 * @param hash_bits  - the number of bits in values to be hashed.
 * @param bloom_bits - log2(m)
 * @param k = k
 * @param comment - a comment to store in the bloom filter.
 */

int nsrl_bloom_create(nsrl_bloom *b,
		      const char *fname,uint32_t hash_bits, uint32_t bloom_bits,uint32_t k,
		      const char *comment)
{
    b->vector_bytes = ((size_t)1) << (bloom_bits-3);	/* Needed vector size */
    b->vector = (uint8_t *)calloc(b->vector_bytes,1);

    if(b->vector==0) return -1;			/* not enough memory to allocate vector buf */
    if(hash_bits < bloom_bits * k){
	fprintf(stderr,"bloom_bits * k > hash_bits (%d * %d > %d)",bloom_bits,k,hash_bits);
	nsrl_exit(1);
    }

    if(hash_bits%8 != 0) {
	fprintf(stderr,"hash_bits must be a multiple of 8 (is %d)\n",hash_bits);
	nsrl_exit(1);
    }

    b->hash_bytes    =  hash_bits/8;
    b->M             =  bloom_bits;
    b->k             =  k;
    b->comment       =  strdup(comment);
    nsrl_bloom_set_params(b);

    if(fname==0) return 0;		/* nameless bloom filter; we are done */

    /**
     * Write the bloom filter to a file
     */

    if(nsrl_bloom_write(b,fname)) return -1;   
    free(b->vector);
#ifdef HAVE_MMAP
    /**
     * Map the bloom filter into memory
     */
    b->vector = (uint8_t *)mmap(0,b->vector_bytes,PROT_READ|PROT_WRITE,MAP_FILE|MAP_SHARED,b->fd,
		     BLOOM_VECTOR_OFFSET);
    b->memmapped = 1;
    return 0;
#else
    fprintf(stderr,"bloom currently requires MMAP\n");
    nsrl_exit(1);
    return -1;
#endif
}

#ifdef HAVE_PTHREAD
int nsrl_bloom_init_mutex(nsrl_bloom *b)
{
    if(b->multithreaded==0){
	if(pthread_mutex_init(&b->mutex,NULL)) return -1;
	b->multithreaded=1;
    }
    return 0;
}
#endif    



/**
 * Establish a passphrase for the specified bloom filter.
 */

void nsrl_set_passphrase(nsrl_bloom *b,const char *passphrase)
{
#ifdef HAVE_OPENSSL_HMAC_H
    EVP_Digest((const void *)passphrase,strlen(passphrase),b->key,&b->hash_bytes,b->md,0);
#endif
}

/**
 * Clear the allocated storage.
 */
void nsrl_bloom_clear(nsrl_bloom *b)
{
#ifdef HAVE_MMAP
    if(b->vector && (b->vector!=MAP_FAILED)){
	if(b->memmapped) munmap(b->vector,b->vector_bytes);
	else free(b->vector);		/* free the memory otherwise */
    }
#endif
    if(b->fd)      close(b->fd);	/* close the file */
    if(b->comment) free(b->comment);
#ifdef HAVE_OPENSSL_HMAC_H
    if(b->key){
	memset(b->key,0,b->hash_bytes);
	free(b->key);
    }
#else
    if(b->hProv){
	CryptReleaseContext( b->hProv, 0 );
    }
#endif
#ifdef HAVE_PTHREAD
    if(b->multithreaded){
	pthread_mutex_destroy(&b->mutex);
	b->multithreaded=0;
    }
#endif
    memset(b,0,sizeof(nsrl_bloom));		/* clean object reuse */
}

void nsrl_bloom_free(nsrl_bloom *b)
{
    nsrl_bloom_clear(b);
    free(b);
}


