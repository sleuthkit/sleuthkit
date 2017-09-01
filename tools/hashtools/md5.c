/*++
* NAME
*	md5 1
* SUMMARY
*	compute MD5 signatures
* SYNOPSIS
*	\fBmd5\fR \fIfile(s)\fR ...
* DESCRIPTION
*	\fBmd5\fR opens the named \fIfile(s)\fR in order (standard
*	input by default) and computes the md5 checksum for each file.
*
*	The output format is one line per file with the checksum and
*	corresponding file name separated by whitespace (no file name 
*	is emitted when reading from standard input).
*
*	This program has a somewhat easier to parse output format
*	than the \fBmd5\fR utility found on some UNIX systems.
* AUTHOR(S)
*	Wietse Venema
*	This program is part of SATAN.
*
*	The MD5 implementation used by this program is placed in the 
*	public domain for free general use by RSA Data Security.
*--*/

#include <stdio.h>
#include "tsk/libtsk.h"

#define MD5_HASH_LENGTH	16

int
main(argc, argv)
  int argc;
  char **argv;
{
    char *myname = argv[0];
    char *crunch();

    if (argc < 2) {
        printf("%s\n", crunch(stdin));
    }
    else {
        while (--argc && *++argv) {
            FILE *fp;
            if ((fp = fopen(*argv, "r")) == 0) {
                fprintf(stderr, "%s: ", myname);
                perror(*argv);
                return (1);
            }
            printf("%s	%s\n", crunch(fp), *argv);
            fclose(fp);
        }
    }
    return (0);
}

char *
crunch(fp)
  FILE *fp;
{
    TSK_MD5_CTX md;
    unsigned char sum[MD5_HASH_LENGTH];
    unsigned char buf[BUFSIZ];
    static char result[2 * MD5_HASH_LENGTH + 1];
    static char hex[] = "0123456789abcdef";
    int buflen;
    int i;

    TSK_MD5_Init(&md);
    while ((buflen = fread(buf, 1, BUFSIZ, fp)) > 0)
        TSK_MD5_Update(&md, buf, buflen);
    TSK_MD5_Final(sum, &md);

    for (i = 0; i < MD5_HASH_LENGTH; i++) {
        result[2 * i] = hex[(sum[i] >> 4) & 0xf];
        result[2 * i + 1] = hex[sum[i] & 0xf];
    }
    return (result);
}
