/* sha1.c : Implementation of the Secure Hash Algorithm */

/* SHA: NIST's Secure Hash Algorithm */

/*	This version written November 2000 by David Ireland of 
	DI Management Services Pty Limited <code@di-mgt.com.au>

	Adapted from code in the Python Cryptography Toolkit, 
	version 1.0.0 by A.M. Kuchling 1995.
*/

/* AM Kuchling's posting:- 
   Based on SHA code originally posted to sci.crypt by Peter Gutmann
   in message <30ajo5$oe8@ccu2.auckland.ac.nz>.
   Modified to test for endianness on creation of SHA objects by AMK.
   Also, the original specification of SHA was found to have a weakness
   by NSA/NIST.  This code implements the fixed version of SHA.
*/

/* Here's the first paragraph of Peter Gutmann's posting:
   
The following is my SHA (FIPS 180) code updated to allow use of the "fixed"
SHA, thanks to Jim Gillogly and an anonymous contributor for the information on
what's changed in the new version.  The fix is a simple change which involves
adding a single rotate in the initial expansion function.  It is unknown
whether this is an optimal solution to the problem which was discovered in the
SHA or whether it's simply a bandaid which fixes the problem with a minimum of
effort (for example the reengineering of a great many Capstone chips).
*/


#include <stdio.h>
#include <string.h>
#include "tsk/libtsk.h"


#define SHA_HASH_LENGTH 	20
#define SHA_BUFSIZ 1024

char *
crunch(fp)
  FILE *fp;
{

    unsigned char sum[SHA_HASH_LENGTH];

    unsigned char buf[SHA_BUFSIZ];

    static char result[2 * SHA_HASH_LENGTH + 1];
    static char hex[] = "0123456789abcdef";

    TSK_SHA_CTX sha;
    int i;
    int buflen;

    TSK_SHA_Init(&sha);
    while ((buflen = fread(buf, 1, SHA_BUFSIZ, fp)) > 0)
        TSK_SHA_Update(&sha, buf, buflen);

    TSK_SHA_Final(sum, &sha);

    for (i = 0; i < SHA_HASH_LENGTH; i++) {
        result[2 * i] = hex[(sum[i] >> 4) & 0xf];
        result[2 * i + 1] = hex[sum[i] & 0xf];
    }
    return (result);
}




int
main(argc, argv)
  int argc;
  char **argv;
{
    char *myname = argv[0];
    char *crunch();
    FILE *fp;

    if (argc < 2) {
        printf("%s\n", crunch(stdin));
    }
    else {
        while (--argc && *++argv) {
            if ((fp = fopen(*argv, "r")) == 0) {
                fprintf(stderr, "%s: ", myname);
                perror(*argv);
                return (1);
            }
            printf("%s  %s\n", crunch(fp), *argv);
            fclose(fp);
        }
    }
    return (0);
}
