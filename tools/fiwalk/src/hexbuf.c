/**
 * hexbuf()
 * Turns a binary buffer into a hexdecimal string.
 */

#include "tsk/tsk_config.h"
#include "hexbuf.h"
#include <stdio.h>

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

const char *hexbuf(char *dst,int dst_len,const unsigned char *bin,int bytes,int flag)
{
    int charcount = 0;
    const char *start = dst;		// remember where the start of the string is
    const char *fmt = (flag & HEXBUF_UPPERCASE) ? "%02X" : "%02x";

    *dst = 0;				// begin with null termination
    while(bytes>0 && dst_len > 3){
	int add_spaces = 0;

	sprintf(dst,fmt,*bin); // convert the next byte
	dst += 2;
	bin += 1;
	dst_len -= 2;
	bytes--;
	charcount++;			// how many characters
	
	if(flag & HEXBUF_SPACE2) add_spaces = 1;
	if((flag & HEXBUF_SPACE4) && charcount%2==0){
	    *dst++ = ' ';
	    *dst   = '\000';
	    dst_len -= 1;
	}
    }
    return start;			// return the start
}


