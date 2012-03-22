/*
 * See:
 * http://stackoverflow.com/questions/2969843/validate-unicode-string-and-escape-if-unicode-is-invalid-c-c
 * http://www.ietf.org/rfc/rfc3987.txt
 */


#include "unicode_escape.h"
#include "tsk3/tsk_tools_i.h"

#include <stdio.h>
#include <iostream>

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#ifdef __HAVE_STDINT_H
#include <stdint.h>
#endif




#define IS_IN_RANGE(c, f, l)    (((c) >= (f)) && ((c) <= (l)))

int UTF8BufferToUTF32Buffer(const char *Data, int DataLen, uint32_t *Buffer, int BufLen, int *Eaten)
{
    if( Eaten )
    {
        *Eaten = 0;
    }

    int Result = 0;

    unsigned char b, b2;
    unsigned char *ptr = (unsigned char*) Data;
    uint32_t uc;

    int i = 0;
    int seqlen;

    while( i < DataLen )
    {
        if( (Buffer) && (!BufLen) )
            break;

        b = ptr[i];

        if( (b & 0x80) == 0 )
        {
            uc = (uint32_t)(b & 0x7F);
            seqlen = 1;
        }
        else if( (b & 0xE0) == 0xC0 )
        {
            uc = (uint32_t)(b & 0x1F);
            seqlen = 2;
        }
        else if( (b & 0xF0) == 0xE0 )
        {
            uc = (uint32_t)(b & 0x0F);
            seqlen = 3;
        }
        else if( (b & 0xF8) == 0xF0 )
        {
            uc = (uint32_t)(b & 0x07);
            seqlen = 4;
        }
        else
        {
            uc = 0;
            return -1;
        }

        if( (i+seqlen) > DataLen )
        {
            return -1;
        }

        for(int j = 1; j < seqlen; ++j)
        {
            b = ptr[i+j];

            if( (b & 0xC0) != 0x80 )
            {
                return -1;
            }
        }

        switch( seqlen )
        {
            case 2:
            {
                b = ptr[i];

                if( !IS_IN_RANGE(b, 0xC2, 0xDF) )
                {
                    return -1;
                }

                break;
            }

            case 3:
            {
                b = ptr[i];
                b2 = ptr[i+1];

                if( ((b == 0xE0) && !IS_IN_RANGE(b2, 0xA0, 0xBF)) ||
                    ((b == 0xED) && !IS_IN_RANGE(b2, 0x80, 0x9F)) ||
                    (!IS_IN_RANGE(b, 0xE1, 0xEC) && !IS_IN_RANGE(b, 0xEE, 0xEF)) )
                {
                    return -1;
                }

                break;
            }

            case 4:
            {
                b = ptr[i];
                b2 = ptr[i+1];

                if( ((b == 0xF0) && !IS_IN_RANGE(b2, 0x90, 0xBF)) ||
                    ((b == 0xF4) && !IS_IN_RANGE(b2, 0x80, 0x8F)) ||
                    !IS_IN_RANGE(b, 0xF1, 0xF3) )
                {
                    return -1;
                }

                break;
            }
        }

        for(int j = 1; j < seqlen; ++j)
        {
            uc = ((uc << 6) | (uint32_t)(ptr[i+j] & 0x3F));
        }

        if( Buffer )
        {
            *Buffer++ = uc;
            --BufLen;
        }

        ++Result;
        i += seqlen;
    }

    if( Eaten )
    {
        *Eaten = i;
    }

    return Result;
}

int count=0;
std::string validateOrEscapeUTF8(std::string input)
{
    std::string output;
    std::string::size_type i = 0;
    while( i < input.length() ) {
	unsigned char ch = input[i];
	if(ch=='\\'){
	    output += "\\\\";
	    i++;
	    continue;
	}

        if( ch>=' ' && ch<127 ){
	    output += ch;
	    i++;
	    continue;
	}

	/* Unicode? */
	int eaten=1;
	uint32_t unich=0;
	if ((ch>=' ') && (ch!=127) && (ch!=0xe5) && (ch!=254) && (ch!=255) &&
	    (UTF8BufferToUTF32Buffer(input.c_str()+i, input.length()-i, &unich, 1, &eaten) == 1 )) {
	    if(unich!=0xff && unich!=0xffff){
		output += input.substr(i,eaten);
		i += eaten;
		continue;
	    }
        }
	if(eaten<1) eaten=1;		// clear at least one character
	while(eaten>0){
	    char buf[10];
	    snprintf(buf,sizeof(buf),"\\x%02X",(unsigned char)input[i]);
	    output += buf;
	    i++;
	    eaten--;
	}
    }
    return output;
}
