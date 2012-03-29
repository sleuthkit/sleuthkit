/*
 * See:
 * http://www.ietf.org/rfc/rfc3987.txt
 */


#include "unicode_escape.h"

#include <stdio.h>
#include <iostream>

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <stdint.h>

#define IS_IN_RANGE(c, f, l)    (((c) >= (f)) && ((c) <= (l)))

inline std::string esc(unsigned char ch)
{
    char buf[10];
    snprintf(buf,sizeof(buf),"\\x%02X",ch);
    return std::string(buf);
}

/** returns true if this is a UTF8 continuation character */
inline bool utf8cont(unsigned char ch)
{
    return ((ch&0x80)==0x80) &&  ((ch & 0x40)==0);
}

/**
 * validateOrEscapeUTF8
 * Input: UTF8 string (possibly corrupt)
 * Output: UTF8 string with corruptions escaped in \xFF notation, where FF is a hex character.
 */

int count=0;
std::string validateOrEscapeUTF8(std::string input)
{
    std::string output;
    std::string::size_type i = 0;
    while( i < input.length() ) {
	unsigned char ch = input.at(i);
	// utf8 1 byte
	if((ch & 0x80)==0){
	    if(ch=='\\'){			// escape the escape character
		output += "\\\\";
		i++;
		continue;
	    }

	    if( ch>=' ' ){	// printable
		output += ch;
		i++;
		continue;
	    }

	    output += esc(ch);
	    i++;
	    continue;
	}


	// utf8 2 bytes
	if((((ch & 0xc0) == 0xc0) && ((ch & 0x20)==0))
	   && (i+1 < input.length())
	   && utf8cont(input.at(i+1))){
	    output += input.at(i++);	// byte1
	    output += input.at(i++);	// byte2
	    continue;
	}
		
	// utf8 3 bytes
	if((((ch & 0xe0) == 0xe0) && ((ch & 0x10)==0))
	   && (i+2 < input.length())
	   && utf8cont(input.at(i+1))
	   && utf8cont(input.at(i+2))){
	    wchar_t unichar = ((input.at(i) & 0x1f) << 12) | ((input.at(i+1) & 0x3f) << 6) | ((input.at(i+2) & 0x3f));
	    
	    if(unichar==0xfffe || unichar==0xffff){ // invalid code points
		output += esc(input.at(i++));
		output += esc(input.at(i++));
		continue;
	    }

	    output += input.at(i++);	// byte1
	    output += input.at(i++);	// byte2
	    output += input.at(i++);	// byte3
	    continue;
	}
	    
	// utf8 4 bytes
	if((((ch & 0xf0) == 0xf0) && ((ch & 0x08)==0))
	   && (i+2 < input.length())
	   && utf8cont(input.at(i+1))
	   && utf8cont(input.at(i+2))
	   && utf8cont(input.at(i+3))){
	    output += input.at(i++);	// byte1
	    output += input.at(i++);	// byte2
	    output += input.at(i++);	// byte3
	    output += input.at(i++);	// byte4
	    continue;
	}
	// Just escape it
	output += esc(input.at(i++));
    }
    return output;
}
