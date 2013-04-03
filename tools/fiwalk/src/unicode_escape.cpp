/**
 * unicode_escape.cpp:
 * Escape unicode that is not valid.
 * 
 * References:
 * http://www.ietf.org/rfc/rfc3987.txt
 * http://en.wikipedia.org/wiki/UTF-8
 *
 * @author Simson Garfinkel
 *
 *
 * The software provided here is released by the Naval Postgraduate
 * School, an agency of the U.S. Department of Navy.  The software
 * bears no warranty, either expressed or implied. NPS does not assume
 * legal liability nor responsibility for a User's use of the software
 * or the results of such use.
 *
 * Please note that within the United States, copyright protection,
 * under Section 105 of the United States Code, Title 17, is not
 * available for any work of the United States Government and/or for
 * any works created by United States Government employees. User
 * acknowledges that this software contains work which was created by
 * NPS government employees and is therefore in the public domain and
 * not subject to copyright.
 */

#include "tsk/tsk_tools_i.h"
#include "unicode_escape.h"

#include <stdio.h>
#include <iostream>

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#define IS_IN_RANGE(c, f, l)    (((c) >= (f)) && ((c) <= (l)))


std::string hexesc(unsigned char ch)
{
    char buf[10];
    snprintf(buf,sizeof(buf),"\\x%02X",ch);
    return std::string(buf);
}

/** returns true if this is a UTF8 continuation character */
bool utf8cont(unsigned char ch)
{
    return ((ch&0x80)==0x80) &&  ((ch & 0x40)==0);
}

/**
 * After a UTF-8 sequence is decided, this function is called
 * to determine if the character is invalid. The UTF-8 spec now
 * says that if a UTF-8 decoding produces an invalid character, or
 * a surrogate, it is not valid. (There were some nasty security
 * vulnerabilities that were exploited before this came out.)
 * So we do a lot of checks here.
 */
bool invalid_utf8unichar(uint32_t unichar)
{
    // Check for invalid characters in the bmp
    switch(unichar){
    case 0xfffe: return true;		// reversed BOM
    case 0xffff: return true;
    default:
	break;
    }
    if(unichar >= 0xd800 && unichar <=0xdfff) return true; // high and low surrogates
    if(unichar < 0x10000) return false;	// looks like it is in the BMP

    // check some regions outside the bmp

    // Plane 1:
    if(unichar > 0x13fff && unichar < 0x16000) return true;
    if(unichar > 0x16fff && unichar < 0x1b000) return true;
    if(unichar > 0x1bfff && unichar < 0x1d000) return true;
	
    // Plane 2
    if(unichar > 0x2bfff && unichar < 0x2f000) return true;
    
    // Planes 3--13 are unassigned
    if(unichar >= 0x30000 && unichar < 0xdffff) return true;

    // Above Plane 16 is invalid
    if(unichar > 0x10FFFF) return true;	// above plane 16?
    
    return false;			// must be valid
}

/**
 * validateOrEscapeUTF8
 * Input: UTF8 string (possibly corrupt)
 * Output: UTF8 string with corruptions escaped in \xFF notation, where FF is a hex character.
 * Note that we cannot use wchar_t because it is 16-bits on Windows and 32-bits on Unix.
 */

int count=0;
std::string validateOrEscapeUTF8(std::string input)
{
    std::string output;
    std::string::size_type i = 0;
    while( i < input.length() ) {
	uint8_t ch = (uint8_t)input.at(i);
	// utf8 1 byte prefix (0xxx xxxx)
	if((ch & 0x80)==0x00){			// 00 .. 0x7f
	    if(ch=='\\'){			// escape the escape character
		output += hexesc(ch);
		i++;
		continue;
	    }

	    if( ch < ' '){		// not printable
		output += hexesc(ch);
		i++;
		continue;
	    }

	    output += ch;		// printable
	    i++;
	    continue;
	}

	// utf8 2 bytes  (110x xxxx) prefix
	if(((ch & 0xe0)==0xc0)  // 2-byte prefix
	   && (i+1 < input.length())
	   && utf8cont((uint8_t)input.at(i+1))){
	    wchar_t unichar = (((uint8_t)input.at(i) & 0x1f) << 6) | (((uint8_t)input.at(i+1) & 0x3f));

	    // check for invalid code point for this encoding
	    if(invalid_utf8unichar(unichar)
	       || ((uint8_t)input.at(i)==0xc0)
	       || (unichar <= 0x7f)){ 
		output += hexesc((uint8_t)input.at(i++));
		output += hexesc((uint8_t)input.at(i++));
		continue;
	    }
			      
	    output += (uint8_t)input.at(i++);	// byte1
	    output += (uint8_t)input.at(i++);	// byte2
	    continue;
	}
		
	// utf8 3 bytes (1110 xxxx prefix)
	if(((ch & 0xf0) == 0xe0)
	   && (i+2 < input.length())
	   && utf8cont((uint8_t)input.at(i+1))
	   && utf8cont((uint8_t)input.at(i+2))){
	    uint32_t unichar = (((uint8_t)input.at(i) & 0x0f) << 12)
		| (((uint8_t)input.at(i+1) & 0x3f) << 6)
		| (((uint8_t)input.at(i+2) & 0x3f));
	    
	    if(invalid_utf8unichar(unichar) || unichar<=0x7ff){ // invalid code points
		output += hexesc((uint8_t)input.at(i++));
		output += hexesc((uint8_t)input.at(i++));
		continue;
	    }

	    output += (uint8_t)input.at(i++);	// byte1
	    output += (uint8_t)input.at(i++);	// byte2
	    output += (uint8_t)input.at(i++);	// byte3
	    continue;
	}
	    
	// utf8 4 bytes (1111 0xxx prefix)
	if((( ch & 0xf8) == 0xf0)
	   && (i+3 < input.length())
	   && utf8cont((uint8_t)input.at(i+1))
	   && utf8cont((uint8_t)input.at(i+2))
	   && utf8cont((uint8_t)input.at(i+3))){
	    uint32_t unichar =( (((uint8_t)input.at(i) & 0x07) << 18)
				|(((uint8_t)input.at(i+1) & 0x3f) << 12)
				|(((uint8_t)input.at(i+2) & 0x3f) <<  6)
				|(((uint8_t)input.at(i+3) & 0x3f)));

	    if(invalid_utf8unichar(unichar)){
		output += hexesc((uint8_t)input.at(i++)); // byte 1
		output += hexesc((uint8_t)input.at(i++)); // byte 2
		output += hexesc((uint8_t)input.at(i++)); // byte 3
		output += hexesc((uint8_t)input.at(i++)); // byte 4
		continue;
	    }
	    output += (uint8_t)input.at(i++);	// byte1
	    output += (uint8_t)input.at(i++);	// byte2
	    output += (uint8_t)input.at(i++);	// byte3
	    output += (uint8_t)input.at(i++);	// byte4
	    continue;
	}

	// Just escape it
	output += hexesc((uint8_t)input.at(i++));
    }
    return output;
}

#ifdef STANDALONE

/* Only needed for testing */
#include "utf8.h"

int main(int argc,char **argv)
{
    /* Try all 4-byte sequences */
    for(uint32_t i=0;i<=0xFFFFFFFF;i++){
	std::string ugly((char *)&i,4);
	std::string res = validateOrEscapeUTF8(ugly);
	std::wstring utf16;
	/* Now check to make sure it is valid UTF8 */
	try {
	    utf8::utf8to16(res.begin(),res.end(),std::back_inserter(utf16));
	} catch(utf8::exception){
	    printf("utf8 error i=%d  hex sequence: ",i);
	    for(size_t j=0;j<ugly.size();j++){
		printf("%02x ",(unsigned char)ugly[j]);
	    }
	    printf(" encoded as: ");
	    for(size_t j=0;j<res.size();j++){
		printf("%02x ",(unsigned char)res[j]);
	    }
	    printf("\n");
	} catch(std::exception){
	    std::cout << "other exception on i=" << i << "\n";
	}
	if(i%1000000==0) std::cout << "i=" << i << "\n";
    }
    std::cout << "done\n";
    exit(1);

    /* Generic fuzzing. Try random attempts */
    

    std::string line;
    while(getline(std::cin,line)){
	std::cout << validateOrEscapeUTF8(line) << "\n";
    }
	
}
#endif
