/*
 * Copyright 2001-2004 Unicode, Inc.
 * 
 * Disclaimer
 * 
 * This source code is provided as is by Unicode, Inc. No claims are
 * made as to fitness for any particular purpose. No warranties of any
 * kind are expressed or implied. The recipient agrees to determine
 * applicability of information provided. If this file has been
 * purchased on magnetic or optical media from Unicode, Inc., the
 * sole remedy for any claim will be exchange of defective media
 * within 90 days of receipt.
 * 
 * Limitations on Rights to Redistribute This Code
 * 
 * Unicode, Inc. hereby grants the right to freely use the information
 * supplied in this file in the creation of products supporting the
 * Unicode Standard, and to make copies of this file in any form
 * for internal or external distribution as long as this notice
 * remains attached.
 */

/* ---------------------------------------------------------------------

    Conversions between UTF32, UTF-16, and UTF-8. Source code file.
    Author: Mark E. Davis, 1994.
    Rev History: Rick McGowan, fixes & updates May 2001.
    Sept 2001: fixed const & error conditions per
	mods suggested by S. Parent & A. Lillich.
    June 2002: Tim Dodd added detection and handling of incomplete
	source sequences, enhanced error detection, added casts
	to eliminate compiler warnings.
    July 2003: slight mods to back out aggressive FFFE detection.
    Jan 2004: updated switches in from-UTF8 conversions.
    Oct 2004: updated to use TSK_UNI_MAX_LEGAL_UTF32 in UTF-32 conversions.

    See the header file "ConvertUTF.h" for complete documentation.

------------------------------------------------------------------------ */

/** \file tsk_unicode.c
 * A local copy of the Unicode conversion routines from unicode.org.
 */

#include "tsk_base_i.h"

/* Some fundamental constants */
typedef unsigned long UTF32;    /* at least 32 bits */
#define TSK_UNI_REPLACEMENT_CHAR (UTF32)0x0000FFFD
#define TSK_UNI_MAX_BMP (UTF32)0x0000FFFF
#define TSK_UNI_MAX_UTF16 (UTF32)0x0010FFFF
#define TSK_UNI_MAX_UTF32 (UTF32)0x7FFFFFFF
#define TSK_UNI_MAX_LEGAL_UTF32 (UTF32)0x0010FFFF


static const int halfShift = 10;        /* used for shifting by 10 bits */

static const UTF32 halfBase = 0x0010000UL;
static const UTF32 halfMask = 0x3FFUL;

#define UNI_SUR_HIGH_START  (UTF32)0xD800
#define UNI_SUR_HIGH_END    (UTF32)0xDBFF
#define UNI_SUR_LOW_START   (UTF32)0xDC00
#define UNI_SUR_LOW_END     (UTF32)0xDFFF
#define false	   0
#define true	    1

/* --------------------------------------------------------------------- */


/* --------------------------------------------------------------------- */

/*
 * Index into the table below with the first byte of a UTF-8 sequence to
 * get the number of trailing bytes that are supposed to follow it.
 * Note that *legal* UTF-8 values can't have 4 or 5-bytes. The table is
 * left as-is for anyone who may want to do such conversion, which was
 * allowed in earlier algorithms.
 */
static const char trailingBytesForUTF8[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3,
    4, 4, 4, 4, 5, 5, 5, 5
};

/*
 * Magic values subtracted from a buffer value during UTF8 conversion.
 * This table contains as many values as there might be trailing bytes
 * in a UTF-8 sequence.
 */
static const UTF32 offsetsFromUTF8[6] =
    { 0x00000000UL, 0x00003080UL, 0x000E2080UL,
    0x03C82080UL, 0xFA082080UL, 0x82082080UL
};


/*
 * Once the bits are split out into bytes of UTF-8, this is a mask OR-ed
 * into the first byte, depending on how many bytes follow.  There are
 * as many entries in this table as there are UTF-8 sequence types.
 * (I.e., one byte sequence, two byte... etc.). Remember that sequencs
 * for *legal* UTF-8 will be 4 or fewer bytes total.
 */
static const UTF8 firstByteMark[7] =
    { 0x00, 0x00, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC };


/* --------------------------------------------------------------------- */

/* The interface converts a whole buffer to avoid function-call overhead.
 * Constants have been gathered. Loops & conditionals have been removed as
 * much as possible for efficiency, in favor of drop-through switches.
 * (See "Note A" at the bottom of the file for equivalent code.)
 * If your compiler supports it, the "isLegalUTF8" call can be turned
 * into an inline function.
 */

/* --------------------------------------------------------------------- */


/** 
 * \ingroup baselib
 * Convert a UTF-16 string to UTF-8.  
 * @param endian Endian ordering flag of UTF-16 text
 * @param sourceStart Pointer to pointer to start of UTF-16 string.  Will be updated to last char processed.
 * @param sourceEnd Pointer to one entry past end of UTF-16 string
 * @param targetStart Pointer to pointer to place where UTF-8 string should be written.  Will be updated to next place to write to. 
 * @param targetEnd Pointer to end of UTF-8 buffer
 * @param flags Flags used during conversion 
 * @returns error code
 */
TSKConversionResult
tsk_UTF16toUTF8(TSK_ENDIAN_ENUM endian, const UTF16 ** sourceStart,
    const UTF16 * sourceEnd, UTF8 ** targetStart,
    UTF8 * targetEnd, TSKConversionFlags flags)
{
    TSKConversionResult result = TSKconversionOK;
    const UTF16 *source = *sourceStart;
    UTF8 *target = *targetStart;
    while (source < sourceEnd) {
        UTF32 ch;
        unsigned short bytesToWrite = 0;
        const UTF32 byteMask = 0xBF;
        const UTF32 byteMark = 0x80;
        const UTF16 *oldSource = source;        /* In case we have to back up because of target overflow. */
        ch = tsk_getu16(endian, (uint8_t *) source);
        source++;

        /* If we have a surrogate pair, convert to UTF32 first. */
        if (ch >= UNI_SUR_HIGH_START && ch <= UNI_SUR_HIGH_END) {
            /* If the 16 bits following the high surrogate are in the source buffer... */
            if (source < sourceEnd) {
                UTF32 ch2 = tsk_getu16(endian, (uint8_t *) source);
                ++source;

                /* If it's a low surrogate, convert to UTF32. */
                if (ch2 >= UNI_SUR_LOW_START && ch2 <= UNI_SUR_LOW_END) {
                    ch = ((ch - UNI_SUR_HIGH_START) << halfShift)
                        + (ch2 - UNI_SUR_LOW_START) + halfBase;
                }
                else if (flags == TSKstrictConversion) {        /* it's an unpaired high surrogate */
                    result = TSKsourceIllegal;
                    break;
                }
                // replace with another character
                else {
                    ch = '^';
                }
            }
            else {              /* We don't have the 16 bits following the high surrogate. */
                --source;       /* return to the high surrogate */
                result = TSKsourceExhausted;
                break;
            }
        }
        /* UTF-16 surrogate values are illegal in UTF-32 */
        else if (ch >= UNI_SUR_LOW_START && ch <= UNI_SUR_LOW_END) {
            if (flags == TSKstrictConversion) {
                --source;       /* return to the illegal value itself */
                result = TSKsourceIllegal;
                break;
            }
            // replace with another character
            else {
                ch = '^';
            }
        }

        /* Figure out how many bytes the result will require */
        if (ch < (UTF32) 0x80) {
            bytesToWrite = 1;
        }
        else if (ch < (UTF32) 0x800) {
            bytesToWrite = 2;
        }
        else if (ch < (UTF32) 0x10000) {
            bytesToWrite = 3;
        }
        else if (ch < (UTF32) 0x110000) {
            bytesToWrite = 4;
        }
        else {
            bytesToWrite = 3;
            ch = TSK_UNI_REPLACEMENT_CHAR;
        }

        target += bytesToWrite;
        if (target > targetEnd) {
            source = oldSource; /* Back up source pointer! */
            target -= bytesToWrite;
            result = TSKtargetExhausted;
            break;
        }
        switch (bytesToWrite) { /* note: everything falls through. */
        case 4:
            *--target = (UTF8) ((ch | byteMark) & byteMask);
            ch >>= 6;
        case 3:
            *--target = (UTF8) ((ch | byteMark) & byteMask);
            ch >>= 6;
        case 2:
            *--target = (UTF8) ((ch | byteMark) & byteMask);
            ch >>= 6;
        case 1:
            *--target = (UTF8) (ch | firstByteMark[bytesToWrite]);
        }
        target += bytesToWrite;
    }
    *sourceStart = source;
    *targetStart = target;
    return result;
}


/** 
* \ingroup baselib
* Convert a UTF-16 string in local endian ordering to UTF-8.  
* @param sourceStart Pointer to pointer to start of UTF-16 string.  Will be updated to last char processed.
* @param sourceEnd Pointer to one entry past end of UTF-16 string
* @param targetStart Pointer to pointer to place where UTF-8 string should be written.  Will be updated to next place to write to. 
* @param targetEnd Pointer to end of UTF-8 buffer
* @param flags Flags used during conversion 
* @returns error code
*/
TSKConversionResult
tsk_UTF16toUTF8_lclorder(const UTF16 ** sourceStart,
    const UTF16 * sourceEnd, UTF8 ** targetStart,
    UTF8 * targetEnd, TSKConversionFlags flags)
{
    TSKConversionResult result = TSKconversionOK;
    const UTF16 *source = *sourceStart;
    UTF8 *target = *targetStart;
    while (source < sourceEnd) {
        UTF32 ch;
        unsigned short bytesToWrite = 0;
        const UTF32 byteMask = 0xBF;
        const UTF32 byteMark = 0x80;
        const UTF16 *oldSource = source;        /* In case we have to back up because of target overflow. */
        ch = *source++;

        /* If we have a surrogate pair, convert to UTF32 first. */
        if (ch >= UNI_SUR_HIGH_START && ch <= UNI_SUR_HIGH_END) {
            /* If the 16 bits following the high surrogate are in the source buffer... */
            if (source < sourceEnd) {
                UTF32 ch2 = *source;
                source++;
                /* If it's a low surrogate, convert to UTF32. */
                if (ch2 >= UNI_SUR_LOW_START && ch2 <= UNI_SUR_LOW_END) {
                    ch = ((ch - UNI_SUR_HIGH_START) << halfShift)
                        + (ch2 - UNI_SUR_LOW_START) + halfBase;
                }
                else if (flags == TSKstrictConversion) {        /* it's an unpaired high surrogate */
                    result = TSKsourceIllegal;
                    break;
                }
                // replace with another character
                else {
                    ch = '^';
                }
            }
            else {              /* We don't have the 16 bits following the high surrogate. */
                --source;       /* return to the high surrogate */
                result = TSKsourceExhausted;
                break;
            }
        }
        /* UTF-16 surrogate values are illegal in UTF-32 */
        else if (ch >= UNI_SUR_LOW_START && ch <= UNI_SUR_LOW_END) {
            if (flags == TSKstrictConversion) {
                --source;       /* return to the illegal value itself */
                result = TSKsourceIllegal;
                break;
            }
            // replace with another character
            else {
                ch = '^';
            }
        }

        /* Figure out how many bytes the result will require */
        if (ch < (UTF32) 0x80) {
            bytesToWrite = 1;
        }
        else if (ch < (UTF32) 0x800) {
            bytesToWrite = 2;
        }
        else if (ch < (UTF32) 0x10000) {
            bytesToWrite = 3;
        }
        else if (ch < (UTF32) 0x110000) {
            bytesToWrite = 4;
        }
        else {
            bytesToWrite = 3;
            ch = TSK_UNI_REPLACEMENT_CHAR;
        }

        target += bytesToWrite;
        if (target > targetEnd) {
            source = oldSource; /* Back up source pointer! */
            target -= bytesToWrite;
            result = TSKtargetExhausted;
            break;
        }
        switch (bytesToWrite) { /* note: everything falls through. */
        case 4:
            *--target = (UTF8) ((ch | byteMark) & byteMask);
            ch >>= 6;
        case 3:
            *--target = (UTF8) ((ch | byteMark) & byteMask);
            ch >>= 6;
        case 2:
            *--target = (UTF8) ((ch | byteMark) & byteMask);
            ch >>= 6;
        case 1:
            *--target = (UTF8) (ch | firstByteMark[bytesToWrite]);
        }
        target += bytesToWrite;
    }
    *sourceStart = source;
    *targetStart = target;
    return result;
}

TSKConversionResult
tsk_UTF16WtoUTF8_lclorder(const wchar_t ** sourceStart,
    const wchar_t * sourceEnd, UTF8 ** targetStart,
    UTF8 * targetEnd, TSKConversionFlags flags)
{
    TSKConversionResult result = TSKconversionOK;
    const wchar_t *source = *sourceStart;
    UTF8 *target = *targetStart;
    while (source < sourceEnd) {
        UTF32 ch;
        unsigned short bytesToWrite = 0;
        const UTF32 byteMask = 0xBF;
        const UTF32 byteMark = 0x80;
        const wchar_t *oldSource = source;        /* In case we have to back up because of target overflow. */
        ch = *source++;

        /* If we have a surrogate pair, convert to UTF32 first. */
        if (ch >= UNI_SUR_HIGH_START && ch <= UNI_SUR_HIGH_END) {
            /* If the 16 bits following the high surrogate are in the source buffer... */
            if (source < sourceEnd) {
                UTF32 ch2 = *source;
                source++;
                /* If it's a low surrogate, convert to UTF32. */
                if (ch2 >= UNI_SUR_LOW_START && ch2 <= UNI_SUR_LOW_END) {
                    ch = ((ch - UNI_SUR_HIGH_START) << halfShift)
                        + (ch2 - UNI_SUR_LOW_START) + halfBase;
                }
                else if (flags == TSKstrictConversion) {        /* it's an unpaired high surrogate */
                    result = TSKsourceIllegal;
                    break;
                }
                // replace with another character
                else {
                    ch = '^';
                }
            }
            else {              /* We don't have the 16 bits following the high surrogate. */
                --source;       /* return to the high surrogate */
                result = TSKsourceExhausted;
                break;
            }
        }
        /* UTF-16 surrogate values are illegal in UTF-32 */
        else if (ch >= UNI_SUR_LOW_START && ch <= UNI_SUR_LOW_END) {
            if (flags == TSKstrictConversion) {
                --source;       /* return to the illegal value itself */
                result = TSKsourceIllegal;
                break;
            }
            // replace with another character
            else {
                ch = '^';
            }
        }

        /* Figure out how many bytes the result will require */
        if (ch < (UTF32) 0x80) {
            bytesToWrite = 1;
        }
        else if (ch < (UTF32) 0x800) {
            bytesToWrite = 2;
        }
        else if (ch < (UTF32) 0x10000) {
            bytesToWrite = 3;
        }
        else if (ch < (UTF32) 0x110000) {
            bytesToWrite = 4;
        }
        else {
            bytesToWrite = 3;
            ch = TSK_UNI_REPLACEMENT_CHAR;
        }

        target += bytesToWrite;
        if (target > targetEnd) {
            source = oldSource; /* Back up source pointer! */
            target -= bytesToWrite;
            result = TSKtargetExhausted;
            break;
        }
        switch (bytesToWrite) { /* note: everything falls through. */
        case 4:
            *--target = (UTF8) ((ch | byteMark) & byteMask);
            ch >>= 6;
        case 3:
            *--target = (UTF8) ((ch | byteMark) & byteMask);
            ch >>= 6;
        case 2:
            *--target = (UTF8) ((ch | byteMark) & byteMask);
            ch >>= 6;
        case 1:
            *--target = (UTF8) (ch | firstByteMark[bytesToWrite]);
        }
        target += bytesToWrite;
    }
    *sourceStart = source;
    *targetStart = target;
    return result;
}

/* --------------------------------------------------------------------- */

/*
 * Utility routine to tell whether a sequence of bytes is legal UTF-8.
 * This must be called with the length pre-determined by the first byte.
 * If not calling this from ConvertUTF8to*, then the length can be set by:
 *  length = trailingBytesForUTF8[*source]+1;
 * and the sequence is illegal right away if there aren't that many bytes
 * available.
 * If presented with a length > 4, this returns false.  The Unicode
 * definition of UTF-8 goes up to 4-byte sequences.
 */

static Boolean
isLegalUTF8(const UTF8 * source, int length)
{
    UTF8 a;
    const UTF8 *srcptr = source + length;
    switch (length) {
    default:
        return false;
        /* Everything else falls through when "true"... */
    case 4:
        if ((a = (*--srcptr)) < 0x80 || a > 0xBF)
            return false;
    case 3:
        if ((a = (*--srcptr)) < 0x80 || a > 0xBF)
            return false;
    case 2:
        if ((a = (*--srcptr)) < 0x80 || a > 0xBF)
            return false;

        switch (*source) {
            /* no fall-through in this inner switch */
        case 0xE0:
            if (a < 0xA0)
                return false;
            break;
        case 0xED:
            if (a > 0x9F)
                return false;
            break;
        case 0xF0:
            if (a < 0x90)
                return false;
            break;
        case 0xF4:
            if (a > 0x8F)
                return false;
            break;
        default:
            if (a < 0x80)
                return false;
        }

    case 1:
        if (*source >= 0x80 && *source < 0xC2)
            return false;
    }
    if (*source > 0xF4)
        return false;
    return true;
}

/* --------------------------------------------------------------------- */

/*
 * Exported function to return whether a UTF-8 sequence is legal or not.
 * This is not used here; it's just exported.
 */
Boolean
tsk_isLegalUTF8Sequence(const UTF8 * source, const UTF8 * sourceEnd)
{
    int length = trailingBytesForUTF8[*source] + 1;
    if (source + length > sourceEnd) {
        return false;
    }
    return isLegalUTF8(source, length);
}

/**
 * Cleans up the passed in string to replace invalid
 * UTF-8 values with the passed in character.
 * @param source String to be cleaned up
 * @param replacement Character to insert into source as needed.
 */
void
tsk_cleanupUTF8(char *source, const char replacement)
{
    size_t total_len = strlen(source);
    size_t cur_idx = 0;

    while (cur_idx < total_len) {
        int length = trailingBytesForUTF8[(UTF8) source[cur_idx]] + 1;
        if (cur_idx + length > total_len) {
            while (cur_idx < total_len) {
                source[cur_idx] = replacement;
                cur_idx++;
            }
            break;
        }
        if (isLegalUTF8((UTF8 *) & source[cur_idx], length) == false) {
            int i;
            for (i = 0; i < length; i++) {
                source[cur_idx + i] = replacement;
            }
        }
        cur_idx += length;
    }
}

/* --------------------------------------------------------------------- */



/** 
* \ingroup baselib
* Convert a UTF-8 string to UTF-16 (in local endian ordering).  
* @param sourceStart Pointer to pointer to start of UTF-8 string.  Will be updated to last char processed.
* @param sourceEnd Pointer to one entry past end of UTF-8 string
* @param targetStart Pointer to pointer to place where UTF-16 string should be written.  Will be updated to next place to write to. 
* @param targetEnd Pointer to end of UTF-16 buffer
* @param flags Flags used during conversion 
* @returns error code
*/
TSKConversionResult
tsk_UTF8toUTF16(const UTF8 ** sourceStart,
    const UTF8 * sourceEnd, UTF16 ** targetStart,
    UTF16 * targetEnd, TSKConversionFlags flags)
{
    TSKConversionResult result = TSKconversionOK;
    const UTF8 *source = *sourceStart;
    UTF16 *target = *targetStart;
    while (source < sourceEnd) {
        UTF32 ch = 0;
        unsigned short extraBytesToRead = trailingBytesForUTF8[*source];
        if (source + extraBytesToRead >= sourceEnd) {
            result = TSKsourceExhausted;
            break;
        }
        /* Do this check whether lenient or strict */
        if (!isLegalUTF8(source, extraBytesToRead + 1)) {
            result = TSKsourceIllegal;
            break;
        }
        /*
         * The cases all fall through. See "Note A" below.
         */
        switch (extraBytesToRead) {
        case 5:
            ch += *source++;
            ch <<= 6;           /* remember, illegal UTF-8 */
        case 4:
            ch += *source++;
            ch <<= 6;           /* remember, illegal UTF-8 */
        case 3:
            ch += *source++;
            ch <<= 6;
        case 2:
            ch += *source++;
            ch <<= 6;
        case 1:
            ch += *source++;
            ch <<= 6;
        case 0:
            ch += *source++;
        }
        ch -= offsetsFromUTF8[extraBytesToRead];

        if (target >= targetEnd) {
            source -= (extraBytesToRead + 1);   /* Back up source pointer! */
            result = TSKtargetExhausted;
            break;
        }
        if (ch <= TSK_UNI_MAX_BMP) {    /* Target is a character <= 0xFFFF */
            /* UTF-16 surrogate values are illegal in UTF-32 */
            if (ch >= UNI_SUR_HIGH_START && ch <= UNI_SUR_LOW_END) {
                if (flags == TSKstrictConversion) {
                    source -= (extraBytesToRead + 1);   /* return to the illegal value itself */
                    result = TSKsourceIllegal;
                    break;
                }
                else {
                    *target++ = TSK_UNI_REPLACEMENT_CHAR;
                }
            }
            else {
                *target++ = (UTF16) ch; /* normal case */
            }
        }
        else if (ch > TSK_UNI_MAX_UTF16) {
            if (flags == TSKstrictConversion) {
                result = TSKsourceIllegal;
                source -= (extraBytesToRead + 1);       /* return to the start */
                break;          /* Bail out; shouldn't continue */
            }
            else {
                *target++ = TSK_UNI_REPLACEMENT_CHAR;
            }
        }
        else {
            /* target is a character in range 0xFFFF - 0x10FFFF. */
            if (target + 1 >= targetEnd) {
                source -= (extraBytesToRead + 1);       /* Back up source pointer! */
                result = TSKtargetExhausted;
                break;
            }
            ch -= halfBase;
            *target++ = (UTF16) ((ch >> halfShift) + UNI_SUR_HIGH_START);
            *target++ = (UTF16) ((ch & halfMask) + UNI_SUR_LOW_START);
        }
    }
    *sourceStart = source;
    *targetStart = target;
    return result;
}

