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


/** \file tsk_unicode.h
 * Contains the definitions for Unicode-based conversion methods.
 */
#ifndef _TSK_UNICODE_H
#define _TSK_UNICODE_H

// include the autoconf header file
#if HAVE_CONFIG_H
#include "tsk/tsk_config.h"
#endif

#include "tsk_base.h"

#ifdef __cplusplus
extern "C" {
#endif


/** \name Unicode */
//@{
    // basic check to see if a Unicode file has been included
    // in an app that is using this as a library
#ifndef TSK_UNI_REPLACEMENT_CHAR

/**************** UNICODE *******************/
/* ---------------------------------------------------------------------

    Conversions between UTF32, UTF-16, and UTF-8.  Header file.

    Several functions are included here, forming a complete set of
    conversions between the three formats.  UTF-7 is not included
    here, but is handled in a separate source file.

    Each of these routines takes pointers to input buffers and output
    buffers.  The input buffers are const.

    Each routine converts the text between *sourceStart and sourceEnd,
    putting the result into the buffer between *targetStart and
    targetEnd. Note: the end pointers are *after* the last item: e.g.
    *(sourceEnd - 1) is the last item.

    The return result indicates whether the conversion was successful,
    and if not, whether the problem was in the source or target buffers.
    (Only the first encountered problem is indicated.)

    After the conversion, *sourceStart and *targetStart are both
    updated to point to the end of last text successfully converted in
    the respective buffers.

    Input parameters:
	sourceStart - pointer to a pointer to the source buffer.
		The contents of this are modified on return so that
		it points at the next thing to be converted.
	targetStart - similarly, pointer to pointer to the target buffer.
	sourceEnd, targetEnd - respectively pointers to the ends of the
		two buffers, for overflow checking only.

    These conversion functions take a TSKConversionFlags argument. When this
    flag is set to strict, both irregular sequences and isolated surrogates
    will cause an error.  When the flag is set to lenient, both irregular
    sequences and isolated surrogates are converted.

    Whether the flag is strict or lenient, all illegal sequences will cause
    an error return. This includes sequences such as: <F4 90 80 80>, <C0 80>,
    or <A0> in UTF-8, and values above 0x10FFFF in UTF-32. Conformant code
    must check for illegal sequences.

    When the flag is set to lenient, characters over 0x10FFFF are converted
    to the replacement character; otherwise (when the flag is set to strict)
    they constitute an error.

    Output parameters:
	The value "TSKsourceIllegal" is returned from some routines if the input
	sequence is malformed.  When "TSKsourceIllegal" is returned, the source
	value will point to the illegal value that caused the problem. E.g.,
	in UTF-8 when a sequence is malformed, it points to the start of the
	malformed sequence.

    Author: Mark E. Davis, 1994.
    Rev History: Rick McGowan, fixes & updates May 2001.
		 Fixes & updates, Sept 2001.

------------------------------------------------------------------------ */

/* ---------------------------------------------------------------------
    The following 4 definitions are compiler-specific.
    The C standard does not guarantee that wchar_t has at least
    16 bits, so wchar_t is no less portable than unsigned short!
    All should be unsigned values to avoid sign extension during
    bit mask & shift operations.
------------------------------------------------------------------------ */


    typedef unsigned short UTF16;       /* at least 16 bits */
    typedef unsigned char UTF8; /* typically 8 bits */
    typedef unsigned char Boolean;      /* 0 or 1 */


    typedef enum {
        TSKconversionOK,        ///< conversion successful
        TSKsourceExhausted,     ///< partial character in source, but hit end
        TSKtargetExhausted,     ///< insuff. room in target for conversion
        TSKsourceIllegal        ///< source sequence is illegal/malformed
    } TSKConversionResult;

    typedef enum {
        TSKstrictConversion = 0,        ///< Error if invalid surrogate pairs are found
        TSKlenientConversion    ///< Ignore invalid surrogate pairs
    } TSKConversionFlags;

    extern TSKConversionResult tsk_UTF8toUTF16(const UTF8 ** sourceStart,
        const UTF8 * sourceEnd,
        UTF16 ** targetStart, UTF16 * targetEnd, TSKConversionFlags flags);

    extern TSKConversionResult tsk_UTF16toUTF8(TSK_ENDIAN_ENUM,
        const UTF16 ** sourceStart, const UTF16 * sourceEnd,
        UTF8 ** targetStart, UTF8 * targetEnd, TSKConversionFlags flags);

    extern TSKConversionResult
        tsk_UTF16toUTF8_lclorder(const UTF16 ** sourceStart,
        const UTF16 * sourceEnd, UTF8 ** targetStart,
        UTF8 * targetEnd, TSKConversionFlags flags);

    extern TSKConversionResult
        tsk_UTF16WtoUTF8_lclorder(const wchar_t ** sourceStart,
        const wchar_t * sourceEnd, UTF8 ** targetStart,
        UTF8 * targetEnd, TSKConversionFlags flags);

    extern Boolean tsk_isLegalUTF8Sequence(const UTF8 * source,
        const UTF8 * sourceEnd);

    extern void
        tsk_cleanupUTF8(char *source, const char replacement);

    extern void
        tsk_cleanupUTF16(TSK_ENDIAN_ENUM endian, wchar_t *source, size_t source_len, const wchar_t replacement);
#endif
//@}


#ifdef __cplusplus
}
#endif
#endif
