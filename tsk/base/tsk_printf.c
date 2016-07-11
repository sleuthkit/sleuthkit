/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2007-2011 Brian Carrier.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file tsk_printf.c
 * These are printf wrappers that are needed so that we can
 * easily print in both Unix and Windows.  For Unix, the
 * internal UTF-8 representation is kept and a normal printf
 * is performed.  For Windows, the UTF-8 representation is first
 * converted to UTF-16 and then printed
 */

#include "tsk_base_i.h"
#include <stdarg.h>


/** \internal
 * Convert the UTF-8 printf arguments to UTF-16 and fill in the
 * printf types (%s, %d, etc.)
 *
 * @param wbuf wide char string to write result to
 * @param wlen number of characters in wbuf
 * @param msg printf message string
 * @param args Arguments to use when filling in message string
 * @returns 1 on error and 0 on success
 */
#ifdef TSK_WIN32
static int
tsk_printf_conv(WCHAR * wbuf, int wlen, const char *msg, va_list * args)
{
    char *cbuf;
    UTF8 *ptr8;
    UTF16 *ptr16;
    int retVal;
    size_t len, clen;

    wbuf[0] = '\0';

    /* Allocate a UTF-8 buffer and process the printf args */
    clen = wlen * 3;
    if (NULL == (cbuf = (char *) tsk_malloc(clen))) {
        return 1;
    }

#ifdef _MSC_VER
    vsnprintf_s(cbuf, clen - 1, _TRUNCATE, msg, *args);
#else
    vsnprintf(cbuf, clen - 1, msg, *args);
#endif
    len = strlen(cbuf);

    //Convert to UTF-16
    ptr8 = (UTF8 *) cbuf;
    ptr16 = (UTF16 *) wbuf;
    retVal =
        tsk_UTF8toUTF16((const UTF8 **) &ptr8, &ptr8[len + 1], &ptr16,
        &ptr16[wlen], TSKlenientConversion);
    if (retVal != TSKconversionOK) {
        *ptr16 = '\0';
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "tsk_printf_conv: error converting string to UTF-16\n");
    }

    free(cbuf);
    return 0;
}
#endif

/**
 * \ingroup baselib
 * fprintf wrapper function that takes UTF-8 strings as input
 * (on all platforms) and does what is necessary to output
 * strings in the correct encoding (UTF-8 on Unix and
 * UTF-16 on Windows).
 *
 * @param fd File to print to
 * @param msg printf message
 */
void
tsk_fprintf(FILE * fd, const char *msg, ...)
{
    va_list args;
    va_start(args, msg);

#ifdef TSK_WIN32
    {
        WCHAR wbuf[2048];
        tsk_printf_conv(wbuf, 2048, msg, &args);
        fwprintf(fd, _TSK_T("%s"), wbuf);
    }
#else
    vfprintf(fd, msg, args);
#endif
    va_end(args);
}

/**
 * \ingroup baselib
 * printf wrapper function that takes UTF-8 strings as input
 * (on all platforms) and does what is necessary to output
 * strings in the correct encoding (UTF-8 on Unix and
 * UTF-16 on Windows).
 *
 * @param msg printf message
 */
void
tsk_printf(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);

#ifdef TSK_WIN32
    {
        WCHAR wbuf[2048];
        tsk_printf_conv(wbuf, 2048, msg, &args);
        wprintf(_TSK_T("%s"), wbuf);
    }
#else
    vprintf(msg, args);
#endif
    va_end(args);
}

/**
 * \ingroup baselib
 * Prints the string removing control characters.
 *
 * @param fd File to print to
 * @param str string to be printed
 *
 * @returns 0 on success and 1 on error
 */
int
tsk_print_sanitized(FILE * fd, const char *str)
{
    size_t index = 0;
    char *buf = NULL;

    buf = tsk_malloc(strlen(str) + 1);
    if (buf == NULL)
      return 1;

    strcpy(buf, str);

    for (index = 0; index < strlen(buf); index++)
      if (TSK_IS_CNTRL(buf[index]))
        buf[index] = '^';

    tsk_fprintf(fd, "%s", buf);

    free(buf);

    return 0;
}
