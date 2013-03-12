/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2011 Brian Carrier.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

#include "tsk_base_i.h"
#include "tsk_base.h"

/**
 * \file tsk_error.c
 * Contains the error handling code and variables.
 */


/* Global variables that fit here as well as anywhere */
char *progname = "unknown";
int tsk_verbose = 0;


/* Error messages */
static const char *tsk_err_aux_str[TSK_ERR_IMG_MAX] = {
    "Insufficient memory",
    "TSK Error"
};

/* imagetools specific error strings */
static const char *tsk_err_img_str[TSK_ERR_IMG_MAX] = {
    "Missing image file names", // 0
    "Invalid image offset",
    "Cannot determine image type",
    "Unsupported image type",
    "Error opening image file",
    "Error stat(ing) image file",       // 5
    "Error seeking in image file",
    "Error reading image file",
    "Read offset too large for image file",
    "Invalid API argument",
    "Invalid magic value",      // 10
    "Error writing data",
    "Error converting file name",
    "Incorrect or missing password"
};


static const char *tsk_err_mm_str[TSK_ERR_VS_MAX] = {
    "Cannot determine partition type",  // 0
    "Unsupported partition type",
    "Error reading image file",
    "Invalid magic value",
    "Invalid walk range",
    "Invalid buffer size",      // 5
    "Invalid sector address",
    "Invalid API argument",
};

static const char *tsk_err_fs_str[TSK_ERR_FS_MAX] = {
    "Cannot determine file system type",        // 0
    "Unsupported file system type",
    "Function/Feature not supported",
    "Invalid walk range",
    "Error reading image file",
    "Invalid file offset",      // 5
    "Invalid API argument",
    "Invalid block address",
    "Invalid metadata address",
    "Error in metadata structure",
    "Invalid magic value",      // 10
    "Error extracting file from image",
    "Error writing data",
    "Error converting Unicode",
    "Error recovering deleted file",
    "General file system error",        // 15
    "File system is corrupt",
    "Attribute not found in file",
};

static const char *tsk_err_hdb_str[TSK_ERR_HDB_MAX] = {
    "Cannot determine hash database type",      // 0
    "Unsupported hash database type",
    "Error reading hash database file",
    "Error reading hash database index",
    "Invalid argument",
    "Error writing data",       // 5
    "Error creating file",
    "Error deleting file",
    "Missing file",
    "Error creating process",
    "Error opening file",       // 10
    "Corrupt hash database"
};

static const char *tsk_err_auto_str[TSK_ERR_AUTO_MAX] = {
    "Database Error",
    "Corrupt file data",
    "Error converting Unicode",
    "Image not opened yet"
};


#ifdef TSK_MULTITHREAD_LIB

#ifdef TSK_WIN32
TSK_ERROR_INFO *
tsk_error_get_info()
{
    return (TSK_ERROR_INFO *)
        tsk_error_win32_get_per_thread_(sizeof(TSK_ERROR_INFO));
}

    // non-windows
#else
static pthread_key_t pt_tls_key;
static pthread_once_t pt_tls_key_once = PTHREAD_ONCE_INIT;

static void
free_error_info(void *per_thread_error_info)
{
    if (per_thread_error_info != 0) {
        free(per_thread_error_info);
        pthread_setspecific(pt_tls_key, 0);
    }
}

static void
make_pt_tls_key()
{
    (void) pthread_key_create(&pt_tls_key, free_error_info);
}

TSK_ERROR_INFO *
tsk_error_get_info()
{
    TSK_ERROR_INFO *ptr = 0;
    (void) pthread_once(&pt_tls_key_once, make_pt_tls_key);
    if ((ptr = (TSK_ERROR_INFO *) pthread_getspecific(pt_tls_key)) == 0) {
        ptr = (TSK_ERROR_INFO *) malloc(sizeof(TSK_ERROR_INFO));
        ptr->t_errno = 0;
        ptr->errstr[0] = 0;
        ptr->errstr2[0] = 0;
        (void) pthread_setspecific(pt_tls_key, ptr);
    }
    return ptr;
}
#endif

// single-threaded
#else

static TSK_ERROR_INFO error_info = { 0, {0}, {0} };

TSK_ERROR_INFO *
tsk_error_get_info()
{
    return &error_info;
}

#endif

/**
 * \ingroup baselib
 * Return the string with the current error message.  The string does not end with a
 * newline.
 *
 * @returns String with error message or NULL if there is no error
 */
const char *
tsk_error_get()
{
    size_t pidx = 0;
    TSK_ERROR_INFO *error_info = tsk_error_get_info();
    int t_errno = error_info->t_errno;
    char *errstr_print = error_info->errstr_print;

    if (t_errno == 0) {
        return NULL;
    }

    memset(errstr_print, 0, TSK_ERROR_STRING_MAX_LENGTH);
    if (t_errno & TSK_ERR_AUX) {
        if ((TSK_ERR_MASK && t_errno) < TSK_ERR_AUX_MAX)
            snprintf(&errstr_print[pidx],
                TSK_ERROR_STRING_MAX_LENGTH - pidx, "%s",
                tsk_err_aux_str[t_errno & TSK_ERR_MASK]);
        else
            snprintf(&errstr_print[pidx],
                TSK_ERROR_STRING_MAX_LENGTH - pidx,
                "auxtools error: %" PRIu32, TSK_ERR_MASK & t_errno);
    }
    else if (t_errno & TSK_ERR_IMG) {
        if ((TSK_ERR_MASK & t_errno) < TSK_ERR_IMG_MAX)
            snprintf(&errstr_print[pidx],
                TSK_ERROR_STRING_MAX_LENGTH - pidx, "%s",
                tsk_err_img_str[t_errno & TSK_ERR_MASK]);
        else
            snprintf(&errstr_print[pidx],
                TSK_ERROR_STRING_MAX_LENGTH - pidx,
                "imgtools error: %" PRIu32, TSK_ERR_MASK & t_errno);
    }
    else if (t_errno & TSK_ERR_VS) {
        if ((TSK_ERR_MASK & t_errno) < TSK_ERR_VS_MAX)
            snprintf(&errstr_print[pidx],
                TSK_ERROR_STRING_MAX_LENGTH - pidx, "%s",
                tsk_err_mm_str[t_errno & TSK_ERR_MASK]);
        else
            snprintf(&errstr_print[pidx],
                TSK_ERROR_STRING_MAX_LENGTH - pidx,
                "mmtools error: %" PRIu32, TSK_ERR_MASK & t_errno);
    }
    else if (t_errno & TSK_ERR_FS) {
        if ((TSK_ERR_MASK & t_errno) < TSK_ERR_FS_MAX)
            snprintf(&errstr_print[pidx],
                TSK_ERROR_STRING_MAX_LENGTH - pidx, "%s",
                tsk_err_fs_str[t_errno & TSK_ERR_MASK]);
        else
            snprintf(&errstr_print[pidx],
                TSK_ERROR_STRING_MAX_LENGTH - pidx,
                "fstools error: %" PRIu32, TSK_ERR_MASK & t_errno);
    }
    else if (t_errno & TSK_ERR_HDB) {
        if ((TSK_ERR_MASK & t_errno) < TSK_ERR_HDB_MAX)
            snprintf(&errstr_print[pidx],
                TSK_ERROR_STRING_MAX_LENGTH - pidx, "%s",
                tsk_err_hdb_str[t_errno & TSK_ERR_MASK]);
        else
            snprintf(&errstr_print[pidx],
                TSK_ERROR_STRING_MAX_LENGTH - pidx,
                "hashtools error: %" PRIu32, TSK_ERR_MASK & t_errno);
    }
    else if (t_errno & TSK_ERR_AUTO) {
        if ((TSK_ERR_MASK & t_errno) < TSK_ERR_AUTO_MAX)
            snprintf(&errstr_print[pidx],
                TSK_ERROR_STRING_MAX_LENGTH - pidx, "%s",
                tsk_err_auto_str[t_errno & TSK_ERR_MASK]);
        else
            snprintf(&errstr_print[pidx],
                TSK_ERROR_STRING_MAX_LENGTH - pidx, "auto error: %" PRIu32,
                TSK_ERR_MASK & t_errno);
    }
    else {
        snprintf(&errstr_print[pidx], TSK_ERROR_STRING_MAX_LENGTH - pidx,
            "Unknown Error: %" PRIu32, t_errno);
    }
    pidx = strlen(errstr_print);

    /* Print the unique string, if it exists */
    if (error_info->errstr[0] != '\0') {
        snprintf(&errstr_print[pidx], TSK_ERROR_STRING_MAX_LENGTH - pidx,
            " (%s)", error_info->errstr);
        pidx = strlen(errstr_print);
    }

    if (error_info->errstr2[0] != '\0') {
        snprintf(&errstr_print[pidx], TSK_ERROR_STRING_MAX_LENGTH - pidx,
            " (%s)", error_info->errstr2);
        pidx = strlen(errstr_print);
    }
    return (char *) error_info->errstr_print;
}

/**
 * \ingroup baselib
 * Return the current error number.
 * @returns the current error number.
 */
uint32_t
tsk_error_get_errno()
{
    return tsk_error_get_info()->t_errno;
}

/**
 * \ingroup baselib
 * Set the current TSK error number.
 * @param t_errno the error number.
 */
void
tsk_error_set_errno(uint32_t t_errno)
{
    tsk_error_get_info()->t_errno = t_errno;
}

/**
 * \ingroup baselib
 * Retrieve the current, basic error string.  
 * Additional information is in errstr2.  
 * Use tsk_error_get() to get a fully formatted string. 
 * @returns the string. This is only valid until the next call to a tsk function.
 */
char *
tsk_error_get_errstr()
{
    return tsk_error_get_info()->errstr;
}

/**
 * \ingroup baselib
 * Set the error string #1. This should contain the basic message. 
 * @param format the printf-style format string
 */
void
tsk_error_set_errstr(char const *format, ...)
{
    va_list args;
    va_start(args, format);
    vsnprintf(tsk_error_get_info()->errstr, TSK_ERROR_STRING_MAX_LENGTH,
        format, args);
    va_end(args);
}

/**
 * \ingroup baselib
 * Set the error string
 * @param format the printf-style format string
 * @param args the printf-style args
 */
void
tsk_error_vset_errstr(char const *format, va_list args)
{
    vsnprintf(tsk_error_get_info()->errstr, TSK_ERROR_STRING_MAX_LENGTH,
        format, args);
}

/**
 * \ingroup baselib
 * Retrieve the current error string #2.
 * This has additional information than string #1.
 * @returns the string. This is only valid until the next call to a tsk function.
 */
char *
tsk_error_get_errstr2()
{
    return tsk_error_get_info()->errstr2;
}

/**
 * \ingroup baselib
 * Set the error string #2. This is called by methods who encounter the error,
 * but did not set errno. 
 * @param format the printf-style format string
 */
void
tsk_error_set_errstr2(char const *format, ...)
{
    va_list args;
    va_start(args, format);
    vsnprintf(tsk_error_get_info()->errstr2, TSK_ERROR_STRING_MAX_LENGTH,
        format, args);
    va_end(args);
}

/**
 * \ingroup baselib
 * Set the error string
 * @param format the printf-style format string
 * @param args the printf-style format args
 */
void
tsk_error_vset_errstr2(char const *format, va_list args)
{
    vsnprintf(tsk_error_get_info()->errstr2, TSK_ERROR_STRING_MAX_LENGTH,
        format, args);
}

/**
 * \ingroup baselib
 * Concatenate a message onto the end of the errstr2.
 * @param format
 */
void
tsk_error_errstr2_concat(char const *format, ...)
{
    va_list args;
    char *errstr2 = tsk_error_get_info()->errstr2;
    int current_length = (int) (strlen(errstr2) + 1);   // +1 for a space
    if (current_length > 0) {
        int remaining = TSK_ERROR_STRING_MAX_LENGTH - current_length;
        errstr2[current_length - 1] = ' ';
        va_start(args, format);
        vsnprintf(&errstr2[current_length], remaining, format, args);
        va_end(args);
    }
}

/**
 * \ingroup baselib
 * Print the current fully formed error message to a file.
 *
 * @param hFile File to print message to
 */
void
tsk_error_print(FILE * hFile)
{
    const char *str;
    if (tsk_error_get_errno() == 0)
        return;

    str = tsk_error_get();
    if (str != NULL) {
        tsk_fprintf(hFile, "%s\n", str);
    }
    else {
        tsk_fprintf(hFile,
            "Error creating Sleuth Kit error string (Errno: %d)\n",
            tsk_error_get_errno());
    }
}

/**
 * \ingroup baselib
 * Clear the error number and error message.
 */
void
tsk_error_reset()
{
    TSK_ERROR_INFO *info = tsk_error_get_info();
    info->t_errno = 0;
    info->errstr[0] = 0;
    info->errstr2[0] = 0;
    info->errstr_print[0] = 0;
}
