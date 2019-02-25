/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2005-2011 Brian Carrier.  All rights reserved 
 *
 * This software is distributed under the Common Public License 1.0
 */
#ifndef _TSK_IMG_I_H
#define _TSK_IMG_I_H

/*
 * Contains the internal library definitions for the disk image functions.  This should
 * be included by the code in the img library. 
 */

// include the base internal header file
#include "tsk/base/tsk_base_i.h"

// include the external disk image header file
#include "tsk_img.h"

// other standard includes
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

#if HAVE_LIBEWF
#include "libewf.h"

inline int is_blank(const char* str) {
    while (*str != '\0') {
        if (!isspace((unsigned char)*str)) {
            return 0;
        }
        str++;
    }
    return 1;
}

/**
* Reads the first 1 MB of the libewf header
*/
inline char* read_libewf_header_value(libewf_handle_t *handle, char* result_buffer, const size_t buffer_size, const uint8_t *identifier, size_t identifier_length, const char* key) {
	result_buffer[0] = '\0';

    strcpy(result_buffer, key);
	libewf_error_t * ewf_error;
	size_t key_len = strlen(key);
	
    int result = libewf_handle_get_utf8_header_value(handle, identifier, identifier_length, (uint8_t *)(result_buffer + key_len), buffer_size - key_len, &ewf_error);
	if (result != -1 && !is_blank(result_buffer + key_len)) {
		strcat(result_buffer, "\n");
	} else {
		//if blank or error, return nothing!
		result_buffer[0] = '\0';
	}

	return result_buffer;
}

inline char* libewf_read_description(libewf_handle_t *handle, char* result_buffer, const size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "description", 11, "Description: ");
}

inline char* libewf_read_case_number(libewf_handle_t *handle,  char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "case_number", 11, "Case Number: ");
}

inline char* libewf_read_evidence_number(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "evidence_number", 15, "Evidence Number: ");
}

inline char* libewf_read_examiner_name(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "examiner_name", 13, "Examiner Name: ");
}

inline char* libewf_read_notes(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "notes", 5, "Notes: ");
}

inline char* libewf_read_model(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "model", 5, "Model: ");
}

inline char* libewf_read_serial_number(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "serial_number", 13, "Serial Number: ");
}

inline char* libewf_read_device_label(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "device_label", 12, "Device Label:");
}

inline char* libewf_read_version(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "version", 7, "Version: ");
}

inline char* libewf_read_platform(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "platform", 8, "Platform: ");
}

inline char* libewf_read_acquired_date(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "acquiry_date", 12, "Acquired Date: ");
}

inline char* libewf_read_system_date(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "system_date", 11, "System Date: ");
}

inline char* libewf_read_acquiry_operating_system(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "acquiry_operating_system", 24, "Acquiry Operating System: ");
}

inline char* libewf_read_acquiry_software_version(libewf_handle_t *handle, char* result_buffer, size_t buffer_size) {
    return read_libewf_header_value(handle, result_buffer, buffer_size, (uint8_t *) "acquiry_software_version", 24, "Acquiry Software Version: ");
}
#endif

// Cygwin needs this, but not everyone defines it
#ifndef O_BINARY
#define O_BINARY 0
#endif
extern void *tsk_img_malloc(size_t);
extern void tsk_img_free(void *);
extern TSK_TCHAR **tsk_img_findFiles(const TSK_TCHAR * a_startingName,
    int *a_numFound);

#ifdef __cplusplus
}
#endif

#endif