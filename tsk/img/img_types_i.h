#ifndef IMG_TYPES_H
#define IMG_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdio.h>
#include "tsk/base/tsk_base.h"  // This provides TSK_TCHAR and tsk_fprintf etc.
#include "tsk/img/tsk_img.h"    // This provides TSK_IMG_TYPE_ENUM

// Parse a UTF-8 string to an image type ID
TSK_IMG_TYPE_ENUM tsk_img_type_toid_utf8(const char *str);

// Parse a TSK_TCHAR string (platform-dependent char type) to an image type ID
TSK_IMG_TYPE_ENUM tsk_img_type_toid(const TSK_TCHAR *str);

// Print the list of supported image formats to a file handle
void tsk_img_type_print(FILE *hFile);

// Get the name of an image format type given its ID
const char *tsk_img_type_toname(TSK_IMG_TYPE_ENUM type);

// Get the description of an image format type given its ID
const char *tsk_img_type_todesc(TSK_IMG_TYPE_ENUM type);

// Return a bitmask of supported image types
TSK_IMG_TYPE_ENUM tsk_img_type_supported(void);

#ifdef __cplusplus
}
#endif

#endif // IMG_TYPES_H