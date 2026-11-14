#ifndef _TSK_ENCRYPTION_H
#define _TSK_ENCRYPTION_H

#include "tsk/img/tsk_img_i.h"
#include "tsk_fs_i.h"

// Start of the TSK_ERR_FS_BITLOCKER_ERROR message for each reason a BitLocker volume stays locked.
// Callers match on these, so the wording must not change.
#define TSK_BITLOCKER_MSG_WRONG_PASSWORD "Incorrect password entered"
#define TSK_BITLOCKER_MSG_NEED_PASSWORD "Password required to decrypt volume"
#define TSK_BITLOCKER_MSG_UNSUPPORTED_PROTECTION "Unsupported key protection type(s)"

#ifdef __cplusplus
extern "C" {
#endif
	int handleVolumeEncryption(TSK_FS_INFO* a_fs_info, const char* a_pass);
	void tsk_fs_get_encryption_description(TSK_FS_INFO* a_fs_info, char* a_desc, size_t a_descLen);
	int tsk_fs_get_encryption_key_index(TSK_FS_INFO* a_fs_info);

#ifdef HAVE_LIBMBEDTLS
	ssize_t read_and_decrypt_bitlocker_blocks(TSK_FS_INFO* a_fs_info, TSK_DADDR_T start, size_t len, void* data);
#endif

	void freeEncryptionData(TSK_FS_INFO* a_fs_info);
#ifdef __cplusplus
}
#endif

#endif