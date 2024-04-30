#ifndef _TSK_ENCRYPTION_H
#define _TSK_ENCRYPTION_H

#include "tsk/img/tsk_img_i.h"
#include "tsk_fs_i.h"

#ifdef __cplusplus
extern "C" {
#endif
	int handleVolumeEncryption(TSK_FS_INFO* a_fs_info, const char* a_pass);

	ssize_t read_and_decrypt_bitlocker_blocks(TSK_FS_INFO* a_fs_info, TSK_DADDR_T start, size_t len, void* data);
	uint8_t decrypt_bitlocker_block(TSK_FS_INFO* a_fs_info, TSK_DADDR_T start, void* data);

	void freeEncryptionData(TSK_FS_INFO* a_fs_info);
#ifdef __cplusplus
}
#endif

#endif