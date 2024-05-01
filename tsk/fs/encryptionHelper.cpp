#include "encryptionHelper.h"

#ifdef HAVE_LIBMBEDTLS
#include "tsk/util/Bitlocker/BitlockerParser.h"
#endif

TSK_DADDR_T convert_bitlocker_block_offset(TSK_FS_INFO* a_fs_info, TSK_DADDR_T a_orig_offset) {
#ifdef HAVE_LIBMBEDTLS
	printf("convert_bitlocker_block_offset: orig offset: 0x%" PRIx64 "\n", a_orig_offset);

	printf("  encryption_type: %d\n", a_fs_info->encryption_type);
	if (a_fs_info->encryption_type != TSK_FS_ENCRYPTION_TYPE_ENUM::TSK_FS_ENCRYPTION_TYPE_BITLOCKER
		|| a_fs_info->encryption_data == NULL) {
		return a_orig_offset;
	}

	BitlockerParser* parser = (BitlockerParser*)a_fs_info->encryption_data;
	return parser->convertVolumeOffset(a_orig_offset);

#else
	return a_orig_offset;
#endif
}

/**
* Test whether the volume is encrypted with Bitlocker and initialize the parser and other fields if it is.
* 
* The theory behind the return values is that we want to get the wrong password / needs password messages back
* to the user, which means we don't want to overwrite it with any other error codes.
* 
* Returns 0 if:
* - We didn't find the Bitlocker signature
* - We found encryption and did all the initialization successfully
* - We found encryption but had an unspecified error in initialization
* Returns -1 if:
* - We got far enough to be confident that it's Bitlocker and that the entered password is incorrect
* - We got far enough to be confident that it's Bitlocker and that the user needs to enter a password
*/
int handleBitlocker(TSK_FS_INFO* a_fs_info, const char* a_pass) {
#ifdef HAVE_LIBMBEDTLS
	BitlockerParser* bitlockerParser = new BitlockerParser();
	BITLOCKER_STATUS status = bitlockerParser->initialize(a_fs_info->img_info, a_fs_info->offset, a_pass);
	if (status == BITLOCKER_STATUS::NOT_BITLOCKER) {
		return 0;
	}

	if (status != BITLOCKER_STATUS::SUCCESS) {

		// If we have a wrong password or missing password we want to get that information back to the user
		// At some point...
		if (status == BITLOCKER_STATUS::WRONG_PASSWORD) {
			writeWarning("### Wrong password");
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_FS_BITLOCKER_PASSWORD_ERROR);
			tsk_error_set_errstr("Incorrect password entered");
			return -1;

		} else if (status == BITLOCKER_STATUS::NEED_PASSWORD) {
			writeWarning("### Need password");
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_FS_BITLOCKER_PASSWORD_ERROR);
			tsk_error_set_errstr("Password required to decrypt volume");
			return -1;
		}
		else {
			writeWarning("### General error");
			// It's unlikely we're going to be able to open the file system but it's safer to try
			return 0;
		}

		delete bitlockerParser;
		return -1;
	}

	a_fs_info->encryption_type = TSK_FS_ENCRYPTION_TYPE_BITLOCKER;
	a_fs_info->encryption_data = (void*)bitlockerParser;
	a_fs_info->flags |= TSK_FS_INFO_FLAG_ENCRYPTED;
	a_fs_info->block_size = bitlockerParser->getSectorSize();
	a_fs_info->decrypt_block = decrypt_bitlocker_block;
#endif
	return 0;
}

/**
* Returns 0 if:
* - There was no encryption found
* - We found encryption and did all the initialization successfully
* - We found encryption but had an unspecified error in initialization  
* Returns -1 if:
* - We found encryption and got far enough that we're confident we should not continue trying to parse the file system and
*     have potentially useful feedback to give the user (like that the password was incorrect)
*/
int handleVolumeEncryption(TSK_FS_INFO* a_fs_info, const char* a_pass) {
	int ret = 0;
#ifdef HAVE_LIBMBEDTLS
	ret = handleBitlocker(a_fs_info, a_pass);
#endif

	return ret;
}

uint8_t decrypt_bitlocker_block(TSK_FS_INFO* a_fs_info, TSK_DADDR_T start, void* data) {
#ifdef HAVE_LIBMBEDTLS
	if (a_fs_info->encryption_type != TSK_FS_ENCRYPTION_TYPE_ENUM::TSK_FS_ENCRYPTION_TYPE_BITLOCKER
		|| a_fs_info->encryption_data == NULL
		|| data == NULL) {

		return -1;
	}

	BitlockerParser* parser = (BitlockerParser*)a_fs_info->encryption_data;
	return parser->decryptSector(start, (uint8_t*)data);

#else
	return -1;
#endif
}

ssize_t read_and_decrypt_bitlocker_blocks(TSK_FS_INFO* a_fs_info, TSK_DADDR_T offsetInVolume, size_t len, void* data) {
#ifdef HAVE_LIBMBEDTLS
	if (a_fs_info->encryption_type != TSK_FS_ENCRYPTION_TYPE_ENUM::TSK_FS_ENCRYPTION_TYPE_BITLOCKER
		|| a_fs_info->encryption_data == NULL
		|| data == NULL) {

		return -1;
	}

	if (len == 0) {
		return 0;
	}

	BitlockerParser* parser = (BitlockerParser*)a_fs_info->encryption_data;
	return parser->readAndDecryptSectors(offsetInVolume, len, (uint8_t*)data);
#else
	return -1;
#endif
}

void freeEncryptionData(TSK_FS_INFO* a_fs_info) {
	if (a_fs_info->encryption_type == TSK_FS_ENCRYPTION_TYPE_ENUM::TSK_FS_ENCRYPTION_TYPE_BITLOCKER
		&& a_fs_info->encryption_data != NULL) {

		BitlockerParser* parser = (BitlockerParser*)a_fs_info->encryption_data;
		delete parser;
		a_fs_info->encryption_data = NULL;
	}
	a_fs_info->encryption_type = TSK_FS_ENCRYPTION_TYPE_ENUM::TSK_FS_ENCRYPTION_TYPE_NONE;
}