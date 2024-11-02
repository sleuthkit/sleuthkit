
/*
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2024 Sleuth Kit Labs, LLC. All Rights reserved
 ** Copyright (c) 2010-2021 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 */

// Methods to handle volume encryption (currently only BitLocker is supported)

#include "encryptionHelper.h"

#ifdef HAVE_LIBMBEDTLS
#include "tsk/util/Bitlocker/BitlockerParser.h"
#endif

/**
* Test whether the volume is encrypted with BitLocker and initialize the parser and other fields if it is.
*
* The theory behind the return values is that we want to get the wrong password / needs password messages back
* to the user, which means we don't want to overwrite it with any other error codes.
*
* @param a_fs_info  The TSK_FS_INFO object. Should have the img_info and volume offset set but can otherwise be uninitialized.
*                      Will be updated if we find an successfully initialize BitLocker.
* @param a_pass     The password or recovery password to use for decryption. May be empty. If the password is not needed
*                      (for example if we have clear key) it will be ignored.
*
* @return 0 if:
* - We didn't find the Bitlocker signature
* - We found encryption and did all the initialization successfully
* - We found encryption but had an unspecified error in initialization
* Returns -1 if:
* - We got far enough to be confident that it's Bitlocker and have a specific error message to get back to the user
*/
#ifdef HAVE_LIBMBEDTLS
int handleBitlocker(TSK_FS_INFO* a_fs_info, const char* a_pass) {
	BitlockerParser* bitlockerParser = new BitlockerParser();
	BITLOCKER_STATUS status = bitlockerParser->initialize(a_fs_info->img_info, a_fs_info->offset, a_pass);
	if (status == BITLOCKER_STATUS::NOT_BITLOCKER) {
		delete bitlockerParser;
		return 0;
	}

	if (status != BITLOCKER_STATUS::SUCCESS) {

		// If we have some specific error cases we want to get that information back to the user
		if (status == BITLOCKER_STATUS::WRONG_PASSWORD) {
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_FS_BITLOCKER_ERROR);
			string errStr = "Incorrect password entered " + bitlockerParser->getRecoveryKeyIdStr();
			tsk_error_set_errstr(errStr.c_str());
			delete bitlockerParser;
			return -1;

		} else if (status == BITLOCKER_STATUS::NEED_PASSWORD) {
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_FS_BITLOCKER_ERROR);
			string errStr = "Password required to decrypt volume " + bitlockerParser->getRecoveryKeyIdStr();
			tsk_error_set_errstr(errStr.c_str());
			delete bitlockerParser;
			return -1;
		}
		else if (status == BITLOCKER_STATUS::UNSUPPORTED_KEY_PROTECTION_TYPE) {
			string message = "Unsupported key protection type(s): " + bitlockerParser->getUnsupportedProtectionTypes();
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_FS_BITLOCKER_ERROR);
			tsk_error_set_errstr(message.c_str());
			delete bitlockerParser;
			return -1;
		}

		// It's unlikely we're going to be able to open the file system (we found at least one BitLocker header) but it's safer to try
		delete bitlockerParser;
		return 0;
	}

	// Store the BitLocker data to use when reading the volume
	a_fs_info->encryption_type = TSK_FS_ENCRYPTION_TYPE_BITLOCKER;
	a_fs_info->encryption_data = (void*)bitlockerParser;
	a_fs_info->flags = (TSK_FS_INFO_FLAG_ENUM)(a_fs_info->flags | TSK_FS_INFO_FLAG_ENCRYPTED);
	a_fs_info->block_size = bitlockerParser->getSectorSize();
	// We don't set a_fs_info->decrypt_block here because Bitlocker needs to handle both reading in the block
	// and doing the decryption since some sectors may have been relocated
	return 0;
}
#else
int handleBitlocker(
  [[maybe_unused]] TSK_FS_INFO* a_fs_info,
  [[maybe_unused]] const char* a_pass)
{
  return 0;
}
#endif

/**
* Check if the volume appears to be encrypted and attempt to initialize the encryption object.
*
* @return 0 if:
* - There was no encryption found
* - We found encryption and did all the initialization successfully
* - We found encryption but had an unspecified error in initialization
* Returns -1 if:
* - We found encryption and got far enough that we're confident we should not continue trying to parse the file system and
*     have potentially useful feedback to give the user (like that the password was incorrect)
*/
#ifdef HAVE_LIBMBEDTLS
int handleVolumeEncryption(TSK_FS_INFO* a_fs_info, const char* a_pass) {
  return handleBitlocker(a_fs_info, a_pass);
}
#else
int handleVolumeEncryption(
  [[maybe_unused]] TSK_FS_INFO* a_fs_info,
  [[maybe_unused]] const char* a_pass)
{
  return 0;
}
#endif

/**
* Reads and decrypts one or more sectors starting at the given offset.
* The offset is expected to be sector-aligned and the length should be a multiple of the sector size.
*
* @param a_fs_info        The TSK_FS_INFO object
* @param offsetInVolume   Offset to start reading at (relative to the start of the volume)
* @param len              Number of bytes to read
* @param data             Will hold decrypted data
*
* @return Number of bytes read or -1 on error
*/
#ifdef HAVE_LIBMBEDTLS
ssize_t read_and_decrypt_bitlocker_blocks(TSK_FS_INFO* a_fs_info, TSK_DADDR_T offsetInVolume, size_t len, void* data) {

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
}
#endif

#ifdef HAVE_LIBMBEDTLS
void fillEncryptionDescription(
  TSK_FS_INFO* a_fs_info,
  char* a_desc,
  size_t a_descLen)
{
	if (a_fs_info->encryption_type == TSK_FS_ENCRYPTION_TYPE_ENUM::TSK_FS_ENCRYPTION_TYPE_BITLOCKER
		&& a_fs_info->encryption_data != NULL) {

		BitlockerParser* parser = (BitlockerParser*)a_fs_info->encryption_data;
		string descStr = parser->getDescription();
		strncpy(a_desc, descStr.c_str(), a_descLen - 1);
	}
}
#else
void fillEncryptionDescription(
  [[maybe_unused]] TSK_FS_INFO* a_fs_info,
  [[maybe_unused]] char* a_desc,
  [[maybe_unused]] size_t a_descLen)
{
}
#endif

/**
* Copys a summary of the encryption algoritm to a_desc. Expected size of description is under 100 characters.
*
* @param a_fs_info  TSK_FS_INFO object
* @param a_desc     Output buffer for description
* @param a_descLen  Size of output buffer (recommended - 256 bytes)
*/
void tsk_fs_get_encryption_description(TSK_FS_INFO* a_fs_info, char* a_desc, size_t a_descLen) {
	if (a_descLen == 0) {
		return;
	}

	memset(a_desc, 0, a_descLen);
  fillEncryptionDescription(a_fs_info, a_desc, a_descLen);
}

/**
* Free any memory being held by encryption objects
*
* @param a_fs_info The TSK_FS_INFO object
*/
#ifdef HAVE_LIBMBEDTLS
void freeEncryptionData(TSK_FS_INFO* a_fs_info) {
	if (a_fs_info->encryption_type == TSK_FS_ENCRYPTION_TYPE_ENUM::TSK_FS_ENCRYPTION_TYPE_BITLOCKER
		&& a_fs_info->encryption_data != NULL) {

		BitlockerParser* parser = (BitlockerParser*)a_fs_info->encryption_data;
		delete parser;
		a_fs_info->encryption_data = NULL;
	}
	a_fs_info->encryption_type = TSK_FS_ENCRYPTION_TYPE_ENUM::TSK_FS_ENCRYPTION_TYPE_NONE;
}
#else
void freeEncryptionData([[maybe_unused]] TSK_FS_INFO* a_fs_info) {}
#endif
