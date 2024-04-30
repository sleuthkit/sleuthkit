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

int handleBitlocker(TSK_FS_INFO* a_fs_info, const char* a_pass) {
#ifdef HAVE_LIBMBEDTLS
	BitlockerParser* bitlockerParser = new BitlockerParser();
	if (0 != bitlockerParser->initialize(a_fs_info->img_info, a_pass)) {
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

ssize_t read_and_decrypt_bitlocker_blocks(TSK_FS_INFO* a_fs_info, TSK_DADDR_T start, size_t len, void* data) {
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
	return parser->readAndDecryptSectors(start, len, (uint8_t*)data);
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