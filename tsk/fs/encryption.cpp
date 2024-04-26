#include "tsk_encryption.h"

#include "tsk/util/Bitlocker/BitlockerParser.h"

int tskEncryptionTest(TSK_IMG_INFO* a_img_info) {
	BitlockerParser parser;
	parser.initialize(a_img_info);

	return 0;
}