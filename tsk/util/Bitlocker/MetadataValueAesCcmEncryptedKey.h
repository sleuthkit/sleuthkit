/*
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2024 Sleuth Kit Labs, LLC. All Rights reserved
 ** Copyright (c) 2010-2021 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 */

#pragma once

#ifdef HAVE_LIBMBEDTLS

#include "MetadataValue.h"
#include "mbedtls/aes.h"

#define BITLOCKER_KEY_MAC_LEN 16
#define BITLOCKER_DECRYPT_KEY_BLOCK_SIZE 16

class MetadataValueAesCcmEncryptedKey : public MetadataValue {
public:
	MetadataValueAesCcmEncryptedKey(BITLOCKER_METADATA_VALUE_TYPE valueType, uint8_t* buf, size_t bufLen);

	BITLOCKER_STATUS decrypt(uint8_t* key, size_t keyLen, MetadataEntry** keyEntry);

	~MetadataValueAesCcmEncryptedKey();
private:
	BITLOCKER_STATUS decryptKey(uint8_t* key, size_t keyLen, uint8_t* encryptedData, size_t encryptedDataLen, uint8_t* decryptedData);

	int createMessageAuthenticationCode(mbedtls_aes_context* aes_context, uint8_t* nonce, uint8_t nonceLen, uint8_t* data, size_t dataLen, uint8_t* mac);

	const size_t m_headerLen = 12;

	uint64_t m_nonceTimestamp = 0;
	uint32_t m_nonceCounter = 0;
	const static size_t m_nonceLen = 12;
	uint8_t m_nonce[m_nonceLen];
	size_t m_encryptedDataLen = 0;
	uint8_t* m_encryptedData = NULL;
};

#endif