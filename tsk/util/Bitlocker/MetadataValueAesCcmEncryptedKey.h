#pragma once

#include "MetadataValue.h"

#include "mbedtls/aes.h"

#define BITLOCKER_KEY_MAC_LEN 16
#define BITLOCKER_DECRYPT_KEY_BLOCK_SIZE 16

class MetadataValueAesCcmEncryptedKey : public MetadataValue {
public:
	MetadataValueAesCcmEncryptedKey(BITLOCKER_METADATA_VALUE_TYPE a_valueType, uint8_t* buf, size_t bufLen);

	int decrypt(uint8_t* key, size_t keyLen, MetadataEntry** keyEntry);

	uint8_t* getNonce() {
		return nonce;
	}

	size_t getNonceLen() {
		return 12;
	}

	void print();

	~MetadataValueAesCcmEncryptedKey();
private:
	int decryptKey(uint8_t* key, size_t keyLen, uint8_t* nonce, size_t nonceLen, uint8_t* encryptedData,
		size_t encryptedDataLen, uint8_t* decryptedData);

	int createMessageAuthenticationCode(mbedtls_aes_context* aes_context, uint8_t* nonce, uint8_t nonceLen, uint8_t* data, size_t dataLen, uint8_t* mac);

	const size_t headerLen = 12;

	uint64_t nonceTimestamp = 0;
	uint32_t nonceCounter = 0;
	uint8_t nonce[12];
	size_t encryptedDataLen = 0;
	uint8_t* encryptedData = NULL;
};