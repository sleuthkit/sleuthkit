#pragma once

#ifdef HAVE_LIBMBEDTLS

#include "MetadataValue.h"

#define BITLOCKER_STRETCH_KEY_SHA256_LEN 32
#define BITLOCKER_STRETCH_KEY_SALT_LEN 16

class MetadataValueStretchKey : public MetadataValue {
public:
	MetadataValueStretchKey(BITLOCKER_METADATA_VALUE_TYPE a_valueType, uint8_t* buf, size_t bufLen);

	int parseStretchKeyUsingPassword(uint8_t* passwordHash, size_t passwordHashLen, uint8_t* stretchKey, size_t stretchKeyLen);

	void print();

	~MetadataValueStretchKey();
private:
	int generateStretchedKey(uint8_t* passwordHash, size_t passwordHashLen, uint8_t* salt, size_t saltLen, uint8_t* result, size_t resultLen);

	const size_t headerLen = 20;
	BITLOCKER_ENCRYPTION_TYPE encryptionType;
	uint8_t salt[16];
	MetadataEntry* encryptedKeyEntry = NULL;
};

#endif