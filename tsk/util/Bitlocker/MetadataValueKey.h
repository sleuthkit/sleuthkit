#pragma once

#ifdef HAVE_LIBMBEDTLS

#include "MetadataValue.h"

class MetadataValueKey : public MetadataValue {
public:
	MetadataValueKey(BITLOCKER_METADATA_VALUE_TYPE a_valueType, uint8_t* buf, size_t bufLen);

	size_t getKeyLen() {
		return keyLen;
	}

	uint8_t* getKeyBytes() {
		return key;
	}

	BITLOCKER_ENCRYPTION_TYPE getEncryptionType() {
		return encryptionType;
	}

	void print() {
		printf("Key\n");
		printf("Encryption type: %s\n", convertEncryptionTypeToString(encryptionType).c_str());
		printf("Key: %s", convertByteArrayToString(key, keyLen).c_str());
	}

	~MetadataValueKey() {
		encryptionType = BITLOCKER_ENCRYPTION_TYPE::UNKNOWN;
		if (key != NULL) {
			memset(key, 0, keyLen);
			free(key);
		}
		keyLen = 0;
	};

private:
	BITLOCKER_ENCRYPTION_TYPE encryptionType = BITLOCKER_ENCRYPTION_TYPE::UNKNOWN;
	size_t keyLen = 0;
	uint8_t* key = NULL;
};

#endif