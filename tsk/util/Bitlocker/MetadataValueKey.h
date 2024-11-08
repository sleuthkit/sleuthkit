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

	~MetadataValueKey() {
		encryptionType = BITLOCKER_ENCRYPTION_TYPE::UNKNOWN;
		if (key != nullptr) {
			memset(key, 0, keyLen);
			free(key);
			key = nullptr;
		}
		keyLen = 0;
	};

private:
	BITLOCKER_ENCRYPTION_TYPE encryptionType = BITLOCKER_ENCRYPTION_TYPE::UNKNOWN;
	size_t keyLen = 0;
	uint8_t* key = NULL;
};

#endif