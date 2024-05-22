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

#define BITLOCKER_STRETCH_KEY_SHA256_LEN 32
#define BITLOCKER_STRETCH_KEY_SALT_LEN 16

class MetadataValueStretchKey : public MetadataValue {
public:
	MetadataValueStretchKey(BITLOCKER_METADATA_VALUE_TYPE valueType, uint8_t* buf, size_t bufLen);

	BITLOCKER_STATUS parseStretchKeyUsingPassword(uint8_t* passwordHash, size_t passwordHashLen, uint8_t* stretchKey, size_t stretchKeyLen);

	~MetadataValueStretchKey();
private:
	BITLOCKER_STATUS generateStretchedKey(uint8_t* passwordHash, size_t passwordHashLen, uint8_t* salt, size_t saltLen, uint8_t* result, size_t resultLen);

	const size_t m_headerLen = 20;
	BITLOCKER_ENCRYPTION_TYPE m_encryptionType;
	uint8_t m_salt[16];
	MetadataEntry* m_encryptedKeyEntry = NULL;
};

#endif