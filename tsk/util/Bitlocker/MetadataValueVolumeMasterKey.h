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

class MetadataValueVolumeMasterKey : public MetadataValue {
public:
	MetadataValueVolumeMasterKey(BITLOCKER_METADATA_VALUE_TYPE valueType, uint8_t* buf, size_t bufLen);

	BITLOCKER_KEY_PROTECTION_TYPE getProtectionType() {
		return m_keyProtectionType;
	}

	list<MetadataEntry*>& getProperties() {
		return m_properties;
	}

	void copyGuid(uint8_t* dest) {
		memcpy(dest, m_guid, 16);
	}

	~MetadataValueVolumeMasterKey();

private:
	const size_t m_headerLen = 28;

	uint8_t m_guid[16];
	uint64_t m_lastModificationTime = 0;
	uint16_t m_unknown;
	BITLOCKER_KEY_PROTECTION_TYPE m_keyProtectionType = BITLOCKER_KEY_PROTECTION_TYPE::UNKNOWN;
	list<MetadataEntry*> m_properties;
};

#endif