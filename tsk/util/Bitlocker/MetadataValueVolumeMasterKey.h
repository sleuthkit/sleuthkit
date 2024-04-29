#pragma once

#ifdef HAVE_LIBMBEDTLS

#include "MetadataValue.h"

class MetadataValueVolumeMasterKey : public MetadataValue {
public:
	MetadataValueVolumeMasterKey(BITLOCKER_METADATA_VALUE_TYPE a_valueType, uint8_t* buf, size_t bufLen);

	BITLOCKER_KEY_PROTECTION_TYPE getProtectionType() {
		return keyProtectionType;
	}

	list<MetadataEntry*>& getProperties() {
		return properties;
	}

	void print();

	~MetadataValueVolumeMasterKey();

private:
	const size_t headerLen = 28;

	uint8_t guid[16];
	uint64_t lastModificationTime = 0;
	uint16_t unknown;
	BITLOCKER_KEY_PROTECTION_TYPE keyProtectionType = BITLOCKER_KEY_PROTECTION_TYPE::UNKNOWN;
	list<MetadataEntry*> properties;
};

#endif