
// Don't include this file from other headers - use a forward declaration and include it in the .cpp
#pragma once

#ifdef HAVE_LIBMBEDTLS

#include <list>

#include "MetadataEntry.h"
#include "MetadataUtils.h"

class MetadataValue {
public:
	MetadataValue(BITLOCKER_METADATA_VALUE_TYPE a_valueType) { valueType = a_valueType; };
	static MetadataValue* createMetadataValue(BITLOCKER_METADATA_VALUE_TYPE a_valueType, uint8_t* buf, size_t bufLen);

	BITLOCKER_METADATA_VALUE_TYPE getValueType() { return valueType; }
	bool wasLoadedSuccessfully() {
		return loadSuccessful;
	}

	void registerError(string errMsg) {
		loadSuccessful = false;
		writeError(errMsg);
	}

	virtual void print() = 0;
	virtual ~MetadataValue() {};

private:
	BITLOCKER_METADATA_VALUE_TYPE valueType;
	bool loadSuccessful = true;
};

/**
* Class used to hold valid but unprocessed metadata values
*/
class MetadataValueGeneric : public MetadataValue {
public:
	MetadataValueGeneric(BITLOCKER_METADATA_VALUE_TYPE a_valueType, uint8_t* buf, size_t bufLen) : MetadataValue(a_valueType) {};

	void print() { printf("MetadataValueGeneric"); }

	~MetadataValueGeneric() {};
};

/**
* Class used to hold unknown or invalid metadata values
*/
class MetadataValueUnknown : public MetadataValue {
public:
	MetadataValueUnknown(BITLOCKER_METADATA_VALUE_TYPE a_valueType, uint8_t* buf, size_t bufLen) : MetadataValue(a_valueType) {};

	void print() { printf("Unknown"); }

	~MetadataValueUnknown() {};
};

#endif