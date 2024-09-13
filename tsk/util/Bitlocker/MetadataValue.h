/*
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2024 Sleuth Kit Labs, LLC. All Rights reserved
 ** Copyright (c) 2010-2021 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 */

// Be careful about including this file in other headers that include MetadataEntry.h - use a forward declaration and include it in the .cpp
#pragma once

#ifdef HAVE_LIBMBEDTLS

#include <list>

#include "MetadataEntry.h"
#include "BitlockerUtils.h"

class MetadataValue {
public:
	MetadataValue(BITLOCKER_METADATA_VALUE_TYPE valueType) { m_valueType = valueType; };

	BITLOCKER_METADATA_VALUE_TYPE getValueType() { return m_valueType; }
	bool wasLoadedSuccessfully() {
		return m_loadSuccessful;
	}

	void registerError(string errMsg) {
		m_loadSuccessful = false;
		writeError(errMsg);
	}
	virtual ~MetadataValue() {};

private:
	BITLOCKER_METADATA_VALUE_TYPE m_valueType;
	bool m_loadSuccessful = true;
};

/**
* Class used to hold valid but currently unprocessed metadata values
*/
class MetadataValueGeneric : public MetadataValue {
public:
	MetadataValueGeneric(BITLOCKER_METADATA_VALUE_TYPE a_valueType, uint8_t* buf, size_t bufLen) : MetadataValue(a_valueType) {};

	~MetadataValueGeneric() {};
};

/**
* Class used to hold unknown or invalid metadata values
*/
class MetadataValueUnknown : public MetadataValue {
public:
	MetadataValueUnknown(BITLOCKER_METADATA_VALUE_TYPE a_valueType, uint8_t* buf, size_t bufLen) : MetadataValue(a_valueType) {};

	~MetadataValueUnknown() {};
};

#endif