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

class MetadataValueUnicode : public MetadataValue {
public:
	MetadataValueUnicode(BITLOCKER_METADATA_VALUE_TYPE valueType, uint8_t* buf, size_t bufLen);

	wstring getUnicodeWString() {
		return m_unicodeStringW;
	}

	~MetadataValueUnicode() {};

private:
	wstring m_unicodeStringW = L"";
};

#endif