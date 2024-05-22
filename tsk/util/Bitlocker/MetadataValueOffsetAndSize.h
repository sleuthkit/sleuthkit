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

class MetadataValueOffsetAndSize : public MetadataValue {
public:
	MetadataValueOffsetAndSize(BITLOCKER_METADATA_VALUE_TYPE valueType, uint8_t* buf, size_t bufLen);

	uint64_t getOffset() {
		return m_offset;
	}

	uint64_t getSize() {
		return m_size;
	}

	~MetadataValueOffsetAndSize() {};

private:
	uint64_t m_offset = 0;
	uint64_t m_size = 0;
};

#endif