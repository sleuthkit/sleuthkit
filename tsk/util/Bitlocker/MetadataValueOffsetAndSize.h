#pragma once
#ifdef HAVE_LIBMBEDTLS

#include "MetadataValue.h"

class MetadataValueOffsetAndSize : public MetadataValue {
public:
	MetadataValueOffsetAndSize(BITLOCKER_METADATA_VALUE_TYPE a_valueType, uint8_t* buf, size_t bufLen);

	uint64_t getOffset() {
		return offset;
	}

	uint64_t getSize() {
		return size;
	}

	void print() { printf("OffsetAndSize"); }

	~MetadataValueOffsetAndSize() {};
private:
	uint64_t offset = 0;
	uint64_t size = 0;
};

#endif