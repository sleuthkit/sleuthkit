#include "MetadataValueOffsetAndSize.h"

MetadataValueOffsetAndSize::MetadataValueOffsetAndSize(BITLOCKER_METADATA_VALUE_TYPE a_valueType, uint8_t* buf, size_t bufLen) : MetadataValue(a_valueType) {
    if (bufLen < 16) {
        registerError("Buffer for creating MetadataValueOffsetAndSize was too short");
        return;
    }

    offset = tsk_getu64(TSK_LIT_ENDIAN, &(buf[0]));
    size = tsk_getu64(TSK_LIT_ENDIAN, &(buf[8]));
}