/*
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2024 Sleuth Kit Labs, LLC. All Rights reserved
 ** Copyright (c) 2010-2021 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 */

#ifdef HAVE_LIBMBEDTLS

#include "MetadataValueOffsetAndSize.h"

MetadataValueOffsetAndSize::MetadataValueOffsetAndSize(BITLOCKER_METADATA_VALUE_TYPE valueType, uint8_t* buf, size_t bufLen) : MetadataValue(valueType) {
    if (bufLen < 16) {
        registerError("MetadataValueOffsetAndSize::MetadataValueOffsetAndSize(): Buffer for creating MetadataValueOffsetAndSize was too short");
        return;
    }

    m_offset = tsk_getu64(TSK_LIT_ENDIAN, &(buf[0]));
    m_size = tsk_getu64(TSK_LIT_ENDIAN, &(buf[8]));
}

#endif