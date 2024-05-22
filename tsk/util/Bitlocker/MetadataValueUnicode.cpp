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

#include "MetadataValueUnicode.h"

#include <iostream>
using namespace std;

MetadataValueUnicode::MetadataValueUnicode(BITLOCKER_METADATA_VALUE_TYPE a_valueType, uint8_t* buf, size_t bufLen) : MetadataValue(a_valueType) {
    if (bufLen == 0) {
        registerError("MetadataValueUnicode::MetadataValueUnicode(): Buffer for creating MetadataValueUnicode was too short");
        return;
    }

    if (bufLen % 2 != 0) {
        registerError("MetadataValueUnicode::MetadataValueUnicode(): Buffer for creating MetadataValueUnicode does not have even length");
        return;
    }
    m_unicodeStringW = wstring(reinterpret_cast<wchar_t*>(buf), bufLen / sizeof(wchar_t));
}

#endif