/*
 *
 * The Sleuth Kit
 *
 * Copyright 2013-2015 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This is a C++ port of the Rejistry library developed by Willi Ballenthin.
 * See https://github.com/williballenthin/Rejistry for the original Java version.
 */

/**
 * \file REGFHeader.cpp
  */

// Local includes
#include "REGFHeader.h"
#include "RejistryException.h"

namespace Rejistry {


    REGFHeader::REGFHeader(RegistryByteBuffer& buf, const uint32_t offset) : BinaryBlock(buf, offset) {
        uint64_t magic = getDWord(offset);

        if (magic != 0x66676572) {
            throw RegistryParseException("REGF magic value not found");
        }
    }

    bool REGFHeader::isSynchronized() const {
        return (getDWord(SEQ1_OFFSET) == getDWord(SEQ2_OFFSET));
    }

    uint32_t REGFHeader::getMajorVersion() const {
        return getDWord(MAJOR_VERSION_OFFSET);
    }

    uint32_t REGFHeader::getMinorVersion() const {
        return getDWord(MINOR_VERSION_OFFSET);
    }

    std::wstring REGFHeader::getHiveName() const {
        return getUTF16String(HIVE_NAME_OFFSET, 0x40);
    }

    uint32_t REGFHeader::getLastHbinOffset() const {
        return getDWord(LAST_HBIN_OFFSET_OFFSET);
    }

    HBIN::HBINPtrList REGFHeader::getHBINs() const {
        uint32_t nextHBINOffset = FIRST_HBIN_OFFSET;
        HBIN::HBINPtrList hbinList;

        do {
            if (getDWord(nextHBINOffset) != 0x6E696268) {
                // Terminate if this doesn't have the correct magic number.
                break;
            }

            HBIN * nextHBIN = new HBIN(this, _buf, getAbsoluteOffset(nextHBINOffset));
            hbinList.push_back(nextHBIN);
            nextHBINOffset += nextHBIN->getRelativeOffsetNextHBIN();
        }
        while (nextHBINOffset <= getLastHbinOffset());

        return hbinList;
    }

    HBIN::HBINPtr REGFHeader::getFirstHBIN() const {
        if (getDWord(FIRST_HBIN_OFFSET) != 0x6E696268) {
            throw RegistryParseException("HBIN magic value not found.");
        }

        return new HBIN(this, _buf, getAbsoluteOffset(FIRST_HBIN_OFFSET));
    }

    /**
     * @throws RegistryParseException in case of error.
     */
    NKRecord::NKRecordPtr REGFHeader::getRootNKRecord() const {
        int32_t firstCellOffset = (int32_t)(getDWord(FIRST_KEY_OFFSET_OFFSET));
        std::auto_ptr< HBIN > firstHBIN(getFirstHBIN());
        if (firstHBIN.get() != NULL) {
            std::auto_ptr< Cell > cellPtr(firstHBIN->getCellAtOffset(firstCellOffset));

            if (cellPtr.get() == NULL) {
                throw RegistryParseException("Failed to get first cell.");
            }
            return cellPtr->getNKRecord();
        }
        else {
            throw RegistryParseException("Failed to get first HBIN.");
        }
    }
};
