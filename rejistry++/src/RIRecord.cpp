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
 * \file RIRecord.cpp
 *
 */

// Local includes
#include "RIRecord.h"
#include "RejistryException.h"
#include "REGFHeader.h"

namespace Rejistry {
    const std::string RIRecord::MAGIC = "ri";

    RIRecord::RIRecord(RegistryByteBuffer * buf, uint32_t offset) : SubkeyListRecord(buf, offset) {
        if (!(getMagic() == MAGIC)) {
            throw RegistryParseException("RIRecord magic value not found.");
        }
    }

    SubkeyListRecord::SubkeyListRecordPtrList RIRecord::getSubkeyLists() const {
        SubkeyListRecord::SubkeyListRecordPtrList subkeyList;

        uint16_t listLength = getListLength();

        for (uint16_t index = 0; index < listLength; ++index) {
            uint32_t offset = getDWord(LIST_START_OFFSET + (index * LIST_ENTRY_SIZE));
            uint32_t parentOffset = REGFHeader::FIRST_HBIN_OFFSET + offset;
            std::auto_ptr< Cell > c(new Cell(_buf, parentOffset));
            if (c.get() == NULL) {
                throw RegistryParseException("Failed to create Cell for key record.");
            }

            subkeyList.push_back(c->getSubkeyList());
        }

        return subkeyList;
    }

    NKRecord::NKRecordPtrList RIRecord::getSubkeys() const {
        NKRecord::NKRecordPtrList finalNKRecordList;
        SubkeyListRecord::SubkeyListRecordPtrList subkeyList = getSubkeyLists();

        SubkeyListRecord::SubkeyListRecordPtrList::iterator it;

        // Iterate over each of the subkey lists getting their subkeys.
        for (it = subkeyList.begin(); it != subkeyList.end(); ++it) {
            NKRecord::NKRecordPtrList nkRecordList = (*it)->getSubkeys();
            finalNKRecordList.insert(finalNKRecordList.end(), nkRecordList.begin(), nkRecordList.end());
        }

        return finalNKRecordList;        
    }

};
