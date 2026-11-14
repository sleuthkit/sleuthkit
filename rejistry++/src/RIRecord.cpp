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
#include <memory>

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
            subkeyList.push_back(getSubkeyListAt(index));
        }

        return subkeyList;
    }

    SubkeyListRecord::SubkeyListRecordPtr RIRecord::getSubkeyListAt(uint16_t index) const {
        auto c = std::make_unique< Cell >(_buf, getSubkeyListCellOffset(index));
        return c->getSubkeyList();
    }

    uint32_t RIRecord::getSubkeyListCellOffset(uint16_t index) const {
        uint32_t offset = getDWord(LIST_START_OFFSET + (index * LIST_ENTRY_SIZE));
        return REGFHeader::FIRST_HBIN_OFFSET + offset;
    }

    NKRecord::NKRecordUniqPtr RIRecord::findSubkey(const std::wstring& name) const {
        std::set<uint32_t> searchedLists;
        return findSubkeyInLookup(name, searchedLists);
    }

    // Search the sub-lists in order, reading each only until a match. The
    // reads have no side effects, so a sub-list this lookup already searched
    // (or is still searching further up, when an ri list leads back into
    // itself) cannot give a different answer and is skipped. That keeps one
    // lookup to one pass over each distinct sub-list, and stops a
    // self-referencing ri list from recursing until the stack overflows.
    NKRecord::NKRecordUniqPtr RIRecord::findSubkeyInLookup(const std::wstring& name, std::set<uint32_t>& searchedLists) const {
        uint16_t listLength = getListLength();
        for (uint16_t index = 0; index < listLength; ++index) {
            uint32_t cellOffset = getSubkeyListCellOffset(index);
            if (!searchedLists.insert(cellOffset).second) {
                continue;
            }
            auto c = std::make_unique< Cell >(_buf, cellOffset);
            NKRecord::NKRecordUniqPtr nk = c->getSubkeyList()->findSubkeyInLookup(name, searchedLists);
            if (nk) {
                return nk;
            }
        }

        return nullptr;
    }

    NKRecord::NKRecordUniqPtrList RIRecord::getSubkeys() const {
        NKRecord::NKRecordUniqPtrList finalNKRecordList;

        // Iterate over each of the subkey lists getting their subkeys.
        for (const auto& subkeyList : getSubkeyLists()) {
            for (auto& nk : subkeyList->getSubkeys()) {
                finalNKRecordList.push_back(std::move(nk));
            }
        }

        return finalNKRecordList;
    }
};
