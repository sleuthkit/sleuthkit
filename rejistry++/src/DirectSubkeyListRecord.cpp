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
 * \file DirectSubkeyListRecord.cpp
 *
 */

// Local includes
#include "DirectSubkeyListRecord.h"
#include "REGFHeader.h"
#include "RejistryException.h"

namespace Rejistry {
    
    std::vector<NKRecord *> DirectSubkeyListRecord::getSubkeys() const {
        std::vector<NKRecord *> subkeyList;
        uint16_t listLength = getListLength();

        for (uint16_t index = 0; index < listLength; ++index) {
            uint32_t relativeOffset = LIST_START_OFFSET + (index * _itemSize);
            uint32_t offset = getDWord(relativeOffset);
            uint32_t parentOffset = REGFHeader::FIRST_HBIN_OFFSET + offset;
            std::auto_ptr< Cell > c(new Cell(_buf, parentOffset));
            if (c.get() == NULL) {
                throw RegistryParseException("Failed to create Cell for key record.");
            }

            subkeyList.push_back(c->getNKRecord());
        }

        return subkeyList;        
    }

};
