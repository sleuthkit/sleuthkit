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
 * \file ValueListRecord.cpp
 *
 */
#include <algorithm>
#include <cstring>
#include <memory>

// Local includes
#include "ValueListRecord.h"
#include "REGFHeader.h"
#include "RejistryException.h"

namespace Rejistry {
    ValueListRecord::ValueListRecord(RegistryByteBuffer * buf, uint32_t offset, uint32_t numValues) 
        : Record(buf, offset), _numValues(numValues) {}

    VKRecord::VKRecordUniqPtrList ValueListRecord::getValues() const {
        VKRecord::VKRecordUniqPtrList valueList;

        for (uint32_t index = 0; index < _numValues; ++index) {
            uint32_t offset = getDWord(VALUE_LIST_OFFSET + (0x4 * index));
            offset += REGFHeader::FIRST_HBIN_OFFSET;

            auto c = std::make_unique< Cell >(_buf, offset);
            valueList.push_back(c->getVKRecord());
        }

        return valueList;
    }

    VKRecord::VKRecordUniqPtr ValueListRecord::getValue(const std::wstring& name) const {
        for (auto& valueRecord : getValues()) {
            if ((!valueRecord->hasName() && name == VKRecord::DEFAULT_VALUE_NAME) ||
                (_wcsicmp(name.c_str(), valueRecord->getName().c_str()) == 0)) {
                return std::move(valueRecord);
            }
        }

        throw NoSuchElementException("Failed to find value.");
    }
};
