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

// Local includes
#include "ValueListRecord.h"
#include "REGFHeader.h"
#include "RejistryException.h"

namespace Rejistry {
    ValueListRecord::ValueListRecord(RegistryByteBuffer * buf, uint32_t offset, uint32_t numValues) 
        : Record(buf, offset), _numValues(numValues) {}

    VKRecord::VKRecordPtrList ValueListRecord::getValues() const {
        VKRecord::VKRecordPtrList valueList;

        for (uint32_t index = 0; index < _numValues; ++index) {
            uint32_t offset = getDWord(VALUE_LIST_OFFSET + (0x4 * index));
            offset += REGFHeader::FIRST_HBIN_OFFSET;
            std::auto_ptr< Cell > c(new Cell(_buf, offset));
            if (c.get() == NULL) {
                throw RegistryParseException("Failed to create Cell for value record.");
            }

            valueList.push_back(c->getVKRecord());
        }

        return valueList;
    }

    VKRecord::VKRecordPtr ValueListRecord::getValue(const std::wstring& name) const {
        VKRecord::VKRecordPtr foundRecord = NULL;

        VKRecord::VKRecordPtrList recordList = getValues();
        VKRecord::VKRecordPtrList::iterator it = recordList.begin();

        for (; it != recordList.end(); ++it) {
            // If we have a name match or we are searching for the "default" entry
            // (which matches a record with no name) we are done.
            if ((!(*it)->hasName() && name == VKRecord::DEFAULT_VALUE_NAME) ||
                (_wcsicmp(name.c_str(), (*it)->getName().c_str()) == 0)) {
                // Create a copy of the record to return as the records
                // in the list will be deleted.
                foundRecord = new VKRecord(*(*it));
                break;
            }
        }

        // Free the list of records.
        for (it = recordList.begin(); it != recordList.end(); ++it) {
            delete *it;
        }

        if (foundRecord == NULL) {
            throw NoSuchElementException("Failed to find value.");
        }

        return foundRecord;
    }
};
