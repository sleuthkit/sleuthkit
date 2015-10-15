/*
 *
 *  The Sleuth Kit
 *
 *  Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 *  Copyright (c) 2010-2015 Basis Technology Corporation. All Rights
 *  reserved.
 *
 *  This software is distributed under the Common Public License 1.0
 *
 *  This is a C++ port of the Rejistry library developed by Willi Ballenthin.
 *  See https://github.com/williballenthin/Rejistry for the original Java version.
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
            if (_wcsicmp(name.c_str(), (*it)->getName().c_str()) == 0) {
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
