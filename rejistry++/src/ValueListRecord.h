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
 * \file ValueListRecord.h
 *
 */
#ifndef _REJISTRY_VALUELISTRECORD_H
#define _REJISTRY_VALUELISTRECORD_H

#include <cstdint>
#include <string>

// Local includes
#include "Record.h"
#include "VKRecord.h"

namespace Rejistry {

    /**
     */
    class ValueListRecord : public Record {
    public:
        typedef ValueListRecord * ValueListRecordPtr;

        ValueListRecord(RegistryByteBuffer * buf, uint32_t offset, uint32_t numValues);
        
        virtual ~ValueListRecord() {}
    
        /**
         * @returns The list of value records. The caller is responsible
         * for freeing these records.
         */
        virtual VKRecord::VKRecordPtrList getValues() const;

        /**
         * Fetch the value with the given name from the value list.
         * @param name The name of the value to fetch.
         * @returns The matching value record. The caller is responsible
         * for freeing this record.
         */
        VKRecord::VKRecordPtr getValue(const std::wstring& name) const;

    private:
        static const uint16_t VALUE_LIST_OFFSET = 0x00;

        uint32_t _numValues;

    protected:
        ValueListRecord() {};
        ValueListRecord(const ValueListRecord &);
        ValueListRecord& operator=(const ValueListRecord &);

    };
};

#endif
