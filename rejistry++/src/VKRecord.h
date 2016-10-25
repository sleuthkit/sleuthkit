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
 * \file VKRecord.h
 *
 */
#ifndef _REJISTRY_VKRECORD_H
#define _REJISTRY_VKRECORD_H

#include <cstdint>
#include <string>

// Local includes
#include "Record.h"
#include "ValueData.h"

namespace Rejistry {

    /**
     * VK Records contain minimal metadata about a single value and store
     * the offset to a cell which contains the value's data.
     */
    class VKRecord : public Record {
    public:
        static const std::wstring DEFAULT_VALUE_NAME;

        typedef VKRecord * VKRecordPtr;
        typedef std::vector< VKRecordPtr > VKRecordPtrList;

        /**
            The AutoNKRecordPtrList class should be used by clients to hold lists of
            VKRecord pointers returned by methods like ValueListRecord::getValues()
            so that the record objects will be automatically freed. Example:
            @code
            AutoVKRecordPtrList valueList(nkRecord->getValueList()->getValues());
            for (VKRecord::VKRecordPtrList::iterator i = valueList.begin(); i != valueList.end(); ++i)
            { ... //do stuff }
            // Don't worry about delete'ing each record object--valueList will take care of
            // that when it goes out of scope.
            @endcode
        */
        class AutoVKRecordPtrList
        {
        public:

            AutoVKRecordPtrList(VKRecordPtrList recordList) : _recordList(recordList) {}
            ~AutoVKRecordPtrList()
            {
                for (VKRecordPtrList::iterator it = _recordList.begin(); it != _recordList.end(); ++it)
                {
                    delete *it;
                }
            }
            VKRecordPtrList::iterator begin() { return _recordList.begin(); }
            VKRecordPtrList::iterator end()   { return _recordList.end(); }
            VKRecordPtrList::size_type size() { return _recordList.size(); }
        private:
            AutoVKRecordPtrList(const AutoVKRecordPtrList&);
            AutoVKRecordPtrList& operator=(const AutoVKRecordPtrList&);

            VKRecordPtrList _recordList;
        };

        VKRecord(RegistryByteBuffer * buf, uint32_t offset);
        VKRecord(const VKRecord &);
        virtual ~VKRecord() {}
    
        /**
         * Does the record have a non-default name?
         * @returns true if the record has an explicit name, or false if the
         * record has the default name.
         */
        bool hasName() const;

        /**
         * @returns true if name is stored as ASCII, or false for UTF-16LE.
         */
        bool hasAsciiName() const;

        /**
         * Get the name of the value stored by this VKRecord.
         * @returns The name of the value.
         */
        std::wstring getName() const;

        /**
         * Get the type of the value stored by this VKRecord.
         * @returns The type of the value.
         * @throws RegistryParseException.
         */
        ValueData::VALUE_TYPES getValueType() const;

        /**
         * @returns The length of the value data.
         */
        uint32_t getDataLength() const;

        /**
         * Get the literal value that describes the value data length.
         * Some interpretation may be required to make this value reasonable.
         * @returns The literal value that describes the value data length.
         */
        uint32_t getRawDataLength() const;

        /**
         * @returns The absolute offset to the value data.
         */
        uint32_t getDataOffset() const;

        /**
         * Parses and returns the data associated with this value.
         * @returns The data associated with this value. The caller is
         * responsible for freeing the data.
         * @throws RegistryParseException
         */
        ValueData::ValueDataPtr getValue() const;

    private:
        static const std::string MAGIC;
        static const uint8_t NAME_LENGTH_OFFSET = 0x02;
        static const uint8_t DATA_LENGTH_OFFSET = 0x04;
        static const uint8_t DATA_OFFSET_OFFSET = 0x08;
        static const uint8_t VALUE_TYPE_OFFSET = 0x0C;
        static const uint8_t NAME_FLAGS_OFFSET = 0x10;
        static const uint8_t NAME_OFFSET_OFFSET = 0x14;

        static const uint8_t SMALL_DATA_SIZE = 0x05;
        static const uint16_t DB_DATA_SIZE = 0x3FD8;
        static const uint32_t LARGE_DATA_SIZE = 0x80000000;

        static const uint16_t MAX_NAME_LENGTH = 32767;

        VKRecord();
        VKRecord& operator=(const VKRecord &);
    };
};

#endif
