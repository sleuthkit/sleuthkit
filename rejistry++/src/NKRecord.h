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
 * \file NKRecord.h
 *
 */
#ifndef _REJISTRY_NKRECORD_H
#define _REJISTRY_NKRECORD_H

#include <cstdint>

// Local includes
#include "Record.h"
#include "ValueListRecord.h"
#include "SubkeyListRecord.h"

namespace Rejistry {

    /**
     * NKRecord is the structure that backs a Registry key. It has a name and
     * may have values and subkeys.
     */
    class NKRecord : public Record {
    public:
        typedef NKRecord * NKRecordPtr;
        typedef std::vector<NKRecordPtr> NKRecordPtrList;

        /**
            The AutoNKRecordPtrList class should be used by clients to hold lists of
            NKRecord pointers returned by methods like SubkeyListRecord::getSubkeys()
            so that the record objects will be automatically freed. Example:
            @code
            AutoNKRecordPtrList subkeyList(nkrecord->getSubkeyList()->getSubkeys());
            for (NKRecord::NKRecordPtrList::iterator i = subkeyList.begin(); i != subkeyList.end(); ++i)
            { ... //do stuff }
            // Don't worry about delete'ing each record object--subkeyList will take care of
            // that when it goes out of scope.
            @endcode
        */
        class AutoNKRecordPtrList
        {
        public:

            AutoNKRecordPtrList(NKRecordPtrList recordList) : _recordList(recordList) {}
            ~AutoNKRecordPtrList()
            {
                for (NKRecordPtrList::iterator it = _recordList.begin(); it != _recordList.end(); ++it)
                {
                    delete *it;
                }
            }
            NKRecordPtrList::iterator begin() { return _recordList.begin(); }
            NKRecordPtrList::iterator end()   { return _recordList.end(); }
            NKRecordPtrList::size_type size() { return _recordList.size(); }
        private:
            AutoNKRecordPtrList(const AutoNKRecordPtrList&);
            AutoNKRecordPtrList& operator=(const AutoNKRecordPtrList&);

            NKRecordPtrList _recordList;
        };

        NKRecord(RegistryByteBuffer * buf, uint32_t offset);
        NKRecord(const NKRecord& );

        virtual ~NKRecord() {}
    
        /**
         * Does the record have a class name?
         * @returns true if the NKRecord has a class name, false otherwise.
         */
        bool hasClassname() const;

        /**
         * Get the class name for the NKRecord if it exists.
         * @throws RegistryParseException.
         */
        std::wstring getClassName() const;

        /**
         * Get the modification timestamp of the NKRecord.
         * @returns The raw modification timestamp of this key.
         */
        uint64_t getTimestamp() const;

        /**
         * @returns true if the NKRecord is a root record. 
         */
        bool isRootKey() const;

        bool hasAsciiName() const;

        /**
         * Get the name of the registry key represented by this record.
         * It is not the full path but a single path component.
         * @returns The key name.
         */
        std::wstring getName() const;

        /**
         * @returns true if the key has a parent key, false otherwise.
         */
        bool hasParentRecord() const;

        /**
         * Get the parent record for this key.
         * @returns The parent record.
         * @throws RegistryParseException.
         */
        NKRecordPtr getParentRecord() const;

        /**
         * @returns The number of values for this key.
         */
        uint32_t getNumberOfValues() const;

        /**
         * @returns The number of subkeys for this key.
         */
        uint32_t getSubkeyCount() const;

        /**
         * @returns The list of subkeys for this key.
         */
        SubkeyListRecord::SubkeyListRecordPtr getSubkeyList() const;

        /**
         * @returns The list of values for this key.
         */
         ValueListRecord::ValueListRecordPtr getValueList() const;

    private:
        static const std::string MAGIC;
        static const uint16_t FLAGS_OFFSET = 0x02;
        static const uint16_t TIMESTAMP_OFFSET = 0x04;
        static const uint16_t PARENT_RECORD_OFFSET_OFFSET = 0x10;
        static const uint16_t SUBKEY_NUMBER_OFFSET = 0x14;
        static const uint16_t SUBKEY_LIST_OFFSET_OFFSET = 0x1C;
        static const uint16_t VALUES_NUMBER_OFFSET = 0x24;
        static const uint16_t VALUE_LIST_OFFSET_OFFSET = 0x28;
        static const uint16_t CLASSNAME_OFFSET_OFFSET = 0x30;
        static const uint16_t NAME_LENGTH_OFFSET = 0x48;
        static const uint16_t CLASSNAME_LENGTH_OFFSET = 0x4A;
        static const uint16_t NAME_OFFSET = 0x4C;

        static const uint8_t MAX_NAME_LENGTH = 255;

        NKRecord() {};
        NKRecord& operator=(const NKRecord &);
    };
};

#endif
