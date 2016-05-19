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
 * \file SubkeyListRecord.h
 *
 */
#ifndef _REJISTRY_SUBKEYLISTRECORD_H
#define _REJISTRY_SUBKEYLISTRECORD_H

#include <cstdint>
#include <string>
#include <list>

// Local includes
#include "Record.h"

namespace Rejistry {

    class NKRecord;

    /**
     * Subkey lists are simple lists of pointers/hash tuples. Different types
     * of subkey lists have been used in different versions of Windows.
     */
    class SubkeyListRecord : public Record {
    public:
        typedef SubkeyListRecord * SubkeyListRecordPtr;
        typedef std::vector<SubkeyListRecordPtr> SubkeyListRecordPtrList;

        SubkeyListRecord(RegistryByteBuffer * buf, uint32_t offset) : Record(buf, offset) {}
        
        virtual ~SubkeyListRecord() {}
    
        /**
         * @returns The number of subkeys this list has.
         */
        uint16_t getListLength() const;

        /**
         * @returns The list of subkeys. The caller is responsible for
         * freeing the returned record list.
         */
        virtual std::vector<NKRecord*> getSubkeys() const = 0;

        /**
         * Fetch the subkey with the given name from the subkey list.
         * @param name The name of the subkey to fetch.
         * @returns The matching subkey record. The caller is responsible
         * for freeing the returned record.
         */
        NKRecord * getSubkey(const std::wstring& name) const;

    private:
        static const uint16_t LIST_LENGTH_OFFSET = 0x02;

    protected:
        SubkeyListRecord();
        SubkeyListRecord(const SubkeyListRecord &);
        SubkeyListRecord& operator=(const SubkeyListRecord &);

    };
};

#endif
