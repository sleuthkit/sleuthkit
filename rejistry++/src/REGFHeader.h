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
 * \file REGFHeader.h
 * File header structure for a Registry hive.
 */

#ifndef _REJISTRY_REGFHEADER_H
#define _REJISTRY_REGFHEADER_H

#include <cstdint>
#include <string>
#include <vector>

// Local includes
#include "RegistryByteBuffer.h"
#include "BinaryBlock.h"
#include "HBIN.h"
#include "NKRecord.h"

namespace Rejistry {

    /**
     * REGFHeader is the file header structure for a Registry hive.
     */
    class REGFHeader : public BinaryBlock {
    public:
        static const uint16_t FIRST_HBIN_OFFSET = 0x1000;

        REGFHeader(RegistryByteBuffer& buf, const uint32_t offset);

        virtual ~REGFHeader() {};

        /**
         * Has the hive been properly synchronized?
         * @returns true if the hive has been properly synchronized,
         * otherwise false.
         */
        bool isSynchronized() const;

        uint32_t getMajorVersion() const;
        uint32_t getMinorVersion() const;

        /**
         * Get the name of the hive.
         * @returns The hive name.
         */
        std::wstring getHiveName() const;

        uint32_t getLastHbinOffset() const;

        /**
         * Get a list of pointers to HBIN records. The caller is
         * responsible for freeing the records.
         * @returns A list of pointers to HBIN records.
         */
        HBIN::HBINPtrList getHBINs() const;

        /**
         * Get a pointer to the first HBIN record. The caller is 
         * responsible for freeing the record.
         * @returns A pointer to the first HBIN record.
         */
        HBIN::HBINPtr getFirstHBIN() const;

        NKRecord::NKRecordPtr getRootNKRecord() const;

    private:
        static const uint8_t MAGIC_OFFSET = 0x0;
        static const uint8_t SEQ1_OFFSET = 0x4;
        static const uint8_t SEQ2_OFFSET = 0x8;
        static const uint8_t MAJOR_VERSION_OFFSET = 0x14;
        static const uint8_t MINOR_VERSION_OFFSET = 0x18;
        static const uint8_t FIRST_KEY_OFFSET_OFFSET = 0x24;
        static const uint8_t HIVE_NAME_OFFSET = 0x30;
        static const uint8_t LAST_HBIN_OFFSET_OFFSET = 0x28;

        REGFHeader() {};
        REGFHeader(const REGFHeader &);
        REGFHeader& operator=(const REGFHeader &);
    };
};

#endif
