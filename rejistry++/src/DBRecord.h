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
 * \file DBRecord.h
 *
 */
#ifndef _REJISTRY_DBRECORD_H
#define _REJISTRY_DBRECORD_H

#include <cstdint>
#include <string>

// Local includes
#include "Record.h"
#include "RegistryByteBuffer.h"

namespace Rejistry {

    /**
     */
    class DBRecord : public Record {
    public:
        typedef DBRecord * DBRecordPtr;

        DBRecord(RegistryByteBuffer * buf, uint32_t offset);
        
        virtual ~DBRecord() {}

        /**
         * Fetches 'length' data from the blocks pointed to by this DBRecord
         * @param length The number of bytes to attempt to parse.
         * @returns The bytes parsed from the blocks.
         */
        ByteBuffer::ByteArray getData(uint32_t length) const;

    private:
        static const std::string MAGIC;
        static const uint16_t INDIRECT_BLOCK_OFFSET_OFFSET = 0x04;

        DBRecord() {};
        DBRecord(const DBRecord &);
        DBRecord& operator=(const DBRecord &);

    };
};

#endif
