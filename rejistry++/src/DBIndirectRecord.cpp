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
 * \file DBIndirectRecord.cpp
 *
 */
#include<algorithm>

// Local includes
#include "DBIndirectRecord.h"
#include "REGFHeader.h"
#include "Cell.h"
#include "RejistryException.h"

namespace Rejistry {

    ByteBuffer::ByteArray DBIndirectRecord::getData(uint32_t length) const {
        std::vector<uint8_t> data;

        uint32_t count = 0;
        
        while (length > 0) {
            uint32_t size = std::min(DB_DATA_SIZE, length);
            uint32_t offset = getDWord(OFFSET_LIST_OFFSET + (count * 4));
            offset += REGFHeader::FIRST_HBIN_OFFSET;
            std::auto_ptr< Cell > c(new Cell(_buf, offset));

            if (c.get() == NULL) {
                throw RegistryParseException("Failed to create Cell.");
            }

            std::vector<uint8_t> cellData = c->getData();
            
            data.insert(data.end(), cellData.begin(), cellData.begin() + size);

            length -= size;
            count += 1;
        }
        
        return data;
    }

};
