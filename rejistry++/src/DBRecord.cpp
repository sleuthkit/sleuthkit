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
 * \file DBRecord.cpp
 *
 */

// Local includes
#include "DBRecord.h"
#include "RejistryException.h"
#include "REGFHeader.h"

namespace Rejistry {
    const std::string DBRecord::MAGIC = "db";

    DBRecord::DBRecord(RegistryByteBuffer * buf, uint32_t offset) : Record(buf, offset) {
        if (!(getMagic() == MAGIC)) {
            throw RegistryParseException("DBRecord magic value not found.");
        }
    }

    ByteBuffer::ByteArray DBRecord::getData(uint32_t length) const {
        uint32_t offset = getDWord(INDIRECT_BLOCK_OFFSET_OFFSET);
        offset += REGFHeader::FIRST_HBIN_OFFSET;

        std::auto_ptr< Cell > c(new Cell(_buf, offset));
        if (c.get() == NULL) {
            throw RegistryParseException("Failed to create Cell for DBRecord.");
        }

        std::auto_ptr< DBIndirectRecord > dbi(c->getDBIndirectRecord());
        return dbi->getData(length);
    }

};
