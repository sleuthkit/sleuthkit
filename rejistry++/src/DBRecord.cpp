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
