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
 * \file DBIndirectRecord.cpp
 *
 */

// Local includes
#include "DBIndirectRecord.h"
#include "REGFHeader.h"
#include "Cell.h"
#include "RejistryException.h"

namespace Rejistry {

    ByteBuffer::ByteArray DBIndirectRecord::getData(uint32_t length) const {
        std::vector<uint8_t> data;
        data.resize(length);

        uint32_t count = 0;

        while (length > 0) {
            uint32_t size = 0x3fd8;
            uint32_t offset = getDWord(OFFSET_LIST_OFFSET + (count * 4));
            offset += REGFHeader::FIRST_HBIN_OFFSET;
            std::auto_ptr< Cell > c(new Cell(_buf, offset));

            if (c.get() == NULL) {
                throw RegistryParseException("Failed to create Cell.");
            }

            std::vector<uint8_t> cellData = c->getData();
            data.insert(data.end(), cellData.begin(), cellData.end());

            if (length < size) {
                size = length;
            }

            length -= size;
            count += 1;
        }
        
        return data;
    }

};
