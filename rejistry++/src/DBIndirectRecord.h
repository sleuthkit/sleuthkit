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
 * \file DBIndirectRecord.h
 *
 */
#ifndef _REJISTRY_DBINDIRECTRECORD_H
#define _REJISTRY_DBINDIRECTRECORD_H

#include <cstdint>
#include <string>

// Local includes
#include "Record.h"
#include "RegistryByteBuffer.h"

namespace Rejistry {

    /**
     */
    class DBIndirectRecord : public Record {
    public:
        typedef DBIndirectRecord * DBIndirectRecordPtr;

        DBIndirectRecord(RegistryByteBuffer * buf, uint32_t offset) : Record(buf, offset) {}
        
        virtual ~DBIndirectRecord() {}

        /**
         * Fetches 'length' data from the blocks pointed to by this
         * indirect block.
         * @param length The number of bytes to attempt to parse.
         * @returns The bytes parsed from the blocks.
         */
        ByteBuffer::ByteArray getData(uint32_t length) const;

    private:
        static const uint16_t OFFSET_LIST_OFFSET = 0x00;

        DBIndirectRecord() {};
        DBIndirectRecord(const DBIndirectRecord &);
        DBIndirectRecord& operator=(const DBIndirectRecord &);
    };
};

#endif
