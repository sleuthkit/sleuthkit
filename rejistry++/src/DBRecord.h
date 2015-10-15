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
