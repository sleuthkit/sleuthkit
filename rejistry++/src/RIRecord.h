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
 * \file RIRecord.h
 *
 */
#ifndef _REJISTRY_RIRECORD_H
#define _REJISTRY_RIRECORD_H

#include <cstdint>
#include <string>

// Local includes
#include "SubkeyListRecord.h"
#include "NKRecord.h"

namespace Rejistry {

    /**
     */
    class RIRecord : public SubkeyListRecord {
    public:
        static const std::string MAGIC;

        RIRecord(RegistryByteBuffer * buf, uint32_t offset);
        
        virtual ~RIRecord() {}

        virtual NKRecord::NKRecordPtrList getSubkeys() const;

    private:
        static const uint16_t LIST_START_OFFSET = 0x04;
        static const uint16_t LIST_ENTRY_SIZE = 0x04;
        
        RIRecord();
        RIRecord(const RIRecord &);
        RIRecord& operator=(const RIRecord &);

        SubkeyListRecordPtrList getSubkeyLists() const;
    };
};

#endif
