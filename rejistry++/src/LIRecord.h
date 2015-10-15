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
 * \file LIRecord.h
 *
 */
#ifndef _REJISTRY_LIRECORD_H
#define _REJISTRY_LIRECORD_H

#include <cstdint>
#include <string>

// Local includes
#include "DirectSubkeyListRecord.h"

namespace Rejistry {

    /**
     */
    class LIRecord : public DirectSubkeyListRecord {
    public:
        static const std::string MAGIC;

        typedef LIRecord * LIRecordPtr;

        LIRecord(RegistryByteBuffer * buf, uint32_t offset);
        
        virtual ~LIRecord() {}
    
    private:
        LIRecord() {};
        LIRecord(const LIRecord &);
        LIRecord& operator=(const LIRecord &);
    };
};

#endif
