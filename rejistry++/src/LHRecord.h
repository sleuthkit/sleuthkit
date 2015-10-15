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
 * \file LHRecord.h
 *
 */
#ifndef _REJISTRY_LHRECORD_H
#define _REJISTRY_LHRECORD_H

#include <cstdint>
#include <string>

// Local includes
#include "DirectSubkeyListRecord.h"

namespace Rejistry {

    /**
     */
    class LHRecord : public DirectSubkeyListRecord {
    public:
        static const std::string MAGIC;

        LHRecord(RegistryByteBuffer * buf, uint32_t offset);
        
        virtual ~LHRecord() {}
    
    private:
        LHRecord() {};
        LHRecord(const LHRecord &);
        LHRecord& operator=(const LHRecord &);
    };
};

#endif
