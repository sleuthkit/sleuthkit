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
 * \file LFRecord.h
 *
 */
#ifndef _REJISTRY_LFRECORD_H
#define _REJISTRY_LFRECORD_H

#include <cstdint>
#include <string>

// Local includes
#include "DirectSubkeyListRecord.h"

namespace Rejistry {

    /**
     */
    class LFRecord : public DirectSubkeyListRecord {
    public:
        static const std::string MAGIC;

        LFRecord(RegistryByteBuffer * buf, uint32_t offset);
        
        virtual ~LFRecord() {}
    
    private:

        LFRecord() {};
        LFRecord(const LFRecord &);
        LFRecord& operator=(const LFRecord &);
    };
};

#endif
