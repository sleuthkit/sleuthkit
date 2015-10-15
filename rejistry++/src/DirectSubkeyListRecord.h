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
 * \file DirectSubkeyListRecord.h
 *
 */
#ifndef _REJISTRY_DIRECTSUBKEYLISTRECORD_H
#define _REJISTRY_DIRECTSUBKEYLISTRECORD_H

#include <cstdint>
#include <string>
#include <list>

// Local includes
#include "SubkeyListRecord.h"

namespace Rejistry {

    /**
     *
     */
    class DirectSubkeyListRecord : public SubkeyListRecord {
    public:
        DirectSubkeyListRecord(RegistryByteBuffer * buf, uint32_t offset, uint32_t itemSize) : SubkeyListRecord(buf, offset) {
            _itemSize = itemSize;
        }
        
        virtual ~DirectSubkeyListRecord() {}
    
        virtual std::vector<NKRecord *> getSubkeys() const;

    private:
        static const uint16_t LIST_START_OFFSET = 0x04;

        uint32_t _itemSize;

    protected:
        DirectSubkeyListRecord() {};
        DirectSubkeyListRecord(const DirectSubkeyListRecord &);
        DirectSubkeyListRecord& operator=(const DirectSubkeyListRecord &);
    };
};

#endif
