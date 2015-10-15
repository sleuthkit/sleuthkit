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
 * \file EmptySubkeyList.h
 *
 */
#ifndef _REJISTRY_EMPTYSUBKEYLIST_H
#define _REJISTRY_EMPTYSUBKEYLIST_H

#include <cstdint>
#include <string>
#include <list>

// Local includes
#include "SubkeyListRecord.h"

namespace Rejistry {

    /**
     *
     */
    class EmptySubkeyList : public SubkeyListRecord {
    public:
        EmptySubkeyList(RegistryByteBuffer * buf, uint32_t offset) : SubkeyListRecord(buf, offset) {}
        
        virtual ~EmptySubkeyList() {}
    
        virtual std::vector<NKRecord *> getSubkeys() const {
            return std::vector<NKRecord *>();
        }

    private:

    protected:
        EmptySubkeyList() {};
        EmptySubkeyList(const EmptySubkeyList &);
        EmptySubkeyList& operator=(const EmptySubkeyList &);
    };
};

#endif
