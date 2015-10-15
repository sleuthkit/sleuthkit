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
 * \file DirectSubkeyListRecord.cpp
 *
 */

// Local includes
#include "DirectSubkeyListRecord.h"
#include "REGFHeader.h"
#include "RejistryException.h"

namespace Rejistry {
    
    std::vector<NKRecord *> DirectSubkeyListRecord::getSubkeys() const {
        std::vector<NKRecord *> subkeyList;
        uint16_t listLength = getListLength();

        for (uint16_t index = 0; index < listLength; ++index) {
            uint32_t relativeOffset = LIST_START_OFFSET + (index * _itemSize);
            uint32_t offset = getDWord(relativeOffset);
            uint32_t parentOffset = REGFHeader::FIRST_HBIN_OFFSET + offset;
            std::auto_ptr< Cell > c(new Cell(_buf, parentOffset));
            if (c.get() == NULL) {
                throw RegistryParseException("Failed to create Cell for key record.");
            }

            subkeyList.push_back(c->getNKRecord());
        }

        return subkeyList;        
    }

};
