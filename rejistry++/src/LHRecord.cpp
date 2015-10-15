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
 * \file LHRecord.cpp
 *
 */

// Local includes
#include "LHRecord.h"
#include "RejistryException.h"

namespace Rejistry {
    const std::string LHRecord::MAGIC = "lh";

    LHRecord::LHRecord(RegistryByteBuffer * buf, uint32_t offset) : DirectSubkeyListRecord(buf, offset, 0x8) {
        if (!(getMagic() == MAGIC)) {
            throw RegistryParseException("LHRecord magic value not found.");
        }
    }
};
