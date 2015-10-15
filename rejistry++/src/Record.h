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
 * \file Record.h
 *
 */
#ifndef _REJISTRY_RECORD_H
#define _REJISTRY_RECORD_H

#include <string>

// Local includes
#include "BinaryBlock.h"

namespace Rejistry {

    /**
     * Common base class for structures that are found within Cells.
     */
    class Record : public BinaryBlock {
    public:
        Record(RegistryByteBuffer * buf, uint32_t offset) : BinaryBlock(*buf, offset) { }
        
        virtual ~Record() {}
    
        /**
         * Get the magic bytes that determine the Record's type.
         * @returns A 2 character string that is the magic record header.
         * @throws RegistryParseException.
         */
        std::string getMagic() const;

    private:
        static const uint8_t MAGIC_OFFSET = 0x0;

    protected:
        Record() {};
        Record(const Record &) {};
        Record& operator=(const Record &);
    };

};

#endif
