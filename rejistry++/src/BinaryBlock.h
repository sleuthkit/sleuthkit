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
 * \file BinaryBlock.h
 *
 */
#ifndef _REJISTRY_BINARYBLOCK_H
#define _REJISTRY_BINARYBLOCK_H

#include <cstdint>

// Local includes
#include "RegistryByteBuffer.h"

namespace Rejistry {

    /**
     *
     */
    class BinaryBlock {
    public:
        BinaryBlock(RegistryByteBuffer& buf, uint32_t offset) {
            _buf = &buf;
            _offset = offset;
        }

    private:

    protected:
        BinaryBlock() {};

        RegistryByteBuffer * _buf;
        uint32_t _offset;

        uint16_t getWord(uint32_t offset) const;

        uint32_t getDWord(uint32_t offset) const;

        uint64_t getQWord(uint32_t offset) const;
        
        std::string getASCIIString(uint32_t offset, uint32_t length) const;

        std::wstring getUTF16String(uint32_t offset, uint32_t length) const;

        uint32_t getAbsoluteOffset(uint32_t offset) const;

        ByteBuffer::ByteArray getData(uint32_t offset, uint32_t length) const;
    };
};

#endif
