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
 * \file BinaryBlock.cpp
 *
 */

// Local includes
#include "BinaryBlock.h"

namespace Rejistry {

    uint16_t BinaryBlock::getWord(uint32_t offset) const {
        return _buf->getWord(_offset + offset);
    }

    uint32_t BinaryBlock::getDWord(uint32_t offset) const {
        return _buf->getDWord(_offset + offset);
    }

    uint64_t BinaryBlock::getQWord(uint32_t offset) const {
        return _buf->getQWord(_offset + offset);
    }

    std::string BinaryBlock::getASCIIString(uint32_t offset, uint32_t length) const {
        return _buf->getASCIIString(_offset + offset, length);
    }

    std::wstring BinaryBlock::getUTF16String(uint32_t offset, uint32_t length) const {
        return _buf->getUTF16String(_offset + offset, length);
    }

    uint32_t BinaryBlock::getAbsoluteOffset(uint32_t offset) const {
        return _offset + offset;
    }

    ByteBuffer::ByteArray BinaryBlock::getData(uint32_t offset, uint32_t length) const {
        return _buf->getData(_offset + offset, length);
    }
};
