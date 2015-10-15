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
 * \file RegistryHiveBuffer.cpp
 *
 */

// Local includes
#include "RegistryHiveBuffer.h"

namespace Rejistry {

    RegistryHiveBuffer::RegistryHiveBuffer(const uint8_t * buffer, const uint32_t size) {
        _buffer = new RegistryByteBuffer(new ByteBuffer(buffer, size));
    }

    RegistryHiveBuffer::~RegistryHiveBuffer() {
        if (_buffer != NULL) {
            delete _buffer;
            _buffer = NULL;
        }
    }

    RegistryKey * RegistryHiveBuffer::getRoot() const {
        return new RegistryKey(getHeader()->getRootNKRecord());
    }

    REGFHeader * RegistryHiveBuffer::getHeader() const {
        return new REGFHeader(*_buffer, 0x0);
    }
};
