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
 * \file RegistryHiveBuffer.h
 *
 */
#ifndef _REJISTRY_REGISTRYHIVEBUFFER_H
#define _REJISTRY_REGISTRYHIVEBUFFER_H

#include <cstdint>

// Local includes
#include "RegistryHive.h"

namespace Rejistry {

    /**
     * An implementation of the RegistryHive interface that uses
     * an existing in-memory buffer.
     */
    class RegistryHiveBuffer : public RegistryHive {
    public:
        /**
         * Create a RegistryHiveBuffer instance for the given buffer.
         * The new RegistryHiveBuffer will make a copy of the buffer
         * so the client is free to delete it at any time.
         * @param buffer Pointer to the in-memory buffer to use.
         * @param size Size of the buffer in bytes.
         */
        RegistryHiveBuffer(const uint8_t * buffer, const uint32_t size);

        virtual ~RegistryHiveBuffer();

        virtual RegistryKey * getRoot() const;
        virtual REGFHeader * getHeader() const;

    private:
        RegistryHiveBuffer();
        RegistryHiveBuffer(const RegistryHiveBuffer &);
        RegistryHiveBuffer& operator=(const RegistryHiveBuffer &);

        RegistryByteBuffer * _buffer;
    };
};

#endif
