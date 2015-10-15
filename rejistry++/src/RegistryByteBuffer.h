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
 * \file RegistryByteBuffer.h
 *
 */
#ifndef _REJISTRY_REGISTRYBYTEBUFFER_H
#define _REJISTRY_REGISTRYBYTEBUFFER_H

#include <cstdint>

// Local includes
#include "ByteBuffer.h"

namespace Rejistry {

    /**
     *
     */
    class RegistryByteBuffer {
    public:
        RegistryByteBuffer(ByteBuffer * buffer);
        virtual ~RegistryByteBuffer();

        uint16_t getWord(const uint32_t offset) const;

        uint32_t getDWord(const uint32_t offset) const;

        uint64_t getQWord(const uint32_t offset) const;

        std::string getASCIIString() const;
        std::string getASCIIString(const uint32_t offset, const uint32_t length) const;

        std::wstring getUTF16String() const;
        std::wstring getUTF16String(const uint32_t offset, const uint32_t length) const;

        ByteBuffer::ByteArray getData() const;
        ByteBuffer::ByteArray getData(const uint32_t offset, const uint32_t length) const;

        std::vector<std::wstring> getStringList() const;
        std::vector<std::wstring> getStringList(const uint32_t offset, const uint32_t length) const;

    private:
        RegistryByteBuffer();
        RegistryByteBuffer(const RegistryByteBuffer &);
        RegistryByteBuffer& operator=(const RegistryByteBuffer &);

        ByteBuffer * _byteBuffer;

    };
};

#endif
