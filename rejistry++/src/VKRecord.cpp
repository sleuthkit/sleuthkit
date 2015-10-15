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
 * \file VKRecord.cpp
 *
 */

// Local includes
#include "VKRecord.h"
#include "RejistryException.h"
#include "REGFHeader.h"

namespace Rejistry {

    const std::string VKRecord::MAGIC = "vk";

    VKRecord::VKRecord(RegistryByteBuffer * buf, uint32_t offset) : Record(buf, offset) {
        if (!(getMagic() == MAGIC)) {
            throw RegistryParseException("VKRecord magic value not found.");
        }
    }

    bool VKRecord::hasName() const {
        return (getWord(NAME_LENGTH_OFFSET) != 0x0);
    }

    bool VKRecord::hasAsciiName() const {
        return (getWord(NAME_FLAGS_OFFSET) & 0x1) == 0x1;
    }

    std::wstring VKRecord::getName() const {
        if (! hasName()) {
            return L"";
        }

        uint32_t nameLength = getWord(NAME_LENGTH_OFFSET);
        if (hasAsciiName()) {
            // TODO: This is a little hacky but it should work fine
            // for ASCII strings.
            std::string name = getASCIIString(NAME_OFFSET_OFFSET, nameLength);
            return std::wstring(name.begin(), name.end());
        }

        return getUTF16String(NAME_OFFSET_OFFSET, nameLength);
    }

    ValueData::VALUE_TYPES VKRecord::getValueType() const {
        return (ValueData::VALUE_TYPES)getDWord(VALUE_TYPE_OFFSET);
    }

    uint32_t VKRecord::getDataLength() const {
        uint32_t size = getDWord(DATA_LENGTH_OFFSET);
        if (size > LARGE_DATA_SIZE){
            size -= LARGE_DATA_SIZE;
        }
        return size;
    }

    uint32_t VKRecord::getRawDataLength() const {
        return getDWord(DATA_LENGTH_OFFSET);
    }

    uint32_t VKRecord::getDataOffset() const {
        if (getRawDataLength() < SMALL_DATA_SIZE || getRawDataLength() >= LARGE_DATA_SIZE) {
            return _offset + DATA_OFFSET_OFFSET;
        } else {
            return REGFHeader::FIRST_HBIN_OFFSET + getDWord(DATA_OFFSET_OFFSET);
        }

    }

    ValueData::ValueDataPtr VKRecord::getValue() const {
        uint32_t length = getRawDataLength();
        uint32_t offset = getDataOffset();

        if (length > LARGE_DATA_SIZE + DB_DATA_SIZE) {
            throw RegistryParseException("Value size too large.");
        }

        RegistryByteBuffer * data = NULL;

        switch (getValueType()) {
        case ValueData::VALTYPE_BIN:
        case ValueData::VALTYPE_NONE:
        case ValueData::VALTYPE_SZ:
        case ValueData::VALTYPE_EXPAND_SZ:
        case ValueData::VALTYPE_MULTI_SZ:
        case ValueData::VALTYPE_LINK:
        case ValueData::VALTYPE_RESOURCE_LIST:
        case ValueData::VALTYPE_FULL_RESOURCE_DESCRIPTOR:
        case ValueData::VALTYPE_RESOURCE_REQUIREMENTS_LIST:

            if (length >= LARGE_DATA_SIZE) {
                uint32_t bufSize = length - LARGE_DATA_SIZE;
                data = new RegistryByteBuffer(new ByteBuffer(getData(DATA_OFFSET_OFFSET, bufSize), bufSize));
            }
            else if (DB_DATA_SIZE < length && length < LARGE_DATA_SIZE) {
                std::auto_ptr< Cell > c(new Cell(_buf, offset));

            }
            else {
                std::auto_ptr< Cell > c(new Cell(_buf, offset));
                if (c.get() == NULL) {
                    throw RegistryParseException("Failed to create Cell for Value data.");
                }
                ByteBuffer * byteBuffer = new ByteBuffer(c->getData(), length);
                data = new RegistryByteBuffer(byteBuffer);
            }
            break;
        case ValueData::VALTYPE_DWORD:
        case ValueData::VALTYPE_BIG_ENDIAN:
            data = new RegistryByteBuffer(new ByteBuffer(getData(DATA_OFFSET_OFFSET, 0x4), 0x4));
            break;
        case ValueData::VALTYPE_QWORD:
            data = new RegistryByteBuffer(new ByteBuffer(getData(DATA_OFFSET_OFFSET, 0x8), 0x8));
            break;
        default:
            throw RegistryParseException("Unknown value type.");
        }

        return new ValueData(data, getValueType());                                                            
    }
};
