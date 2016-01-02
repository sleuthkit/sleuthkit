/*
 *
 * The Sleuth Kit
 *
 * Copyright 2013-2015 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This is a C++ port of the Rejistry library developed by Willi Ballenthin.
 * See https://github.com/williballenthin/Rejistry for the original Java version.
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
    const std::wstring VKRecord::DEFAULT_VALUE_NAME = L"(Default)";

    VKRecord::VKRecord(RegistryByteBuffer * buf, uint32_t offset) : Record(buf, offset) {
        if (!(getMagic() == MAGIC)) {
            throw RegistryParseException("VKRecord magic value not found.");
        }
    }

    VKRecord::VKRecord(const VKRecord& sourceRecord) : Record(sourceRecord._buf, sourceRecord._offset) {        
    }

    bool VKRecord::hasName() const {
        return (getWord(NAME_LENGTH_OFFSET) != 0x0);
    }

    bool VKRecord::hasAsciiName() const {
        return (getWord(NAME_FLAGS_OFFSET) & 0x1) == 0x1;
    }

    std::wstring VKRecord::getName() const {
        if (! hasName()) {
            return VKRecord::DEFAULT_VALUE_NAME;
        }

        uint32_t nameLength = getWord(NAME_LENGTH_OFFSET);

        if (nameLength > MAX_NAME_LENGTH) {
            throw RegistryParseException("Value name length exceeds maximum length.");
        }

        if (hasAsciiName()) {
            // TODO: This is a little hacky but it should work fine
            // for ASCII strings.
            std::vector<uint8_t> name = getData(NAME_OFFSET_OFFSET, nameLength);
            return std::wstring(name.begin(), name.end());
        }

        return getUTF16String(NAME_OFFSET_OFFSET, nameLength);
    }

    ValueData::VALUE_TYPES VKRecord::getValueType() const {
        return (ValueData::VALUE_TYPES)getDWord(VALUE_TYPE_OFFSET);
    }

    uint32_t VKRecord::getDataLength() const {
        uint32_t size = getDWord(DATA_LENGTH_OFFSET);
        if (size >= LARGE_DATA_SIZE){
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
                if (c.get() == NULL) {
                    throw RegistryParseException("Failed to create Cell for Value data.");
                }
                try {
                    std::auto_ptr< DBRecord > db(c->getDBRecord());
                    if (db.get() == NULL) {
                        throw RegistryParseException("Failed to create Cell for DBRecord.");
                    }
                    data = new RegistryByteBuffer(new ByteBuffer(db->getData(length), length));
                }
                catch (RegistryParseException& ) {
                    data = new RegistryByteBuffer(new ByteBuffer(c->getData(), length));
                }
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
            {
                std::auto_ptr< Cell > c(new Cell(_buf, offset));
                if (c.get() == NULL) {
                    throw RegistryParseException("Failed to create Cell for Value data.");
                }
                ByteBuffer * byteBuffer = new ByteBuffer(c->getData(), length);
                data = new RegistryByteBuffer(byteBuffer);
            }
            break;
        default:
            // Unknown registry type. Create an empty buffer.
            data = new RegistryByteBuffer(new ByteBuffer(0));
        }

        return new ValueData(data, getValueType());                                                            
    }
};
