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
#include <memory>
#include <algorithm>

// Local includes
#include "VKRecord.h"
#include "RejistryException.h"
#include "REGFHeader.h"

namespace Rejistry {

    namespace {
        /**
         * Wrap a value's data bytes. A malformed hive can declare a data length
         * larger than the cell(s) that hold the data, so return only the bytes
         * that are actually present, never more than the declared length.
         * Callers can detect truncation by comparing the returned data size
         * with VKRecord::getDataLength().
         */
        std::unique_ptr<RegistryByteBuffer> makeDataBuffer(const ByteBuffer::ByteArray& bytes, uint32_t declaredLength) {
            uint32_t safeLength = std::min(declaredLength, static_cast<uint32_t>(bytes.size()));
            return std::make_unique<RegistryByteBuffer>(std::make_unique<ByteBuffer>(bytes, safeLength));
        }
    }

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
        uint32_t numOfChars = hasAsciiName() ? nameLength : (nameLength / 2); // CT-2984

        if (numOfChars > MAX_NAME_LENGTH) {
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
        return (ValueData::VALUE_TYPES)(getDWord(VALUE_TYPE_OFFSET) & 0x0000FFFF);
    }

    uint32_t VKRecord::getDataLength() const {
        // Clear the DATA_STORED_INLINE flag, if set; the rest is the length.
        return getDWord(DATA_LENGTH_OFFSET) & ~DATA_STORED_INLINE;
    }

    uint32_t VKRecord::getRawDataLength() const {
        return getDWord(DATA_LENGTH_OFFSET);
    }

    uint32_t VKRecord::getDataOffset() const {
        uint32_t rawLength = getRawDataLength();
        if ((rawLength & DATA_STORED_INLINE) != 0 || rawLength < SMALL_DATA_SIZE) {
            // The data is in the record's own data offset field.
            return _offset + DATA_OFFSET_OFFSET;
        } else {
            return REGFHeader::FIRST_HBIN_OFFSET + getDWord(DATA_OFFSET_OFFSET);
        }

    }

    ValueData::ValueDataUniqPtr VKRecord::getValue() const {
        // The raw data length field: the DATA_STORED_INLINE flag plus the length.
        // When the flag is clear, as in every branch below except the inline
        // ones, it is just the length.
        uint32_t length = getRawDataLength();
        uint32_t offset = getDataOffset();
        bool storedInline = (length & DATA_STORED_INLINE) != 0;

        if (storedInline && (length & ~DATA_STORED_INLINE) > DB_DATA_SIZE) {
            throw RegistryParseException("Value size too large.");
        }

        std::unique_ptr<RegistryByteBuffer> data = nullptr;

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

            if (storedInline) {
                // Stored inline: the data is in the record's data offset field.
                uint32_t bufSize = length & ~DATA_STORED_INLINE;
                data = std::make_unique<RegistryByteBuffer>(std::make_unique<ByteBuffer>(getData(DATA_OFFSET_OFFSET, bufSize), bufSize));
            }
            else if (length > DB_DATA_SIZE) {
                // Data larger than DB_DATA_SIZE is stored one of two ways, depending
                // on the hive format version:
                //   - 1.3 and earlier: the whole value in a single data cell.
                //   - 1.4 and later: a small "db" record pointing to a list of data
                //     segments (see DBRecord and DBIndirectRecord).
                // The hive version isn't checked here, so the cell itself decides.
                // The "db" signature alone isn't enough: in a 1.3 hive, a value whose
                // data happens to start with the bytes 'd' 'b' (0x64 0x62) would be
                // misread as a db record and fail to parse. A real db record's cell
                // is tiny, while a single-cell value holds at least the declared
                // length, so a "db" cell that big is the value data itself.
                auto c = std::make_unique< Cell >(_buf, offset);
                DBRecord::DBRecordPtr db;
                try {
                    db = c->getDBRecord();
                }
                catch (RegistryParseException& ) {
                    // No "db" signature: the data is stored directly in this cell.
                }

                if (db) {
                    ByteBuffer::ByteArray cellData;
                    try {
                        cellData = c->getData();
                    }
                    catch (RegistryParseException& ) {
                        // The cell's length field is unusable, so it can't be a
                        // single-cell value; treat it as a db record.
                    }

                    if (cellData.size() >= length) {
                        // Single-cell (format 1.3) value whose data starts with "db".
                        data = makeDataBuffer(cellData, length);
                    }
                    else {
                        data = makeDataBuffer(db->getData(length), length);
                    }
                }
                else {
                    data = makeDataBuffer(c->getData(), length);
                }
            }
            else {
                // Up to DB_DATA_SIZE bytes: the data is in a single cell.
                auto c = std::make_unique< Cell >(_buf, offset);
                data = makeDataBuffer(c->getData(), length);
            }
            break;
        case ValueData::VALTYPE_DWORD:
        case ValueData::VALTYPE_BIG_ENDIAN:
            data = std::make_unique<RegistryByteBuffer>(std::make_unique<ByteBuffer>(getData(DATA_OFFSET_OFFSET, 0x4), 0x4));
            break;
        case ValueData::VALTYPE_QWORD:
        case ValueData::VALTYPE_FILETIME:
            {
                uint32_t dataLen = getDataLength();
                if (storedInline) {
                    // Data is stored inline in the VK record (≤4 bytes).
                    // Malformed QWORD/FILETIME — getAsNumber() will return 0.
                    data = std::make_unique<RegistryByteBuffer>(
                        std::make_unique<ByteBuffer>(getData(DATA_OFFSET_OFFSET, dataLen), dataLen));
                }
                else {
                    auto c = std::make_unique<Cell>(_buf, offset);
                    data = makeDataBuffer(c->getData(), length);
                }
            }
            break;
        default:
            // Unknown registry type. Create an empty buffer.
            data = std::make_unique<RegistryByteBuffer>(std::make_unique<ByteBuffer>(0));
        }

        return std::make_unique<ValueData>(std::move(data), getValueType());                                                            
    }
};
