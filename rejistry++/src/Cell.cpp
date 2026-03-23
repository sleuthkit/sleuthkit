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
 * \file Cell.cpp
 *
 */
#include <cstdlib>
#include <memory>

// Local includes
#include "Cell.h"
#include "LFRecord.h"
#include "LHRecord.h"
#include "RejistryException.h"

namespace Rejistry {

    uint32_t Cell::getLength() const {
        int32_t raw = (int32_t)getDWord(LENGTH_OFFSET);
        if (raw == (int32_t)0x80000000) {
            throw RegistryParseException("Invalid cell length.");
        }
        return (uint32_t)(raw < 0 ? -raw : raw);
    }

    bool Cell::isActive() const {
        return ((int)getDWord(LENGTH_OFFSET) < 0x0);
    }

    std::vector<uint8_t> Cell::getData() const {
        uint32_t len = getLength();
        if (len < DATA_OFFSET) {
            throw RegistryParseException("Cell length too small.");
        }
        return _buf->getData(getAbsoluteOffset(DATA_OFFSET), len - DATA_OFFSET);
    }

    std::string Cell::getDataSignature() const {
        return getASCIIString(DATA_OFFSET, 0x2);
    }

    uint64_t Cell::getDataQword() const {
        return getQWord(DATA_OFFSET);
    }

    NKRecord::NKRecordPtr Cell::getNKRecord() const {
        return new NKRecord(_buf, getAbsoluteOffset(DATA_OFFSET));
    }

    VKRecord::VKRecordPtr Cell::getVKRecord() const {
        return new VKRecord(_buf, getAbsoluteOffset(DATA_OFFSET));
    }

    SubkeyListRecord::SubkeyListRecordPtr Cell::getLFRecord() const {
        return std::make_unique<LFRecord>(_buf, getAbsoluteOffset(DATA_OFFSET));
    }

    SubkeyListRecord::SubkeyListRecordPtr Cell::getLHRecord() const {
        return std::make_unique<LHRecord>(_buf, getAbsoluteOffset(DATA_OFFSET));
    }

    SubkeyListRecord::SubkeyListRecordPtr Cell::getRIRecord() const {
        return std::make_unique<RIRecord>(_buf, getAbsoluteOffset(DATA_OFFSET));
    }

    SubkeyListRecord::SubkeyListRecordPtr Cell::getLIRecord() const {
        return std::make_unique<LIRecord>(_buf, getAbsoluteOffset(DATA_OFFSET));
    }

    DBRecord::DBRecordPtr Cell::getDBRecord() const {
        return std::make_unique<DBRecord>(_buf, getAbsoluteOffset(DATA_OFFSET));
    }

    DBIndirectRecord::DBIndirectRecordPtr Cell::getDBIndirectRecord() const {
        return std::make_unique<DBIndirectRecord>(_buf, getAbsoluteOffset(DATA_OFFSET));
    }

    ValueListRecord::ValueListRecordPtr Cell::getValueListRecord(const uint32_t numValues) const {
        return std::make_unique<ValueListRecord>(_buf, getAbsoluteOffset(DATA_OFFSET), numValues);
    }

    SubkeyListRecord::SubkeyListRecordPtr Cell::getSubkeyList() const {
        std::string magic = getDataSignature();

        if (magic == LFRecord::MAGIC) {
            return getLFRecord();
        }
        else if (magic == LHRecord::MAGIC) {
            return getLHRecord();
        }
        else if (magic == RIRecord::MAGIC) {
            return getRIRecord();
        }
        else if (magic == LIRecord::MAGIC) {
            return getLIRecord();
        }
        else {
            throw RegistryParseException("Unexpected subkey list type: " + magic);
        }
    }
};
