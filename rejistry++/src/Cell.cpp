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
 * \file Cell.cpp
 *
 */
#include <cstdlib>

// Local includes
#include "Cell.h"
#include "LFRecord.h"
#include "LHRecord.h"
#include "RejistryException.h"

namespace Rejistry {

    uint32_t Cell::getLength() const {
        return std::abs((int)getDWord(LENGTH_OFFSET));
    }

    bool Cell::isActive() const {
        return ((int)getDWord(LENGTH_OFFSET) < 0x0);
    }

    std::vector<uint8_t> Cell::getData() const {
        return _buf->getData(getAbsoluteOffset(DATA_OFFSET), getLength() - DATA_OFFSET);
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
        return new LFRecord(_buf, getAbsoluteOffset(DATA_OFFSET));
    }

    SubkeyListRecord::SubkeyListRecordPtr Cell::getLHRecord() const {
        return new LHRecord(_buf, getAbsoluteOffset(DATA_OFFSET));
    }

    SubkeyListRecord::SubkeyListRecordPtr Cell::getRIRecord() const {
        return new RIRecord(_buf, getAbsoluteOffset(DATA_OFFSET));
    }

    LIRecord::LIRecordPtr Cell::getLIRecord() const {
        return new LIRecord(_buf, getAbsoluteOffset(DATA_OFFSET));
    }

    DBRecord::DBRecordPtr Cell::getDBRecord() const {
        return new DBRecord(_buf, getAbsoluteOffset(DATA_OFFSET));
    }

    DBIndirectRecord::DBIndirectRecordPtr Cell::getDBIndirectRecord() const {
        return new DBIndirectRecord(_buf, getAbsoluteOffset(DATA_OFFSET));
    }

    ValueListRecord::ValueListRecordPtr Cell::getValueListRecord(const uint32_t numValues) const {
        return new ValueListRecord(_buf, getAbsoluteOffset(DATA_OFFSET), numValues);
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
