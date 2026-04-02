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
 * \file HBIN.cpp
 *
 */

// Local includes
#include "HBIN.h"
#include "RejistryException.h"

namespace Rejistry {
    HBIN::HBIN(const REGFHeader * header, RegistryByteBuffer * buf, uint32_t offset) : BinaryBlock(*buf, offset) {
        _header = header;

        // offset is applied within getDWord by BinaryBlock
        if (getDWord(0x0) != 0x6E696268) {
            throw RegistryParseException("Invalid HBIN magic header.");
        }
    }
        
    uint32_t HBIN::getRelativeOffsetNextHBIN() const {
        return getDWord(NEXT_HBIN_OFFSET_OFFSET);
    }

    uint32_t HBIN::getRelativeOffsetFirstHBIN() const {
        return getDWord(FIRST_HBIN_OFFSET_OFFSET);
    }

    Cell::CellUniqPtrList HBIN::getCells() const {
        uint32_t nextCellOffset = FIRST_CELL_OFFSET;
        uint32_t hbinSize = getRelativeOffsetNextHBIN();

        std::vector <Cell::CellUniqPtr> cellList;
        do {
            auto nextCell =  std::make_unique<Cell>(_buf, getAbsoluteOffset(nextCellOffset));
            uint32_t cellLen = nextCell->getLength();
            if (cellLen == 0 || nextCellOffset + cellLen < nextCellOffset) {
                throw RegistryParseException("Invalid cell length.");
            }
            cellList.push_back(std::move(nextCell));
            nextCellOffset += cellLen;
            if (nextCellOffset > hbinSize) {
                break;
            }
        }
        while (nextCellOffset < hbinSize);

        return cellList;
    }

    Cell::CellUniqPtr HBIN::getCellAtOffset(uint32_t offset) const {
        return std::make_unique<Cell>(_buf, getAbsoluteOffset(offset));
    }
};
