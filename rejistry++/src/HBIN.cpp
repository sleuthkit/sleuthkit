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
 * \file HBIN.cpp
 *
 */

// Local includes
#include "HBIN.h"
#include "RejistryException.h"

namespace Rejistry {
    HBIN::HBIN(const REGFHeader * header, RegistryByteBuffer * buf, uint32_t offset) : BinaryBlock(*buf, offset) {
        _header = header;

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

    Cell::CellPtrList HBIN::getCells() const {
        uint32_t nextCellOffset = FIRST_CELL_OFFSET;
        Cell::CellPtrList cellList;

        do {
            Cell::CellPtr nextCell = new Cell(_buf, getAbsoluteOffset(nextCellOffset));
            cellList.push_back(nextCell);
            nextCellOffset += nextCell->getLength();
        }
        while (nextCellOffset < getRelativeOffsetNextHBIN());

        return cellList;
    }

    Cell::CellPtr HBIN::getCellAtOffset(uint32_t offset) const {
        return new Cell(_buf, getAbsoluteOffset(offset));
    }
};
