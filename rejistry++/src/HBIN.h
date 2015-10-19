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
 * \file HBIN.h
 *
 */
#ifndef _REJISTRY_HBIN_H
#define _REJISTRY_HBIN_H

#include <cstdint>
#include <list>

// Local includes
#include "BinaryBlock.h"
#include "Cell.h"

namespace Rejistry {

    // Forward declaration for REGFHeader
    class REGFHeader;

    /**
     * Class that represents a Registry HBIN. HBIN is an allocation unit of
     * a registry hive that is usually 0x1000 bytes long.
     */
    class HBIN : public BinaryBlock {
    public:
        typedef HBIN * HBINPtr;
        typedef std::vector< HBINPtr > HBINPtrList;

        /**
            The AutoHBINPtrList class should be used by clients to hold lists of
            HBIN pointers returned by methods like REGFHeader::getHBINs()
            so that the record objects will be automatically freed. Example:
            @code
            AutoHBINPtrList hbinList(header->getHBINs());
            for (HBIN::HBINPtrList::iterator i = hbinList.begin(); i != hbinList.end(); ++i)
            { ... //do stuff }
            // Don't worry about delete'ing each record object--valueList will take care of
            // that when it goes out of scope.
            @endcode
        */
        class AutoHBINPtrList
        {
        public:

            AutoHBINPtrList(HBINPtrList recordList) : _recordList(recordList) {}
            ~AutoHBINPtrList()
            {
                for (HBINPtrList::iterator it = _recordList.begin(); it != _recordList.end(); ++it)
                {
                    delete *it;
                }
            }
            HBINPtrList::iterator begin() { return _recordList.begin(); }
            HBINPtrList::iterator end()   { return _recordList.end(); }
            HBINPtrList::size_type size() { return _recordList.size(); }
        private:
            AutoHBINPtrList(const AutoHBINPtrList&);
            AutoHBINPtrList& operator=(const AutoHBINPtrList&);

            HBINPtrList _recordList;
        };


        HBIN(const REGFHeader * header, RegistryByteBuffer * buf, uint32_t offset);
        
        virtual ~HBIN() {}
    
        /**
         * Gets the relative offset from the start of this HBIN to the
         * next HBIN structure.
         * @returns The relative offset to the next HBIN.
         */
        uint32_t getRelativeOffsetNextHBIN() const;

        /**
         * Gets the relative offset from the start of this HBIN to the
         * first HBIN in the hive.
         * @returns The relative offset to the first HBIN.
         */
        uint32_t getRelativeOffsetFirstHBIN() const;

        /**
         * Get all cells in this HBIN.
         * @returns A list of Cells. The caller is responsible for freeing
         * the memory associated with the cells.
         */
        Cell::CellPtrList getCells() const;

        /**
         * Get the cell at the given relative offset into this HBIN.
         * @param offset Relative offset into this HBIN.
         * @returns A pointer to the Cell at the given offset. The 
         * caller is responsible for freeing the memory associated with
         * the Cell.
         */
        Cell::CellPtr getCellAtOffset(uint32_t offset) const;

    private:
        static const uint8_t FIRST_HBIN_OFFSET_OFFSET = 0x4;
        static const uint8_t NEXT_HBIN_OFFSET_OFFSET = 0x8;
        static const uint8_t FIRST_CELL_OFFSET = 0x20;

        HBIN() {};
        HBIN(const HBIN &);
        HBIN& operator=(const HBIN &);

        const REGFHeader * _header;
    };
};

#endif
