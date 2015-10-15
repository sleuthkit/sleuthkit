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
 * \file Cell.h
 *
 */
#ifndef _REJISTRY_CELL_H
#define _REJISTRY_CELL_H

#include <cstdint>
#include <string>

// Local includes
#include "BinaryBlock.h"
#include "RegistryByteBuffer.h"
#include "NKRecord.h"
#include "VKRecord.h"
#include "ValueListRecord.h"
#include "SubkeyListRecord.h"
#include "RIRecord.h"
#include "LIRecord.h"
#include "DBIndirectRecord.h"
#include "DBRecord.h"

namespace Rejistry {

    /**
     * Class that represents a Registry cell.
     */
    class Cell : public BinaryBlock {
    public:
        typedef Cell * CellPtr;
        typedef std::vector< CellPtr > CellPtrList;

        /**
            The AutoCellPtrList class should be used by clients to hold lists of
            Cell pointers returned by methods like HBIN::getCells()
            so that the record objects will be automatically freed. Example:
            @code
            AutoCellPtrList cellList(hbin->getCells());
            for (Cell::CellPtrList::iterator i = cellList.begin(); i != cellList.end(); ++i)
            { ... //do stuff }
            // Don't worry about delete'ing each record object--valueList will take care of
            // that when it goes out of scope.
            @endcode
        */
        class AutoCellPtrList
        {
        public:

            AutoCellPtrList(CellPtrList recordList) : _recordList(recordList) {}
            ~AutoCellPtrList()
            {
                for (CellPtrList::iterator it = _recordList.begin(); it != _recordList.end(); ++it)
                {
                    delete *it;
                }
            }
            CellPtrList::iterator begin() { return _recordList.begin(); }
            CellPtrList::iterator end()   { return _recordList.end(); }
            CellPtrList::size_type size() { return _recordList.size(); }
        private:
            AutoCellPtrList(const AutoCellPtrList&);
            AutoCellPtrList& operator=(const AutoCellPtrList&);

            CellPtrList _recordList;
        };


        Cell(RegistryByteBuffer * buf, const uint32_t offset) : BinaryBlock(*buf, offset) {} 
        
        virtual ~Cell() {};

        /**
         * Get the size of the cell.
         * @returns Cell length.
         */
        uint32_t getLength() const;

        /**
         * Does the cell contain active content.
         * @returns true if the cell is active, otherwise false.
         */
        bool isActive() const;

        /**
         * Gets the data for this cell.
         * @returns A vector containing the cell data.
         */
        std::vector<uint8_t> getData() const;

        /**
         * Gets the first 2 bytes of the data of this cell and interprets
         * them as the ASCII magic header of a sub-structure.
         * @returns The 2 character string that identifies the substructure.
         */
        std::string getDataSignature() const;

        /**
         * Gets the first eight bytes of the data of this cell and interprets
         * it as a little endian QWORD.
         * @returns The first 8 bytes of the cell as a little endian QWORD.
         */
        uint64_t getDataQword() const;

        /**
         * Interprets the cell data as an NKRecord and returns it.
         * @returns Pointer to an NKRecord object. Caller is responsible for freeing.
         * @throws RegistryParseException
         */
        NKRecord::NKRecordPtr getNKRecord() const;

        /**
         * Interprets the cell data as an VKRecord and returns it.
         * @returns Pointer to an VKRecord object.
         * @throws RegistryParseException
         */
        VKRecord::VKRecordPtr getVKRecord() const;

        /**
         * Interprets the cell data as an LFRecord and returns it.
         * @returns Pointer to an LFRecord object.
         * @throws RegistryParseException
         */
        SubkeyListRecord::SubkeyListRecordPtr getLFRecord() const;

        /**
         * Interprets the cell data as an LHRecord and returns it.
         * @returns Pointer to an LHRecord object.
         * @throws RegistryParseException
         */
        SubkeyListRecord::SubkeyListRecordPtr getLHRecord() const;

        /**
         * Interprets the cell data as an RIRecord and returns it.
         * @returns Pointer to an RIRecord object.
         * @throws RegistryParseException
         */
        SubkeyListRecord::SubkeyListRecordPtr getRIRecord() const;

        /**
         * Interprets the cell data as an LIRecord and returns it.
         * @returns Pointer to an LIRecord object.
         * @throws RegistryParseException
         */
        LIRecord::LIRecordPtr getLIRecord() const;

        /**
         * Interprets the cell data as an DBRecord and returns it.
         * @returns Pointer to an DBRecord object.
         * @throws RegistryParseException
         */
        DBRecord::DBRecordPtr getDBRecord() const;

        /**
         * Interprets the cell data as an DBIndirectRecord and returns it.
         * @returns Pointer to an DBIndirectRecord object.
         * @throws RegistryParseException
         */
        DBIndirectRecord::DBIndirectRecordPtr getDBIndirectRecord() const;

        /**
         * Interprets the cell data as an ValueListRecord and returns it.
         * @param numValues The number of values the value list should attempt
         * to parse.
         * @returns Pointer to an ValueListRecord object. The caller is responsible
         * for freeing the returned record.
         * @throws RegistryParseException
         */
        ValueListRecord::ValueListRecordPtr getValueListRecord(const uint32_t numValues) const;

        /**
         * Interprets the cell data as a SubkeyList and returns it.
         * @returns Pointer to an SubkeyList object.
         * @throws RegistryParseException
         */
        SubkeyListRecord::SubkeyListRecordPtr getSubkeyList() const;

    private:
        Cell() {};

        static const uint8_t LENGTH_OFFSET = 0x0;
        static const uint8_t DATA_OFFSET = 0x4;
    };
};

#endif
