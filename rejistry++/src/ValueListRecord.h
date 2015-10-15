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
 * \file ValueListRecord.h
 *
 */
#ifndef _REJISTRY_VALUELISTRECORD_H
#define _REJISTRY_VALUELISTRECORD_H

#include <cstdint>
#include <string>

// Local includes
#include "Record.h"
#include "VKRecord.h"

namespace Rejistry {

    /**
     */
    class ValueListRecord : public Record {
    public:
        typedef ValueListRecord * ValueListRecordPtr;

        ValueListRecord(RegistryByteBuffer * buf, uint32_t offset, uint32_t numValues);
        
        virtual ~ValueListRecord() {}
    
        /**
         * @returns The list of value records. The caller is responsible
         * for freeing these records.
         */
        virtual VKRecord::VKRecordPtrList getValues() const;

        /**
         * Fetch the value with the given name from the value list.
         * @param name The name of the value to fetch.
         * @returns The matching value record. The caller is responsible
         * for freeing this record.
         */
        VKRecord::VKRecordPtr getValue(const std::wstring& name) const;

    private:
        static const uint16_t VALUE_LIST_OFFSET = 0x00;

        uint32_t _numValues;

    protected:
        ValueListRecord() {};
        ValueListRecord(const ValueListRecord &);
        ValueListRecord& operator=(const ValueListRecord &);

    };
};

#endif
