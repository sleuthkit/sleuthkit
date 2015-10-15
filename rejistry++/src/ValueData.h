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
 * \file ValueData.h
 *
 */
#ifndef _REJISTRY_VALUEDATA_H
#define _REJISTRY_VALUEDATA_H

#include <string>
#include <list>
#include <cstdint>

// Local includes
#include "RegistryByteBuffer.h"

namespace Rejistry {

    /**
     * Class that represents the actual data associated
     * with a registry value.
     */
    class ValueData {
    public:
        typedef ValueData * ValueDataPtr;

        enum VALUE_TYPES {
            VALTYPE_NONE = 0,
            VALTYPE_SZ,
            VALTYPE_EXPAND_SZ,
            VALTYPE_BIN,
            VALTYPE_DWORD,
            VALTYPE_BIG_ENDIAN,
            VALTYPE_LINK,
            VALTYPE_MULTI_SZ,
            VALTYPE_RESOURCE_LIST,
            VALTYPE_FULL_RESOURCE_DESCRIPTOR,
            VALTYPE_RESOURCE_REQUIREMENTS_LIST,
            VALTYPE_QWORD
        };

        /// Map the value type enum to a string.
        static std::wstring getValueType(ValueData::VALUE_TYPES type);

        ValueData(RegistryByteBuffer * buf, const VALUE_TYPES type) {
            _buf = buf;
            _type = type;
        }
        
        VALUE_TYPES getValueType() const { return _type; };

        /**
         * Get the data as a string if the underlying registry data type 
         * is compatible.
         * @returns Data as UTF16 little endian string.
         * @throws 
         */
        std::wstring getAsString() const;

        /**
         * Get the data as a list of strings if the underlying registry 
         * data type is compatible. Data that can be parsed as a string
         * is returned in a list with one entry
         * @returns Data as a list of UTF16 little endian strings.
         * @throws 
         */
        std::vector<std::wstring> getAsStringList() const;

        /**
         * Get the raw binary data from this value.
         * @returns Pointer to a buffer containing the data.
         */
        ByteBuffer::ByteArray getAsRawData() const;

        /**
         * Get the data from this value as a number if the underlying
         * registry type is compatible.
         * @returns Numeric representation of the value.
         * @throws
         */
        uint64_t getAsNumber() const;

    private:
        ValueData();
        ValueData(const ValueData &);
        ValueData& operator=(const ValueData &);

        RegistryByteBuffer * _buf;
        VALUE_TYPES _type;
    };
};

#endif
