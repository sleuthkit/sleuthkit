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
 * \file RegistryValue.h
 *
 */
#ifndef _REJISTRY_REGISTRYVALUE_H
#define _REJISTRY_REGISTRYVALUE_H

#include <string>
#include <vector>

// Local includes
#include "ValueData.h"
#include "VKRecord.h"

namespace Rejistry {

    /**
     * Class that represents a Registry value.
     */
    class RegistryValue {
    public:

        typedef RegistryValue * RegistryValuePtr;
        typedef std::vector<RegistryValuePtr> RegistryValuePtrList;

        RegistryValue(VKRecord* vk) { _vk = vk; }
        RegistryValue(const RegistryValue& );

        virtual ~RegistryValue();
        
        /**
         * Get the name of this value.
         * @returns ASCII key name
         */
        std::wstring getName() const;

        /**
         * Get the type of this value.
         * @returns Enum type of value.
         */
        ValueData::VALUE_TYPES getValueType() const;

        /**
         * Get the value data.
         * @returns Pointer to the value data.
         * @throws RegistryParseException on error.
         */
        ValueData * getValue() const;

    private:
        RegistryValue();
        RegistryValue& operator=(const RegistryValue &);

        VKRecord * _vk;
    };
};

#endif
