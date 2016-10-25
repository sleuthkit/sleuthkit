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

        /**
         * Get the length of the value in bytes.
         * @returns The length of the value in bytes.
         */
        uint32_t getValueLength() const;

    private:
        RegistryValue();
        RegistryValue& operator=(const RegistryValue &);

        VKRecord * _vk;
    };
};

#endif
