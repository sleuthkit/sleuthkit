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
 * \file RegistryKey.h
 *
 */
#ifndef _REJISTRY_REGISTRYKEY_H
#define _REJISTRY_REGISTRYKEY_H

#include <string>
#include <vector>

// Local includes 
#include "RegistryValue.h"
#include "NKRecord.h"

namespace Rejistry {

    /**
     * Class that represents a Registry Key.
     */
    class RegistryKey {
    public:
        typedef RegistryKey * RegistryKeyPtr;
        typedef std::vector<RegistryKeyPtr> RegistryKeyPtrList;

        RegistryKey(NKRecord* nk) { _nk = nk; }
        RegistryKey(const RegistryKey& );
        RegistryKey& operator=(const RegistryKey &);

        virtual ~RegistryKey();

        uint64_t getTimestamp() const;

        /**
         * Get the name of this registry key.
         * @returns Key name
         */
        std::wstring getName() const;

        /**
         * Get the parent of the current registry key.
         * @returns Pointer to parent registry key.
         * @throws RegistryParseException if parent cannot be found.
         */
        RegistryKeyPtr getParent() const;

        /**
         * Get all subkeys for the current registry key.
         * @returns A collection of pointers to keys.
         * @throws RegistryParseException on error.
         */
        RegistryKeyPtrList getSubkeyList() const;

        /**
         * Get the subkey with the given name.
         * @param name ASCII name of the subkey of retrieve.
         * @returns Pointer to the subkey.
         * @throws RegistryParseException if subkey cannot be found.
         */
        RegistryKeyPtr getSubkey(const std::wstring& name) const;

        /**
         * Get all values for the current key.
         * @returns A collection of pointers to values.
         * @throws RegistryParseException on error.
         */
        RegistryValue::RegistryValuePtrList getValueList() const;

        /**
         * Get the value for the given name.
         * @param name ASCII name of the value to retrieve.
         * @returns Pointer to the value.
         * @throws RegistryParseException on error.
         */
        RegistryValue::RegistryValuePtr getValue(const std::wstring& name) const;

    private:
        RegistryKey();

        NKRecord * _nk;
    };
};

#endif
