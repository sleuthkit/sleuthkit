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
 * \file RegistryHive.h
 * Main interface for first interaction with Registry hives.
 */
#ifndef _REJISTRY_REGISTRYHIVE_H
#define _REJISTRY_REGISTRYHIVE_H

#include "REGFHeader.h"
#include "RegistryKey.h"

namespace Rejistry {

    /**
     *
     */
    class RegistryHive {
    public:
        /**
         * Get the root key for this hive.
         */
        virtual RegistryKey * getRoot() const = 0;

        /**
         * Get the header for this hive.
         */
        virtual REGFHeader * getHeader() const = 0;

    };
};

#endif