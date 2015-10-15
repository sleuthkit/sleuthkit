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