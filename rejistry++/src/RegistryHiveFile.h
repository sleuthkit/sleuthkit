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
 * \file RegistryHiveFile.h
 *
 */
#ifndef _REJISTRY_REGISTRYHIVEFILE_H
#define _REJISTRY_REGISTRYHIVEFILE_H

// Local includes
#include "RegistryHive.h"

namespace Rejistry {

    /**
     * An implementation of the RegistryHive interface that uses
     * an underlying registry file on disk.
     */
    class RegistryHiveFile : public RegistryHive {
    public:
        RegistryHiveFile(const std::wstring& filePath);

        virtual ~RegistryHiveFile();

        virtual RegistryKey * getRoot() const;
        virtual REGFHeader * getHeader() const;

    private:
        RegistryHiveFile();
        RegistryHiveFile(const RegistryHiveFile &);
        RegistryHiveFile& operator=(const RegistryHiveFile &);


        RegistryByteBuffer * _buffer;

        std::string getErrorMessage() const;
    };
};

#endif
