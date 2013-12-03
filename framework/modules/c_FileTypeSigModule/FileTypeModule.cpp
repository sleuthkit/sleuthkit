/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file FileTypeSigModule.cpp
 * Contains the module that uses libmagic to determine the
 * file type based on signatures.
 */

// System includes
#include <string>
#include <sstream>
#include <stdlib.h>
#include <string.h>

// Framework includes
#include "tsk/framework/utilities/TskModuleDev.h"

// Poco includes
#include "Poco/UnicodeConverter.h"
#include "Poco/File.h"
#include "Poco/Path.h"

// Magic includes
#include "magic.h"

namespace 
{
    const char *MODULE_NAME = "tskFileTypeSigModule";
    const char *MODULE_DESCRIPTION = "Determines file type based on signature using libmagic";
    const char *MODULE_VERSION = "1.0.3";

  static const uint32_t FILE_BUFFER_SIZE = 1024;

  static magic_t magicHandle = NULL;
}

extern "C" 
{
    /**
     * Module identification function. 
     *
     * @return The name of the module.
     */
    TSK_MODULE_EXPORT const char *name() 
    {
        return MODULE_NAME;
    }

    /**
     * Module identification function. 
     *
     * @return A description of the module.
     */
    TSK_MODULE_EXPORT const char *description()
    {
        return MODULE_DESCRIPTION;
    }

    /**
     * Module identification function. 
     *
     * @return The version of the module.
     */
    TSK_MODULE_EXPORT const char *version()
    {
        return MODULE_VERSION;
    }

    /**
     * Module initialization function. Takes a string as input that allows
     * arguments to be passed into the module.
     * @param arguments Tells the module which
     */
    TskModule::Status TSK_MODULE_EXPORT initialize(const char* arguments)
    {
        magicHandle = magic_open(MAGIC_NONE);
        if (magicHandle == NULL) {
            LOGERROR("FileTypeSigModule: Error allocating magic cookie.");
            return TskModule::FAIL;
        }

//Attempt to load magic database from default places on Linux.
//Don't bother trying magic_load() for defaults on win32 because it will always cause an exception instead of gracefully returning.
#ifndef TSK_WIN32
        /* Load the default magic database, which is found in this order:
               1. MAGIC env variable
               2. $HOME/.magic.mgc (or $HOME/.magic dir)
               3. /usr/share/misc/magic.mgc (or /usr/share/misc/magic dir) (unless libmagic was build configured abnormally)
        */
        if (magic_load(magicHandle, NULL)) {
            std::stringstream msg;
            msg << "FileTypeSigModule: Error loading default magic file: " << magic_error(magicHandle);
            LOGERROR(msg.str());
            //don't return, just fall through to the default loading below
        } else {
            return TskModule::OK;
        }
#endif
        //Load the magic database file in the repo
        std::string path = GetSystemProperty(TskSystemProperties::MODULE_CONFIG_DIR) + Poco::Path::separator() + MODULE_NAME + Poco::Path::separator() + "magic.mgc";

        Poco::File magicFile = Poco::File(path);
        if (magicFile.exists() == false) {
            std::stringstream msg;
            msg << "FileTypeSigModule: Magic file not found: " << path;
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }

        if (magic_load(magicHandle, path.c_str())) {
            std::stringstream msg;
            msg << "FileTypeSigModule: Error loading magic file: " << magic_error(magicHandle) << GetSystemProperty(TskSystemProperties::MODULE_CONFIG_DIR);
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }

        return TskModule::OK;
    }

    /**
     * The run() method is where the module's work is performed.
     * The module will be passed a pointer to a file from which both
     * content and metadata can be retrieved.
     * @param pFile A pointer to a file to be processed.
     * @returns TskModule::OK on success and TskModule::FAIL on error.
     */
    TskModule::Status TSK_MODULE_EXPORT run(TskFile * pFile)
    {
        if (pFile == NULL)
        {
            LOGERROR("FileTypeSigModule: Passed NULL file pointer.");
            return TskModule::FAIL;
        }

        if (pFile->getSize() == 0)
            return TskModule::OK;

        try
        {
            char buffer[FILE_BUFFER_SIZE];

            //Do that magic magic
            ssize_t readLen = pFile->read(buffer, FILE_BUFFER_SIZE);
            // we shouldn't get zero as a return value since we know the file is not 0 sized at this point
            if (readLen <= 0) {
                std::stringstream msg;
                msg << "FileTypeSigModule: Error reading file contents for file " << pFile->getId();
                LOGERROR(msg.str());
                return TskModule::FAIL;
            }

            const char *type = magic_buffer(magicHandle, buffer, readLen);
            if (type == NULL) {
                std::stringstream msg;
                msg << "FileTypeSigModule: Error getting file type: " << magic_error(magicHandle);
                LOGERROR(msg.str());
                return TskModule::FAIL;
            }

            // clean up type -- we've seen invalid UTF-8 data being returned
            char cleanType[1024];
            cleanType[1023] = '\0';
            strncpy(cleanType, type, 1023);
            TskUtilities::cleanUTF8(cleanType);

            // Add to blackboard
            TskBlackboardAttribute attr(TSK_FILE_TYPE_SIG, MODULE_NAME, "", cleanType);
            pFile->addGenInfoAttribute(attr);
        }
        catch (TskException& tskEx)
        {
            std::stringstream msg;
            msg << "FileTypeModule: Caught framework exception: " << tskEx.message();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        catch (std::exception& ex)
        {
            std::stringstream msg;
            msg << "FileTypeModule: Caught exception: " << ex.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }

        return TskModule::OK;
    }

    TskModule::Status TSK_MODULE_EXPORT finalize()
    {
        if (magicHandle != NULL) {
            magic_close(magicHandle);
        }
        return TskModule::OK;
    }
}
