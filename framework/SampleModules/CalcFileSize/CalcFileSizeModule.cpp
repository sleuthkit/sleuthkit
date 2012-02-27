/*
 *
 *  The Sleuth Kit
 *
 *  Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 *  Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 *  reserved.
 *
 *  This software is distributed under the Common Public License 1.0
 */


/* Sample module that reads a file and posts the size to the blackboard */

#include <sstream>
#include <math.h>

// Framework includes
#include "TskModuleDev.h"

// We process the file 8k at a time
static const uint32_t FILE_BUFFER_SIZE = 8193;

extern "C" 
{
    /**
     * Module initialization function. Takes a string as input that allows
     * arguments to be passed into the module.
     * @param arguments This module takes no arguments
     */
    TskModule::Status TSK_MODULE_EXPORT initialize(std::string& arguments)
    {    
        return TskModule::OK;
    }
 
    /**
     * The run() method is where the modules work is performed.
     * The module will be passed a pointer to a file from which both
     * content and metadata can be retrieved.
     * @param pFile A pointer to a file to be processed.
     * @returns TskModule::OK on success and TskModule::FAIL on error.
     */
    TskModule::Status TSK_MODULE_EXPORT run(TskFile * pFile)
    {
        if (pFile == NULL)
        {
            LOGERROR(L"CalcFileSizeModule module passed NULL file pointer.");
            return TskModule::FAIL;
        }

        try
        {
            if (!pFile->exists())
            {
                std::wstringstream msg;
                msg << L"File to be analyzed does not exist: " << pFile->getPath().c_str();
                LOGERROR(msg.str());
                return TskModule::FAIL;
            }

            // Open file.
            pFile->open();

            long totalBytes = 0;
            char buffer[FILE_BUFFER_SIZE];
            int bytesRead = 0;

            // Read file content into buffer.
            do
            {
                memset(buffer, 0, FILE_BUFFER_SIZE);
                bytesRead = pFile->read(buffer, FILE_BUFFER_SIZE);
                totalBytes += bytesRead;
            } while (bytesRead > 0);

            // Post the file size to the blackboard
            TskBlackboardArtifact genInfo = pFile->getGenInfo();

            TskBlackboardAttribute attr((int) TSK_VALUE, "CalcFileSizeModule", "ByteCount", totalBytes);
            genInfo.addAttribute(attr);

            // Close file.
            pFile->close();
        }
        catch (TskException& tskEx)
        {
            std::wstringstream msg;
            msg << L"CalcFileSizeModule - Caught framework exception: " << tskEx.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        catch (std::exception& ex)
        {
            std::wstringstream msg;
            msg << L"CalcFileSizeModule - Caught exception: " << ex.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        return TskModule::OK;
    }

    TskModule::Status TSK_MODULE_EXPORT finalize()
    {
        return TskModule::OK;
    }
}