/*
 *
 *  The Sleuth Kit
 *
 *  Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 *  Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
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
     * Module initialization function. Receives a string of initialization arguments, 
     * typically read by the caller from a pipeline configuration file. 
     * Returns TskModule::OK or TskModule::FAIL. Returning TskModule::FAIL indicates 
     * the module is not in an operational state.  
     *
     * @param args This module takes no arguments.
     * @return TskModule::OK if initialization succeeded, otherwise TskModule::FAIL.
     */
    TskModule::Status TSK_MODULE_EXPORT initialize(std::string& arguments)
    {    
        return TskModule::OK;
    }
 
    /**
     * Module execution function. Receives a pointer to a file the module is to
     * process. The file is represented by a TskFile interface from which both
     * file content and file metadata can be retrieved. Returns TskModule::OK, 
     * TskModule::FAIL, or TskModule::STOP. Returning TskModule::FAIL indicates 
     * the module experienced an error processing the file. Returning TskModule::STOP
     * is a request to terminate processing of the file.
     *
     * @param pFile A pointer to a file to be processed.
     * @returns TskModule::OK on success, TskModule::FAIL on error, or TskModule::STOP.
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

    /**
     * Module cleanup function. This is where the module should free any resources 
     * allocated during initialization or execution.
     *
     * @returns TskModule::OK on success and TskModule::FAIL on error.
     */
    TskModule::Status TSK_MODULE_EXPORT finalize()
    {
        return TskModule::OK;
    }
}