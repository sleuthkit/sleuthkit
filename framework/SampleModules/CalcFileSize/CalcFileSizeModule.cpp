/*
 *
 *  The Sleuth Kit
 *
 *  Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 *
 *  This is free and unencumbered software released into the public domain.
 *  
 *  Anyone is free to copy, modify, publish, use, compile, sell, or
 *  distribute this software, either in source code form or as a compiled
 *  binary, for any purpose, commercial or non-commercial, and by any
 *  means.
 *  
 *  In jurisdictions that recognize copyright laws, the author or authors
 *  of this software dedicate any and all copyright interest in the
 *  software to the public domain. We make this dedication for the benefit
 *  of the public at large and to the detriment of our heirs and
 *  successors. We intend this dedication to be an overt act of
 *  relinquishment in perpetuity of all present and future rights to this
 *  software under copyright law.
 *  
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 *  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 *  OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 *  ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 *  OTHER DEALINGS IN THE SOFTWARE. 
 */

/**
 * \file CalcFileSizeModule.cpp
 * This sample module shows a basic Sleuth Kit Framework module.  It is
 * released as public domain and you are free to remove this header,  use
 * it as a starting point for your module, and choose whatever license that
 * you want.  Note that the framework itself is NOT public domain.
 */

// TSK Framework includes
#include "TskModuleDev.h"

// Poco includes
//#include "Poco/Exception.h"

// C/C++ library includes
#include <string>
#include <sstream>
#include <math.h>

// Functions and variables other than the module API functions are enclosed in
// an anonymous namespace to give them file scope instead of global scope. This
// replaces the older practice of declaring file scope functions and variables
// using the "static" keyword.
namespace
{
	const uint32_t FILE_BUFFER_SIZE = 8193;
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
        return "CalcFileSize";
    }

    /**
     * Module identification function. 
     *
     * @return A description of the module.
     */
    TSK_MODULE_EXPORT const char *description()
    {
        return "Calculates file sizes and posts them to the blackboard as a demonstration of how to develop a module";
    }

    /**
     * Module identification function. 
     *
     * @return The version of the module.
     */
    TSK_MODULE_EXPORT const char *version()
    {
        return "1.0.0";
    }

    /**
     * Module initialization function. Receives a string of initialization arguments, 
     * typically read by the caller from a pipeline configuration file. 
     * Returns TskModule::OK or TskModule::FAIL. Returning TskModule::FAIL indicates 
     * the module is not in an operational state.  
     *
     * @param args a string of initialization arguments.
     * @return TskModule::OK if initialization succeeded, otherwise TskModule::FAIL.
     */
    TskModule::Status TSK_MODULE_EXPORT initialize(const char *arguments)
    {
		// The TSK Framework convention is to prefix error messages with the
		// name of the module/class and function that emitted the message. 
        const std::string MSG_PREFIX = "CalcFileSize::initialize : ";

		// Well-behaved modules should catch and log all possible exceptions
		// and return an appropriate TskModule::Status to the TSK Framework. 
		TskModule::Status status = TskModule::OK;
        try
        {
			// If this module required initialization, the initialization code would
			// go here.
        }
        catch (TskException &ex)
        {
            status = TskModule::FAIL;
            std::ostringstream msg;
            msg << MSG_PREFIX << "TskException: " << ex.message();
            LOGERROR(msg.str());
        }
		// Uncomment this catch block and the #include of "Poco/Exception.h" if using
		// Poco.
        //catch (Poco::Exception &ex)
        //{
        //    status = TskModule::FAIL;
        //    std::ostringstream msg;
        //    msg << MSG_PREFIX << "Poco::Exception: " << ex.displayText();
        //    LOGERROR(msg.str());
        //}
        catch (std::exception &ex)
        {
            status = TskModule::FAIL;
            std::ostringstream msg;
            msg << MSG_PREFIX << "std::exception: " << ex.what();
            LOGERROR(msg.str());
        }
        catch (...)
        {
            status = TskModule::FAIL;
            LOGERROR(MSG_PREFIX + "unrecognized exception");
        }

        return status;
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
    TskModule::Status TSK_MODULE_EXPORT run(TskFile *pFile)
    {
		// The TSK Framework convention is to prefix error messages with the
		// name of the module/class and function that emitted the message. 
        const std::string MSG_PREFIX = "CalcFileSize::run : ";

		// Well-behaved modules should catch and log all possible exceptions
		// and return an appropriate TskModule::Status to the TSK Framework. 
		TskModule::Status status = TskModule::OK;
        try
        {
			// Error checking code for the module throws TskException objects.
			if (pFile == NULL)
			{
				throw TskException("TskFile file pointer argument is NULL");
			}

            // Read file content into buffer.
            long totalBytes = 0;
            char buffer[FILE_BUFFER_SIZE];
            int bytesRead = 0;
            do
            {
                memset(buffer, 0, FILE_BUFFER_SIZE);
                bytesRead = pFile->read(buffer, FILE_BUFFER_SIZE);
                totalBytes += bytesRead;
            } 
			while (bytesRead > 0);

            // Post the file size to the blackboard
            TskBlackboardArtifact genInfo = pFile->getGenInfo();
            TskBlackboardAttribute attr((int) TSK_VALUE, "CalcFileSizeModule", "ByteCount", totalBytes);
            genInfo.addAttribute(attr);
        }
        catch (TskException &ex)
        {
            status = TskModule::FAIL;
            std::ostringstream msg;
            msg << MSG_PREFIX << "TskException: " << ex.message();
            LOGERROR(msg.str());
        }
		// Uncomment this catch block and the #include of "Poco/Exception.h" if using
		// Poco.
        //catch (Poco::Exception &ex)
        //{
        //    status = TskModule::FAIL;
        //    std::ostringstream msg;
        //    msg << MSG_PREFIX << "Poco::Exception: " << ex.displayText();
        //    LOGERROR(msg.str());
        //}
        catch (std::exception &ex)
        {
            status = TskModule::FAIL;
            std::ostringstream msg;
            msg << MSG_PREFIX << "std::exception: " << ex.what();
            LOGERROR(msg.str());
        }
        catch (...)
        {
            status = TskModule::FAIL;
            LOGERROR(MSG_PREFIX + "unrecognized exception");
        }

        return status;
    }

    /**
     * Module cleanup function. This is where the module should free any resources 
     * allocated during initialization or execution.
     *
     * @returns TskModule::OK on success and TskModule::FAIL on error.
     */
    TskModule::Status TSK_MODULE_EXPORT finalize()
    {
		// The TSK Framework convention is to prefix error messages with the
		// name of the module/class and function that emitted the message. 
        const std::string MSG_PREFIX = "CalcFileSize::finalize : ";

		// Well-behaved modules should catch and log all possible exceptions
		// and return an appropriate TskModule::Status to the TSK Framework. 
		TskModule::Status status = TskModule::OK;
        try
        {
			// If this module required finalization, the finalization code would
			// go here.
        }
        catch (TskException &ex)
        {
            status = TskModule::FAIL;
            std::ostringstream msg;
            msg << MSG_PREFIX << "TskException: " << ex.message();
            LOGERROR(msg.str());
        }
		// Uncomment this catch block and the #include of "Poco/Exception.h" if using
		// Poco.
        //catch (Poco::Exception &ex)
        //{
        //    status = TskModule::FAIL;
        //    std::ostringstream msg;
        //    msg << MSG_PREFIX << "Poco::Exception: " << ex.displayText();
        //    LOGERROR(msg.str());
        //}
        catch (std::exception &ex)
        {
            status = TskModule::FAIL;
            std::ostringstream msg;
            msg << MSG_PREFIX << "std::exception: " << ex.what();
            LOGERROR(msg.str());
        }
        catch (...)
        {
            status = TskModule::FAIL;
            LOGERROR(MSG_PREFIX + "unrecognized exception");
        }

        return status;
    }
}