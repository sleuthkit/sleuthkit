/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2011-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file HashCalcModule.cpp 
 * Contains the implementation of the hash calculation file analysis module.
 */

// System includes
#include <string>
#include <sstream>
#include <string.h>

// Framework includes
#include "tsk/framework/utilities/TskModuleDev.h"

// strings for command line arguments
static const std::string MD5_NAME("MD5");
static const std::string SHA1_NAME("SHA1");

static bool calculateMD5 = true;
static bool calculateSHA1 = false;

static const char hexMap[] = "0123456789abcdef";

extern "C" 
{
    /**
     * Module identification function. 
     *
     * @return The name of the module.
     */
    TSK_MODULE_EXPORT const char *name()
    {
        return "tskHashCalcModule";
    }

    /**
     * Module identification function. 
     *
     * @return A description of the module.
     */
    TSK_MODULE_EXPORT const char *description()
    {
        return "Calculates MD5 and/or SHA-1 hashes of file content";
    }

    /**
     * Module identification function. 
     *
     * @return The version of the module.
     */
    TSK_MODULE_EXPORT const char *version()
    {
        return "1.0.1";
    }

    /**
     * Module initialization function. Receives arguments, typically read by the
     * caller from a pipeline configuration file, that determine what hashes the 
     * module calculates for a given file.
     *
     * @param args Valid values are "MD5", "SHA1" or the empty string which will 
     * result in just "MD5" being calculated. Hash names can be in any order,
     * separated by spaces or commas. 
     * @return TskModule::OK if initialization arguments are valid, otherwise 
     * TskModule::FAIL.
     */
    TskModule::Status TSK_MODULE_EXPORT initialize(const char* arguments)
    {
        std::string args(arguments);

        // If the argument string is empty we calculate both hashes.
        if (args.empty()) {
            calculateMD5 = true;
            calculateSHA1 = false;
        }
        else {
            calculateMD5 = false;
            calculateSHA1 = false;

            // If the argument string contains "MD5" we calculate an MD5 hash.
            if (args.find(MD5_NAME) != std::string::npos) 
                calculateMD5 = true;

            // If the argument string contains "SHA1" we calculate a SHA1 hash.
            if (args.find(SHA1_NAME) != std::string::npos) 
                calculateSHA1 = true;

            // If neither hash is to be calculated it means that the arguments
            // passed to the module were incorrect. We log an error message
            // through the framework logging facility.
            if (!calculateMD5 && !calculateSHA1) {
                std::stringstream msg;
                msg << "Invalid arguments passed to hash module: " << args.c_str();
                LOGERROR(msg.str());
                return TskModule::FAIL;
            }
        }

        if (calculateMD5)
            LOGINFO("HashCalcModule: Configured to calculate MD5 hashes");

        if (calculateSHA1)
            LOGINFO("HashCalcModule: Configured to calculate SHA-1 hashes");

        return TskModule::OK;
    }

    /**
     * Module execution function. Receives a pointer to a file the module is to
     * process. The file is represented by a TskFile interface which is used
     * to read the contents of the file and post calculated hashes of the 
     * file contents to the database.
     *
     * @param pFile A pointer to a file for which the hash calculations are to be performed.
     * @returns TskModule::OK on success, TskModule::FAIL on error.
     */
    TskModule::Status TSK_MODULE_EXPORT run(TskFile * pFile) 
    {
        if (pFile == NULL) 
        {
            LOGERROR("HashCalcModule: passed NULL file pointer.");
            return TskModule::FAIL;
        }

        // We will not attempt to calculate hash values for "unused sector"
        // files.
        if (pFile->getTypeId() == TskImgDB::IMGDB_FILES_TYPE_UNUSED)
            return TskModule::OK;

        try 
        {
            TSK_MD5_CTX md5Ctx;
            TSK_SHA_CTX sha1Ctx;

            if (calculateMD5)
                TSK_MD5_Init(&md5Ctx);

            if (calculateSHA1)
                TSK_SHA_Init(&sha1Ctx);

            // file buffer
            static const uint32_t FILE_BUFFER_SIZE = 32768;
            char buffer[FILE_BUFFER_SIZE];

            ssize_t bytesRead = 0;

            // Read file content into buffer and write it to the DigestOutputStream.
            do 
            {
                bytesRead = pFile->read(buffer, FILE_BUFFER_SIZE);
                if (bytesRead > 0) {
                    if (calculateMD5)
                        TSK_MD5_Update(&md5Ctx, (unsigned char *) buffer, (unsigned int) bytesRead);

                    if (calculateSHA1)
                        TSK_SHA_Update(&sha1Ctx, (unsigned char *) buffer, (unsigned int) bytesRead);                  
                }
            } while (bytesRead > 0);

            if (calculateMD5) {
                unsigned char md5Hash[16];
                TSK_MD5_Final(md5Hash, &md5Ctx);

                char md5TextBuff[33];            
                for (int i = 0; i < 16; i++) {
                    md5TextBuff[2 * i] = hexMap[(md5Hash[i] >> 4) & 0xf];
                    md5TextBuff[2 * i + 1] = hexMap[md5Hash[i] & 0xf];
                }
                md5TextBuff[32] = '\0';
                pFile->setHash(TskImgDB::MD5, md5TextBuff);
            }

            if (calculateSHA1) {
                unsigned char sha1Hash[20];
                TSK_SHA_Final(sha1Hash, &sha1Ctx);

                char textBuff[41];            
                for (int i = 0; i < 20; i++) {
                    textBuff[2 * i] = hexMap[(sha1Hash[i] >> 4) & 0xf];
                    textBuff[2 * i + 1] = hexMap[sha1Hash[i] & 0xf];
                }
                textBuff[40] = '\0';
                pFile->setHash(TskImgDB::SHA1, textBuff);
            }

        }
        catch (TskException& tskEx)
        {
            std::stringstream msg;
            msg << "HashCalcModule - Error processing file id " << pFile->getId() << ": " << tskEx.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        catch (std::exception& ex)
        {
            std::stringstream msg;
            msg << "HashCalcModule - Error processing file id " << pFile->getId() << ": " << ex.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }

        return TskModule::OK;
    }

    /**
     * Module cleanup function. This module does not need to free any 
     * resources allocated during initialization or execution.
     *
     * @returns TskModule::OK
     */
    TskModule::Status TSK_MODULE_EXPORT finalize()
    {
        return TskModule::OK;
    }
}

