/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2013 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file
 * 
 */

#include <string>
#include <cstring>

#include "Poco/SharedPtr.h"

#include "tsk/framework/framework_i.h" // to get TSK_FRAMEWORK_API
#include "tsk/framework/utilities/TskUtilities.h"
#include "TskExtract.h"
#include "TskL01Extract.h"

namespace TskArchiveExtraction
{
    TskExtract::TskExtract()
    {}

    TskExtract::~TskExtract()
    {}

    namespace
    {
        // Support functions (not for clients)

        /**
         * Determines if a file is in Encase L01 format, regardless of filename.
         * File signature: First three bytes of an L01 file will be "LVF".
         */
        bool isL01File(const char *path)
        {
            bool result = false;
            FILE *f = fopen(path, "rb");

	        if (f != NULL) {
                unsigned char buf[4];
                size_t bytesRead = fread(&buf, sizeof(unsigned char), 3, f);
                if (bytesRead == 3) {
                    buf[3] = 0;
                    if (strcmp((const char*)buf, "LVF") == 0)
                        result = true;
                }
                fclose(f);
            }
            return result;
        }
    }

    /**
     * Factory Function
     * @param   archivePath Local path of the container file.
     * @param   extFilter   Optional filter string specifying a particular type of archive.
     * @returns Smart pointer to a new extractor object appropriate to the container
     *          Pointer will be NULL if an extractor is not found for this container.
     */
    ExtractorPtr createExtractor(const std::wstring &archivePath, const std::string filter /*= ""*/)
    {
        return createExtractor(TskUtilities::toUTF8(archivePath), filter);
    }

    /**
     * Factory Function
     * @param   archivePath Local path of the container file.
     * @param   extFilter   Optional filter string specifying a particular type of archive.
     * @returns Smart pointer to a new extractor object appropriate to the container
     *          Pointer will be NULL if an extractor is not found for this container.
     */
    ExtractorPtr createExtractor(const std::string &archivePath, const std::string filter /*= ""*/)
    {
        //Check based on file signature 
        if (filter.empty())
        {
            if (isL01File(archivePath.c_str()))
            {
                return new TskL01Extract(archivePath);
            }
        }
        else
        {
            if (filter == "L01")
            {
                return new TskL01Extract(archivePath);
            }
            //else if (filter == "RAR")
            //{
            //    return new RarExtract(archivePath);        
            //}
            //else if (filter == "ZIP")
            //{
            //    return new TskZipExtract(archivePath);
            //}
        }
        return NULL;
    }
}
