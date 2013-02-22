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

#include "Poco/SharedPtr.h"

#include "framework_i.h" // to get TSK_FRAMEWORK_API
#include "Utilities/TskUtilities.h"
#include "TskExtract.h"
#include "TskL01Extract.h"


// Support functions (not for clients)
bool isL01File(const char *path);


/// Factory Function
ExtractorPtr createTskExtractor(const std::wstring &archivePath, const std::string extFilter /*= ""*/)
{
    //Check based on file signature 
    if (extFilter.empty())
    {
        std::string narrowPath = TskUtilities::toUTF8(archivePath);
        if (isL01File(narrowPath.c_str()))
        {
            return new TskL01Extract(archivePath);
        }
    }
    else
    {
        ///@todo verify filetype matches?
        if (extFilter == "L01")
        {
            return new TskL01Extract(archivePath);
        }
        //case "RAR":
        //    //return new TskRarExtract;
        //break;

        //case "ZIP":
        //    //return new TskZipExtract;
        //break;
    }
    return NULL;
}

/**
 * Determines if a file is in Encase L01 format, regardless of filename.
 * File signature: First three bytes of an L01 file will be "LVF".
 */
bool isL01File(const char *path)
{
    bool result = false;
    FILE *f;

	if (!fopen_s(&f, path, "rb")) {
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
