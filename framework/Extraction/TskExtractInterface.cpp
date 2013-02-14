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
#include "TskExtractInterface.h"
#include "TskL01Extract.h"


/// Factory Function
ExtractorPtr_t createExtractor(const std::string extFilter /*= ""*/)
{
    if (extFilter.empty())
    {
        //use file signature 
        //return TskL01Extract
    }

    ///@todo check filename extension matches the extFilter
    if (extFilter == "L01")
    {
        return new TskL01Extract;
    }
    //case "RAR":
    //    //return new TskRarExtract;
    //break;

    //case "ZIP":
    //    //return new TskZipExtract;
    //break;

}

