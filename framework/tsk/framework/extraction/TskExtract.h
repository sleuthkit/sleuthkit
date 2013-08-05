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
#ifndef _TSK_EXTRACT_H
#define _TSK_EXTRACT_H

#include <string>
#include "Poco/SharedPtr.h"

// Forward dec
class TskFile;

namespace TskArchiveExtraction
{
    /**
     * Abstract base interface class for container extractor classes
     * 
     */
    class TSK_FRAMEWORK_API TskExtract
    {
    public:
        TskExtract();
        virtual ~TskExtract();

        virtual int extractFiles(TskFile * containerFile = NULL) = 0;
    };


    TSK_FRAMEWORK_API typedef Poco::SharedPtr<TskExtract> ExtractorPtr;

    // Non-member Factory Functions
    TSK_FRAMEWORK_API ExtractorPtr createExtractor(const std::wstring &archivePath, const std::string filter = "");
    TSK_FRAMEWORK_API ExtractorPtr createExtractor(const std::string &archivePath, const std::string filter = "");
}

#endif
