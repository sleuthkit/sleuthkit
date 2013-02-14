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
#ifndef _TSK_EXTRACT_INTERFACE_H
#define _TSK_EXTRACT_INTERFACE_H


#include <string>
#include "Poco/SharedPtr.h"

// Forward dec
class TskFile;

/**
 * 
 * 
 */
 
class TSK_FRAMEWORK_API TskExtractInterface
{
public:
    TskExtractInterface() {}
    virtual ~TskExtractInterface() {}

    virtual int extractFiles(const std::wstring &archivePath, TskFile * parent = NULL) = 0;

protected:
    std::wstring m_archivePath;
    TskFile     *m_parentFile;
};

TSK_FRAMEWORK_API typedef Poco::SharedPtr<TskExtractInterface> ExtractorPtr_t;

// Non-member Factory Function
TSK_FRAMEWORK_API ExtractorPtr_t createExtractor(const std::string extFilter = "");

#endif
