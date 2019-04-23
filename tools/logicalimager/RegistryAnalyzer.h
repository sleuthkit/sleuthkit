/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2019 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
* \file RegistryAnalyzer.h
* Contains the class definitions for Registry Analyzer.
*/

#pragma once

#include <string>

#include "rejistry++/include/librejistry++.h"
#include "tsk/tsk_tools_i.h"
#include "RegHiveType.h"

class RegistryAnalyzer {
public:
    RegistryAnalyzer(const std::string &outputFilePath);
    ~RegistryAnalyzer();

    int analyzeSAMUsers() const;

private:
    int parseSAMVRecord(const unsigned char *pVRec, size_t aVRecLen, std::wstring &userName,
        std::wstring &userFullName, std::wstring &comment, uint32_t &acctType) const;

    int RegistryAnalyzer::parseSAMFRecord(const unsigned char *pFRec, long aFRecLen, FILETIME &lastLoginDate,
        FILETIME &lastPWResetDate, FILETIME &accountExpiryDate, FILETIME &lastFailedLoginDate,
        unsigned short &loginCount, unsigned short &acbFlags) const;

    RegistryAnalyzer(const RegistryAnalyzer&) = delete;

    std::string m_outputFilePath;
    FILE *m_outputFile;
};
