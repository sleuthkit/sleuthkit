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
* \file LogicalImagerConfiguration.h
* Contains the class definitions for the Logicial Imager Rule Set.
*/

#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <sstream>
#include <locale>
#include <iomanip>
#include <exception>

#include "LogicalImagerConfiguration.h"
#include "LogicalImagerRuleSet.h"

/**
* Implement the logical imager configuration.
*
*/
LogicalImagerConfiguration::~LogicalImagerConfiguration() {
}

LogicalImagerConfiguration::LogicalImagerConfiguration(const std::string &configFilename) {
    std::ifstream file(configFilename);
    if (!file) {
        throw std::logic_error("ERROR: failed to open configuration file " + configFilename);
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string str = buffer.str();

    nlohmann::json configJson;
    try {
        configJson = nlohmann::json::parse(str);
    }
    catch (std::exception &e) {
        throw std::logic_error("ERROR: parsing configuration file " + configFilename + "\n" + e.what());
    }

    m_ruleSets.empty();

    bool hasError = false;
    std::string errorStr;
    const std::string newline("\n");
    for (auto it = configJson.begin(); it != configJson.end(); it++) {
        if (it.key() == "rule-sets") {
            for (auto ruleSetIter = it.value().begin(); ruleSetIter != it.value().end(); ++ruleSetIter) {
                nlohmann::json ruleSetValue = ruleSetIter.value();
                std::vector<std::pair<const RuleMatchResult *, std::vector<LogicalImagerRuleBase *>>> rules;
                LogicalImagerRuleSet *ruleSet = new LogicalImagerRuleSet();
                ruleSet->constructRuleSet(ruleSetValue, rules);
                m_ruleSets.push_back(ruleSet);
            }
        }
        else if (it.key() == "finalize-image-writer") {
            it.value().get_to(m_finalizeImageWriter);
        }
    }

    if (hasError) {
        throw std::logic_error("ERROR: parsing configuration file " + configFilename + newline + errorStr);
    }
}

/**
* Given a file and its path, match it using the logical imager rule set.
* All rules in a single set must matched (ANDed)
* May extract and/or alert depending on the rule setting.
*
* @param fs_file TSK_FS_FILE containing the filename
* @param path parent path to fs_file
* @returns TSK_RETVAL_ENUM TSK_OK if match has no errors.
*/
TSK_RETVAL_ENUM LogicalImagerConfiguration::matches(TSK_FS_FILE *fs_file, const char *path) const {
    for (std::vector<LogicalImagerRuleSet *>::const_iterator iter = m_ruleSets.begin(); iter != m_ruleSets.end(); ++iter) {
        (void)(*iter)->matches(fs_file, path);
    }
    return TSK_OK;
}

/**
* Extract a file. tsk_img_writer_create must have been called prior to this method.
*
* @param fs_file File details
* @returns TSK_RETVAL_ENUM TSK_OK if file is extracted, TSK_ERR otherwise.
*/
TSK_RETVAL_ENUM LogicalImagerConfiguration::extractFile(TSK_FS_FILE *fs_file) {
    TSK_OFF_T offset = 0;
    size_t bufferLen = 16 * 1024;
    char buffer[16 * 1024];

    while (true) {
        ssize_t bytesRead = tsk_fs_file_read(fs_file, offset, buffer, bufferLen, TSK_FS_FILE_READ_FLAG_NONE);
        if (bytesRead == -1) {
            if (fs_file->meta && fs_file->meta->size == 0) {
                // ts_fs_file_read returns -1 with empty files, don't report it.
                return TSK_OK;
            }
            else {
                // fprintf(stderr, "processFile: tsk_fs_file_read returns -1 filename=%s\toffset=%" PRId64 "\n", fs_file->name->name, offset);
                return TSK_ERR;
            }
        }
        offset += bytesRead;
        if (offset >= fs_file->meta->size) {
            break;
        }
    }
    return TSK_OK;
}

const std::pair<const RuleMatchResult *, std::list<std::string>> LogicalImagerConfiguration::getFullFilePaths() const
{
    if (m_ruleSets.size()) {
        return m_ruleSets[0]->getFullFilePaths();
    }
    else {
        std::list<std::string> fullPaths;
        std::pair<const RuleMatchResult *, std::list<std::string>> xxx;
        xxx.first = (const RuleMatchResult *) NULL;
        xxx.second = fullPaths;
        return xxx;
    }
}
