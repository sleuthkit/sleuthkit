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
* \file LogicalImagerRuleSet.cpp
* Contains C++ code that creates the Logical Imager Rul Set class.
*/

#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <sstream>
#include <locale>
#include <iomanip>
#include <exception>

#include "LogicalImagerRuleSet.h"
#include "LogicalImagerExtensionRule.h"
#include "LogicalImagerPathRule.h"
#include "LogicalImagerSizeRule.h"
#include "LogicalImagerFilenameRule.h"
#include "LogicalImagerDateRule.h"
#include "json.h"

/**
 * Convert a date time string to time_t
 * @param datetimeStr Date time string in yyyy-mm-dd format
 * @returns time_t time_t data
 *
 * NOTE: There is a known problem: std::get_time on Visual 2015 does not fail on incorrect date
 * https://stackoverflow.com/questions/43235953/stdget-time-on-visual-2015-does-not-fail-on-incorrect-date
 * https://social.msdn.microsoft.com/Forums/en-US/d9b650a2-424d-4ee6-b3b6-ea93cfc6cb5f/stdgettime-on-visual-2015-does-not-fail-on-incorrect-date?forum=vclanguage
 * We have decided to ignore it as the explicit date is not going to be used. Relative days (min-days) will be used.
 */
time_t stringToTimet(const std::string &datetimeStr) {
    std::tm t = {};
    std::istringstream ss(datetimeStr);
    ss.imbue(std::locale("C"));
    ss >> std::get_time(&t, "%Y-%m-%d");
    if (ss.fail()) {
       throw std::logic_error("ERROR: Date parsing failed for " + datetimeStr);
    }
    time_t time = mktime(&t);
    return time;
}

int getPositiveInt(const std::string &key, nlohmann::json ruleJson) {
    int size;
    ruleJson[key].get_to(size);
    if (size < 0) {
        throw std::logic_error("ERROR: invalid " + key + ". Value must be >= 0");
    }
    return size;
}

/* 
* Construct a rule set
*
* @param ruleSetKey String key for the rule set
* @param ruleSetValue JSON of the rule set
* @throws std::logic_error on any error
*/
void LogicalImagerRuleSet::constructRuleSet(const std::string &ruleSetKey, nlohmann::json ruleSetValue) {
    std::string description;
    bool shouldSave = true;
    bool shouldAlert = false;
    bool hasExtensions = false;
    bool hasFileNames = false;

    std::vector<LogicalImagerRuleBase *> vector;
    std::list<std::string> fullPaths;

    auto jsonMap = ruleSetValue.get<std::unordered_map<std::string, nlohmann::json>>();
    for (auto ruleIter = jsonMap.begin(); ruleIter != jsonMap.end(); ++ruleIter) {
        std::string ruleKey = ruleIter->first;
        nlohmann::json ruleJson = ruleIter->second;
        if (ruleKey == "description") {
            ruleJson.begin().value().get_to(description);
        } else if (ruleKey == "shouldSave") {
            ruleJson.begin().value().get_to(shouldSave);
        } else if (ruleKey == "shouldAlert") {
            ruleJson.begin().value().get_to(shouldAlert);
        } else if (ruleKey == "extensions") {
            std::set<std::string> extensions;
            for (auto valueIter = ruleJson.begin(); valueIter != ruleJson.end(); ++valueIter) {
                std::string str;
                valueIter.value().get_to(str);
                extensions.insert(str);
            }
            LogicalImagerExtensionRule *extensionRule = new LogicalImagerExtensionRule(extensions);
            vector.push_back(extensionRule);
            hasExtensions = true;
        } else if (ruleKey == "file-names") {
            std::set<std::string> filenames;
            for (auto valueIter = ruleJson.begin(); valueIter != ruleJson.end(); ++valueIter) {
                std::string str;
                valueIter.value().get_to(str);
                filenames.insert(str);
            }
            LogicalImagerFilenameRule *filenameRule = new LogicalImagerFilenameRule(filenames);
            vector.push_back(filenameRule);
            hasFileNames = true;
        } else if (ruleKey == "folder-names") {
            std::set<std::string> paths;
            for (auto valueIter = ruleJson.begin(); valueIter != ruleJson.end(); ++valueIter) {
                std::string str;
                valueIter.value().get_to(str);
                paths.insert(str);
            }
            LogicalImagerPathRule *pathRule = new LogicalImagerPathRule(paths);
            vector.push_back(pathRule);
        } else if (ruleKey == "size-range") {
            int sizeMin = 0;
            int sizeMax = 0;
            auto sizeJsonMap = ruleJson.get<std::unordered_map<std::string, nlohmann::json>>();
            for (auto iter = sizeJsonMap.begin(); iter != sizeJsonMap.end(); ++iter) {
                if (iter->first == "min") {
                    sizeMin = getPositiveInt("min", ruleJson);
                } else if (iter->first == "max") {
                    sizeMax = getPositiveInt("max", ruleJson);
                } else {
                    throw std::logic_error("ERROR: unsupported size-range key " + iter->first);
                }
            }
            LogicalImagerSizeRule *sizeRule = new LogicalImagerSizeRule(sizeMin, sizeMax);
            vector.push_back(sizeRule);
        } else if (ruleKey == "date-range") {
            time_t minTime = 0;
            time_t maxTime = 0;
            int minDays = 0;
            auto sizeJsonMap = ruleJson.get<std::unordered_map<std::string, nlohmann::json>>();
            for (auto iter = sizeJsonMap.begin(); iter != sizeJsonMap.end(); ++iter) {
                if (iter->first == "min") {
                    std::string minTimeStr;
                    ruleJson["min"].get_to(minTimeStr);
                    minTime = stringToTimet(minTimeStr);
                } else if (iter->first == "max") {
                    std::string maxTimeStr;
                    ruleJson["max"].get_to(maxTimeStr);
                    maxTime = stringToTimet(maxTimeStr);
                } else if (iter->first == "min-days") {
                    minDays = getPositiveInt("min-days", ruleJson);
                } else {
                    throw std::logic_error("ERROR: unsupported date-range key " + iter->first);
                }
            }
            LogicalImagerDateRule *dateRule = new LogicalImagerDateRule(minTime, maxTime, minDays);
            vector.push_back(dateRule);
        } else if (ruleKey == "full-paths") {
            for (auto valueIter = ruleJson.begin(); valueIter != ruleJson.end(); ++valueIter) {
                std::string str;
                valueIter.value().get_to(str);
                fullPaths.push_back(str);
            }
        }
        else {
            throw std::logic_error("ERROR: unsupported rule key " + ruleKey);
        }
    }
    // Validation
    if (description.empty()) {
        throw std::logic_error("ERROR: description is empty");
    }
    // A rule should not have both extensions and file name.
    if (hasExtensions && hasFileNames) {
        throw std::logic_error("ERROR: a rule cannot have both extensions and file-names");
    }
    // A rule with full-paths cannot have other rule definitions
    if (!fullPaths.empty() && !vector.empty()) {
        throw std::logic_error("ERROR: a rule with full-paths cannot have other rule definitions");
    }

    RuleMatchResult *ruleMatchKey = new RuleMatchResult(description, shouldSave, shouldAlert);
    if (!fullPaths.empty()) {
        m_fullFilePaths.first = ruleMatchKey;
        m_fullFilePaths.second = fullPaths;
        return;
    }
    m_rules.insert(std::pair<const RuleMatchResult *, std::vector<LogicalImagerRuleBase *>>(ruleMatchKey, vector));
}

/**
 * Construct the LogicalImagerRuleSet based on a configuration filename
 * The configuration file is in JSON format. It has the following key and values.

{
  "finalize_image_writer": false,
  "rule-sets": {
    "full-path-search": {
      "description": "Full file path search",
      "shouldSave": true,
      "shouldAlert": true,
      "full-paths": [
        "Documents and Settings/John/My Documents/Downloads",
        "Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/Blue hills.jpg",
      ]
    },
    "example-rule-1": {
      "description": "Find all pictures smaller than 3000 bytes, under the 'Google' folder",
      "shouldSave": true,
      "shouldAlert": true,
      "extensions": [ "jpg", "jpeg", "png", "gif" ],
      "size-range": { "max": 3000 },
      "folder-names": [ "Google" ]
    },
    "example-rule-2": {
      "description": "Find all 'readme.txt' and 'autoexec.bat' files",
      "shouldSave": true,
      "shouldAlert": true,
      "file-names": [ "readme.txt", "autoexec.bat" ]
    },
    "example-rule-3": {
      "description": "find files newer than 2012-03-22",
      "shouldSave": false,
      "shouldAlert": true,
      "date-range": { "min": "2012-03-22" }
    },
    "example-rule-4": {
      "description": "find all png files under the user folder",
      "shouldSave": true,
      "shouldAlert": true,
      "extensions": [ "png" ],
      "folder-names": [ "[USER_FOLDER]/My Documents/Downloads" ]
    },
    "example-rule-5": {
      "description": "find files 30 days or newer",
      "shouldSave": false,
      "shouldAlert": true,
      "date-range": { "min-days": 30 }
    }
  }
}
 * "finalize_image_writer" is optional. Default is false. If true, it will finalize the image writer by writing the 
 *     remaing sectors to the sparse_image.vhd file.
 * "description" is required.
 * "shouldSave" is optional. Default is true. If true, any matched files will be save to the sparse_image.vhd.
 * "shouldAlert" is optional. Default is false. If true, an alert record will be send to the console and the alert file.
 *
 * Creates an alert file based on the alertFilename. 
 * Files matching the logical imager rule set are recorded in the alert file, if shouldAlert is true.
 *
 * @param configFilename Configuration filename of the rule set
 * @param alertFilename Alert filename
 * @param driveName Name of drive
 * @throws std::logic_error if there is any error 
 *
 */
LogicalImagerRuleSet::LogicalImagerRuleSet(const std::string &configFilename, const std::string &alertFilename, const std::string &driveName) :
    m_driveName(driveName) 
{
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

    bool hasError = false;
    std::string errorStr;
    const std::string newline("\n");
    for (auto it = configJson.begin(); it != configJson.end(); it++) {
        if (it.key() == "rule-sets") {
            for (auto ruleSetIter = it.value().begin(); ruleSetIter != it.value().end(); ++ruleSetIter) {
                std::string ruleSetKey = ruleSetIter.key();
                nlohmann::json ruleSetValue = ruleSetIter.value();
                constructRuleSet(ruleSetKey, ruleSetValue);
            }
        } else if (it.key() == "finalize_image_writer") {
            it.value().get_to(m_finalizeImageWriter);
        }
    }

    if (hasError) {
        throw std::logic_error("ERROR: parsing configuration file " + configFilename + newline + errorStr);
    }

    bool doHeader = false;
    if (INVALID_FILE_ATTRIBUTES == GetFileAttributesA(alertFilename.c_str()) && GetLastError() == ERROR_FILE_NOT_FOUND) {
        doHeader = true;
    }
    m_alertFilePath.assign(alertFilename);
    m_alertFile = fopen(m_alertFilePath.c_str(), "a");
    if (!m_alertFile) {
        fprintf(stderr, "ERROR: Failed to open alert file %s\n", m_alertFilePath.c_str());
        exit(1);
    }
    if (doHeader) {
        fprintf(m_alertFile, "Drive\tExtraction Status\tDescription\tFilename\tPath\n");
    }
}

LogicalImagerRuleSet::~LogicalImagerRuleSet() {
    closeAlert();

    for (auto it = m_rules.begin(); it != m_rules.end(); ++it) {
        if (it->first)
            delete it->first;
    }
}

/*
* Close the alert file.
*/
void LogicalImagerRuleSet::closeAlert() const {
    if (m_alertFile) {
        fclose(m_alertFile);
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
TSK_RETVAL_ENUM LogicalImagerRuleSet::matches(TSK_FS_FILE *fs_file, const char *path) const {
    for (std::map<const RuleMatchResult *, std::vector<LogicalImagerRuleBase *>>::const_iterator it = m_rules.begin(); it != m_rules.end(); ++it) {
        const std::vector<LogicalImagerRuleBase *> vector = it->second;
        bool result = true;
        // All rules in this set must match (ANDed)
        for (std::vector<LogicalImagerRuleBase *>::const_iterator iter = vector.begin(); iter != vector.end(); ++iter) {
            if (!(*iter)->matches(fs_file, path)) {
                result = false; // bail as soon as one rule failed to match
                break;
            }
        }
        if (result) {
            // all rules match
            TSK_RETVAL_ENUM extractStatus = TSK_ERR;
            if (it->first->isShouldSave()) {
                extractStatus = extractFile(fs_file);
            }
            if (it->first->isShouldAlert()) {
                alert(extractStatus, it->first->getDescription(), fs_file, path);
            }
        }
    }
    return TSK_OK;
}

/*
* Get the full file path rule set
* 
* @returns the fulll file paths rule set
*/
const std::pair<const RuleMatchResult *, std::list<std::string>> LogicalImagerRuleSet::getFullFilePaths() const {
    return m_fullFilePaths;
}

/**
* Extract a file. tsk_img_writer_create must have been called prior to this method.
*
* @param fs_file File details
* @returns TSK_RETVAL_ENUM TSK_OK if file is extracted, TSK_ERR otherwise.
*/
TSK_RETVAL_ENUM LogicalImagerRuleSet::extractFile(TSK_FS_FILE *fs_file) const {
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

/*
* Write an file match alert record to the alert file. Also send same record to stdout.
* An alert file record contains tab-separated fields: 
*   - extractStatus
*   - description
*   - name
*   - path
*
* @param extractStatus Extract status: 0 if file was extracted, 1 otherwise
* @param description File match rule description
* @param fs_file TSK_FS_FILE that matches
* @param path Parent path of fs_file
*/
void LogicalImagerRuleSet::alert(TSK_RETVAL_ENUM extractStatus, const std::string &description, TSK_FS_FILE *fs_file, const char *path) const {
    if (fs_file->name && (strcmp(fs_file->name->name, ".") == 0 || strcmp(fs_file->name->name, "..") == 0)) {
        // Don't alert . and ..
        return;
    }
    // alert file format is "driveName<tab>extractStatus<tab>description<tab>name<tab>path"
    fprintf(m_alertFile, "%s\t%d\t%s\t%s\t%s\n",
        m_driveName.c_str(),
        extractStatus,
        description.c_str(),
        (fs_file->name ? fs_file->name->name : "name is null"),
        path);
    fprintf(stdout, "%s\t%d\t%s\t%s\t%s\n",
        m_driveName.c_str(),
        extractStatus,
        description.c_str(),
        (fs_file->name ? fs_file->name->name : "name is null"),
        path);
}
