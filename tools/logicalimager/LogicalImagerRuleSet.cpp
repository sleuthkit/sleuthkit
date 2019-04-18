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
time_t stringToTimet(const std::string datetimeStr) {
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
 * @param configFilename Configuration filename of the rule set
 *
 */
LogicalImagerRuleSet::LogicalImagerRuleSet(const std::string &configFilename) {
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
}

LogicalImagerRuleSet::~LogicalImagerRuleSet() {
    for (auto it = m_rules.begin(); it != m_rules.end(); ++it) {
        if (it->first)
            delete it->first;
    }
}

/**
 * Given a file and its path, match it using the logical imager rule set.
 * All rules in a single set must matched (ANDed)
 * @param fs_file TSK_FS_FILE containing the filename
 * @param path parent path to fs_file
 * @returns RuleMatchResult * if match, NULL otherwise. Caller should delete the return object.
 */
RuleMatchResult *LogicalImagerRuleSet::matches(TSK_FS_FILE *fs_file, const char *path) const {
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
            // all rules match, no need to apply other rules in the set
            return new RuleMatchResult(it->first->getDescription(), it->first->isShouldSave(), it->first->isShouldAlert());
        }
    }
    return (RuleMatchResult *) NULL;
}

const std::pair<const RuleMatchResult *, std::list<std::string>> LogicalImagerRuleSet::getFullFilePaths() const {
    return m_fullFilePaths;
}
