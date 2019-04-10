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
#include "LogicalImagerRuleSet.h"
#include "LogicalImagerExtensionRule.h"
#include "LogicalImagerPathRule.h"
#include "LogicalImagerSizeRule.h"
#include "LogicalImagerFilenameRule.h"
#include "LogicalImagerDateRule.h"
#include "json.h"

#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <sstream>
#include <locale>
#include <iomanip>
#include <exception>

/**
 * Convert a date time string to time_t
 * @param datetimeStr Date time string in yyyy-mm-dd HH:MM:SS format
 * @returns time_t time_t data
 *
 */
time_t stringToTimet(const std::string datetimeStr) {
    std::tm t = {};
    std::istringstream ss(datetimeStr);
    ss.imbue(std::locale("C"));
    ss >> std::get_time(&t, "%Y-%m-%d %H:%M:%S");
    if (ss.fail()) {
        std::cerr << "stringToTimet: Parse failed for " << datetimeStr << std::endl;
        exit(1);
    }
    time_t time = mktime(&t);
    return time;
}

void LogicalImagerRuleSet::testFullFilePath() {
    // NOTE: C++ source code containing UTF-8 string literals should be saved as "Unicode (UTF-8 without signature) - Codepage 65001"
    // The VC++ compiler option /utf-8 should be used to specify the source code is in UTF-8 encoding.
    // This is purely for testing only. We can revert this if UTF-8 string literals are removed from the source code.

    RuleMatchResult *ruleKey = new RuleMatchResult("Full file path search", true, true);
    std::list<std::string> filePaths;

    filePaths.push_back(u8"Documents and Settings/John/My Documents/Downloads");

    // File path with Chinese name in the fa_keyword_search_test.img
    filePaths.push_back(u8"上交所与香港特许秘书公会签合作协议.doc");
    filePaths.push_back(u8"胡锦涛.htm");

    // File path with an Arabic folder name in the XP image
    filePaths.push_back(u8"Documents and Settings/John/My Documents/Downloads/جهاد_files/layout.css");

    // Test existing files, with some duplicates
    filePaths.push_back("Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/Blue hills.jpg");
    filePaths.push_back("Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/sunset.jpg");
    filePaths.push_back("Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/water lilies.jpg");
    filePaths.push_back("Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/blue hills.jpg");
    filePaths.push_back("Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/BLUE HILLS.JPG");
    filePaths.push_back("Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/winter.jpg");
    filePaths.push_back("Documents and Settings/All Users/Documents/My Pictures/Sample  Pictures/blue hills.jpg");
    filePaths.push_back("Documents and Settings/All Users/Application Data/Adobe/Reader/9.4/ARM/AdbeRdr950_en_US.exe");
    filePaths.push_back("/Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/Blue hills.jpg");

    // Test invalid or file not found paths
    filePaths.push_back("Documents and Settings/All Users/Application Data/Adobe/Reader/9.4/ARM/NoSuchFile.txt");
    filePaths.push_back("No Such Folder/No such subfolder/no-such-file.txt");
    filePaths.push_back("No Such Folder/No such subfolder/Winter.jpg");
    filePaths.push_back("C:/Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/Blue hills.jpg");
    filePaths.push_back("Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/../Sample Pictures/Blue hills.jpg");
    filePaths.push_back("Documents and Settings\\All Users\\Documents\\My Pictures\\Sample Pictures\\Blue hills.jpg");

    m_fullFilePaths.first = ruleKey;
    m_fullFilePaths.second = filePaths;
}

void LogicalImagerRuleSet::testFullFolderPath() {
    std::vector<LogicalImagerRuleBase *> vector;
    RuleMatchResult *ruleKey = new RuleMatchResult("Test folder path search", true, true);

    std::string path_strs[] = { 
        "Documents and Settings/John/My Documents",
        "Documents and Settings/All Users/Documents/My Pictures/Sample Pictures"
    };
    std::set<std::string> paths(path_strs, path_strs + sizeof(path_strs) / sizeof(path_strs[0]));
    LogicalImagerPathRule *path_rule = new LogicalImagerPathRule(paths);
    vector.push_back(path_rule);

    // find all file/dir call "dirty-bomb_files"
    std::string filename_strs[] = { "dirty-bomb_files", "جهاد_files", "hidden" };
    std::set<std::string> filenames(filename_strs, filename_strs + sizeof(filename_strs) / sizeof(filename_strs[0]));
    LogicalImagerFilenameRule *filename_rule = new LogicalImagerFilenameRule(filenames);
    vector.push_back(filename_rule);

    m_rules.insert(std::pair<const RuleMatchResult *, std::vector<LogicalImagerRuleBase *>>(ruleKey, vector));
}

void LogicalImagerRuleSet::testExtension() {
    std::vector<LogicalImagerRuleBase *> vector;
    RuleMatchResult *ruleKey = new RuleMatchResult("Find all pictures smaller than 3000 bytes in the Google folder", true, true);

    // find all pictures smaller than 3000 bytes in the Google folder
    std::string extension_strs[] = { "jpg", "jpeg", "gif", "png" };
    std::set<std::string> extensions(extension_strs, extension_strs + sizeof(extension_strs) / sizeof(extension_strs[0]));
    LogicalImagerExtensionRule *extension_rule = new LogicalImagerExtensionRule(extensions);

    std::string path_strs[] = { "Google" };
    std::set<std::string> paths(path_strs, path_strs + sizeof(path_strs) / sizeof(path_strs[0]));
    LogicalImagerPathRule *path_rule = new LogicalImagerPathRule(paths);
    LogicalImagerSizeRule *size_rule = new LogicalImagerSizeRule(0, 3000);
    vector.push_back(extension_rule);
    vector.push_back(path_rule);
    vector.push_back(size_rule);
    m_rules.insert(std::pair<const RuleMatchResult *, std::vector<LogicalImagerRuleBase *>>(ruleKey, vector));
}

void LogicalImagerRuleSet::testFilename() {
    std::vector<LogicalImagerRuleBase *> vector;
    RuleMatchResult *ruleKey = new RuleMatchResult("find all 'readme.txt' and 'autoexec.bat' files", true, true);

    // find all 'readme.txt' and 'autoexec.bat' files
    std::string filename_strs[] = { "ReadMe.txt", "Autoexec.bat" };
    std::set<std::string> filenames(filename_strs, filename_strs + sizeof(filename_strs) / sizeof(filename_strs[0]));
    LogicalImagerFilenameRule *filename_rule = new LogicalImagerFilenameRule(filenames);
    vector.push_back(filename_rule);
    m_rules.insert(std::pair<const RuleMatchResult *, std::vector<LogicalImagerRuleBase *>>(ruleKey, vector));
}

void LogicalImagerRuleSet::testFileSize() {
    std::vector<LogicalImagerRuleBase *> vector;
    RuleMatchResult *ruleKey = new RuleMatchResult("find very large programs", false, true); // don't save, but alert

    // find by file size 
    std::string archive_strs[] = { "exe", "bin", "dll" };
    std::set<std::string> archive_extensions(archive_strs, archive_strs + sizeof(archive_strs) / sizeof(archive_strs[0]));
    LogicalImagerExtensionRule *archive_extension_rule = new LogicalImagerExtensionRule(archive_extensions);
    LogicalImagerSizeRule *archive_size_rule = new LogicalImagerSizeRule(10000000, 0);
    vector.push_back(archive_extension_rule);
    vector.push_back(archive_size_rule);
    m_rules.insert(std::pair<const RuleMatchResult *, std::vector<LogicalImagerRuleBase *>>(ruleKey, vector));
}

void LogicalImagerRuleSet::testFileDate() {
    std::vector<LogicalImagerRuleBase *> vector;
    RuleMatchResult *ruleKey = new RuleMatchResult("find files newer than 2012-03-21"); // default is save and not alert

    // find files newer than 2012-03-21 (midnight)
    time_t min_time = stringToTimet("2012-03-21 00:00:00");
    LogicalImagerDateRule *date_rule = new LogicalImagerDateRule(min_time, 0);
    vector.push_back(date_rule);
    m_rules.insert(std::pair<const RuleMatchResult *, std::vector<LogicalImagerRuleBase *>>(ruleKey, vector));
}

void LogicalImagerRuleSet::testUserFolder() {
    std::vector<LogicalImagerRuleBase *> vector;
    RuleMatchResult *ruleKey = new RuleMatchResult("find all png files under the user folder", true, true);

    // find all png files under the user folder
    std::string extension_strs[] = { "png" };
    std::set<std::string> extensions(extension_strs, extension_strs + sizeof(extension_strs) / sizeof(extension_strs[0]));
    LogicalImagerExtensionRule *extension_rule = new LogicalImagerExtensionRule(extensions);

    std::string path_strs[] = { 
        "[USER_FOLDER]/Documents/My Pictures/Sample Pictures/", 
        "[USER_FOLDER]/My Documents/Downloads/", 
        "[USER_FOLDER]/Local Settings/Application Data/Google/Chrome/" 
        };
    std::set<std::string> paths(path_strs, path_strs + sizeof(path_strs) / sizeof(path_strs[0]));
    LogicalImagerPathRule *path_rule = new LogicalImagerPathRule(paths);
    vector.push_back(extension_rule);
    vector.push_back(path_rule);
    m_rules.insert(std::pair<const RuleMatchResult *, std::vector<LogicalImagerRuleBase *>>(ruleKey, vector));
}

void LogicalImagerRuleSet::constructRuleSet(const std::string &ruleSetKey, nlohmann::json ruleSetValue) {
    std::string description;
    bool shouldSave;
    bool shouldAlert;

    ruleSetValue["description"].get_to(description);
    ruleSetValue["shouldSave"].get_to(shouldSave);
    ruleSetValue["shouldAlert"].get_to(shouldAlert);
    RuleMatchResult *ruleMatchKey = new RuleMatchResult(description, shouldSave, shouldAlert);
    std::vector<LogicalImagerRuleBase *> vector;

    auto jsonMap = ruleSetValue.get<std::unordered_map<std::string, nlohmann::json>>();
    for (auto ruleIter = jsonMap.begin(); ruleIter != jsonMap.end(); ++ruleIter) {
        std::string ruleKey = ruleIter->first;
        nlohmann::json ruleJson = ruleIter->second;
        if (ruleKey == "extensions") {
            std::set<std::string> extensions;
            for (auto valueIter = ruleJson.begin(); valueIter != ruleJson.end(); ++valueIter) {
                std::string str;
                valueIter.value().get_to(str);
                extensions.insert(str);
            }
            LogicalImagerExtensionRule *extensionRule = new LogicalImagerExtensionRule(extensions);
            vector.push_back(extensionRule);
        } else if (ruleKey == "file-names") {
            std::set<std::string> filenames;
            for (auto valueIter = ruleJson.begin(); valueIter != ruleJson.end(); ++valueIter) {
                std::string str;
                valueIter.value().get_to(str);
                filenames.insert(str);
            }
            LogicalImagerFilenameRule *filenameRule = new LogicalImagerFilenameRule(filenames);
            vector.push_back(filenameRule);
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
                    ruleJson["min"].get_to(sizeMin);
                } else if (iter->first == "max") {
                    ruleJson["max"].get_to(sizeMax);
                } else {
                    std::cerr << "WARNING: Unsupported key: " << iter->first << std::endl;
                }
            }
            LogicalImagerSizeRule *sizeRule = new LogicalImagerSizeRule(sizeMin, sizeMax);
            vector.push_back(sizeRule);
        } else if (ruleKey == "date-range") {
            time_t minTime = 0;
            time_t maxTime = 0;
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
                } else {
                    std::cerr << "WARNING: Unsupported key: " << iter->first << std::endl;
                }
            }
            LogicalImagerDateRule *dateRule = new LogicalImagerDateRule(minTime, maxTime);
            vector.push_back(dateRule);
        } else if (ruleKey == "full-paths") {
            std::list<std::string> fullPaths;
            for (auto valueIter = ruleJson.begin(); valueIter != ruleJson.end(); ++valueIter) {
                std::string str;
                valueIter.value().get_to(str);
                fullPaths.push_back(str);
            }
            m_fullFilePaths.first = ruleMatchKey;
            m_fullFilePaths.second = fullPaths;
            return;
        }
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
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string str = buffer.str();

    nlohmann::json configJson;
    try {
        configJson = nlohmann::json::parse(str);
    }
    catch (std::exception &e) {
        std::cerr << "ERROR parsing configuration file " << configFilename << std::endl;
        std::cerr << e.what() << std::endl;
        exit(1);
    }
//    std::cout << configJson.dump(4) << std::endl;

    for (auto it = configJson.begin(); it != configJson.end(); ++it) {
        if (it.key() == "rule-set") {
            for (auto ruleSetIter = it.value().begin(); ruleSetIter != it.value().end(); ++ruleSetIter) {
                std::string ruleSetKey = ruleSetIter.key();
                nlohmann::json ruleSetValue = ruleSetIter.value();
                constructRuleSet(ruleSetKey, ruleSetValue);
            }
        }
    }

    // The following rules are for mocking the config file and testing only.
    //testFullFolderPath();
    //testFullFilePath();
    //testExtension();
    //testFilename();
    //testFileSize();
    //testFileDate();
    //testUserFolder();
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
