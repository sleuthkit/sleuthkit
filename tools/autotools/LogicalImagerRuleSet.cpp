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

#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <sstream>
#include <locale>
#include <iomanip>

time_t stringToTimet(const std::string str) {
    std::tm t = {};
    std::istringstream ss(str);
    ss.imbue(std::locale("C"));
    ss >> std::get_time(&t, "%Y-%m-%d %H:%M:%S");
    if (ss.fail()) {
        std::cerr << "Parse failed\n";
        return 0;
    }
    else {
        std::cout << std::put_time(&t, "%Y-%m-%d") << std::endl;
    }
    time_t time = mktime(&t);
    return time;
}

LogicalImagerRuleSet::LogicalImagerRuleSet(const std::string configFilename)
{
    // TODO: read the config yaml file and construct the m_rules map
    
    // find all pictures smaller than 3000 bytes in the Google folder
    std::string extension_strs[] = {"jpg", "jpeg", "gif", "png"};
    std::set<std::string> extensions(extension_strs, extension_strs + sizeof(extension_strs)/sizeof(extension_strs[0]));
    LogicalImagerExtensionRule *extension_rule = new LogicalImagerExtensionRule(extensions);

    std::string path_strs[] = {"Google"};
    std::set<std::string> paths(path_strs, path_strs + sizeof(path_strs) / sizeof(path_strs[0]));
    LogicalImagerPathRule *path_rule = new LogicalImagerPathRule(paths);

    LogicalImagerSizeRule *size_rule = new LogicalImagerSizeRule(0, 3000);

    std::vector<LogicalImagerRuleBase *> vector;
    vector.push_back(extension_rule);
    vector.push_back(path_rule);
    vector.push_back(size_rule);
    m_rules.insert(std::pair<std::string, std::vector<LogicalImagerRuleBase *>>(std::string("pictures_smaller_than_3000_in_Google_folder_rule"), vector));

    // find all 'readme.txt' and 'autoexec.bat' files
    std::string filename_strs[] = {"ReadMe.txt", "Autoexec.bat"};
    std::set<std::string> filenames(filename_strs, filename_strs + sizeof(filename_strs) / sizeof(filename_strs[0]));
    LogicalImagerFilenameRule *filename_rule = new LogicalImagerFilenameRule(filenames);
    vector.clear();
    vector.push_back(filename_rule);
    m_rules.insert(std::pair<std::string, std::vector<LogicalImagerRuleBase *>>(std::string("readme.txt_rule"), vector));

    // find really big programs
    std::string archive_strs[] = {"exe", "bin", "dll"};
    std::set<std::string> archive_extensions(archive_strs, archive_strs + sizeof(archive_strs) / sizeof(archive_strs[0]));
    LogicalImagerExtensionRule *archive_extension_rule = new LogicalImagerExtensionRule(archive_extensions);
    LogicalImagerSizeRule *archive_size_rule = new LogicalImagerSizeRule(10000000, 0);
    vector.clear();
    vector.push_back(archive_extension_rule);
    vector.push_back(archive_size_rule);
    //m_rules.insert(std::pair<std::string, std::vector<LogicalImagerRuleBase *>>(std::string("really_big_archive_rule"), vector));

    // find files last modified between 2007-01-01 and 2007-01-31
    time_t min_time = stringToTimet("2007-12-01 00:00:00");
    time_t max_time = stringToTimet("2007-12-31 00:00:00");
    LogicalImagerDateRule *date_rule = new LogicalImagerDateRule(min_time, max_time);
    vector.clear();
    vector.push_back(date_rule);
    m_rules.insert(std::pair<std::string, std::vector<LogicalImagerRuleBase *>>(std::string("date_rule"), vector));

    // find files newer than 2014-01-01
    min_time = stringToTimet("2012-03-01 00:00:00");
    LogicalImagerDateRule *date2_rule = new LogicalImagerDateRule(min_time, 0);
    vector.clear();
    vector.push_back(date2_rule);
    m_rules.insert(std::pair<std::string, std::vector<LogicalImagerRuleBase *>>(std::string("date2_rule"), vector));

}

LogicalImagerRuleSet::~LogicalImagerRuleSet() 
{
}

bool LogicalImagerRuleSet::matches(TSK_FS_FILE * fs_file, const char * path) const
{
    for (std::map<std::string, std::vector<LogicalImagerRuleBase *>>::const_iterator it = m_rules.begin(); it != m_rules.end(); ++it) {
        const std::vector<LogicalImagerRuleBase *> vector = it->second;
        bool result = true;
        // All rules in this set must match (ANDed)
        for (std::vector<LogicalImagerRuleBase *>::const_iterator iter = vector.begin(); iter != vector.end(); ++iter) {
            if (!(*iter)->matches(fs_file, path)) {
                result = false; // bail as soon as one rule failed to match
                break;
            }
        }
        if (result)
            return true; // all rules match, return true. Don't need to apply other rules
    }
    return false;
}