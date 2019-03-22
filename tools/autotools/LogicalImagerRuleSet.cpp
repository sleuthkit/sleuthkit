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

#include <fstream>
#include <iostream>
#include <iterator>
#include <map>

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

    // find all 'readme.txt' files
    std::string filename_strs[] = {"ReadMe.txt", "Autoexec.bat"};
    std::set<std::string> filenames(filename_strs, filename_strs + sizeof(filename_strs) / sizeof(filename_strs[0]));
    LogicalImagerFilenameRule *filename_rule = new LogicalImagerFilenameRule(filenames);
    vector.clear();
    vector.push_back(filename_rule);
    m_rules.insert(std::pair<std::string, std::vector<LogicalImagerRuleBase *>>(std::string("readme.txt_rule"), vector));
}

LogicalImagerRuleSet::~LogicalImagerRuleSet() 
{
}

bool LogicalImagerRuleSet::matches(TSK_FS_FILE * fs_file, const char * path) const
{
    for (std::map<std::string, std::vector<LogicalImagerRuleBase *>>::const_iterator it = m_rules.begin(); it != m_rules.end(); ++it) {
        const std::vector<LogicalImagerRuleBase *> vector = it->second;
        bool result = true;
        for (std::vector<LogicalImagerRuleBase *>::const_iterator iter = vector.begin(); iter != vector.end(); ++iter) {
            if (!(*iter)->matches(fs_file, path)) {
                result = false;
                break;
            }
        }
        if (result)
            return true;
    }
    return false;
}