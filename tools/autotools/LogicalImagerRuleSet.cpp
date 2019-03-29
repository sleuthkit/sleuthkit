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

/**
 * Construct the LogicalImagerRuleSet based on a configuration filename
 * @param configFilename Configuration filename of the rule set
 *
 */
LogicalImagerRuleSet::LogicalImagerRuleSet(const std::string configFilename)
{
    // TODO: read the config yaml file and construct the m_rules map
    
    // Testing TSKHlprPath2Inum

    // Non-Ascii paths

    char *u8str = u8"جهاد_files名門大洋";
    fprintf(stdout, "Printing utf-8 strings\n");
    fprintf(stdout, "%s\n", u8str);
    fprintf(stdout, "%s\n", u8"Hello 名門大洋 aäbcdefghijklmnoöpqrsßtuüvwxy");

    char *utf8str = u8"جهاد_files";
    fprintf(stdout, "%s\n", utf8str);

    // File path with an Arabic folder name in the XP image
    m_filePaths.push_back(u8"Documents and Settings/John/My Documents/Downloads/جهاد_files/layout.css");

    // Test existing files, with some duplicates
    m_filePaths.push_back("Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/Blue hills.jpg");
    m_filePaths.push_back("Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/sunset.jpg");
    m_filePaths.push_back("Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/water lilies.jpg");
    m_filePaths.push_back("Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/blue hills.jpg");
    m_filePaths.push_back("Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/BLUE HILLS.JPG");
    m_filePaths.push_back("Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/winter.jpg");
    m_filePaths.push_back("Documents and Settings/All Users/Documents/My Pictures/Sample  Pictures/blue hills.jpg");
    m_filePaths.push_back("Documents and Settings/All Users/Application Data/Adobe/Reader/9.4/ARM/AdbeRdr950_en_US.exe");
    m_filePaths.push_back("Documents and Settings\\All Users\\Documents\\My Pictures\\Sample Pictures\\Blue hills.jpg");

    // Test invalid or file not found paths
    m_filePaths.push_back("Documents and Settings/All Users/Application Data/Adobe/Reader/9.4/ARM/NoSuchFile.txt");
    m_filePaths.push_back("No Such Folder/No such subfolder/no-such-file.txt");
    m_filePaths.push_back("No Such Folder/No such subfolder/Winter.jpg");
    m_filePaths.push_back("");
    m_filePaths.push_back(".");
    m_filePaths.push_back("..");
    m_filePaths.push_back("C:");
    m_filePaths.push_back("*.*");
    m_filePaths.push_back("C:/Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/Blue hills.jpg");
    m_filePaths.push_back("/Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/Blue hills.jpg");
    m_filePaths.push_back("Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/../Sample Pictures/Blue hills.jpg");


    return;

    // The following rules are for mocking the config file and testing only.

    std::vector<LogicalImagerRuleBase *> vector;

    // find all pictures smaller than 3000 bytes in the Google folder
    std::string extension_strs[] = {"jpg", "jpeg", "gif", "png"};
    std::set<std::string> extensions(extension_strs, extension_strs + sizeof(extension_strs)/sizeof(extension_strs[0]));
    LogicalImagerExtensionRule *extension_rule = new LogicalImagerExtensionRule(extensions);

    std::string path_strs[] = {"Google"};
    std::set<std::string> paths(path_strs, path_strs + sizeof(path_strs) / sizeof(path_strs[0]));
    LogicalImagerPathRule *path_rule = new LogicalImagerPathRule(paths);
    LogicalImagerSizeRule *size_rule = new LogicalImagerSizeRule(0, 3000);
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
    m_rules.insert(std::pair<std::string, std::vector<LogicalImagerRuleBase *>>(std::string("filename_rule"), vector));

    // find by file size 
    std::string archive_strs[] = {"exe", "bin", "dll"};
    std::set<std::string> archive_extensions(archive_strs, archive_strs + sizeof(archive_strs) / sizeof(archive_strs[0]));
    LogicalImagerExtensionRule *archive_extension_rule = new LogicalImagerExtensionRule(archive_extensions);
    LogicalImagerSizeRule *archive_size_rule = new LogicalImagerSizeRule(10000000, 0);
    vector.clear();
    vector.push_back(archive_extension_rule);
    vector.push_back(archive_size_rule);
    m_rules.insert(std::pair<std::string, std::vector<LogicalImagerRuleBase *>>(std::string("really_big_programs_rule"), vector));

    // find files newer than 2012-03-21 (midnight)
    time_t min_time = stringToTimet("2012-03-21 00:00:00");
    LogicalImagerDateRule *date_rule = new LogicalImagerDateRule(min_time, 0);
    vector.clear();
    vector.push_back(date_rule);
    m_rules.insert(std::pair<std::string, std::vector<LogicalImagerRuleBase *>>(std::string("date_rule"), vector));
}

LogicalImagerRuleSet::~LogicalImagerRuleSet() 
{
}

/**
 * Given a file and its path, match it using the logical imager rule set.
 * All rules in a single set must matched (ANDed)
 * @param fs_file TSK_FS_FILE containing the filename
 * @param path parent path to fs_file
 * @returns true if match, false otherwise
 */
bool LogicalImagerRuleSet::matches(TSK_FS_FILE *fs_file, const char *path) const
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
            return true; // all rules match, no need to apply other rules in the set
    }
    return false;
}

const std::vector<std::string> LogicalImagerRuleSet::getFilePaths() const
{
    return m_filePaths;
}
