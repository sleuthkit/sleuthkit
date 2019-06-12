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
* Contains the class definitions for the Logicial Imager Rule Configuration.
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

/*
* Construct the LogicalImagerRuleSet based on a configuration filename
* The configuration file is in JSON format. 
* It has the following key and values.

* "finalize_image_writer" is optional. Default is false. If true, it will finalize the image writer by writing the
*     remaing sectors to the sparse_image.vhd file.
* "rule-sets" is required. It is a list of rule-set.
* A rule set is has a "set-name" (required) and a list of "rules"
* A rule is has the following key/value pairs:
     "name" - name of the rule (required)
     "description" - rule description (required)
     "shouldSave" is optional. Default is true. If true, any matched files will be save to the sparse_image.vhd.
     "shouldAlert" is optional. Default is false. If true, an alert record will be send to the console and the alert file.

An example:
{
  "finalize-image-writer": false,
  "rule-sets": [
    {
      "set-name": "rule-set-full-paths",
      "rules": [
        {
          "name": "rule-1",
          "description": "a full path rule",
          "shouldSave": true,
          "shouldAlert": true,
          "full-paths": [
            "Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/Sunset.jpg",
            "Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/WINTER.JPG",
            "/Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/Blue hills.jpg"
          ]
        }
      ]
    },
    {
      "set-name": "rule-set-full-paths-2",
      "rules": [
        {
          "name": "rule-2",
          "description": "a full path rule 2",
          "shouldSave": true,
          "shouldAlert": true,
          "full-paths": [
            "Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/Sunset.jpg",
            "/AUTOEXEC.BAT"
          ]
        }
      ]
    },
    {
      "set-name": "rule-set-1",
      "rules": [
        {
          "name": "example-rule-1",
          "description": "find file with extension png",
          "shouldSave": true,
          "shouldAlert": true,
          "extensions": [
            "png",
            "gif"
          ],
          "folder-names": [
            "Google"
          ]
        },
        {
          "name": "example-rule-2",
          "description": "Find all 'readme.txt' and 'autoexec.bat' files",
          "shouldSave": true,
          "shouldAlert": true,
          "file-names": [
            "readme.txt",
            "autoexec.bat"
          ]
        },
        {
          "name": "example-rule-3",
          "description": "find files newer than 2012-03-22",
          "shouldSave": false,
          "shouldAlert": true,
          "date-range": {
            "min": "2012-03-22"
          }
        },
        {
          "name": "example-rule-4",
          "shouldAlert": false,
          "shouldSave": true,
          "description": "find files newer than 30 days",
          "date-range": {
            "min-days": 30
          }
        },
        {
          "name": "example-rule-5",
          "description": "find all png files under the user folder",
          "shouldSave": true,
          "shouldAlert": true,
          "extensions": [
            "png"
          ],
          "folder-names": [
            "[USER_FOLDER]/My Documents/Downloads"
          ]
        }
      ]
    },
    {
      "set-name": "rule-set-3",
      "rules": [
        {
          "name": "rule-1",
          "description": "find file with extension jpg",
          "shouldSave": true,
          "shouldAlert": true,
          "extensions": [
            "jpg"
          ],
          "folder-names": [
            "My Pictures"
          ]
        }
      ]
    },
    {
      "set-name": "encryption-rule",
      "rules": [
        {
          "name": "encryption-rule",
          "description": "find encryption programs",
          "shouldSave": true,
          "shouldAlert": true,
          "file-names": [
            "truecrypt.exe"
          ]
        }
      ]
    }
  ]
}

* @param configFilename Configuration filename of the rule set
* @param callbackFunc A callback function when a file matches.
* @throws std::logic_error if there is any error
*/

LogicalImagerConfiguration::LogicalImagerConfiguration(const std::string &configFilename, LogicalImagerRuleSet::matchCallback callbackFunc) :
    m_callbackFunc(callbackFunc)
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
        (void)(*iter)->matches(fs_file, path, m_callbackFunc);
    }
    return TSK_OK;
}

/**
* Return a list of full-paths rule sets in the Logical Imager Configuration
* @returns each element in the list consists of a RuleMatchResult and a list of full-paths.
*/
const std::vector<std::pair<const RuleMatchResult *, std::list<std::string>>> LogicalImagerConfiguration::getFullFilePaths() const
{
    std::vector<std::pair<const RuleMatchResult *, std::list<std::string>>> vector;
    for (std::vector<LogicalImagerRuleSet *>::const_iterator iter = m_ruleSets.begin(); iter != m_ruleSets.end(); ++iter) {
        vector.push_back((*iter)->getFullFilePaths());
    }
    return vector;
}
