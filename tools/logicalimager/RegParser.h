/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2019 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

#pragma once

#include "rejistry++\include\librejistry++.h"
#include "RegHiveType.h"
#include "tsk/tsk_tools_i.h"
#include "RegKey.h"
#include "RegVal.h"

 /**
  * RegParser - a registry parser that uses the Rejistry++ library to search
  * the registry for keys/values.
  */
class RegParser {
public:
    RegParser(const RegHiveType::Enum aHiveType);
    RegParser(const std::wstring &filePath);
    ~RegParser();

    virtual int loadHive(TSK_FS_FILE *aHiveFile, RegHiveType::Enum aHiveType);

    // get the root key
    virtual int getRootKey(RegKey &aKey);

    // get the subkey for the given key name
    virtual int getKey(const std::wstring &keyName, RegKey &aKey);

    //returns all subkeys of given key
    virtual int getSubKeys(const std::wstring &keyName, std::vector<std::wstring> &subKeysList);
    virtual int getSubKeys(const std::wstring &keyName, std::vector<RegKey *> &subKeysList);

    // return the data for the given named value
    virtual int getValue(const std::wstring &keyName, const std::wstring &valName, RegVal &val);
    virtual int getValue(const RegKey *startKey, const std::wstring &subpathName, const std::wstring &valName, RegVal &val);

    // return all values for the given key
    virtual int getValues(const std::wstring &keyName, std::vector<RegVal *> &valList);
    virtual int getValues(const RegKey *startKey, const std::wstring &subpathName, std::vector<RegVal *> &valList);

private:
    Rejistry::RegistryHive *m_registryHive;
    Rejistry::RegistryKey *m_rootKey;

    std::vector<std::wstring> splitKeyName(const std::wstring &keyName) const;
    const Rejistry::RegistryKey *findKey(const std::wstring &keyName, const Rejistry::RegistryKey *startingKey = NULL) const;

    RegParser() = delete;
    RegParser(const RegParser &) = delete;
    RegParser& operator=(const RegParser&) = delete;
};
