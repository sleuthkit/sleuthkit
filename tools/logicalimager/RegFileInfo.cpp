/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2019 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

#include "RegFileInfo.h"

RegFileInfo::RegFileInfo(std::string &aName, std::string &aPath, RegHiveType::Enum a_hiveType, 
                         TSK_OFF_T aOff, TSK_INUM_T aMetaAddr, RegParser *a_regParser) :
    m_name(aName),
    m_path(aPath),
    m_hiveType(a_hiveType),
    m_off(aOff),
    m_metaAddr(aMetaAddr),
    m_regParser(a_regParser)
{
    m_userName.clear();
    m_userSID.clear();
}

RegFileInfo::~RegFileInfo() {
    delete m_regParser;
}

/**
* Covert a hive name to a hive type.
*
* @param aName hive name
* @returns RegHiveType::Enum hive type
*/
RegHiveType::Enum RegFileInfo::hiveNameToType(const std::string &aName) {
    if (0 == _stricmp("SYSTEM", aName.c_str()))
        return RegHiveType::SYSTEM;
    else if (0 == _stricmp("SOFTWARE", aName.c_str()))
        return RegHiveType::SOFTWARE;
    else if (0 == _stricmp("SECURITY", aName.c_str()))
        return RegHiveType::SECURITY;
    else if (0 == _stricmp("SAM", aName.c_str()))
        return RegHiveType::SAM;
    else if (0 == _stricmp("NTUSER.DAT", aName.c_str()))
        return RegHiveType::NTUSER;
    else if (0 == _stricmp("USRCLASS.DAT", aName.c_str()))
        return RegHiveType::USRCLASS;
    else
        return RegHiveType::UNKNOWN;
}
