/***************************************************************************
** This data and information is proprietary to, and a valuable trade secret
** of, Basis Technology Corp.  It is given in confidence by Basis Technology
** and may only be used as permitted under the license agreement under which
** it has been distributed, and in no other way.
**
** Copyright (c) 2014 Basis Technology Corp. All rights reserved.
**
** The technical data and information provided herein are provided with
** `limited rights', and the computer software provided herein is provided
** with `restricted rights' as those terms are defined in DAR and ASPR
** 7-104.9(a).
***************************************************************************/

#include "RegFileInfo.h"

RegFileInfo::RegFileInfo(std::string aName, std::string aPath, RegHiveType::Enum a_hiveType, TSK_OFF_T aOff, TSK_INUM_T aMetaAddr, RegParser *a_regParser) :
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

RegFileInfo::~RegFileInfo()
{
    delete m_regParser;
}

RegHiveType::Enum RegFileInfo::hiveNameToType(const std::string aName)
{
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
