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
* \file RegFileInfo.h
* Contains the class definitions for Registry File Info.
*/

#pragma once

#include <string>

#include "tsk/auto/tsk_auto.h"
#include "RegParser.h"
#include "RegHiveType.h"

class RegFileInfo {
public:
    RegFileInfo(std::string &aName, std::string &aPath, RegHiveType::Enum a_hiveType, TSK_OFF_T aOff, TSK_INUM_T aMetaAddr, RegParser *a_regParser);
    ~RegFileInfo(void);

    static RegHiveType::Enum hiveNameToType(const std::string &aName);

    std::string getName() const { return m_name; };
    std::string getPath() const { return m_path; };
    TSK_OFF_T getOffset() const { return m_off; };
    TSK_INUM_T getMetaAddr() const { return m_metaAddr; };
    RegHiveType::Enum getHiveType() const { return m_hiveType; };
    std::string getPathName() const { return m_path + "/" + m_name; };

    std::string  getUserName() const { return m_userName; };

    void setUserAccountName(const std::string & a_name) { m_userName = a_name; };
    void setUserSID(const std::string & a_sid) { m_userSID = a_sid; };
    RegParser &getRegParser() const { return *m_regParser; };

private:
    std::string m_name;
    std::string m_path;
    TSK_OFF_T m_off;
    TSK_INUM_T m_metaAddr;
    RegHiveType::Enum m_hiveType;
    RegParser *m_regParser;

    std::string m_userName;
    std::string m_userSID;
};

class CompareRegfileType {
public:
    bool operator()(RegFileInfo *lhs, RegFileInfo *rhs) { return lhs->getHiveType() < rhs->getHiveType(); }
};
