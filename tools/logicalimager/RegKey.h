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

#include <string>
#include <Windows.h>

#include "rejistry++\include\librejistry++.h"

 /**
  * RegKey - Abstracts a Registry key
  *
  */
class RegKey {
public:
    RegKey(std::wstring &keyName);
    RegKey(std::wstring &keyName, long numKeys, long numValues);
    ~RegKey();

    int initialize(const Rejistry::RegistryKey *regKey);

    std::wstring getKeyName() const { return m_keyName; };
    size_t getNumSubkeys() const { return m_numSubkeys; };
    size_t getNumValues() const { return m_numValues; };
    void getModifyTime(FILETIME& ft) const { memcpy((void *)&ft, (void *)&m_modifyTime, sizeof(FILETIME)); };
    const Rejistry::RegistryKey * getRegistryKey() const { return m_regKey; };

    void setModifyTime(FILETIME ft) { m_modifyTime = ft; }
    void setNumSubkeys(long numSubkeys) { m_numSubkeys = numSubkeys; }
    void setNumValues(long numValues) { m_numValues = numValues; }

    void print();

private:
    std::wstring m_keyName;
    FILETIME m_modifyTime;
    size_t m_numSubkeys;
    size_t m_numValues;

    const Rejistry::RegistryKey *m_regKey;
};
