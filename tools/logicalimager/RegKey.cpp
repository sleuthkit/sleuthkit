/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2019 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

#include <iostream>

#include "RegKey.h"

RegKey::RegKey(std::wstring &keyName) : m_regKey(NULL), m_keyName(keyName) {
    m_numSubkeys = -1;// unknown
    m_numValues = -1; // unknown

    m_modifyTime.dwLowDateTime = 0;
    m_modifyTime.dwHighDateTime = 0;
}

RegKey::RegKey(std::wstring &keyName, long numSubkeys, long numValues) : 
    m_regKey(NULL), 
    m_keyName(keyName),
    m_numSubkeys(numSubkeys),
    m_numValues(numValues)
{
    m_modifyTime.dwLowDateTime = 0;
    m_modifyTime.dwHighDateTime = 0;
}

RegKey::~RegKey() {
    if (m_regKey != NULL) {
        delete m_regKey;
        m_regKey = NULL;
    }
}

/**
 * Initialize a RegKey object from a Rejistry::RegistryKey object.
 *
 * @param regKey a Rejistry::RegistryKey object
 * @returns 0 if initialization is successful, otherwise -1.
 */
int RegKey::initialize(const Rejistry::RegistryKey *regKey) {
    if (regKey == NULL) {
        return -1;
    }

    m_keyName = regKey->getName();
    m_numSubkeys = regKey->getSubkeyList().size();
    m_numValues = regKey->getValueList().size();
    uint64_t timestamp = regKey->getTimestamp();
    m_modifyTime.dwLowDateTime = (DWORD)(timestamp & 0xFFFFFFFF);
    m_modifyTime.dwHighDateTime = (DWORD)(timestamp >> 32);

    m_regKey = new Rejistry::RegistryKey(*regKey);

    return 0;
}

/**
* Print the RegKey
*/
void RegKey::print() {
    std::wcout << L"Key: " << m_keyName << std::endl;
    std::wcout << L"\t" << L"Subkeys: " << m_numSubkeys << std::endl;
    std::wcout << L"\t" << L"Values: " << m_numValues << std::endl;
}
