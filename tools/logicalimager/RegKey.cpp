/***************************************************************************
 ** This data and information is proprietary to, and a valuable trade secret
 ** of, Basis Technology Corp.  It is given in confidence by Basis Technology
 ** and may only be used as permitted under the license agreement under which
 ** it has been distributed, and in no other way.
 **
 ** Copyright (c) 2015 Basis Technology Corp. All rights reserved.
 **
 ** The technical data and information provided herein are provided with
 ** `limited rights', and the computer software provided herein is provided
 ** with `restricted rights' as those terms are defined in DAR and ASPR
 ** 7-104.9(a).
 ***************************************************************************/

#include <iostream>

#include "RegKey.h"

using namespace std;

RegKey::RegKey(wstring keyName) : m_regKey(NULL) {
  m_keyName = keyName;

  m_numSubkeys = -1;// unknown
  m_numValues = -1; // unknown

  m_modifyTime.dwLowDateTime = 0;
  m_modifyTime.dwHighDateTime = 0;

}

RegKey::RegKey(wstring keyName, long numSubkeys, long numValues) : m_regKey(NULL) {
  m_keyName = keyName;

  m_numSubkeys = numSubkeys;
  m_numValues = numValues;

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
 * @returns 0 if initialization is successful, otherwise false.
 */
int RegKey::initialize(const Rejistry::RegistryKey * regKey) {
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

void RegKey::print() {

  wcout << L"Key: " << m_keyName << endl;
  wcout << L"\t" << L"Subkeys: " << m_numSubkeys << endl;
  wcout << L"\t" << L"Values: " << m_numValues << endl;

}
