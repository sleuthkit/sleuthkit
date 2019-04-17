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

#pragma once

#include <string>
#include <Windows.h>

#include "rejistry++\include\librejistry++.h"
using namespace std;

/**
 * RegKey - Abstracts a Registry key
 *                 
 */
class RegKey
{
 public:
  RegKey(wstring keyName);
  RegKey(wstring keyName, long numKeys, long numValues);
  ~RegKey();

  int initialize(const Rejistry::RegistryKey * regKey);

  wstring getKeyName() const { return m_keyName; }; 
  size_t getNumSubkeys() const { return m_numSubkeys; };
  size_t getNumValues() const { return m_numValues; };
  void getModifyTime(FILETIME& ft) const { memcpy((void *)&ft, (void *)&m_modifyTime , sizeof(FILETIME));};
  const Rejistry::RegistryKey * getRegistryKey() const { return m_regKey; };

  void setModifyTime(FILETIME ft) {m_modifyTime = ft; } 
  void setNumSubkeys(long numSubkeys)  { m_numSubkeys = numSubkeys; }
  void setNumValues(long numValues)  {  m_numValues = numValues; }
  
  void print();

 private:
  wstring m_keyName;
  FILETIME m_modifyTime;
  size_t m_numSubkeys;
  size_t m_numValues;

  const Rejistry::RegistryKey * m_regKey;

};
