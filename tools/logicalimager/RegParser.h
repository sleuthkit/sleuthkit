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

#include "rejistry++\include\librejistry++.h"
#include "RegHiveType.h"
#include "tsk/tsk_tools_i.h"
#include "RegKey.h"
#include "RegVal.h"

/**
 * RegParser - a registry parser that uses the Rejistry++ library to search
 * the registry for keys/values.
 */
class RegParser
{
 public:

  RegParser(const RegHiveType::Enum aHiveType);
  RegParser(const std::wstring& filePath);
  ~RegParser();

  virtual int loadHive(TSK_FS_FILE * aHiveFile, RegHiveType::Enum aHiveType);

  // get the root key
  virtual int getRootKey(RegKey& aKey);

  // get the subkey for the given key name
  virtual int getKey(const wstring& keyName, RegKey& aKey);

  //returns all subkeys of given key
  virtual int getSubKeys(const wstring& keyName, vector<wstring>& subKeysList);
  virtual int getSubKeys(const wstring& keyName, vector<RegKey *>& subKeysList);

  // return the data for the given named value
  virtual int getValue(const wstring& keyName, const wstring& valName, RegVal& val );
  virtual int getValue(const RegKey * startKey, const wstring& subpathName, const wstring& valName, RegVal& val );

  // return all values for the given key
  virtual int getValues(const wstring& keyName, vector<RegVal *>& valList ); 
  virtual int getValues(const RegKey * startKey, const wstring& subpathName, vector<RegVal *>& valList ); 

 private:
  Rejistry::RegistryHive * m_registryHive;
  Rejistry::RegistryKey * m_rootKey;

  std::vector<std::wstring> splitKeyName(const std::wstring& keyName) const;
  const Rejistry::RegistryKey * findKey(const std::wstring& keyName, const Rejistry::RegistryKey* startingKey = NULL) const;
};
