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
#include <vector>
#include <windows.h>

#include "rejistry++\include\librejistry++.h"

using namespace std;

/**
 * RegValue - Abstracts a Registry Value
 *                 
 *
 */
class RegVal
{
 public:
  RegVal();
  RegVal(wstring valName);
  RegVal(wstring valName, int valType, long valLen);
  RegVal(wstring valName, int valType, long valLen, unsigned long dwData); // numeric data
  RegVal(wstring valName, int valType, long valLen, unsigned _int64 dwData64); // numeric data 64
  RegVal(wstring valName, int valType, long valLen, wstring wsData); // string data
  RegVal(wstring valName, int valType, long valLen, unsigned char * binData); // bin data
  RegVal(const Rejistry::RegistryValue * value);

  int initialize(const Rejistry::RegistryValue * value);

  void setValName(wstring valName)  { m_valName = valName; }
  void setValType(int valType)  { m_valType = valType; }
  void setValLen(long valLen)  {  m_valLen = valLen; }

  void setDWORD(unsigned long dwData) { m_dwData = dwData; }
  void setQWORD(unsigned _int64 dwData64) { m_dwData64 = dwData64; }
  void setString(wstring wsData) { m_wsData = wsData; }
  void setBinaryData(unsigned char *pData);
  void addMultiStringData(wstring strData); // multi string data

  wstring getValName() const { return m_valName; }; 
  int getValType() const { return m_valType; };
  long getValLen() const { return m_valLen; };
  
  unsigned long getDWORD() const { return m_dwData; }
  unsigned _int64 getDWORD64() const { return m_dwData64; }
  wstring getString() const { return m_wsData; }
  long getBinary(vector<unsigned char *>& vBytes) const;
  const unsigned char * getBinary() const { return &m_vBytes[0];};
  vector<wstring> getMultiString() const { return m_vMultiString;};

  bool isString() { return (m_valType == REG_SZ) || (m_valType == REG_EXPAND_SZ) ; }
  bool isDWORD()  { return (m_valType == REG_DWORD) || (m_valType == REG_DWORD_LITTLE_ENDIAN) || (m_valType == REG_DWORD_BIG_ENDIAN); }
  bool isQWORD()  { return (m_valType == REG_QWORD) || (m_valType == REG_QWORD_LITTLE_ENDIAN); }
  bool isBinary()      { return (m_valType == REG_BINARY); }   
  bool isMultiString() { return (m_valType == REG_MULTI_SZ); }
    
  string  valTypeStr();
  wstring dataToStr();
  void print();

 private:
  Rejistry::RegistryValue * m_registryValue;

  // metadata
  wstring m_valName;
  int m_valType;
  long m_valLen;

  // data
  unsigned long       m_dwData;    
  unsigned _int64     m_dwData64; 
  wstring m_wsData;
  vector<unsigned char> m_vBytes;
  std::vector<wstring> m_vMultiString;
};
