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
#include <vector>
#include <windows.h>

#include "rejistry++\include\librejistry++.h"

 /**
  * RegValue - Abstracts a Registry Value
  */
class RegVal
{
public:
    RegVal();
    RegVal(std::wstring &valName);
    RegVal(std::wstring &valName, int valType, long valLen);
    RegVal(std::wstring &valName, int valType, long valLen, unsigned long dwData); // numeric data
    RegVal(std::wstring &valName, int valType, long valLen, unsigned _int64 dwData64); // numeric data 64
    RegVal(std::wstring &valName, int valType, long valLen, std::wstring &wsData); // string data
    RegVal(std::wstring &valName, int valType, long valLen, unsigned char *binData); // bin data
    RegVal(const Rejistry::RegistryValue *value);

    int initialize(const Rejistry::RegistryValue *value);

    void setValName(std::wstring &valName) { m_valName = valName; }
    void setValType(int valType) { m_valType = valType; }
    void setValLen(long valLen) { m_valLen = valLen; }

    void setDWORD(unsigned long dwData) { m_dwData = dwData; }
    void setQWORD(unsigned _int64 dwData64) { m_dwData64 = dwData64; }
    void setString(std::wstring &wsData) { m_wsData = wsData; }
    void setBinaryData(unsigned char *pData);
    void addMultiStringData(std::wstring &strData); // multi string data

    std::wstring getValName() const { return m_valName; };
    int getValType() const { return m_valType; };
    long getValLen() const { return m_valLen; };

    unsigned long getDWORD() const { return m_dwData; }
    unsigned _int64 getDWORD64() const { return m_dwData64; }
    std::wstring getString() const { return m_wsData; }
    long getBinary(std::vector<unsigned char *>& vBytes) const;
    const unsigned char *getBinary() const { return &m_vBytes[0]; };
    std::vector<std::wstring> getMultiString() const { return m_vMultiString; };

    bool isString() { return (m_valType == REG_SZ) || (m_valType == REG_EXPAND_SZ); }
    bool isDWORD() { return (m_valType == REG_DWORD) || (m_valType == REG_DWORD_LITTLE_ENDIAN) || (m_valType == REG_DWORD_BIG_ENDIAN); }
    bool isQWORD() { return (m_valType == REG_QWORD) || (m_valType == REG_QWORD_LITTLE_ENDIAN); }
    bool isBinary() { return (m_valType == REG_BINARY); }
    bool isMultiString() { return (m_valType == REG_MULTI_SZ); }

    std::string valTypeStr();
    std::wstring dataToStr();
    void print();

private:
    Rejistry::RegistryValue *m_registryValue;

    // metadata
    std::wstring m_valName;
    int m_valType;
    long m_valLen;

    // data
    unsigned long       m_dwData;
    unsigned _int64     m_dwData64;
    std::wstring m_wsData;
    std::vector<unsigned char> m_vBytes;
    std::vector<std::wstring> m_vMultiString;
};
