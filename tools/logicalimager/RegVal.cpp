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
#include <sstream>
#include <string>
#include <iomanip>

#include "RegVal.h"

std::string ValTypStrArr[] = {
  "REG_NONE",                    // ( 0 )   // No value type
  "REG_SZ",                      // ( 1 )   // Unicode nul terminated string
  "REG_EXPAND_SZ",               // ( 2 )   // Unicode nul terminated string - (with environment variable references)                  
  "REG_BINARY",                  // ( 3 )   // Free form binary
  "REG_DWORD" ,                  // ( 4 )   // 32-bit number
  "REG_DWORD_BIG_ENDIAN ",       // ( 5 )   // 32-bit number
  "REG_LINK",                    // ( 6 )   // Symbolic Link (unicode)
  "REG_MULTI_SZ",                // ( 7 )   // Multiple Unicode strings
  "REG_RESOURCE_LIST",           // ( 8 )   // Resource list in the resource map
  "REG_FULL_RESOURCE_DESCRIPTOR", // ( 9 )  // Resource list in the hardware description
  "REG_RESOURCE_REQUIREMENTS_LIST", // ( 10 )
  "REG_QWORD",// ( 11 )  // 64-bit number
};

RegVal::RegVal() : m_registryValue(NULL) {
    m_valName.clear();
    m_valType = -1;
    m_valLen = -1;
    m_dwData = 0;
    m_dwData64 = 0;
    m_wsData.clear();
    m_vBytes.clear();
    m_vMultiString.clear();
}

RegVal::RegVal(std::wstring &valName) : m_registryValue(NULL), m_valName(valName) {
    m_valType = -1;
    m_valLen = -1;
    m_dwData = 0;
    m_dwData64 = 0;
    m_wsData.clear();
    m_vBytes.clear();
    m_vMultiString.clear();
}

RegVal::RegVal(std::wstring &valName, int valType, long valLen) : 
    m_registryValue(NULL),
    m_valName(valName),
    m_valType(valType),
    m_valLen(valLen) 
{
    m_dwData = 0;
    m_dwData64 = 0;
}

RegVal::RegVal(std::wstring &valName, int valType, long valLen, unsigned long dwData) :
    m_registryValue(NULL),
    m_valName(valName),
    m_valType(valType),
    m_valLen(valLen),
    m_dwData(dwData)
{
    m_dwData64 = 0;
}

RegVal::RegVal(std::wstring &valName, int valType, long valLen, unsigned _int64 dwData64) :
    m_registryValue(NULL),
    m_valName(valName),
    m_valType(valType),
    m_valLen(valLen),
    m_dwData64(dwData64)
{
    m_dwData = 0;
}

RegVal::RegVal(std::wstring &valName, int valType, long valLen, std::wstring &wsData) :
    m_registryValue(NULL),
    m_valName(valName),
    m_valType(valType),
    m_valLen(valLen),
    m_wsData(wsData)
{
    m_dwData = 0;
    m_dwData64 = 0;
}

RegVal::RegVal(std::wstring &valName, int valType, long valLen, unsigned char *binData) :
    m_registryValue(NULL),
    m_valName(valName),
    m_valType(valType),
    m_valLen(valLen)
{
    m_dwData = 0;
    m_dwData64 = 0;
    if (valLen >= 2) {
        m_vBytes.assign(&binData[0], &binData[valLen - 1]);
    }
}

RegVal::RegVal(const Rejistry::RegistryValue *value) {
    initialize(value);
}

/*
* Initialize a RegVal object
* 
* @param value Rejistry::RegistryValue pointer to value
* @returns 0 on success, -1 otherwise
*/
int RegVal::initialize(const Rejistry::RegistryValue *value) {
    try {
        m_valName = value->getName();
        m_valType = (int)value->getValueType();

        if (m_valType < REG_NONE || m_valType > REG_QWORD) {
            //std::wcerr << "Failed to initialize registry value due to unknown value type: " << m_valType << std::endl;
            return -1;
        }

        m_valLen = value->getValueLength();
        m_registryValue = new Rejistry::RegistryValue(*value);

        Rejistry::ValueData * valueData = value->getValue();

        switch (m_valType) {
        case REG_DWORD:
        case REG_DWORD_BIG_ENDIAN:
            m_dwData = (unsigned long)valueData->getAsNumber();
            break;
        case REG_QWORD:
            m_dwData64 = valueData->getAsNumber();
            break;
        case REG_SZ:
        case REG_EXPAND_SZ:
        case REG_LINK:
            m_wsData = valueData->getAsString();
            break;
        case REG_MULTI_SZ:
            m_vMultiString = valueData->getAsStringList();
            break;
        case REG_NONE:
        case REG_BINARY:
        case REG_RESOURCE_LIST:
        case REG_RESOURCE_REQUIREMENTS_LIST:
        case REG_FULL_RESOURCE_DESCRIPTOR:
            m_vBytes = valueData->getAsRawData();
            break;
        default:
            // This shouldn't happen because we check the range above.
            break;
        }
    }
    catch (Rejistry::RegistryParseException& e)
    {
        std::cerr << "Failed to initialize registry value due to registry parse exception: " << e.message() << std::endl;
        return -1;
    }
    return 0;
}

/*
* Set binary data
* 
* @param pData point to data
*/
void RegVal::setBinaryData(unsigned char *pData) {
    // @@@ BC: Seems like we should be forcing them to pass in the size of pData here

    m_vBytes.assign(&pData[0], &pData[m_valLen - 1]);
}

/*
* Add multiple string data
*
* @param strData reference to wstring data
*/
void RegVal::addMultiStringData(std::wstring &strData) {
    m_vMultiString.push_back(strData);
}

/*
* Get the valType string
* 
* @return string associated with valType value
*/
std::string RegVal::valTypeStr() {
    if ((m_valType < REG_NONE) || (m_valType > REG_QWORD)) {
        return "unknown";
    }
    else {
        return ValTypStrArr[m_valType];
    }
}

/*
* Print the RegVal object
*/
void RegVal::print() {
    std::wcout << L"Val Name: " << m_valName << std::endl;
    std::cout << "\t" << "Type: " << valTypeStr() << std::endl;
    std::cout << "\t" << "Len: " << m_valLen << std::endl;
    std::wcout << L"\t" << L"Data: " << dataToStr() << std::endl;
}

/*
* Return a buffer in hexadecimals
*
* @param buf buffer of data
* @param maxSize maximum size of string to return
* @param len size of buffer
* @returns string of hexadecimals representation of buffer
*/
std::string hexprintBuf(const unsigned char *buf, size_t maxSize, size_t len) {
    std::stringstream ss;

    size_t maxLen = min(maxSize, len);
    for (size_t i = 0; i < maxLen; ++i) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (unsigned short)buf[i] << " ";
        if (i && ((i + 1) % 16 == 0))
            ss << std::endl;
    }
    ss << std::endl;

    return ss.str();
}

/*
* Return RegVal data object as a wstring
*
* @returns wstring of the data 
*/
std::wstring RegVal::dataToStr() {
    std::wstringstream wss;

    if (isString()) {
        wss << m_wsData;
    }
    else if (isDWORD()) {
        wss << m_dwData;
    }
    else if (isQWORD()) {
        wss << m_dwData64;
    }
    else if (isBinary()) {
        //wss << toWide(hexprintBuf((const char *)&m_vBytes[0], m_vBytes.size(), 20 ));
        std::cout << hexprintBuf((const unsigned char *)&m_vBytes[0], m_vBytes.size(), 80);
    }
    else if (isMultiString()) {
        for (std::vector<std::wstring>::iterator it = m_vMultiString.begin(); it != m_vMultiString.end(); ++it) {
            wss << *it << ", ";
        }
    }
    return wss.str();
}
