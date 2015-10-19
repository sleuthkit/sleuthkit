/*
 *
 *  The Sleuth Kit
 *
 *  Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 *  Copyright (c) 2010-2015 Basis Technology Corporation. All Rights
 *  reserved.
 *
 *  This software is distributed under the Common Public License 1.0
 *
 *  This is a C++ port of the Rejistry library developed by Willi Ballenthin.
 *  See https://github.com/williballenthin/Rejistry for the original Java version.
 */

/**
 * \file Rejistry.cpp
 * This is a test driver for the Rejistry++ library.
 */
#include <iostream>
#include <fstream>
#include <iomanip>
#include <Windows.h>
#include <io.h>
#include <fcntl.h>
#include <codecvt>

#include "RegistryHiveFile.h"
#include "Record.h"

namespace Rejistry {
    std::wstring getBooleanString(bool b) {
        return (b ? L"True" : L"False");
    }

    void printDatetimeString(const uint64_t& dateTime) {

        SYSTEMTIME systemTime;
        FileTimeToSystemTime((LPFILETIME)&dateTime, &systemTime);

        std::wcout << std::dec << systemTime.wYear << "-"
            << std::setw(2) << std::setfill(L'0') << systemTime.wMonth << "-"
            << std::setw(2) << std::setfill(L'0') << std::dec << systemTime.wDay << "T"
            << std::setw(2) << std::setfill(L'0') << std::dec << systemTime.wHour << ":"
            << std::setw(2) << std::setfill(L'0') << std::dec << systemTime.wMinute << ":"
            << std::setw(2) << std::setfill(L'0') << std::dec << systemTime.wSecond << "."
            << std::setw(3) << std::setfill(L'0') << std::dec << systemTime.wMilliseconds << "Z";
    }

    void dumpHexString(const std::vector<uint8_t>& data, const uint32_t offset, const uint64_t length, const size_t linePadding) {
        uint8_t line[16];
        uint32_t lineIndex = 0;

        std::cout << "0x";
        std::cout << std::hex << std::setw(8) << std::setfill('0') << offset; 

        for (uint32_t i = offset; i < offset + length; ++i) {
            if (lineIndex == 16) {
                std::wcout << " ";

                for (uint32_t j = 0; j < 16; j++) {
                    if (line[j] >= ' ' && line[j] <= '~') {
                        std::cout << line[j];
                    }
                    else {
                        std::cout << ".";
                    }
                }

                std::cout << std::endl;
                for (uint16_t k = 0; k < linePadding; ++k) {
                    std::cout << " ";
                }
                std::cout << "0x" << std::hex << std::uppercase << std::setw(8) << i; 
                lineIndex = 0;
            }

            std::cout << " ";
            uint8_t b = data[i];
            std::wcout << std::hex << std::uppercase << std::setw(2) << std::setfill(L'0') << (int)b;

            line[lineIndex++] = data[i];

            if (lineIndex == 16 && i == offset + length -1) {
                std::cout << " ";

                for (uint32_t j = 0; j < 16; j++) {
                    if (line[j] >= ' ' && line[j] <= '~') {
                        std::cout << line[j];
                    }
                    else {
                        std::cout << ".";
                    }
                }
            }
        }

        if (lineIndex != 16) {
            uint16_t count = ((16 - lineIndex) * 3) + 1;
            for (uint16_t i = 0; i < count; ++i) {
                std::cout << " ";
            }

            for (uint32_t i = 0; i < lineIndex; ++i) {
                if (line[i] >= ' ' && line[i] <= '~') {
                    std::cout << line[i];
                }
                else {
                    std::cout << ".";
                }
            }
        }
    }


    void printVKRecord(const VKRecord::VKRecordPtr vkRecord, const std::wstring& prefix) {
        std::wcout << prefix << "vkrecord has name: " << getBooleanString(vkRecord->hasName()) << std::endl;
        std::wcout << prefix << "vkrecord has ascii name: " << getBooleanString(vkRecord->hasAsciiName()) << std::endl;
        std::wcout << prefix << "vkrecord name: " << vkRecord->getName() << std::endl;
        std::wcout << prefix << "vkrecord value type: " << ValueData::getValueType(vkRecord->getValueType()) << std::endl;
        std::wcout << prefix << "vkrecord data length: " << std::dec << vkRecord->getDataLength() << std::endl;

        ValueData::ValueDataPtr data = vkRecord->getValue();
        std::wcout << prefix << "vkrecord data: ";

        switch (data->getValueType()) {
        case ValueData::VALTYPE_SZ:
        case ValueData::VALTYPE_EXPAND_SZ:
            std::wcout << data->getAsString() << std::endl;
            break;
        case ValueData::VALTYPE_MULTI_SZ:
            {
                std::vector<std::wstring> stringList = data->getAsStringList();
                
                for (uint32_t i = 0; i < stringList.size(); ++i) {
                    if (i != 0) {
                        std::wcout << prefix << "               ";
                    }
                    std::wcout << stringList[i] << std::endl;
                }
            }
            break;
        case ValueData::VALTYPE_DWORD:
        case ValueData::VALTYPE_QWORD:
        case ValueData::VALTYPE_BIG_ENDIAN:
            std::wcout << std::hex << "0x" << data->getAsNumber() << std::endl;
            break;
        default:
            {
                std::wcout << std::endl << prefix << "               ";
                std::vector<uint8_t> rawData = data->getAsRawData();
                dumpHexString(rawData, 0, rawData.size(), prefix.size() + 15);
                std::wcout << std::endl;
            }
        }

    }

    void printNKRecord(const NKRecord::NKRecordPtr nkRecord, const std::wstring& prefix) {
        std::wcout << prefix << "nkrecord has classname: " << getBooleanString(nkRecord->hasClassname()) << std::endl;
        std::wcout << prefix << "nkrecord classname: " << nkRecord->getClassName() << std::endl;
        std::wcout << prefix << "nkrecord timestamp: "; printDatetimeString(nkRecord->getTimestamp()); std::wcout << std::endl;
        std::wcout << prefix << "nkrecord is root: " << getBooleanString(nkRecord->isRootKey()) << std::endl;
        std::wcout << prefix << "nkrecord name: " << nkRecord->getName() << std::endl;
        std::wcout << prefix << "nkrecord has parent: " << getBooleanString(nkRecord->hasParentRecord()) << std::endl;
        std::wcout << prefix << "nkrecord number of values: " << nkRecord->getNumberOfValues() << std::endl;
        std::wcout << prefix << "nkrecord number of subkeys: " << nkRecord->getSubkeyCount() << std::endl;

        VKRecord::AutoVKRecordPtrList vkList(nkRecord->getValueList()->getValues());
        VKRecord::VKRecordPtrList::iterator vkIter;
        for (vkIter = vkList.begin(); vkIter != vkList.end(); ++vkIter) {
            std::wcout << prefix << "  value: " << (*vkIter)->getName() << std::endl;
            printVKRecord((*vkIter), L"    " + prefix);
        }
    }

    void recurseNKRecord(NKRecord::NKRecordPtr nkRecord, const std::wstring& prefix) {
        printNKRecord(nkRecord, prefix);

        NKRecord::AutoNKRecordPtrList subkeyList(nkRecord->getSubkeyList()->getSubkeys());
        NKRecord::NKRecordPtrList::iterator it = subkeyList.begin();

        for (; it != subkeyList.end(); ++it) {
            std::wcout << prefix << "  key: " << (*it)->getName() << std::endl;
            recurseNKRecord((*it), L"    " + prefix);
        }

    }

    void processRegistryFile(wchar_t * regFilePath) {
        try {
            RegistryHiveFile registryFile(regFilePath);
            REGFHeader * header = registryFile.getHeader();
            std::wcout << "hive name: " << header->getHiveName() << std::endl;
            std::wcout << "major version: " << header->getMajorVersion() << std::endl;
            std::wcout << "minor version: " << header->getMinorVersion() << std::endl;

            HBIN::AutoHBINPtrList hbinList (header->getHBINs());
            std::wcout << "number of hbins: " << hbinList.size() << std::endl;

            std::wcout << "last hbin offset: " << header->getLastHbinOffset() << std::endl;

            HBIN::HBINPtrList::iterator it;
            int i = 0;
            for (it = hbinList.begin(); it != hbinList.end(); ++it) {
                std::wcout << "hbin " << i << ", relative offset first hbin: " << (*it)->getRelativeOffsetFirstHBIN() << std::endl;
                std::wcout << "hbin " << i << ", relative offset next hbin: " << (*it)->getRelativeOffsetNextHBIN() << std::endl;

                Cell::AutoCellPtrList cellList((*it)->getCells());
                Cell::CellPtrList::iterator cellIter;
                int j = 0;
                for (cellIter = cellList.begin(); cellIter != cellList.end(); ++cellIter) {
                    std::wcout << "hbin " << i << ", cell " << j << ", is allocated: " << ((*cellIter)->isActive() ? "yes" : "no") << std::endl;
                    std::wcout << "hbin " << i << ", cell " << j << ", length: " << (*cellIter)->getLength() << std::endl;
                    j++;
                }

                i++;
            }

            printNKRecord(header->getRootNKRecord(), L"root ");
            
            NKRecord::AutoNKRecordPtrList nkRecordList((header->getRootNKRecord()->getSubkeyList()->getSubkeys()));
            NKRecord::NKRecordPtrList::iterator keyIter = nkRecordList.begin();
            for (; keyIter != nkRecordList.end(); ++keyIter) {
                std::wcout << L"  " << (*keyIter)->getName() << std::endl;
                printNKRecord((*keyIter), L"    ");
            }

            recurseNKRecord(header->getRootNKRecord(), L"");
        }
        catch (std::exception& ex) {
            std::wcout << ex.what() << std::endl;
        }
    }
}

int wmain(int argc, wchar_t *argv[], wchar_t *envp[])
{
    if (argc < 2) {
        std::wcout << "Usage: " << argv[0] << " <path to registry file>" << std::endl;
        exit(1);
    }

    std::wcout.imbue(std::locale(std::wcout.getloc(), new std::codecvt_utf8_utf16<wchar_t>()));
    Rejistry::processRegistryFile(argv[1]);
}