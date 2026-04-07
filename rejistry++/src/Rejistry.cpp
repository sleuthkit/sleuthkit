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

#include "RegistryHiveFile.h"
#include "RegistryHiveBuffer.h"
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

        std::wcout << L"0x";
        std::wcout << std::hex << std::setw(8) << std::setfill(L'0') << offset;

        for (uint32_t i = offset; i < offset + length; ++i) {
            if (lineIndex == 16) {
                std::wcout << L" ";

                for (uint32_t j = 0; j < 16; j++) {
                    std::wcout << (wchar_t)(line[j] >= ' ' && line[j] <= '~' ? line[j] : '.');
                }

                std::wcout << std::endl;
                for (uint16_t k = 0; k < linePadding; ++k) {
                    std::wcout << L" ";
                }
                std::wcout << L"0x" << std::hex << std::uppercase << std::setw(8) << i;
                lineIndex = 0;
            }

            std::wcout << L" ";
            std::wcout << std::hex << std::uppercase << std::setw(2) << std::setfill(L'0') << (int)data[i];

            line[lineIndex++] = data[i];

            if (lineIndex == 16 && i == offset + length - 1) {
                std::wcout << L" ";
                for (uint32_t j = 0; j < 16; j++) {
                    std::wcout << (wchar_t)(line[j] >= ' ' && line[j] <= '~' ? line[j] : '.');
                }
            }
        }

        if (lineIndex != 16) {
            uint16_t count = ((16 - lineIndex) * 3) + 1;
            for (uint16_t i = 0; i < count; ++i) {
                std::wcout << L" ";
            }
            for (uint32_t i = 0; i < lineIndex; ++i) {
                std::wcout << (wchar_t)(line[i] >= ' ' && line[i] <= '~' ? line[i] : '.');
            }
        }
    }


    void printVKRecord(const VKRecord* vkRecord, const std::wstring& prefix) {
        try {

            std::wcout << prefix << "vkrecord has name: " << getBooleanString(vkRecord->hasName()) << std::endl;
            std::wcout << prefix << "vkrecord has ascii name: " << getBooleanString(vkRecord->hasAsciiName()) << std::endl;
            std::wcout << prefix << "vkrecord name: " << vkRecord->getName() << std::endl;
            std::wcout << prefix << "vkrecord value type: " << ValueData::getValueType(vkRecord->getValueType()) << std::endl;
            std::wcout << prefix << "vkrecord data length: " << std::dec << vkRecord->getDataLength() << std::endl;

            ValueData::ValueDataUniqPtr data = vkRecord->getValue();
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
            case ValueData::VALTYPE_FILETIME:
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
        catch (std::exception& ex) {
            std::wcout << "printVKRecord exception: " << ex.what() << std::endl;
        }
    }

    void printNKRecord(const NKRecord* nkRecord, const std::wstring& prefix) {
        try {
            std::wcout << prefix << "nkrecord has classname: " << getBooleanString(nkRecord->hasClassname()) << std::endl;
            std::wcout << prefix << "nkrecord classname: " << nkRecord->getClassName() << std::endl;
            std::wcout << prefix << "nkrecord timestamp: "; printDatetimeString(nkRecord->getTimestamp()); std::wcout << std::endl;
            std::wcout << prefix << "nkrecord is root: " << getBooleanString(nkRecord->isRootKey()) << std::endl;
            std::wcout << prefix << "nkrecord name: " << nkRecord->getName() << std::endl;
            std::wcout << prefix << "nkrecord has parent: " << getBooleanString(nkRecord->hasParentRecord()) << std::endl;
            std::wcout << prefix << "nkrecord number of values: " << nkRecord->getNumberOfValues() << std::endl;
            std::wcout << prefix << "nkrecord number of subkeys: " << nkRecord->getSubkeyCount() << std::endl;

            for (auto& vkRecord : nkRecord->getValueList()->getValues()) {
                std::wcout << prefix << "  value: " << vkRecord->getName() << std::endl;
                printVKRecord(vkRecord.get(), L"    " + prefix);
            }
        }
        catch (std::exception& ex) {
            std::wcout << "printNKRecord exception: " << ex.what() << std::endl;
        }
    }

    void recurseNKRecord(NKRecord* nkRecord, const std::wstring& prefix) {
        printNKRecord(nkRecord, prefix);

        NKRecord::NKRecordUniqPtrList subkeyList = nkRecord->getSubkeyList()->getSubkeys();
        for (auto& nk : subkeyList) {
            std::wcout << prefix << "  key: " << nk->getName() << std::endl;
            recurseNKRecord(nk.get(), L"    " + prefix);
        }
    }

    void processRegistryHive(RegistryHive& hive) {
        // Save and restore stream flags so repeated calls don't inherit
        // hex/fill state left behind by printVKRecord/dumpHexString.
        std::ios_base::fmtflags savedFlags = std::wcout.flags();
        std::streamsize savedWidth = std::wcout.width(0);
        wchar_t savedFill = std::wcout.fill(L' ');
        std::wcout << std::dec;

        try {
            auto header = hive.getHeader();
            std::wcout << "hive name: " << header->getHiveName() << std::endl;
            std::wcout << "major version: " << header->getMajorVersion() << std::endl;
            std::wcout << "minor version: " << header->getMinorVersion() << std::endl;
            std::wcout << "hive sync: " << (header->isSynchronized() ? "Yes" : "No") << std::endl;

            auto hbinList(header->getHBINs());
            std::wcout << "number of hbins: " << hbinList.size() << std::endl;
            std::wcout << "last hbin offset: " << header->getLastHbinOffset() << std::endl;

            int i = 0;
            for (auto& hbin : hbinList) {
                std::wcout << "hbin " << i << ", relative offset first hbin: " << hbin->getRelativeOffsetFirstHBIN() << std::endl;
                std::wcout << "hbin " << i << ", relative offset next hbin: " << hbin->getRelativeOffsetNextHBIN() << std::endl;

                int j = 0;
                for (auto& cell : hbin->getCells()) {
                    std::wcout << "hbin " << i << ", cell " << j << ", is allocated: " << (cell->isActive() ? "yes" : "no") << std::endl;
                    std::wcout << "hbin " << i << ", cell " << j << ", length: " << cell->getLength() << std::endl;
                    j++;
                }
                i++;
            }

            auto root = header->getRootNKRecord();
            recurseNKRecord(root.get(), L"");
        }
        catch (std::exception& ex) {
            std::wcout << "processRegistryHive exception: " << ex.what() << std::endl;
        }

        std::wcout.flags(savedFlags);
        std::wcout.width(savedWidth);
        std::wcout.fill(savedFill);
    }

    void processRegistryBuffer(wchar_t * regFilePath) {
        // Read entire file into memory
        std::ifstream file(regFilePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            std::wcout << "processRegistryBuffer: failed to open file" << std::endl;
            return;
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<uint8_t> buffer(static_cast<size_t>(size));
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
            std::wcout << "processRegistryBuffer: failed to read file" << std::endl;
            return;
        }

        try {
            std::wcout << L"=== RegistryHiveBuffer ===" << std::endl;
            RegistryHiveBuffer hiveBuffer(buffer.data(), static_cast<uint32_t>(size));
            processRegistryHive(hiveBuffer);
        }
        catch (std::exception& ex) {
            std::wcout << "processRegistryBuffer exception: " << ex.what() << std::endl;
        }
    }

    void processRegistryFile(wchar_t * regFilePath) {
        try {
            std::wcout << L"=== RegistryHiveFile ===" << std::endl;
            RegistryHiveFile registryFile(regFilePath);
            processRegistryHive(registryFile);
        }
        catch (std::exception& ex) {
            std::wcout << "processRegistryFile exception: " << ex.what() << std::endl;
        }
    }
}

int wmain(int argc, wchar_t *argv[], wchar_t *envp[])
{
    if (argc < 2) {
        std::wcout << L"Usage: " << argv[0] << L" <path to registry file> [output file]" << std::endl;
        exit(1);
    }

    if (argc >= 3) {
        // Redirect stdout to the output file at the OS level, then set UTF-8
        // text mode. This is more reliable than imbuing with codecvt facets.
        if (_wfreopen(argv[2], L"w", stdout) == nullptr) {
            std::wcerr << L"Failed to open output file: " << argv[2] << std::endl;
            exit(1);
        }
        _setmode(_fileno(stdout), _O_U8TEXT);
    }
    else {
        // No output file — write UTF-16 directly to the console
        _setmode(_fileno(stdout), _O_U16TEXT);
    }

    Rejistry::processRegistryFile(argv[1]);
    Rejistry::processRegistryBuffer(argv[1]);
}