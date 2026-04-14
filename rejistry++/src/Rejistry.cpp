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
 * Test driver for the Rejistry++ library.
 *
 * Exercises all public APIs (low-level NKRecord/VKRecord and high-level
 * RegistryKey/RegistryValue) in a single pass. Output is deterministic
 * and diffable against a known-good baseline to detect regressions.
 *
 * High-level RegistryKey/RegistryValue fields are compared against their
 * low-level equivalents; output is only produced on MISMATCH.  APIs that
 * are unique to the high-level layer (named lookups, getParent) are
 * always printed.
 */
#include <iostream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <map>
#define NOMINMAX
#include <Windows.h>
#include <io.h>
#include <fcntl.h>
#include <malloc.h>  // _resetstkoflw

#include "RegistryHiveFile.h"
#include "RegistryHiveBuffer.h"
#include "RegistryKey.h"
#include "Record.h"

namespace Rejistry {

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Summary statistics — accumulated during traversal, printed at end
    // -----------------------------------------------------------------------

    struct HiveStats {
        // HBIN / Cell counts (populated in processRegistryHive HBIN loop)
        uint32_t hbinCount = 0;
        uint32_t cellTotal = 0;
        uint32_t cellAllocated = 0;
        uint32_t cellUnallocated = 0;
        std::map<std::string, uint32_t> cellTypeCounts;  // signature -> count (allocated only)

        // Key / Subkey counts (populated in recurseAll)
        uint32_t keyCount = 0;
        std::map<std::string, uint32_t> subkeyListMagicCounts;  // magic -> count

        // Value counts (populated in recurseAll)
        uint32_t valueTotal = 0;
        std::map<std::wstring, uint32_t> valueTypeCounts;  // type name -> count

        // Extremes
        uint32_t maxSubkeysForKey = 0;
        uint32_t maxValuesForKey = 0;
        uint32_t deepestLevel = 0;

        void print() const {
            std::wcout << std::endl << L"=== Hive Summary ===" << std::endl;
            std::wcout << L"Number of HBIN records: " << std::dec << hbinCount << std::endl;

            std::wcout << L"Number of cells (total): " << cellTotal << std::endl;
            std::wcout << L"  Allocated: " << cellAllocated << std::endl;
            std::wcout << L"  Unallocated: " << cellUnallocated << std::endl;
            std::wcout << L"  Allocated cell types:" << std::endl;
            for (auto& kv : cellTypeCounts) {
                std::wcout << L"    " << kv.first.c_str() << L": " << kv.second << std::endl;
            }

            std::wcout << L"Number of keys enumerated: " << keyCount << std::endl;
            std::wcout << L"  Subkey list magic breakdown:" << std::endl;
            for (auto& kv : subkeyListMagicCounts) {
                std::wstring label = kv.first.empty() ? L"(empty)" : std::wstring(kv.first.begin(), kv.first.end());
                std::wcout << L"    " << label << L": " << kv.second << std::endl;
            }

            std::wcout << L"Number of values enumerated: " << valueTotal << std::endl;
            std::wcout << L"  Value type breakdown:" << std::endl;
            for (auto& kv : valueTypeCounts) {
                std::wcout << L"    " << kv.first << L": " << kv.second << std::endl;
            }

            std::wcout << L"Largest number of subkeys for a key: " << maxSubkeysForKey << std::endl;
            std::wcout << L"Largest number of values for a key: " << maxValuesForKey << std::endl;
            std::wcout << L"Deepest subkey level: " << deepestLevel << std::endl;
        }
    };

    // Global stats instance — reset per hive
    static HiveStats g_stats;

    // -----------------------------------------------------------------------
    // Low-level record printing
    // -----------------------------------------------------------------------

    void printVKRecord(const VKRecord* vkRecord, const std::wstring& prefix) {
        try {
            std::wcout << prefix << "vkrecord name: " << vkRecord->getName() << std::endl;
            std::wcout << prefix << "vkrecord has name: " << getBooleanString(vkRecord->hasName()) << std::endl;
            std::wcout << prefix << "vkrecord has ascii name: " << getBooleanString(vkRecord->hasAsciiName()) << std::endl;
            std::wcout << prefix << "vkrecord value type: " << ValueData::getValueType(vkRecord->getValueType()) << std::endl;
            std::wcout << prefix << "vkrecord data length: " << std::dec << vkRecord->getDataLength() << std::endl;
            std::wcout << prefix << "vkrecord raw data length: " << std::dec << vkRecord->getRawDataLength() << std::endl;
            std::wcout << prefix << "vkrecord data offset: " << std::dec << vkRecord->getDataOffset() << std::endl;

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
            std::wcout << prefix << "nkrecord has ascii name: " << getBooleanString(nkRecord->hasAsciiName()) << std::endl;
            std::wcout << prefix << "nkrecord has parent: " << getBooleanString(nkRecord->hasParentRecord()) << std::endl;
            if (nkRecord->hasParentRecord()) {
                try {
                    auto parent = nkRecord->getParentRecord();
                    std::wcout << prefix << "nkrecord parent name: " << parent->getName() << std::endl;
                }
                catch (std::exception& ex) {
                    std::wcout << prefix << "nkrecord parent name: exception (" << ex.what() << ")" << std::endl;
                }
            }
            else {
                std::wcout << prefix << "nkrecord parent name: (root)" << std::endl;
            }

            std::wcout << prefix << "nkrecord number of values: " << std::dec << nkRecord->getNumberOfValues() << std::endl;
            std::wcout << prefix << "nkrecord number of subkeys: " << std::dec << nkRecord->getSubkeyCount() << std::endl;
        }
        catch (std::exception& ex) {
            std::wcout << "printNKRecord exception: " << ex.what() << std::endl;
        }
    }

    // -----------------------------------------------------------------------
    // Cross-layer value checks (RegistryValue vs VKRecord)
    // Only prints on mismatch. Calls all RegistryValue APIs.
    // -----------------------------------------------------------------------

    void crossCheckValues(const VKRecord::VKRecordUniqPtrList& vkRecords,
                          const RegistryValue::RegistryValuePtrList& rvList,
                          const std::wstring& prefix) {
        if (vkRecords.size() != rvList.size()) {
            std::wcout << prefix << "MISMATCH value list size: nk=" << vkRecords.size()
                << " rk=" << rvList.size() << std::endl;
        }

        size_t count = std::min(vkRecords.size(), rvList.size());
        for (size_t i = 0; i < count; ++i) {
            try {
                const VKRecord* vk = vkRecords[i].get();
                const RegistryValue& rv = *rvList[i];

                // RegistryValue::getName() vs VKRecord::getName()
                std::wstring vkName = vk->getName();
                std::wstring rvName = rv.getName();
                if (vkName != rvName) {
                    std::wcout << prefix << "MISMATCH regval name: vk=\"" << vkName
                        << "\" rv=\"" << rvName << "\"" << std::endl;
                }

                // RegistryValue::getValueType() vs VKRecord::getValueType()
                ValueData::VALUE_TYPES vkType = vk->getValueType();
                ValueData::VALUE_TYPES rvType = rv.getValueType();
                if (vkType != rvType) {
                    std::wcout << prefix << "MISMATCH regval \"" << vkName << "\" type: vk="
                        << ValueData::getValueType(vkType) << " rv="
                        << ValueData::getValueType(rvType) << std::endl;
                }

                // RegistryValue::getValueLength() vs VKRecord::getDataLength()
                uint32_t vkLen = vk->getDataLength();
                uint32_t rvLen = rv.getValueLength();
                if (vkLen != rvLen) {
                    std::wcout << prefix << "MISMATCH regval \"" << vkName << "\" length: vk="
                        << std::dec << vkLen << " rv=" << rvLen << std::endl;
                }

                // RegistryValue::getValue() — exercise the method, compare data
                try {
                    auto rvData = rv.getValue();
                    auto vkData = vk->getValue();

                    // Compare via getAsRawData() for a type-agnostic byte comparison
                    auto rvRaw = rvData->getAsRawData();
                    auto vkRaw = vkData->getAsRawData();
                    if (rvRaw != vkRaw) {
                        std::wcout << prefix << "MISMATCH regval \"" << vkName
                            << "\" data: vk size=" << vkRaw.size()
                            << " rv size=" << rvRaw.size() << std::endl;
                    }
                }
                catch (std::exception& ex) {
                    std::wcout << prefix << "crossCheckValues getValue exception for \""
                        << vkName << "\": " << ex.what() << std::endl;
                }
            }
            catch (std::exception& ex) {
                std::wcout << prefix << "crossCheckValues exception at index " << i
                    << ": " << ex.what() << std::endl;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Single-pass recursive traversal: low-level + high-level + cross-checks
    // -----------------------------------------------------------------------
    void recurseAll(NKRecord* nkRecord, const RegistryKey& regKey, const std::wstring& prefix, uint32_t depth = 0) {

        // --- Stats: count this key, track depth ---
        g_stats.keyCount++;
        if (depth > g_stats.deepestLevel) {
            g_stats.deepestLevel = depth;
        }

        // --- Low-level NKRecord details ---
        printNKRecord(nkRecord, prefix);

        // --- Low-level VKRecord details + ValueListRecord checks ---
        VKRecord::VKRecordUniqPtrList vkRecords;
        try {
            auto valueListRecord = nkRecord->getValueList();
            size_t valueListSize = valueListRecord->getValuesSize();
            std::wcout << prefix << "nkrecord value list size: " << std::dec << valueListSize << std::endl;
            uint32_t reportedValues = nkRecord->getNumberOfValues();
            if (valueListSize != reportedValues) {
                std::wcout << prefix << "MISMATCH [" << nkRecord->getName()
                    << "] getNumberOfValues()=" << reportedValues
                    << " != getValuesSize()=" << valueListSize << std::endl;
            }

            vkRecords = valueListRecord->getValues();
            g_stats.valueTotal += static_cast<uint32_t>(vkRecords.size());
            if (vkRecords.size() > g_stats.maxValuesForKey) {
                g_stats.maxValuesForKey = static_cast<uint32_t>(vkRecords.size());
            }
            for (auto& vkRecord : vkRecords) {
                std::wcout << prefix << "  value: " << vkRecord->getName() << std::endl;
                printVKRecord(vkRecord.get(), L"    " + prefix);
                try {
                    g_stats.valueTypeCounts[ValueData::getValueType(vkRecord->getValueType())]++;
                }
                catch (...) {
                    g_stats.valueTypeCounts[L"(unknown)"]++;
                }
            }
        }
        catch (std::exception& ex) {
            std::wcout << prefix << "recurseAll getValues exception: " << ex.what() << std::endl;
        }

        // --- SubkeyListRecord metadata ---
        NKRecord::NKRecordUniqPtrList nkSubkeys;
        try {
            uint32_t subkeyCount = nkRecord->getSubkeyCount();
            auto subkeyListRecord = nkRecord->getSubkeyList();

            std::string magic = subkeyListRecord->getMagic();
            std::wcout << prefix << "nkrecord subkey list magic: " << magic.c_str() << std::endl;
            uint16_t listLength = subkeyListRecord->getListLength();
            std::wcout << prefix << "nkrecord subkey list length: " << std::dec << listLength << std::endl;

            g_stats.subkeyListMagicCounts[magic]++;
            if (subkeyCount > g_stats.maxSubkeysForKey) {
                g_stats.maxSubkeysForKey = subkeyCount;
            }

            if (listLength != subkeyCount) {
                // RI records: getListLength() returns the number of child
                // sub-lists (LH/LF/LI segments), not the total subkey count.
                if (magic != "ri") {
                    // LF/LH/LI records: getListLength() should equal
                    // getSubkeyCount(). A mismatch indicates corruption.
                    std::wcout << prefix << "MISMATCH [" << nkRecord->getName()
                        << "] getSubkeyCount()=" << subkeyCount
                        << " != getListLength()=" << listLength << std::endl;
                }
            }

            nkSubkeys = subkeyListRecord->getSubkeys();
        }
        catch (std::exception& ex) {
            std::wcout << prefix << "recurseAll getSubkeyList exception: " << ex.what() << std::endl;
        }

        // --- High-level cross-layer checks (only print on mismatch) ---
        RegistryKey::RegistryKeyPtrList rkSubkeys;
        try {
            // RegistryKey::getName() vs NKRecord::getName()
            std::wstring nkName = nkRecord->getName();
            std::wstring rkName = regKey.getName();
            if (nkName != rkName) {
                std::wcout << prefix << "MISMATCH regkey name: nk=\"" << nkName
                    << "\" rk=\"" << rkName << "\"" << std::endl;
            }

            // RegistryKey::getTimestamp() vs NKRecord::getTimestamp()
            uint64_t nkTs = nkRecord->getTimestamp();
            uint64_t rkTs = regKey.getTimestamp();
            if (nkTs != rkTs) {
                std::wcout << prefix << "MISMATCH regkey timestamp: nk=" << nkTs
                    << " rk=" << rkTs << std::endl;
            }

            // RegistryKey::getSubkeyListSize() vs NKRecord::getSubkeyCount()
            size_t rkSubkeySize = regKey.getSubkeyListSize();
            uint32_t nkSubkeyCount = nkRecord->getSubkeyCount();
            if (rkSubkeySize != nkSubkeyCount) {
                std::wcout << prefix << "MISMATCH regkey subkey count: nk=" << nkSubkeyCount
                    << " rk=" << rkSubkeySize << std::endl;
            }

            // RegistryKey::getSubkeyList().size() vs NKRecord subkeys size
            rkSubkeys = regKey.getSubkeyList();
            if (rkSubkeys.size() != nkSubkeys.size()) {
                std::wcout << prefix << "MISMATCH regkey subkey list count: nk=" << nkSubkeys.size()
                    << " rk=" << rkSubkeys.size() << std::endl;
            }

            // RegistryKey::getSubkeyListSize() vs getSubkeyList().size()
            if (rkSubkeySize != rkSubkeys.size()) {
                std::wcout << prefix << "MISMATCH regkey subkey list size vs count: size="
                    << rkSubkeySize << " count=" << rkSubkeys.size() << std::endl;
            }

            // RegistryKey::getValueListSize() vs NKRecord::getNumberOfValues()
            size_t rkValueSize = regKey.getValueListSize();
            uint32_t nkValueCount = nkRecord->getNumberOfValues();
            if (rkValueSize != nkValueCount) {
                std::wcout << prefix << "MISMATCH regkey value count: nk=" << nkValueCount
                    << " rk=" << rkValueSize << std::endl;
            }

            // RegistryKey::getValueList() vs VKRecord list
            auto rkValues = regKey.getValueList();
            if (rkValues.size() != vkRecords.size()) {
                std::wcout << prefix << "MISMATCH regkey value list count: nk=" << vkRecords.size()
                    << " rk=" << rkValues.size() << std::endl;
            }

            // RegistryKey::getValueListSize() vs getValueList().size()
            if (rkValueSize != rkValues.size()) {
                std::wcout << prefix << "MISMATCH regkey value list size vs count: size="
                    << rkValueSize << " count=" << rkValues.size() << std::endl;
            }

            // Cross-check individual values (RegistryValue vs VKRecord)
            crossCheckValues(vkRecords, rkValues, prefix);

            // RegistryKey::getParent() — unique to high-level API
            if (nkRecord->hasParentRecord()) {
                try {
                    auto rkParent = regKey.getParent();
                    auto nkParent = nkRecord->getParentRecord();
                    if (rkParent->getName() != nkParent->getName()) {
                        std::wcout << prefix << "MISMATCH regkey parent name: nk=\""
                            << nkParent->getName() << "\" rk=\""
                            << rkParent->getName() << "\"" << std::endl;
                    }
                }
                catch (std::exception& ex) {
                    std::wcout << prefix << "regkey getParent exception: " << ex.what() << std::endl;
                }
            }
        }
        catch (std::exception& ex) {
            std::wcout << prefix << "recurseAll cross-check exception: " << ex.what() << std::endl;
        }

        // --- Named lookups (unique to high-level API, always printed) ---
        // Cap at MAX_NAMED_LOOKUPS to avoid O(n^2) on large subkey lists
        // (e.g. RI records with 600+ subkeys where each getSubkey() call
        // materializes the entire subkey list).
        static const size_t MAX_NAMED_LOOKUPS = 10;

        {
            size_t lookupCount = std::min(nkSubkeys.size(), MAX_NAMED_LOOKUPS);
            for (size_t idx = 0; idx < lookupCount; ++idx) {
                std::wstring name = nkSubkeys[idx]->getName();
                try {
                    auto looked = regKey.getSubkey(name);
                }
                catch (std::exception& ex) {
                    std::wcout << prefix << "  subkey lookup \"" << name << "\": FAILED. exception ("
                        << ex.what() << ")" << std::endl;
                }
            }
            if (nkSubkeys.size() > MAX_NAMED_LOOKUPS) {
                std::wcout << prefix << "  subkey lookup: " << (nkSubkeys.size() - MAX_NAMED_LOOKUPS)
                    << " more skipped (threshold=" << MAX_NAMED_LOOKUPS << ")" << std::endl;
            }
        }

        {
            size_t lookupCount = std::min(vkRecords.size(), MAX_NAMED_LOOKUPS);
            for (size_t idx = 0; idx < lookupCount; ++idx) {
                std::wstring name = vkRecords[idx]->getName();
                try {
                    auto looked = regKey.getValue(name);
                }
                catch (std::exception& ex) {
                    std::wcout << prefix << "  value lookup \"" << name << "\": FAILED. exception ("
                        << ex.what() << ")" << std::endl;
                }
            }
            if (vkRecords.size() > MAX_NAMED_LOOKUPS) {
                std::wcout << prefix << "  value lookup: " << (vkRecords.size() - MAX_NAMED_LOOKUPS)
                    << " more skipped (threshold=" << MAX_NAMED_LOOKUPS << ")" << std::endl;
            }
        }

        // --- Recurse into subkeys (paired low-level + high-level) ---
        size_t count = std::min(nkSubkeys.size(), rkSubkeys.size());
        for (size_t i = 0; i < count; ++i) {
            std::wcout << prefix << "  key: " << nkSubkeys[i]->getName() << std::endl;
            recurseAll(nkSubkeys[i].get(), *rkSubkeys[i], L"    " + prefix, depth + 1);
        }

        // If sizes differ, still print remaining NKRecord subkeys
        for (size_t i = count; i < nkSubkeys.size(); ++i) {
            std::wcout << prefix << "  key (nk only): " << nkSubkeys[i]->getName() << std::endl;
        }
        for (size_t i = count; i < rkSubkeys.size(); ++i) {
            std::wcout << prefix << "  key (rk only): " << rkSubkeys[i]->getName() << std::endl;
        }
    }

    // -----------------------------------------------------------------------
    // Top-level hive processing
    // -----------------------------------------------------------------------

    void processRegistryHive(RegistryHive& hive) {
        // Reset stats for this hive
        g_stats = HiveStats{};

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
            g_stats.hbinCount = static_cast<uint32_t>(hbinList.size());
            std::wcout << "number of hbins: " << hbinList.size() << std::endl;
            std::wcout << "last hbin offset: " << header->getLastHbinOffset() << std::endl;

            // REGFHeader::getFirstHBIN()
            try {
                auto firstHbin = header->getFirstHBIN();
                std::wcout << "first hbin relative offset first hbin: " << firstHbin->getRelativeOffsetFirstHBIN() << std::endl;
                std::wcout << "first hbin relative offset next hbin: " << firstHbin->getRelativeOffsetNextHBIN() << std::endl;
            }
            catch (std::exception& ex) {
                std::wcout << "getFirstHBIN exception: " << ex.what() << std::endl;
            }

            int i = 0;
            for (auto& hbin : hbinList) {
                std::wcout << "hbin " << i
                    << ", offset first: " << hbin->getRelativeOffsetFirstHBIN()
                    << ", offset next: " << hbin->getRelativeOffsetNextHBIN()
                    << std::endl;

                int j = 0;
                for (auto& cell : hbin->getCells()) {
                    bool active = cell->isActive();

                    g_stats.cellTotal++;
                    if (active) {
                        g_stats.cellAllocated++;
                    }
                    else {
                        g_stats.cellUnallocated++;
                    }

                    try {
                        std::string sig = cell->getDataSignature();
                        std::wcout << "  cell " << j
                            << ", allocated: " << (active ? "yes" : "no")
                            << ", length: " << cell->getLength()
                            << ", signature: " << sig.c_str()
                            << ", data size: " << cell->getData().size()
                            << std::endl;
                        if (active) {
                            if (sig == "nk" || sig == "vk" || sig == "lf" ||
                                sig == "lh" || sig == "ri" || sig == "li" ||
                                sig == "sk" || sig == "db") {
                                g_stats.cellTypeCounts[sig]++;
                            }
                            else {
                                g_stats.cellTypeCounts["(data)"]++;
                            }
                        }
                    }
                    catch (std::exception& ex) {
                        std::wcout << "  cell " << j
                            << ", allocated: " << (active ? "yes" : "no")
                            << ", length: " << cell->getLength()
                            << ", data: exception (" << ex.what() << ")"
                            << std::endl;
                    }
                    j++;
                }


                i++;
            }

            // Single-pass tree traversal with both API layers
            auto nkRoot = header->getRootNKRecord();
            auto rkRoot = hive.getRoot();
            recurseAll(nkRoot.get(), *rkRoot, L"");
        }
        catch (std::exception& ex) {
            std::wcout << "processRegistryHive exception: " << ex.what() << std::endl;
        }

        // Print summary statistics
        g_stats.print();

        std::wcout.flags(savedFlags);
        std::wcout.width(savedWidth);
        std::wcout.fill(savedFill);
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

// -----------------------------------------------------------------------
// SEH wrapper — must be in its own function because __try/__except cannot
// coexist with C++ objects that have destructors in the same function.
// -----------------------------------------------------------------------

static const wchar_t* sehCodeToString(DWORD code) {
    switch (code) {
    case EXCEPTION_STACK_OVERFLOW:         return L"EXCEPTION_STACK_OVERFLOW";
    case EXCEPTION_ACCESS_VIOLATION:       return L"EXCEPTION_ACCESS_VIOLATION";
    case EXCEPTION_IN_PAGE_ERROR:          return L"EXCEPTION_IN_PAGE_ERROR";
    case EXCEPTION_ILLEGAL_INSTRUCTION:    return L"EXCEPTION_ILLEGAL_INSTRUCTION";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION: return L"EXCEPTION_NONCONTINUABLE_EXCEPTION";
    case EXCEPTION_INVALID_DISPOSITION:    return L"EXCEPTION_INVALID_DISPOSITION";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:  return L"EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
    case EXCEPTION_FLT_DENORMAL_OPERAND:   return L"EXCEPTION_FLT_DENORMAL_OPERAND";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:     return L"EXCEPTION_FLT_DIVIDE_BY_ZERO";
    case EXCEPTION_FLT_OVERFLOW:           return L"EXCEPTION_FLT_OVERFLOW";
    case EXCEPTION_FLT_UNDERFLOW:          return L"EXCEPTION_FLT_UNDERFLOW";
    case EXCEPTION_INT_DIVIDE_BY_ZERO:     return L"EXCEPTION_INT_DIVIDE_BY_ZERO";
    case EXCEPTION_INT_OVERFLOW:           return L"EXCEPTION_INT_OVERFLOW";
    case EXCEPTION_PRIV_INSTRUCTION:       return L"EXCEPTION_PRIV_INSTRUCTION";
    default:                               return L"UNKNOWN_SEH_EXCEPTION";
    }
}

static int sehRunProcessRegistryFile(wchar_t* regFilePath) {
    __try {
        Rejistry::processRegistryFile(regFilePath);
        return 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        // If stack overflow, restore the guard page so we can keep running
        // (printing the error message itself needs stack space).
        if (code == EXCEPTION_STACK_OVERFLOW) {
            _resetstkoflw();
        }
        std::wcout << std::endl
            << L"FATAL: Structured Exception (SEH) 0x" << std::hex << code
            << L" (" << sehCodeToString(code) << L")" << std::endl;
        std::wcerr << std::endl
            << L"FATAL: Structured Exception (SEH) 0x" << std::hex << code
            << L" (" << sehCodeToString(code) << L")" << std::endl;
        return 1;
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

    auto start = std::chrono::high_resolution_clock::now();

    int result = sehRunProcessRegistryFile(argv[1]);

    auto end = std::chrono::high_resolution_clock::now();
    auto totalSeconds = std::chrono::duration_cast<std::chrono::seconds>(end - start).count();
    auto h = totalSeconds / 3600;
    auto m = (totalSeconds % 3600) / 60;
    auto s = totalSeconds % 60;
    std::wcout << std::endl << L"=== Completed in " << std::dec
        << h << L" h : " << m << L" m : " << s << L" s ===" << std::endl;

    return result;
}
