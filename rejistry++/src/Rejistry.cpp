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
#include <set>
#include <string>
#include <vector>
#include <exception>
#define NOMINMAX
#include <Windows.h>
#include <io.h>
#include <fcntl.h>
#include <malloc.h>  // _resetstkoflw
#include <share.h>   // _SH_DENYNO
#include <csignal>

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

    /**
     * Returns s, with "  [invalid UTF-16]" appended if it contains an unpaired
     * surrogate (a high surrogate not followed by a low one, or a lone low one).
     *
     * Such strings can't be converted to UTF-8, so callers like the CyberTriage
     * collector lose them; Rejistry++ replaces unpaired surrogates with U+FFFD
     * (CT-4851). The output can't show this by itself: writing it as UTF-8 also
     * turns an unpaired surrogate into U+FFFD, so check before printing. The
     * marker should never appear; if it does, some code path is returning
     * unsanitized UTF-16.
     */
    std::wstring markInvalidUTF16(const std::wstring& s) {
        for (size_t i = 0; i < s.size(); i++) {
            wchar_t c = s[i];
            if (c >= 0xD800 && c <= 0xDBFF) {
                if (i + 1 < s.size() && s[i + 1] >= 0xDC00 && s[i + 1] <= 0xDFFF) {
                    i++;            // valid pair
                    continue;
                }
                return s + L"  [invalid UTF-16]";
            }
            if (c >= 0xDC00 && c <= 0xDFFF) {
                return s + L"  [invalid UTF-16]";
            }
        }
        return s;
    }

    /**
     * Absolute buffer offset of a record. BinaryBlock::_offset is protected and
     * the library has no accessor; a pointer to member formed through a derived
     * class reads it without changing the library. The driver uses it to tell
     * whether a named lookup returned the record that enumeration listed, and
     * to tell when the tree walk reaches a key or subkey list it has already
     * seen (see WalkState). Offsets are never printed, so the output does not
     * depend on where the generator happened to place cells.
     */
    struct RecordOffset : NKRecord {
        static uint32_t of(const BinaryBlock& r) { return r.*(&RecordOffset::_offset); }
    };

    std::wstring widen(const char* s) {
        std::wstring wide;
        for (; *s != '\0'; ++s) {
            wide.push_back(static_cast<unsigned char>(*s));
        }
        return wide;
    }

    /**
     * getName() as displayed (markInvalidUTF16), or a marker if it throws, so
     * one unreadable name does not end the rest of the dump.
     */
    template <class R> std::wstring displayName(const R& r) {
        try {
            return markInvalidUTF16(r.getName());
        }
        catch (std::exception& ex) {
            return L"<unreadable name: " + widen(ex.what()) + L">";
        }
    }

    /** getName() unmarked, for the lines that print it raw, or the same marker. */
    template <class R> std::wstring rawName(const R& r) {
        try {
            return r.getName();
        }
        catch (std::exception& ex) {
            return L"<unreadable name: " + widen(ex.what()) + L">";
        }
    }

    /**
     * The form in which SubkeyListRecord::getSubkey() and
     * ValueListRecord::getValue() compare names: they use _wcsicmp on
     * c_str(), so only the part before the first NUL counts, and in the C
     * locale _wcsicmp folds ASCII letters only. Two siblings with the same
     * key can make a lookup return the wrong one.
     */
    std::wstring lookupKey(const std::wstring& name) {
        std::wstring key(name.c_str());
        for (auto& c : key) {
            if (c >= L'a' && c <= L'z') {
                c = c - L'a' + L'A';
            }
        }
        return key;
    }

    // Keys are not followed below this depth. Windows allows 512 levels;
    // this only stops crafted chains from exhausting the stack.
    static const uint32_t MAX_TREE_DEPTH = 1024;

    /**
     * What recurseAll needs to know about the walk so far. In a sound hive
     * every key is listed once, by the key its parent field names, in a
     * subkey list of its own. A damaged or crafted hive can list a key twice,
     * list it under two keys, or give two keys the same list. Following every
     * listing then walks the same keys again and again (exponentially, or
     * until memory runs out), so the walk follows each key and each list
     * once and says why it skips the rest.
     */
    struct WalkState {
        std::vector<uint32_t> ancestors;             // offsets of the keys on the current path
        std::set<uint32_t> walked;                   // offsets of the keys walked so far
        std::map<uint32_t, std::pair<uint32_t, std::wstring>> listOwners;  // subkey list offset -> first key (offset, name) that listed it
    };

    /**
     * Restores std::wcout's format flags on scope exit. The driver's other
     * lines rely on whatever base (hex/dec) earlier lines left set, so the
     * lines that print only on anomalies put it back as they found it.
     */
    struct StreamStateGuard {
        std::ios_base::fmtflags flags = std::wcout.flags();
        ~StreamStateGuard() { std::wcout.flags(flags); }
    };

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
            std::wcout << prefix << "vkrecord name: " << displayName(*vkRecord) << std::endl;
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
                std::wcout << markInvalidUTF16(data->getAsString()) << std::endl;
                break;
            case ValueData::VALTYPE_MULTI_SZ:
            {
                std::vector<std::wstring> stringList = data->getAsStringList();

                if (stringList.empty()) {
                    std::wcout << std::endl;
                }
                for (uint32_t i = 0; i < stringList.size(); ++i) {
                    if (i != 0) {
                        std::wcout << prefix << "               ";
                    }
                    std::wcout << markInvalidUTF16(stringList[i]) << std::endl;
                }
            }
            break;
            case ValueData::VALTYPE_DWORD:
            case ValueData::VALTYPE_QWORD:
            case ValueData::VALTYPE_BIG_ENDIAN:
            case ValueData::VALTYPE_FILETIME:
                std::wcout << std::hex << "0x" << data->getAsNumber() << std::endl;
                break;
            case ValueData::VALTYPE_LINK:
                // The collector reads REG_LINK with getAsString(), so print
                // what it returns. If it throws, say so on this line and
                // still dump the raw bytes below, as for the binary types.
                try {
                    std::wcout << markInvalidUTF16(data->getAsString()) << std::endl;
                    break;
                }
                catch (std::exception& ex) {
                    std::wcout << "getAsString exception: " << ex.what();
                }
                // fall through to the raw dump
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
            {
                // A class name that can't be read must not hide the key's
                // other lines.
                std::wstring className;
                try {
                    className = markInvalidUTF16(nkRecord->getClassName());
                }
                catch (std::exception& ex) {
                    className = L"<unreadable class name: " + widen(ex.what()) + L">";
                }
                std::wcout << prefix << "nkrecord classname: " << className << std::endl;
            }
            std::wcout << prefix << "nkrecord timestamp: "; printDatetimeString(nkRecord->getTimestamp()); std::wcout << std::endl;
            std::wcout << prefix << "nkrecord is root: " << getBooleanString(nkRecord->isRootKey()) << std::endl;
            std::wcout << prefix << "nkrecord name: " << displayName(*nkRecord) << std::endl;
            std::wcout << prefix << "nkrecord has ascii name: " << getBooleanString(nkRecord->hasAsciiName()) << std::endl;
            std::wcout << prefix << "nkrecord has parent: " << getBooleanString(nkRecord->hasParentRecord()) << std::endl;
            if (nkRecord->hasParentRecord()) {
                try {
                    auto parent = nkRecord->getParentRecord();
                    std::wcout << prefix << "nkrecord parent name: " << markInvalidUTF16(parent->getName()) << std::endl;
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
                std::wstring vkName = rawName(*vk);
                std::wstring rvName = rawName(rv);
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
    // walk.ancestors holds the offsets of nkRecord and the keys above it, so a
    // subkey list that leads back into one of them is reported instead of
    // followed; see WalkState for the rest.
    void recurseAll(NKRecord* nkRecord, const RegistryKey& regKey, const std::wstring& prefix,
                    WalkState& walk, uint32_t depth = 0) {

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
                std::wcout << prefix << "MISMATCH [" << rawName(*nkRecord)
                    << "] getNumberOfValues()=" << reportedValues
                    << " != getValuesSize()=" << valueListSize << std::endl;
            }

            vkRecords = valueListRecord->getValues();
            g_stats.valueTotal += static_cast<uint32_t>(vkRecords.size());
            if (vkRecords.size() > g_stats.maxValuesForKey) {
                g_stats.maxValuesForKey = static_cast<uint32_t>(vkRecords.size());
            }
            for (auto& vkRecord : vkRecords) {
                std::wcout << prefix << "  value: " << displayName(*vkRecord) << std::endl;
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
        uint32_t listOffset = 0;    // 0 for a key without subkeys (EmptySubkeyList)
        try {
            uint32_t subkeyCount = nkRecord->getSubkeyCount();
            auto subkeyListRecord = nkRecord->getSubkeyList();
            listOffset = RecordOffset::of(*subkeyListRecord);

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
                    std::wcout << prefix << "MISMATCH [" << rawName(*nkRecord)
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
            std::wstring nkName = rawName(*nkRecord);
            std::wstring rkName = rawName(regKey);
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
        // Each probe looks a name up through RegistryKey (the collector's
        // path), then checks that the list lookup returned the record that
        // enumeration listed under that name. Only failures and wrong records
        // are printed. Cap at MAX_NAMED_LOOKUPS to avoid O(n^2) on large
        // subkey lists (a lookup reads the list up to the name it finds, so
        // probing every name of an n-entry list reads ~n^2/2 entries). Past the
        // cap, only names that compare equal (see lookupKey) to an earlier
        // sibling that is a different record are probed, since only those
        // can resolve to the wrong record (a list that names the same record
        // again cannot), up to MAX_COLLIDING_LOOKUPS of them, plus names that
        // can't be read.
        static const size_t MAX_NAMED_LOOKUPS = 10;
        static const size_t MAX_COLLIDING_LOOKUPS = 50;

        {
            std::vector<uint32_t> offsets;
            std::vector<std::wstring> names(nkSubkeys.size());
            std::vector<std::string> nameErrors(nkSubkeys.size());
            std::vector<bool> nameOk(nkSubkeys.size(), false);
            for (size_t i = 0; i < nkSubkeys.size(); ++i) {
                offsets.push_back(RecordOffset::of(*nkSubkeys[i]));
                try {
                    names[i] = nkSubkeys[i]->getName();
                    nameOk[i] = true;
                }
                catch (std::exception& ex) {
                    nameErrors[i] = ex.what();
                }
            }

            auto probe = [&](size_t idx) {
                StreamStateGuard guard;
                if (!nameOk[idx]) {
                    std::wcout << prefix << "  subkey lookup #" << std::dec << idx
                        << ": skipped, name unreadable (" << nameErrors[idx].c_str() << ")" << std::endl;
                    return;
                }
                const std::wstring& name = names[idx];
                try {
                    auto looked = regKey.getSubkey(name);
                    auto found = nkRecord->getSubkeyList()->getSubkey(name);
                    uint32_t foundOffset = RecordOffset::of(*found);
                    if (foundOffset != offsets[idx]) {
                        std::wcout << prefix << "  subkey lookup \"" << name
                            << "\": MISMATCH returned a different key (enumerated #" << std::dec << idx
                            << ", lookup returned ";
                        auto at = std::find(offsets.begin(), offsets.end(), foundOffset);
                        if (at != offsets.end()) {
                            std::wcout << "#" << (at - offsets.begin()) << " ";
                        }
                        else {
                            std::wcout << "a key that is not enumerated ";
                        }
                        std::wcout << "\"" << rawName(*found) << "\")" << std::endl;
                    }
                }
                catch (std::exception& ex) {
                    std::wcout << prefix << "  subkey lookup \"" << name << "\": FAILED. exception ("
                        << ex.what() << ")" << std::endl;
                }
            };

            size_t lookupCount = std::min(nkSubkeys.size(), MAX_NAMED_LOOKUPS);
            for (size_t idx = 0; idx < lookupCount; ++idx) {
                probe(idx);
            }
            if (nkSubkeys.size() > MAX_NAMED_LOOKUPS) {
                std::wcout << prefix << "  subkey lookup: " << (nkSubkeys.size() - MAX_NAMED_LOOKUPS)
                    << " more skipped (threshold=" << MAX_NAMED_LOOKUPS << ")" << std::endl;

                std::map<std::wstring, size_t> firstWithKey;
                size_t collidingProbed = 0;
                size_t collidingSkipped = 0;
                for (size_t idx = 0; idx < nkSubkeys.size(); ++idx) {
                    if (!nameOk[idx]) {
                        if (idx >= MAX_NAMED_LOOKUPS) {
                            probe(idx);
                        }
                        continue;
                    }
                    auto first = firstWithKey.emplace(lookupKey(names[idx]), idx);
                    bool collides = !first.second && offsets[first.first->second] != offsets[idx];
                    if (collides && idx >= MAX_NAMED_LOOKUPS) {
                        if (collidingProbed < MAX_COLLIDING_LOOKUPS) {
                            probe(idx);
                            collidingProbed++;
                        }
                        else {
                            collidingSkipped++;
                        }
                    }
                }
                if (collidingSkipped > 0) {
                    StreamStateGuard guard;
                    std::wcout << prefix << "  subkey lookup: " << std::dec << collidingSkipped
                        << " more names equal to an earlier sibling's not probed (threshold="
                        << MAX_COLLIDING_LOOKUPS << ")" << std::endl;
                }
            }
        }

        {
            std::vector<uint32_t> offsets;
            std::vector<std::wstring> names(vkRecords.size());
            std::vector<std::string> nameErrors(vkRecords.size());
            std::vector<bool> nameOk(vkRecords.size(), false);
            for (size_t i = 0; i < vkRecords.size(); ++i) {
                offsets.push_back(RecordOffset::of(*vkRecords[i]));
                try {
                    names[i] = vkRecords[i]->getName();
                    nameOk[i] = true;
                }
                catch (std::exception& ex) {
                    nameErrors[i] = ex.what();
                }
            }

            auto probe = [&](size_t idx) {
                StreamStateGuard guard;
                if (!nameOk[idx]) {
                    std::wcout << prefix << "  value lookup #" << std::dec << idx
                        << ": skipped, name unreadable (" << nameErrors[idx].c_str() << ")" << std::endl;
                    return;
                }
                const std::wstring& name = names[idx];
                try {
                    auto looked = regKey.getValue(name);
                    auto found = nkRecord->getValueList()->getValue(name);
                    uint32_t foundOffset = RecordOffset::of(*found);
                    if (foundOffset != offsets[idx]) {
                        std::wcout << prefix << "  value lookup \"" << name
                            << "\": MISMATCH returned a different value (enumerated #" << std::dec << idx
                            << ", lookup returned ";
                        auto at = std::find(offsets.begin(), offsets.end(), foundOffset);
                        if (at != offsets.end()) {
                            std::wcout << "#" << (at - offsets.begin()) << " ";
                        }
                        else {
                            std::wcout << "a value that is not enumerated ";
                        }
                        std::wcout << "\"" << rawName(*found) << "\")" << std::endl;
                    }
                }
                catch (std::exception& ex) {
                    std::wcout << prefix << "  value lookup \"" << name << "\": FAILED. exception ("
                        << ex.what() << ")" << std::endl;
                }
            };

            size_t lookupCount = std::min(vkRecords.size(), MAX_NAMED_LOOKUPS);
            for (size_t idx = 0; idx < lookupCount; ++idx) {
                probe(idx);
            }
            if (vkRecords.size() > MAX_NAMED_LOOKUPS) {
                std::wcout << prefix << "  value lookup: " << (vkRecords.size() - MAX_NAMED_LOOKUPS)
                    << " more skipped (threshold=" << MAX_NAMED_LOOKUPS << ")" << std::endl;

                std::map<std::wstring, size_t> firstWithKey;
                size_t collidingProbed = 0;
                size_t collidingSkipped = 0;
                for (size_t idx = 0; idx < vkRecords.size(); ++idx) {
                    if (!nameOk[idx]) {
                        if (idx >= MAX_NAMED_LOOKUPS) {
                            probe(idx);
                        }
                        continue;
                    }
                    // An unnamed value's getName() is "(Default)", which is
                    // also how getValue() matches it, so it shares that key.
                    auto first = firstWithKey.emplace(lookupKey(names[idx]), idx);
                    bool collides = !first.second && offsets[first.first->second] != offsets[idx];
                    if (collides && idx >= MAX_NAMED_LOOKUPS) {
                        if (collidingProbed < MAX_COLLIDING_LOOKUPS) {
                            probe(idx);
                            collidingProbed++;
                        }
                        else {
                            collidingSkipped++;
                        }
                    }
                }
                if (collidingSkipped > 0) {
                    StreamStateGuard guard;
                    std::wcout << prefix << "  value lookup: " << std::dec << collidingSkipped
                        << " more names equal to an earlier sibling's not probed (threshold="
                        << MAX_COLLIDING_LOOKUPS << ")" << std::endl;
                }
            }
        }

        // --- Recurse into subkeys (paired low-level + high-level) ---
        uint32_t ownOffset = RecordOffset::of(*nkRecord);

        // A subkey list belongs to one key. If another key's walk already
        // listed this one, its keys were reported there.
        if (listOffset != 0) {
            auto owner = walk.listOwners.emplace(listOffset, std::make_pair(ownOffset, displayName(*nkRecord)));
            if (!owner.second && owner.first->second.first != ownOffset) {
                std::wcout << prefix << "  shared subkey list: same list as key \"" << owner.first->second.second
                    << "\", not listed again" << std::endl;
                return;
            }
        }

        // Every listing that is not followed says why: a cycle back into the
        // path, the depth limit, the key named earlier in this same list, or
        // the key already walked from another listing. A key whose parent
        // field names some other key is reported, since that is how one key
        // comes to be listed under two; it is still walked the first time.
        std::map<uint32_t, size_t> firstListing;    // child offset -> index of its first listing here
        size_t count = std::min(nkSubkeys.size(), rkSubkeys.size());
        for (size_t i = 0; i < count; ++i) {
            std::wcout << prefix << "  key: " << displayName(*nkSubkeys[i]) << std::endl;
            uint32_t childOffset = RecordOffset::of(*nkSubkeys[i]);
            auto listing = firstListing.emplace(childOffset, i);
            if (std::find(walk.ancestors.begin(), walk.ancestors.end(), childOffset) != walk.ancestors.end()) {
                std::wcout << prefix << "    cycle: subkey list points back to an ancestor key, not followed" << std::endl;
                continue;
            }
            if (depth + 1 > MAX_TREE_DEPTH) {
                StreamStateGuard guard;
                std::wcout << prefix << "    depth limit reached (" << std::dec << MAX_TREE_DEPTH
                    << " levels), not followed" << std::endl;
                continue;
            }
            if (!listing.second) {
                StreamStateGuard guard;
                std::wcout << prefix << "    duplicate: this subkey list already named this key at entry #"
                    << std::dec << listing.first->second << ", not followed" << std::endl;
                continue;
            }
            try {
                auto parent = nkSubkeys[i]->getParentRecord();
                if (RecordOffset::of(*parent) != ownOffset) {
                    std::wcout << prefix << "    parent mismatch: this key's parent field names \""
                        << displayName(*parent) << "\", not the listing key" << std::endl;
                }
            }
            catch (std::exception& ex) {
                std::wcout << prefix << "    parent mismatch: this key's parent field does not name a key ("
                    << ex.what() << ")" << std::endl;
            }
            if (!walk.walked.insert(childOffset).second) {
                std::wcout << prefix << "    already walked: reached earlier through another key, not followed" << std::endl;
                continue;
            }
            walk.ancestors.push_back(childOffset);
            recurseAll(nkSubkeys[i].get(), *rkSubkeys[i], L"    " + prefix, walk, depth + 1);
            walk.ancestors.pop_back();
        }

        // If sizes differ, still print remaining NKRecord subkeys
        for (size_t i = count; i < nkSubkeys.size(); ++i) {
            std::wcout << prefix << "  key (nk only): " << displayName(*nkSubkeys[i]) << std::endl;
        }
        for (size_t i = count; i < rkSubkeys.size(); ++i) {
            std::wcout << prefix << "  key (rk only): " << displayName(*rkSubkeys[i]) << std::endl;
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

        std::unique_ptr<REGFHeader> header;
        try {
            header = hive.getHeader();
            std::wcout << "hive name: " << markInvalidUTF16(header->getHiveName()) << std::endl;
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

                // A cell size the walk can't step over ends this hbin's
                // listing only; the other hbins and the key tree still print.
                Cell::CellUniqPtrList cells;
                try {
                    cells = hbin->getCells();
                }
                catch (std::exception& ex) {
                    std::wcout << "  getCells exception: " << ex.what() << std::endl;
                }

                int j = 0;
                for (auto& cell : cells) {
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
        }
        catch (std::exception& ex) {
            std::wcout << "processRegistryHive exception: " << ex.what() << std::endl;
        }

        // Single-pass tree traversal with both API layers. It has its own try
        // so that a failure in the hbin/cell survey above does not also hide
        // the key tree. A hive whose header can't be read has no tree.
        if (header) {
            try {
                auto nkRoot = header->getRootNKRecord();
                auto rkRoot = hive.getRoot();
                WalkState walk;
                walk.ancestors.push_back(RecordOffset::of(*nkRoot));
                walk.walked.insert(RecordOffset::of(*nkRoot));
                recurseAll(nkRoot.get(), *rkRoot, L"", walk);
            }
            catch (std::exception& ex) {
                std::wcout << "processRegistryHive exception: " << ex.what() << std::endl;
            }
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

// -----------------------------------------------------------------------
// Output file writer. Writes the bytes stdout in _O_U8TEXT text mode wrote
// (LF -> CRLF, UTF-16 -> UTF-8, no BOM) without the CRT's per-character
// locking and its flush at every std::endl, which were most of the driver's
// run time. U+FFFF is dropped: it is WEOF, which the stdout filebuf took as
// a flush request rather than a character, so it never reached the file.
// One difference: the CRT converted in 852-unit slices and wrote a surrogate
// pair that straddled a slice as two U+FFFD; this writes the pair intact.
//
// Output is written in 64K-character chunks, and flushed at exit and from
// the crash handlers. A process that ends without reaching them (a fast-fail
// such as a /GS or heap-corruption stop, or being killed) loses the last
// chunk. --flush-each-line writes every line as it is printed, as the CRT
// did, so the file ends exactly where the run stopped, at about twice the
// buffered run time.
// -----------------------------------------------------------------------
class Utf8CrlfFileBuf : public std::wstreambuf {
public:
    Utf8CrlfFileBuf(FILE* file, bool flushEachLine) : _file(file), _flushEachLine(flushEachLine) {
        // Sized so that flushing from a crash handler normally needs no
        // allocation (the heap may be damaged by then).
        _pending.reserve(CHUNK_CHARS * 2);
        _wide.reserve(CHUNK_CHARS * 4);
        _utf8.reserve(CHUNK_CHARS * 6);
    }

    // Write out everything buffered so far.
    void flushAll() {
        convert(_pending.size());
        if (fflush(_file) != 0) {
            _writeFailed = true;
        }
    }

    bool writeFailed() const { return _writeFailed; }

protected:
    int_type overflow(int_type c) override {
        if (c != traits_type::eof()) {
            _pending.push_back(static_cast<wchar_t>(c));
            maybeConvert();
        }
        return traits_type::not_eof(c);
    }

    std::streamsize xsputn(const wchar_t* s, std::streamsize n) override {
        // Taken a chunk at a time, so printing a very large value does not
        // need several more copies of it.
        const wchar_t* end = s + n;
        while (s < end) {
            const wchar_t* sliceEnd = s + std::min(end - s, static_cast<std::ptrdiff_t>(CHUNK_CHARS));
            while (s < sliceEnd) {
                const wchar_t* weof = std::find(s, sliceEnd, static_cast<wchar_t>(0xFFFF));
                _pending.append(s, weof);
                s = (weof == sliceEnd) ? sliceEnd : weof + 1;
            }
            maybeConvert();
        }
        return n;
    }

    // std::endl calls this.
    int sync() override {
        if (_flushEachLine) {
            flushAll();
        }
        return 0;
    }

private:
    static const size_t CHUNK_CHARS = 1 << 16;

    void maybeConvert() {
        if (_pending.size() >= CHUNK_CHARS) {
            size_t n = _pending.size();
            if (_pending[n - 1] >= 0xD800 && _pending[n - 1] <= 0xDBFF) {
                n--;    // keep a surrogate pair together
            }
            convert(n);
        }
    }

    void convert(size_t n) {
        if (n == 0) {
            return;
        }
        _wide.clear();
        for (size_t i = 0; i < n; i++) {
            wchar_t c = _pending[i];
            if (c == L'\n') {
                _wide.push_back(L'\r');
            }
            _wide.push_back(c);
        }
        int len = WideCharToMultiByte(CP_UTF8, 0, _wide.data(), static_cast<int>(_wide.size()), NULL, 0, NULL, NULL);
        if (len <= 0) {
            _writeFailed = true;
            _pending.erase(0, n);
            return;
        }
        _utf8.resize(static_cast<size_t>(len));
        WideCharToMultiByte(CP_UTF8, 0, _wide.data(), static_cast<int>(_wide.size()), &_utf8[0], len, NULL, NULL);
        if (fwrite(_utf8.data(), 1, _utf8.size(), _file) != _utf8.size()) {
            _writeFailed = true;
        }
        _pending.erase(0, n);
    }

    FILE* _file;
    bool _flushEachLine;
    bool _writeFailed = false;
    std::wstring _pending;
    std::wstring _wide;
    std::string _utf8;
};

static Utf8CrlfFileBuf* g_outputBuf = nullptr;

static void flushOutput() {
    if (g_outputBuf != nullptr) {
        g_outputBuf->flushAll();
    }
}

// Flush from a crash handler. A fault while flushing loses the buffered
// output but must not end the process before the handler finishes.
static void flushOutputGuarded() {
    __try {
        flushOutput();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
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
        flushOutputGuarded();
        return 1;
    }
}

int wmain(int argc, wchar_t *argv[], wchar_t *envp[])
{
    if (argc < 2) {
        std::wcout << L"Usage: " << argv[0] << L" <path to registry file> [output file [--flush-each-line]]" << std::endl;
        exit(1);
    }

    if (argc >= 3) {
        bool flushEachLine = false;
        if (argc >= 4) {
            if (wcscmp(argv[3], L"--flush-each-line") != 0 || argc > 4) {
                std::wcerr << L"Usage: " << argv[0] << L" <path to registry file> [output file [--flush-each-line]]" << std::endl;
                exit(1);
            }
            flushEachLine = true;
        }

        // Write the output file through Utf8CrlfFileBuf: UTF-8 with CRLF line
        // ends, the bytes the CRT's _O_U8TEXT mode produced (see the class).
        FILE* outputFile = _wfsopen(argv[2], L"wb", _SH_DENYNO);
        if (outputFile == nullptr) {
            std::wcerr << L"Failed to open output file: " << argv[2] << std::endl;
            exit(1);
        }
        g_outputBuf = new Utf8CrlfFileBuf(outputFile, flushEachLine);
        std::wcout.rdbuf(g_outputBuf);
        // Keep what is buffered if the process is ended by an unhandled
        // C++ exception or abort() (a pure virtual call, a Debug assert).
        std::set_terminate([]() {
            flushOutputGuarded();
            abort();
        });
        signal(SIGABRT, [](int) {
            flushOutputGuarded();
        });
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

    flushOutput();
    // A streambuf exception (e.g. bad_alloc) only sets badbit on wcout, after
    // which every later line was dropped.
    if (g_outputBuf != nullptr && (g_outputBuf->writeFailed() || std::wcout.bad())) {
        std::wcerr << L"Failed writing output file: " << argv[2] << std::endl;
        return 1;
    }
    return result;
}
