/*
 *
 * The Sleuth Kit
 *
 * Copyright 2013-2015 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This is a C++ port of the Rejistry library developed by Willi Ballenthin.
 * See https://github.com/williballenthin/Rejistry for the original Java version.
 */

/**
 * \file SubkeyListRecord.cpp
 *
 */

// Local includes
#include "SubkeyListRecord.h"
#include "RejistryException.h"
#include "NKRecord.h"

namespace Rejistry {

    uint16_t SubkeyListRecord::getListLength() const {
        return getWord(LIST_LENGTH_OFFSET);
    }

    NKRecord::NKRecordUniqPtr SubkeyListRecord::getSubkey(const std::wstring& name) const {
        NKRecord::NKRecordUniqPtr nk = findSubkey(name);
        if (!nk) {
            throw NoSuchElementException("Failed to find subkey.");
        }
        return nk;
    }

    NKRecord::NKRecordUniqPtr SubkeyListRecord::findSubkey(const std::wstring& name) const {
        for (auto& nk : getSubkeys()) {
            if (nameMatches(*nk, name)) {
                return std::move(nk);
            }
        }
        return nullptr;
    }

    NKRecord::NKRecordUniqPtr SubkeyListRecord::findSubkeyInLookup(const std::wstring& name, std::set<uint32_t>&) const {
        return findSubkey(name);
    }

    bool SubkeyListRecord::nameMatches(const NKRecord& nk, const std::wstring& name) {
        return _wcsicmp(name.c_str(), nk.getName().c_str()) == 0;
    }

};
