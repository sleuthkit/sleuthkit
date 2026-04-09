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
 * \file RegistryKey.cpp
 *
 */

// Local includes 
#include "RegistryKey.h"
#include "RejistryException.h"

namespace Rejistry {
    RegistryKey::RegistryKey(const RegistryKey& rk) {
        _nk = std::make_unique<NKRecord>(*(rk._nk));
    }

    RegistryKey& RegistryKey::operator=(const RegistryKey & rk) {
        if (this != &rk) {
            _nk = std::make_unique<NKRecord>(*(rk._nk));
        }
        return *this;
    }

    RegistryKey::~RegistryKey() {
    }

    uint64_t RegistryKey::getTimestamp() const {
        return _nk->getTimestamp();
    }

    std::wstring RegistryKey::getName() const {
        return _nk->getName();
    }

    std::unique_ptr<RegistryKey> RegistryKey::getParent() const {
        if (!_nk->hasParentRecord()) {
            throw NoSuchElementException("Registry Key has no parent.");
        }

        return std::make_unique<RegistryKey>(_nk->getParentRecord());
    }

    RegistryKey::RegistryKeyPtrList RegistryKey::getSubkeyList() const {
        std::vector<RegistryKey::RegistryKeyUniqPtr> subkeys;
        for (auto& nk : _nk->getSubkeyList()->getSubkeys()) {
            subkeys.push_back(std::make_unique<RegistryKey>(std::move(nk)));
        }

        return subkeys;
    }

    size_t RegistryKey::getSubkeyListSize() const {
        return _nk->getSubkeyCount();
    }

    RegistryKey::RegistryKeyUniqPtr RegistryKey::getSubkey(const std::wstring& name) const {
        return std::make_unique<RegistryKey>(_nk->getSubkeyList()->getSubkey(name));
    }

    RegistryValue::RegistryValuePtrList RegistryKey::getValueList() const {
        RegistryValue::RegistryValuePtrList values;

        for (auto& valueRecord : _nk->getValueList()->getValues()) { 
            values.push_back(std::make_unique<RegistryValue>(std::move(valueRecord)));
        }

        return values;
    }

    size_t RegistryKey::getValueListSize() const {
        auto valueListRecord = _nk->getValueList();
        return valueListRecord->getValuesSize();
    }

    RegistryValue::RegistryValueUniqPtr RegistryKey::getValue(const std::wstring& name) const {
        return std::make_unique<RegistryValue>(_nk->getValueList()->getValue(name));
    }
};
