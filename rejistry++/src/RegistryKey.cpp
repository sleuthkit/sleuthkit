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
        _nk = new NKRecord(*(rk._nk));
    }

    RegistryKey& RegistryKey::operator=(const RegistryKey & rk) {
        if (this != &rk) {
            _nk = new NKRecord(*(rk._nk));
        }
        return *this;
    }

    RegistryKey::~RegistryKey() {
        if (_nk != NULL) {
            delete _nk;
            _nk = NULL;
        }
    }

    uint64_t RegistryKey::getTimestamp() const {
        return _nk->getTimestamp();
    }


    std::wstring RegistryKey::getName() const {
        return _nk->getName();
    }

    /**
     * Caller is responsible for freeing the key
     */
    RegistryKey::RegistryKeyPtr RegistryKey::getParent() const {
        if (!_nk->hasParentRecord()) {
            throw NoSuchElementException("Registry Key has no parent.");
        }

        return new RegistryKey(_nk->getParentRecord());
    }

    /**
     * Caller is responsible for freeing the keys in the list
     */
    RegistryKey::RegistryKeyPtrList RegistryKey::getSubkeyList() const {
        std::vector<RegistryKey *> subkeys;
        SubkeyListRecord::SubkeyListRecordPtr subkeyListRecordPtr = _nk->getSubkeyList();
        NKRecord::NKRecordPtrList nkRecordList = subkeyListRecordPtr->getSubkeys();
        NKRecord::NKRecordPtrList::iterator it;
        for (it = nkRecordList.begin(); it != nkRecordList.end(); ++it) {
            subkeys.push_back(new RegistryKey(*it));
        }
        delete subkeyListRecordPtr;
        return subkeys;
    }


    size_t RegistryKey::getSubkeyListSize() const {
        std::vector<RegistryKey *> subkeys;
        SubkeyListRecord::SubkeyListRecordPtr subkeyListRecordPtr = _nk->getSubkeyList();
        NKRecord::NKRecordPtrList nkRecordList = subkeyListRecordPtr->getSubkeys();
        delete subkeyListRecordPtr;
        return nkRecordList.size();
    }


    /**
     * Caller is responsible for freeing returned key
     */
    RegistryKey::RegistryKeyPtr RegistryKey::getSubkey(const std::wstring& name) const {
        SubkeyListRecord::SubkeyListRecordPtr subkeyListRecordPtr = _nk->getSubkeyList();
        Rejistry::NKRecord *nkRecord = subkeyListRecordPtr->getSubkey(name);
        delete subkeyListRecordPtr;
        return new RegistryKey(nkRecord);
    }

    /**
     * Caller is responsible for freeing the values in the list
     */
    RegistryValue::RegistryValuePtrList RegistryKey::getValueList() const {
        RegistryValue::RegistryValuePtrList values;
        VKRecord::VKRecordPtrList vkRecordList = _nk->getValueList()->getValues();
        VKRecord::VKRecordPtrList::iterator it;
        for (it = vkRecordList.begin(); it != vkRecordList.end(); ++it) {
            values.push_back(new RegistryValue(*it));
        }
        return values;
    }


    size_t RegistryKey::getValueListSize() const {
        Rejistry::ValueListRecord *valueListRecord = _nk->getValueList();
        size_t size = valueListRecord->getValuesSize();
        delete valueListRecord;
        return size;
    }

    /**
     * Caller is responsible for freeing returned value
     */
    RegistryValue::RegistryValuePtr RegistryKey::getValue(const std::wstring& name) const {
        Rejistry::ValueListRecord *valueListRecord = _nk->getValueList();
        Rejistry::VKRecord *vkRecord = valueListRecord->getValue(name);
        delete valueListRecord;
        return new RegistryValue(vkRecord);
    }
};
