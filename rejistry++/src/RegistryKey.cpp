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

    RegistryKey::RegistryKeyPtr RegistryKey::getParent() const {
        if (!_nk->hasParentRecord()) {
            throw NoSuchElementException("Registry Key has no parent.");
        }

        return new RegistryKey(_nk->getParentRecord());
    }

    RegistryKey::RegistryKeyPtrList RegistryKey::getSubkeyList() const {
        std::vector<RegistryKey *> subkeys;
        NKRecord::NKRecordPtrList nkRecordList = _nk->getSubkeyList()->getSubkeys();
        NKRecord::NKRecordPtrList::iterator it;
        for (it = nkRecordList.begin(); it != nkRecordList.end(); ++it) {
            subkeys.push_back(new RegistryKey(*it));
        }
        return subkeys;
    }

    RegistryKey::RegistryKeyPtr RegistryKey::getSubkey(const std::wstring& name) const {
        return new RegistryKey(_nk->getSubkeyList()->getSubkey(name));
    }

    RegistryValue::RegistryValuePtrList RegistryKey::getValueList() const {
        RegistryValue::RegistryValuePtrList values;
        VKRecord::VKRecordPtrList vkRecordList = _nk->getValueList()->getValues();
        VKRecord::VKRecordPtrList::iterator it;
        for (it = vkRecordList.begin(); it != vkRecordList.end(); ++it) {
            values.push_back(new RegistryValue(*it));
        }
        return values;
    }

    RegistryValue::RegistryValuePtr RegistryKey::getValue(const std::wstring& name) const {
        return new RegistryValue(_nk->getValueList()->getValue(name));
    }
};
