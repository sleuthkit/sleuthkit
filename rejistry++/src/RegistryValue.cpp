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
 * \file RegistryValue.cpp
 *
 */

// Local includes
#include "RegistryValue.h"

namespace Rejistry {
    RegistryValue::RegistryValue(const RegistryValue& rv) {
        _vk = new VKRecord(*(rv._vk));
    }

    RegistryValue::~RegistryValue() {
        if (_vk != NULL) {
            delete _vk;
            _vk = NULL;
        }
    }

    std::wstring RegistryValue::getName() const {
        return _vk->getName();
    }

    ValueData::VALUE_TYPES RegistryValue::getValueType() const {
        return _vk->getValueType();
    }

    ValueData * RegistryValue::getValue() const {
        return _vk->getValue();
    }

};
