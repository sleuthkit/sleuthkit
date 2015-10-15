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
 * \file ValueData.cpp
 *
 */

// Local includes
#include "ValueData.h"
#include "RejistryException.h"

namespace Rejistry {

    std::wstring ValueData::getAsString() const {
        switch(_type) {
        case ValueData::VALTYPE_SZ:
        case ValueData::VALTYPE_EXPAND_SZ:
            return _buf->getUTF16String();
        default:
            throw IllegalArgumentException("Cannot get string data for non string type.");
        }
    }

    std::vector<std::wstring> ValueData::getAsStringList() const {
        std::vector<std::wstring> stringList;
        switch(_type) {
        case ValueData::VALTYPE_SZ:
        case ValueData::VALTYPE_EXPAND_SZ:
            stringList.push_back(_buf->getUTF16String());
            break;
        case ValueData::VALTYPE_MULTI_SZ:
            stringList = _buf->getStringList();
            break;
        default:
            throw IllegalArgumentException("Cannot get string data for non string type.");
        }

        return stringList;
    }

    ByteBuffer::ByteArray ValueData::getAsRawData() const {
        return _buf->getData();
    }

    uint64_t ValueData::getAsNumber() const {
        switch(_type) {
        case ValueData::VALTYPE_DWORD:
            return _buf->getDWord(0);
        case ValueData::VALTYPE_QWORD:
            return _buf->getQWord(0);
        case ValueData::VALTYPE_BIG_ENDIAN:
            // TODO: convert to big endian.
            return _buf->getDWord(0);
        default:
            throw IllegalArgumentException("Cannot get string data for non string type.");
        }
    }

    std::wstring ValueData::getValueType(ValueData::VALUE_TYPES type) {
        switch (type) {
        case ValueData::VALTYPE_SZ:
            return L"REG_SZ";
        case ValueData::VALTYPE_EXPAND_SZ:
            return L"REG_EXPAND_SZ";
        case ValueData::VALTYPE_MULTI_SZ:
            return L"REG_MULTI_SZ";
        case ValueData::VALTYPE_BIG_ENDIAN:
            return L"REG_BIG_ENDIAN";
        case ValueData::VALTYPE_BIN:
            return L"REG_BIN";
        case ValueData::VALTYPE_DWORD:
            return L"REG_DWORD";
        case ValueData::VALTYPE_QWORD:
            return L"REG_QWORD";
        case ValueData::VALTYPE_LINK:
            return L"REG_LINK";
        case ValueData::VALTYPE_NONE:
            return L"REG_NONE";
        case ValueData::VALTYPE_RESOURCE_LIST:
            return L"REG_RESOURCE_LIST";
        case ValueData::VALTYPE_FULL_RESOURCE_DESCRIPTOR:
            return L"REG_FULL_RESOURCE_DESCRIPTOR";
        case ValueData::VALTYPE_RESOURCE_REQUIREMENTS_LIST:
            return L"REG_RESOURCE_REQUIREMENTS_LIST";
        default:
            return L"Unrecognized type";
        }
    }


};
