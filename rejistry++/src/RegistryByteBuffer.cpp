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
 * \file RegistryByteBuffer.cpp
 *
 */
#include <stdexcept>
#include <sstream>
#include <locale>
#include <codecvt>
#include <iostream>
#include <cwchar>

// Local includes
#include "RegistryByteBuffer.h"
#include "RejistryException.h"
#include "../../tsk/base/tsk_base.h"
#include "../../tsk/base/tsk_unicode.h"

namespace Rejistry {

    std::wstring_convert<std::codecvt_utf16<wchar_t, 0x10ffff, std::little_endian>, wchar_t> conv;

    // Take ownership of the passed in buffer
    RegistryByteBuffer::RegistryByteBuffer(std::unique_ptr<ByteBuffer> buffer) {
        if (buffer == nullptr) {
            throw RegistryParseException("Buffer must not be null.");
        }
        _byteBuffer = std::move(buffer);
    }

    RegistryByteBuffer::~RegistryByteBuffer() {
    }

    /**
    * @returns 0 if offset is too large.
    */
    uint16_t RegistryByteBuffer::getWord(const uint32_t offset) const {
        return _byteBuffer->getShort(offset) & 0xFFFF;
    }

    /**
    * @returns 0 if offset is too large.
    */
    uint32_t RegistryByteBuffer::getDWord(const uint32_t offset) const {
        return _byteBuffer->getInt(offset) & 0xFFFFFFFF;
    }

    /**
    * @returns 0 if offset is too large.
    */
    uint64_t RegistryByteBuffer::getQWord(const uint32_t offset) const {
        return _byteBuffer->getLong(offset) & 0xFFFFFFFFFFFFFFFF;
    }

    /**
    * Throws exception if offset or length is too large.
    */
    std::string RegistryByteBuffer::getASCIIString() const {
        return getASCIIString(0, _byteBuffer->limit());
    }

	/**
	* Reads data from the registry and returns the data as a string
	* as it is represented in the registry, including Null characters.
	*
	* @param offset: Offset where data begins
	* @param length: Number of bytes to read
	*/
    std::string RegistryByteBuffer::getASCIIString(const uint32_t offset, const uint32_t length) const {
        if (length == 0) {
            return "";
        }

        ByteBuffer::ByteArray data = getData(offset, length);

        return std::string(data.begin(), data.end());
    }

    std::wstring RegistryByteBuffer::getUTF16String() const {
        return getUTF16String(0, _byteBuffer->limit());
    }

	/**
	* Reads data from the registry and returns a wstring of the data
	* as it is represented in the registry, including Null characters.
	*
	* @param offset: Offset where data begins
	* @param length: Number of bytes to read
	*/
    std::wstring RegistryByteBuffer::getUTF16String(const uint32_t offset, const uint32_t length) const {
		if (length == 0) {
			return L"";
		}

		ByteBuffer::ByteArray data = getData(offset, length);
		// There are cases where an odd number of bytes are returned which
		// leads to errors during conversion. See CT-2917 test12 for more details. 
		if (data.size() % 2 != 0) {
			data.push_back('\0');
		}

		// Empty value data (single UTF16 null char)
		if (data.size() == 2 && data[0] == '\0' && data[1] == '\0') {
			return L"";
		}

		size_t numOfWchars = data.size() / sizeof(wchar_t);

		// Sanitize data to ensure its valid UTF16 (CT-4851)
		tsk_cleanupUTF16(TSK_LIT_ENDIAN, (wchar_t*)(&data[0]), numOfWchars, L'\uFFFD');

		return std::wstring((wchar_t*)(&data[0]), numOfWchars);
	}

    ByteBuffer::ByteArray RegistryByteBuffer::getData() const {
        return getData(0, _byteBuffer->limit());
    }

	/**
	* Reads data from the registry based off of the given offset and length of data to read.
	*
	* @param offset: Offset where data begins
	* @param length: Number of bytes to read
	*/
    ByteBuffer::ByteArray RegistryByteBuffer::getData(const uint32_t offset, const uint32_t length) const {
        // Check bounds before allocating, so a corrupt length from the hive
        // can't force a huge allocation.
        if (offset > _byteBuffer->limit() || length > _byteBuffer->limit() - offset) {
            throw RegistryParseException("Requested data extends past the end of the buffer.");
        }

        uint32_t savedPosition = _byteBuffer->position();
        _byteBuffer->position(offset);
        ByteBuffer::ByteArray data;
        data.resize(length);
        _byteBuffer->get(data, 0, length);
        _byteBuffer->position(savedPosition);
        return data;
    }

    std::vector<std::wstring> RegistryByteBuffer::getStringList() const {
        return getStringList(0, _byteBuffer->limit());
    }

	/**
	* Reads REG_MULTI_SZ data: UTF-16LE strings, each ending in a null
	* character, with an extra null character ending the list.
	*
	* Splits only at null characters on a 2-byte character boundary. Empty
	* strings between other strings are kept: Windows treats the first empty
	* string as the end of the list, but anything after it is still part of the
	* value. Null characters at the end of the data are the list terminator and
	* are dropped. A last string with no terminator ends at the end of the data,
	* and an odd trailing byte becomes the low byte of a final character, as in
	* getUTF16String(). Unpaired surrogates are replaced with U+FFFD, also as in
	* getUTF16String().
	*
	* @param offset: Offset where data begins
	* @param length: Number of bytes to read
	*/
    std::vector<std::wstring> RegistryByteBuffer::getStringList(const uint32_t offset, const uint32_t length) const {
        std::vector<std::wstring> stringList;
        ByteBuffer::ByteArray data = getData(offset, length);

        if (data.size() % 2 != 0) {
            data.push_back('\0');
        }

        size_t numChars = data.size() / sizeof(wchar_t);

        // Replace unpaired surrogates (invalid UTF-16) with U+FFFD, as
        // getUTF16String() does (CT-4851); otherwise callers converting an
        // entry to UTF-8 can fail and lose the whole entry. The replacement is
        // in place and one unit for one unit, on this function's own copy of
        // the data, so sizes and the null characters used for splitting below
        // are unchanged.
        tsk_cleanupUTF16(TSK_LIT_ENDIAN, reinterpret_cast<wchar_t*>(data.data()), numChars, L'\uFFFD');

        const wchar_t* chars = reinterpret_cast<const wchar_t*>(data.data());

        // Trailing null characters are the list terminator.
        while (numChars > 0 && chars[numChars - 1] == L'\0') {
            numChars--;
        }

        size_t start = 0;
        for (size_t i = 0; i < numChars; i++) {
            if (chars[i] == L'\0') {
                stringList.push_back(std::wstring(chars + start, i - start));
                start = i + 1;
            }
        }
        if (numChars > 0) {
            stringList.push_back(std::wstring(chars + start, numChars - start));
        }

        return stringList;
    }
};
