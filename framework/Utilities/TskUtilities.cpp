/*
 *
 *  The Sleuth Kit
 *
 *  Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 *  Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 *  reserved.
 *
 *  This software is distributed under the Common Public License 1.0
 */

/**
 * \file TskUtilities.cpp
 * Contains common utility methods.
 */

#include "TskUtilities.h"

#include "Poco/UnicodeConverter.h"

std::string TskUtilities::toUTF8(const std::wstring &utf16Str)
{
    std::string utf8Str;
    Poco::UnicodeConverter::toUTF8(utf16Str, utf8Str);
    return utf8Str;
}

std::wstring TskUtilities::toUTF16(const std::string &utf8Str)
{
    std::wstring utf16Str;
    Poco::UnicodeConverter::toUTF16(utf8Str, utf16Str);
    return utf16Str;
}
