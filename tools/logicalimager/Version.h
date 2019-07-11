/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2019 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
* \file Version.h
* Contains the class definitions for the Version class
*/

#pragma once

#include <string>

/**
* Implement the major and minor version.
*
*/
class Version {
public:

    Version(std::string version)
    {
        int status = std::sscanf(version.c_str(), "%d.%d", &m_major, &m_minor);
        if (status != 2) {
            throw std::logic_error("ERROR: Invalid version " + version + ". Expected major.minor");
        }
    }

    bool operator < (const Version& rhs) const {
        if (m_major < rhs.m_major)
            return true;
        if (m_minor < rhs.m_minor)
            return true;
        return false;
    }

    bool operator == (const Version& other) const {
        return m_major == other.m_major
            && m_minor == other.m_minor;
    }

    friend std::ostream& operator << (std::ostream& stream, const Version& ver) {
        stream << ver.m_major;
        stream << '.';
        stream << ver.m_minor;
        return stream;
    }

private:
    int m_major = 0;
    int m_minor = 0;
};