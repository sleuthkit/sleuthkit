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
 * \file RejistryException.cpp
 * Contains definition of Framework exception classes.
 * Based on techniques used in the Poco Exception class.
 */

#include "RejistryException.h"
#include <typeinfo>

namespace Rejistry {
    RejistryException::RejistryException(int code) : m_code(code)
    {
    }

    RejistryException::RejistryException(const std::string &msg, int code) : m_msg(msg), m_code(code)
    {
    }

    RejistryException::RejistryException(const RejistryException &e) : std::exception(e), m_msg(e.m_msg), m_code(e.m_code)
    {
    }

    RejistryException::~RejistryException() throw()
    {
    }

    RejistryException& RejistryException::operator =(const RejistryException &e)
    {
        if (&e != this)
        {
            m_msg = e.m_msg;
            m_code = e.m_code;
        }

        return *this;
    }

    const char * RejistryException::name() const throw()
    {
        return "RejistryException";
    }

    const char * RejistryException::className() const throw()
    {
        return typeid(*this).name();
    }

    const char * RejistryException::what() const throw()
    {
        std::string whatMsg = name();
        if (m_msg.length())
            whatMsg += ": " + m_msg;
        return whatMsg.c_str();
    }

    REJISTRY_IMPLEMENT_EXCEPTION(RegistryParseException, RejistryException, "Error parsing registry")
    REJISTRY_IMPLEMENT_EXCEPTION(NoSuchElementException, RejistryException, "No such element")
    REJISTRY_IMPLEMENT_EXCEPTION(IllegalArgumentException, RejistryException, "Illegal argument")
}