/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
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
        return name();
    }

    REJISTRY_IMPLEMENT_EXCEPTION(RegistryParseException, RejistryException, "Error parsing registry")
    REJISTRY_IMPLEMENT_EXCEPTION(NoSuchElementException, RejistryException, "No such element")
    REJISTRY_IMPLEMENT_EXCEPTION(IllegalArgumentException, RejistryException, "Illegal argument")
}