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
 * \file TskException.cpp
 * Contains definition of Framework exception classes.
 * Based on techniques used in the Poco Exception class.
 */

#include "TskException.h"
#include <typeinfo>

TskException::TskException(int code) : m_code(code)
{
}

TskException::TskException(const std::string &msg, int code) : m_msg(msg), m_code(code)
{
}

TskException::TskException(const TskException &e) : std::exception(e), m_msg(e.m_msg), m_code(e.m_code)
{
}

TskException::~TskException() throw()
{
}

TskException& TskException::operator =(const TskException &e)
{
    if (&e != this)
    {
        m_msg = e.m_msg;
        m_code = e.m_code;
    }

    return *this;
}

const char * TskException::name() const throw()
{
    return "TskException";
}

const char * TskException::className() const throw()
{
    return typeid(*this).name();
}

const char * TskException::what() const throw()
{
    return name();
}

TSK_IMPLEMENT_EXCEPTION(TskFileException, TskException, "File access error")
TSK_IMPLEMENT_EXCEPTION(TskNullPointerException, TskException, "NULL pointer")
TSK_IMPLEMENT_EXCEPTION(TskFileNotFoundException, TskFileException, "File not found")
TSK_IMPLEMENT_EXCEPTION(TskSystemPropertiesException, TskException, "System property not found")
