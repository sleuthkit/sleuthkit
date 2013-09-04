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
 * \file TskException.h
 * Contains definition of Framework exception classes.
 * Based on techniques used in the Poco Exception class.
 */

#ifndef _TSK_EXCEPTION_H
#define _TSK_EXCEPTION_H

#include <stdexcept>

#include "tsk/framework/framework_i.h"

/**
 * Framework exception class
 */
class TSK_FRAMEWORK_API TskException : public std::exception
{
public:
    /// Create an exception using the supplied message.
    TskException(const std::string& msg, int code = 0);

    /// Copy Constructor
    TskException(const TskException& e);

    /// Destructor
    ~TskException() throw ();

    /// Assignment operator
    TskException& operator= (const TskException& e);

    /// Returns a static string describing the exception.
    virtual const char * name() const throw();

    /// Returns the name of the exception class.
    virtual const char * className() const throw();

    /// Returns a static string describing the exception.
    /// Same as name(), but for compatibility with std::exception.
    virtual const char * what() const throw();

    /// Returns the message text.
    const std::string& message() const;

    /// Returns the exception code.
    int code() const;

protected:
    /// Default constructor.
    TskException(int code = 0);

    /// Sets the message for the exception.
    void message(const std::string& msg);

private:
    std::string m_msg;
    int m_code;
};

inline const std::string& TskException::message() const
{
    return m_msg;
}

inline void TskException::message(const std::string &msg)
{
    m_msg = msg;
}

inline int TskException::code() const
{
    return m_code;
}

//
// Macros for quickly declaring and implementing exception classes.
// Unfortunately, we cannot use a template here because character
// pointers (which we need for specifying the exception name)
// are not allowed as template arguments.
//
#define TSK_DECLARE_EXCEPTION(CLS, BASE) \
	class TSK_FRAMEWORK_API CLS: public BASE									    \
	{																				\
	public:																			\
		CLS(int code = 0);															\
		CLS(const std::string& msg, int code = 0);									\
		CLS(const CLS& exc);														\
		~CLS() throw();																\
		CLS& operator = (const CLS& exc);											\
		const char* name() const throw();											\
		const char* className() const throw();										\
	};


#define TSK_IMPLEMENT_EXCEPTION(CLS, BASE, NAME)													\
	CLS::CLS(int code): BASE(code)																	\
	{																								\
	}																								\
	CLS::CLS(const std::string& msg, int code): BASE(msg, code)										\
	{																								\
	}																								\
	CLS::CLS(const CLS& exc): BASE(exc)																\
	{																								\
	}																								\
	CLS::~CLS() throw()																				\
	{																								\
	}																								\
	CLS& CLS::operator = (const CLS& exc)															\
	{																								\
		BASE::operator = (exc);																		\
		return *this;																				\
	}																								\
	const char* CLS::name() const throw()	           												\
	{																								\
		return NAME;																				\
	}																								\
	const char* CLS::className() const throw()			    										\
	{																								\
		return typeid(*this).name();																\
	}																								\

//
// Standard exception classes
//
TSK_DECLARE_EXCEPTION(TskFileException, TskException)
TSK_DECLARE_EXCEPTION(TskNullPointerException, TskException)
TSK_DECLARE_EXCEPTION(TskFileNotFoundException, TskFileException)
TSK_DECLARE_EXCEPTION(TskSystemPropertiesException, TskException)

#endif
