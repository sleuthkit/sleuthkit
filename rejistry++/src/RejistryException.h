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
 * \file RejistryException.h
 * Contains definition of all Rejistry exception classes.
 */

#ifndef _REJISTRYEXCCEPTION_H
#define _REJISTRYEXCCEPTION_H

#include <stdexcept>

namespace Rejistry {
    /**
     * Rejistry exception class
     */
    class RejistryException : public std::exception
    {
    public:
        /// Create an exception using the supplied message.
        RejistryException(const std::string& msg, int code = 0);

        /// Copy Constructor
        RejistryException(const RejistryException& e);

        /// Destructor
        ~RejistryException() throw ();

        /// Assignment operator
        RejistryException& operator= (const RejistryException& e);

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
        RejistryException(int code = 0);

        /// Sets the message for the exception.
        void message(const std::string& msg);

    private:
        std::string m_msg;
        int m_code;
    };

    inline const std::string& RejistryException::message() const
    {
        return m_msg;
    }

    inline void RejistryException::message(const std::string &msg)
    {
        m_msg = msg;
    }

    inline int RejistryException::code() const
    {
        return m_code;
    }

    //
    // Macros for quickly declaring and implementing exception classes.
    // Unfortunately, we cannot use a template here because character
    // pointers (which we need for specifying the exception name)
    // are not allowed as template arguments.
    //
    #define REJISTRY_DECLARE_EXCEPTION(CLS, BASE) \
	    class CLS: public BASE                  									    \
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


    #define REJISTRY_IMPLEMENT_EXCEPTION(CLS, BASE, NAME)												\
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
    REJISTRY_DECLARE_EXCEPTION(RegistryParseException, RejistryException)
    REJISTRY_DECLARE_EXCEPTION(NoSuchElementException, RejistryException)
    REJISTRY_DECLARE_EXCEPTION(IllegalArgumentException, RejistryException)
}

#endif
