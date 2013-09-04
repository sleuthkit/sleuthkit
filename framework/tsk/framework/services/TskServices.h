/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _TSK_SERVICES_H
#define _TSK_SERVICES_H

#include "Log.h"
#include "Scheduler.h"
#include "TskImgDB.h"
#include "tsk/framework/extraction/TskImageFile.h"
#include "tsk/framework/services/TskBlackboard.h"
#include "tsk/framework/services/TskSystemProperties.h"
#include "tsk/framework/file/TskFileManager.h"

/**
 * Provides singleton access to many framework services.  This is used
 * to register and access the classes that implement the services. 
 */
class TSK_FRAMEWORK_API TskServices
{
public:
    static TskServices &Instance(); 

    Log& getLog();
    void setLog(Log &log);

    void setScheduler(Scheduler &scheduler);
    Scheduler& getScheduler();

    void setImgDB(TskImgDB& imgDB);
    TskImgDB& getImgDB();

    void setImageFile(TskImageFile& imgFile);
    TskImageFile& getImageFile();

    void setBlackboard(TskBlackboard& blackboard);
    TskBlackboard& getBlackboard();

    void setSystemProperties(TskSystemProperties& systemProperties);
    TskSystemProperties& getSystemProperties();

    /**
     * Set the File Manager service.
     * The standard framework implementation class is TskFileManagerImpl.
     * @param fileManager A File Manager implementation.
     * @throws TskException if one has already been set.
     */
    void setFileManager(TskFileManager& fileManager);
    /**
     * Return the File Manager service.
     * @returns File Manager reference.
     * @throws TskException if File Manager has not been set.
     */
    TskFileManager& getFileManager();

private:
    // Private constructor, copy constructor and assignment operator
    // to prevent creation of multiple instances.
    TskServices() {};
    TskServices(TskServices const&) {};
    TskServices& operator=(TskServices const&) { return *m_pInstance; };

    // Private destructor to prevent deletion of our instance.
    ~TskServices() {};

    // Default log instance that is used until TskServices::setLog() is called.
    Log m_defaultLog;

    static TskServices *m_pInstance;
    Log *m_log;
    Scheduler *m_scheduler;
    TskImgDB * m_imgDB;
    TskImageFile * m_imageFile;
    TskBlackboard * m_blackboard;
    TskSystemProperties * m_systemProperties;
    TskFileManager * m_fileManager;
};

/** 
 * Associates a string value with a name.
 *
 * @param prop An element of the /ref PredefinedProperty enum.
 * @param value The value to associate with the name corresponding to the
 * /ref PredefinedProperty enum element.
 * @return Throws /ref TskException if prop is out of range.
 */
inline void SetSystemPropertyW(TskSystemProperties::PredefinedProperty prop, const std::wstring &value)
{
    TskServices::Instance().getSystemProperties().setW(prop, value);
}

/** 
 * Associates a string value with a name.
 *
 * @param name The name with which to associate the value.
 * @param value The value to associate with the name.
 * @return Throws /ref TskException if name is empty.
 */
inline void SetSystemPropertyW(const std::wstring &name, const std::wstring &value)
{
    TskServices::Instance().getSystemProperties().setW(name, value);
}

/** 
 * Associates a string value with a name.
 *
 * @param prop An element of the /ref PredefinedProperty enum.
 * @param value The value to associate with the name corresponding to the
 * /ref PredefinedProperty enum element.
 * @return Throws /ref TskException if prop is out of range.
 */
inline void SetSystemProperty(TskSystemProperties::PredefinedProperty prop, const std::string &value)
{
    TskServices::Instance().getSystemProperties().set(prop, value);
}

/** 
 * Associates a string value with a name.
 *
 * @param name The name with which to associate the value.
 * @param value The value to associate with the name.
 * @return Throws /ref TskException if name is empty.
 */
inline void SetSystemProperty(const std::string &name, const std::string &value)
{
    TskServices::Instance().getSystemProperties().set(name, value);
}

/** 
 * Retrieves the string value associated with the given name.
 *
 * @param prop An element of the /ref PredefinedProperty enum.
 * @returns String value corresponding to prop. Throws
 * /ref TskException if the requested value is for a required predefined 
 * property that is not set.
 */
inline std::wstring GetSystemPropertyW(TskSystemProperties::PredefinedProperty prop)
{
    return TskServices::Instance().getSystemProperties().getW(prop);
}

/** 
 * Retrieves the string value associated with the given name.
 *
 * @param name Name of value to retrieve.
 * @returns String value or empty string if name was not found. 
 */
inline std::wstring GetSystemPropertyW(const std::wstring &name)
{
    return TskServices::Instance().getSystemProperties().getW(name);
}

/** 
 * Retrieves the string value associated with the given name.
 *
 * @param prop An element of the /ref PredefinedProperty enum.
 * @returns String value corresponding to prop. Throws
 * /ref TskException if the requested value is for a required predefined 
 * property that is not set.
 */
inline std::string GetSystemProperty(TskSystemProperties::PredefinedProperty prop)
{
    return TskServices::Instance().getSystemProperties().get(prop);
}

/** 
 * Retrieves the string value associated with the given name.
 *
 * @param name Name of value to retrieve.
 * @returns String value or empty string if name was not found. 
 */
inline std::string GetSystemProperty(const std::string &name)
{
    return TskServices::Instance().getSystemProperties().get(name);
}

/**
 * Recursively expands any system property macros in a given string. 
 *
 * @param inputStr The input string.
 * @return A copy of the input string with all system property macros
 * expanded.
 */
inline std::wstring ExpandSystemPropertyMacrosW(const std::wstring &inputStr)
{
    return TskServices::Instance().getSystemProperties().expandMacrosW(inputStr);
}

/**
 * Recursively expands any system property macros in a given string. 
 *
 * @param inputStr The input string.
 * @return A copy of the input string with all system property macros
 * expanded.
 */
inline std::string ExpandSystemPropertyMacros(const std::string &inputStr)
{
    return TskServices::Instance().getSystemProperties().expandMacros(inputStr);
}

#endif
