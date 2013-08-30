/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#include <string>

#include "TskServices.h"
#include "tsk/framework/utilities/TskException.h"
#include "tsk/framework/services/TskSystemPropertiesImpl.h"

TskServices *TskServices::m_pInstance = NULL;

/**
 * Singleton interface to return the TskServices instance.
 */
TskServices &TskServices::Instance()
{
    if (!m_pInstance) {
        m_pInstance = new TskServices;
        m_pInstance->m_log = NULL;
        m_pInstance->m_scheduler = NULL;
        m_pInstance->m_imgDB = NULL;
        m_pInstance->m_blackboard = NULL;
        m_pInstance->m_systemProperties = NULL;
        m_pInstance->m_imageFile = NULL;
        m_pInstance->m_fileManager = NULL;
    }
    return *m_pInstance;
}

/** 
 * Return the system log service.  If no log was setup, a service will be
 * created that sends messages to stderr.
 * @returns log reference. 
 */
Log& TskServices::getLog()
{
    // create a default one if it has not been set yet
    if (!m_log) {
        m_defaultLog.logInfo(L"TskServices::getLog - Log has not been set, using default implementation.");
        return m_defaultLog;
    }
    return *m_log;
}

/**
 * Set the log service. 
 * Throws an exception if one has already been set. 
 */
void TskServices::setLog(Log &log)
{
    if (m_log) {
        LOGERROR(L"TskServices::setLog - Log has already been initialized.");
        throw TskException("Log already initialized.");
    } else {
        m_log = &log;
    }
}

/** 
 * Return the system scheduler service.  If no service was setup, an exception
 * is thrown.
 * @returns scheduler reference. 
 */
Scheduler& TskServices::getScheduler()
{
    if (m_scheduler == NULL)
    {
        LOGERROR(L"TskServices::getScheduler - Scheduler has not been initialized.");
        throw TskException("Scheduler not initialized.");
    }

    return *m_scheduler;
}

/**
 * Set the scheduler service. 
 * Throws an exception if one has already been set. 
 */
void TskServices::setScheduler(Scheduler &scheduler)
{
    if (m_scheduler) {
        LOGERROR(L"TskServices::setScheduler - Scheduler has already been initialized.");
        throw TskException("Scheduler already initialized.");
    } else {
        m_scheduler = &scheduler;
    }
}


/** 
 * Return the database service.  If no service was setup, an exception
 * is thrown.
 * @returns database reference. 
 */
TskImgDB& TskServices::getImgDB()
{
    if (m_imgDB == NULL)
    {
        LOGERROR(L"TskServices::getImgDB - ImgDB has not been initialized.");
        throw TskException("ImgDB not initialized.");
    }

    return *m_imgDB;
}

/**
 * Set the database service. 
 * Throws an exception if one has already been set. 
 */
void TskServices::setImgDB(TskImgDB& imgDB)
{
    if (m_imgDB) {
        LOGERROR(L"TskServices::setImgDB - ImgDB has already been initialized.");
        throw TskException("ImgDB already initialized.");
    } else {
        m_imgDB = &imgDB;
    }
}



/**
 * Set the image file service. 
 * Throws an exception if one has already been set. 
 */
void TskServices::setImageFile(TskImageFile& imageFile)
{
    if (m_imageFile) {
        LOGERROR(L"TskServices::setImageFile - ImageFile has already been initialized.");
        throw TskException("ImageFile already initialized.");
    } else {
        m_imageFile = &imageFile;
    }
}

/** 
 * Return the image file service.  If no service was setup, an exception
 * is thrown.
 * @returns image file reference. 
 */
TskImageFile& TskServices::getImageFile()
{
    if (m_imageFile == NULL)
    {
        LOGERROR(L"TskServices::getImageFile - ImageFile has not been initialized.");
        throw TskException("ImageFile not initialized.");
    }

    return *m_imageFile;
}

/**
 * Set the blackboard service. 
 * Throws an exception if one has already been set. 
 */
void TskServices::setBlackboard(TskBlackboard& blackboard)
{
    if (m_blackboard) {
        LOGERROR(L"TskServices::setBlackboard - Blackboard has already been initialized.");
        throw TskException("Blackboard already initialized.");
    } else {
        m_blackboard = &blackboard;
    }
}

/** 
 * Return the blackboard service.  If no service was setup, an exception
 * is thrown.
 * @returns blackboard file reference. 
 */
TskBlackboard& TskServices::getBlackboard()
{
    if (m_blackboard == NULL)
    {
        LOGERROR(L"TskServices::getBlackboard - Blackboard has not been initialized.");
        throw TskException("Blackboard not initialized.");
    }
    return *m_blackboard;
}

/**
 * Set the system properties service. 
 * Throws an exception if one has already been set. 
 */
void TskServices::setSystemProperties(TskSystemProperties& systemProperties)
{
    if (m_systemProperties) {
        LOGERROR(L"TskServices::setSystemProperties - SystemProperties has already been initialized.");
        throw TskException("SystemProperties already initialized.");
    } else {
        m_systemProperties = &systemProperties;
    }
}

/** 
 * Return the system properties service.  If no service was setup, a
 * default memory-based version is created.
 * @returns system properties reference. 
 */
TskSystemProperties& TskServices::getSystemProperties()
{
    if (m_systemProperties == NULL)
    {
        TskSystemPropertiesImpl *prop = new TskSystemPropertiesImpl();
        prop->initialize();
        setSystemProperties(*prop);

        LOGINFO(L"TskServices::getSystemProperties - SystemProperties has not been set, using default implementation.");
    }
    return *m_systemProperties;
}

void TskServices::setFileManager(TskFileManager& fileManager)
{
    if (m_fileManager) {
        LOGERROR(L"TskServices::setFileManager - File Manager has already been initialized.");
        throw TskException("FileManager already initialized.");
    } else {
        m_fileManager = &fileManager;
    }
}

TskFileManager& TskServices::getFileManager()
{
    if (m_fileManager == NULL)
    {
        LOGERROR(L"TskServices::getFileManager - File Manager has not been initialized.");
        throw TskException("File Manager not initialized.");
    }
    return *m_fileManager;
}
