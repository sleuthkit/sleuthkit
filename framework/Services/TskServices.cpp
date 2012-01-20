/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#include <string>

#include "TskServices.h"
#include "Utilities/TskException.h"
#include "Services/TskSystemPropertiesImpl.h"

TskServices *TskServices::m_pInstance = NULL;

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
    }
    return *m_pInstance;
}

Log& TskServices::getLog()
{
    // create a default one if it has not been set yet
    if (!m_log) {
        m_log = new Log;
        m_log->logInfo(L"TskServices::getLog - Log has not been set, using default implementation.");
    }
    return *m_log;
}

void TskServices::setLog(Log &log)
{
    if (m_log) {
        LOGERROR(L"TskServices::setLog - Log has already been initialized.");
        throw TskException("Log already initialized.");
    } else {
        m_log = &log;
    }
}

Scheduler& TskServices::getScheduler()
{
    if (m_scheduler == NULL)
    {
        LOGERROR(L"TskServices::getScheduler - Scheduler has not been initialized.");
        throw TskException("Scheduler not initialized.");
    }

    return *m_scheduler;
}

void TskServices::setScheduler(Scheduler &scheduler)
{
    if (m_scheduler) {
        LOGERROR(L"TskServices::setScheduler - Scheduler has already been initialized.");
        throw TskException("Scheduler already initialized.");
    } else {
        m_scheduler = &scheduler;
    }
}

void TskServices::setImgDB(TskImgDB& imgDB)
{
    if (m_imgDB) {
        LOGERROR(L"TskServices::setImgDB - ImgDB has already been initialized.");
        throw TskException("ImgDB already initialized.");
    } else {
        m_imgDB = &imgDB;
    }
}

TskImgDB& TskServices::getImgDB()
{
    if (m_imgDB == NULL)
    {
        LOGERROR(L"TskServices::getImgDB - ImgDB has not been initialized.");
        throw TskException("ImgDB not initialized.");
    }

    return *m_imgDB;
}

void TskServices::setImageFile(TskImageFile& imageFile)
{
    if (m_imageFile) {
        LOGERROR(L"TskServices::setImageFile - ImageFile has already been initialized.");
        throw TskException("ImageFile already initialized.");
    } else {
        m_imageFile = &imageFile;
    }
}

TskImageFile& TskServices::getImageFile()
{
    if (m_imageFile == NULL)
    {
        LOGERROR(L"TskServices::getImageFile - ImageFile has not been initialized.");
        throw TskException("ImageFile not initialized.");
    }

    return *m_imageFile;
}

void TskServices::setBlackboard(TskBlackboard& blackboard)
{
    if (m_blackboard) {
        LOGERROR(L"TskServices::setBlackboard - Blackboard has already been initialized.");
        throw TskException("Blackboard already initialized.");
    } else {
        m_blackboard = &blackboard;
    }
}

TskBlackboard& TskServices::getBlackboard()
{
    if (m_blackboard == NULL)
    {
        LOGERROR(L"TskServices::getBlackboard - Blackboard has not been initialized.");
        throw TskException("Blackboard not initialized.");
    }
    return *m_blackboard;
}

void TskServices::setSystemProperties(TskSystemProperties& systemProperties)
{
    if (m_systemProperties) {
        LOGERROR(L"TskServices::setSystemProperties - SystemProperties has already been initialized.");
        throw TskException("SystemProperties already initialized.");
    } else {
        m_systemProperties = &systemProperties;
    }
}

TskSystemProperties& TskServices::getSystemProperties()
{
    if (m_systemProperties == NULL)
    {
        TskSystemPropertiesImpl *prop = new TskSystemPropertiesImpl();
        prop->initialize();
        setSystemProperties(*prop);

        LOGINFO(L"TskServices::getSystemProperties - SystemProperties has not been set, using default implementation.");
        //throw TskException("SystemProperties not initialized.");
    }
    return *m_systemProperties;
}