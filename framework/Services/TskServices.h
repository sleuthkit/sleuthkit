/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _TSK_SERVICES_H
#define _TSK_SERVICES_H

#include "Log.h"
#include "Scheduler.h"
#include "TskImgDB.h"
#include "Extraction/TskImageFile.h"
#include "Services/TskBlackboard.h"
#include "Services/TskSystemProperties.h"

/**
 * Provices singleton access to many framework services.  This is used
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

private:
    // Private constructor, copy constructor and assignment operator
    // to prevent creation of multiple instances.
    TskServices() {};
    TskServices(TskServices const&) {};
    TskServices& operator=(TskServices const&) { return *m_pInstance; };

    // Private destructor to prevent deletion of our instance.
    ~TskServices() {};

    static TskServices *m_pInstance;
    Log *m_log;
    Scheduler *m_scheduler;
    TskImgDB * m_imgDB;
    TskImageFile * m_imageFile;
    TskBlackboard * m_blackboard;
    TskSystemProperties * m_systemProperties;
};
#endif
