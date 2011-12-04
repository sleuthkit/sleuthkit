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
    /**
     * Singleton interface to return the TskServices instance.
     */
    static TskServices &Instance(); 

    /** Return a Log instance. If there is no existing Log, it will be created in the current directory with a timestamp.
    * @returns 0 if no Log is created. */
    Log& getLog();

    /** Register a log implementation with the framework. */
    void setLog(Log &log);

    /** Register a Scheduler implementation with the framework */
    void setScheduler(Scheduler &scheduler);

    /** Return the Secheduler instance.
     * @returns 0 if no Scheduler was set. */
    Scheduler& getScheduler();

    /** Register a TskImgDB implementation with the framework.
     * @param imgDB The TskImgDB implementation to register
     */
    void setImgDB(TskImgDB& imgDB);

    /**
     * Return the registered TskImgDB.
     * @return The registered TskImgDB implementation or NULL
     */
    TskImgDB& getImgDB();

    /**
     * Register an TskImageFile implementation with the framework.
     * @param imgFile The TskImageFile implementation to register
     */
    void setImageFile(TskImageFile& imgFile);

    /**
     * Return the registered TskImageFile.
     * @return The registered TskImageFile implementation or NULL
     */
    TskImageFile& getImageFile();

    /**
     * Register an TskBlackboard implementation with the framework.
     * @param blackboard The TskBlackboard implementation to register
     */
    void setBlackboard(TskBlackboard& blackboard);

    /**
     * Return the registered TskBlackboard.
     * @return The registered TskBlackboard implementation or NULL
     */
    TskBlackboard& getBlackboard();

    /**
     * Register an TskSystemProperties implementation with the framework.
     * @param systemProperties The TskSystemProperties implementation to register
     */
    void setSystemProperties(TskSystemProperties& systemProperties);

    /**
     * Return the registered TskSystemProperties.
     * @return The registered TskSystemProperties implementation or NULL
     */
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
