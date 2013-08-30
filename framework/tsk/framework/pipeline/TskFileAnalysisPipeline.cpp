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
 * \file TskFileAnalysisPipeline.cpp
 * Contains the implementation for the TskFileAnalysisPipeline class.
 */

// Include the class definition first to ensure it does not depend on subsequent includes in this file.
#include "TskFileAnalysisPipeline.h"

// TSK Framework includes
#include "tsk/framework/file/TskFileManagerImpl.h"
#include "tsk/framework/services/TskServices.h"

// Poco includes
#include "Poco/AutoPtr.h"
#include "Poco/Stopwatch.h"

// C/C++ library includes
#include <sstream>
#include <memory>

void TskFileAnalysisPipeline::run(const uint64_t fileId)
{
    // Get a file object for the given fileId
    std::auto_ptr<TskFile> file(TskFileManagerImpl::instance().getFile(fileId));

    if (m_modules.size() == 0){
        file->setStatus(TskImgDB::IMGDB_FILES_STATUS_ANALYSIS_COMPLETE);
        return;
    }

    // Run the file object through the pipeline.
    run(file.get());
}

void TskFileAnalysisPipeline::run(TskFile* file)
{
    const std::string MSG_PREFIX = "TskFileAnalysisPipeline::run : ";

    if (m_modules.size() == 0)
        return;

    if (file == NULL)
    {
        LOGERROR(MSG_PREFIX + "passed NULL file pointer");
        throw TskNullPointerException();
    }

    TskImgDB& imgDB = TskServices::Instance().getImgDB();

    try
    {
        // If this is an excluded file or the file is not ready for analysis
        // we return without processing.
        if (excludeFile(file))
        {
            std::stringstream msg;
            msg << MSG_PREFIX << "skipping file (excluded) "  << file->getName() << "(" << file->getId() << ")";
            LOGINFO(msg.str());
            file->setStatus(TskImgDB::IMGDB_FILES_STATUS_ANALYSIS_SKIPPED);
            return;
        }

        if (file->getStatus() != TskImgDB::IMGDB_FILES_STATUS_READY_FOR_ANALYSIS) 
        {
            std::stringstream msg;
            msg << MSG_PREFIX << "skipping file (not ready) " << file->getName() << "(" << file->getId() << ")";
            LOGINFO(msg.str());
            return;
        }

        // Update status to indicate analysis is in progress.
        file->setStatus(TskImgDB::IMGDB_FILES_STATUS_ANALYSIS_IN_PROGRESS);
        std::stringstream msg;
        msg << MSG_PREFIX <<  "analyzing " << file->getName() << "(" << file->getId() << ")";
        LOGINFO(msg.str());

        imgDB.begin();

        // If there is an Executable module in the pipeline we must
        // ensure that the file exists on disk.
        if (m_hasExeModule && !file->exists())
        {
            TskFileManagerImpl::instance().saveFile(file);
        }

        bool bModuleFailed = false;

        Poco::Stopwatch stopWatch;
        for (size_t i = 0; i < m_modules.size(); i++)
        {
            // we have no way of knowing if the file was closed by a module,
            // so always make sure it is open
            file->open();

            // Reset the file offset to the beginning of the file.
            file->seek(0);

            stopWatch.restart();
            TskModule::Status status = m_modules[i]->run(file);
            stopWatch.stop();            
            updateModuleExecutionTime(m_modules[i]->getModuleId(), stopWatch.elapsed());
            
            imgDB.setModuleStatus(file->getId(), m_modules[i]->getModuleId(), (int)status);

            // If any module encounters a failure while processing a file
            // we will set the file status to failed once the pipeline is complete.
            if (status == TskModule::FAIL)
                bModuleFailed = true;

            // Stop processing the file when a module tells us to.
            else if (status == TskModule::STOP)
                break;
        }

        // Delete the file if it exists. The file may have been created by us
        // above or by a module that required it to exist on disk.
        // Carved and derived files should not be deleted since the content is
        // typically created by external tools.
        if (file->getTypeId() != TskImgDB::IMGDB_FILES_TYPE_CARVED &&
            file->getTypeId() != TskImgDB::IMGDB_FILES_TYPE_DERIVED &&
            file->exists())
        { 
            TskFileManagerImpl::instance().deleteFile(file);
        }

        // We allow modules to set status on the file so we only update it
        // if the modules haven't.
        if (file->getStatus() == TskImgDB::IMGDB_FILES_STATUS_ANALYSIS_IN_PROGRESS)
        {
            if (bModuleFailed)
            {
                file->setStatus(TskImgDB::IMGDB_FILES_STATUS_ANALYSIS_FAILED);
            }
            else
            {
                file->setStatus(TskImgDB::IMGDB_FILES_STATUS_ANALYSIS_COMPLETE);
            }
        }
        imgDB.commit();
    }
    catch (std::exception& ex)
    {
        std::stringstream msg;
        msg << MSG_PREFIX << "error while processing file id (" << file->getId() << ") : " << ex.what();
        LOGERROR(msg.str());
        imgDB.updateFileStatus(file->getId(), TskImgDB::IMGDB_FILES_STATUS_ANALYSIS_FAILED);
        imgDB.commit();
        // Rethrow the exception
        throw;
    }
}
