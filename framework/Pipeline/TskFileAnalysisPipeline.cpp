/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file TskFileAnalysisPipeline.cpp
 * Contains the implementation for the TskFileAnalysisPipeline class.
 */

// System includes
#include <sstream>

// Framework includes
#include "TskFileAnalysisPipeline.h"
#include "File/TskFileManagerImpl.h"
#include "Services/TskServices.h"

// Poco includes
#include "Poco/AutoPtr.h"

TskFileAnalysisPipeline::TskFileAnalysisPipeline()
{
}

TskFileAnalysisPipeline::~TskFileAnalysisPipeline()
{
}

void TskFileAnalysisPipeline::run(const uint64_t fileId)
{
    if (m_modules.size() == 0)
        return;

    // Get a file object for the given fileId
    std::auto_ptr<TskFile> file(TskFileManagerImpl::instance().getFile(fileId));

    // Run the file object through the pipeline.
    run(file.get());
}

void TskFileAnalysisPipeline::run(TskFile* file)
{
    if (m_modules.size() == 0)
        return;

    if (file == NULL)
    {
        LOGERROR(L"TskFileAnalysisPipeline::run - Passed NULL file pointer.");
        throw TskNullPointerException();
    }

    TskImgDB& imgDB = TskServices::Instance().getImgDB();

    try
    {
        // If this is an excluded file or the file is not ready for analysis
        // we return without processing.
        if (excludeFile(file))
        {
            file->setStatus(TskImgDB::IMGDB_FILES_STATUS_ANALYSIS_SKIPPED);
            return;
        }

        if (file->status() != TskImgDB::IMGDB_FILES_STATUS_READY_FOR_ANALYSIS)
            return;

        // Update status to indicate analysis is in progress.
        file->setStatus(TskImgDB::IMGDB_FILES_STATUS_ANALYSIS_IN_PROGRESS);

        // If there is an Executable module in the pipeline we must
        // ensure that the file exists on disk.
        bool bCreated = false;

        if (!file->exists())
        {
            TskFileManagerImpl::instance().saveFile(file);
            bCreated = true;
        }

        for (int i = 0; i < m_modules.size(); i++)
        {
            TskModule::Status status = m_modules[i]->run(file);

            imgDB.setModuleStatus(file->id(), m_modules[i]->getModuleId(), (int)status);

            // Stop processing the file when a module tells us to.
            if (status == TskModule::STOP)
                break;
        }

        // Delete the file if we created it above.
        if (bCreated)
            TskFileManagerImpl::instance().deleteFile(file);

        // We allow modules to set status on the file so we only update it
        // if the modules haven't
        if (file->status() == TskImgDB::IMGDB_FILES_STATUS_ANALYSIS_IN_PROGRESS)
            file->setStatus(TskImgDB::IMGDB_FILES_STATUS_ANALYSIS_COMPLETE);
    }
    catch (std::exception& ex)
    {
        std::wstringstream msg;
        msg << L"TskFileAnalysisPipeline::run - Error while processing file id (" << file->id()
            << L") : " << ex.what();
        LOGERROR(msg.str());
        imgDB.updateFileStatus(file->id(), TskImgDB::IMGDB_FILES_STATUS_ANALYSIS_FAILED);

        // Rethrow the exception
        throw;
    }
}
