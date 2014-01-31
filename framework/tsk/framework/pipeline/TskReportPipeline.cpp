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
 * \file TskReportPipeline.cpp
 * Contains the implementation for the TskReportPipeline class.
 */

// Include the class definition first to ensure it does not depend on subsequent includes in this file.
#include "TskReportPipeline.h"

// TSK Framework includes
#include "tsk/framework/services/TskServices.h"

// Poco includes
#include "Poco/Stopwatch.h"

// C/C++ library includes
#include <sstream>

void TskReportPipeline::run()
{
    Poco::Stopwatch stopWatch;
    for (size_t i = 0; i < m_modules.size(); i++)
    {
        stopWatch.restart();
        TskModule::Status status = m_modules[i]->report();
        stopWatch.stop();
        updateModuleExecutionTime(m_modules[i]->getModuleId(), stopWatch.elapsed());

        TskServices::Instance().getImgDB().setModuleStatus(0, m_modules[i]->getModuleId(), (int)status);

        // The reporting pipeline continues to run on module failure. Only shutdown the pipeline if a module signals STOP.
        if (status == TskModule::STOP)
        {
            break;
        }
    }
}
