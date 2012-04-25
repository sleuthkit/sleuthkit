/*
 *
 *  The Sleuth Kit
 *
 *  Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 *  Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 *  reserved.
 *
 *  This software is distributed under the Common Public License 1.0
 */

#ifndef _TSK_OSSLIBTSK_H
#define _TSK_OSSLIBTSK_H

/**
 * Include this file when incorporating the framework into an
 * application.
 */

#include "framework_i.h"

#include "Services/TskServices.h"
#include "Services/Log.h"
#include "Services/TskImgDB.h"
#include "Services/Scheduler.h"
#include "Services/TskSystemProperties.h"
#include "Services/TskBlackboard.h"
#include "Services/TskDBBlackboard.h"
#include "Utilities/SectorRuns.h"
#include "Utilities/TskException.h"
#include "Utilities/TskUtilities.h"
#include "Extraction/TskImageFileTsk.h"
#include "Extraction/CarveExtract.h"
#include "Extraction/CarvePrep.h"
#include "File/TskFileManager.h"
#include "File/TskFile.h"
#include "Pipeline/TskPipelineManager.h"
#include "Pipeline/TskPipeline.h"
#include "Pipeline/TskFileAnalysisPipeline.h"
#include "Pipeline/TskReportPipeline.h"
#include "Pipeline/TskModule.h"
#include "Pipeline/TskExecutableModule.h"
#include "Pipeline/TskPluginModule.h"
#include "Pipeline/TskFileAnalysisPluginModule.h"
#include "Pipeline/TskReportPluginModule.h"

#endif
