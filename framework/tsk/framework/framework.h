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

#include "tsk/framework/framework_i.h"

#include "tsk/framework/services/TskServices.h"
#include "tsk/framework/services/Log.h"
#include "tsk/framework/services/TskImgDB.h"
#include "tsk/framework/services/Scheduler.h"
#include "tsk/framework/services/TskSystemProperties.h"
#include "tsk/framework/services/TskBlackboard.h"
#include "tsk/framework/services/TskDBBlackboard.h"
#include "tsk/framework/utilities/SectorRuns.h"
#include "tsk/framework/utilities/TskException.h"
#include "tsk/framework/utilities/TskUtilities.h"
#include "tsk/framework/extraction/TskImageFileTsk.h"
#include "tsk/framework/extraction/CarveExtract.h"
#include "tsk/framework/extraction/CarvePrep.h"
#include "tsk/framework/file/TskFileManager.h"
#include "tsk/framework/file/TskFile.h"
#include "tsk/framework/pipeline/TskPipelineManager.h"
#include "tsk/framework/pipeline/TskPipeline.h"
#include "tsk/framework/pipeline/TskFileAnalysisPipeline.h"
#include "tsk/framework/pipeline/TskReportPipeline.h"
#include "tsk/framework/pipeline/TskModule.h"
#include "tsk/framework/pipeline/TskExecutableModule.h"
#include "tsk/framework/pipeline/TskPluginModule.h"
#include "tsk/framework/pipeline/TskFileAnalysisPluginModule.h"
#include "tsk/framework/pipeline/TskReportPluginModule.h"

#endif
