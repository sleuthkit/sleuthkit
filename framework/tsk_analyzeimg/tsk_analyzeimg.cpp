/*
*
*  The Sleuth Kit
*
*  Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
*  Copyright (c) 2011 Basis Technology Corporation. All Rights
*  reserved.
*
*  This software is distributed under the Common Public License 1.0
*/
#include <iostream>
#include <cstdio>
#include <cstdlib>

#include "tsk3/tsk_tools_i.h"
#include "framework.h"
#include "Services/TskSchedulerQueue.h"

// @@@ Remove once Poco stuff is hidden in systemPropertiesImpl
#include "Poco/Util/XMLConfiguration.h"


static uint8_t 
makeDir(const TSK_TCHAR *dir) 
{
#ifdef TSK_WIN32
    if (CreateDirectoryW(dir, NULL) == 0) {
        fprintf(stderr, "Error creating directory: %d\n", GetLastError());
        return 1;
    }
#else

#endif
    return 0;
}

void 
usage() 
{
    fprintf(stderr, "tsk_analyzeimg [-c framework_config_file] [-p pipeline_config_file] image_name\n");
    fprintf(stderr, "\t-c framework_config_file: Path to XML framework config file\n");
    fprintf(stderr, "\t-p pipeline_config_file: Path to XML pipeline config file (overrides pipeline config specified with -c)\n");
    exit(1);
}

int main(int argc, char **argv1)
{
    TSK_TCHAR **argv;
    extern int OPTIND;
    int ch;
    struct STAT_STR stat_buf;
    TSK_TCHAR *pipeline_config = NULL;
    TSK_TCHAR *framework_config = NULL;

#ifdef TSK_WIN32
    // On Windows, get the wide arguments (mingw doesn't support wmain)
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == NULL) {
        fprintf(stderr, "Error getting wide arguments\n");
        exit(1);
    }
#else
    argv = (TSK_TCHAR **) argv1;
#endif

    while ((ch =
        GETOPT(argc, argv, _TSK_T("c:p:vV"))) > 0) {
            switch (ch) {
        case _TSK_T('?'):
        default:
            TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
                argv[OPTIND]);
            usage();
        case _TSK_T('c'):
            framework_config = OPTARG;
            break;
        case _TSK_T('p'):
            pipeline_config = OPTARG;
            break;
        case _TSK_T('v'):
            tsk_verbose++;
            break;
        case _TSK_T('V'):
            tsk_version_print(stdout);
            exit(0);
            }
    }

    /* We need at least one more argument */
    if (OPTIND == argc) {
        tsk_fprintf(stderr, "Missing image name\n");
        usage();
    }
    TSK_TCHAR *imagePath = argv[OPTIND];

    // Load the framework config if they specified it
    Poco::AutoPtr<Poco::Util::XMLConfiguration> pXMLConfig;
    if (framework_config) {
        // @@@ Not Unix-friendly
        try {
            pXMLConfig = new Poco::Util::XMLConfiguration(TskUtilities::toUTF8(framework_config));
        }
        catch (std::exception& e) {
            fprintf(stderr, "Error opening framework config file (%s)\n", e.what());
            return 1;
        }
        // Initialize properties based on the config file.
        TskSystemPropertiesImpl *systemProperties = new TskSystemPropertiesImpl();    
        systemProperties->initialize(*pXMLConfig);
        TskServices::Instance().setSystemProperties(*systemProperties);
    }

    // make up an output folder to store the database and such in
    TSK_TCHAR outDirPath[1024];
    TSNPRINTF(outDirPath, 1024, _TSK_T("%s_tsk_out"), imagePath);
    if (TSTAT(outDirPath, &stat_buf) == 0) {
        fprintf(stderr, "Output directory already exists (%"PRIttocTSK")\n", outDirPath);
        return 1;
    }

    if (makeDir(outDirPath)) {
        return 1;
    }

    // @@@ Not UNIX-friendly
    TSK_SYS_PROP_SET(TskSystemProperties::OUT_DIR, outDirPath);

    // Create and register our SQLite ImgDB class   
    std::auto_ptr<TskImgDB> pImgDB(NULL);
    pImgDB = std::auto_ptr<TskImgDB>(new TskImgDBSqlite(outDirPath));
    if (pImgDB->initialize() != 0) {
        fprintf(stderr, "Error initializing SQLite database\n");
        tsk_error_print(stderr);
        return 1;
    }

    // @@@ Call pImgDB->addToolInfo() as needed to set version info...

    TskServices::Instance().setImgDB(*pImgDB);

    // Create a Blackboard and register it with the framework.
    TskServices::Instance().setBlackboard((TskBlackboard &) TskDBBlackboard::instance());

    // @@@ Not UNIX-friendly
    if (pipeline_config != NULL) 
        TSK_SYS_PROP_SET(TskSystemProperties::PIPELINE_CONFIG, pipeline_config);

    // Create a Scheduler and register it
    // @@@ Should make this be default
    TskSchedulerQueue scheduler;
    TskServices::Instance().setScheduler(scheduler);

    // Create an ImageFile and register it with the framework.
    TskImageFileTsk imageFileTsk;
    if (imageFileTsk.open(imagePath) != 0) {
        fprintf(stderr, "Error opening image: %"PRIttocTSK"\n", imagePath);
        tsk_error_print(stderr);
        return 1;
    }
    TskServices::Instance().setImageFile(imageFileTsk);

    // Let's get the pipelines setup to make sure there are no errors.
    TskPipelineManager pipelineMgr;
    TskPipeline *filePipeline;
    try {
        filePipeline = pipelineMgr.createPipeline(TskPipelineManager::FILE_ANALYSIS_PIPELINE);
    }
    catch (TskException &e ) {
        fprintf(stderr, "Error creating file analysis pipeline\n");
        std::cerr << e.message() << endl;
        filePipeline = NULL;
    }

    TskPipeline *reportPipeline;
    try {
        reportPipeline = pipelineMgr.createPipeline(TskPipelineManager::REPORTING_PIPELINE);
    }
    catch (TskException &e ) {
        fprintf(stderr, "Error creating reporting pipeline\n");
        std::cerr << e.message() << endl;
        reportPipeline = NULL;
    }

    // now we analyze the data.
    // Extract
    if (imageFileTsk.extractFiles() != 0) {
        fprintf(stderr, "Error adding file system info to database\n");
        tsk_error_print(stderr);
        return 1;
    }

    // @@@ go through the scheduler queue....

    //Run pipeline on all files
    // @@@ this needs to cycle over the files to analyze, 10 is just here for testing 
    if (filePipeline) {
        TskSchedulerQueue::task_struct *task;
        while ((task = scheduler.next()) != NULL) {
            if (task->task != Scheduler::FileAnalysis)  {
                fprintf(stderr, "WARNING: Skipping task %d\n", task->task);
                continue;
            }
            printf("processing file: %d\n", (int)task->id);
            try {
                filePipeline->run(task->id);
            }
            catch (...) {
                // error message has been logged already.
            }
        }
    }

    if (reportPipeline) {
        try {
            reportPipeline->run();
        }
        catch (...) {
            fprintf(stderr, "Error running reporting pipeline\n");
            return 1;
        }
    }

    fprintf(stderr, "image analysis complete\n");
    return 0;
}
