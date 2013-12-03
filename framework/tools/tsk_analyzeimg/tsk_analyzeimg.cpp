/*
*
*  The Sleuth Kit
*
*  Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
*  Copyright (c) 2011-2012 Basis Technology Corporation. All Rights
*  reserved.
*
*  This software is distributed under the Common Public License 1.0
*/
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <sstream>
#include <time.h>
#include <memory>

#include "tsk/tsk_tools_i.h" // Needed for tsk_getopt
#include "tsk/framework/framework.h"
#include "tsk/framework/services/TskSchedulerQueue.h"
#include "tsk/framework/services/TskSystemPropertiesImpl.h"
#include "tsk/framework/services/TskImgDBSqlite.h"
#include "tsk/framework/file/TskFileManagerImpl.h"
#include "tsk/framework/extraction/TskCarvePrepSectorConcat.h"
#include "tsk/framework/extraction/TskCarveExtractScalpel.h"
#include "tsk/framework/extraction/TskExtract.h"

#include "Poco/Path.h"
#include "Poco/File.h"

#ifdef TSK_WIN32
#include <Windows.h>
#else
#include <sys/stat.h>
#endif

#include "Poco/File.h"
#include "Poco/UnicodeConverter.h"

static uint8_t 
makeDir(const char *dir) 
{
    Poco::File path(dir);
    try {
        if (!path.createDirectory()) {
            fprintf(stderr, "Error creating directory: %s\n", dir);
            return 1;
        }
    } catch (const Poco::Exception &ex) {
        std::stringstream msg;
        msg << "Error creating directory: " << dir << " Poco exception: " << ex.displayText();
        fprintf(stderr, "%s\n", msg.str().c_str());
        return 1;
    }
    return 0;
}

/**
 * Logs all messages to a log file and prints
 * error messages to STDERR
 */
class StderrLog : public Log
{
public:
    StderrLog() : Log() {
    }

    ~StderrLog() {
    }

    void log(Channel a_channel, const std::wstring &a_msg)
    {
        Log::log(a_channel, a_msg);
        if (a_channel != Error) {
            return;
        }
        fprintf(stderr, "%S\n", a_msg.c_str());
    }
};

void 
usage(const char *program) 
{
    fprintf(stderr, "%s [-c framework_config_file] [-p pipeline_config_file] [-d outdir] [-C] [-v] [-V] [-L] image_name\n", program);
    fprintf(stderr, "\t-c framework_config_file: Path to XML framework config file\n");
    fprintf(stderr, "\t-p pipeline_config_file: Path to XML pipeline config file (overrides pipeline config specified with -c)\n");
    fprintf(stderr, "\t-d outdir: Path to output directory\n");
    fprintf(stderr, "\t-C: Disable carving, overriding framework config file settings\n");
    fprintf(stderr, "\t-u: Enable unused sector file creation\n");
    fprintf(stderr, "\t-v: Enable verbose mode to get more debug information\n");
    fprintf(stderr, "\t-V: Display the tool version\n");
    fprintf(stderr, "\t-L: Print no error messages to STDERR -- only log them\n");
    exit(1);
}

int main(int argc, char **argv1)
{
    TSK_TCHAR **argv;
    extern int OPTIND;
    int ch;
    std::string pipeline_config;
    std::string framework_config;
    std::string outDirPath;
    bool suppressSTDERR = false;
    bool doCarving = true;
    bool createUnusedSectorFiles = false;

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
        GETOPT(argc, argv, _TSK_T("d:c:p:vuVLC"))) > 0) {
        switch (ch) {
        case _TSK_T('c'):
#ifdef TSK_WIN32
            framework_config.assign(TskUtilities::toUTF8(std::wstring(OPTARG)));
#else
            framework_config.assign(OPTARG);
#endif
            break;

        case _TSK_T('p'):
#ifdef TSK_WIN32
            pipeline_config.assign(TskUtilities::toUTF8(std::wstring(OPTARG)));
#else
            pipeline_config.assign(OPTARG);
#endif
            break;
        case _TSK_T('u'):
            createUnusedSectorFiles = true;
            break;
        case _TSK_T('v'):
            tsk_verbose++;
            break;

        case _TSK_T('V'):
            tsk_version_print(stdout);
            exit(0);
            break;

        case _TSK_T('d'):
#ifdef TSK_WIN32
            outDirPath.assign(TskUtilities::toUTF8(std::wstring(OPTARG)));
#else
            outDirPath.assign(OPTARG);
#endif
            break;

        case _TSK_T('C'):
            doCarving = false;
            break;

        case _TSK_T('L'):
            suppressSTDERR = true;
            break;

        case _TSK_T('?'):
        default:
            TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
                argv[OPTIND]);
            usage(argv1[0]);
        }
    }

    /* We need at least one more argument */
    if (OPTIND == argc) {
        tsk_fprintf(stderr, "Missing image name\n");
        usage(argv1[0]);
    }

    std::string imagePath;
#ifdef TSK_WIN32
    imagePath = TskUtilities::toUTF8(std::wstring(argv[OPTIND]));
#else
    imagePath = argv1[OPTIND];
#endif
    
    if (!Poco::File(imagePath).exists()) {
        std::stringstream msg;
        msg << "Image file not found: " << imagePath;
        LOGERROR(msg.str());
        return 1;
    }

    // Load the framework config if they specified it
    try
    {
        // try the one specified on the command line
        if (framework_config.size()) {
            TskSystemPropertiesImpl *systemProperties = new TskSystemPropertiesImpl();
            systemProperties->initialize(framework_config);
            TskServices::Instance().setSystemProperties(*systemProperties);
        }
        // try the one in the current directory
        else if (Poco::File("framework_config.xml").exists()) {
            TskSystemPropertiesImpl *systemProperties = new TskSystemPropertiesImpl();
            systemProperties->initialize("framework_config.xml");
            TskServices::Instance().setSystemProperties(*systemProperties);
        }
        // try one back up a few directories for the use case that we built this in
        // the source tree.
        else {
            TskSystemPropertiesImpl *systemProperties = new TskSystemPropertiesImpl();
            systemProperties->initialize();
            std::string progdir = systemProperties->get(TskSystemProperties::PROG_DIR);
            std::string configPath = progdir + "../../../runtime/framework_config.xml";
            if (Poco::File(configPath).exists()) {
                systemProperties->initialize(configPath);
                TskServices::Instance().setSystemProperties(*systemProperties);
            } else {
                fprintf(stderr, "No framework config file found\n");
            }
        }
    }
    catch (TskException& ex)
    {
        fprintf(stderr, "Loading framework config file: %s\n", ex.message().c_str());
        return 1;
    }

    // if they didn't specify the output directory, make one
    if (outDirPath == "") {
        outDirPath.assign(imagePath);
        outDirPath.append("_tsk_out");
    }
    if (Poco::File(outDirPath).exists()) {
        std::stringstream msg;
        msg << "Output directory already exists " << outDirPath;
        LOGERROR(msg.str());
        return 1;
    }

    SetSystemProperty(TskSystemProperties::OUT_DIR, outDirPath);
    // make the output dirs, makeDir() logs the error.
    if (makeDir(outDirPath.c_str()))  {
        return 1;
    }

    if (makeDir(GetSystemProperty(TskSystemProperties::SYSTEM_OUT_DIR).c_str())) {
        return 1;
    }

    if (makeDir(GetSystemProperty(TskSystemProperties::MODULE_OUT_DIR).c_str())) {
        return 1;
    }

    std::string logDir = GetSystemProperty(TskSystemProperties::LOG_DIR);
    if (makeDir(logDir.c_str()))  {
        return 1;
    }


    // Create a log object
    struct tm * newtime;
    time_t aclock;

    time(&aclock);   // Get time in seconds
    newtime = localtime(&aclock);
    char filename[MAX_BUFF_LENGTH];
    snprintf(filename, MAX_BUFF_LENGTH, "/log_%.4d-%.2d-%.2d-%.2d-%.2d-%.2d.txt",
        newtime->tm_year + 1900, newtime->tm_mon+1, newtime->tm_mday,  
        newtime->tm_hour, newtime->tm_min, newtime->tm_sec);

    logDir.append(filename);
    std::auto_ptr<Log> log(NULL);

    if(suppressSTDERR)
        log = std::auto_ptr<Log>(new Log());
    else
        log = std::auto_ptr<Log>(new StderrLog());

    log->open(logDir.c_str());
    TskServices::Instance().setLog(*log);

    // Create and register our SQLite ImgDB class   
    std::auto_ptr<TskImgDB> pImgDB(NULL);
    pImgDB = std::auto_ptr<TskImgDB>(new TskImgDBSqlite(outDirPath.c_str()));
    if (pImgDB->initialize() != 0) {
        std::stringstream msg;
        msg << "Error initializing SQLite database: " << outDirPath;
        LOGERROR(msg.str());
        return 1;
    }

    // @@@ Call pImgDB->addToolInfo() as needed to set version info...

    TskServices::Instance().setImgDB(*pImgDB);

    // Create a Blackboard and register it with the framework.
    TskServices::Instance().setBlackboard((TskBlackboard &) TskDBBlackboard::instance());

    if (pipeline_config.size()) 
        SetSystemProperty(TskSystemProperties::PIPELINE_CONFIG_FILE, pipeline_config);

    // Create a Scheduler and register it
    TskSchedulerQueue scheduler;
    TskServices::Instance().setScheduler(scheduler);

    // Create a FileManager and register it with the framework.
    TskServices::Instance().setFileManager(TskFileManagerImpl::instance());

    TskImageFileTsk imageFileTsk;

    // Check to see if input image is actually a container file
    TskArchiveExtraction::ExtractorPtr containerExtractor = TskArchiveExtraction::createExtractor(imagePath);

    if (containerExtractor.isNull())
    {
        // Create an ImageFile and register it with the framework.
        if (imageFileTsk.open(imagePath) != 0) {
            std::stringstream msg;
            msg << "Error opening image: " << imagePath;
            LOGERROR(msg.str());
            return 1;
        }
        TskServices::Instance().setImageFile(imageFileTsk);
    }

    // Let's get the pipelines setup to make sure there are no errors.
    TskPipelineManager pipelineMgr;
    TskPipeline *filePipeline;
    try {
        filePipeline = pipelineMgr.createPipeline(TskPipelineManager::FILE_ANALYSIS_PIPELINE);
    }
    catch (const TskException &e ) {
        std::stringstream msg;
        msg << "Error creating file analysis pipeline: " << e.message();
        LOGERROR(msg.str());
        filePipeline = NULL;
    }

    TskPipeline *reportPipeline;
    try {
        reportPipeline = pipelineMgr.createPipeline(TskPipelineManager::POST_PROCESSING_PIPELINE);
    }
    catch (const TskException &e ) {
        std::stringstream msg;
        msg << "Error creating reporting pipeline: " << e.message();
        LOGERROR(msg.str());
        reportPipeline = NULL;
    }

    if ((filePipeline == NULL) && (reportPipeline == NULL)) {
        std::stringstream msg;
        msg << "No pipelines configured.  Stopping";
        LOGERROR(msg.str());
        exit(1);
    }

    // Now we analyze the data.

    std::auto_ptr<TskCarveExtractScalpel> carver(new TskCarveExtractScalpel(createUnusedSectorFiles));

    // Extract
    if (!containerExtractor.isNull())   // Input is an archive file
    {
        if (containerExtractor->extractFiles() != 0)
        {
            std::wstringstream msg;
            msg << L"Error adding archived file info to database";
            LOGERROR(msg.str());
            return 1;
        }
    }
    else // Input is an image file
    {
        if (imageFileTsk.extractFiles() != 0)
        {
            std::wstringstream msg;
            msg << L"Error adding file system info to database";
            LOGERROR(msg.str());
            return 1;
        }

        if (doCarving && !GetSystemProperty("SCALPEL_DIR").empty())
        {
            TskCarvePrepSectorConcat carvePrep;
            carvePrep.processSectors();
            carver.reset(new TskCarveExtractScalpel());
        }
    }

    TskSchedulerQueue::task_struct *task;
    while ((task = scheduler.nextTask()) != NULL) 
    {
        try
        {
            if (task->task == Scheduler::FileAnalysis && filePipeline && !filePipeline->isEmpty())
            {
                filePipeline->run(task->id);
            }
            else if (task->task == Scheduler::Carve && carver.get())
            {
                carver->processFile(static_cast<int>(task->id));
            }
            else
            {
                std::stringstream msg;
                msg << "WARNING: Skipping task: " << task->task;
                LOGWARN(msg.str());
            }
            delete task;
        }
        catch (...) 
        {
            // Error message has been logged already.
        }
    }

    if (filePipeline && !filePipeline->isEmpty())
    {
        filePipeline->logModuleExecutionTimes();
    }

    // Do image analysis tasks.
    if (reportPipeline) 
    {
        try 
        {
            reportPipeline->run();
        }
        catch (...) 
        {
            std::stringstream msg;
            msg << "Error running reporting pipeline";
            LOGERROR(msg.str());
            return 1;
        }
        
        if (!reportPipeline->isEmpty())
        {
            reportPipeline->logModuleExecutionTimes();
        }
    }

    std::stringstream msg;
    msg << "image analysis complete";
    LOGINFO(msg.str());
    cout << "Results saved to " << outDirPath << std::endl;
    return 0;
}

