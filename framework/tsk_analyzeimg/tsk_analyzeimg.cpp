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

#include "tsk3/tsk_tools_i.h" // Needed for tsk_getopt
#include "framework.h"
#include "Services/TskSchedulerQueue.h"
#include "Services/TskSystemPropertiesImpl.h"
#include "Services/TskImgDBSqlite.h"
#include "File/TskFileManagerImpl.h"
#include "Extraction/TskCarvePrepSectorConcat.h"
#include "Extraction/TskCarveExtractScalpel.h"
#include "Extraction/TskExtract.h"

#include "Poco/Path.h"
#include "Poco/File.h"

#ifdef TSK_WIN32
#include <Windows.h>
#else
#error "Only Windows is currently supported"
#endif

#include "Poco/File.h"
#include "Poco/UnicodeConverter.h"

static uint8_t 
makeDir(const TSK_TCHAR *dir) 
{
#ifdef TSK_WIN32
    if (CreateDirectoryW(dir, NULL) == 0) {
        fprintf(stderr, "Error creating directory: %d\n", GetLastError());
        return 1;
    }
#else
#error Unsupported OS
#endif
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
        Log::~Log();
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
    struct STAT_STR stat_buf;
    TSK_TCHAR *pipeline_config = NULL;
    TSK_TCHAR *framework_config = NULL;
    std::wstring outDirPath;
    bool suppressSTDERR = false;
    bool doCarving = true;

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
        GETOPT(argc, argv, _TSK_T("d:c:p:vVLC"))) > 0) {
        switch (ch) {
        case _TSK_T('?'):
        default:
            TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
                argv[OPTIND]);
            usage(argv1[0]);
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
            break;
        case _TSK_T('d'):
            outDirPath.assign(OPTARG);
            break;
        case _TSK_T('C'):
            doCarving = false;
            break;
        case _TSK_T('L'):
            suppressSTDERR = true;
            break;
        }
    }

    /* We need at least one more argument */
    if (OPTIND == argc) {
        tsk_fprintf(stderr, "Missing image name\n");
        usage(argv1[0]);
    }

    TSK_TCHAR *imagePath = argv[OPTIND];
	if (TSTAT(imagePath, &stat_buf) != 0) {
        std::wstringstream msg;
        msg << L"Image file not found: " << imagePath;
        LOGERROR(msg.str());
        return 1;
    }

    // Load the framework config if they specified it
    try
    {
        if (framework_config) {
            // Initialize properties based on the config file.
            TskSystemPropertiesImpl *systemProperties = new TskSystemPropertiesImpl();
            systemProperties->initialize(framework_config);
            TskServices::Instance().setSystemProperties(*systemProperties);
        }
        else {
            Poco::File config("framework_config.xml");
            if (config.exists()) {
                TskSystemPropertiesImpl *systemProperties = new TskSystemPropertiesImpl();
                systemProperties->initialize("framework_config.xml");
                TskServices::Instance().setSystemProperties(*systemProperties);
            }
            else {
                fprintf(stderr, "No framework config file found\n");
            }
        }
    }
    catch (TskException& ex)
    {
        fprintf(stderr, "%s\n", ex.message().c_str());
        return 1;
    }

    if (outDirPath == _TSK_T("")) {
        outDirPath.assign(imagePath);
        outDirPath.append(_TSK_T("_tsk_out"));
    }
    if (TSTAT(outDirPath.c_str(), &stat_buf) == 0) {
        std::wstringstream msg;
        msg << L"Output directory already exists " << outDirPath.c_str();
        LOGERROR(msg.str());
        return 1;
    }

    // @@@ Not UNIX-friendly
    SetSystemPropertyW(TskSystemProperties::OUT_DIR, outDirPath);

    if (makeDir(outDirPath.c_str())) 
    {
        return 1;
    }

    if (makeDir(GetSystemPropertyW(TskSystemProperties::SYSTEM_OUT_DIR).c_str()))
    {
        return 1;
    }

    if (makeDir(GetSystemPropertyW(TskSystemProperties::MODULE_OUT_DIR).c_str()))
    {
        return 1;
    }

    std::wstring logDir = GetSystemPropertyW(TskSystemProperties::LOG_DIR);
    if (makeDir(logDir.c_str())) 
    {
        return 1;
    }

    struct tm newtime;
    time_t aclock;

    time(&aclock);   // Get time in seconds
    localtime_s(&newtime, &aclock);   // Convert time to struct tm form 
    wchar_t filename[MAX_BUFF_LENGTH];
    _snwprintf_s(filename, MAX_BUFF_LENGTH, MAX_BUFF_LENGTH, L"\\log_%.4d-%.2d-%.2d-%.2d-%.2d-%.2d.txt",
        newtime.tm_year + 1900, newtime.tm_mon+1, newtime.tm_mday,  
        newtime.tm_hour, newtime.tm_min, newtime.tm_sec);

    logDir.append(filename);
    Log *log = NULL;

    if(suppressSTDERR)
        log = new Log();
    else
        log = new StderrLog();

    log->open(logDir.c_str());
    TskServices::Instance().setLog(*log);

    // Create and register our SQLite ImgDB class   
    std::auto_ptr<TskImgDB> pImgDB(NULL);
    pImgDB = std::auto_ptr<TskImgDB>(new TskImgDBSqlite(outDirPath.c_str()));
    if (pImgDB->initialize() != 0) {
        std::wstringstream msg;
        msg << L"Error initializing SQLite database: " << outDirPath.c_str();
        LOGERROR(msg.str());
        return 1;
    }

    // @@@ Call pImgDB->addToolInfo() as needed to set version info...

    TskServices::Instance().setImgDB(*pImgDB);

    // Create a Blackboard and register it with the framework.
    TskServices::Instance().setBlackboard((TskBlackboard &) TskDBBlackboard::instance());

    // @@@ Not UNIX-friendly
    if (pipeline_config != NULL) 
        SetSystemPropertyW(TskSystemProperties::PIPELINE_CONFIG_FILE, pipeline_config);

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
            std::wstringstream msg;
            msg << L"Error opening image: " << imagePath;
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
    catch (TskException &e ) {
        std::wstringstream msg;
        std::wstring exceptionMsg;
        Poco::UnicodeConverter::toUTF16(e.message(), exceptionMsg);
        msg << L"Error creating file analysis pipeline: " << exceptionMsg;
        LOGERROR(msg.str());
        filePipeline = NULL;
    }

    TskPipeline *reportPipeline;
    try {
        reportPipeline = pipelineMgr.createPipeline(TskPipelineManager::POST_PROCESSING_PIPELINE);
    }
    catch (TskException &e ) {
        std::wstringstream msg;
        std::wstring exceptionMsg;
        Poco::UnicodeConverter::toUTF16(e.message(), exceptionMsg);
        msg << L"Error creating reporting pipeline: " << exceptionMsg;
        LOGERROR(msg.str());
        reportPipeline = NULL;
    }

    if ((filePipeline == NULL) && (reportPipeline == NULL)) {
        std::wstringstream msg;
        msg << L"No pipelines configured.  Stopping";
        LOGERROR(msg.str());
        exit(1);
    }

    // Now we analyze the data.

    std::auto_ptr<TskCarveExtractScalpel> carver;

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
            carvePrep.processSectors(true);
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
                std::wstringstream msg;
                msg << L"WARNING: Skipping task: " << task->task;
                LOGWARN(msg.str());
                continue;
            }
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
            std::wstringstream msg;
            msg << L"Error running reporting pipeline";
            LOGERROR(msg.str());
            return 1;
        }
        
        if (!reportPipeline->isEmpty())
        {
            reportPipeline->logModuleExecutionTimes();
        }
    }

    std::wstringstream msg;
    msg << L"image analysis complete";
    LOGINFO(msg.str());
    wcout << L"Results saved to " << outDirPath;
    return 0;
}

