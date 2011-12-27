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
#include <stdio.h>
#include <stdlib.h>

#include "tsk3/tsk_tools_i.h"
#include "framework.h"

void 
usage() 
{
    fprintf(stderr, "tsk_analyzeimg image_name\n");
    exit(1);
}

int main(int argc, char **argv1)
{
    TSK_TCHAR **argv;
    extern int OPTIND;
    int ch;
    struct STAT_STR stat_buf;

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
            GETOPT(argc, argv, _TSK_T("vV"))) > 0) {
        switch (ch) {
        case _TSK_T('?'):
        default:
            TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
                argv[OPTIND]);
            usage();
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
    
    // make up an output folder
    TSK_TCHAR outDirPath[1024];
    TSNPRINTF(outDirPath, 1024, _TSK_T("%s_tsk_out"), imagePath);
    if (TSTAT(outDirPath, &stat_buf) == 0) {
        fprintf(stderr, "Output directory already exists (%"PRIttocTSK")\n", outDirPath);
        return 1;
    }

    // @@@ MAKE THE DIRECTORY

    // Create and register our SQLite ImgDB class   
    std::auto_ptr<TskImgDB> pImgDB(NULL);
    pImgDB = std::auto_ptr<TskImgDB>(new TskImgDBSqlite(outDirPath));
    if (pImgDB->initialize() != 0) {
        fprintf(stderr, "Error initializing SQLite database\n");
        tsk_error_print(stderr);
        return 1;
    }
    TskServices::Instance().setImgDB(*pImgDB);

    // Create a Blackboard and register it with the framework.
    TskServices::Instance().setBlackboard(TskDBBlackboard::instance());

    // Create an ImageFile and register it with the framework.
    TskImageFileTsk imageFileTsk;
    if (imageFileTsk.open(imagePath) != 0) {
        fprintf(stderr, "Error opening image: %"PRIttocTSK"\n", imagePath);
        tsk_error_print(stderr);
        return 1;
    }
    TskServices::Instance().setImageFile(imageFileTsk);

    // Extract
    
    //Run pipeline on all files

}