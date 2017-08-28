/*
 ** tsk_loaddb
 ** The Sleuth Kit 
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2010-2011 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

#include "tsk/tsk_tools_i.h"
#include "tsk/auto/tsk_case_db.h"
#include <locale.h>

static TSK_TCHAR *progname;

static void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-ahkvV] [-i imgtype] [-b dev_sector_size] [-d database] [-z ZONE] image [image]\n"),
        progname);
    tsk_fprintf(stderr, "\t-a: Add image to existing database, instead of creating a new one (requires -d to specify database)\n");
    tsk_fprintf(stderr, "\t-k: Don't create block data table\n");
    tsk_fprintf(stderr, "\t-h: Calculate hash values for the files\n");
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-b dev_sector_size: The size (in bytes) of the device sectors\n");
    tsk_fprintf(stderr, "\t-d database: Path for the database (default is the same directory as the image, with name derived from image name)\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Print version\n");
    tsk_fprintf(stderr, "\t-z: Time zone of original machine (i.e. EST5EDT or GMT)\n");
    
    exit(1);
}



int
main(int argc, char **argv1)
{
    TSK_IMG_TYPE_ENUM imgtype = TSK_IMG_TYPE_DETECT;

    int ch;
    TSK_TCHAR **argv;
    unsigned int ssize = 0;
    TSK_TCHAR *cp;
    TSK_TCHAR *database = NULL;
    
    bool blkMapFlag = true;   // true if we are going to write the block map
    bool createDbFlag = true; // true if we are going to create a new database
    bool calcHash = false;

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

    progname = argv[0];
    setlocale(LC_ALL, "");

    while ((ch = GETOPT(argc, argv, _TSK_T("ab:d:hi:kvVz:"))) > 0) {
        switch (ch) {
        case _TSK_T('?'):
        default:
            TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
                argv[OPTIND]);
            usage();

        case _TSK_T('a'):
            createDbFlag = false;
            break;

        case _TSK_T('b'):
            ssize = (unsigned int) TSTRTOUL(OPTARG, &cp, 0);
            if (*cp || *cp == *OPTARG || ssize < 1) {
                TFPRINTF(stderr,
                    _TSK_T
                    ("invalid argument: sector size must be positive: %s\n"),
                    OPTARG);
                usage();
            }
            break;

        case _TSK_T('i'):
            if (TSTRCMP(OPTARG, _TSK_T("list")) == 0) {
                tsk_img_type_print(stderr);
                exit(1);
            }
            imgtype = tsk_img_type_toid(OPTARG);
            if (imgtype == TSK_IMG_TYPE_UNSUPP) {
                TFPRINTF(stderr, _TSK_T("Unsupported image type: %s\n"),
                    OPTARG);
                usage();
            }
            break;
                
        case _TSK_T('k'):
            blkMapFlag = false;
            break;

        case _TSK_T('h'):
            calcHash = true;
            break;

        case _TSK_T('d'):
            database = OPTARG;
            break;

        case _TSK_T('v'):
            tsk_verbose++;
            break;
        
        case _TSK_T('V'):
            tsk_version_print(stdout);
            exit(0);

        case _TSK_T('z'):
            TSK_TCHAR envstr[32];
            TSNPRINTF(envstr, 32, _TSK_T("TZ=%s"), OPTARG);
            if (0 != TPUTENV(envstr)) {
                tsk_fprintf(stderr, "error setting environment");
                exit(1);
            }
            TZSET();
            break;
        }
    }

    /* We need at least one more argument */
    if (OPTIND >= argc) {
        tsk_fprintf(stderr, "Missing image names\n");
        usage();
    }
    
    TSK_TCHAR buff[1024];
    
    if (database == NULL) {
        if (createDbFlag == false) {
            fprintf(stderr, "Error: -a requires that database be specified with -d\n");
            usage();
        }
        TSNPRINTF(buff, 1024, _TSK_T("%s.db"), argv[OPTIND]);
        database = buff;
    }
    
    //tskRecover.setFileFilterFlags(TSK_FS_DIR_WALK_FLAG_UNALLOC);

    TskCaseDb * tskCase;
    
    if (createDbFlag) {
        tskCase = TskCaseDb::newDb(database);
    } else {
        tskCase = TskCaseDb::openDb(database);
    }

    if (tskCase == NULL) {
        tsk_error_print(stderr);
        exit(1);
    }

    TskAutoDb *autoDb = tskCase->initAddImage();
    autoDb->createBlockMap(blkMapFlag);
    autoDb->hashFiles(calcHash);
    autoDb->setAddUnallocSpace(true);

    if (autoDb->startAddImage(argc - OPTIND, &argv[OPTIND], imgtype, ssize)) {
        std::vector<TskAuto::error_record> errors = autoDb->getErrorList();
        for (size_t i = 0; i < errors.size(); i++) {
            fprintf(stderr, "Error: %s\n", TskAuto::errorRecordToString(errors[i]).c_str());
        } 
    }

    if (autoDb->commitAddImage() == -1) {
        tsk_error_print(stderr);
        exit(1);
    }
    TFPRINTF(stdout, _TSK_T("Database stored at: %s\n"), database);

    autoDb->closeImage();
    delete tskCase;
    delete autoDb;
    
    exit(0);
}
