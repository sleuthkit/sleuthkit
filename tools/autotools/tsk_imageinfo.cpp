/*
 ** tsk_imageinfo
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2021 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

#include "tsk/tsk_tools_i.h"
#include "tsk/auto/tsk_is_image_supported.h"
#include <locale.h>
#include <time.h>


static TSK_TCHAR *progname;

static void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-vV] [-i imgtype] [-b dev_sector_size] image\n"),
        progname);
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-b dev_sector_size: The size (in bytes) of the device sectors\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Print version\n");


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

    while ((ch = GETOPT(argc, argv, _TSK_T("b:i:vV"))) > 0) {
        switch (ch) {
        case _TSK_T('?'):
        default:
            TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
                argv[OPTIND]);
            usage();
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

        case _TSK_T('v'):
            tsk_verbose++;
            break;

        case _TSK_T('V'):
            tsk_version_print(stdout);
            exit(0);
        }
    }

    /* We need at least one more argument */
    if (OPTIND >= argc) {
        tsk_fprintf(stderr,
            "Missing image name\n");
        usage();
    }

    int imageCount = argc - OPTIND;
    if (imageCount != 1) {
        tsk_fprintf(stderr,
            "Only one image supported\n");
        usage();
    }

    TskIsImageSupported imageProcessor;
    if (imageProcessor.openImage(imageCount, &argv[OPTIND], imgtype, ssize)) {
        tsk_error_print(stderr);
        exit(1);
    }

    // Run findFilesInImage to process the image and detect data / encryption
    imageProcessor.findFilesInImg();

    imageProcessor.printResults();

    exit(0);
}
