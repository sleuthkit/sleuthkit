/*
 * img_cat
 * The Sleuth Kit 
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All rights reserved 
 *
 * This software is distributed under the Common Public License 1.0
 */
#include "tsk/tsk_tools_i.h"
#include <errno.h>

#ifdef TSK_WIN32
#include <fcntl.h>
#endif

static TSK_TCHAR *progname;

static void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-vV] [-i imgtype] [-b dev_sector_size] [-s start_sector] [-e stop_sector] image\n"),
        progname);
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use 'i list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-b dev_sector_size: The size (in bytes) of the device sectors\n");
    tsk_fprintf(stderr,
        "\t-s start_sector: The sector number to start at\n");
    tsk_fprintf(stderr,
        "\t-e stop_sector:  The sector number to stop at\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Print version\n");

    exit(1);
}


int
main(int argc, char **argv1)
{
    TSK_IMG_INFO *img;
    TSK_IMG_TYPE_ENUM imgtype = TSK_IMG_TYPE_DETECT;
    int ch;
    TSK_OFF_T start_sector = 0;
    TSK_OFF_T end_sector = 0;
    ssize_t cnt;
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

    while ((ch = GETOPT(argc, argv, _TSK_T("b:i:vVs:e:"))) > 0) {
        switch (ch) {
        case _TSK_T('?'):
        default:
            TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
                argv[OPTIND]);
            usage();
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

        case _TSK_T('s'):
            start_sector = TSTRTOUL(OPTARG, &cp, 0);
            if (*cp || *cp == *OPTARG || start_sector < 1) {
                TFPRINTF(stderr,
                    _TSK_T
                    ("invalid argument: start sector must be positive: %s\n"),
                    OPTARG);
                usage();
            }
            break;

        case _TSK_T('e'):
            end_sector = TSTRTOUL(OPTARG, &cp, 0);
            if (*cp || *cp == *OPTARG || end_sector < 1) {
                TFPRINTF(stderr,
                    _TSK_T
                    ("invalid argument: end sector must be positive: %s\n"),
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
        tsk_fprintf(stderr, "Missing image name\n");
        usage();
    }

    if ((img =
            tsk_img_open(argc - OPTIND, &argv[OPTIND], imgtype,
                ssize)) == NULL) {
        tsk_error_print(stderr);
        exit(1);
    }

#ifdef TSK_WIN32
    if (-1 == _setmode(_fileno(stdout), _O_BINARY)) {
        fprintf(stderr,
            "error setting stdout to binary: %s", strerror(errno));
        exit(1);
    }
#endif

    TSK_OFF_T start_byte = 0;
    if (start_sector)
        start_byte = start_sector * img->sector_size;

    TSK_OFF_T end_byte = 0;
    if (end_sector)
        end_byte = (end_sector + 1) * img->sector_size;
    else
        end_byte = img->size;


    for (TSK_OFF_T done = start_byte; done < end_byte; done += cnt) {
        char buf[16 * 1024];
        size_t len;

        if (done + (TSK_OFF_T) sizeof(buf) > end_byte) {
            len = (size_t) (end_byte - done);
        }
        else {
            len = sizeof(buf);
        }

        cnt = tsk_img_read(img, done, buf, len);
        if (cnt != (ssize_t) len) {
            if (cnt >= 0) {
                tsk_fprintf(stderr,
                    "img_cat: Error reading image file at offset: %"
                    PRIuOFF ", len: %" PRIuOFF ", return: %" PRIuOFF "\n",
                    done, len, cnt);
            }
            else {
                tsk_error_print(stderr);
            }
            tsk_img_close(img);
            exit(1);
        }

        if (fwrite(buf, cnt, 1, stdout) != 1) {
            fprintf(stderr,
                "img_cat: Error writing to stdout:  %s", strerror(errno));
            tsk_img_close(img);
            exit(1);
        }
    }

    tsk_img_close(img);
    exit(0);
}
