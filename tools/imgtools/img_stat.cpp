/*
 * imgstat
 * The Sleuth Kit 
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2005-2011 Brian Carrier.  All rights reserved 
 *
 *
 * This software is distributed under the Common Public License 1.0
 */
#include "tsk/tsk_tools_i.h"
#include <stdio.h>

static TSK_TCHAR *progname;

static void
verify_progress_cb(int a_percent, const char *a_msg, void *a_ctx)
{
    if (a_msg != NULL) {
        /* Final call on FAIL/ERROR: clear progress line, capture message. */
        tsk_printf("\r%-45s\r", "");   /* erase progress line */
        if (a_ctx)
            snprintf((char *) a_ctx, 100, "%s", a_msg);
    } else {
        tsk_printf("\rCalculating hash of image: %3d%%", a_percent);
        fflush(stdout);
    }
}

static void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %" PRIttocTSK " [-ctvV] [-i imgtype] [-b dev_sector_size] image\n"),
        progname);
    tsk_fprintf(stderr, "\t-c: verify image integrity (MD5 check; EWF only)\n");
    tsk_fprintf(stderr, "\t-t: display type only\n");
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for list of supported types)\n");
    tsk_fprintf(stderr,
        "\t-b dev_sector_size: The size (in bytes) of the device sectors\n");
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
    uint8_t type = 0;
    uint8_t do_check = 0;
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

    while ((ch = GETOPT(argc, argv, _TSK_T("b:ci:tvV"))) > 0) {
        switch (ch) {
        case _TSK_T('?'):
        default:
            TFPRINTF(stderr, _TSK_T("Invalid argument: %" PRIttocTSK "\n"),
                argv[OPTIND]);
            usage();
            break;
        case _TSK_T('b'):
            ssize = (unsigned int) TSTRTOUL(OPTARG, &cp, 0);
            if (*cp || *cp == *OPTARG || ssize < 1) {
                TFPRINTF(stderr,
                    _TSK_T
                    ("invalid argument: sector size must be positive: %" PRIttocTSK "\n"),
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
                TFPRINTF(stderr, _TSK_T("Unsupported image type: %" PRIttocTSK "\n"),
                    OPTARG);
                usage();
            }
            break;

        case _TSK_T('c'):
            do_check = 1;
            break;

        case _TSK_T('t'):
            type = 1;
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

    if (type) {
        const char *str = tsk_img_type_toname(img->itype);
        tsk_printf("%s\n", str);
    }
    else {
        img->imgstat(img, stdout);
    }

    if (do_check) {
        char vdetail[100];
        vdetail[0] = '\0';
        TSK_IMG_VERIFY_RESULT vr = tsk_img_verify(img, verify_progress_cb, vdetail);
        switch (vr) {
        case TSK_IMG_VERIFY_PASS:
            tsk_printf("\rVerification: PASS                    \n");
            break;
        case TSK_IMG_VERIFY_FAIL:
            tsk_printf("Verification: FAIL\n");
            if (vdetail[0]) tsk_printf("Details: %s\n", vdetail);
            tsk_img_close(img);
            exit(1);
        case TSK_IMG_VERIFY_ERROR:
            tsk_printf("Verification: ERROR\n");
            if (vdetail[0]) tsk_printf("Details: %s\n", vdetail);
            tsk_img_close(img);
            exit(1);
        case TSK_IMG_VERIFY_UNSUPPORTED:
            tsk_printf("Verification: UNSUPPORTED\n");
            break;
        }
    }

    tsk_img_close(img);
    exit(0);
}
