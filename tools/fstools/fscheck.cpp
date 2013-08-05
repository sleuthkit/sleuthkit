/*
** fscheck
** The Sleuth Kit 
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2004-2005 Brian Carrier.  All rights reserved 
**
** This software is distributed under the Common Public License 1.0
*/
#include "tsk/tsk_tools_i.h"

static void
usage()
{
    fprintf(stderr,
        "usage: %s [-vV] [-f fstype] [-i imgtype] [-b dev_sector_size] [-o imgoffset] image [images]\n",
        progname);
    fprintf(stderr, "\t-i imgtype: The format of the image file\n");
    tsk_fprintf(stderr,
        "\t-b dev_sector_size: The size (in bytes) of the device sectors\n");
    fprintf(stderr,
        "\t-o imgoffset: The offset of the file system in the image (in sectors)\n");
    fprintf(stderr, "\t-v: verbose output to stderr\n");
    fprintf(stderr, "\t-V: Print version\n");
    fprintf(stderr, "\t-f fstype: File system type\n");
    fs_print_types(stderr);
    img_print_types(stderr);

    exit(1);
}


int
main(int argc, char **argv)
{
    TSK_IMG_TYPE_ENUM imgtype = TSK_IMG_TYPE_DETECT;
    TSK_IMG_INFO *img;

    TSK_OFF_T imgaddr = 0;
    TSK_FS_TYPE_ENUM fstype = TSK_FS_TYPE_DETECT;
    TSK_FS_INFO *fs;

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

    while ((ch = GETOPT(argc, argv, "b:f:i:o:vV")) > 0) {
        switch (ch) {
        case '?':
        default:
            fprintf(stderr, "Invalid argument: %s\n", argv[OPTIND]);
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
        case 'f':
            if (TSTRCMP(OPTARG, _TSK_T("list")) == 0) {
                tsk_fs_type_print(stderr);
                exit(1);
            }
            fstype = tsk_fs_type_toid(OPTARG);
            if (fstype == TSK_FS_TYPE_UNSUPP) {
                TFPRINTF(stderr,
                    _TSK_T("Unsupported file system type: %s\n"), OPTARG);
                usage();
            }
            break;

        case 'i':
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

        case 'o':
            if ((imgaddr = tsk_parse_offset(OPTARG)) == -1) {
                tsk_error_print(stderr);
                exit(1);
            }
            break;

        case 'v':
            verbose++;
            break;

        case 'V':
            print_version(stdout);
            exit(0);
        }
    }

    /* We need at least one more argument */
    if (OPTIND >= argc) {
        fprintf(stderr, "Missing image name\n");
        usage();
    }

    img =
        img_open(imgoff, argc - OPTIND,
        (const char **) &argv[OPTIND], imgtype, ssize);
    if (img == NULL) {
        tsk_error_print(stderr);
        exit(1);
    }

    if (fs = fs_open(img, fstype)) {
        if (tsk_error_get_errno() == TSK_ERR_FS_UNSUPTYPE)
            tsk_print_types(stderr);

        tsk_error_print(stderr);
        img->close(img);
        exit(1);

    }

    if (fs->fscheck(fs, stdout)) {
        tsk_error_print(stderr);
        fs->close(fs);
        img->close(img);
        exit(1);
    }

    fs->close(fs);
    img->close(img);

    exit(0);
}
