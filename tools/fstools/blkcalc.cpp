/*
** blkcalc
** The Sleuth Kit
**
** Calculates the corresponding block number between 'blkls' and 'dd' images
** when given an 'blkls' block number, it determines the block number it
** had in a 'dd' image.  When given a 'dd' image, it determines the
** value it would have in a 'blkls' image (if the block is unallocated)
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier. All Rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc. All Rights reserved
**
** TCTUTILs
** Copyright (c) 2001 Brian Carrier.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/
#include "tsk/tsk_tools_i.h"
#include <locale.h>

static TSK_TCHAR *progname;

static void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-dsu unit_addr] [-vV] [-f fstype] [-i imgtype] [-b dev_sector_size] [-o imgoffset] image [images]\n"),
        progname);
    tsk_fprintf(stderr, "Slowly calculates the opposite block number\n");
    tsk_fprintf(stderr, "\tOne of the following must be given:\n");
    tsk_fprintf(stderr,
        "\t  -d: The given address is from a 'dd' image \n");
    tsk_fprintf(stderr,
        "\t  -s: The given address is from a 'blkls -s' (slack) image\n");
    tsk_fprintf(stderr,
        "\t  -u: The given address is from a 'blkls' (unallocated) image\n");
    tsk_fprintf(stderr,
        "\t-f fstype: The file system type (use '-f list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-b dev_sector_size: The size (in bytes) of the device sectors\n");
    tsk_fprintf(stderr,
        "\t-o imgoffset: The offset of the file system in the image (in sectors)\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Print version\n");

    exit(1);
}



int
main(int argc, char **argv1)
{
    TSK_IMG_TYPE_ENUM imgtype = TSK_IMG_TYPE_DETECT;
    TSK_IMG_INFO *img;

    TSK_OFF_T imgaddr = 0;
    TSK_FS_TYPE_ENUM fstype = TSK_FS_TYPE_DETECT;
    TSK_FS_INFO *fs;

    int ch;
    TSK_TCHAR *cp;
    uint8_t type = 0;
    int set = 0;

    TSK_DADDR_T count = 0;
    TSK_TCHAR **argv;
    unsigned int ssize = 0;

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

    while ((ch = GETOPT(argc, argv, _TSK_T("b:d:f:i:o:s:u:vV"))) > 0) {
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

        case _TSK_T('d'):
            type |= TSK_FS_BLKCALC_DD;
            count = TSTRTOULL(OPTARG, &cp, 0);
            if (*cp || *cp == *OPTARG) {
                TFPRINTF(stderr, _TSK_T("Invalid address: %s\n"), OPTARG);
                usage();
            }
            set = 1;
            break;

        case _TSK_T('f'):
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

        case _TSK_T('o'):
            if ((imgaddr = tsk_parse_offset(OPTARG)) == -1) {
                tsk_error_print(stderr);
                exit(1);
            }
            break;

        case _TSK_T('s'):
            type |= TSK_FS_BLKCALC_SLACK;
            count = TSTRTOULL(OPTARG, &cp, 0);
            if (*cp || *cp == *OPTARG) {
                TFPRINTF(stderr, _TSK_T("Invalid address: %s\n"), OPTARG);
                usage();
            }
            set = 1;
            break;

        case _TSK_T('u'):
            type |= TSK_FS_BLKCALC_BLKLS;
            count = TSTRTOULL(OPTARG, &cp, 0);
            if (*cp || *cp == *OPTARG) {
                TFPRINTF(stderr, _TSK_T("Invalid address: %s\n"), OPTARG);
                usage();
            }
            set = 1;
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

    if ((!type) || (set == 0)) {
        tsk_fprintf(stderr, "Calculation type not given (-u, -d, -s)\n");
        usage();
    }

    if ((type & TSK_FS_BLKCALC_DD) && (type & TSK_FS_BLKCALC_BLKLS)
        && (type & TSK_FS_BLKCALC_SLACK)) {
        tsk_fprintf(stderr, "Only one block type can be given\n");
        usage();
    }


    if ((img =
            tsk_img_open(argc - OPTIND, &argv[OPTIND], imgtype,
                ssize)) == NULL) {
        tsk_error_print(stderr);
        exit(1);
    }
    if ((imgaddr * img->sector_size) >= img->size) {
        tsk_fprintf(stderr,
            "Sector offset supplied is larger than disk image (maximum: %"
            PRIu64 ")\n", img->size / img->sector_size);
        exit(1);
    }

    if ((fs = tsk_fs_open_img(img, imgaddr * img->sector_size, fstype)) == NULL) {
        tsk_error_print(stderr);
        if (tsk_error_get_errno() == TSK_ERR_FS_UNSUPTYPE)
            tsk_fs_type_print(stderr);
        img->close(img);
        exit(1);
    }

    if (-1 == tsk_fs_blkcalc(fs, (TSK_FS_BLKCALC_FLAG_ENUM) type, count)) {
        tsk_error_print(stderr);
        fs->close(fs);
        img->close(img);
        exit(1);
    }

    fs->close(fs);
    img->close(img);

    exit(0);
}
