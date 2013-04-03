/*
** ifind (inode find)
** The Sleuth Kit
**
** Given an image  and block number, identify which inode it is used by
** 
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
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
#include <time.h>

static TSK_TCHAR *progname;
static uint8_t localflags;

static void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-alvV] [-f fstype] [-i imgtype] [-b dev_sector_size] [-o imgoffset] [-d unit_addr] [-n file] [-p par_addr] [-z ZONE] image [images]\n"),
        progname);
    tsk_fprintf(stderr, "\t-a: find all inodes\n");
    tsk_fprintf(stderr,
        "\t-d unit_addr: Find the meta data given the data unit\n");
    tsk_fprintf(stderr, "\t-l: long format when -p is given\n");
    tsk_fprintf(stderr,
        "\t-n file: Find the meta data given the file name\n");
    tsk_fprintf(stderr,
        "\t-p par_addr: Find UNALLOCATED MFT entries given the parent's meta address (NTFS only)\n");
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-b dev_sector_size: The size (in bytes) of the device sectors\n");
    tsk_fprintf(stderr,
        "\t-f fstype: File system type (use '-f list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-o imgoffset: The offset of the file system in the image (in sectors)\n");
    tsk_fprintf(stderr, "\t-v: Verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Print version\n");
    tsk_fprintf(stderr,
        "\t-z ZONE: Time zone setting when -l -p is given\n");

    exit(1);
}

#define IFIND_PATH 0x01
#define IFIND_DATA 0x02
#define IFIND_PARENT 0x04

int
main(int argc, char **argv1)
{
    TSK_IMG_TYPE_ENUM imgtype = TSK_IMG_TYPE_DETECT;
    TSK_IMG_INFO *img;

    TSK_OFF_T imgaddr = 0;
    TSK_FS_TYPE_ENUM fstype = TSK_FS_TYPE_DETECT;
    TSK_FS_INFO *fs;
    uint8_t type = 0;

    int ch;
    TSK_TCHAR *cp;
    extern int OPTIND;
    TSK_DADDR_T block = 0;      /* the block to find */
    TSK_INUM_T parinode = 0;
    TSK_TCHAR *path = NULL;
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

    localflags = 0;

    while ((ch = GETOPT(argc, argv, _TSK_T("ab:d:f:i:ln:o:p:vVz:"))) > 0) {
        switch (ch) {
        case _TSK_T('a'):
            localflags |= TSK_FS_IFIND_ALL;
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
        case _TSK_T('d'):
            if (type) {
                tsk_fprintf(stderr,
                    "error: only one address type can be given\n");
                usage();
            }
            type = IFIND_DATA;
            block = TSTRTOULL(OPTARG, &cp, 0);
            if (*cp || *cp == *OPTARG) {
                TFPRINTF(stderr, _TSK_T("Invalid block address: %s\n"),
                    OPTARG);
                usage();
            }
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
        case _TSK_T('l'):
            localflags |= TSK_FS_IFIND_PAR_LONG;
            break;
        case _TSK_T('n'):
            {
                size_t len;
                if (type) {
                    tsk_fprintf(stderr,
                        "error: only one address type can be given\n");
                    usage();
                }
                type = IFIND_PATH;
                len = (TSTRLEN(OPTARG) + 1) * sizeof(TSK_TCHAR);
                if ((path = (TSK_TCHAR *) malloc(len)) == NULL) {
                    tsk_fprintf(stderr, "error allocating memory\n");
                    exit(1);
                }
                TSTRNCPY(path, OPTARG, TSTRLEN(OPTARG) + 1);
                break;
            }
        case 'o':
            if ((imgaddr = tsk_parse_offset(OPTARG)) == -1) {
                tsk_error_print(stderr);
                exit(1);
            }
            break;
        case 'p':
            if (type) {
                tsk_fprintf(stderr,
                    "error: only one address type can be given\n");
                usage();
            }
            type = IFIND_PARENT;
            if (tsk_fs_parse_inum(OPTARG, &parinode, NULL, NULL, NULL,
                    NULL)) {
                TFPRINTF(stderr, _TSK_T("Invalid inode address: %s\n"),
                    OPTARG);
                usage();
            }
            break;
        case 'v':
            tsk_verbose++;
            break;
        case 'V':
            tsk_version_print(stdout);
            exit(0);
        case 'z':
            {
                TSK_TCHAR envstr[32];
                TSNPRINTF(envstr, 32, _TSK_T("TZ=%s"), OPTARG);
                if (0 != TPUTENV(envstr)) {
                    tsk_fprintf(stderr, "error setting environment");
                    exit(1);
                }

                /* we should be checking this somehow */
                TZSET();
                break;
            }
        case '?':
        default:
            tsk_fprintf(stderr, "Invalid argument: %s\n", argv[OPTIND]);
            usage();
        }
    }

    /* We need at least one more argument */
    if (OPTIND >= argc) {
        tsk_fprintf(stderr, "Missing image name\n");
        if (path)
            free(path);
        usage();
    }

    if (!type) {
        tsk_fprintf(stderr, "-d, -n, or -p must be given\n");
        usage();
    }


    if ((img =
            tsk_img_open(argc - OPTIND, &argv[OPTIND], imgtype,
                ssize)) == NULL) {
        tsk_error_print(stderr);
        if (path)
            free(path);
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
        if (path)
            free(path);
        exit(1);
    }

    if (type == IFIND_DATA) {
        if (block > fs->last_block) {
            tsk_fprintf(stderr,
                "Block %" PRIuDADDR
                " is larger than last block in image (%" PRIuDADDR
                ")\n", block, fs->last_block);
            fs->close(fs);
            img->close(img);
            exit(1);
        }
        if (tsk_fs_ifind_data(fs, (TSK_FS_IFIND_FLAG_ENUM) localflags,
                block)) {
            tsk_error_print(stderr);
            fs->close(fs);
            img->close(img);
            exit(1);
        }
    }

    else if (type == IFIND_PARENT) {
        if (TSK_FS_TYPE_ISNTFS(fs->ftype) == 0) {
            tsk_fprintf(stderr, "-p works only with NTFS file systems\n");
            fs->close(fs);
            img->close(img);
            exit(1);
        }
        else if (parinode > fs->last_inum) {
            tsk_fprintf(stderr,
                "Meta data %" PRIuINUM
                " is larger than last MFT entry in image (%" PRIuINUM
                ")\n", parinode, fs->last_inum);
            fs->close(fs);
            img->close(img);
            exit(1);
        }
        if (tsk_fs_ifind_par(fs, (TSK_FS_IFIND_FLAG_ENUM) localflags,
                parinode)) {
            tsk_error_print(stderr);
            fs->close(fs);
            img->close(img);
            exit(1);
        }
    }

    else if (type == IFIND_PATH) {
        int retval;
        TSK_INUM_T inum;

        if (-1 == (retval = tsk_fs_ifind_path(fs, path, &inum))) {
            tsk_error_print(stderr);
            fs->close(fs);
            img->close(img);
            free(path);
            exit(1);
        }
        free(path);
        if (retval == 1)
            tsk_printf("File not found\n");
        else
            tsk_printf("%" PRIuINUM "\n", inum);
    }
    fs->close(fs);
    img->close(img);

    exit(0);
}
