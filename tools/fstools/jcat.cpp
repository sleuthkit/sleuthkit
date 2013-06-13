/*
** jcat
** The Sleuth Kit 
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2004-2005 Brian Carrier.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
*/
#include "tsk/tsk_tools_i.h"
#include <locale.h>

#ifdef TSK_WIN32
#include <fcntl.h>
#endif

static TSK_TCHAR *progname;

/* usage - explain and terminate */
static void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-f fstype] [-i imgtype] [-b dev_sector_size] [-o imgoffset] [-vV] image [images] [inode] blk\n"),
        progname);
    tsk_fprintf(stderr, "\tblk: The journal block to view\n");
    tsk_fprintf(stderr,
        "\tinode: The file system inode where the journal is located\n");
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-b dev_sector_size: The size (in bytes) of the device sectors\n");
    tsk_fprintf(stderr,
        "\t-f fstype: File system type (use '-f list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-o imgoffset: The offset of the file system in the image (in sectors)\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: print version\n");
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

    TSK_INUM_T inum;
    int ch;
    TSK_DADDR_T blk;
    TSK_TCHAR *cp;
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

    while ((ch = GETOPT(argc, argv, _TSK_T("b:f:i:o:vV"))) > 0) {
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
        case _TSK_T('v'):
            tsk_verbose++;
            break;
        case _TSK_T('V'):
            tsk_version_print(stdout);
            exit(0);
        }
    }

    /* We need at least two more arguments */
    if (OPTIND + 1 >= argc) {
        tsk_fprintf(stderr, "Missing image name and/or block address\n");
        usage();
    }

    blk = TSTRTOULL(argv[argc - 1], &cp, 0);
    if (*cp || *cp == *argv[argc - 1]) {
        TFPRINTF(stderr, _TSK_T("bad block number: %s"), argv[argc - 1]);
        exit(1);
    }

    /* Do we have an inode as well? */
    if (tsk_fs_parse_inum(argv[argc - 2], &inum, NULL, NULL, NULL, NULL)) {
        /* Not a number therefore an image */
        if ((img =
                tsk_img_open(argc - OPTIND - 1, &argv[OPTIND],
                    imgtype, ssize)) == NULL) {
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
        inum = fs->journ_inum;
    }
    else {
        if ((img =
                tsk_img_open(argc - OPTIND - 2, &argv[OPTIND],
                    imgtype, ssize)) == NULL) {
            tsk_error_print(stderr);
            exit(1);
        }

        if ((fs = tsk_fs_open_img(img, imgaddr * img->sector_size, fstype)) == NULL) {
            tsk_error_print(stderr);
            if (tsk_error_get_errno() == TSK_ERR_FS_UNSUPTYPE)
                tsk_fs_type_print(stderr);
            img->close(img);
            exit(1);
        }
    }

    if (inum > fs->last_inum) {
        tsk_fprintf(stderr,
            "Inode value is too large for image (%" PRIuINUM ")\n",
            fs->last_inum);
        fs->close(fs);
        img->close(img);
        exit(1);
    }

    if (inum < fs->first_inum) {
        tsk_fprintf(stderr,
            "Inode value is too small for image (%" PRIuINUM ")\n",
            fs->first_inum);
        fs->close(fs);
        img->close(img);
        exit(1);
    }

    if (fs->jopen == NULL) {
        tsk_fprintf(stderr,
            "Journal support does not exist for this file system\n");
        fs->close(fs);
        img->close(img);
        exit(1);
    }

#ifdef TSK_WIN32
    if (-1 == _setmode(_fileno(stdout), _O_BINARY)) {
        fprintf(stderr,
            "jcat: error setting stdout to binary: %s", strerror(errno));
        fs->close(fs);
        img->close(img);
        exit(1);
    }
#endif

    if (fs->jopen(fs, inum)) {
        tsk_error_print(stderr);
        fs->close(fs);
        img->close(img);
        exit(1);
    }
    if (fs->jblk_walk(fs, blk, blk, 0, 0, NULL)) {
        tsk_error_print(stderr);
        fs->close(fs);
        img->close(img);
        exit(1);
    }

    fs->close(fs);
    img->close(img);
    exit(0);
}
