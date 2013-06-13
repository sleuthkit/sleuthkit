/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
** Copyright (c) 1997,1998,1999, International Business Machines
** Corporation and others. All Rights Reserved.
**
*/

/* TCT:
 *
 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
 */
#include "tsk/tsk_tools_i.h"
#include <locale.h>

static TSK_TCHAR *progname;

/* usage - explain and terminate */

static void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-aAelvV] [-f fstype] [-i imgtype] [-b dev_sector_size] [-o imgoffset] image [images] [start-stop]\n"),
        progname);
    tsk_fprintf(stderr, "\t-e: every block (including file system metadata blocks)\n");
    tsk_fprintf(stderr,
        "\t-l: print details in time machine list format\n");
    tsk_fprintf(stderr, "\t-a: Display allocated blocks\n");
    tsk_fprintf(stderr, "\t-A: Display unallocated blocks\n");
    tsk_fprintf(stderr,
        "\t-f fstype: File system type (use '-f list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-b dev_sector_size: The size (in bytes) of the device sectors\n");
    tsk_fprintf(stderr,
        "\t-o imgoffset: The offset of the file system in the image (in sectors)\n");
    tsk_fprintf(stderr,
        "\t-s: print slack space only (other flags are ignored\n");
    tsk_fprintf(stderr, "\t-v: verbose to stderr\n");
    tsk_fprintf(stderr, "\t-V: print version\n");

    exit(1);
}






/* main - open file system, list block info */

int
main(int argc, char **argv1)
{
    TSK_IMG_TYPE_ENUM imgtype = TSK_IMG_TYPE_DETECT;
    TSK_IMG_INFO *img;

    TSK_OFF_T imgaddr = 0;
    TSK_FS_TYPE_ENUM fstype = TSK_FS_TYPE_DETECT;
    TSK_FS_INFO *fs;

    TSK_TCHAR *cp, *dash;
    TSK_DADDR_T bstart = 0, blast = 0;
    int ch;
    int flags =
        TSK_FS_BLOCK_WALK_FLAG_UNALLOC |
        TSK_FS_BLOCK_WALK_FLAG_META | TSK_FS_BLOCK_WALK_FLAG_CONT;

    char lclflags = TSK_FS_BLKLS_CAT, set_bounds = 1;
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

    while ((ch = GETOPT(argc, argv, _TSK_T("aAb:ef:i:lo:svV"))) > 0) {
        switch (ch) {
        case _TSK_T('?'):
        default:
            TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
                argv[OPTIND]);
            usage();
        case _TSK_T('a'):
            flags |= TSK_FS_BLOCK_WALK_FLAG_ALLOC;
            flags &= ~TSK_FS_BLOCK_WALK_FLAG_UNALLOC;
            break;
        case _TSK_T('A'):
            flags |= TSK_FS_BLOCK_WALK_FLAG_UNALLOC;
            flags &= ~TSK_FS_BLOCK_WALK_FLAG_ALLOC;
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
        case _TSK_T('e'):
            flags |= (TSK_FS_BLOCK_WALK_FLAG_ALLOC | TSK_FS_BLOCK_WALK_FLAG_UNALLOC);
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
            lclflags = TSK_FS_BLKLS_LIST;
            break;
        case _TSK_T('o'):
            if ((imgaddr = tsk_parse_offset(OPTARG)) == -1) {
                tsk_error_print(stderr);
                exit(1);
            }
            break;
        case _TSK_T('s'):
            lclflags |= TSK_FS_BLKLS_SLACK;
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

    /* Slack has only the image name */
    if (lclflags & TSK_FS_BLKLS_SLACK) {
        if (lclflags & TSK_FS_BLKLS_LIST) {
            tsk_fprintf(stderr,
                "Other options ignored with the slack space flag, try again\n");
            exit(1);
        }

        /* There should be no other arguments */
        img = tsk_img_open(argc - OPTIND, &argv[OPTIND], imgtype, ssize);

        if (img == NULL) {
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
    }
    else {

        /* We need to determine if the block range was given */
        if ((dash = TSTRCHR(argv[argc - 1], _TSK_T('-'))) == NULL) {
            /* No dash in arg - therefore it is an image file name */
            if ((img =
                    tsk_img_open(argc - OPTIND, &argv[OPTIND],
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

            set_bounds = 1;
        }
        else {
            /* We have a dash, but it could be part of the file name */
            *dash = '\0';

            bstart = TSTRTOULL(argv[argc - 1], &cp, 0);
            if (*cp || *cp == *argv[argc - 1]) {
                /* Not a number - consider it a file name */
                *dash = _TSK_T('-');
                if ((img =
                        tsk_img_open(argc - OPTIND, &argv[OPTIND],
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

                set_bounds = 1;
            }
            else {
                /* Check after the dash */
                dash++;
                blast = TSTRTOULL(dash, &cp, 0);
                if (*cp || *cp == *dash) {
                    /* Not a number - consider it a file name */
                    dash--;
                    *dash = _TSK_T('-');
                    if ((img =
                            tsk_img_open(argc - OPTIND, &argv[OPTIND],
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

                    set_bounds = 1;
                }
                else {

                    set_bounds = 0;
                    /* It was a block range, so do not include it in the open */
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
                }
            }
        }

        if ((fs = tsk_fs_open_img(img, imgaddr * img->sector_size, fstype)) == NULL) {
            tsk_error_print(stderr);
            if (tsk_error_get_errno() == TSK_ERR_FS_UNSUPTYPE)
                tsk_fs_type_print(stderr);
            img->close(img);
            exit(1);
        }


        /* do we need to set the range or just check them? */
        if (set_bounds) {
            bstart = fs->first_block;
            blast = fs->last_block;
        }
        else {
            if (bstart < fs->first_block)
                bstart = fs->first_block;

            if (blast > fs->last_block)
                blast = fs->last_block;
        }
    }

    if (tsk_fs_blkls(fs, (TSK_FS_BLKLS_FLAG_ENUM) lclflags, bstart, blast,
            (TSK_FS_BLOCK_WALK_FLAG_ENUM)flags)) {
        tsk_error_print(stderr);
        fs->close(fs);
        img->close(img);
        exit(1);
    }

    fs->close(fs);
    img->close(img);
    exit(0);
}
