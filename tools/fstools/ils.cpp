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
*/

/* TCT */
/*++
 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
 --*/

#include "tsk/tsk_tools_i.h"
#include <locale.h>

static TSK_TCHAR *progname;

/* usage - explain and terminate */
static void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-emOpvV] [-aAlLzZ] [-f fstype] [-i imgtype] [-b dev_sector_size] [-o imgoffset] [-s seconds] image [images] [inum[-end]]\n"),
        progname);
    tsk_fprintf(stderr, "\t-e: Display all inodes\n");
    tsk_fprintf(stderr, "\t-m: Display output in the mactime format\n");
    tsk_fprintf(stderr,
        "\t-O: Display inodes that are unallocated, but were sill open (UFS/ExtX only)\n");
    tsk_fprintf(stderr,
        "\t-p: Display orphan inodes (unallocated with no file name)\n");
    tsk_fprintf(stderr,
        "\t-s seconds: Time skew of original machine (in seconds)\n");
    tsk_fprintf(stderr, "\t-a: Allocated inodes\n");
    tsk_fprintf(stderr, "\t-A: Unallocated inodes\n");
    tsk_fprintf(stderr, "\t-l: Linked inodes\n");
    tsk_fprintf(stderr, "\t-L: Unlinked inodes\n");
    tsk_fprintf(stderr, "\t-z: Unused inodes\n");
    tsk_fprintf(stderr, "\t-Z: Used inodes\n");
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-b dev_sector_size: The size (in bytes) of the device sectors\n");
    tsk_fprintf(stderr,
        "\t-f fstype: File system type (use '-f list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-o imgoffset: The offset of the file system in the image (in sectors)\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Display version number\n");
    exit(1);
}



/* main - open file system, list inode info */
int
main(int argc, char **argv1)
{
    TSK_IMG_TYPE_ENUM imgtype = TSK_IMG_TYPE_DETECT;
    TSK_IMG_INFO *img;

    TSK_OFF_T imgaddr = 0;
    TSK_FS_TYPE_ENUM fstype = TSK_FS_TYPE_DETECT;
    TSK_FS_INFO *fs;

    TSK_TCHAR *cp, *dash;
    TSK_INUM_T istart = 0, ilast = 0;
    int ch;
    int flags = TSK_FS_META_FLAG_UNALLOC | TSK_FS_META_FLAG_USED;
    int ils_flags = 0;
    int set_range = 1;
    TSK_TCHAR *image = NULL;
    int32_t sec_skew = 0;
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

    /*
     * Provide convenience options for the most commonly selected feature
     * combinations.
     */
    while ((ch =
            GETOPT(argc, argv, _TSK_T("aAb:ef:i:lLmo:Oprs:vVzZ"))) > 0) {
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
        case _TSK_T('e'):
            flags |= (TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_UNALLOC);
            flags &= ~TSK_FS_META_FLAG_USED;
            break;
        case _TSK_T('m'):
            ils_flags |= TSK_FS_ILS_MAC;
            break;
        case _TSK_T('o'):
            if ((imgaddr = tsk_parse_offset(OPTARG)) == -1) {
                tsk_error_print(stderr);
                exit(1);
            }
            break;
        case _TSK_T('O'):
            flags |= TSK_FS_META_FLAG_UNALLOC;
            flags &= ~TSK_FS_META_FLAG_ALLOC;
            ils_flags |= TSK_FS_ILS_OPEN;
            break;
        case _TSK_T('p'):
            flags |= (TSK_FS_META_FLAG_ORPHAN | TSK_FS_META_FLAG_UNALLOC);
            flags &= ~TSK_FS_META_FLAG_ALLOC;
            break;
        case _TSK_T('r'):
            flags |= (TSK_FS_META_FLAG_UNALLOC | TSK_FS_META_FLAG_USED);
            flags &= ~TSK_FS_META_FLAG_ALLOC;
            break;
        case _TSK_T('s'):
            sec_skew = TATOI(OPTARG);
            break;
        case _TSK_T('v'):
            tsk_verbose++;
            break;
        case _TSK_T('V'):
            tsk_version_print(stdout);
            exit(0);

            /*
             * Provide fine controls to tweak one feature at a time.
             */
        case _TSK_T('a'):
            flags |= TSK_FS_META_FLAG_ALLOC;
			flags &= ~TSK_FS_META_FLAG_UNALLOC;
            break;
        case _TSK_T('A'):
            flags |= TSK_FS_META_FLAG_UNALLOC;
            break;
        case _TSK_T('l'):
            ils_flags |= TSK_FS_ILS_LINK;
            break;
        case _TSK_T('L'):
            ils_flags |= TSK_FS_ILS_UNLINK;
            break;
        case _TSK_T('z'):
            flags |= TSK_FS_META_FLAG_UNUSED;
            break;
        case _TSK_T('Z'):
            flags |= TSK_FS_META_FLAG_USED;
            break;
        }
    }

    if (OPTIND >= argc) {
        tsk_fprintf(stderr, "Missing image name\n");
        usage();
    }

    if ((ils_flags & TSK_FS_ILS_LINK) && (ils_flags & TSK_FS_ILS_UNLINK)) {
        tsk_fprintf(stderr,
            "ERROR: Only linked or unlinked should be used\n");
        usage();
    }

    /* We need to determine if an inode or inode range was given */
    if ((dash = TSTRCHR(argv[argc - 1], _TSK_T('-'))) == NULL) {
        /* Check if is a single number */
        istart = TSTRTOULL(argv[argc - 1], &cp, 0);
        if (*cp || *cp == *argv[argc - 1]) {
            /* Not a number - consider it a file name */
            image = argv[OPTIND];
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
        }
        else {
            /* Single address set end addr to start */
            ilast = istart;
            set_range = 0;
            image = argv[OPTIND];
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
    else {
        /* We have a dash, but it could be part of the file name */
        *dash = '\0';

        istart = TSTRTOULL(argv[argc - 1], &cp, 0);
        if (*cp || *cp == *argv[argc - 1]) {
            /* Not a number - consider it a file name */
            *dash = _TSK_T('-');
            image = argv[OPTIND];
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
        }
        else {
            dash++;
            ilast = TSTRTOULL(dash, &cp, 0);
            if (*cp || *cp == *dash) {
                /* Not a number - consider it a file name */
                dash--;
                *dash = '-';
                image = argv[OPTIND];
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
            }
            else {
                set_range = 0;
                /* It was a block range, so do not include it in the open */
                image = argv[OPTIND];
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
    if (set_range) {
        istart = fs->first_inum;
        ilast = fs->last_inum;
    }
    else {
        if (istart < fs->first_inum)
            istart = fs->first_inum;

        if (ilast > fs->last_inum)
            ilast = fs->last_inum;
    }

    /* NTFS uses alloc and link different than UNIX so change
     * the default behavior
     *
     * The link value can be > 0 on deleted files (even when closed)
     */

    /* NTFS and FAT have no notion of deleted but still open */
    if ((ils_flags & TSK_FS_ILS_OPEN) && (TSK_FS_TYPE_ISNTFS(fs->ftype)
            || TSK_FS_TYPE_ISFAT(fs->ftype))) {
        fprintf(stderr,
            "Error: '-O' argument does not work with NTFS and FAT images\n");
        exit(1);
    }

    if (tsk_fs_ils(fs, (TSK_FS_ILS_FLAG_ENUM) ils_flags, istart, ilast,
            (TSK_FS_META_FLAG_ENUM) flags, sec_skew, image)) {
        tsk_error_print(stderr);
        fs->close(fs);
        img->close(img);
        exit(1);
    }

    fs->close(fs);
    img->close(img);
    exit(0);
}
