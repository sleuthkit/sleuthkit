/*
** ffind  (file find)
** The Sleuth Kit 
**
** Find the file that uses the specified inode (including deleted files)
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

static TSK_TCHAR *progname;

void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-aduvV] [-f fstype] [-i imgtype] [-b dev_sector_size] [-o imgoffset] image [images] inode\n"),
        progname);
    tsk_fprintf(stderr, "\t-a: Find all occurrences\n");
    tsk_fprintf(stderr, "\t-d: Find deleted entries ONLY\n");
    tsk_fprintf(stderr, "\t-u: Find undeleted entries ONLY\n");
    tsk_fprintf(stderr,
        "\t-f fstype: Image file system type (use '-f list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-b dev_sector_size: The size (in bytes) of the device sectors\n");
    tsk_fprintf(stderr,
        "\t-o imgoffset: The offset of the file system in the image (in sectors)\n");
    tsk_fprintf(stderr, "\t-v: Verbose output to stderr\n");
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

    int dir_walk_flags = TSK_FS_DIR_WALK_FLAG_RECURSE;
    int ch;
    extern int OPTIND;
    TSK_FS_ATTR_TYPE_ENUM type;
    uint16_t id;
    uint8_t id_used = 0, type_used = 0;
    uint8_t ffind_flags = 0;
    TSK_INUM_T inode;
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

    while ((ch = GETOPT(argc, argv, _TSK_T("ab:df:i:o:uvV"))) > 0) {
        switch (ch) {
        case _TSK_T('a'):
            ffind_flags |= TSK_FS_FFIND_ALL;
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
            dir_walk_flags |= TSK_FS_DIR_WALK_FLAG_UNALLOC;
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
        case _TSK_T('u'):
            dir_walk_flags |= TSK_FS_DIR_WALK_FLAG_ALLOC;
            break;
        case _TSK_T('v'):
            tsk_verbose++;
            break;
        case _TSK_T('V'):
            tsk_version_print(stdout);
            exit(0);
        case _TSK_T('?'):
        default:
            TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
                argv[OPTIND]);
            usage();
        }
    }

    /* if the user did not specify either of the alloc/unalloc dir_walk_flags
     ** then show them all
     */
    if ((!(dir_walk_flags & TSK_FS_DIR_WALK_FLAG_ALLOC))
        && (!(dir_walk_flags & TSK_FS_DIR_WALK_FLAG_UNALLOC)))
        dir_walk_flags |=
            (TSK_FS_DIR_WALK_FLAG_ALLOC | TSK_FS_DIR_WALK_FLAG_UNALLOC);


    if (OPTIND + 1 >= argc) {
        tsk_fprintf(stderr, "Missing image name and/or address\n");
        usage();
    }


    /* Get the inode */
    if (tsk_fs_parse_inum(argv[argc - 1], &inode, &type, &type_used, &id,
            &id_used)) {
        TFPRINTF(stderr, _TSK_T("Invalid inode: %s\n"), argv[argc - 1]);
        usage();
    }

    /* open image */
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

    if (inode < fs->first_inum) {
        tsk_fprintf(stderr,
            "Inode is too small for image (%" PRIuINUM ")\n",
            fs->first_inum);
        exit(1);
    }
    if (inode > fs->last_inum) {
        tsk_fprintf(stderr,
            "Inode is too large for image (%" PRIuINUM ")\n",
            fs->last_inum);
        exit(1);
    }

    if (tsk_fs_ffind(fs, (TSK_FS_FFIND_FLAG_ENUM) ffind_flags, inode, type,
            type_used, id, id_used,
            (TSK_FS_DIR_WALK_FLAG_ENUM) dir_walk_flags)) {
        tsk_error_print(stderr);
        fs->close(fs);
        img->close(img);
        exit(1);
    }

    fs->close(fs);
    img->close(img);
    exit(0);
}
