/*
** usnjls
** The Sleuth Kit
**
** Given an NTFS image and UsnJrnl file inode, parses its content showing
** the list of recent changes wihtin the File System.
**
** Matteo Cafasso [noxdafox <at> gmail [dot] com]
**
** This software is distributed under the Common Public License 1.0
**
*/


#include <locale.h>
#include "tsk/fs/tsk_fs_i.h"


static TSK_TCHAR *progname;
static const char *usnjrnl_path = "$Extend/$UsnJrnl";


/* usage - explain and terminate */
static void
usage()
{
    TFPRINTF(stderr,
             _TSK_T
             ("usage: %s [-f fstype] [-i imgtype] [-b dev_sector_size]"
              " [-o imgoffset] [-lmvV] image [inode]\n"),
             progname);
    tsk_fprintf(stderr,
                "\t-i imgtype: The format of the image file "
                "(use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
                "\t-b dev_sector_size: The size (in bytes)"
                " of the device sectors\n");
    tsk_fprintf(stderr,
                "\t-f fstype: File system type "
                "(use '-f list' for supported types)\n");
    tsk_fprintf(stderr,
                "\t-o imgoffset: The offset of the file system"
                " in the image (in sectors)\n");
    tsk_fprintf(stderr, "\t-l: Long output format with detailed information\n");
    tsk_fprintf(stderr, "\t-m: Time machine output format\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: print version\n");

    exit(1);
}


int
main(int argc, char **argv1)
{
    TSK_IMG_INFO *img = NULL;
    TSK_IMG_TYPE_ENUM imgtype = TSK_IMG_TYPE_DETECT;

    TSK_FS_INFO *fs = NULL;
    TSK_OFF_T imgaddr = 0;
    TSK_FS_FILE *jrnl_file = NULL;
    TSK_FS_TYPE_ENUM fstype = TSK_FS_TYPE_DETECT;

    int ch;
    TSK_INUM_T inum;
    TSK_TCHAR **argv;
    TSK_TCHAR *cp = NULL;
    unsigned int ssize = 0;
    TSK_FS_USNJLS_FLAG_ENUM flag = TSK_FS_USNJLS_NONE;

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

    while ((ch = GETOPT(argc, argv, _TSK_T("b:f:i:o:lmvV"))) > 0) {
        switch (ch) {
        case _TSK_T('?'): {
            default:
                TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
                         argv[OPTIND]);
                usage();
        }
        case _TSK_T('b'):
            ssize = (unsigned int) TSTRTOUL(OPTARG, &cp, 0);
            if (*cp || *cp == *OPTARG || ssize < 1) {
                TFPRINTF(stderr,
                         _TSK_T("invalid argument: sector size "
                                "must be positive: %s\n"),
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
        case _TSK_T('l'):
            flag = TSK_FS_USNJLS_LONG;
            break;
        case _TSK_T('m'):
            flag = TSK_FS_USNJLS_MAC;
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
        tsk_fprintf(stderr, "Missing image name and/or address\n");
        usage();
    }

    /* open image - there is an optional inode address at the end of args.
     *
     * Check the final argument and see if it is a number
     */
    if (tsk_fs_parse_inum(argv[argc - 1], &inum, NULL, NULL, NULL, NULL)) {
        img = tsk_img_open(argc - OPTIND, &argv[OPTIND], imgtype, ssize);
        if (img == NULL) {
            tsk_error_print(stderr);
            exit(1);
        }

        if ((imgaddr * img->sector_size) >= img->size) {
            tsk_fprintf(stderr,
                        "Sector offset is larger than disk image (maximum: %"
                        PRIu64 ")\n", img->size / img->sector_size);
            exit(1);
        }

        fs = tsk_fs_open_img(img, imgaddr * img->sector_size, fstype);
        if (fs == NULL) {
            tsk_error_print(stderr);

            if (tsk_error_get_errno() == TSK_ERR_FS_UNSUPTYPE) {
                tsk_fs_type_print(stderr);
            }

            img->close(img);
            exit(1);
        }

        jrnl_file = tsk_fs_file_open(fs, NULL, usnjrnl_path);
        if (jrnl_file == NULL) {
            tsk_fprintf(
                stderr,
                "Unable to open Journal %s, is this a NTFS filesystem?\n",
                usnjrnl_path);

            exit(1);
        }

        inum = jrnl_file->name->meta_addr;
        tsk_fs_file_close(jrnl_file);
    } else {
        img = tsk_img_open(argc - OPTIND - 1, &argv[OPTIND], imgtype, ssize);
        if (img == NULL) {
            tsk_error_print(stderr);
            exit(1);
        }

        if ((imgaddr * img->sector_size) >= img->size) {
            tsk_fprintf(stderr,
                        "Sector offset is larger than disk image (maximum: %"
                        PRIu64 ")\n", img->size / img->sector_size);
            exit(1);
        }

        fs = tsk_fs_open_img(img, imgaddr * img->sector_size, fstype);
        if (fs == NULL) {
            tsk_error_print(stderr);

            if (tsk_error_get_errno() == TSK_ERR_FS_UNSUPTYPE) {
                tsk_fs_type_print(stderr);
            }

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

    if (tsk_fs_usnjls(fs, inum, flag)) {
        tsk_error_print(stderr);
        fs->close(fs);
        img->close(img);
        exit(1);
    }

    fs->close(fs);
    img->close(img);
    exit(0);
}
