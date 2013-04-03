/*
** fcat 
** The Sleuth Kit 
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2012 Brian Carrier, Basis Technology.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**/

#include "tsk/tsk_tools_i.h"
#include <locale.h>

/* usage - explain and terminate */

static TSK_TCHAR *progname;

static void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-hRsvV] [-f fstype] [-i imgtype] [-b dev_sector_size] [-o imgoffset] file_path image [images]\n"),
        progname);
    tsk_fprintf(stderr, "\t-h: Do not display holes in sparse files\n");
    tsk_fprintf(stderr,
        "\t-R: Suppress recovery errors\n");
    tsk_fprintf(stderr, "\t-s: Display slack space at end of file\n");
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-b dev_sector_size: The size (in bytes) of the device sectors\n");
    tsk_fprintf(stderr,
        "\t-f fstype: File system type (use '-f list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-o imgoffset: The offset of the file system in the image (in sectors)\n");
    tsk_fprintf(stderr, "\t-v: verbose to stderr\n");
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

    TSK_INUM_T inum;
    int fw_flags = 0;
    int ch;
    int retval;
    int suppress_recover_error = 0;
    TSK_TCHAR **argv;
    TSK_TCHAR *cp;
    unsigned int ssize = 0;
    TSK_TCHAR *path = NULL;
    size_t len;

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

    while ((ch = GETOPT(argc, argv, _TSK_T("b:f:hi:o:rRsvV"))) > 0) {
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
        case _TSK_T('h'):
            fw_flags |= TSK_FS_FILE_WALK_FLAG_NOSPARSE;
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
        case _TSK_T('R'):
            suppress_recover_error = 1;
            break;
        case _TSK_T('s'):
            fw_flags |= TSK_FS_FILE_WALK_FLAG_SLACK;
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
        tsk_fprintf(stderr, "Missing image name and/or path\n");
        usage();
    }


    // copy in path
    len = (TSTRLEN(argv[OPTIND]) + 1) * sizeof(TSK_TCHAR);
    if ((path = (TSK_TCHAR *) tsk_malloc(len)) == NULL) {
        tsk_fprintf(stderr, "error allocating memory\n");
        exit(1);
    }
    TSTRNCPY(path, argv[OPTIND], TSTRLEN(argv[OPTIND]) + 1);

    if ((img =
            tsk_img_open(argc - OPTIND - 1, &argv[OPTIND+1],
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


    if (-1 == (retval = tsk_fs_ifind_path(fs, path, &inum))) {
        tsk_error_print(stderr);
        fs->close(fs);
        img->close(img);
        free(path);
        exit(1);
    }
    else if (retval == 1) {
        tsk_fprintf(stderr, "File not found\n");
        fs->close(fs);
        img->close(img);
        free(path);
        exit(1);
    }
    free(path); 

    // @@@ Cannot currently get ADS with this approach
    retval =
        tsk_fs_icat(fs, inum, (TSK_FS_ATTR_TYPE_ENUM)0, 0, 0, 0,
        (TSK_FS_FILE_WALK_FLAG_ENUM) fw_flags);
    if (retval) {
        if ((suppress_recover_error == 1)
            && (tsk_error_get_errno() == TSK_ERR_FS_RECOVER)) {
            tsk_error_reset();
        }
        else {
            tsk_error_print(stderr);
            fs->close(fs);
            img->close(img);
            exit(1);
        }
    }

    fs->close(fs);
    img->close(img);
    exit(0);
}
