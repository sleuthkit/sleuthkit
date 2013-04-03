/*
** blkcat
** The  Sleuth Kit 
**
** Given an image , block number, and size, display the contents
** of the block to stdout.
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

#define BLKLS_TYPE _TSK_T("blkls")
#define RAW_STR "raw"

static TSK_TCHAR *progname;

void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-ahsvVw] [-f fstype] [-i imgtype] [-b dev_sector_size] [-o imgoffset] [-u usize] image [images] unit_addr [num]\n"),
        progname);
    tsk_fprintf(stderr, "\t-a: displays in all ASCII \n");
    tsk_fprintf(stderr, "\t-h: displays in hexdump-like fashion\n");
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-b dev_sector_size: The size (in bytes) of the device sectors\n");
    tsk_fprintf(stderr,
        "\t-o imgoffset: The offset of the file system in the image (in sectors)\n");
    tsk_fprintf(stderr,
        "\t-f fstype: File system type (use '-f list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-s: display basic block stats such as unit size, fragments, etc.\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: display version\n");
    tsk_fprintf(stderr, "\t-w: displays in web-like (html) fashion\n");
    tsk_fprintf(stderr,
        "\t-u usize: size of each data unit in image (for raw, blkls, swap)\n");
    tsk_fprintf(stderr,
        "\t[num] is the number of data units to display (default is 1)\n");

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

    TSK_DADDR_T addr = 0;
    TSK_TCHAR *cp;
    TSK_DADDR_T read_num_units; /* Number of data units */
    int usize = 0;              /* Length of each data unit */
    int ch;
    char format = 0;
    extern int OPTIND;
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

    while ((ch = GETOPT(argc, argv, _TSK_T("ab:f:hi:o:su:vVw"))) > 0) {
        switch (ch) {
        case _TSK_T('a'):
            format |= TSK_FS_BLKCAT_ASCII;
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
        case _TSK_T('f'):
            if (TSTRCMP(OPTARG, BLKLS_TYPE) == 0) {
                fstype = TSK_FS_TYPE_RAW;
            }
            else if (TSTRCMP(OPTARG, _TSK_T("list")) == 0) {
                tsk_fprintf(stderr,
                    "\t%" PRIttocTSK " (Unallocated Space)\n", BLKLS_TYPE);
                tsk_fs_type_print(stderr);
                exit(1);
            }
            else {
                fstype = tsk_fs_type_toid(OPTARG);
            }
            if (fstype == TSK_FS_TYPE_UNSUPP) {
                TFPRINTF(stderr,
                    _TSK_T("Unsupported file system type: %s\n"), OPTARG);
                usage();
            }
            break;
        case _TSK_T('h'):
            format |= TSK_FS_BLKCAT_HEX;
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
            format |= TSK_FS_BLKCAT_STAT;
            break;
        case _TSK_T('u'):
            usize = TSTRTOUL(OPTARG, &cp, 0);
            if (*cp || cp == OPTARG) {
                TFPRINTF(stderr, _TSK_T("Invalid block size: %s\n"),
                    OPTARG);
                usage();
            }
            break;
        case _TSK_T('v'):
            tsk_verbose++;
            break;
        case _TSK_T('V'):
            tsk_version_print(stdout);
            exit(0);
            break;
        case _TSK_T('w'):
            format |= TSK_FS_BLKCAT_HTML;
            break;
        case _TSK_T('?'):
        default:
            TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
                argv[OPTIND]);
            usage();
        }
    }

    if (format & TSK_FS_BLKCAT_STAT) {
        if (OPTIND == argc)
            usage();

        if (format & (TSK_FS_BLKCAT_HTML | TSK_FS_BLKCAT_ASCII |
                TSK_FS_BLKCAT_HEX)) {
            tsk_fprintf(stderr,
                "NOTE: Additional flags will be ignored\n");
        }
    }
    /* We need at least two more arguments */
    else if (OPTIND + 1 >= argc) {
        tsk_fprintf(stderr, "Missing image name and/or address\n");
        usage();
    }

    if ((format & TSK_FS_BLKCAT_ASCII) && (format & TSK_FS_BLKCAT_HEX)) {
        tsk_fprintf(stderr,
            "Ascii and Hex flags can not be used together\n");
        usage();
    }

    /* We need to figure out if there is a length argument... */
    /* Check out the second argument from the end */

    /* default number of units is 1 */
    read_num_units = 1;

    /* Get the block address */
    if (format & TSK_FS_BLKCAT_STAT) {
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
        addr = TSTRTOULL(argv[argc - 2], &cp, 0);
        if (*cp || *cp == *argv[argc - 2]) {

            /* Not a number, so it is the image name and we do not have a length */
            addr = TSTRTOULL(argv[argc - 1], &cp, 0);
            if (*cp || *cp == *argv[argc - 1]) {
                TFPRINTF(stderr, _TSK_T("Invalid block address: %s\n"),
                    argv[argc - 1]);
                usage();
            }

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
        else {
            /* We got a number, so take the length as well while we are at it */
            read_num_units = TSTRTOULL(argv[argc - 1], &cp, 0);
            if (*cp || *cp == *argv[argc - 1]) {
                TFPRINTF(stderr, _TSK_T("Invalid size: %s\n"),
                    argv[argc - 1]);
                usage();
            }
            else if (read_num_units <= 0) {
                tsk_fprintf(stderr, "Invalid size: %" PRIuDADDR "\n",
                    read_num_units);
                usage();
            }

            if ((img =
                    tsk_img_open(argc - OPTIND - 2, &argv[OPTIND],
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

    /* open the file */
    if ((fs = tsk_fs_open_img(img, imgaddr * img->sector_size, fstype)) == NULL) {
        tsk_error_print(stderr);
        if (tsk_error_get_errno() == TSK_ERR_FS_UNSUPTYPE)
            tsk_fs_type_print(stderr);
        img->close(img);
        exit(1);
    }


    /* Set the default size if given */
    if ((usize != 0) &&
        (TSK_FS_TYPE_ISRAW(fs->ftype) || TSK_FS_TYPE_ISSWAP(fs->ftype))) {
        TSK_DADDR_T sectors;
        int orig_dsize, new_dsize;

        if (usize % 512) {
            tsk_fprintf(stderr,
                "New data unit size not a multiple of 512 (%d)\n", usize);
            usage();
        }

        /* We need to do some math to update the block_count value */

        /* Get the original number of sectors */
        orig_dsize = fs->block_size / 512;
        sectors = fs->block_count * orig_dsize;

        /* Convert that to the new size */
        new_dsize = usize / 512;
        fs->block_count = sectors / new_dsize;
        if (sectors % new_dsize)
            fs->block_count++;
        fs->last_block = fs->block_count - 1;

        fs->block_size = usize;
    }

    if (addr > fs->last_block) {
        tsk_fprintf(stderr,
            "Data unit address too large for image (%" PRIuDADDR ")\n",
            fs->last_block);
        fs->close(fs);
        img->close(img);
        exit(1);
    }
    if (addr < fs->first_block) {
        tsk_fprintf(stderr,
            "Data unit address too small for image (%" PRIuDADDR ")\n",
            fs->first_block);
        fs->close(fs);
        img->close(img);
        exit(1);
    }

    if (tsk_fs_blkcat(fs, (TSK_FS_BLKCAT_FLAG_ENUM) format, addr,
            read_num_units)) {
        tsk_error_print(stderr);
        fs->close(fs);
        img->close(img);
        exit(1);
    }

    fs->close(fs);
    img->close(img);

    exit(0);
}
