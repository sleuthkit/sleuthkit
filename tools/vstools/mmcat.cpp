/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2008-2011 Brian Carrier.  All rights reserved
 *
 * Output the contents of a partition
 *
 * This software is distributed under the Common Public License 1.0
 */

#include "tsk/tsk_tools_i.h"

#ifdef TSK_WIN32
#include <fcntl.h>
#endif

static TSK_TCHAR *progname;

void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("%s [-i imgtype] [-b dev_sector_size] [-o imgoffset] [-vV] [-t vstype] image [images] part_num\n"),
        progname);
    tsk_fprintf(stderr,
        "\t-t vstype: The type of partition system (use '-t list' for list of supported types)\n");
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for list of supported types)\n");
    tsk_fprintf(stderr,
        "\t-b dev_sector_size: The size (in bytes) of the device sectors\n");
    tsk_fprintf(stderr,
        "\t-o imgoffset: Offset to the start of the volume that contains the partition system (in sectors)\n");
    tsk_fprintf(stderr, "\t-v: verbose output\n");
    tsk_fprintf(stderr, "\t-V: print the version\n");
    exit(1);
}


int
main(int argc, char **argv1)
{
    TSK_VS_INFO *vs;
    TSK_IMG_TYPE_ENUM imgtype = TSK_IMG_TYPE_DETECT;
    TSK_VS_TYPE_ENUM vstype = TSK_VS_TYPE_DETECT;
    int ch;
    TSK_OFF_T imgaddr = 0;
    TSK_IMG_INFO *img;
    TSK_PNUM_T pnum;
    TSK_DADDR_T addr;
    const TSK_VS_PART_INFO *vs_part;
    char *buf;
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

    while ((ch = GETOPT(argc, argv, _TSK_T("b:i:o:t:vV"))) > 0) {
        switch (ch) {
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
        case _TSK_T('t'):
            if (TSTRCMP(OPTARG, _TSK_T("list")) == 0) {
                tsk_vs_type_print(stderr);
                exit(1);
            }
            vstype = tsk_vs_type_toid(OPTARG);
            if (vstype == TSK_VS_TYPE_UNSUPP) {
                TFPRINTF(stderr,
                    _TSK_T("Unsupported volume system type: %s\n"),
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
        case '?':
        default:
            tsk_fprintf(stderr, "Unknown argument\n");
            usage();
        }
    }

    /* We need at least two more arguments */
    if (OPTIND + 1 >= argc) {
        tsk_fprintf(stderr,
            "Missing image name and/or partition number\n");
        usage();
    }

    /* open the image */
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

    if (tsk_parse_pnum(argv[argc - 1], &pnum)) {
        tsk_error_print(stderr);
        exit(1);
    }

    /* process the partition tables */
    if ((vs = tsk_vs_open(img, imgaddr * img->sector_size, vstype)) == NULL) {
        tsk_error_print(stderr);
        if (tsk_error_get_errno() == TSK_ERR_VS_UNSUPTYPE)
            tsk_vs_type_print(stderr);

        exit(1);
    }

    if (pnum >= vs->part_count) {
        tsk_fprintf(stderr,
            "Partition address is too large (maximum: %"
            PRIuPNUM ")\n", vs->part_count);
        exit(1);
    }

    vs_part = tsk_vs_part_get(vs, pnum);
    if (vs_part == NULL) {
        tsk_fprintf(stderr, "Error looking up partition\n");
        exit(1);
    }

    buf = (char *) malloc(vs->block_size);
    if (buf == NULL) {
        tsk_error_print(stderr);
        exit(1);
    }

#ifdef TSK_WIN32
    if (-1 == _setmode(_fileno(stdout), _O_BINARY)) {
        fprintf(stderr,
                "error setting stdout to binary: %s", strerror(errno));
        exit(1);
    }
#endif

    for (addr = 0; addr < vs_part->len; addr++) {
        ssize_t retval;
        retval =
            tsk_vs_part_read_block(vs_part, addr, buf, vs->block_size);
        if (retval == -1) {
            tsk_error_print(stderr);
            exit(1);
        }

        if ((size_t) retval != fwrite(buf, 1, retval, stdout)) {
            tsk_fprintf(stderr, "Error writing data to stdout\n");
            exit(1);
        }
    }

    tsk_vs_close(vs);
    tsk_img_close(img);
    exit(0);
}
