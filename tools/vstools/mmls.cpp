/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
 *
 * mmls - list media management structure contents
 *
 * This software is distributed under the Common Public License 1.0
 */
#include "tsk/tsk_tools_i.h"

static TSK_TCHAR *progname;

static uint8_t print_bytes = 0;
static uint8_t recurse = 0;

static int recurse_cnt = 0;
static TSK_DADDR_T recurse_list[64];

void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("%s [-i imgtype] [-b dev_sector_size] [-o imgoffset] [-BrvV] [-aAmM] [-t vstype] image [images]\n"),
        progname);
    tsk_fprintf(stderr,
        "\t-t vstype: The type of volume system (use '-t list' for list of supported types)\n");
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for list supported types)\n");
    tsk_fprintf(stderr,
        "\t-b dev_sector_size: The size (in bytes) of the device sectors\n");
    tsk_fprintf(stderr,
        "\t-o imgoffset: Offset to the start of the volume that contains the partition system (in sectors)\n");
    tsk_fprintf(stderr, "\t-B: print the rounded length in bytes\n");
    tsk_fprintf(stderr,
        "\t-r: recurse and look for other partition tables in partitions (DOS Only)\n");
    tsk_fprintf(stderr, "\t-v: verbose output\n");
    tsk_fprintf(stderr, "\t-V: print the version\n");
    tsk_fprintf(stderr,
        "Unless any of these are specified, all volume types are shown\n");
    tsk_fprintf(stderr, "\t-a: Show allocated volumes\n");
    tsk_fprintf(stderr, "\t-A: Show unallocated volumes\n");
    tsk_fprintf(stderr, "\t-m: Show metadata volumes\n");
    tsk_fprintf(stderr, "\t-M: Hide metadata volumes\n");
    exit(1);
}

/*
 * The callback action for the part_walk
 *
 * Prints the layout information
 * */
static TSK_WALK_RET_ENUM
part_act(TSK_VS_INFO * vs, const TSK_VS_PART_INFO * part, void *ptr)
{
    if (part->flags & TSK_VS_PART_FLAG_META)
        tsk_printf("%.3" PRIuPNUM ":  Meta      ", part->addr);

    /* Neither table or slot were given */
    else if ((part->table_num == -1) && (part->slot_num == -1))
        tsk_printf("%.3" PRIuPNUM ":  -------   ", part->addr);

    /* Table was not given, but slot was */
    else if ((part->table_num == -1) && (part->slot_num != -1))
        tsk_printf("%.3" PRIuPNUM ":  %.3" PRIu8 "       ",
            part->addr, part->slot_num);

    /* The Table was given, but slot wasn't */
    else if ((part->table_num != -1) && (part->slot_num == -1))
        tsk_printf("%.3" PRIuPNUM ":  -------   ", part->addr);

    /* Both table and slot were given */
    else if ((part->table_num != -1) && (part->slot_num != -1))
        tsk_printf("%.3" PRIuPNUM ":  %.3d:%.3d   ",
            part->addr, part->table_num, part->slot_num);

    if (print_bytes) {
        TSK_OFF_T size;
        char unit = 'B';
        size = part->len * part->vs->block_size;

        if (size > 1024) {
            size /= 1024;
            unit = 'K';
        }

        if (size > 1024) {
            size /= 1024;
            unit = 'M';
        }

        if (size > 1024) {
            size /= 1024;
            unit = 'G';
        }

        if (size > 1024) {
            size /= 1024;
            unit = 'T';
        }

        /* Print the layout */
        tsk_printf("%.10" PRIuDADDR "   %.10" PRIuDADDR "   %.10" PRIuDADDR
            "   %.4" PRIuOFF "%c   %s\n", part->start,
            (TSK_DADDR_T) (part->start + part->len - 1), part->len, size,
            unit, part->desc);
    }
    else {
        /* Print the layout */
        tsk_printf("%.10" PRIuDADDR "   %.10" PRIuDADDR "   %.10" PRIuDADDR
            "   %s\n", part->start,
            (TSK_DADDR_T) (part->start + part->len - 1), part->len,
            part->desc);
    }

    if ((recurse) && (vs->vstype == TSK_VS_TYPE_DOS)
        && (part->flags == TSK_VS_PART_FLAG_ALLOC)) {
        if (recurse_cnt < 64) {
            recurse_list[recurse_cnt++] = part->start * part->vs->block_size;
        }
    }

    return TSK_WALK_CONT;
}

static void
print_header(const TSK_VS_INFO * vs)
{
    tsk_printf("%s\n", tsk_vs_type_todesc(vs->vstype));
    tsk_printf("Offset Sector: %" PRIuDADDR "\n",
        (TSK_DADDR_T) (vs->offset / vs->block_size));
    tsk_printf("Units are in %d-byte sectors\n\n", vs->block_size);
    if (print_bytes)
        tsk_printf
            ("      Slot      Start        End          Length       Size    Description\n");
    else
        tsk_printf
            ("      Slot      Start        End          Length       Description\n");
}


int
main(int argc, char **argv1)
{
    TSK_VS_INFO *vs;
    int ch;
    TSK_OFF_T imgaddr = 0;
    int flags = 0;
    TSK_IMG_INFO *img;
    TSK_IMG_TYPE_ENUM imgtype = TSK_IMG_TYPE_DETECT;
    TSK_VS_TYPE_ENUM vstype = TSK_VS_TYPE_DETECT;
    uint8_t hide_meta = 0;
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

    while ((ch = GETOPT(argc, argv, _TSK_T("aAb:Bi:mMo:rt:vV"))) > 0) {
        switch (ch) {
        case _TSK_T('a'):
            flags |= TSK_VS_PART_FLAG_ALLOC;
            break;
        case _TSK_T('A'):
            flags |= TSK_VS_PART_FLAG_UNALLOC;
            break;
        case _TSK_T('B'):
            print_bytes = 1;
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
        case _TSK_T('m'):
            flags |= (TSK_VS_PART_FLAG_META);
            break;
        case _TSK_T('M'):
            // we'll set this after all flags have been set
            hide_meta = 1;
            break;
        case _TSK_T('o'):
            if ((imgaddr = tsk_parse_offset(OPTARG)) == -1) {
                tsk_error_print(stderr);
                exit(1);
            }
            break;
        case _TSK_T('r'):
            recurse = 1;
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
        case _TSK_T('v'):
            tsk_verbose++;
            break;
        case _TSK_T('V'):
            tsk_version_print(stdout);
            exit(0);
        case _TSK_T('?'):
        default:
            tsk_fprintf(stderr, "Unknown argument\n");
            usage();
        }
    }

    // if they want to hide metadata volumes, set that now
    if (hide_meta) {
        if (flags == 0)
            flags = (TSK_VS_PART_FLAG_ALLOC | TSK_VS_PART_FLAG_UNALLOC);
        else
            flags &= ~TSK_VS_PART_FLAG_META;
    }
    else if (flags == 0) {
        flags = TSK_VS_PART_FLAG_ALL;
    }

    /* We need at least one more argument */
    if (OPTIND >= argc) {
        tsk_fprintf(stderr, "Missing image name\n");
        usage();
    }

    /* open the image */
    img = tsk_img_open(argc - OPTIND, &argv[OPTIND], imgtype, ssize);

    if (img == NULL) {
        tsk_error_print(stderr);
        goto on_error;
    }
    if ((imgaddr * img->sector_size) >= img->size) {
        tsk_fprintf(stderr,
            "Sector offset supplied is larger than disk image (maximum: %"
            PRIu64 ")\n", img->size / img->sector_size);
        goto on_error;
    }

    /* process the partition tables */
    vs = tsk_vs_open(img, imgaddr * img->sector_size, vstype);
    if (vs == NULL) {
        tsk_error_print(stderr);
        if (tsk_error_get_errno() == TSK_ERR_VS_UNSUPTYPE)
            tsk_vs_type_print(stderr);
        goto on_error;
    }

    print_header(vs);

    if (tsk_vs_part_walk(vs, 0, vs->part_count - 1,
            (TSK_VS_PART_FLAG_ENUM) flags, part_act, NULL)) {
        tsk_error_print(stderr);
        tsk_vs_close(vs);
        goto on_error;
    }

    if ((recurse) && (vs->vstype == TSK_VS_TYPE_DOS)) {
        int i;
        /* disable recursing incase we hit another DOS partition
         * future versions may support more layers */
        recurse = 0;

        for (i = 0; i < recurse_cnt; i++) {
            TSK_VS_INFO *vs2;
            vs2 = tsk_vs_open(img, recurse_list[i], TSK_VS_TYPE_DETECT);
            if (vs2 != NULL) {
                tsk_printf("\n\n");
                print_header(vs2);
                if (tsk_vs_part_walk(vs2, 0, vs2->part_count - 1,
                        (TSK_VS_PART_FLAG_ENUM) flags, part_act, NULL)) {
                    tsk_error_reset();
                }
                tsk_vs_close(vs2);
            }
            else {
                /* Ignore error in this case and reset */
                tsk_error_reset();
            }
        }
    }
    // TODO: tsk error leaks here.
    // is the memory managed by pthread_setspecific(pt_tls_key, ...) freed?

    tsk_vs_close(vs);
    tsk_img_close(img);
    exit(0);

on_error:
    if( img != NULL ) {
        tsk_img_close( img );
    }
    exit( 1 );
}
