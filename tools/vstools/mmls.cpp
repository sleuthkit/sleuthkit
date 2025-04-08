/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (C) 2024 Sleuth Kit Labs, LLC
 * Copyright (c) 2006-2023 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
 *
 * mmls - list media management structure contents
 *
 * This software is distributed under the Common Public License 1.0
 */
#include "tsk/tsk_tools_i.h"
#include "tools/util.h"

#include <memory>
#include <utility>
#include <variant>

void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("usage: mmls [-i imgtype] [-b dev_sector_size] [-o imgoffset] [-BcrvVh] [-aAmM] [-t vstype] image [images]\n"));
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
    tsk_fprintf(stderr, "\t-c: print CSV output\n");
    tsk_fprintf(stderr, "\t-v: verbose output\n");
    tsk_fprintf(stderr, "\t-V: print the version\n");
    tsk_fprintf(stderr, "\t-h: help. print this message\n");
    tsk_fprintf(stderr,
        "Unless any of these are specified, all volume types are shown\n");
    tsk_fprintf(stderr, "\t-a: Show allocated volumes\n");
    tsk_fprintf(stderr, "\t-A: Show unallocated volumes\n");
    tsk_fprintf(stderr, "\t-m: Show metadata volumes\n");
    tsk_fprintf(stderr, "\t-M: Hide metadata volumes\n");
}

struct WalkState {
  bool print_bytes = false;
  bool csv = false;
  bool recurse = false;
  int recurse_cnt = 0;
  TSK_DADDR_T recurse_list[64] = {0};
};

std::pair<TSK_OFF_T, char> size_with_unit(TSK_OFF_T size) {
    char unit = 'B';

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

    return { size, unit };
}

TSK_WALK_RET_ENUM
part_act_tabular(TSK_VS_INFO * vs, const TSK_VS_PART_INFO * part, void* ptr)
{
    WalkState* ws = static_cast<WalkState*>(ptr);

    if (part->flags & TSK_VS_PART_FLAG_META) {
        tsk_printf("%.3" PRIuPNUM ":  Meta      ", part->addr);
    }
    /* Neither table or slot were given */
    else if ((part->table_num == -1) && (part->slot_num == -1)) {
        tsk_printf("%.3" PRIuPNUM ":  -------   ", part->addr);
    }
    /* Table was not given, but slot was */
    else if ((part->table_num == -1) && (part->slot_num != -1)) {
        tsk_printf("%.3" PRIuPNUM ":  %.3" PRIu8 "       ",
            part->addr, part->slot_num);
    }
    /* The Table was given, but slot wasn't */
    else if ((part->table_num != -1) && (part->slot_num == -1)) {
        tsk_printf("%.3" PRIuPNUM ":  -------   ", part->addr);
    }
    /* Both table and slot were given */
    else if ((part->table_num != -1) && (part->slot_num != -1)) {
        tsk_printf("%.3" PRIuPNUM ":  %.3d:%.3d   ",
            part->addr, part->table_num, part->slot_num);
    }

    if (ws->print_bytes) {
        const auto [size, unit] = size_with_unit(part->len * part->vs->block_size);

        /* Print the layout */
        tsk_printf("%.10" PRIuDADDR "   %.10" PRIuDADDR "   %.10" PRIuDADDR
            "   %.4" PRIdOFF "%c   %s\n", part->start,
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

    if (ws->recurse && vs->vstype == TSK_VS_TYPE_DOS
        && part->flags == TSK_VS_PART_FLAG_ALLOC) {
        if (ws->recurse_cnt < 64) {
            ws->recurse_list[ws->recurse_cnt++] = part->start * part->vs->block_size;
        }
    }

    return TSK_WALK_CONT;
}

/*
 * The callback action for the part_walk
 *
 * Prints the layout information
 */
static TSK_WALK_RET_ENUM
part_act_csv(TSK_VS_INFO * vs, const TSK_VS_PART_INFO * part, void* ptr)
{
    WalkState* ws = static_cast<WalkState*>(ptr);

    const char delim = ',';

    if (part->flags & TSK_VS_PART_FLAG_META) {
        tsk_printf("%.3" PRIuPNUM "%c%s%c", part->addr, delim, "Meta", delim);
    }
    /* Neither table or slot were given */
    else if ((part->table_num == -1) && (part->slot_num == -1)) {
        tsk_printf("%.3" PRIuPNUM "%c%c", part->addr, delim, delim);
    }
    /* Table was not given, but slot was */
    else if ((part->table_num == -1) && (part->slot_num != -1)) {
        tsk_printf("%.3" PRIuPNUM "%c%.3" PRIu8 "%c",
            part->addr, delim, part->slot_num, delim);
    }
    /* The Table was given, but slot wasn't */
    else if ((part->table_num != -1) && (part->slot_num == -1)) {
        tsk_printf("%.3" PRIuPNUM "%c%c", part->addr, delim, delim);
    }
    /* Both table and slot were given */
    else if ((part->table_num != -1) && (part->slot_num != -1)) {
        tsk_printf("%.3" PRIuPNUM "%c%.3d:%.3d%c",
            part->addr, delim, part->table_num, part->slot_num, delim);
    }

    if (ws->print_bytes) {
        const auto [size, unit] = size_with_unit(part->len * part->vs->block_size);

        /* Print the layout */
        tsk_printf("%.10" PRIuDADDR "%c%.10" PRIuDADDR "%c%.10" PRIuDADDR
           "%c%.4" PRIdOFF "%c%c%s\n", part->start, delim,
           (TSK_DADDR_T) (part->start + part->len - 1), delim, part->len, delim, size,
           unit, delim, part->desc);
    }
    else {
        /* Print the layout */
        tsk_printf("%.10" PRIuDADDR "%c%.10" PRIuDADDR "%c%.10" PRIuDADDR
            "%c%s\n", part->start, delim,
            (TSK_DADDR_T) (part->start + part->len - 1), delim, part->len, delim,
            part->desc);
    }

    if (ws->recurse && vs->vstype == TSK_VS_TYPE_DOS
        && part->flags == TSK_VS_PART_FLAG_ALLOC) {
        if (ws->recurse_cnt < 64) {
            ws->recurse_list[ws->recurse_cnt++] = part->start * part->vs->block_size;
        }
    }

    return TSK_WALK_CONT;
}

void
print_header_tabular(const TSK_VS_INFO * vs, bool print_bytes)
{
    tsk_printf("%s\n", tsk_vs_type_todesc(vs->vstype));
    tsk_printf("Offset Sector: %" PRIuDADDR "\n",
        (TSK_DADDR_T) (vs->offset / vs->block_size));
    tsk_printf("Units are in %d-byte sectors\n\n", vs->block_size);

    if (print_bytes) {
        tsk_printf("      Slot      Start        End          Length       Size    Description\n");
    }
    else {
        tsk_printf("      Slot      Start        End          Length       Description\n");
    }
}

void
print_header_csv([[maybe_unused]] const TSK_VS_INFO * vs, bool print_bytes)
{
    if (print_bytes) {
        tsk_printf("ID,Slot,Start,End,Length,Size,Description\n");
    }
    else {
        tsk_printf("ID,Slot,Start,End,Length,Description\n");
    }
}

struct Options {
  int flags = 0;
  bool print_bytes = 0;
  unsigned int ssize = 0;
  TSK_OFF_T imgaddr = 0;
  TSK_IMG_TYPE_ENUM imgtype = TSK_IMG_TYPE_DETECT;
  TSK_VS_TYPE_ENUM vstype = TSK_VS_TYPE_DETECT;
  bool recurse = false;
  bool csv = false;
  unsigned int verbose = 0;
};

std::variant<Options, int> parse_args(int argc, TSK_TCHAR** argv) {
    Options opts;

    bool hide_meta = false;
    TSK_TCHAR *cp;
    int ch;

    while ((ch = GETOPT(argc, argv, _TSK_T("aAb:Bi:mMo:rt:cvVh"))) > 0) {
        switch (ch) {
        case _TSK_T('a'):
            opts.flags |= TSK_VS_PART_FLAG_ALLOC;
            break;
        case _TSK_T('A'):
            opts.flags |= TSK_VS_PART_FLAG_UNALLOC;
            break;
        case _TSK_T('B'):
            opts.print_bytes = true;
            break;
        case _TSK_T('b'):
            opts.ssize = (unsigned int) TSTRTOUL(OPTARG, &cp, 0);
            if (*cp || *cp == *OPTARG || opts.ssize < 1) {
                TFPRINTF(stderr,
                    _TSK_T
                    ("invalid argument: sector size must be positive: %" PRIttocTSK "\n"),
                    OPTARG);
                usage();
                return 1;
            }
            break;
        case _TSK_T('c'):
            opts.csv = true;
            break;
        case _TSK_T('h'):
          usage();
          return 1;
        case _TSK_T('i'):
            if (TSTRCMP(OPTARG, _TSK_T("list")) == 0) {
                tsk_img_type_print(stderr);
                return 1;
            }
            opts.imgtype = tsk_img_type_toid(OPTARG);
            if (opts.imgtype == TSK_IMG_TYPE_UNSUPP) {
                TFPRINTF(stderr, _TSK_T("Unsupported image type: %" PRIttocTSK "\n"),
                    OPTARG);
                usage();
                return 1;
            }
            break;
        case _TSK_T('m'):
            opts.flags |= (TSK_VS_PART_FLAG_META);
            break;
        case _TSK_T('M'):
            // we'll set this after all flags have been set
            hide_meta = true;
            break;
        case _TSK_T('o'):
            if ((opts.imgaddr = tsk_parse_offset(OPTARG)) == -1) {
                tsk_error_print(stderr);
                return 1;
            }
            break;
        case _TSK_T('r'):
            opts.recurse = true;
            break;
        case _TSK_T('t'):
            if (TSTRCMP(OPTARG, _TSK_T("list")) == 0) {
                tsk_vs_type_print(stderr);
                return 1;
            }
            opts.vstype = tsk_vs_type_toid(OPTARG);
            if (opts.vstype == TSK_VS_TYPE_UNSUPP) {
                TFPRINTF(stderr,
                    _TSK_T("Unsupported volume system type: %" PRIttocTSK "\n"),
                    OPTARG);
                usage();
                return 1;
            }
            break;
        case _TSK_T('v'):
            opts.verbose++;
            break;
        case _TSK_T('V'):
            tsk_version_print(stdout);
            return 0;
        case _TSK_T('?'):
        default:
            tsk_fprintf(stderr, "Unknown argument\n");
            usage();
            return 1;
        }
    }

    // if they want to hide metadata volumes, set that now
    if (hide_meta) {
        if (opts.flags == 0) {
            opts.flags = (TSK_VS_PART_FLAG_ALLOC | TSK_VS_PART_FLAG_UNALLOC);
        }
        else {
            opts.flags &= ~TSK_VS_PART_FLAG_META;
        }
    }
    else if (opts.flags == 0) {
        opts.flags = TSK_VS_PART_FLAG_ALL;
    }

    /* We need at least one more argument */
    if (OPTIND >= argc) {
        tsk_fprintf(stderr, "Missing image name\n");
        usage();
        return 1;
    }

    return opts;
}

int do_it(
  const Options& opts,
  const TSK_TCHAR* const* img_paths,
  size_t img_paths_len)
{
    auto [
      flags,
      print_bytes,
      ssize,
      imgaddr,
      imgtype,
      vstype,
      recurse,
      is_csv,
      _ // verbose
    ] = opts;

    tsk_verbose = opts.verbose;

    /* open the image */
    std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
        tsk_img_open(img_paths_len, img_paths, imgtype, ssize),
        tsk_img_close
    };

    if (!img) {
        tsk_error_print(stderr);
        return 1;
    }

    if ((imgaddr * img->sector_size) >= img->size) {
        tsk_fprintf(stderr,
            "Sector offset supplied is larger than disk image (maximum: %"
            PRIu64 ")\n", img->size / img->sector_size);
        return 1;
    }

    /* process the partition tables */
    std::unique_ptr<TSK_VS_INFO, decltype(&tsk_vs_close)> vs{
        tsk_vs_open(img.get(), imgaddr * img->sector_size, vstype),
        tsk_vs_close
    };

    if (!vs) {
        tsk_error_print(stderr);
        if (tsk_error_get_errno() == TSK_ERR_VS_UNSUPTYPE)
            tsk_vs_type_print(stderr);
        return 1;
    }

    const auto print_header = is_csv ? print_header_csv : print_header_tabular;
    const auto part_act = is_csv ? part_act_csv : part_act_tabular;

    print_header(vs.get(), print_bytes);

    WalkState ws{print_bytes, is_csv, recurse};
    if (tsk_vs_part_walk(vs.get(), 0, vs->part_count - 1,
            (TSK_VS_PART_FLAG_ENUM) flags, part_act, &ws)) {
        tsk_error_print(stderr);
        return 1;
    }

    if (ws.recurse && vs->vstype == TSK_VS_TYPE_DOS) {
        /* disable recursing incase we hit another DOS partition
         * future versions may support more layers */
        ws.recurse = false;

        for (int i = 0; i < ws.recurse_cnt; i++) {
            std::unique_ptr<TSK_VS_INFO, decltype(&tsk_vs_close)> vs2{
                tsk_vs_open(img.get(), ws.recurse_list[i], TSK_VS_TYPE_DETECT),
                tsk_vs_close
            };
            if (vs2) {
                tsk_printf("\n\n");
                print_header(vs2.get(), print_bytes);
                if (tsk_vs_part_walk(vs2.get(), 0, vs2->part_count - 1,
                        (TSK_VS_PART_FLAG_ENUM) flags, part_act, &ws)) {
                    tsk_error_reset();
                }
            }
            else {
                /* Ignore error in this case and reset */
                tsk_error_reset();
            }
        }
    }
    // TODO: tsk error leaks here.
    // is the memory managed by pthread_setspecific(pt_tls_key, ...) freed?

    return 0;
}

int
main(int argc1, char **argv1)
{
    auto [argv, argc] = argv_to_tsk_tchar(argc1, argv1);

    const auto p = parse_args(argc, argv.get());
    if (const int* ret = std::get_if<int>(&p)) {
      return *ret;
    }

    const auto& opts = std::get<Options>(p);
    return do_it(opts, &argv[OPTIND], argc - OPTIND);
}
