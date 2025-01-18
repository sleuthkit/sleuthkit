/*
** fls
** The Sleuth Kit
**
** Given an image and directory inode, display the file names and
** directories that exist (both active and deleted)
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carier.  All rights reserved
**
** TASK
** Copyright (c) 2002 @stake Inc.  All rights reserved
**
** TCTUTILs
** Copyright (c) 2001 Brian Carrier.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/
#include "tsk/tsk_tools_i.h"
#include "tsk/base/tsk_os_cpp.h"
#include "tsk/fs/apfs_fs.h"
#include "tools/util.h"

#include <locale.h>
#include <time.h>

#include <memory>
#include <optional>
#include <string>
#include <variant>

void
usage()
{
    tsk_fprintf(stderr,
        "usage: fls [-adDFlhpruvV] [-f fstype] [-i imgtype] [-b dev_sector_size] [-m dir/] [-o imgoffset] [-z ZONE] [-s seconds] image [images] [inode]\n");
    tsk_fprintf(stderr,
        "\tIf [inode] is not given, the root directory is used\n");
    tsk_fprintf(stderr, "\t-a: Display \".\" and \"..\" entries\n");
    tsk_fprintf(stderr, "\t-d: Display deleted entries only\n");
    tsk_fprintf(stderr, "\t-D: Display only directories\n");
    tsk_fprintf(stderr, "\t-F: Display only files\n");
    tsk_fprintf(stderr, "\t-l: Display long version (like ls -l)\n");
    tsk_fprintf(stderr,
        "\t-i imgtype: Format of image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-b dev_sector_size: The size (in bytes) of the device sectors\n");
    tsk_fprintf(stderr,
        "\t-f fstype: File system type (use '-f list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-m: Display output in mactime input format with\n");
    tsk_fprintf(stderr,
        "\t      dir/ as the actual mount point of the image\n");
    tsk_fprintf(stderr, "\t-h: Include MD5 checksum hash in mactime output\n");
    tsk_fprintf(stderr,
        "\t-o imgoffset: Offset into image file (in sectors)\n");
    tsk_fprintf(stderr,
        "\t-P pooltype: Pool container type (use '-P list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-B pool_volume_block: Starting block (for pool volumes only)\n");
    tsk_fprintf(stderr, "\t-S snap_id: Snapshot ID (for APFS only)\n");
    tsk_fprintf(stderr, "\t-p: Display full path for each file\n");
    tsk_fprintf(stderr, "\t-r: Recurse on directory entries\n");
    tsk_fprintf(stderr, "\t-u: Display undeleted entries only\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Print version\n");
    tsk_fprintf(stderr,
        "\t-z: Time zone of original machine (i.e. EST5EDT or GMT) (only useful with -l)\n");
    tsk_fprintf(stderr,
        "\t-s seconds: Time skew of original machine (in seconds) (only useful with -l & -m)\n");
    tsk_fprintf(stderr, "\t-k password: Decryption password for encrypted volumes\n");
}

struct Options {
    int fls_flags = TSK_FS_FLS_DIR | TSK_FS_FLS_FILE;;
    int name_flags = TSK_FS_DIR_WALK_FLAG_ALLOC | TSK_FS_DIR_WALK_FLAG_UNALLOC;
    unsigned int ssize = 0;
    TSK_OFF_T imgaddr = 0;
    TSK_IMG_TYPE_ENUM imgtype = TSK_IMG_TYPE_DETECT;
    TSK_POOL_TYPE_ENUM pooltype = TSK_POOL_TYPE_DETECT;
    TSK_FS_TYPE_ENUM fstype = TSK_FS_TYPE_DETECT;
    TSK_OFF_T pvol_block = 0;
    TSK_OFF_T snap_id = 0;
    int32_t sec_skew = 0;
    const char* password = "";
    std::optional<TSK_TSTRING> macpre;
    unsigned int verbose = 0;
};

std::variant<Options, int> parse_args(int argc, TSK_TCHAR** argv, char** argv1) {
    Options opts;

    TSK_TCHAR *cp;
    int ch;

    while ((ch =
            GETOPT(argc, argv, _TSK_T("ab:dDf:Fi:m:hlo:prs:uvVz:P:B:k:S:"))) > 0) {
        switch (ch) {
        case _TSK_T('?'):
        default:
            TFPRINTF(stderr, _TSK_T("Invalid argument: %" PRIttocTSK "\n"),
                argv[OPTIND]);
            usage();
            return 1;
        case _TSK_T('a'):
            opts.fls_flags |= TSK_FS_FLS_DOT;
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
        case _TSK_T('d'):
            opts.name_flags &= ~TSK_FS_DIR_WALK_FLAG_ALLOC;
            break;
        case _TSK_T('D'):
            opts.fls_flags &= ~TSK_FS_FLS_FILE;
            opts.fls_flags |= TSK_FS_FLS_DIR;
            break;
        case _TSK_T('f'):
            if (TSTRCMP(OPTARG, _TSK_T("list")) == 0) {
                tsk_fs_type_print(stderr);
                return 1;
            }
            opts.fstype = tsk_fs_type_toid(OPTARG);
            if (opts.fstype == TSK_FS_TYPE_UNSUPP) {
                TFPRINTF(stderr,
                    _TSK_T("Unsupported file system type: %" PRIttocTSK "\n"), OPTARG);
                usage();
                return 1;
            }
            break;
        case _TSK_T('F'):
            opts.fls_flags &= ~TSK_FS_FLS_DIR;
            opts.fls_flags |= TSK_FS_FLS_FILE;
            break;
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
        case _TSK_T('l'):
            opts.fls_flags |= TSK_FS_FLS_LONG;
            break;
        case _TSK_T('m'):
            opts.fls_flags |= TSK_FS_FLS_MAC;
            opts.macpre = OPTARG;
            break;
        case _TSK_T('h'):
            opts.fls_flags |= TSK_FS_FLS_HASH;
            break;
        case _TSK_T('o'):
            if ((opts.imgaddr = tsk_parse_offset(OPTARG)) == -1) {
                tsk_error_print(stderr);
                return 1;
            }
            break;
        case _TSK_T('P'):
            if (TSTRCMP(OPTARG, _TSK_T("list")) == 0) {
                tsk_pool_type_print(stderr);
                return 1;
            }
            opts.pooltype = tsk_pool_type_toid(OPTARG);
            if (opts.pooltype == TSK_POOL_TYPE_UNSUPP) {
                TFPRINTF(stderr,
                    _TSK_T("Unsupported pool container type: %" PRIttocTSK "\n"), OPTARG);
                usage();
                return 1;
            }
            break;
        case _TSK_T('B'):
            if ((opts.pvol_block = tsk_parse_offset(OPTARG)) == -1) {
                tsk_error_print(stderr);
                return 1;
            }
            break;
        case _TSK_T('S'):
            if ((opts.snap_id = tsk_parse_offset(OPTARG)) == -1) {
                tsk_error_print(stderr);
                return 1;
            }
            break;
        case _TSK_T('p'):
            opts.fls_flags |= TSK_FS_FLS_FULL;
            break;
        case _TSK_T('k'):
            opts.password = argv1[OPTIND - 1];
            break;
        case _TSK_T('r'):
            opts.name_flags |= TSK_FS_DIR_WALK_FLAG_RECURSE;
            break;
        case _TSK_T('s'):
            opts.sec_skew = TATOI(OPTARG);
            break;
        case _TSK_T('u'):
            opts.name_flags &= ~TSK_FS_DIR_WALK_FLAG_UNALLOC;
            break;
        case _TSK_T('v'):
            opts.verbose++;
            break;
        case _TSK_T('V'):
            tsk_version_print(stdout);
            return 0;
        case 'z':
            {
                TSK_TCHAR envstr[32];
                TSNPRINTF(envstr, 32, _TSK_T("TZ=%s"), OPTARG);
                if (0 != TPUTENV(envstr)) {
                    tsk_fprintf(stderr, "error setting environment");
                    return 1;
                }

                /* we should be checking this somehow */
                TZSET();
            }
            break;
        }
    }

    /* We need at least one more argument */
    if (OPTIND == argc) {
        tsk_fprintf(stderr, "Missing image name\n");
        usage();
        return 1;
    }

    /* Set the full flag to print the full path name if recursion is
     ** set and we are only displaying files or deleted files
     */
    if ((opts.name_flags & TSK_FS_DIR_WALK_FLAG_RECURSE)
        && (((opts.name_flags & TSK_FS_DIR_WALK_FLAG_UNALLOC)
                && !(opts.name_flags & TSK_FS_DIR_WALK_FLAG_ALLOC))
            || ((opts.fls_flags & TSK_FS_FLS_FILE)
                && !(opts.fls_flags & TSK_FS_FLS_DIR)))) {

        opts.fls_flags |= TSK_FS_FLS_FULL;
    }

    /* set flag to save full path for mactimes style printing */
    if (opts.fls_flags & TSK_FS_FLS_MAC) {
        opts.fls_flags |= TSK_FS_FLS_FULL;
    }

    /* we need to append a / to the end of the directory if
     * one does not already exist
     */
    if (opts.macpre && opts.macpre->back() != _TSK_T('/')) {
        *opts.macpre += _TSK_T("/");
    }

    return opts;
}

struct Holder {
    std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img_parent;
    std::unique_ptr<const TSK_POOL_INFO, decltype(&tsk_pool_close)> pool;
    std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img;
    std::unique_ptr<TSK_FS_INFO, decltype(&tsk_fs_close)> fs;
    TSK_INUM_T inode;
};

std::variant<Holder, int>
open_handles(const Options& opts, const TSK_TCHAR* const* argv, size_t argc) {
    auto [
      fls_flags,
      name_flags,
      ssize,
      imgaddr,
      imgtype,
      pooltype,
      fstype,
      pvol_block,
      _snap_id,
      _sec_skew,
      password,
      _macpre,
      _verbose
    ] = opts;

    std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img_parent{
      nullptr, tsk_img_close
    };

    std::unique_ptr<const TSK_POOL_INFO, decltype(&tsk_pool_close)> pool{
      nullptr, tsk_pool_close
    };

    std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
      nullptr, tsk_img_close
    };

    std::unique_ptr<TSK_FS_INFO, decltype(&tsk_fs_close)> fs{
      nullptr, tsk_fs_close
    };

    bool had_inum_arg = false;
    TSK_INUM_T inode;

    /* open image - there is an optional inode address at the end of args
     *
     * Check the final argument and see if it is a number
     */
    if (tsk_fs_parse_inum(argv[argc - 1], &inode, NULL, NULL, NULL, NULL)) {
        /* Not an inode at the end */
        img.reset(tsk_img_open(argc, argv, imgtype, ssize));
    }
    else {
        // check that we have enough arguments
        if (argc == 1) {
            tsk_fprintf(stderr, "Missing image name or inode\n");
            usage();
            return 1;
        }

        img.reset(tsk_img_open(argc - 1, argv, imgtype, ssize));
        had_inum_arg = true;
    }

    if (!img) {
        tsk_error_print(stderr);
        return 1;
    }

    if (imgaddr * img->sector_size >= img->size) {
        tsk_fprintf(stderr,
            "Sector offset supplied is larger than disk image (maximum: %"
             PRIu64 ")\n", img->size / img->sector_size);
        return 1;
    }

    if (pvol_block == 0) {
        fs.reset(tsk_fs_open_img_decrypt(img.get(), imgaddr * img->sector_size, fstype, password));
        if (!fs) {
            tsk_error_print(stderr);
            if (tsk_error_get_errno() == TSK_ERR_FS_UNSUPTYPE) {
                tsk_fs_type_print(stderr);
            }
            return 1;
        }
    }
    else {
        // Pool block was specified, so open pool
        pool.reset(tsk_pool_open_img_sing(img.get(), imgaddr * img->sector_size, pooltype));
        if (!pool) {
            tsk_error_print(stderr);
            if (tsk_error_get_errno() == TSK_ERR_FS_UNSUPTYPE) {
                tsk_pool_type_print(stderr);
            }
            return 1;
        }

        img_parent = std::move(img);

        TSK_OFF_T offset = imgaddr * img->sector_size;
#if HAVE_LIBVSLVM
        if (pool->ctype == TSK_POOL_TYPE_LVM){
            offset = 0;
        }
#endif /* HAVE_LIBVSLVM */
        img.reset(pool->get_img_info(pool.get(), (TSK_DADDR_T)pvol_block));
        fs.reset(tsk_fs_open_img_decrypt(img.get(), offset, fstype, password));
        if (!fs) {
            tsk_error_print(stderr);
            if (tsk_error_get_errno() == TSK_ERR_FS_UNSUPTYPE) {
                tsk_fs_type_print(stderr);
            }
            return 1;
        }
    }

    if (!had_inum_arg) {
      inode = fs->root_inum;
    }

    return Holder{
        std::move(img_parent),
        std::move(pool),
        std::move(img),
        std::move(fs),
        inode
    };
}

int do_it(TSK_FS_INFO* fs, uint64_t snap_id, int fls_flags, TSK_INUM_T inode, int name_flags, const TSK_TCHAR* macpre, int32_t sec_skew) {
    if (snap_id > 0) {
        tsk_apfs_set_snapshot(fs, snap_id);
    }

    if (tsk_fs_fls(fs, (TSK_FS_FLS_FLAG_ENUM) fls_flags, inode,
            (TSK_FS_DIR_WALK_FLAG_ENUM) name_flags, macpre, sec_skew)) {
        tsk_error_print(stderr);
        return 1;
    }

    return 0;
}

int
main(int argc1, char **argv1)
{
    auto [argv, argc] = argv_to_tsk_tchar(argc1, argv1);

    setlocale(LC_ALL, "");

    const auto p = parse_args(argc, argv.get(), argv1);
    if (const int* ret = std::get_if<int>(&p)) {
      return *ret;
    }
    const auto& opts = std::get<Options>(p);

    tsk_verbose = opts.verbose;

    auto r = open_handles(opts, &argv[OPTIND], argc - OPTIND);
    if (const int* ret = std::get_if<int>(&r)) {
      return *ret;
    }
    auto& h = std::get<Holder>(r);

    return do_it(
        h.fs.get(),
        opts.snap_id,
        opts.fls_flags,
        h.inode,
        opts.name_flags,
        opts.macpre ? opts.macpre->c_str() : nullptr,
        opts.sec_skew
    );
}
