

#include "tsk3/tsk_tools_i.h"
#include "tsk_recover.h"
#include <locale.h>

static TSK_TCHAR *progname;

static void
usage()
{
    // @@@ UPDATE ME
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-tvV] [-f fstype] [-i imgtype] [-b dev_sector_size] [-o imgoffset] image\n"),
        progname);
    tsk_fprintf(stderr, "\t-t: display type only\n");
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-b dev_sector_size: The size (in bytes) of the device sectors\n");
    tsk_fprintf(stderr,
        "\t-f fstype: File system type (use '-f list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-o imgoffset: The offset of the file system in the image (in sectors)\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Print version\n");

    exit(1);
}


TskRecover::TskRecover(TSK_TCHAR *a_base_dir)
{
    m_base_dir = a_base_dir;
}

uint8_t 
TskRecover::writeFile(TSK_FS_FILE *a_fs_file, const char *a_path)
{
    printf ("Got File %s%s (%"PRIuINUM")\n", a_path, a_fs_file->name->name, a_fs_file->name->meta_addr);
    return 0;
}


uint8_t 
TskRecover::processFile(TSK_FS_FILE * fs_file, const char *path)
{
    if (isDotDir(fs_file, path))
        return 0;
    
    if (isDir(fs_file))
        return 0;
    
    if (isNtfsSystemFiles(fs_file, path))
        return 0;
    
    writeFile(fs_file, path);
    
    return 0;
}


int
main(int argc, char **argv1)
{
    TSK_IMG_TYPE_ENUM imgtype = TSK_IMG_TYPE_DETECT;

    int ch;
    uint8_t type = 0;
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

    while ((ch = GETOPT(argc, argv, _TSK_T("b:f:i:o:tvV"))) > 0) {
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


        case _TSK_T('t'):
            type = 1;
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
    
    TskRecover tskRecover(_TSK_T(""));
    
    tskRecover.setFileFilterFlags(TSK_FS_DIR_WALK_FLAG_UNALLOC);
    if (tskRecover.openImage(argc - OPTIND,  &argv[OPTIND], imgtype,
                      ssize)) {
        tsk_error_print(stderr);
        exit(1);
    }
    if (tskRecover.findFilesInImg()) {
        tsk_error_print(stderr);
        exit(1);
    }
    
#if 0
    if ((imgaddr * img->sector_size) >= img->size) {
        tsk_fprintf(stderr,
            "Sector offset supplied is larger than disk image (maximum: %"
            PRIu64 ")\n", img->size / img->sector_size);
        exit(1);
    }

    if ((fs = tsk_fs_open_img(img, imgaddr * img->sector_size, fstype)) == NULL) {
        tsk_error_print(stderr);
        if (tsk_errno == TSK_ERR_FS_UNSUPTYPE)
            tsk_fs_type_print(stderr);
        img->close(img);
        exit(1);
    }

    if (type) {
        tsk_printf("%s\n", tsk_fs_type_toname(fs->ftype));
    }
    else {
        if (fs->fsstat(fs, stdout)) {
            tsk_error_print(stderr);
            fs->close(fs);
            img->close(img);
            exit(1);
        }
    }

    fs->close(fs);
    img->close(img);
#endif
    exit(0);
}
