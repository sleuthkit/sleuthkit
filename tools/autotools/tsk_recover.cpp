/*
 ** tsk_recover
 ** The Sleuth Kit 
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2010 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

#include "tsk3/tsk_tools_i.h"
#include "tsk_recover.h"
#include <locale.h>
#include <sys/stat.h>
#include <errno.h>

static TSK_TCHAR *progname;

static void
usage()
{
    // @@@ UPDATE ME
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-vV] [-f fstype] [-i imgtype] [-b dev_sector_size] output_dir image\n"),
        progname);
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-b dev_sector_size: The size (in bytes) of the device sectors\n");
    tsk_fprintf(stderr,
        "\t-f fstype: File system type (use '-f list' for supported types)\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Print version\n");

    exit(1);
}


TskRecover::TskRecover(TSK_TCHAR *a_base_dir)
{
    m_base_dir = a_base_dir;
}


static TSK_WALK_RET_ENUM 
file_walk_cb(TSK_FS_FILE *a_fs_file, TSK_OFF_T a_off, TSK_DADDR_T a_addr, char *a_buf,
     size_t a_len, TSK_FS_BLOCK_FLAG_ENUM a_flags, void *a_ptr)
{
#ifdef TSK_WIN32
    
#else
    FILE *hFile = (FILE *)a_ptr;
    if (fwrite(a_buf, a_len, 1, hFile) != 1) {
        fprintf(stderr, "Error writing file content\n");
        return TSK_WALK_STOP;
    }
#endif
    return TSK_WALK_CONT;
}


uint8_t 
TskRecover::writeFile(TSK_FS_FILE *a_fs_file, const char *a_path)
{
#ifdef TSK_WIN32
    printf("Error: Windows not supported yet!\n");
#else
    struct stat statds;
    char fbuf[PATH_MAX];
    FILE *hFile;
    
    snprintf(fbuf, PATH_MAX, "%s/%s", (char *)m_base_dir, a_path);
    
    // see if the directory already exists. Create, if not.
    if (0 != lstat(fbuf, &statds)) {
        size_t len = strlen(fbuf);
        for (size_t i = 0; i < len; i++) {
            if ( ((i > 0) && (fbuf[i] == '/') && (fbuf[i-1] != '/')) || ((fbuf[i] != '/') && (i == len-1)) ) {
                uint8_t replaced = 0;
                
                if (fbuf[i] == '/') {
                    fbuf[i] = '\0';
                    replaced = 1;
                }
                if (0 != lstat(fbuf, &statds)) {
                    if (mkdir (fbuf, 0775)) {
                        fprintf(stderr, "Error making directory (%s) (%x)\n", fbuf, errno);
                        return 1;
                    }
                }
                if (replaced)
                    fbuf[i] = '/';
            }
        }
    }
    
    if (fbuf[strlen(fbuf)-1] != '/')
        strncat(fbuf, "/", PATH_MAX);
    strncat(fbuf, a_fs_file->name->name, PATH_MAX);
    
    // open the file
    if ((hFile = fopen(fbuf, "w+")) == NULL) {
        fprintf(stderr, "Error opening file for writing (%s)\n", fbuf);
        return 1;
    }
    
    if (tsk_fs_file_walk(a_fs_file, (TSK_FS_FILE_WALK_FLAG_ENUM)0, file_walk_cb, hFile)) {
        fprintf(stderr, "Error walking: %s\n", fbuf);
        tsk_error_print(stderr);
        fclose(hFile);
        return 1;
    }
    
    fclose(hFile);
    
#endif
    
    printf ("Recovered file %s%s (%"PRIuINUM")\n", a_path, a_fs_file->name->name, a_fs_file->name->meta_addr);
    
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
    
    if ((!fs_file->meta) || (fs_file->meta->size == 0)) 
        return 0;
    
    writeFile(fs_file, path);
    
    return 0;
}


int
main(int argc, char **argv1)
{
    TSK_IMG_TYPE_ENUM imgtype = TSK_IMG_TYPE_DETECT;

    int ch;
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

        case _TSK_T('v'):
            tsk_verbose++;
            break;

        case _TSK_T('V'):
            tsk_version_print(stdout);
            exit(0);
        }
    }

    /* We need at least one more argument */
    if (OPTIND + 1 >= argc) {
        tsk_fprintf(stderr, "Missing output directory and/or image name\n");
        usage();
    }
    
    TskRecover tskRecover(_TSK_T(argv[OPTIND]));
    
    tskRecover.setFileFilterFlags(TSK_FS_DIR_WALK_FLAG_UNALLOC);
    if (tskRecover.openImage(argc - OPTIND - 1,  &argv[OPTIND+1], imgtype,
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

    fs->close(fs);
    img->close(img);
#endif
    exit(0);
}
