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
#include <locale.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>

#include "tsk_recover.h"

static TSK_TCHAR *progname;

static void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-vVa] [-f fstype] [-i imgtype] [-b dev_sector_size] [-o sector_offset] output_dir image\n"),
        progname);
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-b dev_sector_size: The size (in bytes) of the device sectors\n");
    tsk_fprintf(stderr,
        "\t-f fstype: File system type (use '-f list' for supported types)\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Print version\n");
    tsk_fprintf(stderr,
        "\t-a: Recover all files (allocated and unallocated)\n");
    tsk_fprintf(stderr,
        "\t-o sector_offset: sector offset for a volume to recover (recovers only that volume)\n");

    exit(1);
}


TskRecover::TskRecover(TSK_TCHAR * a_base_dir)
{
    m_base_dir = a_base_dir;
#ifdef TSK_WIN32
    m_vsName[0] = L'\0';
#else
    m_vsName[0] = '\0';
#endif
    m_writeVolumeDir = false;
    m_fileCount = 0;
}


static TSK_WALK_RET_ENUM
file_walk_cb(TSK_FS_FILE * a_fs_file, TSK_OFF_T a_off, TSK_DADDR_T a_addr,
    char *a_buf, size_t a_len, TSK_FS_BLOCK_FLAG_ENUM a_flags, void *a_ptr)
{
#ifdef TSK_WIN32
    DWORD written = 0;
    //write to the file
    if (!WriteFile((HANDLE) a_ptr, a_buf, a_len, &written, NULL)) {
        fprintf(stderr, "Error writing file content\n");
        return TSK_WALK_STOP;
    }

#else
    FILE *hFile = (FILE *) a_ptr;
    if (fwrite(a_buf, a_len, 1, hFile) != 1) {
        fprintf(stderr, "Error writing file content\n");
        return TSK_WALK_STOP;
    }
#endif
    return TSK_WALK_CONT;
}


uint8_t TskRecover::writeFile(TSK_FS_FILE * a_fs_file, const char *a_path)
{
#ifdef TSK_WIN32
    UTF16 *
        utf16;
    UTF8 *
        utf8;
    wchar_t
        path16[FILENAME_MAX];
    wchar_t
        name[FILENAME_MAX];
    wchar_t
        path[FILENAME_MAX];
    size_t
        ilen;

    ilen = strlen(a_path);

    //converting path from utf8 to utf16
    utf8 = (UTF8 *) a_path;
    utf16 = (UTF16 *) path16;
    TSKConversionResult
        retVal =
        tsk_UTF8toUTF16((const UTF8 **) &utf8, &utf8[ilen], &utf16,
        &utf16[FILENAME_MAX], TSKlenientConversion);

    if (retVal != TSKconversionOK) {
        fprintf(stderr, "Error Converting file path");
        return 1;
    }
    *utf16 = '\0';

    //combining base path with path of current file
    _snwprintf(path, FILENAME_MAX, (wchar_t *) m_base_dir);
    wcsncat(path, L"\\", FILENAME_MAX);
    wcsncat(path, m_vsName, FILENAME_MAX);
    wcsncat(path, path16, FILENAME_MAX);

    //build up directory structure
    size_t
        len = wcslen((const wchar_t *) path);
    for (size_t i = 0; i < len; i++) {
        if (path[i] == L'/')
            path[i] = L'\\';
        if (((i > 0) && (path[i] == L'\\') && (path[i - 1] != L'\\'))
            || ((path[i] != L'\\') && (i == len - 1))) {
            uint8_t
                replaced = 0;
            if (path[i] == L'\\') {
                path[i] = L'\0';
                replaced = 1;
            }
            BOOL
                result = CreateDirectoryW((LPCTSTR) path, NULL);
            if (!result) {
                if (GetLastError() == ERROR_PATH_NOT_FOUND) {
                    fprintf(stderr, "Error Creating Directory (%S)", path);
                    return 1;
                }
            }
            if (replaced)
                path[i] = L'\\';
        }
    }

    //fix the end of the path so that the file name can be appended
    if (path[len - 1] != L'\\')
        path[len] = L'\\';

    //convert file name from utf8 to utf16
    char
        name8[FILENAME_MAX];
    snprintf(name8, FILENAME_MAX, a_fs_file->name->name);

    ilen = strlen(name8);
    utf8 = (UTF8 *) name8;
    utf16 = (UTF16 *) name;

    retVal = tsk_UTF8toUTF16((const UTF8 **) &utf8, &utf8[ilen],
        &utf16, &utf16[FILENAME_MAX], TSKlenientConversion);
    *utf16 = '\0';

    if (retVal != TSKconversionOK) {
        fprintf(stderr, "Error Converting file name to UTF-16");
        return 1;
    }

    //append the file name onto the path
    wcsncat(path, name, FILENAME_MAX);

    //create the file
    HANDLE
        handle =
        CreateFileW((LPCTSTR) path, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error Creating File (%S)", path);
        return 1;
    }

    //try to write to the file
    if (tsk_fs_file_walk(a_fs_file, (TSK_FS_FILE_WALK_FLAG_ENUM) 0,
            file_walk_cb, handle)) {
        fprintf(stderr, "Error walking file\n");
        tsk_error_print(stderr);
        CloseHandle(handle);
        return 1;
    }

    CloseHandle(handle);

#else
    struct stat
        statds;
    char
        fbuf[PATH_MAX];
    FILE *
        hFile;

    snprintf(fbuf, PATH_MAX, "%s/%s/%s", (char *) m_base_dir, m_vsName,
        a_path);

    // see if the directory already exists. Create, if not.
    if (0 != lstat(fbuf, &statds)) {
        size_t
            len = strlen(fbuf);
        for (size_t i = 0; i < len; i++) {
            if (((i > 0) && (fbuf[i] == '/') && (fbuf[i - 1] != '/'))
                || ((fbuf[i] != '/') && (i == len - 1))) {
                uint8_t
                    replaced = 0;

                if (fbuf[i] == '/') {
                    fbuf[i] = '\0';
                    replaced = 1;
                }
                if (0 != lstat(fbuf, &statds)) {
                    if (mkdir(fbuf, 0775)) {
                        fprintf(stderr,
                            "Error making directory (%s) (%x)\n", fbuf,
                            errno);
                        return 1;
                    }
                }
                if (replaced)
                    fbuf[i] = '/';
            }
        }
    }

    if (fbuf[strlen(fbuf) - 1] != '/')
        strncat(fbuf, "/", PATH_MAX);
    strncat(fbuf, a_fs_file->name->name, PATH_MAX);

    // open the file
    if ((hFile = fopen(fbuf, "w+")) == NULL) {
        fprintf(stderr, "Error opening file for writing (%s)\n", fbuf);
        return 1;
    }

    if (tsk_fs_file_walk(a_fs_file, (TSK_FS_FILE_WALK_FLAG_ENUM) 0,
            file_walk_cb, hFile)) {
        fprintf(stderr, "Error walking: %s\n", fbuf);
        tsk_error_print(stderr);
        fclose(hFile);
        return 1;
    }

    fclose(hFile);

#endif

    m_fileCount++;
    if (tsk_verbose) 
        tsk_fprintf(stderr, "Recovered file %s%s (%" PRIuINUM ")\n", a_path,
            a_fs_file->name->name, a_fs_file->name->meta_addr);

    return 0;
}


uint8_t TskRecover::processFile(TSK_FS_FILE * fs_file, const char *path)
{
    if (isDotDir(fs_file, path))
        return 0;

    if (isDir(fs_file))
        return 0;

    if (isNtfsSystemFiles(fs_file, path))
        return 0;

    if ((!fs_file->meta) || (fs_file->meta->size == 0))
        return 0;

    if (isFATSystemFiles(fs_file))
        return 0;

    writeFile(fs_file, path);

    return 0;
}

uint8_t
TskRecover::filterVol(const TSK_VS_PART_INFO * vs_part)
{
    // if this is method was called, we know the image has a volume system. 
    m_writeVolumeDir = true;
    return 0;
}

uint8_t
TskRecover::filterFs(TSK_FS_INFO * fs_info)
{
    if (m_writeVolumeDir) {
#ifdef TSK_WIN32
        _snwprintf(m_vsName, FILENAME_MAX, (LPCWSTR) L"vol_%"PRIuOFF"\\", fs_info->offset / m_img_info->sector_size);
#else
        snprintf(m_vsName, FILENAME_MAX, "vol_%"PRIuOFF"/", fs_info->offset / m_img_info->sector_size);
#endif
    }
    return 0;

}

uint8_t
TskRecover::findFiles(bool all, TSK_OFF_T soffset)
{
    uint8_t retval;
    
    if (!all)
        retval = findFilesInFs(soffset * m_img_info->sector_size);
    else
        retval = findFilesInImg();
    
    printf("Files Recovered: %d\n", m_fileCount);
    return retval;
}

int
main(int argc, char **argv1)
{
    TSK_IMG_TYPE_ENUM imgtype = TSK_IMG_TYPE_DETECT;

    int ch;
    bool allImgs = true;
    TSK_TCHAR **argv;
    unsigned int ssize = 0;
    TSK_OFF_T soffset = 0;
    TSK_TCHAR *cp;
    TSK_FS_DIR_WALK_FLAG_ENUM walkflag = TSK_FS_DIR_WALK_FLAG_UNALLOC;

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

    while ((ch = GETOPT(argc, argv, _TSK_T("b:f:i:o:tvVa"))) > 0) {
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

        case _TSK_T('o'):
            soffset = (TSK_OFF_T) TSTRTOUL(OPTARG, &cp, 0);
            if (*cp || *cp == *OPTARG || soffset < 0) {
                TFPRINTF(stderr,
                    _TSK_T
                    ("invalid argument: sector offset must be positive: %s\n"),
                    OPTARG);
                usage();
            }
            else
                allImgs = false;
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
            break;

        case _TSK_T('a'):
            walkflag =
                (TSK_FS_DIR_WALK_FLAG_ENUM) (TSK_FS_DIR_WALK_FLAG_UNALLOC |
                TSK_FS_DIR_WALK_FLAG_ALLOC);
            break;
        }
    }

    /* We need at least one more argument */
    if (OPTIND + 1 >= argc) {
        tsk_fprintf(stderr,
            "Missing output directory and/or image name\n");
        usage();
    }

    TskRecover tskRecover(argv[OPTIND]);

    tskRecover.setFileFilterFlags(walkflag);
    if (tskRecover.openImage(argc - OPTIND - 1, &argv[OPTIND + 1], imgtype,
            ssize)) {
        tsk_error_print(stderr);
        exit(1);
    }

    if (tskRecover.findFiles(allImgs, soffset)) {
        tsk_error_print(stderr);
        exit(1);
    }

    exit(0);
}
