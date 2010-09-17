/*
 ** tsk_comparedir
 ** The Sleuth Kit 
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2010 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

#include "tsk3/tsk_tools_i.h"
#include "tsk_comparedir.h"
#include <locale.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <set>
#include <stdlib.h>

#ifdef WIN32
#include <windows.h>
#include "shlobj.h"
#else
#include <dirent.h>
#endif

static TSK_TCHAR *progname;

static void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-o sector_offset] [-n start_inum] image comparison_directory\n"),
        progname);

    tsk_fprintf(stderr,
        "\t-o sector_offset: sector offset for file system to compare\n");
    tsk_fprintf(stderr,
        "\t-n start_inum: inum for directory in image file to start compare at\n");

    exit(1);
}



TSK_RETVAL_ENUM
    TskCompareDir::processFile(TSK_FS_FILE * a_fs_file, const char *a_path)
{
    //exclude certain types
    if (isDotDir(a_fs_file, a_path))
        return TSK_OK;

    if (isDir(a_fs_file))
        return TSK_OK;

    if (isNtfsSystemFiles(a_fs_file, a_path))
        return TSK_OK;

    if ((!a_fs_file->meta) || (a_fs_file->meta->size == 0))
        return TSK_OK;

    if (isFATSystemFiles(a_fs_file))
        return TSK_OK;

#ifdef WIN32
    size_t PATH_MAX = FILENAME_MAX;
#endif

    //create the full path
    size_t len = strlen(a_fs_file->name->name) + strlen(a_path) + 1;
    char *fullPath = (char *) tsk_malloc(len);
    if (fullPath == NULL)
        return TSK_ERR;

    snprintf(fullPath, len, "/");
    strncat(fullPath, a_path, len-strlen(fullPath));
    strncat(fullPath, a_fs_file->name->name, len-strlen(fullPath));

    //convert path for win32
#ifdef WIN32
    for (int i = 0; i < strlen(fullPath); i++) {
        if (fullPath[i] == '/')
            fullPath[i] = '\\';
    }
#endif

    //add the path to the set
    m_filesInImg.insert(fullPath);
    return TSK_OK;
}

TSK_FILTER_ENUM
    TskCompareDir::filterVol(const TSK_VS_PART_INFO * a_vs_part)
{
    fprintf(stderr, "Given image with volumes without specifying offset");
    return TSK_FILTER_STOP;
}


uint8_t
    TskCompareDir::compareLclFiles(const TSK_TCHAR * a_base_dir,
    const TSK_TCHAR * dir)
{
    std::set < char *, ltstr >::iterator it;

#ifdef TSK_WIN32
    WIN32_FIND_DATA ffd;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    wchar_t fullpath[FILENAME_MAX];
    UTF16 *utf16;
    UTF8 *utf8;
    char file8[FILENAME_MAX];

    //create the full path (utf16)
    wcsncpy(fullpath, (wchar_t *) a_base_dir, FILENAME_MAX);
    if (wcslen((wchar_t *) dir) > 0)
        wcsncat(fullpath, dir, FILENAME_MAX);

    wcsncat(fullpath, L"\\*", FILENAME_MAX);


    //start the directory walk
    hFind = FindFirstFile((LPCWSTR) fullpath, &ffd);
    DWORD err = GetLastError();
    if (hFind == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error opening directory: %S\n", fullpath);

        wchar_t message[64];
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, 0,
            (LPWSTR) & message, 64, NULL);
        fprintf(stderr, "error: %S", message);
        return 1;
    }

    do {
        wchar_t file[FILENAME_MAX];
        wcsncpy(file, dir, FILENAME_MAX);
        wcsncat(file, L"\\", FILENAME_MAX);
        wcsncat(file, ffd.cFileName, FILENAME_MAX);
        //if the file is a directory make recursive call
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (file[wcslen(file) - 1] != L'.')
                if (compareLclFiles(a_base_dir, file))
                    return 1;
        }
        else {

            /* convert from utf16 to utf8 to try to find the file in the set
             * of names that were found in the image file. */
            utf8 = (UTF8 *) file8;
            utf16 = (UTF16 *) file;

            size_t ilen = wcslen(file);

            TSKConversionResult retVal =
                tsk_UTF16toUTF8_lclorder((const UTF16 **) &utf16,
                &utf16[ilen], &utf8,
                &utf8[FILENAME_MAX], TSKlenientConversion);

            *utf8 = '\0';
            if (retVal != TSKconversionOK) {
                fprintf(stderr, "Error Converting file name");
                return 1;
            }

            //if the file is in the set, remove it and continue, if not print
            it = m_filesInImg.find(file8);
            if (it != m_filesInImg.end()) {
                m_filesInImg.erase(it);
            }
            else {
                printf("file: %s not found in image file\n", file8);
                m_missDirFile = true;
            }
        }
    } while (FindNextFile(hFind, &ffd) != 0);

    FindClose(hFind);

#else
    DIR *dp;
    struct dirent *dirp;
    char file[PATH_MAX];
    char fullPath[PATH_MAX];
    struct stat status;

    strncpy(fullPath, a_base_dir, PATH_MAX);
    strncat(fullPath, dir, PATH_MAX);
    if ((dp = opendir(fullPath)) == NULL) {
        fprintf(stderr, "Error opening directory");
        return 1;
    }
    while ((dirp = readdir(dp)) != NULL) {
        strncpy(file, dir, PATH_MAX);
        strncat(file, "/", PATH_MAX);
        strncat(file, dirp->d_name, PATH_MAX);

        strncpy(fullPath, a_base_dir, PATH_MAX);
        strncat(fullPath, file, PATH_MAX);

        stat(fullPath, &status);
        if (S_ISDIR(status.st_mode)) {
            if (file[strlen(file) - 1] != '.')
                if (compareLclFiles(a_base_dir, file))
                    return 1;
        }
        else {
            it = m_filesInImg.find(file);
            if (it != m_filesInImg.end()) {
                m_filesInImg.erase(it);
            }
            else {
                printf("file: %s not found in image file\n", file);
                m_missDirFile = true;
            }
        }
    }
#endif

    return 0;
}



/*
 * @param a_soffset Sector offset where file system to analyze is located
 * @param a_inum is 0 if root directory should be processed
 * @param a_lcl_dir Path of local directory to compare with image contents.
 * @returns 1 on error
 */
uint8_t
    TskCompareDir::compareDirs(TSK_OFF_T a_soffset, TSK_INUM_T a_inum,
    const TSK_TCHAR * a_lcl_dir)
{
    uint8_t retval;

    // collect the file names that are in the disk image
    if (a_inum != 0)
        retval =
            findFilesInFs(a_soffset * m_img_info->sector_size, a_inum);
    else
        retval = findFilesInFs(a_soffset * m_img_info->sector_size);

    if (retval)
        return 1;

    m_missDirFile = false;

    // compare with the local files
    if (compareLclFiles(a_lcl_dir, (TSK_TCHAR *) _TSK_T("")))
        return 1;

    if (!m_missDirFile)
        printf("All files in directory found in image\n");

    if (m_filesInImg.begin() == m_filesInImg.end()) {
        printf("All files in image found in directory\n");
    }
    else {
        std::set < char *, ltstr >::iterator it;
        for (it = m_filesInImg.begin(); it != m_filesInImg.end(); it++)
            printf("file: %s not found in directory\n",
                (TSK_TCHAR *) * it);
    }

    return 0;
}


int
main(int argc, char **argv1)
{
    TSK_TCHAR **argv;
#ifdef WIN32
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == NULL) {
        fprintf(stderr, "Error getting wide arguments\n");
        exit(1);
    }
#else
    argv = (TSK_TCHAR **) argv1;
#endif

    TSK_OFF_T soffset = 0;
    TSK_TCHAR *cp;
    int ch;
    TSK_INUM_T inum = 0;

    progname = argv[0];
    setlocale(LC_ALL, "");

    while ((ch = GETOPT(argc, argv, _TSK_T("o:n:"))) > 0) {
        switch (ch) {
        case _TSK_T('?'):
        default:
            TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
                argv[OPTIND]);
            usage();

        case _TSK_T('o'):
            soffset = (TSK_OFF_T) TSTRTOUL(OPTARG, &cp, 0);
            if (*cp || *cp == *OPTARG || soffset < 0) {
                TFPRINTF(stderr,
                    _TSK_T
                    ("invalid argument: sector offset must be positive: %s\n"),
                    OPTARG);
                usage();
            }
            break;

        case _TSK_T('n'):
            inum = (TSK_INUM_T) TSTRTOUL(OPTARG, &cp, 0);
            if (*cp || *cp == *OPTARG || inum <= 0) {
                TFPRINTF(stderr,
                    _TSK_T
                    ("invalid argument: inum must be positive: %s\n"),
                    OPTARG);
                usage();
            }
            break;
        }
    }

    /* We need at least one more argument */
    if (OPTIND + 1 >= argc) {
        tsk_fprintf(stderr,
            "Missing output directory and/or image name\n");
        usage();
    }

    TskCompareDir tskCompareDir;

    tskCompareDir.setFileFilterFlags(TSK_FS_DIR_WALK_FLAG_ALLOC);

    if (tskCompareDir.openImage(1, &argv[OPTIND], TSK_IMG_TYPE_DETECT, 0)) {
        tsk_error_print(stderr);
        exit(1);
    }

    if (tskCompareDir.compareDirs(soffset, inum, argv[OPTIND + 1])) {
        tsk_error_print(stderr);
        exit(1);
    }

    return 0;
}
