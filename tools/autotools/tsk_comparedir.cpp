/*
 ** tsk_comparedir
 ** The Sleuth Kit 
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2010-2011 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

#include "tsk/tsk_tools_i.h"
#include "tsk_comparedir.h"
#include <locale.h>
#include <sys/stat.h>
#include <errno.h>
#include <set>

#ifdef WIN32
#include <windows.h>
#include "shlobj.h"
#else
#include <dirent.h>
#endif

/* The general concept of this procedure is to walk the image and load the file and dir names
 * into a structure.  Then, analyze the directory to see if the name is in there or not. If it
 * was found, remove it.  At the end, we'll have a list of names that were in either the image
 * or dir, but not both. */

static TSK_TCHAR *progname;

#define TSK_CD_BUFSIZE  1024

static void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-f fstype] [-i imgtype] [-b dev_sector_size] [-o sector_offset] [-n start_inum] [-vV] image [image] comparison_directory\n"),
        progname);

    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-b dev_sector_size: The size (in bytes) of the device sectors\n");    
    tsk_fprintf(stderr,
        "\t-f fstype: The file system type (use '-f list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-o sector_offset: sector offset for file system to compare\n");
    tsk_fprintf(stderr,
        "\t-n start_inum: inum for directory in image file to start compare at\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Print version\n");

    exit(1);
}


// Print errors as they are encountered
uint8_t TskCompareDir::handleError() 
{
    fprintf(stderr, "%s", tsk_error_get());
    return 0;
}

/**
 * Process a local directory and compare its contents with the image.
 * This will recursively call itself on subdirectories. 
 * @param a_dir Subdirectory of m_lclDir to process. 
 * @returns 1 on error
 */
uint8_t
    TskCompareDir::processLclDir(const TSK_TCHAR * a_dir)
{
    std::set < char *, ltstr >::iterator it;

#ifdef TSK_WIN32
    WIN32_FIND_DATA ffd;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    wchar_t fullpath[TSK_CD_BUFSIZE];
    UTF16 *utf16;
    UTF8 *utf8;
    char file8[TSK_CD_BUFSIZE];

    //create the full path (utf16)
    wcsncpy(fullpath, (wchar_t *) m_lclDir, TSK_CD_BUFSIZE);
    if (wcslen((wchar_t *) a_dir) > 0)
        wcsncat(fullpath, a_dir, TSK_CD_BUFSIZE);

    wcsncat(fullpath, L"\\*", TSK_CD_BUFSIZE);


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
        wchar_t file[TSK_CD_BUFSIZE];
        wcsncpy(file, a_dir, TSK_CD_BUFSIZE);
        wcsncat(file, L"\\", TSK_CD_BUFSIZE);
        wcsncat(file, ffd.cFileName, TSK_CD_BUFSIZE);
        //if the file is a directory make recursive call
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // skip the '.' and '..' entries
            if ((file[0] == L'.') && ((file[1] == '\0') || ((file[1] == L'.') && (file[2] == '\0')))) {
                // do nothing
            }
            else if (processLclDir(file)) {
                return 1;
            }
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
                &utf8[TSK_CD_BUFSIZE], TSKlenientConversion);

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
    char file[TSK_CD_BUFSIZE];
    char fullPath[TSK_CD_BUFSIZE];
    struct stat status;

    strncpy(fullPath, m_lclDir, TSK_CD_BUFSIZE);
    strncat(fullPath, a_dir, TSK_CD_BUFSIZE-strlen(fullPath));
    if ((dp = opendir(fullPath)) == NULL) {
        fprintf(stderr, "Error opening directory");
        return 1;
    }
    while ((dirp = readdir(dp)) != NULL) {
        strncpy(file, a_dir, TSK_CD_BUFSIZE);
        strncat(file, "/", TSK_CD_BUFSIZE-strlen(file));
        strncat(file, dirp->d_name, TSK_CD_BUFSIZE-strlen(file));

        strncpy(fullPath, m_lclDir, TSK_CD_BUFSIZE);
        strncat(fullPath, file, TSK_CD_BUFSIZE-strlen(fullPath));

        stat(fullPath, &status);
        if (S_ISDIR(status.st_mode)) {
            // skip the '.' and '..' entries
            if ((file[0] == '.') && ((file[1] == '\0') || ((file[1] == '.') && (file[2] == '\0')))) {
                // do nothing
            }
            else if (processLclDir(file)) {
                return 1;
            }
        }
        else {
            // see if we already saw this file in the image
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


/********** Methods that load the internal list / set with info from the image **********/

TSK_RETVAL_ENUM
TskCompareDir::processFile(TSK_FS_FILE * a_fs_file, const char *a_path)
{
    //exclude certain types
    if (isDotDir(a_fs_file))
        return TSK_OK;
    
    if (isDir(a_fs_file))
        return TSK_OK;
    
    if ((isNtfsSystemFiles(a_fs_file, a_path)) || (isFATSystemFiles(a_fs_file)))
        return TSK_OK;
    
    if (!a_fs_file->meta)
        return TSK_OK;
    
    //create the full path
    size_t len = strlen(a_fs_file->name->name) + strlen(a_path) + 1;
    char *fullPath = (char *) tsk_malloc(len);
    if (fullPath == NULL) {
        registerError();
        return TSK_STOP;
    }
    
    snprintf(fullPath, len, "/");
    strncat(fullPath, a_path, len-strlen(fullPath));
    strncat(fullPath, a_fs_file->name->name, len-strlen(fullPath));
    
    //convert path for win32
#ifdef WIN32
    for (size_t i = 0; i < strlen(fullPath); i++) {
        if (fullPath[i] == '/')
            fullPath[i] = '\\';
    }
#endif
    
    //add the path to the internal list/set
    m_filesInImg.insert(fullPath);
    return TSK_OK;
}

TSK_FILTER_ENUM
TskCompareDir::filterVol(const TSK_VS_PART_INFO * a_vs_part)
{
    fprintf(stderr, "Error: volume system detected.  You must specify a specific file system using '-o'\n");
    return TSK_FILTER_STOP;
}



/*
 * @param a_soffset Sector offset where file system to analyze is located
 * @param a_inum is 0 if root directory should be processed
 * @param a_lcl_dir Path of local directory to compare with image contents.
 * @returns 1 on error
 */
uint8_t
    TskCompareDir::compareDirs(TSK_OFF_T a_soffset, TSK_INUM_T a_inum,
    TSK_FS_TYPE_ENUM a_fstype, const TSK_TCHAR * a_lcl_dir)
{
    uint8_t retval;

    // collect the file names that are in the disk image
    if (a_inum != 0)
        retval =
            findFilesInFs(a_soffset * m_img_info->sector_size, a_fstype, a_inum);
    else
        retval = findFilesInFs(a_soffset * m_img_info->sector_size, a_fstype);

    if (retval)
        return 1;

    m_missDirFile = false;
    m_lclDir = a_lcl_dir;

    // process the local directory
    if (processLclDir(_TSK_T("")))
        return 1;

    if (m_missDirFile == false) {
        printf("All files in directory found in image\n");
    }

    if (m_filesInImg.begin() == m_filesInImg.end()) {
        printf("All files in image found in directory\n");
    }
    else {
        std::set < char *, ltstr >::iterator it;
        for (it = m_filesInImg.begin(); it != m_filesInImg.end(); ++it)
            printf("file: %s not found in directory\n",
                (TSK_TCHAR *) * it);
    }

    return 0;
}


int
main(int argc, char **argv1)
{
    TSK_TCHAR **argv;
    TSK_IMG_TYPE_ENUM imgtype = TSK_IMG_TYPE_DETECT;
    TSK_FS_TYPE_ENUM fstype = TSK_FS_TYPE_DETECT;
    unsigned int ssize = 0;
    
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

    while ((ch = GETOPT(argc, argv, _TSK_T("b:f:i:o:n:vV"))) > 0) {
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
            

        case _TSK_T('n'):
            if (tsk_fs_parse_inum(OPTARG, &inum, NULL, NULL, NULL, NULL)) {
                tsk_error_print(stderr);
                usage();
            }
            break;
        
        case _TSK_T('o'):
            if ((soffset = tsk_parse_offset(OPTARG)) == -1) {
                tsk_error_print(stderr);
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

    /* We need at least two more argument */
    if (OPTIND + 1 >= argc) {
        tsk_fprintf(stderr,
            "Missing output directory and/or image name\n");
        usage();
    }

    TskCompareDir tskCompareDir;

    tskCompareDir.setFileFilterFlags(TSK_FS_DIR_WALK_FLAG_ALLOC);

    if (tskCompareDir.openImage(argc - OPTIND - 1, &argv[OPTIND], imgtype, ssize)) {
        tsk_error_print(stderr);
        exit(1);
    }

    if (tskCompareDir.compareDirs(soffset, inum, fstype, argv[argc - 1])) {
        // errors were already displayed
        exit(1);
    }

    return 0;
}
