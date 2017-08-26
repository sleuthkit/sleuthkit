/*
 ** tsk_gettimes
 ** The Sleuth Kit 
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2010-2011 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

#include "tsk/tsk_tools_i.h"
#include <locale.h>
#include <time.h>


static TSK_TCHAR *progname;

static void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-vVm] [-i imgtype] [-b dev_sector_size] [-z zone] [-s seconds] image [image]\n"),
        progname);
    tsk_fprintf(stderr,
        "\t-i imgtype: The format of the image file (use '-i list' for supported types)\n");
    tsk_fprintf(stderr,
        "\t-b dev_sector_size: The size (in bytes) of the device sectors\n");
	tsk_fprintf(stderr, "\t-m: Calculate MD5 hash in output (slow)\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Print version\n");
    tsk_fprintf(stderr,
                "\t-z: Time zone of original machine (i.e. EST5EDT or GMT) (only useful with -l)\n");
    tsk_fprintf(stderr,
                "\t-s seconds: Time skew of original machine (in seconds) (only useful with -l & -m)\n");
    

    exit(1);
}


class TskGetTimes:public TskAuto {
public:
    TskGetTimes(int32_t);
	TskGetTimes(int32_t, bool);
    virtual TSK_RETVAL_ENUM processFile(TSK_FS_FILE * fs_file, const char *path);
    virtual TSK_FILTER_ENUM filterVol(const TSK_VS_PART_INFO * vs_part);
    virtual TSK_FILTER_ENUM filterFs(TSK_FS_INFO * fs_info);
    virtual uint8_t handleError();
    
private:
    int m_curVolAddr;
    int32_t m_secSkew;
	bool m_compute_hash;
};


TskGetTimes::TskGetTimes(int32_t a_secSkew)
{
    m_curVolAddr = -1;
    m_secSkew = a_secSkew;
	m_compute_hash = false;
}

TskGetTimes::TskGetTimes(int32_t a_secSkew, bool a_compute_hash)
{
    m_curVolAddr = -1;
    m_secSkew = a_secSkew;
	m_compute_hash = a_compute_hash;
}

// Print errors as they are encountered
uint8_t TskGetTimes::handleError() 
{
    fprintf(stderr, "%s", tsk_error_get());
    return 0;
}


TSK_RETVAL_ENUM TskGetTimes::processFile(TSK_FS_FILE * fs_file, const char *path)
{
    return TSK_OK;
}


TSK_FILTER_ENUM
TskGetTimes::filterFs(TSK_FS_INFO * fs_info)
{
    TSK_TCHAR volName[32];
    if (m_curVolAddr > -1) {
        TSNPRINTF(volName, 32, _TSK_T("vol%d/"),m_curVolAddr);
    }
    else {
        volName[0] = '\0';
    }

    TSK_FS_FLS_FLAG_ENUM fls_flags = (TSK_FS_FLS_FLAG_ENUM)(TSK_FS_FLS_MAC | TSK_FS_FLS_DIR | TSK_FS_FLS_FILE | TSK_FS_FLS_FULL);
    if(m_compute_hash){
        fls_flags = (TSK_FS_FLS_FLAG_ENUM)(fls_flags | TSK_FS_FLS_HASH);
    }

    if (tsk_fs_fls(fs_info, (TSK_FS_FLS_FLAG_ENUM)(fls_flags),
        fs_info->root_inum, (TSK_FS_DIR_WALK_FLAG_ENUM)(TSK_FS_DIR_WALK_FLAG_ALLOC | TSK_FS_DIR_WALK_FLAG_UNALLOC | TSK_FS_DIR_WALK_FLAG_RECURSE), volName, m_secSkew)) {
    }
    return TSK_FILTER_SKIP;
}


TSK_FILTER_ENUM
TskGetTimes::filterVol(const TSK_VS_PART_INFO * vs_part)
{
    m_curVolAddr = vs_part->addr;
    return TSK_FILTER_CONT;
}


int
main(int argc, char **argv1)
{
    TSK_IMG_TYPE_ENUM imgtype = TSK_IMG_TYPE_DETECT;
    int ch;
    TSK_TCHAR **argv;
    unsigned int ssize = 0;
    TSK_TCHAR *cp;
    int32_t sec_skew = 0;
	bool do_hash = false;

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

    while ((ch = GETOPT(argc, argv, _TSK_T("b:i:s:mvVz:"))) > 0) {
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
                
        case _TSK_T('s'):
            sec_skew = TATOI(OPTARG);
            break;

        case _TSK_T('m'):
            do_hash = true;
            break;

        case _TSK_T('v'):
            tsk_verbose++;
            break;

        case _TSK_T('V'):
            tsk_version_print(stdout);
            exit(0);
                
        case 'z':
            {
                TSK_TCHAR envstr[32];
                TSNPRINTF(envstr, 32, _TSK_T("TZ=%s"), OPTARG);
                if (0 != TPUTENV(envstr)) {
                    tsk_fprintf(stderr, "error setting environment");
                    exit(1);
                }
                
                /* we should be checking this somehow */
                TZSET();
            }
            break;
                
        }
    }

    /* We need at least one more argument */
    if (OPTIND >= argc) {
        tsk_fprintf(stderr,
            "Missing image name\n");
        usage();
    }

    TskGetTimes tskGetTimes(sec_skew, do_hash);
    if (tskGetTimes.openImage(argc - OPTIND, &argv[OPTIND], imgtype,
            ssize)) {
        tsk_error_print(stderr);
        exit(1);
    }
    
    if (tskGetTimes.findFilesInImg()) {
        // we already logged the errors
        exit(1);
    }
    
    exit(0);
}
