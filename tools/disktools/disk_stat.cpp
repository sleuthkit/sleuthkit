/*
 * The Sleuth Kit
 * 
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2005 Brian Carrier.  All rights reserved 
 *
 * This software is distributed under the Common Public License 1.0
 */
#include "tsk3/tsk_tools_i.h"

void
usage()
{
    fprintf(stderr, "usage: disk_stat [-V] DEVICE\n");
    fprintf(stderr, "\t-V: Print version\n");
    return;
}

#if HAVE_LINUX_HDREG_H

#include "disk_ide.h"
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>



int
main(int argc, char **argv)
{
    int fd;
    char *device = NULL;        /* e.g. "/dev/hda" */
    struct stat devstat;
    int ch;

    DISK_INFO *di;

    while ((ch = GETOPT(argc, argv, "V")) > 0) {
        switch (ch) {
        case 'V':
            tsk_version_print(stdout);
            return 0;
        default:
            usage();
            return 0;
        }
    }

    if (OPTIND < argc)
        device = argv[OPTIND];

    if (!device) {
        fprintf(stderr, "no device specified\n");
        usage();
        exit(1);
    }

    if (0 != stat(device, &devstat)) {
        fprintf(stderr, "Error opening %s\n", device);
        exit(1);
    }

    if ((S_ISCHR(devstat.st_mode) == 0) && (S_ISBLK(devstat.st_mode) == 0)) {
        fprintf(stderr, "The file name must correspond to a device\n");
        exit(1);
    }

    fd = open(device, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr,
            "error opening device %s (%s)", device, strerror(errno));
        exit(1);
    }

    if ((di = device_open(fd)) == NULL) {
        exit(1);
    }

    close(fd);

    printf("Maximum Disk Sector: %" PRIu64 "\n", di->native_max);
    printf("Maximum User Sector: %" PRIu64 "\n", di->user_max);

    if (di->user_max < di->native_max) {
        printf("\n** HPA Detected (Sectors %" PRIu64 " - %" PRIu64
            ") **\n\n", di->user_max + 1, di->native_max);
    }

    if ((di->flags & DISK_HAS_HPA_SUPPORT) == 0)
        printf("(Disk does not support HPA)\n");

    exit(0);
}

#else

int
main(int argc, char **argv1)
{
    int ch;
    TSK_TCHAR **argv;

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

    while ((ch = GETOPT(argc, argv, _TSK_T("V"))) > 0) {
        switch (ch) {
        case 'V':
            tsk_version_print(stdout);
            return 0;
        default:
            usage();
            return 0;
        }
    }

    fprintf(stderr, "This tool works only on Linux systems\n");
    return 0;
}

#endif
