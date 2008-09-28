/*
 * The Sleuth Kit
 * 
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2005 Brian Carrier.  All rights reserved 
 *
 * This software is distributed under the Common Public License 1.0
 */
#include "tsk3/tsk_tools_i.h"
#include <errno.h>

void
usage()
{
    fprintf(stderr, "usage: disk_sreset [-V] DEVICE\n");
    fprintf(stderr, "\t-V: Print version\n");
    return;
}


#if HAVE_LINUX_HDREG_H

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "disk_ide.h"

int
main(int argc, char **argv)
{
    int fd;
    char *device = NULL;        /* e.g. "/dev/hda" */
    struct stat devstat;
    int ch;

    DISK_INFO *di1, *di2;

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
        fprintf(stderr, "error opening device %s (%s)", device,
            strerror(errno));
        exit(1);
    }

    /* Get the two address values */
    if ((di1 = device_open(fd)) == NULL) {
        exit(1);
    }
    if ((di1->flags & DISK_HAS_HPA_SUPPORT) == 0) {
        fprintf(stderr, "This disk does not support HPA\n");
        close(fd);
        exit(1);
    }

    /* Is there an actual HPA? */
    if (di1->user_max >= di1->native_max) {
        fprintf(stderr, "An HPA was not detected on this device\n");
        close(fd);
        exit(1);
    }

    printf("Removing HPA from %" PRIu64 " to %" PRIu64
        " until next reset\n", di1->user_max + 1, di1->native_max);
    set_max(fd, di1->native_max);

    /* Make sure the new value is correct */
    if ((di2 = device_open(fd)) == NULL) {
        exit(1);
    }
    close(fd);

    if (di2->user_max != di1->native_max) {
        fprintf(stderr,
            "Error: HPA still exists after resetting it - huh?\n");
        exit(1);
    }

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
