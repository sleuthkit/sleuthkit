/*
 * The Sleuth Kit
 * 
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2005 Brian Carrier.  All rights reserved 
 *
 * Based on code from http://www.win.tue.nl/~aeb/linux/setmax.c
 * and from hdparm
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file ide.c
 * Contains the functions to query and configure Linux ATA devices.
 */

/* setmax.c - aeb, 000326 - use on 2.4.0test9 or newer */
/* IBM part thanks to Matan Ziv-Av <matan@svgalib.org> */


#include "libtsk.h"

#if HAVE_CONFIG_H
#include "tsk_config.h"
#endif

#if HAVE_LINUX_HDREG_H

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/hdreg.h>
#include <string.h>

#include "disk_ide.h"


/**
 * Get basic information about a device (including the maximum user sector of the drive).  
 * @param di Structure with info about device
 * @returns 1 on error and 0 on success
 */
static int
identify_device(DISK_INFO * di)
{
    unsigned char id_args[4 + 512];
    uint16_t *id_val;

    /* Execute the IDENTIFY DEVICE command */
    memset(id_args, 0, 516);
    id_args[0] = WIN_IDENTIFY;
    id_args[3] = 1;

    if (ioctl(di->fd, HDIO_DRIVE_CMD, &id_args)) {
        id_args[0] = WIN_PIDENTIFY;
        if (ioctl(di->fd, HDIO_DRIVE_CMD, &id_args)) {
            fprintf(stderr, "IDENTIFY DEVICE failed\n");
            return 1;
        }
    }

    /* The result is organized by 16-bit words */
    id_val = (uint16_t *) & id_args[4];

    if (id_val[0] & 0x8000) {
        fprintf(stderr, "Device is not an ATA disk\n");
        return 1;
    }

    /* Give up if LBA or HPA is not supported */
    if ((id_val[49] & 0x0200) == 0) {
        fprintf(stderr, "Error: LBA mode not supported by drive\n");
        return 1;
    }

    // see if the removable media feature is supported
    if (id_val[82] & 0x0004) {
        di->flags |= DISK_HAS_REMOVABLE_SUPPORT;
    }

    // see if the HPA commands are supported
    if (id_val[82] & 0x0400) {
        di->flags |= DISK_HAS_HPA_SUPPORT;
    }

    // see if word 83 is valid -- this is a signature check
    if ((id_val[83] & 0xc000) == 0x4000) {

        // see if the 48-bit commands are supported
        if (id_val[83] & 0x0400) {
            di->flags |= DISK_HAS_48_SUPPORT;
        }
    }


    di->user_max = 0;
    if (di->flags & DISK_HAS_48_SUPPORT) {
        di->user_max = (uint64_t) id_val[103] << 48 |
            (uint64_t) id_val[102] << 32 |
            (uint64_t) id_val[101] << 16 | (uint64_t) id_val[100];

        // the max LBA+1 is in id_val
        di->user_max--;
    }

    /* Use the 28-bit fields */
    if (di->user_max == 0) {
        di->user_max = (uint64_t) id_val[61] << 16 | id_val[60];

        // the max LBA+1 is in id_val
        di->user_max--;
    }

    return 0;
}


/**
 * Get the maximum address of the drive (includes the HPA) and set it in
 * di.
 * @param di Structure to store native max address in
 * @returns 1 on error and 0 on success
 */
static int
get_native_max(DISK_INFO * di)
{
    unsigned char task_args[7];
    int i;

    di->native_max = 0;

    if ((di->flags & DISK_HAS_HPA_SUPPORT) == 0) {
        di->native_max = di->user_max;
        return 0;
    }

    // @@@ check if "Removable feature set is implemented" 
    // -- according to spec, this command will not work in that case
    if (di->flags & DISK_HAS_REMOVABLE_SUPPORT) {
        fprintf(stderr, "Removable feature set enabled\n");
        di->native_max = di->user_max;
        return 0;
    }


    /* Get the actual size using READ NATIVE MAX ADDRESS */
    task_args[0] = WIN_READ_NATIVE_MAX;
    task_args[1] = 0x00;
    task_args[2] = 0x00;
    task_args[3] = 0x00;
    task_args[4] = 0x00;
    task_args[5] = 0x00;
    task_args[6] = 0x40;

    if (ioctl(di->fd, HDIO_DRIVE_TASK, &task_args)) {
        fprintf(stderr, "READ NATIVE MAX ADDRESS failed\n");
        for (i = 0; i < 7; i++)
            fprintf(stderr, "%d = 0x%x\n", i, task_args[i]);
        return 1;
    }

    di->native_max = ((task_args[IDE_SELECT_OFFSET] & 0xf) << 24) +
        (task_args[IDE_HCYL_OFFSET] << 16) +
        (task_args[IDE_LCYL_OFFSET] << 8) + task_args[IDE_SECTOR_OFFSET];

    /* @@@ Do the 48-bit version */
    if (di->native_max == 0x0fffffff) {
        if ((di->flags & DISK_HAS_48_SUPPORT) == 0) {
            fprintf(stderr,
                "READ NATIVE MAX returned 0xffffff, and 48-bit not supported\n");
            return 1;
        }

        /*
           fprintf(stderr,
           "This disk uses the 48-bit ATA commands, which are not supported\n");
           exit(1);
         */
#if HAVE_IDE_TASK_REQUEST_T
        // Try READ NATIVE MAX ADDRESS EXT
        ide_task_request_t req_task;
        memset(&req_task, 0, sizeof(req_task));

        req_task.io_ports[IDE_SELECT_OFFSET] = 0x40;
        req_task.io_ports[IDE_COMMAND_OFFSET] = WIN_READ_NATIVE_MAX_EXT;
        req_task.req_cmd = IDE_DRIVE_TASK_NO_DATA;
        req_task.in_flags.all = 0xffff;
        if (ioctl(di->fd, HDIO_DRIVE_TASKFILE, &req_task)) {
            fprintf(stderr, "READ NATIVE MAX ADDRESS EXT failed\n");
            for (i = 0; i < 8; i++)
                fprintf(stderr, "%d = 0x%x\n", i, req_task.io_ports[i]);
            return 1;
        }

        /* if OK, compute maximum address value */
        if ((req_task.io_ports[IDE_STATUS_OFFSET] & 0x01) == 0) {
            uint32_t high = (req_task.hob_ports[IDE_HCYL_OFFSET] << 16) |
                (req_task.hob_ports[IDE_LCYL_OFFSET] << 8) |
                req_task.hob_ports[IDE_SECTOR_OFFSET];
            uint32_t low = ((req_task.io_ports[IDE_HCYL_OFFSET]) << 16) |
                ((req_task.io_ports[IDE_LCYL_OFFSET]) << 8) |
                (req_task.io_ports[IDE_SECTOR_OFFSET]);
            di->native_max = ((uint64_t) high << 24) | low;
            di->native_max++;   /* since the return value is (maxlba - 1), we add 1 */
        }
        else {

        }
#endif
    }

    return 0;
}

/**
 * Set the maximum user accessible sector.
 * @param fd Handle to open device
 * @param addr Maximum address
 */
void
set_max(int fd, uint64_t addr)
{
    unsigned char task_args[7];
    uint64_t tmp_size;
    int i;

    /* Does this require the EXT version? */
    if (addr > 0x0fffffff) {
        // @@@ Need EXT version
        fprintf(stderr,
            "This disk requires the 48-bit commands, which are not yet supported\n");
        exit(1);
    }

    else {
        /* Now we reset the max address to nat_size */
        task_args[0] = 0xf9;
        task_args[1] = 0;
        task_args[2] = 0;       // Make it temporary

        /* Convert the LBA address to the proper register location */
        tmp_size = addr;
        task_args[3] = (tmp_size & 0xff);
        tmp_size >>= 8;
        task_args[4] = (tmp_size & 0xff);
        tmp_size >>= 8;
        task_args[5] = (tmp_size & 0xff);
        tmp_size >>= 8;
        task_args[6] = (tmp_size & 0x0f);

        task_args[6] |= 0x40;   /* Set the LBA mode */

        if (ioctl(fd, HDIO_DRIVE_TASK, &task_args)) {
            fprintf(stderr, "SET MAX failed\n");
            for (i = 0; i < 7; i++)
                fprintf(stderr, "%d = 0x%x\n", i, task_args[i]);
            exit(1);
        }
    }
} /** * Open the device and collect basic stats on the size * @param a_fd Handle to device * @returns structure with stats or NULL on error

 */
DISK_INFO *
device_open(int a_fd)
{
    DISK_INFO *di;

    di = (DISK_INFO *) malloc(sizeof(DISK_INFO));
    if (di == NULL) {
        fprintf(stderr, "Error allocating memory\n");
        return NULL;
    }
    memset(di, 0, sizeof(DISK_INFO));
    di->fd = a_fd;

    if (identify_device(di)) {
        free(di);
        return NULL;
    }

    if (get_native_max(di)) {
        free(di);
        return NULL;
    }
    return di;
}

#endif
