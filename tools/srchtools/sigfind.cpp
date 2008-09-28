/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2004 Brian Carrier.  All rights reserved
 *
 * sigfind
 *
 * This software is distributed under the Common Public License 1.0
 */

#include "tsk3/tsk_tools_i.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>

extern char *progname;

void
usage()
{
    fprintf(stderr,
            "%s [-b bsize] [-o offset] [-t template] [-lV] [hex_signature] file\n",
            progname);
    fprintf(stderr, "\t-b bsize: Give block size (default 512)\n");
    fprintf(stderr,
            "\t-o offset: Give offset into block where signature should exist (default 0)\n");
    fprintf(stderr, "\t-l: Signature will be little endian in image\n");
    fprintf(stderr, "\t-V: Version\n");
    fprintf(stderr,
            "\t-t template: The name of a data structure template:\n");
    fprintf(stderr,
            "\t\tdospart, ext2, ext3, fat, hfs, hfs+, ntfs, ufs1, ufs2\n");
    exit(1);
}

// @@@ Should have a big endian flag as well
int
main(int argc, char **argv)
{
    int ch;
    uint8_t sig[4] = { 0, 0, 0, 0 };
    uint8_t block[1024];

    char **err = NULL;
    int fd;
    int offset = 0, rel_offset = 0;
    int read_size = 512, bs = 512;
    daddr_t i, prev_hit;
    int sig_size = 0;
    uint8_t lit_end = 0;
    int sig_print = 0;


    progname = argv[0];

    while ((ch = getopt(argc, argv, "b:lo:t:V")) > 0) {
        switch (ch) {
        case 'b':
            bs = strtol(optarg, err, 10);
            if ((bs == 0) || (errno == EINVAL)) {
                fprintf(stderr, "Error converting block size: %s\n",
                        optarg);
                exit(1);
            }

            if (bs % 512) {
                fprintf(stderr, "Invalid block size\n");
                exit(1);
            }
            break;
        case 'l':
            lit_end = 1;
            break;

        case 'o':

            /* Get the offset in the sector */
            offset = strtol(optarg, err, 10);
            if ((offset == 0) || (errno == EINVAL)) {
                fprintf(stderr, "Error converting offset value: %s\n",
                        optarg);
                exit(1);
            }
            break;

        case 't':
            if ((strcmp(optarg, "ext2") == 0) ||
                (strcmp(optarg, "ext3") == 0)) {
                lit_end = 1;
                sig[0] = 0x53;
                sig[1] = 0xef;
                sig_size = 2;
                offset = 56;
                bs = 512;
            }
            else if ((strcmp(optarg, "dospart") == 0) ||
                     (strcmp(optarg, "fat") == 0) ||
                     (strcmp(optarg, "ntfs") == 0)) {
                lit_end = 1;
                sig[0] = 0x55;
                sig[1] = 0xaa;
                sig_size = 2;
                offset = 510;
                bs = 512;
            }
            else if (strcmp(optarg, "ufs1") == 0) {
                lit_end = 1;
                sig[0] = 0x54;
                sig[1] = 0x19;
                sig[2] = 0x01;
                sig[3] = 0x00;
                sig_size = 4;
                /* Located 1372 into SB */
                offset = 348;
                bs = 512;
            }
            else if (strcmp(optarg, "ufs2") == 0) {
                lit_end = 1;
                sig[0] = 0x19;
                sig[1] = 0x01;
                sig[2] = 0x54;
                sig[3] = 0x19;
                sig_size = 4;
                /* Located 1372 into SB */
                offset = 348;
                bs = 512;
            }
            else if (strcmp(optarg, "hfs+") == 0) {
                lit_end = 1;
                sig[0] = 0x48;
                sig[1] = 0x2b;
                sig[2] = 0x00;
                sig[3] = 0x04;
                sig_size = 4;
                /* Located 1024 into image */
                offset = 0;
                bs = 512;
            }
            else if (strcmp(optarg, "hfs") == 0) {
                lit_end = 1;
                sig[0] = 0x42;
                sig[1] = 0x44;
                sig_size = 2;
                /* Located 1024 into image */
                offset = 0;
                bs = 512;
            }
            else {
                fprintf(stderr, "Invalid template\n");
                exit(1);
            }
            break;

        case 'V':
            tsk_version_print(stdout);
            exit(0);
        default:
            usage();
        }
    }


    /* If we didn't get a template then check the cmd line */
    if (sig_size == 0) {
        if (optind + 1 > argc) {
            usage();
        }
        /* Get the hex value */
        sig_size = 0;
        for (i = 0; i < 9; i++) {
            uint8_t tmp;
            tmp = argv[optind][i];

            if (tmp == 0) {
                if (i % 2) {
                    fprintf(stderr,
                            "Invaild signature - full bytes only\n");
                    exit(1);
                }
                break;
            }

            /* Digit */
            if ((tmp >= 0x30) && (tmp <= 0x39)) {
                tmp -= 0x30;
            }
            /* lowercase a-f */
            else if ((tmp >= 0x61) && (tmp <= 0x66)) {
                tmp -= 0x57;
            }
            else if ((tmp >= 0x41) && (tmp <= 0x46)) {
                tmp -= 0x37;
            }
            else {
                fprintf(stderr, "Invalid signature value: %c\n", tmp);
                exit(1);
            }

            /* big nibble */
            if (0 == (i % 2)) {
                sig[sig_size] = 16 * tmp;
            }
            else {
                sig[sig_size] += tmp;
                sig_size++;
            }
        }
        optind++;

        /* Check the signature length */
        if (i == 9) {
            fprintf(stderr,
                    "Error: Maximum supported signature size is 4 bytes\n");
            exit(1);
        }


        /* Need to switch order */
        if (lit_end) {
            uint8_t tmp;

            if (sig_size == 2) {
                tmp = sig[1];
                sig[1] = sig[0];
                sig[0] = tmp;
            }
            else if (sig_size == 3) {
                tmp = sig[2];
                sig[2] = sig[0];
                sig[0] = tmp;
            }
            else if (sig_size == 4) {
                tmp = sig[3];
                sig[3] = sig[0];
                sig[0] = tmp;

                tmp = sig[2];
                sig[2] = sig[1];
                sig[1] = tmp;
            }
        }
    }

    if (offset < 0) {
        fprintf(stderr, "Error: negative offset\n");
        exit(1);
    }


    /* Check that the signature and offset are not larger than a block */
    if ((offset + sig_size) > bs) {
        fprintf(stderr,
                "Error: The offset and signature sizes are greater than the block size\n");
        exit(1);
    }

    /* If our signature crosses the 512 boundary, then read 1k at a time */
    if ((offset / 512) != ((offset + sig_size - 1) / 512)) {
        read_size = 1024;
    }

    rel_offset = offset % 512;


    /* Get the image */
    if (optind + 1 != argc) {
        usage();
    }

    fd = open(argv[optind], O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "error opening: %s\n", argv[optind]);
        exit(1);
    }

    /* Seek to the correct block */
    if (offset > 512) {
        if (-1 == lseek(fd, (offset / 512) * 512, SEEK_SET)) {
            fprintf(stderr, "error doing initial seek\n");
            exit(1);
        }
    }


    /* Make a version that can be more easily printed */
    for (i = 0; i < sig_size; i++) {
        sig_print |= (sig[i] << ((sig_size - 1 - i) * 8));
    }

    printf("Block size: %d  Offset: %d  Signature: %X\n", bs, offset,
           sig_print);

    /* Loop through by blocks  - we will read in block sized chunks
     * so that we can be used on raw devices 
     */
    prev_hit = -1;
    for (i = 0;; i++) {
        int retval;

        /* Read the signature area */
        retval = read(fd, (void *) block, read_size);
        if (retval == 0)
            break;

        else if (retval == -1) {
            fprintf(stderr, "error reading bytes %lu\n",
                    (unsigned long) i);
            exit(1);
        }

        /* Check the sig */
        if ((block[rel_offset] == sig[0]) &&
            ((sig_size < 2) || (block[rel_offset + 1] == sig[1])) &&
            ((sig_size < 3) || (block[rel_offset + 2] == sig[2])) &&
            ((sig_size < 4) || (block[rel_offset + 3] == sig[3]))) {
            if (prev_hit == -1)
                printf("Block: %lu (-)\n", (unsigned long) i);
            else
                printf("Block: %lu (+%lu)\n", (unsigned long) i,
                       (unsigned long) (i - prev_hit));

            prev_hit = i;
        }

        /* Seek ahead another block */
        if (-1 == lseek(fd, bs - read_size, SEEK_CUR)) {
            break;
        }
    }

    close(fd);
    exit(0);
}
