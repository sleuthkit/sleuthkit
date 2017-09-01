/*
** blkcat
** The  Sleuth Kit
**
** Given an image , block number, and size, display the contents
** of the block to stdout.
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
** TCTUTILs
** Copyright (c) 2001 Brian Carrier.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/

#include "tsk_fs_i.h"
#include <ctype.h>

/**
 * \file dcat_lib.c
 * Contains the library API functions used by the TSK blkcat command
 * line tool.
 */


/**
 * \internal
 * Print block statistics to stdout
 *
 * @param fs File system to analyze
 */
static void
stats(TSK_FS_INFO * fs)
{
    tsk_printf("%d: Size of Addressable Unit\n", fs->block_size);
}


/**
 * Read a specific number of blocks and print the contents to STDOUT
 *
 * @param fs File system to analyze
 * @param lclflags flags
 * @param addr Starting block address to read from
 * @param read_num_units Number of blocks to read
 *
 * @return 1 on error and 0 on success
 */
uint8_t
tsk_fs_blkcat(TSK_FS_INFO * fs, TSK_FS_BLKCAT_FLAG_ENUM lclflags,
    TSK_DADDR_T addr, TSK_DADDR_T read_num_units)
{
    char *buf;
    int i;

    if (lclflags & TSK_FS_BLKCAT_STAT) {
        stats(fs);
        return 0;
    }

    if (addr + read_num_units - 1 > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_blkcat: requested size is larger than last block in image (%"
            PRIuDADDR ")", fs->last_block);
        return 1;
    }

#ifdef TSK_WIN32
    if (-1 == _setmode(_fileno(stdout), _O_BINARY)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WRITE);
        tsk_error_set_errstr
            ("blkcat_lib: error setting stdout to binary: %s",
            strerror(errno));
        return 1;
    }
#endif

    if (lclflags & TSK_FS_BLKCAT_HTML) {
        tsk_printf("<html>\n");
        tsk_printf("<head>\n");
        tsk_printf("<title>Unit: %" PRIuDADDR "   Size: %" PRIuOFF
            " bytes</title>\n", addr, read_num_units * fs->block_size);
        tsk_printf("</head>\n");
        tsk_printf("<body>\n");

    }

    if ((lclflags & TSK_FS_BLKCAT_HEX) && (lclflags & TSK_FS_BLKCAT_HTML))
        tsk_printf("<table border=0>\n");

    if ((buf = tsk_malloc(fs->block_size)) == NULL)
        return 1;

    for (i = 0; i < read_num_units; i++) {
        ssize_t cnt;

        /* Read the block */
        cnt = tsk_fs_read_block(fs, addr + i, buf, fs->block_size);
        if (cnt != fs->block_size) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr("blkcat: Error reading block at %"
                PRIuDADDR, addr);
            return 1;
        }


        /* do a hexdump like printout */
        if (lclflags & TSK_FS_BLKCAT_HEX) {
            TSK_OFF_T idx1, idx2;

            for (idx1 = 0; idx1 < fs->block_size; idx1 += 16) {

                /* Print the offset */
                if (lclflags & TSK_FS_BLKCAT_HTML)
                    tsk_printf("<tr><td>%" PRIuOFF "</td>",
                        i * fs->block_size + idx1);
                else
                    tsk_printf("%" PRIuOFF "\t",
                        i * fs->block_size + idx1);


                /* Print the hex */
                for (idx2 = 0; idx2 < 16; idx2++) {
                    if ((lclflags & TSK_FS_BLKCAT_HTML)
                        && (0 == (idx2 % 4)))
                        tsk_printf("<td>");

                    tsk_printf("%.2x", buf[idx2 + idx1] & 0xff);

                    if (3 == (idx2 % 4)) {
                        if (lclflags & TSK_FS_BLKCAT_HTML)
                            tsk_printf("</td>");
                        else
                            tsk_printf(" ");
                    }
                }

                /* Print the ASCII */
                tsk_printf("\t");
                for (idx2 = 0; idx2 < 16; idx2++) {
                    if ((lclflags & TSK_FS_BLKCAT_HTML)
                        && (0 == (idx2 % 4)))
                        tsk_printf("<td>");

                    if ((isascii((int) buf[idx2 + idx1])) &&
                        (!iscntrl((int) buf[idx2 + idx1])))
                        tsk_printf("%c", buf[idx2 + idx1]);
                    else
                        tsk_printf(".");

                    if (3 == (idx2 % 4)) {
                        if (lclflags & TSK_FS_BLKCAT_HTML)
                            tsk_printf("</td>");
                        else
                            tsk_printf(" ");
                    }
                }

                if (lclflags & TSK_FS_BLKCAT_HTML)
                    tsk_printf("</tr>");
                tsk_printf("\n");
            }
        }


        /* print in all ASCII */
        else if (lclflags & TSK_FS_BLKCAT_ASCII) {
            TSK_OFF_T idx;
            for (idx = 0; idx < fs->block_size; idx++) {

                if ((isprint((int) buf[idx]))
                    || (buf[idx] == '\t')) {
                    tsk_printf("%c", buf[idx]);
                }
                else if ((buf[idx] == '\n')
                    || (buf[idx] == '\r')) {
                    if (lclflags & TSK_FS_BLKCAT_HTML)
                        tsk_printf("<br>");
                    tsk_printf("%c", buf[idx]);
                }
                else
                    tsk_printf(".");
            }
        }

        /* print raw */
        else {
            if (fwrite(buf, fs->block_size, 1, stdout) != 1) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_WRITE);
                tsk_error_set_errstr
                    ("blkcat_lib: error writing to stdout: %s",
                    strerror(errno));
                free(buf);
                return 1;
            }
        }
    }

    free(buf);

    if (lclflags & TSK_FS_BLKCAT_HEX) {
        if (lclflags & TSK_FS_BLKCAT_HTML)
            tsk_printf("</table>\n");
        else
            tsk_printf("\n");
    }
    else if (lclflags & TSK_FS_BLKCAT_ASCII) {
        if (lclflags & TSK_FS_BLKCAT_HTML)
            tsk_printf("<br>");
        tsk_printf("\n");
    }
    else {
        if (lclflags & TSK_FS_BLKCAT_HTML)
            tsk_printf("<br>");
    }

    if (lclflags & TSK_FS_BLKCAT_HTML)
        tsk_printf("</body>\n</html>\n");

    return 0;
}
