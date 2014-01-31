/*
** The Sleuth Kit
**
** This software is subject to the IBM Public License ver. 1.0,
** which was displayed prior to download and is included in the readme.txt
** file accompanying the Sleuth Kit files.  It may also be requested from:
** Crucial Security Inc.
** 14900 Conference Center Drive
** Chantilly, VA 20151
**
** Wyatt Banks [wbanks@crucialsecurity.com]
** Copyright (c) 2005 Crucial Security Inc.  All rights reserved.
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
** Copyright (c) 2007-2011 Brian Carrier.  All rights reserved
**
** Copyright (c) 1997,1998,1999, International Business Machines
** Corporation and others. All Rights Reserved.
*/
/* TCT
 * LICENSE
 *      This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *      Wietse Venema
 *      IBM T.J. Watson Research
 *      P.O. Box 704
 *      Yorktown Heights, NY 10598, USA
 --*/
/*
** You may distribute the Sleuth Kit, or other software that incorporates
** part of all of the Sleuth Kit, in object code form under a license agreement,
** provided that:
** a) you comply with the terms and conditions of the IBM Public License
**    ver 1.0; and
** b) the license agreement
**     i) effectively disclaims on behalf of all Contributors all warranties
**        and conditions, express and implied, including warranties or
**        conditions of title and non-infringement, and implied warranties
**        or conditions of merchantability and fitness for a particular
**        purpose.
**    ii) effectively excludes on behalf of all Contributors liability for
**        damages, including direct, indirect, special, incidental and
**        consequential damages such as lost profits.
**   iii) states that any provisions which differ from IBM Public License
**        ver. 1.0 are offered by that Contributor alone and not by any
**        other party; and
**    iv) states that the source code for the program is available from you,
**        and informs licensees how to obtain it in a reasonable manner on or
**        through a medium customarily used for software exchange.
**
** When the Sleuth Kit or other software that incorporates part or all of
** the Sleuth Kit is made available in source code form:
**     a) it must be made available under IBM Public License ver. 1.0; and
**     b) a copy of the IBM Public License ver. 1.0 must be included with
**        each copy of the program.
*/

/**
 * \file iso9660.c
 * Contains the internal TSK ISO9660 file system code to handle basic file
 * system processing for opening file system, processing sectors, and directory entries.
 */

#include "tsk_fs_i.h"
#include "tsk_iso9660.h"
#include <ctype.h>


/* free all memory used by inode linked list */
static void
iso9660_inode_list_free(TSK_FS_INFO * fs)
{
    ISO_INFO *iso = (ISO_INFO *) fs;
    iso9660_inode_node *tmp;

    while (iso->in_list) {
        tmp = iso->in_list;
        iso->in_list = iso->in_list->next;
        free(tmp);
    }
    iso->in_list = NULL;
}


/**
 * Process the System Use Sharing Protocol (SUSP) data.  Typically,
 * rockridge data are stored in this.
 *
 * @param fs File system to process
 * @param buf Buffer of data to process
 * @param count Length of buffer in bytes.
 * @param hFile File handle to print details to  (or NULL for no printing)
 * @returns NULL on error
 */
static rockridge_ext *
parse_susp(TSK_FS_INFO * fs, char *buf, int count, FILE * hFile)
{
    rockridge_ext *rr;
    ISO_INFO *iso = (ISO_INFO *) fs;

    char *end = buf + count - 1;

    if (tsk_verbose)
        tsk_fprintf(stderr, "parse_susp: count is: %d\n", count);

    // allocate the output data structure
    rr = (rockridge_ext *) tsk_malloc(sizeof(rockridge_ext));
    if (rr == NULL) {
        return NULL;
    }

    while ((uintptr_t)buf + sizeof(iso9660_susp_head) <= (uintptr_t)end) {
        iso9660_susp_head *head = (iso9660_susp_head *) buf;

        if (buf + head->len - 1 > end)
            break;

        /* Identify the entry type -- listed in the order
         * that they are listed in the specs */

        // SUSP Continuation Entry 
        if ((head->sig[0] == 'C') && (head->sig[1] == 'E')) {
            iso9660_susp_ce *ce = (iso9660_susp_ce *) buf;

            if ((uintptr_t)buf + sizeof(iso9660_susp_ce) - 1 > (uintptr_t)end) {
                if (tsk_verbose) 
                    tsk_fprintf(stderr, "parse_susp: not enough room for CE structure\n");
                break;
            }

            if (hFile) {
                fprintf(hFile, "CE Entry\n");
                fprintf(hFile, "* Block: %" PRIu32 "\n",
                    tsk_getu32(fs->endian, ce->blk_m));
                fprintf(hFile, "* Offset: %" PRIu32 "\n",
                    tsk_getu32(fs->endian, ce->offset_m));
                fprintf(hFile, "* Len: %" PRIu32 "\n",
                    tsk_getu32(fs->endian, ce->celen_m));
            }

            // read the continued buffer and parse it
            if ((tsk_getu32(fs->endian, ce->blk_m) < fs->last_block) &&
                (tsk_getu32(fs->endian, ce->offset_m) < fs->block_size)) {
                ssize_t cnt;
                TSK_OFF_T off;
                char *buf2;

                off =
                    tsk_getu32(fs->endian,
                    ce->blk_m) * fs->block_size + tsk_getu32(fs->endian,
                    ce->offset_m);
                buf2 =
                    (char *) tsk_malloc(tsk_getu32(fs->endian,
                        ce->celen_m));

                if (buf2 != NULL) {
                    cnt =
                        tsk_fs_read(fs, off, buf2,
                        tsk_getu32(fs->endian, ce->celen_m));
                    if (cnt == tsk_getu32(fs->endian, ce->celen_m)) {
                        parse_susp(fs, buf2, (int) cnt, hFile);
                    }
                    else if (tsk_verbose) {
                        fprintf(stderr,
                            "parse_susp: error reading CE entry\n");
                        tsk_error_print(stderr);
                        tsk_error_reset();
                    }
                    free(buf2);
                }
                else {
                    if (tsk_verbose)
                        fprintf(stderr,
                            "parse_susp: error allocating memory to process CE entry\n");
                    tsk_error_reset();
                }
            }
            else {
                if (tsk_verbose)
                    fprintf(stderr,
                        "parse_susp: CE offset or block too large to process\n");
            }

            buf += head->len;
        }
        // SUSP Padding Entry
        else if ((head->sig[0] == 'P') && (head->sig[1] == 'D')) {
            if (hFile) {
                fprintf(hFile, "PD Entry\n");
            }
            buf += head->len;
        }
        // SUSP Sharing Protocol Entry -- we ignore
        else if ((head->sig[0] == 'S') && (head->sig[1] == 'P')) {
            iso9660_susp_sp *sp = (iso9660_susp_sp *) buf;
            if (hFile) {
                fprintf(hFile, "SP Entry\n");
                fprintf(hFile, "* SKip Len: %d\n", sp->skip);
            }
            buf += head->len;
        }
        // SUSP System Terminator
        else if ((head->sig[0] == 'S') && (head->sig[1] == 'T')) {
            if (hFile) {
                fprintf(hFile, "ST Entry\n");
            }
            buf += head->len;
        }
        // SUSP Extention Registration -- not used
        else if ((head->sig[0] == 'E') && (head->sig[1] == 'R')) {
            iso9660_susp_er *er = (iso9660_susp_er *) buf;
            if (hFile) {
                char buf[258];
                fprintf(hFile, "ER Entry\n");

                memcpy(buf, er->ext_id, er->len_id);
                buf[er->len_id] = '\0';
                fprintf(hFile, "* Extension ID: %s\n", buf);

                memcpy(buf, er->ext_id + er->len_id, er->len_des);
                buf[er->len_des] = '\0';
                fprintf(hFile, "* Extension Descriptor: %s\n", buf);

                memcpy(buf, er->ext_id + er->len_id + er->len_des,
                    er->len_src);
                buf[er->len_src] = '\0';
                fprintf(hFile, "* Extension Spec Source: %s\n", buf);
            }
            buf += head->len;
        }
        // SUSP Extention Sigs  -- not used
        else if ((head->sig[0] == 'E') && (head->sig[1] == 'S')) {
            if (hFile) {
                fprintf(hFile, "ES Entry\n");
            }
            buf += head->len;
        }

        /*
         * Rock Ridge Extensions
         */

        /* POSIX file attributes */
        else if ((head->sig[0] == 'P') && (head->sig[1] == 'X')) {
            iso9660_rr_px_entry *rr_px;

            if ((uintptr_t)buf + sizeof(iso9660_rr_px_entry) - 1> (uintptr_t)end) {
                if (tsk_verbose) 
                    tsk_fprintf(stderr, "parse_susp: not enough room for POSIX structure\n");
                break;
            }

            rr_px = (iso9660_rr_px_entry *) buf;
            rr->uid = tsk_getu32(fs->endian, rr_px->uid_m);
            rr->gid = tsk_getu32(fs->endian, rr_px->gid_m);
            rr->mode = tsk_getu16(fs->endian, rr_px->mode_m);
            rr->nlink = tsk_getu32(fs->endian, rr_px->links_m);
            if (hFile) {
                fprintf(hFile, "PX Entry\n");
                fprintf(hFile, "* UID: %" PRIuUID "\n", rr->uid);
                fprintf(hFile, "* GID: %" PRIuGID "\n", rr->gid);
                fprintf(hFile, "* Mode: %d\n", rr->mode);
                fprintf(hFile, "* Links: %" PRIu32 "\n", rr->nlink);
            }
            buf += head->len;
        }

        // RR - device information
        else if ((head->sig[0] == 'P') && (head->sig[1] == 'N')) {
            iso9660_rr_pn_entry *rr_pn = (iso9660_rr_pn_entry *) buf;
            if (hFile) {
                fprintf(hFile, "PN Entry\n");
                fprintf(hFile, "* Device ID High: %" PRIu32 "\n",
                    tsk_getu32(fs->endian, rr_pn->dev_h_m));
                fprintf(hFile, "* Device ID Low: %" PRIu32 "\n",
                    tsk_getu32(fs->endian, rr_pn->dev_l_m));
            }
            buf += head->len;
        }

        // RR - symbolic link
        else if ((head->sig[0] == 'S') && (head->sig[1] == 'L')) {
            //iso9660_rr_sl_entry *rr_sl = (iso9660_rr_sl_entry *) buf;
            if (hFile) {
                fprintf(hFile, "SL Entry\n");
            }
            buf += head->len;
        }
        // RR -- alternative name
        else if ((head->sig[0] == 'N') && (head->sig[1] == 'M')) {
            iso9660_rr_nm_entry *rr_nm;

            if ((uintptr_t)buf + sizeof(iso9660_rr_nm_entry) - 1> (uintptr_t)end) {
                if (tsk_verbose) 
                    tsk_fprintf(stderr, "parse_susp: not enough room for RR alternative name structure\n");
                break;
            }

            rr_nm = (iso9660_rr_nm_entry *) buf;

            if ((uintptr_t)&rr_nm->name[0] + (int) rr_nm->len - 5 - 1> (uintptr_t)end) {
                if (tsk_verbose) 
                    tsk_fprintf(stderr, "parse_susp: not enough room for RR alternative name\n");
                break;
            }

            strncpy(rr->fn, &rr_nm->name[0], (int) rr_nm->len - 5);
            rr->fn[(int) rr_nm->len - 5] = '\0';
            if (hFile) {
                fprintf(hFile, "NM Entry\n");
                fprintf(hFile, "* %s\n", rr->fn);
            }
            buf += head->len;
        }
        // RR - relocated directory
        else if ((head->sig[0] == 'C') && (head->sig[1] == 'L')) {
            if (hFile) {
                fprintf(hFile, "CL Entry\n");
            }
            buf += head->len;
        }
        // RR - parent of relocated directory
        else if ((head->sig[0] == 'P') && (head->sig[1] == 'L')) {
            if (hFile) {
                fprintf(hFile, "PL Entry\n");
            }
            buf += head->len;
        }
        // RR - relocation signal
        else if ((head->sig[0] == 'R') && (head->sig[1] == 'E')) {
            if (hFile) {
                fprintf(hFile, "RE Entry\n");
            }
            buf += head->len;
        }
        // RR - time stamps
        else if ((head->sig[0] == 'T') && (head->sig[1] == 'F')) {
            if (hFile) {
                fprintf(hFile, "TF Entry\n");
            }
            buf += head->len;
        }
        // RR - sparse file
        else if ((head->sig[0] == 'S') && (head->sig[1] == 'F')) {
            if (hFile) {
                fprintf(hFile, "SF Entry\n");
            }
            buf += head->len;
        }

        /* RR is a system use field indicating RockRidge, but not part of RockRidge */
        else if ((head->sig[0] == 'R') && (head->sig[1] == 'R')) {
            iso->rr_found = 1;
            if (hFile) {
                fprintf(hFile, "RR Entry\n");
            }
            buf += head->len;
        }

        else {
            buf += 2;
            if ((uintptr_t) buf % 2)
                buf--;
        }
    }

    return rr;
}


///////////////////////////////////////////////////////////////////////////
// The following functions are responsible for loading all of the file metadata into memory.
// The process is that the Path table is processed first.  It contains an entry for each
// directory.  That info is then used to locate the directory contents and those contents
// are then processed.
//
// Files do not have a corresponding metadata entry, so we assign them based
// on the order that they are loaded.
///////////////////////////////////////////////////////////////////////////


/* XXX Instead of loading all of the file metadata, we could instead save a mapping
 * between inode number and the byte offset of the metadata (and any other data
 * needed for fast lookups).
 */

/** \internal
 * Process the contents of a directory and load the
 * information about files in that directory into ISO_INFO.  This is called
 * by the methods that process the path table (which contains pointers to the
 * various directories).  The results in ISO_INFO are used to identify the
 * inode address of files found from dent_walk and for file lookups.
 *
 * Type: ISO9660_TYPE_PVD for primary volume descriptor, ISO9660_TYPE_SVD for
 * supplementary volume descriptor (do Joliet utf-8 conversion).
 *
 * @param fs File system to analyze
 * @param a_offs Byte offset of directory start
 * @param count previous file count
 * @param ctype Character set used for the names
 * @param a_fn Name of the directory to use for the "." entry (in UTF-8)
 *
 * @returns total number of files or -1 on error
 */
static int
iso9660_load_inodes_dir(TSK_FS_INFO * fs, TSK_OFF_T a_offs, int count,
    int ctype, const char *a_fn, uint8_t is_first)
{
    ISO_INFO *iso = (ISO_INFO *) fs;
    int s_cnt = 1;              // count of sectors needed for dir
    TSK_OFF_T s_offs = a_offs;  // offset for sector reads
    int i;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "iso9660_load_inodes_dir: offs: %" PRIuOFF
            " count: %d ctype: %d fn: %s\n", a_offs, count, ctype, a_fn);

    // cycle through each sector -- entries will not cross them
    for (i = 0; i < s_cnt; i++) {
        ssize_t cnt1;
        int b_offs;             // offset in buffer
        char buf[ISO9660_SSIZE_B];

        cnt1 = tsk_fs_read(fs, s_offs, buf, ISO9660_SSIZE_B);
        if (cnt1 != ISO9660_SSIZE_B) {
            if (cnt1 >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("iso_get_dentries");
            return -1;
        }

        /* process the directory entries */
        for (b_offs = 0; b_offs < ISO9660_SSIZE_B;) {
            iso9660_inode_node *in_node = NULL;
            iso9660_dentry *dentry;

            dentry = (iso9660_dentry *) & buf[b_offs];

            if (dentry->entry_len == 0) {
                b_offs += 2;
                continue;
            }
            // sanity checks on entry_len
            else if (dentry->entry_len < sizeof(iso9660_dentry)) {
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                                "iso9660_load_inodes_dir: entry length is shorter than dentry, bailing\n");
                break;
            }
            else if (b_offs + dentry->entry_len > ISO9660_SSIZE_B) {
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                                "iso9660_load_inodes_dir: entry is longer than sector, bailing\n");
                break;
            }

            /* when processing the other volume descriptor directories, we ignore the
             * directories because we have no way of detecting if it is a duplicate of
             * a directory from the other volume descriptor (they use different blocks).
             * We will see the contents of this directory from the path table anyway. */
            if ((dentry->flags & ISO9660_FLAG_DIR) && (is_first == 0)) {
                b_offs += dentry->entry_len;
                continue;
            }

            // allocate a node for this entry
            in_node = (iso9660_inode_node *)
                tsk_malloc(sizeof(iso9660_inode_node));
            if (in_node == NULL) {
                return -1;
            }

            // the first entry is for the current directory
            if ((i == 0) && (b_offs == 0)) {
                // should have no name or '.'
                if (dentry->fi_len > 1) {
                    if (tsk_verbose)
                        tsk_fprintf(stderr,
                                    "iso9660_load_inodes_dir: first entry has name length > 1\n");
                    free(in_node);
                    in_node = NULL;
                    b_offs += dentry->entry_len;
                    continue;
                }

                /* find how many more sectors are in the directory */
                s_cnt =
                    tsk_getu32(fs->endian,
                    dentry->data_len_m) / ISO9660_SSIZE_B;
                if (tsk_verbose)
                    tsk_fprintf(stderr, "iso9660_load_inodes_dir: %d number of additional sectors\n", s_cnt);
                
                // @@@ Should have a sanity check here on s_cnt, but I'm not sure what it would be...

                /* use the specified name instead of "." */
                if (strlen(a_fn) > ISO9660_MAXNAMLEN_STD) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_ARG);
                    tsk_error_set_errstr
                        ("iso9660_load_inodes_dir: Name argument specified is too long");
                    return -1;
                }
                strncpy(in_node->inode.fn, a_fn, ISO9660_MAXNAMLEN_STD + 1);

                /* for all directories except the root, we skip processing the "." and ".." entries because
                 * they duplicate the other entires and the dent_walk code will rely on the offset
                 * for the entry in the parent directory. */
                if (count != 0) {
                    free(in_node);
                    in_node = NULL;
                    b_offs += dentry->entry_len;
                    dentry = (iso9660_dentry *) & buf[b_offs];
                    b_offs += dentry->entry_len;
                    continue;
                }
            }
            else {
                char *file_ver;
                
                // the entry has a UTF-16 name
                if (ctype == ISO9660_CTYPE_UTF16) {
                    UTF16 *name16;
                    UTF8 *name8;
                    int retVal;

                    if (dentry->entry_len < sizeof(iso9660_dentry) + dentry->fi_len) {
                        if (tsk_verbose)
                            tsk_fprintf(stderr,
                                        "iso9660_load_inodes_dir: UTF-16 name length is too large, bailing\n");
                        break;
                    }

                    name16 =
                        (UTF16 *) & buf[b_offs + sizeof(iso9660_dentry)];
                    // the name is in UTF-16 BE -- convert to LE if needed
                    if (fs->endian & TSK_LIT_ENDIAN) {
                        int a;

                        for (a = 0; a < dentry->fi_len / 2; a++) {
                            name16[a] = ((name16[a] & 0xff) << 8) +
                                ((name16[a] & 0xff00) >> 8);
                        }
                    }
                    name8 = (UTF8 *) in_node->inode.fn;

                    retVal =
                        tsk_UTF16toUTF8(fs->endian,
                        (const UTF16 **) &name16,
                        (UTF16 *) & buf[b_offs + sizeof(iso9660_dentry) +
                            dentry->fi_len], &name8,
                        (UTF8 *) ((uintptr_t) & in_node->inode.
                            fn[ISO9660_MAXNAMLEN_STD]),
                        TSKlenientConversion);
                    if (retVal != TSKconversionOK) {
                        if (tsk_verbose)
                            tsk_fprintf(stderr,
                                "iso9660_load_inodes_dir: Error converting Joliet name to UTF8: %d",
                                retVal);
                        in_node->inode.fn[0] = '\0';
                    }
                    *name8 = '\0';
                }

                else if (ctype == ISO9660_CTYPE_ASCII) {
                    int readlen;

                    readlen = dentry->fi_len;
                    if (readlen > ISO9660_MAXNAMLEN_STD)
                        readlen = ISO9660_MAXNAMLEN_STD;
                    
                    if (dentry->entry_len < sizeof(iso9660_dentry) + dentry->fi_len) {
                        if (tsk_verbose)
                            tsk_fprintf(stderr,
                                        "iso9660_load_inodes_dir: ASCII name length is too large, bailing\n");
                        break;
                    }


                    memcpy(in_node->inode.fn,
                        &buf[b_offs + sizeof(iso9660_dentry)], readlen);
                    in_node->inode.fn[readlen] = '\0';
                }
                else {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_ARG);
                    tsk_error_set_errstr
                        ("Invalid ctype in iso9660_load_inodes_dir");
                    return -1;
                }

                // the version is embedded in the name
                file_ver = strchr(in_node->inode.fn, ';');
                if (file_ver) {
                    in_node->inode.version = atoi(file_ver + 1);
                    *file_ver = '\0';
                    file_ver = NULL;
                }

                // if no extension, remove the final '.'
                if (in_node->inode.fn[strlen(in_node->inode.fn) - 1] ==
                    '.')
                    in_node->inode.fn[strlen(in_node->inode.fn) - 1] =
                        '\0';
                
                
                if (strlen(in_node->inode.fn) == 0) {
                    if (tsk_verbose)
                        tsk_fprintf(stderr,
                                    "iso9660_load_inodes_dir: length of name after processing is 0. bailing\n");
                    break;
                    
                }
            }

            

            // copy the raw dentry data into the node
            memcpy(&(in_node->inode.dr), dentry, sizeof(iso9660_dentry));

            in_node->inode.ea = NULL;

            // sanity checks
            if (tsk_getu32(fs->endian, dentry->ext_loc_m) > fs->last_block) {
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                                "iso9660_load_inodes_dir: file starts past end of image (%"PRIu32"). bailing\n",
                                tsk_getu32(fs->endian, dentry->ext_loc_m));
                break;
            }
            in_node->offset =
                tsk_getu32(fs->endian, dentry->ext_loc_m) * fs->block_size;
            
            if (tsk_getu32(fs->endian, in_node->inode.dr.data_len_m) + in_node->offset > fs->block_count * fs->block_size) {
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                                "iso9660_load_inodes_dir: file ends past end of image (%"PRIu32" bytes). bailing\n",
                                tsk_getu32(fs->endian, in_node->inode.dr.data_len_m) + in_node->offset);
                break;
            }
            /* record size to make sure fifos show up as unique files */
            in_node->size =
                tsk_getu32(fs->endian, in_node->inode.dr.data_len_m);

            
            in_node->ea_size = dentry->ext_len;
            in_node->dentry_offset = s_offs + b_offs;

            if (is_first)
                in_node->inode.is_orphan = 0;
            else
                in_node->inode.is_orphan = 1;

            in_node->inum = count++;

            /* RockRidge data is located after the name.  See if it is there.  */
            if ((int) (dentry->entry_len - sizeof(iso9660_dentry) -
                    dentry->fi_len) > 1) {
                int extra_bytes =
                    dentry->entry_len - sizeof(iso9660_dentry) -
                    dentry->fi_len;

                in_node->inode.rr =
                    parse_susp(fs,
                    &buf[b_offs + sizeof(iso9660_dentry) + dentry->fi_len],
                    extra_bytes, NULL);
                if (in_node->inode.rr == NULL) {
                    if (tsk_verbose)
                        tsk_fprintf(stderr,
                                    "iso9660_load_inodes_dir: parse_susp returned error (%s). bailing\n", tsk_error_get());
                    break;
                }
                
                in_node->inode.susp_off =
                    b_offs + sizeof(iso9660_dentry) + dentry->fi_len +
                    s_offs;
                in_node->inode.susp_len = extra_bytes;
            }
            else {
                in_node->inode.rr = NULL;
                in_node->inode.susp_off = 0;
                in_node->inode.susp_len = 0;
            }

            /* add inode to the list */
            if (iso->in_list) {
                iso9660_inode_node *tmp, *prev_tmp;

                for (tmp = iso->in_list; tmp; tmp = tmp->next) {
                    /* When processing the "first" volume descriptor, all entries get added to the list.
                     * for the later ones, we skip duplicate ones that have content (blocks) that overlaps
                     * with entries from a previous volume descriptor. */
                    if ((in_node->offset == tmp->offset)
                        && (in_node->size == tmp->size)
                        && (in_node->size) && (is_first == 0)) {
                        
                        // if we found rockridge, then update original if needed.
                        if (in_node->inode.rr) {
                            if (tmp->inode.rr == NULL) {
                                tmp->inode.rr = in_node->inode.rr;
                                tmp->inode.susp_off =
                                    in_node->inode.susp_off;
                                tmp->inode.susp_len =
                                    in_node->inode.susp_len;
                                in_node->inode.rr = NULL;
                            }
                            else {
                                free(in_node->inode.rr);
                                in_node->inode.rr = NULL;
                            }
                        }

                        if (tsk_verbose)
                            tsk_fprintf(stderr,
                                "iso9660_load_inodes_dir: Removing duplicate entry for: %s (orig name: %s start: %d size: %d)\n",
                                in_node->inode.fn, tmp->inode.fn, in_node->offset, in_node->size);
                        free(in_node);
                        in_node = NULL;
                        count--;
                        break;
                    }
                    prev_tmp = tmp;
                }

                // add it to the end (if we didn't get rid of it above)
                if (in_node) {
                    prev_tmp->next = in_node;
                    in_node->next = NULL;
                }
            }
            else {
                iso->in_list = in_node;
                in_node->next = NULL;
            }

            // skip two entries if this was the root directory (the . and ..).
            if ((i == 0) && (b_offs == 0) && (count == 1)) {
                b_offs += dentry->entry_len;
                dentry = (iso9660_dentry *) & buf[b_offs];
            }
            b_offs += dentry->entry_len;
        }
        s_offs += cnt1;
    }
    return count;
}


/**
 * Process the path table for a joliet secondary volume descriptor
 * and load all of the files pointed to it.
 * The path table contains an entry for each directory.  This code
 * then locates each of the diretories and proceses the contents.
 *
 * @param fs File system to process
 * @param svd Pointer to the secondary volume descriptor
 * @param count Current count of inodes
 * @returns updated count of inodes or -1 on error
 */
static int
iso9660_load_inodes_pt_joliet(TSK_FS_INFO * fs, iso9660_svd * svd,
    int count, uint8_t is_first)
{
    TSK_OFF_T pt_offs;          /* offset of where we are in path table */
    size_t pt_len;              /* bytes left in path table */

    // get the location of the path table
    pt_offs =
        (TSK_OFF_T) (tsk_getu32(fs->endian,
            svd->pt_loc_m) * fs->block_size);
    pt_len = tsk_getu32(fs->endian, svd->pt_size_m);

    while (pt_len > 0) {
        char utf16_buf[ISO9660_MAXNAMLEN_JOL + 1];      // UTF-16 name from img
        char utf8buf[2 * ISO9660_MAXNAMLEN_JOL + 1];    // UTF-8 version of name
        int readlen;
        TSK_OFF_T extent;       /* offset of extent for current directory */
        path_table_rec dir;
        int retVal;
        ssize_t cnt;

        UTF16 *name16;
        UTF8 *name8;

        // Read the path table entry
        cnt = tsk_fs_read(fs, pt_offs, (char *) &dir, (int) sizeof(dir));
        if (cnt != sizeof(dir)) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("iso9660_load_inodes_pt");
            return -1;
        }
        pt_len -= cnt;
        pt_offs += (TSK_OFF_T) cnt;

        readlen = dir.len_di;
        if (dir.len_di > ISO9660_MAXNAMLEN_JOL)
            readlen = ISO9660_MAXNAMLEN_JOL;

        memset(utf16_buf, 0, ISO9660_MAXNAMLEN_JOL);
        /* get UCS-2 filename for the entry */
        cnt = tsk_fs_read(fs, pt_offs, (char *) utf16_buf, readlen);
        if (cnt != dir.len_di) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("iso_find_inodes");
            return -1;
        }
        pt_len -= cnt;
        pt_offs += (TSK_OFF_T) cnt;

        // ISO stores UTF-16 in BE -- convert to local if we need to
        if (fs->endian & TSK_LIT_ENDIAN) {
            int i;
            for (i = 0; i < cnt; i += 2) {
                char t = utf16_buf[i];
                utf16_buf[i] = utf16_buf[i + 1];
                utf16_buf[i] = t;
            }
        }

        name16 = (UTF16 *) utf16_buf;
        name8 = (UTF8 *) utf8buf;

        retVal = tsk_UTF16toUTF8(fs->endian, (const UTF16 **) &name16,
            (UTF16 *) ((uintptr_t) & utf16_buf[cnt + 1]), &name8,
            (UTF8 *) ((uintptr_t) & utf8buf[2 * ISO9660_MAXNAMLEN_JOL]),
            TSKlenientConversion);
        if (retVal != TSKconversionOK) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "fsstat: Error converting Joliet name to UTF8: %d",
                    retVal);
            utf8buf[0] = '\0';
        }
        *name8 = '\0';

        /* padding byte is there if strlen(file name) is odd */
        if (dir.len_di % 2) {
            pt_len--;
            pt_offs++;
        }

        extent =
            (TSK_OFF_T) (tsk_getu32(fs->endian,
                dir.ext_loc) * fs->block_size);

        // process the directory contents
        count =
            iso9660_load_inodes_dir(fs, extent, count,
            ISO9660_CTYPE_UTF16, utf8buf, is_first);

        if (count == -1) {
            return -1;
        }
    }
    return count;
}

/**
 * Proces the path table and the directories that are listed in it.
 * The files in each directory will be stored in ISO_INFO.
 *
 * @param iso File system to analyze and store results in
 * @returns -1 on error or count of inodes found.
 */
static int
iso9660_load_inodes_pt(ISO_INFO * iso)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & iso->fs_info;
    int count = 0;
    iso9660_svd_node *s;
    iso9660_pvd_node *p;
    char fn[ISO9660_MAXNAMLEN_STD + 1]; /* store current directory name */
    path_table_rec dir;
    TSK_OFF_T pt_offs;          /* offset of where we are in path table */
    size_t pt_len;              /* bytes left in path table */
    TSK_OFF_T extent;           /* offset of extent for current directory */
    ssize_t cnt;
    uint8_t is_first = 1;

    if (tsk_verbose)
        tsk_fprintf(stderr, "iso9660_load_inodes_pt\n");

    /* initialize in case repeatedly called */
    iso9660_inode_list_free(fs);
    iso->in_list = NULL;

    /* The secondary volume descriptor table will contain the
     * longer / unicode files, so we process it first to give them
     * a higher priority */
    for (s = iso->svd; s != NULL; s = s->next) {

        /* Check if this is Joliet -- there are three possible signatures */
        if ((s->svd.esc_seq[0] == 0x25) && (s->svd.esc_seq[1] == 0x2F) &&
            ((s->svd.esc_seq[2] == 0x40) || (s->svd.esc_seq[2] == 0x43)
                || (s->svd.esc_seq[2] == 0x45))) {
            count =
                iso9660_load_inodes_pt_joliet(fs, &(s->svd), count,
                is_first);
            if (count == -1) {
                return -1;
            }
            is_first = 0;
        }
    }


    /* Now look for unique files in the primary descriptors */
    for (p = iso->pvd; p != NULL; p = p->next) {

        pt_offs =
            (TSK_OFF_T) (tsk_getu32(fs->endian,
                p->pvd.pt_loc_m) * fs->block_size);
        pt_len = tsk_getu32(fs->endian, p->pvd.pt_size_m);

        while (pt_len > 0) {
            int readlen;

            /* get next path table entry... */
            cnt = tsk_fs_read(fs, pt_offs, (char *) &dir, sizeof(dir));
            if (cnt != sizeof(dir)) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2("iso_find_inodes");
                return -1;
            }
            pt_len -= cnt;
            pt_offs += (TSK_OFF_T) cnt;

            readlen = dir.len_di;
            if (readlen > ISO9660_MAXNAMLEN_STD)
                readlen = ISO9660_MAXNAMLEN_STD;

            /* get directory name, this is the only chance */
            cnt = tsk_fs_read(fs, pt_offs, fn, readlen);
            if (cnt != readlen) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2("iso_find_inodes");
                return -1;
            }
            fn[cnt] = '\0';

            pt_len -= cnt;
            pt_offs += (TSK_OFF_T) cnt;

            /* padding byte is there if strlen(file name) is odd */
            if (dir.len_di % 2) {
                pt_len--;
                pt_offs++;
            }

            extent =
                (TSK_OFF_T) (tsk_getu32(fs->endian,
                    dir.ext_loc) * fs->block_size);

            // process the directory contents
            count =
                iso9660_load_inodes_dir(fs, extent, count,
                ISO9660_CTYPE_ASCII, fn, is_first);

            if (count == -1) {
                return -1;
            }
        }
    }
    return count;
}

/**
 * Load the raw "inode" into the cached buffer (iso->dinode)
 *
 * dinode_load (for now) does not check for extended attribute records...
 * my issue is I dont have an iso9660 image with extended attr recs, so I
 * can't test/debug, etc
 *
 * @returns 1 if not found and 0 on succuss
 */
uint8_t
iso9660_dinode_load(ISO_INFO * iso, TSK_INUM_T inum,
    iso9660_inode * dinode)
{
    iso9660_inode_node *n;

    n = iso->in_list;
    while (n && (n->inum != inum))
        n = n->next;

    if (n) {
        memcpy(dinode, &n->inode, sizeof(iso9660_inode));
        return 0;
    }
    else {
        return 1;
    }
}


static uint16_t
isomode2tskmode(uint16_t a_mode)
{
    uint16_t mode = 0;

    if (a_mode & ISO_EA_IRUSR)
        mode |= TSK_FS_META_MODE_IRUSR;
    if (a_mode & ISO_EA_IWUSR)
        mode |= TSK_FS_META_MODE_IWUSR;
    if (a_mode & ISO_EA_IXUSR)
        mode |= TSK_FS_META_MODE_IXUSR;

    if (a_mode & ISO_EA_IRGRP)
        mode |= TSK_FS_META_MODE_IRGRP;
    if (a_mode & ISO_EA_IWGRP)
        mode |= TSK_FS_META_MODE_IWGRP;
    if (a_mode & ISO_EA_IXGRP)
        mode |= TSK_FS_META_MODE_IXGRP;

    if (a_mode & ISO_EA_IROTH)
        mode |= TSK_FS_META_MODE_IROTH;
    if (a_mode & ISO_EA_IWOTH)
        mode |= TSK_FS_META_MODE_IWOTH;
    if (a_mode & ISO_EA_IXOTH)
        mode |= TSK_FS_META_MODE_IXOTH;

    return mode;
}

/**
 * Copies cached disk inode into generic structure.
 *
 * @returns 1 on error and 0 on success
 */
static uint8_t
iso9660_dinode_copy(ISO_INFO * iso, TSK_FS_META * fs_meta, TSK_INUM_T inum,
    iso9660_inode * dinode)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & iso->fs_info;
    struct tm t;

    if (fs_meta == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("iso9660_dinode_copy: fs_file or meta is NULL");
        return 1;
    }

    fs_meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    if (fs_meta->attr) {
        tsk_fs_attrlist_markunused(fs_meta->attr);
    }

    if (fs_meta->content_len < ISO9660_FILE_CONTENT_LEN) {
        if ((fs_meta =
                tsk_fs_meta_realloc(fs_meta,
                    ISO9660_FILE_CONTENT_LEN)) == NULL) {
            return 1;
        }
    }

    fs_meta->addr = inum;
    fs_meta->size = tsk_getu32(fs->endian, dinode->dr.data_len_m);

    memset(&t, 0, sizeof(struct tm));
    t.tm_sec = dinode->dr.rec_time.sec;
    t.tm_min = dinode->dr.rec_time.min;
    t.tm_hour = dinode->dr.rec_time.hour;
    t.tm_mday = dinode->dr.rec_time.day;
    t.tm_mon = dinode->dr.rec_time.month - 1;
    t.tm_year = dinode->dr.rec_time.year;
    //gmt_hrdiff = iso->dinode->dr.rec_time.gmt_off * 15 / 60;

    fs_meta->crtime = mktime(&t);
    fs_meta->mtime = fs_meta->atime = fs_meta->ctime = 0;
    fs_meta->crtime_nano = fs_meta->mtime_nano = fs_meta->atime_nano =
        fs_meta->ctime_nano = 0;

    if (dinode->dr.flags & ISO9660_FLAG_DIR)
        fs_meta->type = TSK_FS_META_TYPE_DIR;
    else
        fs_meta->type = TSK_FS_META_TYPE_REG;

    if (dinode->ea) {
        fs_meta->uid = tsk_getu32(fs->endian, dinode->ea->uid);
        fs_meta->gid = tsk_getu32(fs->endian, dinode->ea->gid);
        fs_meta->mode =
            isomode2tskmode(tsk_getu16(fs->endian, dinode->ea->mode));
        fs_meta->nlink = 1;
    }
    else {
        fs_meta->uid = 0;
        fs_meta->gid = 0;
        fs_meta->mode = 0;
        fs_meta->nlink = 1;
    }

    ((TSK_DADDR_T *) fs_meta->content_ptr)[0] =
        (TSK_DADDR_T) tsk_getu32(fs->endian, dinode->dr.ext_loc_m);

    // mark files that were found from other volume descriptors as unalloc so that they
    // come up as orphan files.
    if (dinode->is_orphan)
        fs_meta->flags = TSK_FS_META_FLAG_UNALLOC | TSK_FS_META_FLAG_USED;
    else
        fs_meta->flags = TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_USED;
    return 0;
}

static void
iso9660_close(TSK_FS_INFO * fs)
{
    ISO_INFO *iso = (ISO_INFO *) fs;
    iso9660_pvd_node *p;
    iso9660_svd_node *s;

    fs->tag = 0;
    while (iso->pvd != NULL) {
        p = iso->pvd;
        iso->pvd = iso->pvd->next;
        free(p);
    }

    while (iso->svd != NULL) {
        s = iso->svd;
        iso->svd = iso->svd->next;
        free(s);
    }

    tsk_fs_free(fs);
}


static uint8_t
iso9660_inode_lookup(TSK_FS_INFO * fs, TSK_FS_FILE * a_fs_file,
    TSK_INUM_T inum)
{
    ISO_INFO *iso = (ISO_INFO *) fs;
    iso9660_inode *dinode;

    if (tsk_verbose)
        tsk_fprintf(stderr, "iso9660_inode_lookup: iso:"
            " inum: %" PRIuINUM "\n", inum);

    if (a_fs_file == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("iso9660_inode_lookup: fs_file is NULL");
        return 1;
    }

    if (a_fs_file->meta == NULL) {
        if ((a_fs_file->meta =
                tsk_fs_meta_alloc(ISO9660_FILE_CONTENT_LEN)) == NULL)
            return 1;
    }
    else {
        tsk_fs_meta_reset(a_fs_file->meta);
    }

    // see if they are looking for the special "orphans" directory
    if (inum == TSK_FS_ORPHANDIR_INUM(fs)) {
        if (tsk_fs_dir_make_orphan_dir_meta(fs, a_fs_file->meta)) {
            return 1;
        }
        else {
            return 0;
        }
    }
    else {
        /* allocate cache buffers */
        /* dinode */
        dinode = (iso9660_inode *) tsk_malloc(sizeof(iso9660_inode));
        if (dinode == NULL) {
            fs->tag = 0;
            iso9660_close(fs);
            return 1;
        }

        // load the inode into the ISO buffer
        if (iso9660_dinode_load(iso, inum, dinode)) {
            free(dinode);
            return 1;
        }

        // copy into the FS_META structure
        if (iso9660_dinode_copy(iso, a_fs_file->meta, inum, dinode)) {
            free(dinode);
            return 1;
        }
    }

    free(dinode);
    return 0;
}

static uint8_t
iso9660_inode_walk(TSK_FS_INFO * fs, TSK_INUM_T start, TSK_INUM_T last,
    TSK_FS_META_FLAG_ENUM flags, TSK_FS_META_WALK_CB action, void *ptr)
{
    char *myname = "iso9660_inode_walk";
    ISO_INFO *iso = (ISO_INFO *) fs;
    TSK_INUM_T inum, end_inum_tmp;
    TSK_FS_FILE *fs_file;
    int myflags;
    iso9660_inode *dinode;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if (tsk_verbose)
        tsk_fprintf(stderr, "iso9660_inode_walk: "
            " start: %" PRIuINUM " last: %" PRIuINUM " flags: %d"
            " action: %" PRIu64 " ptr: %" PRIu64 "\n",
            start, last, flags, (uint64_t) action, (uint64_t) ptr);

    myflags = TSK_FS_META_FLAG_ALLOC;

    /*
     * Sanity checks.
     */
    if (start < fs->first_inum || start > fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: Start inode:  %" PRIuINUM "", myname,
            start);
        return 1;
    }
    if (last < fs->first_inum || last > fs->last_inum || last < start) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: End inode: %" PRIuINUM "", myname, last);
        return 1;
    }

    /* If ORPHAN is wanted, then make sure that the flags are correct */
    if (flags & TSK_FS_META_FLAG_ORPHAN) {
        flags |= TSK_FS_META_FLAG_UNALLOC;
        flags &= ~TSK_FS_META_FLAG_ALLOC;
        flags |= TSK_FS_META_FLAG_USED;
        flags &= ~TSK_FS_META_FLAG_UNUSED;
    }
    else if (((flags & TSK_FS_META_FLAG_ALLOC) == 0) &&
        ((flags & TSK_FS_META_FLAG_UNALLOC) == 0)) {
        flags |= (TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_UNALLOC);
    }

    /* If neither of the USED or UNUSED flags are set, then set them
     * both
     */
    if (((flags & TSK_FS_META_FLAG_USED) == 0) &&
        ((flags & TSK_FS_META_FLAG_UNUSED) == 0)) {
        flags |= (TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_UNUSED);
    }

    /* If we are looking for orphan files and have not yet filled
     * in the list of unalloc inodes that are pointed to, then fill
     * in the list
     * */
    if ((flags & TSK_FS_META_FLAG_ORPHAN)) {
        if (tsk_fs_dir_load_inum_named(fs) != TSK_OK) {
            tsk_error_errstr2_concat
                ("- iso9660_inode_walk: identifying inodes allocated by file names");
            return 1;
        }
    }


    if ((fs_file = tsk_fs_file_alloc(fs)) == NULL)
        return 1;

    if ((fs_file->meta =
            tsk_fs_meta_alloc(ISO9660_FILE_CONTENT_LEN)) == NULL)
        return 1;

    // we need to handle fs->last_inum specially because it is for the
    // virtual ORPHANS directory.  Handle it outside of the loop.
    if (last == TSK_FS_ORPHANDIR_INUM(fs))
        end_inum_tmp = last - 1;
    else
        end_inum_tmp = last;

    /* allocate cache buffers */
    /* dinode */
    dinode = (iso9660_inode *) tsk_malloc(sizeof(iso9660_inode));
    if (dinode == NULL) {
        fs->tag = 0;
        iso9660_close(fs);
        return 1;
    }
    /*
     * Iterate.
     */
    for (inum = start; inum <= end_inum_tmp; inum++) {
        int retval;
        if (iso9660_dinode_load(iso, inum, dinode)) {
            tsk_fs_file_close(fs_file);
            free(dinode);
            return 1;
        }

        if (iso9660_dinode_copy(iso, fs_file->meta, inum, dinode)) {
            free(dinode);
            return 1;
        }
        myflags = fs_file->meta->flags;

        if ((flags & myflags) != myflags)
            continue;

        /* If we want only orphans, then check if this
         * inode is in the seen list
         * */
        if ((myflags & TSK_FS_META_FLAG_UNALLOC) &&
            (flags & TSK_FS_META_FLAG_ORPHAN) &&
            (tsk_fs_dir_find_inum_named(fs, inum))) {
            continue;
        }

        retval = action(fs_file, ptr);
        if (retval == TSK_WALK_ERROR) {
            tsk_fs_file_close(fs_file);
            free(dinode);
            return 1;
        }
        else if (retval == TSK_WALK_STOP) {
            break;
        }
    }

    // handle the virtual orphans folder if they asked for it
    if ((last == TSK_FS_ORPHANDIR_INUM(fs))
        && (flags & TSK_FS_META_FLAG_ALLOC)
        && (flags & TSK_FS_META_FLAG_USED)) {
        int retval;

        if (tsk_fs_dir_make_orphan_dir_meta(fs, fs_file->meta)) {
            tsk_fs_file_close(fs_file);
            free(dinode);
            return 1;
        }
        /* call action */
        retval = action(fs_file, ptr);
        if (retval == TSK_WALK_STOP) {
            tsk_fs_file_close(fs_file);
            free(dinode);
            return 0;
        }
        else if (retval == TSK_WALK_ERROR) {
            tsk_fs_file_close(fs_file);
            free(dinode);
            return 1;
        }
    }


    /*
     * Cleanup.
     */
    tsk_fs_file_close(fs_file);
    if (dinode != NULL)
        free((char *) dinode);
    return 0;
}

// @@@ Doesn' thit seem to ignore interleave?
/* return 1 if block is allocated in a file's extent, return 0 otherwise */
static int
iso9660_is_block_alloc(TSK_FS_INFO * fs, TSK_DADDR_T blk_num)
{
    ISO_INFO *iso = (ISO_INFO *) fs;
    iso9660_inode_node *in_node;

    if (tsk_verbose)
        tsk_fprintf(stderr, "iso9660_is_block_alloc: "
            " blk_num: %" PRIuDADDR "\n", blk_num);

    for (in_node = iso->in_list; in_node; in_node = in_node->next) {
        TSK_DADDR_T first_block = in_node->offset / fs->block_size;
        TSK_DADDR_T file_size =
            tsk_getu32(fs->endian, in_node->inode.dr.data_len_m);
        TSK_DADDR_T last_block =
            first_block + (file_size / fs->block_size);
        if (file_size % fs->block_size)
            last_block++;

        if ((blk_num >= first_block) && (blk_num <= last_block))
            return 1;
    }

    return 0;
}


TSK_FS_BLOCK_FLAG_ENUM static
iso9660_block_getflags(TSK_FS_INFO * a_fs, TSK_DADDR_T a_addr)
{
    return (iso9660_is_block_alloc(a_fs, a_addr)) ?
        TSK_FS_BLOCK_FLAG_ALLOC : TSK_FS_BLOCK_FLAG_UNALLOC;
}


/* flags: TSK_FS_BLOCK_FLAG_ALLOC and FS_FLAG_UNALLOC
 * ISO9660 has a LOT of very sparse meta, so in this function a block is only
 * checked to see if it is part of an inode's extent
 */
static uint8_t
iso9660_block_walk(TSK_FS_INFO * fs, TSK_DADDR_T start, TSK_DADDR_T last,
    TSK_FS_BLOCK_WALK_FLAG_ENUM flags, TSK_FS_BLOCK_WALK_CB action,
    void *ptr)
{
    char *myname = "iso9660_block_walk";
    TSK_DADDR_T addr;
    TSK_FS_BLOCK *fs_block;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if (tsk_verbose)
        tsk_fprintf(stderr, "iso9660_block_walk: "
            " start: %" PRIuDADDR " last: %" PRIuDADDR " flags: %d"
            " action: %" PRIu64 " ptr: %" PRIu64 "\n",
            start, last, flags, (uint64_t) action, (uint64_t) ptr);

    /*
     * Sanity checks.
     */
    if (start < fs->first_block || start > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: Start block: %" PRIuDADDR "", myname,
            start);
        return 1;
    }
    if (last < fs->first_block || last > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: End block: %" PRIuDADDR "", myname,
            last);
        return 1;
    }

    /* Sanity check on flags -- make sure at least one ALLOC is set */
    if (((flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC) == 0) &&
        ((flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC) == 0)) {
        flags |=
            (TSK_FS_BLOCK_WALK_FLAG_ALLOC |
            TSK_FS_BLOCK_WALK_FLAG_UNALLOC);
    }
    if (((flags & TSK_FS_BLOCK_WALK_FLAG_META) == 0) &&
        ((flags & TSK_FS_BLOCK_WALK_FLAG_CONT) == 0)) {
        flags |=
            (TSK_FS_BLOCK_WALK_FLAG_CONT | TSK_FS_BLOCK_WALK_FLAG_META);
    }

    if ((fs_block = tsk_fs_block_alloc(fs)) == NULL) {
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "isofs_block_walk: Block Walking %" PRIuDADDR " to %" PRIuDADDR
            "\n", start, last);

    /* cycle through block addresses */
    for (addr = start; addr <= last; addr++) {
        int retval;
        int myflags = iso9660_block_getflags(fs, addr);

        // test if we should call the callback with this one
        if ((myflags & TSK_FS_BLOCK_FLAG_ALLOC)
            && (!(flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC)))
            continue;
        else if ((myflags & TSK_FS_BLOCK_FLAG_UNALLOC)
            && (!(flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC)))
            continue;

        if (flags & TSK_FS_BLOCK_WALK_FLAG_AONLY)
            myflags |= TSK_FS_BLOCK_FLAG_AONLY;

        if (tsk_fs_block_get_flag(fs, fs_block, addr, myflags) == NULL) {
            tsk_error_set_errstr2("iso_block_walk");
            tsk_fs_block_free(fs_block);
            return 1;
        }

        retval = action(fs_block, ptr);
        if (retval == TSK_WALK_ERROR) {
            tsk_fs_block_free(fs_block);
            return 1;
        }
        else if (retval == TSK_WALK_STOP) {
            break;
        }
    }

    tsk_fs_block_free(fs_block);
    return 0;
}



static uint8_t
iso9660_make_data_run(TSK_FS_FILE * a_fs_file)
{
    ISO_INFO *iso;
    iso9660_dentry dd;
    TSK_FS_INFO *fs = NULL;
    TSK_FS_ATTR *fs_attr = NULL;
    TSK_FS_ATTR_RUN *data_run = NULL;
    iso9660_inode *dinode;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if ((a_fs_file == NULL) || (a_fs_file->meta == NULL)
        || (a_fs_file->fs_info == NULL)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("iso9660_make_data_run: fs_file or meta is NULL");
        return 1;
    }
    fs = a_fs_file->fs_info;
    iso = (ISO_INFO *) fs;

    // see if we have already loaded the runs
    if ((a_fs_file->meta->attr != NULL)
        && (a_fs_file->meta->attr_state == TSK_FS_META_ATTR_STUDIED)) {
        return 0;
    }
    else if (a_fs_file->meta->attr_state == TSK_FS_META_ATTR_ERROR) {
        return 1;
    }
    // not sure why this would ever happen, but...
    else if (a_fs_file->meta->attr != NULL) {
        tsk_fs_attrlist_markunused(a_fs_file->meta->attr);
    }
    else if (a_fs_file->meta->attr == NULL) {
        a_fs_file->meta->attr = tsk_fs_attrlist_alloc();
    }

    /* allocate cache buffers */
    /* dinode */
    if ((dinode =
            (iso9660_inode *) tsk_malloc(sizeof(iso9660_inode))) == NULL) {
        fs->tag = 0;
        iso9660_close(fs);
        return 1;
    }

    // copy the raw data
    if (iso9660_dinode_load(iso, a_fs_file->meta->addr, dinode)) {
        tsk_error_set_errstr2("iso9660_make_data_run");
        a_fs_file->meta->attr_state = TSK_FS_META_ATTR_ERROR;
        free(dinode);
        return 1;
    }
    memcpy(&dd, &dinode->dr, sizeof(iso9660_dentry));
    free(dinode);
    dinode = NULL;

    if (dd.gap_sz) {
        a_fs_file->meta->attr_state = TSK_FS_META_ATTR_ERROR;
        tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
        tsk_error_set_errstr("file %" PRIuINUM
            " has an interleave gap -- not supported",
            a_fs_file->meta->addr);
        return 1;
    }

    if ((fs_attr =
            tsk_fs_attrlist_getnew(a_fs_file->meta->attr,
                TSK_FS_ATTR_NONRES)) == NULL) {
        return 1;
    }

    // make a non-resident run
    data_run = tsk_fs_attr_run_alloc();
    if (data_run == NULL) {
        return -1;
    }
    data_run->addr = ((TSK_DADDR_T *) a_fs_file->meta->content_ptr)[0];
    data_run->len =
        (a_fs_file->meta->size + fs->block_size - 1) / fs->block_size;
    data_run->offset = 0;

    // initialize the data run
    if (tsk_fs_attr_set_run(a_fs_file, fs_attr, data_run, NULL,
            TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
            a_fs_file->meta->size, a_fs_file->meta->size,
            roundup(a_fs_file->meta->size + dd.ext_len,
                fs->block_size) - dd.ext_len, 0, 0)) {
        return 1;
    }

    // the first bytes in the run could be allocated for the extended attribute.
    fs_attr->nrd.skiplen = dd.ext_len;

    a_fs_file->meta->attr_state = TSK_FS_META_ATTR_STUDIED;

    return 0;
}



static uint8_t
iso9660_fscheck(TSK_FS_INFO * fs, FILE * hFile)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("fscheck not implemented for iso9660 yet");
    return 1;
}

/**
 * Print details about the file system to a file handle.
 *
 * @param fs File system to print details on
 * @param hFile File handle to print text to
 *
 * @returns 1 on error and 0 on success
 */
static uint8_t
iso9660_fsstat(TSK_FS_INFO * fs, FILE * hFile)
{
    char str[129];              /* store name of publisher/preparer/etc */
    ISO_INFO *iso = (ISO_INFO *) fs;
    char *cp;
    int i;

    iso9660_pvd_node *p = iso->pvd;
    iso9660_svd_node *s;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if (tsk_verbose)
        tsk_fprintf(stderr, "iso9660_fsstat:\n");

    i = 0;

    for (p = iso->pvd; p != NULL; p = p->next) {
        i++;
        tsk_fprintf(hFile, "\n=== PRIMARY VOLUME DESCRIPTOR %d ===\n", i);
        tsk_fprintf(hFile, "FILE SYSTEM INFORMATION\n");
        tsk_fprintf(hFile,
            "--------------------------------------------\n");
        tsk_fprintf(hFile, "File System Type: ISO9660\n");
        tsk_fprintf(hFile, "Volume Name: %s\n", p->pvd.vol_id);
        tsk_fprintf(hFile, "Volume Set Size: %d\n",
            tsk_getu16(fs->endian, p->pvd.vol_set_m));
        tsk_fprintf(hFile, "Volume Set Sequence: %d\n",
            tsk_getu16(fs->endian, p->pvd.vol_seq_m));

        /* print publisher */
        if (p->pvd.pub_id[0] == 0x5f)
            /* publisher is in a file.  TODO: handle this properly */
            snprintf(str, 8, "In file\n");
        else
            snprintf(str, 128, "%s", p->pvd.pub_id);

        cp = &str[127];
        /* find last printable non space character */
        while ((!isprint(*cp) || isspace(*cp)) && (cp != str))
            cp--;
        *++cp = '\0';
        tsk_fprintf(hFile, "Publisher: %s\n", str);
        memset(str, ' ', 128);


        /* print data preparer */
        if (p->pvd.prep_id[0] == 0x5f)
            /* preparer is in a file.  TODO: handle this properly */
            snprintf(str, 8, "In file\n");
        else
            snprintf(str, 128, "%s", p->pvd.prep_id);

        cp = &str[127];
        while ((!isprint(*cp) || isspace(*cp)) && (cp != str))
            cp--;
        *++cp = '\0';
        tsk_fprintf(hFile, "Data Preparer: %s\n", str);
        memset(str, ' ', 128);


        /* print recording application */
        if (p->pvd.app_id[0] == 0x5f)
            /* application is in a file.  TODO: handle this properly */
            snprintf(str, 8, "In file\n");
        else
            snprintf(str, 128, "%s", p->pvd.app_id);
        cp = &str[127];
        while ((!isprint(*cp) || isspace(*cp)) && (cp != str))
            cp--;
        *++cp = '\0';
        tsk_fprintf(hFile, "Recording Application: %s\n", str);
        memset(str, ' ', 128);


        /* print copyright */
        if (p->pvd.copy_id[0] == 0x5f)
            /* copyright is in a file.  TODO: handle this properly */
            snprintf(str, 8, "In file\n");
        else
            snprintf(str, 37, "%s", p->pvd.copy_id);
        cp = &str[36];
        while ((!isprint(*cp) || isspace(*cp)) && (cp != str))
            cp--;
        *++cp = '\0';
        tsk_fprintf(hFile, "Copyright: %s\n", str);
        memset(str, ' ', 37);

        tsk_fprintf(hFile, "\nMETADATA INFORMATION\n");
        tsk_fprintf(hFile,
            "--------------------------------------------\n");
        tsk_fprintf(hFile,
            "Path Table Location: %" PRIu32 "-%" PRIu32 "\n",
            tsk_getu32(fs->endian, p->pvd.pt_loc_m), tsk_getu32(fs->endian,
                p->pvd.pt_loc_m) + tsk_getu32(fs->endian,
                p->pvd.pt_size_m) / fs->block_size);

        tsk_fprintf(hFile, "Inode Range: %" PRIuINUM " - %" PRIuINUM "\n",
            fs->first_inum, fs->last_inum);
        tsk_fprintf(hFile, "Root Directory Block: %" PRIuDADDR "\n",
            tsk_getu32(fs->endian, p->pvd.dir_rec.ext_loc_m));

        tsk_fprintf(hFile, "\nCONTENT INFORMATION\n");
        tsk_fprintf(hFile,
            "--------------------------------------------\n");
        tsk_fprintf(hFile, "Sector Size: %d\n", ISO9660_SSIZE_B);
        tsk_fprintf(hFile, "Block Size: %d\n", tsk_getu16(fs->endian,
                p->pvd.blk_sz_m));
        if (fs->block_pre_size) {
            tsk_fprintf(hFile, "Raw CD pre-block size: %d\n",
                fs->block_pre_size);
            tsk_fprintf(hFile, "Raw CD post-block size: %d\n",
                fs->block_post_size);
        }

        tsk_fprintf(hFile, "Total Sector Range: 0 - %d\n",
            (int) ((fs->block_size / ISO9660_SSIZE_B) *
                (fs->block_count - 1)));
        /* get image slack, ignore how big the image claims itself to be */
        tsk_fprintf(hFile, "Total Block Range: 0 - %d\n",
            (int) fs->block_count - 1);
    }

    i = 0;

    for (s = iso->svd; s != NULL; s = s->next) {
        i++;
        tsk_fprintf(hFile,
            "\n=== SUPPLEMENTARY VOLUME DESCRIPTOR %d ===\n", i);
        tsk_fprintf(hFile, "FILE SYSTEM INFORMATION\n");
        tsk_fprintf(hFile,
            "--------------------------------------------\n");
        tsk_fprintf(hFile, "File System Type: ISO9660\n");
        tsk_fprintf(hFile, "Volume Name: %s\n", s->svd.vol_id);
        tsk_fprintf(hFile, "Volume Set Size: %d\n",
            tsk_getu16(fs->endian, s->svd.vol_set_m));
        tsk_fprintf(hFile, "Volume Set Sequence: %d\n",
            tsk_getu16(fs->endian, s->svd.vol_seq_m));



        /* print publisher */
        if (s->svd.pub_id[0] == 0x5f)
            /* publisher is in a file.  TODO: handle this properly */
            snprintf(str, 8, "In file\n");
        else
            snprintf(str, 128, "%s", s->svd.pub_id);

        cp = &str[127];
        /* find last printable non space character */
        while ((!isprint(*cp) || isspace(*cp)) && (cp != str))
            cp--;
        *++cp = '\0';
        tsk_fprintf(hFile, "Publisher: %s\n", str);
        memset(str, ' ', 128);


        /* print data preparer */
        if (s->svd.prep_id[0] == 0x5f)
            /* preparer is in a file.  TODO: handle this properly */
            snprintf(str, 8, "In file\n");
        else
            snprintf(str, 128, "%s", s->svd.prep_id);

        cp = &str[127];
        while ((!isprint(*cp) || isspace(*cp)) && (cp != str))
            cp--;
        *++cp = '\0';
        tsk_fprintf(hFile, "Data Preparer: %s\n", str);
        memset(str, ' ', 128);


        /* print recording application */
        if (s->svd.app_id[0] == 0x5f)
            /* application is in a file.  TODO: handle this properly */
            snprintf(str, 8, "In file\n");
        else
            snprintf(str, 128, "%s", s->svd.app_id);
        cp = &str[127];
        while ((!isprint(*cp) || isspace(*cp)) && (cp != str))
            cp--;
        *++cp = '\0';
        tsk_fprintf(hFile, "Recording Application: %s\n", str);
        memset(str, ' ', 128);


        /* print copyright */
        if (s->svd.copy_id[0] == 0x5f)
            /* copyright is in a file.  TODO: handle this properly */
            snprintf(str, 8, "In file\n");
        else
            snprintf(str, 37, "%s\n", s->svd.copy_id);
        cp = &str[36];
        while ((!isprint(*cp) || isspace(*cp)) && (cp != str))
            cp--;
        *++cp = '\0';
        tsk_fprintf(hFile, "Copyright: %s\n", str);
        memset(str, ' ', 37);

        tsk_fprintf(hFile, "\nMETADATA INFORMATION\n");
        tsk_fprintf(hFile,
            "--------------------------------------------\n");
        tsk_fprintf(hFile,
            "Path Table Location: %" PRIu32 "-%" PRIu32 "\n",
            tsk_getu32(fs->endian, s->svd.pt_loc_m), tsk_getu32(fs->endian,
                s->svd.pt_loc_m) + tsk_getu32(fs->endian,
                s->svd.pt_size_m) / fs->block_size);

        tsk_fprintf(hFile, "Root Directory Block: %" PRIuDADDR "\n",
            tsk_getu32(fs->endian, s->svd.dir_rec.ext_loc_m));

        /* learn joliet level (1-3) */
        if (!strncmp((char *) s->svd.esc_seq, "%/E", 3))
            tsk_fprintf(hFile, "Joliet Name Encoding: UCS-2 Level 3\n");
        if (!strncmp((char *) s->svd.esc_seq, "%/C", 3))
            tsk_fprintf(hFile, "Joliet Name Encoding: UCS-2 Level 2\n");
        if (!strncmp((char *) s->svd.esc_seq, "%/@", 3))
            tsk_fprintf(hFile, "Joliet Name Encoding: UCS-2 Level 1\n");
        if (iso->rr_found)
            tsk_fprintf(hFile, "RockRidge Extensions present\n");


        tsk_fprintf(hFile, "\nCONTENT INFORMATION\n");
        tsk_fprintf(hFile,
            "--------------------------------------------\n");
        tsk_fprintf(hFile, "Sector Size: %d\n", ISO9660_SSIZE_B);
        tsk_fprintf(hFile, "Block Size: %d\n", fs->block_size);

        tsk_fprintf(hFile, "Total Sector Range: 0 - %d\n",
            (int) ((fs->block_size / ISO9660_SSIZE_B) *
                (fs->block_count - 1)));
        /* get image slack, ignore how big the image claims itself to be */
        tsk_fprintf(hFile, "Total Block Range: 0 - %d\n",
            (int) fs->block_count - 1);
    }

    return 0;
}


/**
 * Make a unix-style permissions string based the flags in dentry and
 * the cached inode in fs, storing results in perm.  Caller must
 * ensure perm can hold 10 chars plus one null char.
 */
static char *
make_unix_perm(TSK_FS_INFO * fs, iso9660_dentry * dd,
    iso9660_inode * dinode, char *perm)
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "make_unix_perm: fs: %" PRIu64
            " dd: %" PRIu64 "\n", (uint64_t) fs, (uint64_t) dd);

    memset(perm, '-', 10);
    perm[10] = '\0';

    if (dd->flags & ISO9660_FLAG_DIR)
        perm[0] = 'd';

    if (dinode->ea) {
        if (tsk_getu16(fs->endian, dinode->ea->mode) & ISO9660_BIT_UR)
            perm[1] = 'r';

        if (tsk_getu16(fs->endian, dinode->ea->mode) & ISO9660_BIT_UX)
            perm[3] = 'x';

        if (tsk_getu16(fs->endian, dinode->ea->mode) & ISO9660_BIT_GR)
            perm[4] = 'r';

        if (tsk_getu16(fs->endian, dinode->ea->mode) & ISO9660_BIT_GX)
            perm[6] = 'x';

        if (tsk_getu16(fs->endian, dinode->ea->mode) & ISO9660_BIT_AR)
            perm[7] = 'r';

        if (tsk_getu16(fs->endian, dinode->ea->mode) & ISO9660_BIT_AX)
            perm[9] = 'x';
    }
    else {
        strcpy(&perm[1], "r-xr-xr-x");
    }

    return perm;
}

#if 0
static void
iso9660_print_rockridge(FILE * hFile, rockridge_ext * rr)
{
    char mode_buf[11];

    tsk_fprintf(hFile, "\nROCKRIDGE EXTENSIONS\n");

    tsk_fprintf(hFile, "Owner-ID: ");
    tsk_fprintf(hFile, "%d\t", (int) rr->uid);

    tsk_fprintf(hFile, "Group-ID: ");
    tsk_fprintf(hFile, "%d\n", (int) rr->gid);

    tsk_fprintf(hFile, "Mode: ");
    memset(mode_buf, '-', 11);
    mode_buf[10] = '\0';

    /* file type */
    /* note: socket and symbolic link are multi bit fields */
    if ((rr->mode & MODE_IFSOCK) == MODE_IFSOCK)
        mode_buf[0] = 's';
    else if ((rr->mode & MODE_IFLNK) == MODE_IFLNK)
        mode_buf[0] = 'l';
    else if (rr->mode & MODE_IFDIR)
        mode_buf[0] = 'd';
    else if (rr->mode & MODE_IFIFO)
        mode_buf[0] = 'p';
    else if (rr->mode & MODE_IFBLK)
        mode_buf[0] = 'b';
    else if (rr->mode & MODE_IFCHR)
        mode_buf[0] = 'c';

    /* owner permissions */
    if (rr->mode & TSK_FS_META_MODE_IRUSR)
        mode_buf[1] = 'r';
    if (rr->mode & TSK_FS_META_MODE_IWUSR)
        mode_buf[2] = 'w';

    if ((rr->mode & TSK_FS_META_MODE_IXUSR)
        && (rr->mode & TSK_FS_META_MODE_ISUID))
        mode_buf[3] = 's';
    else if (rr->mode & TSK_FS_META_MODE_IXUSR)
        mode_buf[3] = 'x';
    else if (rr->mode & TSK_FS_META_MODE_ISUID)
        mode_buf[3] = 'S';

    /* group permissions */
    if (rr->mode & TSK_FS_META_MODE_IRGRP)
        mode_buf[4] = 'r';
    if (rr->mode & TSK_FS_META_MODE_IWGRP)
        mode_buf[5] = 'w';

    if ((rr->mode & TSK_FS_META_MODE_IXGRP)
        && (rr->mode & TSK_FS_META_MODE_ISGID))
        mode_buf[6] = 's';
    else if (rr->mode & TSK_FS_META_MODE_IXGRP)
        mode_buf[6] = 'x';
    else if (rr->mode & TSK_FS_META_MODE_ISGID)
        mode_buf[6] = 'S';

    /* other permissions */
    if (rr->mode & TSK_FS_META_MODE_IROTH)
        mode_buf[7] = 'r';
    if (rr->mode & TSK_FS_META_MODE_IWOTH)
        mode_buf[8] = 'w';

    if ((rr->mode & TSK_FS_META_MODE_IXOTH)
        && (rr->mode & TSK_FS_META_MODE_ISVTX))
        mode_buf[9] = 't';
    else if (rr->mode & TSK_FS_META_MODE_IXOTH)
        mode_buf[9] = 'x';
    else if (rr->mode & TSK_FS_META_MODE_ISVTX)
        mode_buf[9] = 'T';

    tsk_fprintf(hFile, "%s\n", mode_buf);
    tsk_fprintf(hFile, "Number links: %" PRIu32 "\n", rr->nlink);

    tsk_fprintf(hFile, "Alternate name: %s\n", rr->fn);
    tsk_fprintf(hFile, "\n");
}
#endif

/**
 * Print details on a specific file to a file handle.
 *
 * @param fs File system file is located in
 * @param hFile File handle to print text to
 * @param inum Address of file in file system
 * @param numblock The number of blocks in file to force print (can go beyond file size)
 * @param sec_skew Clock skew in seconds to also print times in
 *
 * @returns 1 on error and 0 on success
 */
static uint8_t
iso9660_istat(TSK_FS_INFO * fs, FILE * hFile, TSK_INUM_T inum,
    TSK_DADDR_T numblock, int32_t sec_skew)
{
    ISO_INFO *iso = (ISO_INFO *) fs;
    TSK_FS_FILE *fs_file;
    iso9660_dentry dd;
    iso9660_inode *dinode;
    char timeBuf[128];

    // clean up any error messages that are lying around
    tsk_error_reset();

    if ((fs_file = tsk_fs_file_open_meta(fs, NULL, inum)) == NULL)
        return 1;

    tsk_fprintf(hFile, "Entry: %" PRIuINUM "\n", inum);

    /* allocate cache buffers */
    /* dinode */
    dinode = (iso9660_inode *) tsk_malloc(sizeof(iso9660_inode));
    if (dinode == NULL) {
        fs->tag = 0;
        iso9660_close(fs);
        return 1;
    }

    if (iso9660_dinode_load(iso, inum, dinode)) {
        tsk_error_set_errstr2("iso9660_istat");
        tsk_fs_file_close(fs_file);
        free(dinode);
        return 1;
    }
    memcpy(&dd, &dinode->dr, sizeof(iso9660_dentry));

    tsk_fprintf(hFile, "Type: ");
    if (dd.flags & ISO9660_FLAG_DIR)
        tsk_fprintf(hFile, "Directory\n");
    else
        tsk_fprintf(hFile, "File\n");

    tsk_fprintf(hFile, "Links: %d\n", fs_file->meta->nlink);

    if (dd.gap_sz > 0) {
        tsk_fprintf(hFile, "Interleave Gap Size: %d\n", dd.gap_sz);
        tsk_fprintf(hFile, "Interleave File Unit Size: %d\n", dd.unit_sz);
    }

    tsk_fprintf(hFile, "Flags: ");

    if (dd.flags & ISO9660_FLAG_HIDE)
        tsk_fprintf(hFile, "Hidden, ");

    if (dd.flags & ISO9660_FLAG_ASSOC)
        tsk_fprintf(hFile, "Associated, ");

    if (dd.flags & ISO9660_FLAG_RECORD)
        tsk_fprintf(hFile, "Record Format, ");

    if (dd.flags & ISO9660_FLAG_PROT)
        tsk_fprintf(hFile, "Protected,  ");

    /* check if reserved bits are set, be suspicious */
    if (dd.flags & ISO9660_FLAG_RES1)
        tsk_fprintf(hFile, "Reserved1, ");

    if (dd.flags & ISO9660_FLAG_RES2)
        tsk_fprintf(hFile, "Reserved2, ");

    if (dd.flags & ISO9660_FLAG_MULT)
        tsk_fprintf(hFile, "Non-final multi-extent entry");
    putchar('\n');

    tsk_fprintf(hFile, "Name: %s\n", dinode->fn);
    tsk_fprintf(hFile, "Size: %" PRIu32 "\n", tsk_getu32(fs->endian,
            dinode->dr.data_len_m));

    if (dinode->ea) {
        char perm_buf[11];
        tsk_fprintf(hFile, "\nEXTENDED ATTRIBUTE INFO\n");
        tsk_fprintf(hFile, "Owner-ID: %" PRIu32 "\n",
            tsk_getu32(fs->endian, dinode->ea->uid));
        tsk_fprintf(hFile, "Group-ID: %" PRIu32 "\n",
            tsk_getu32(fs->endian, dinode->ea->gid));
        tsk_fprintf(hFile, "Mode: %s\n", make_unix_perm(fs, &dd, dinode,
                perm_buf));
    }
    else if (dinode->susp_off) {
        char *buf2 = (char *) tsk_malloc((size_t) dinode->susp_len);
        if (buf2 != NULL) {
            ssize_t cnt;
            fprintf(hFile, "\nRock Ridge Extension Data\n");
            cnt =
                tsk_fs_read(fs, dinode->susp_off, buf2,
                (size_t) dinode->susp_len);
            if (cnt == dinode->susp_len) {
                parse_susp(fs, buf2, (int) cnt, hFile);
            }
            else {
                fprintf(hFile, "Error reading Rock Ridge Location\n");
                if (tsk_verbose) {
                    fprintf(stderr,
                        "istat: error reading rock ridge entry\n");
                    tsk_error_print(stderr);
                }
                tsk_error_reset();
            }
            free(buf2);
        }
        else {
            if (tsk_verbose)
                fprintf(stderr,
                    "istat: error allocating memory to process rock ridge entry\n");
            tsk_error_reset();
        }
    }
    //else if (iso->dinode->rr) {
    //    iso9660_print_rockridge(hFile, iso->dinode->rr);
    //}
    else {
        char perm_buf[11];
        tsk_fprintf(hFile, "Owner-ID: 0\n");
        tsk_fprintf(hFile, "Group-ID: 0\n");
        tsk_fprintf(hFile, "Mode: %s\n", make_unix_perm(fs, &dd, dinode,
                perm_buf));
    }

    if (sec_skew != 0) {
        tsk_fprintf(hFile, "\nAdjusted File Times:\n");
        if (fs_file->meta->mtime)
            fs_file->meta->mtime -= sec_skew;
        if (fs_file->meta->atime)
            fs_file->meta->atime -= sec_skew;
        if (fs_file->meta->crtime)
            fs_file->meta->crtime -= sec_skew;

        tsk_fprintf(hFile, "Written:\t%s\n",
            tsk_fs_time_to_str(fs_file->meta->mtime, timeBuf));
        tsk_fprintf(hFile, "Accessed:\t%s\n",
            tsk_fs_time_to_str(fs_file->meta->atime, timeBuf));
        tsk_fprintf(hFile, "Created:\t%s\n",
            tsk_fs_time_to_str(fs_file->meta->crtime, timeBuf));

        if (fs_file->meta->mtime == 0)
            fs_file->meta->mtime += sec_skew;
        if (fs_file->meta->atime == 0)
            fs_file->meta->atime += sec_skew;
        if (fs_file->meta->crtime == 0)
            fs_file->meta->crtime += sec_skew;


        tsk_fprintf(hFile, "\nOriginal File Times:\n");
    }
    else {
        tsk_fprintf(hFile, "\nFile Times:\n");
    }

    tsk_fprintf(hFile, "Created:\t%s\n",
        tsk_fs_time_to_str(fs_file->meta->crtime, timeBuf));
    tsk_fprintf(hFile, "File Modified:\t%s\n",
        tsk_fs_time_to_str(fs_file->meta->mtime, timeBuf));
    tsk_fprintf(hFile, "Accessed:\t%s\n",
        tsk_fs_time_to_str(fs_file->meta->atime, timeBuf));

    tsk_fprintf(hFile, "\nSectors:\n");
    /* since blocks are all contiguous, print them here to simplify file_walk */
    {
        int block = tsk_getu32(fs->endian, dinode->dr.ext_loc_m);
        TSK_OFF_T size = fs_file->meta->size;
        int rowcount = 0;

        while ((int64_t) size > 0) {
            tsk_fprintf(hFile, "%d ", block++);
            size -= fs->block_size;
            rowcount++;
            if (rowcount == 8) {
                rowcount = 0;
                tsk_fprintf(hFile, "\n");
            }
        }
        tsk_fprintf(hFile, "\n");
    }

    tsk_fs_file_close(fs_file);
    if (dinode != NULL)
        free((char *) dinode);
    return 0;
}




static uint8_t
iso9660_jopen(TSK_FS_INFO * fs, TSK_INUM_T inum)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("ISO9660 does not have a journal");
    return 1;
}

static uint8_t
iso9660_jentry_walk(TSK_FS_INFO * fs, int flags,
    TSK_FS_JENTRY_WALK_CB action, void *ptr)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("ISO9660 does not have a journal");
    return 1;
}

static uint8_t
iso9660_jblk_walk(TSK_FS_INFO * fs, TSK_DADDR_T start, TSK_DADDR_T end,
    int flags, TSK_FS_JBLK_WALK_CB action, void *ptr)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("ISO9660 does not have a journal");
    return 1;
}


static TSK_FS_ATTR_TYPE_ENUM
iso9660_get_default_attr_type(const TSK_FS_FILE * a_file)
{
    return TSK_FS_ATTR_TYPE_DEFAULT;
}

/** Load the volume descriptors into save the raw data structures in
 * the file system state structure (fs).  Also determines the block size.
 *
 * This is useful for discs which may have 2 volumes on them (no, not
 * multisession CD-R/CD-RW).
 * Design note: If path table address is the same, then you have the same image.
 * Only store unique image info.
 * Uses a linked list even though Ecma-119 says there is only 1 primary vol
 * desc, consider possibility of more.
 *
 * Returns -1 on error and 0 on success
 */
static int
load_vol_desc(TSK_FS_INFO * fs)
{
    int count = 0;
    ISO_INFO *iso = (ISO_INFO *) fs;
    TSK_OFF_T offs;
    char *myname = "iso_load_vol_desc";
    ssize_t cnt;
    iso9660_pvd_node *p;
    iso9660_svd_node *s;
    uint8_t magic_seen = 0;

    iso->pvd = NULL;
    iso->svd = NULL;
    //fs->block_size = 0;
    fs->dev_bsize = fs->img_info->sector_size;

#if 0
    b = (iso_bootrec *) tsk_malloc(sizeof(iso_bootrec));
    if (b == NULL) {
        return -1;
    }
#endif

    // @@@ Technically, we should seek ahea 16 * sector size
    for (offs = ISO9660_SBOFF;; offs += sizeof(iso9660_gvd)) {
        iso9660_gvd *vd;

        // allocate a buffer the size of the nodes in the linked list
        // this will be stored in ISO_INFO, so it is not always freed here
        if ((vd =
                (iso9660_gvd *) tsk_malloc(sizeof(iso9660_pvd_node))) ==
            NULL) {
            return -1;
        }

      ISO_RETRY_MAGIC:

        // read the full descriptor
        cnt = tsk_fs_read(fs, offs, (char *) vd, sizeof(iso9660_gvd));
        if (cnt != sizeof(iso9660_gvd)) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("iso_load_vol_desc: Error reading");
            free(vd);
            return -1;
        }

        // verify the magic value
        if (strncmp(vd->magic, ISO9660_MAGIC, 5)) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "%s: Bad volume descriptor: Magic number is not CD001\n",
                    myname);

            // see if we have a RAW image
            if (magic_seen == 0) {
                if (fs->block_pre_size == 0) {
                    if (tsk_verbose)
                        tsk_fprintf(stderr,
                            "Trying RAW ISO9660 with 16-byte pre-block size\n");
                    fs->block_pre_size = 16;
                    fs->block_post_size = 288;
                    goto ISO_RETRY_MAGIC;
                }
                else if (fs->block_pre_size == 16) {
                    if (tsk_verbose)
                        tsk_fprintf(stderr,
                            "Trying RAW ISO9660 with 24-byte pre-block size\n");
                    fs->block_pre_size = 24;
                    fs->block_post_size = 280;
                    goto ISO_RETRY_MAGIC;
                }
                else {
                    fs->block_pre_size = 0;
                    fs->block_post_size = 0;
                }
            }
            free(vd);
            return -1;
        }
        magic_seen = 1;

        // see if we are done
        if (vd->type == ISO9660_VOL_DESC_SET_TERM)
            break;

        switch (vd->type) {

        case ISO9660_PRIM_VOL_DESC:
            p = (iso9660_pvd_node *) vd;

            /* list not empty */
            if (iso->pvd) {
                iso9660_pvd_node *ptmp = iso->pvd;
                /* append to list if path table address not found in list */
                while ((p->pvd.pt_loc_l != ptmp->pvd.pt_loc_l)
                    && (ptmp->next))
                    ptmp = ptmp->next;

                // we already have it
                if (p->pvd.pt_loc_l == ptmp->pvd.pt_loc_l) {
                    free(vd);
                    p = NULL;
                    vd = NULL;
                }
                else {
                    ptmp->next = p;
                    p->next = NULL;
                    count++;
                }
            }

            /* list empty, insert */
            else {
                iso->pvd = p;
                p->next = NULL;
                count++;
            }

            break;

        case ISO9660_SUPP_VOL_DESC:
            s = (iso9660_svd_node *) vd;

            /* list not empty */
            if (iso->svd) {
                iso9660_svd_node *stmp = iso->svd;
                /* append to list if path table address not found in list */
                while ((s->svd.pt_loc_l != stmp->svd.pt_loc_l)
                    && (stmp->next))
                    stmp = stmp->next;

                // we already have it
                if (s->svd.pt_loc_l == stmp->svd.pt_loc_l) {
                    free(vd);
                    s = NULL;
                    vd = NULL;
                }
                else {
                    stmp->next = s;
                    s->next = NULL;
                    count++;
                }
            }

            /* list empty, insert */
            else {
                iso->svd = s;
                s->next = NULL;
                count++;
            }

            break;

            /* boot records are just read and discarded for now... */
        case ISO9660_BOOT_RECORD:
#if 0
            cnt = tsk_fs_read(fs, offs, (char *) b, sizeof(iso_bootrec));
            if (cnt != sizeof(iso_bootrec)) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2("iso_load_vol_desc: Error reading");
                return -1;
            }
            offs += sizeof(iso_bootrec);
#endif
            break;
        }
    }


    /* now that we have all primary and supplementary volume descs, we should cull the list of */
    /* primary that match up with supplems, since supplem has all info primary has plus more. */
    /* this will make jobs such as searching all volumes easier later */
    for (s = iso->svd; s != NULL; s = s->next) {
        for (p = iso->pvd; p != NULL; p = p->next) {
            // see if they have the same starting address
            if (tsk_getu32(fs->endian,
                    p->pvd.pt_loc_m) == tsk_getu32(fs->endian,
                    s->svd.pt_loc_m)) {
                // see if it is the head of the list
                if (p == iso->pvd) {
                    iso->pvd = p->next;
                }
                else {
                    iso9660_pvd_node *ptmp = iso->pvd;
                    while (ptmp->next != p)
                        ptmp = ptmp->next;
                    ptmp->next = p->next;
                }
                p->next = NULL;
                free(p);
                p = NULL;
                count--;
                break;
            }
        }
    }

    if ((iso->pvd == NULL) && (iso->svd == NULL)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr
            ("load_vol_desc: primary and secondary volume descriptors null");
        return -1;
    }


    return 0;
}


/* iso9660_open -
 * opens an iso9660 filesystem.
 * Design note: This function doesn't read a superblock, since iso9660 doesnt
 * really have one.  Volume info is read in with a call to load_vol_descs().
 */
TSK_FS_INFO *
iso9660_open(TSK_IMG_INFO * img_info, TSK_OFF_T offset,
    TSK_FS_TYPE_ENUM ftype, uint8_t test)
{
    ISO_INFO *iso;
    TSK_FS_INFO *fs;
    uint8_t tmpguess[4];

    if (TSK_FS_TYPE_ISISO9660(ftype) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Invalid FS type in iso9660_open");
        return NULL;
    }

    if (tsk_verbose) {
        tsk_fprintf(stderr, "iso9660_open img_info: %" PRIu64
            " ftype: %" PRIu8 " test: %" PRIu8 "\n", (uint64_t) img_info,
            ftype, test);
    }

    if ((iso = (ISO_INFO *) tsk_fs_malloc(sizeof(ISO_INFO))) == NULL) {
        return NULL;
    }
    fs = &(iso->fs_info);

    iso->rr_found = 0;
    iso->in_list = NULL;

    fs->ftype = TSK_FS_TYPE_ISO9660;
    fs->duname = "Block";
    fs->flags = 0;
    fs->tag = TSK_FS_INFO_TAG;
    fs->img_info = img_info;
    fs->offset = offset;


    /* ISO has no magic to calibrate the endian ordering on and it
     * stores all numbers in big and small endian.  We will use the big
     * endian order so load up a 4-byte array and flags.  We could hardwire
     * the definition, but I would rather use guessu32 in case I later add
     * other initialization data to that function (since all other FSs use
     * it) */
    tmpguess[0] = 0;
    tmpguess[1] = 0;
    tmpguess[2] = 0;
    tmpguess[3] = 1;
    tsk_fs_guessu32(fs, tmpguess, 1);

    // we need a value here to test for RAW images. So, start with 2048
    fs->block_size = 2048;

    /* load_vol_descs checks magic value */
    if (load_vol_desc(fs) == -1) {
        fs->tag = 0;
        iso9660_close(fs);
        if (tsk_verbose)
            fprintf(stderr,
                "iso9660_open: Error loading volume descriptor\n");
        if (test)
            return NULL;
        else {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_MAGIC);
            tsk_error_set_errstr("Invalid FS type in iso9660_open");
            return NULL;
        }
    }

    if (iso->pvd) {
        fs->block_size = tsk_getu16(fs->endian, iso->pvd->pvd.blk_sz_m);
        fs->block_count = tsk_getu32(fs->endian, iso->pvd->pvd.vs_sz_m);

        /* Volume ID */
        for (fs->fs_id_used = 0; fs->fs_id_used < 32; fs->fs_id_used++) {
            fs->fs_id[fs->fs_id_used] =
                iso->pvd->pvd.vol_id[fs->fs_id_used];
        }

    }
    else {
        fs->block_size = tsk_getu16(fs->endian, iso->svd->svd.blk_sz_m);
        fs->block_count = tsk_getu32(fs->endian, iso->svd->svd.vs_sz_m);

        /* Volume ID */
        for (fs->fs_id_used = 0; fs->fs_id_used < 32; fs->fs_id_used++) {
            fs->fs_id[fs->fs_id_used] =
                iso->svd->svd.vol_id[fs->fs_id_used];
        }
    }

    /* We have seen this case on an image that seemed to be only 
     * setting blk_siz_l instead of both blk_sz_m and _l. We should
     * support both in the future, but this prevents a crash later
     * on when we divide by block_size. */
    if (fs->block_size == 0) {
        fs->tag = 0;
        iso9660_close(fs);
        if (tsk_verbose)
            fprintf(stderr, "iso9660_open: Block size is 0\n");
        if (test)
            return NULL;
        else {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_MAGIC);
            tsk_error_set_errstr("Block size is 0");
            return NULL;
        }
    }

    fs->first_block = 0;
    fs->last_block = fs->last_block_act = fs->block_count - 1;

    // determine the last block we have in this image
    if ((TSK_DADDR_T) ((img_info->size - offset) / fs->block_size) <
        fs->block_count)
        fs->last_block_act =
            (img_info->size - offset) / fs->block_size - 1;

    fs->inum_count = iso9660_load_inodes_pt(iso);
    if ((int) fs->inum_count == -1) {
        fs->tag = 0;
        iso9660_close(fs);
        if (tsk_verbose)
            fprintf(stderr, "iso9660_open: Error loading primary table\n");
        return NULL;
    }
    fs->inum_count++;           // account for the orphan directory

    fs->last_inum = fs->inum_count - 1;
    fs->first_inum = ISO9660_FIRSTINO;
    fs->root_inum = ISO9660_ROOTINO;


    fs->inode_walk = iso9660_inode_walk;
    fs->block_walk = iso9660_block_walk;
    fs->block_getflags = iso9660_block_getflags;

    fs->get_default_attr_type = iso9660_get_default_attr_type;
    fs->load_attrs = iso9660_make_data_run;

    fs->file_add_meta = iso9660_inode_lookup;
    fs->dir_open_meta = iso9660_dir_open_meta;
    fs->fsstat = iso9660_fsstat;
    fs->fscheck = iso9660_fscheck;
    fs->istat = iso9660_istat;
    fs->close = iso9660_close;
    fs->name_cmp = iso9660_name_cmp;

    fs->jblk_walk = iso9660_jblk_walk;
    fs->jentry_walk = iso9660_jentry_walk;
    fs->jopen = iso9660_jopen;

    return fs;
}
