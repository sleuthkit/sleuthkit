/*
   @@@ UNALLOC only if seq is less - alloc can be less than block if it wrapped around ...
** ext2fs_journal
** The Sleuth Kit 
**
** Journaling code for TSK_FS_INFO_TYPE_EXT_3 image
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2004-2005 Brian Carrier.  All rights reserved 
**
**
** This software is distributed under the Common Public License 1.0
**
*/

/** \file ext2fs_journal.c
 * Contains the internal TSK Ext3 journal walking code.
 */

#include "tsk_fs_i.h"
#include "tsk_ext2fs.h"



/* Everything in the journal is in big endian */
#define big_tsk_getu32(x)	\
	(uint32_t)((((uint8_t *)x)[3] <<  0) + \
	(((uint8_t *)x)[2] <<  8) + \
	(((uint8_t *)x)[1] << 16) + \
	(((uint8_t *)x)[0] << 24) )


/*
 *
 */

static TSK_WALK_RET_ENUM
load_sb_action(TSK_FS_FILE * fs_file, TSK_OFF_T a_off, TSK_DADDR_T addr,
    char *buf, size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    TSK_FS_INFO *fs = fs_file->fs_info;
    ext2fs_journ_sb *sb;
    EXT2FS_INFO *ext2fs = (EXT2FS_INFO *) fs;
    EXT2FS_JINFO *jinfo = ext2fs->jinfo;

    if (size < 1024) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
        tsk_error_set_errstr
            ("FS block size is less than 1024, not supported in journal yet");
        return TSK_WALK_ERROR;
    }

    sb = (ext2fs_journ_sb *) buf;

    if (big_tsk_getu32(sb->magic) != EXT2_JMAGIC) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Journal inode %" PRIuINUM
            " does not have a valid magic value: %" PRIx32,
            jinfo->j_inum, big_tsk_getu32(sb->magic));
        return TSK_WALK_ERROR;
    }

    jinfo->bsize = big_tsk_getu32(sb->bsize);
    jinfo->first_block = big_tsk_getu32(sb->first_blk);
    jinfo->last_block = big_tsk_getu32(sb->num_blk) - 1;
    jinfo->start_blk = big_tsk_getu32(sb->start_blk);
    jinfo->start_seq = big_tsk_getu32(sb->start_seq);

    return TSK_WALK_STOP;
}

/* Place journal data in *fs
 *
 * Return 0 on success and 1 on error 
 * */
uint8_t
ext2fs_jopen(TSK_FS_INFO * fs, TSK_INUM_T inum)
{
    EXT2FS_INFO *ext2fs = (EXT2FS_INFO *) fs;
    EXT2FS_JINFO *jinfo;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if (!fs) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("ext2fs_jopen: fs is null");
        return 1;
    }

    ext2fs->jinfo = jinfo =
        (EXT2FS_JINFO *) tsk_malloc(sizeof(EXT2FS_JINFO));
    if (jinfo == NULL) {
        return 1;
    }
    jinfo->j_inum = inum;

    jinfo->fs_file = tsk_fs_file_open_meta(fs, NULL, inum);
    if (!jinfo->fs_file) {
        free(jinfo);
        return 1;
//      error("error finding journal inode %" PRIu32, inum);
    }

    if (tsk_fs_file_walk(jinfo->fs_file, 0, load_sb_action, NULL)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_FWALK);
        tsk_error_set_errstr("Error loading ext3 journal");
        tsk_fs_file_close(jinfo->fs_file);
        free(jinfo);
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "journal opened at inode %" PRIuINUM " bsize: %" PRIu32
            " First JBlk: %" PRIuDADDR " Last JBlk: %" PRIuDADDR "\n",
            inum, jinfo->bsize, jinfo->first_block, jinfo->last_block);

    return 0;
}


/* Limitations: does not use the action or any flags 
 *
 * return 0 on success and 1 on error
 * */
uint8_t
ext2fs_jentry_walk(TSK_FS_INFO * fs, int flags,
    TSK_FS_JENTRY_WALK_CB action, void *ptr)
{
    EXT2FS_INFO *ext2fs = (EXT2FS_INFO *) fs;
    EXT2FS_JINFO *jinfo = ext2fs->jinfo;
    char *journ;
    TSK_FS_LOAD_FILE buf1;
    TSK_DADDR_T i;
    int b_desc_seen = 0;
    ext2fs_journ_sb *journ_sb = NULL;
    ext4fs_journ_commit_head *commit_head;

    // clean up any error messages that are lying around
    tsk_error_reset();


    if ((jinfo == NULL) || (jinfo->fs_file == NULL)
        || (jinfo->fs_file->meta == NULL)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("ext2fs_jentry_walk: journal is not open");
        return 1;
    }

    if (jinfo->fs_file->meta->size !=
        (jinfo->last_block + 1) * jinfo->bsize) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("ext2fs_jentry_walk: journal file size is different from \nsize reported in journal super block");
        return 1;
    }

    /* Load the journal into a buffer */
    buf1.left = buf1.total = (size_t) jinfo->fs_file->meta->size;
    journ = buf1.cur = buf1.base = tsk_malloc(buf1.left);
    if (journ == NULL) {
        return 1;
    }

    if (tsk_fs_file_walk(jinfo->fs_file,
            0, tsk_fs_load_file_action, (void *) &buf1)) {
        free(journ);
        return 1;
    }

    if (buf1.left > 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_FWALK);
        tsk_error_set_errstr
            ("ext2fs_jentry_walk: Buffer not fully copied");
        free(journ);
        return 1;
    }


    /* Process the journal 
     * Cycle through each block
     */
    tsk_printf("JBlk\tDescription\n");

    /* Note that 'i' is incremented when we find a descriptor block and
     * process its contents. */
    for (i = 0; i < jinfo->last_block; i++) {
        ext2fs_journ_head *head;


        /* if there is no magic, then it is a normal block 
         * These should be accounted for when we see its corresponding
         * descriptor.  We get the 'unknown' when its desc has
         * been reused, it is in the next batch to be overwritten,
         * or if it has not been used before
         */
        head = (ext2fs_journ_head *) & journ[i * jinfo->bsize];
        if (big_tsk_getu32(head->magic) != EXT2_JMAGIC) {
            if (i < jinfo->first_block) {
                tsk_printf("%" PRIuDADDR ":\tUnused\n", i);
            }

#if 0
            /* For now, we ignore the case of the iitial entries before a descriptor, it is too hard ... */

            else if (b_desc_seen == 0) {
                ext2fs_journ_head *head2 = NULL;
                TSK_DADDR_T a;
                int next_head = 0, next_seq = 0;
                ext2fs_journ_dentry *dentry;

                /* This occurs when the log cycled around 
                 * We need to find out where the descriptor is
                 * and where we need to end */
                b_desc_seen = 1;

                for (a = i; a < jinfo->last_block; a++) {
                    head2 =
                        (ext2fs_journ_head *) & journ[a * jinfo->bsize];
                    if ((big_tsk_getu32(head2->magic) == EXT2_JMAGIC)) {
                        next_head = a;
                        next_seq = big_tsk_getu32(head2->entry_seq);
                        break;
                    }

                }
                if (next_head == 0) {
                    tsk_printf("%" PRIuDADDR ":\tFS Block Unknown\n", i);
                }

                /* Find the last descr in the journ */
                for (a = jinfo->last_block; a > i; a--) {
                    head2 =
                        (ext2fs_journ_head *) & journ[a * jinfo->bsize];
                    if ((big_tsk_getu32(head2->magic) == EXT2_JMAGIC)
                        && (big_tsk_getu32(head2->entry_type) ==
                            EXT2_J_ETYPE_DESC)
                        && (next_seq == big_tsk_getu32(head2->entry_seq))) {
                        break;

// @@@@ We should abort if we reach a commit before  descriptor

                    }
                }

                /* We did not find a descriptor in the journ! 
                 * print unknown for the rest of the journ
                 */
                if (a == i) {
                    tsk_printf("%" PRIuDADDR ":\tFS Block Unknown\n", i);
                    continue;
                }


                dentry =
                    (ext2fs_journ_dentry *) ((uintptr_t) head2 +
                    sizeof(ext2fs_journ_head));;


                /* Cycle through the descriptor entries */
                while ((uintptr_t) dentry <=
                    ((uintptr_t) head2 + jinfo->bsize -
                        sizeof(ext2fs_journ_head))) {


                    /* Only start to look after the index in the desc has looped */
                    if (++a <= jinfo->last_block) {
                        ext2fs_journ_head *head3;

                        /* Look at the block that this entry refers to */
                        head3 =
                            (ext2fs_journ_head *) & journ[i *
                            jinfo->bsize];
                        if ((big_tsk_getu32(head3->magic) == EXT2_JMAGIC)) {
                            i--;
                            break;
                        }

                        /* If it doesn't have the magic, then it is a
                         * journal entry and we print the FS info */
                        tsk_printf("%" PRIuDADDR ":\tFS Block %" PRIu32
                            "\n", i, big_tsk_getu32(dentry->fs_blk));

                        /* Our counter is over the end of the journ */
                        if (++i > jinfo->last_block)
                            break;

                    }

                    /* Increment to the next */
                    if (big_tsk_getu32(dentry->flag) & EXT2_J_DENTRY_LAST)
                        break;

                    /* If the SAMEID value is set, then we advance by the size of the entry, otherwise add 16 for the ID */
                    else if (big_tsk_getu32(dentry->flag) &
                        EXT2_J_DENTRY_SAMEID)
                        dentry =
                            (ext2fs_journ_dentry *) ((uintptr_t) dentry +
                            sizeof(ext2fs_journ_dentry));

                    else
                        dentry =
                            (ext2fs_journ_dentry *) ((uintptr_t) dentry +
                            sizeof(ext2fs_journ_dentry)
                            + 16);

                }
            }
#endif
            else {
                tsk_printf("%" PRIuDADDR
                    ":\tUnallocated FS Block Unknown\n", i);
            }
        }

        /* The super block */
        else if ((big_tsk_getu32(head->entry_type) == EXT2_J_ETYPE_SB1) ||
            (big_tsk_getu32(head->entry_type) == EXT2_J_ETYPE_SB2)) {
            tsk_printf("%" PRIuDADDR ":\tSuperblock (seq: %" PRIu32 ")\n",
                i, big_tsk_getu32(head->entry_seq));
            journ_sb = head;
            tsk_printf("sb version: %d\n",
                big_tsk_getu32(head->entry_type));
            tsk_printf("sb version: %d\n",
                big_tsk_getu32(journ_sb->entrytype));
            tsk_printf("sb feature_compat flags 0x%08X\n",
                big_tsk_getu32(journ_sb->feature_compat));
            if (big_tsk_getu32(journ_sb->
                    feature_compat) & JBD2_FEATURE_COMPAT_CHECKSUM)
                tsk_printf("\tJOURNAL_CHECKSUMS\n");
            tsk_printf("sb feature_incompat flags 0x%08X\n",
                big_tsk_getu32(journ_sb->feature_incompat));
            if (big_tsk_getu32(journ_sb->
                    feature_incompat) & JBD2_FEATURE_INCOMPAT_REVOKE)
                tsk_printf("\tJOURNAL_REVOKE\n");
            if (big_tsk_getu32(journ_sb->
                    feature_incompat) & JBD2_FEATURE_INCOMPAT_64BIT)
                tsk_printf("\tJOURNAL_64BIT\n");
            if (big_tsk_getu32(journ_sb->
                    feature_incompat) & JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT)
                tsk_printf("\tJOURNAL_ASYNC_COMMIT\n");
            tsk_printf("sb feature_ro_incompat flags 0x%08X\n",
                big_tsk_getu32(journ_sb->feature_ro_incompat));
        }

        /* Revoke Block */
        else if (big_tsk_getu32(head->entry_type) == EXT2_J_ETYPE_REV) {
            tsk_printf("%" PRIuDADDR ":\t%sRevoke Block (seq: %" PRIu32
                ")\n", i, ((i < jinfo->start_blk)
                    || (big_tsk_getu32(head->entry_seq) <
                        jinfo->start_seq)) ? "Unallocated " : "Allocated ",
                big_tsk_getu32(head->entry_seq));
        }

        /* The commit is the end of the entries */
        else if (big_tsk_getu32(head->entry_type) == EXT2_J_ETYPE_COM) {
            tsk_printf("%" PRIuDADDR ":\t%sCommit Block (seq: %" PRIu32, i,
                ((i < jinfo->start_blk)
                    || (big_tsk_getu32(head->entry_seq) <
                        jinfo->start_seq)) ? "Unallocated " : "Allocated ",
                big_tsk_getu32(head->entry_seq));
            commit_head = head;
            //tsk_printf("commit seq %" PRIu32 "\n", big_tsk_getu32(commit_head->c_header.entry_seq));
            if (big_tsk_getu32(journ_sb->
                    feature_compat) & JBD2_FEATURE_COMPAT_CHECKSUM) {
                int chksum_type = commit_head->chksum_type;
                if (chksum_type) {
                    tsk_printf(", checksum_type: %d",
                        commit_head->chksum_type);
                    switch (commit_head->chksum_type) {
                    case JBD2_CRC32_CHKSUM:
                        tsk_printf("-CRC32");
                        break;
                    case JBD2_MD5_CHKSUM:
                        tsk_printf("-MD5");
                        break;
                    case JBD2_SHA1_CHKSUM:
                        tsk_printf("-SHA1");
                        break;
                    default:
                        tsk_printf("-UNKOWN");
                        break;
                    }
                    tsk_printf(", checksum_size: %d",
                        commit_head->chksum_size);
                    tsk_printf(", chksum: 0x%08X",
                        big_tsk_getu32(commit_head->chksum));
                }
            }
            tsk_printf(", sec: %llu.%u", tsk_getu64(TSK_BIG_ENDIAN,
                    commit_head->commit_sec),
                NSEC_PER_SEC / 10 * tsk_getu32(TSK_BIG_ENDIAN,
                    commit_head->commit_nsec));
            tsk_printf(")\n");
        }

        /* The descriptor describes the FS blocks that follow it */
        else if (big_tsk_getu32(head->entry_type) == EXT2_J_ETYPE_DESC) {
            ext2fs_journ_dentry *dentry;
            ext2fs_journ_head *head2;
            int unalloc = 0;

            b_desc_seen = 1;


            /* Is this an unallocated journ block or sequence */
            if ((i < jinfo->start_blk) ||
                (big_tsk_getu32(head->entry_seq) < jinfo->start_seq))
                unalloc = 1;

            tsk_printf("%" PRIuDADDR ":\t%sDescriptor Block (seq: %" PRIu32
                ")\n", i, (unalloc) ? "Unallocated " : "Allocated ",
                big_tsk_getu32(head->entry_seq));

            dentry =
                (ext2fs_journ_dentry *) ((uintptr_t) head +
                sizeof(ext2fs_journ_head));;

            /* Cycle through the descriptor entries to account for the journal blocks */
            while ((uintptr_t) dentry <=
                ((uintptr_t) head + jinfo->bsize -
                    sizeof(ext2fs_journ_head))) {


                /* Our counter is over the end of the journ */
                if (++i > jinfo->last_block)
                    break;


                /* Look at the block that this entry refers to */
                head2 = (ext2fs_journ_head *) & journ[i * jinfo->bsize];
                if ((big_tsk_getu32(head2->magic) == EXT2_JMAGIC) &&
                    (big_tsk_getu32(head2->entry_seq) >=
                        big_tsk_getu32(head->entry_seq))) {
                    i--;
                    break;
                }

                /* If it doesn't have the magic, then it is a
                 * journal entry and we print the FS info */
                tsk_printf("%" PRIuDADDR ":\t%sFS Block %" PRIu32 "\n", i,
                    (unalloc) ? "Unallocated " : "Allocated ",
                    big_tsk_getu32(dentry->fs_blk));

                /* Increment to the next */
                if (big_tsk_getu32(dentry->flag) & EXT2_J_DENTRY_LAST)
                    break;

                /* If the SAMEID value is set, then we advance by the size of the entry, otherwise add 16 for the ID */
                else if (big_tsk_getu32(dentry->flag) &
                    EXT2_J_DENTRY_SAMEID)
                    dentry =
                        (ext2fs_journ_dentry *) ((uintptr_t) dentry +
                        sizeof(ext2fs_journ_dentry));

                else
                    dentry =
                        (ext2fs_journ_dentry *) ((uintptr_t) dentry +
                        sizeof(ext2fs_journ_dentry) + 16);
            }
        }
    }

    free(journ);
    return 0;
}





/* 
 * Limitations for 1st version: start must equal end and action is ignored
 *
 * Return 0 on success and 1 on error
 */
uint8_t
ext2fs_jblk_walk(TSK_FS_INFO * fs, TSK_DADDR_T start, TSK_DADDR_T end,
    int flags, TSK_FS_JBLK_WALK_CB action, void *ptr)
{
    EXT2FS_INFO *ext2fs = (EXT2FS_INFO *) fs;
    EXT2FS_JINFO *jinfo = ext2fs->jinfo;
    char *journ;
    TSK_FS_LOAD_FILE buf1;
    TSK_DADDR_T i;
    ext2fs_journ_head *head;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if ((jinfo == NULL) || (jinfo->fs_file == NULL)
        || (jinfo->fs_file->meta == NULL)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("ext2fs_jblk_walk: journal is not open");
        return 1;
    }

    if (jinfo->last_block < end) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("ext2fs_jblk_walk: end is too large ");
        return 1;
    }

    if (start != end) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("ext2fs_blk_walk: only start == end is currently supported");
        return 1;
    }

    if (jinfo->fs_file->meta->size !=
        (jinfo->last_block + 1) * jinfo->bsize) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
        tsk_error_set_errstr
            ("ext2fs_jblk_walk: journal file size is different from size reported in journal super block");
        return 1;
    }


    /* Load into buffer and then process it 
     * Only get the minimum needed
     */
    buf1.left = buf1.total = (size_t) ((end + 1) * jinfo->bsize);
    journ = buf1.cur = buf1.base = tsk_malloc(buf1.left);
    if (journ == NULL) {
        return 1;
    }

    if (tsk_fs_file_walk(jinfo->fs_file, 0, tsk_fs_load_file_action,
            (void *) &buf1)) {
        free(journ);
        return 1;
    }

    if (buf1.left > 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_FWALK);
        tsk_error_set_errstr("ext2fs_jblk_walk: Buffer not fully copied");
        free(journ);
        return 1;
    }

    head = (ext2fs_journ_head *) & journ[end * jinfo->bsize];


    /* Check if our target block is a journal data structure.
     * 
     * If not, 
     * we need to look for its descriptor to see if it has been
     * escaped
     */
    if (big_tsk_getu32(head->magic) != EXT2_JMAGIC) {

        /* cycle backwards until we find a desc block */
        for (i = end - 1; i >= 0; i--) {
            ext2fs_journ_dentry *dentry;
            TSK_DADDR_T diff;

            head = (ext2fs_journ_head *) & journ[i * jinfo->bsize];

            if (big_tsk_getu32(head->magic) != EXT2_JMAGIC)
                continue;

            /* If we get a commit, then any desc we find will not
             * be for our block, so forget about it */
            if (big_tsk_getu32(head->entry_type) == EXT2_J_ETYPE_COM)
                break;

            /* Skip any other data structure types */
            if (big_tsk_getu32(head->entry_type) != EXT2_J_ETYPE_DESC)
                continue;

            /* We now have the previous descriptor 
             *
             * NOTE: We have no clue if this is the correct 
             * descriptor if it is not the current 'run' of 
             * transactions, but this is the best we can do
             */
            diff = end - i;

            dentry =
                (ext2fs_journ_dentry *) (&journ[i * jinfo->bsize] +
                sizeof(ext2fs_journ_head));

            while ((uintptr_t) dentry <=
                ((uintptr_t) & journ[(i + 1) * jinfo->bsize] -
                    sizeof(ext2fs_journ_head))) {

                if (--diff == 0) {
                    if (big_tsk_getu32(dentry->flag) & EXT2_J_DENTRY_ESC) {
                        journ[end * jinfo->bsize] = 0xC0;
                        journ[end * jinfo->bsize + 1] = 0x3B;
                        journ[end * jinfo->bsize + 2] = 0x39;
                        journ[end * jinfo->bsize + 3] = 0x98;
                    }
                    break;
                }

                /* If the SAMEID value is set, then we advance by the size of the entry, otherwise add 16 for the ID */
                if (big_tsk_getu32(dentry->flag) & EXT2_J_DENTRY_SAMEID)
                    dentry =
                        (ext2fs_journ_dentry *) ((uintptr_t) dentry +
                        sizeof(ext2fs_journ_dentry));
                else
                    dentry =
                        (ext2fs_journ_dentry *) ((uintptr_t) dentry +
                        sizeof(ext2fs_journ_dentry) + 16);

            }
            break;
        }
    }

    if (fwrite(&journ[end * jinfo->bsize], jinfo->bsize, 1, stdout) != 1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WRITE);
        tsk_error_set_errstr
            ("ext2fs_jblk_walk: error writing buffer block");
        free(journ);
        return 1;
    }

    free(journ);
    return 0;
}
