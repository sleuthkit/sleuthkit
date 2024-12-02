/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
 *
 * tsk_vs_open - wrapper function for specific partition type
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file mm_open.c
 * Contains general code to open volume systems.
 */

#include "tsk_vs_i.h"
#include "tsk/util/detect_encryption.h"


/**
 * \ingroup vslib
 *
 * Open a disk image and process the media management system
 * data.  This calls VS specific code to determine the type and
 * collect data.
 *
 * @param img_info The opened disk image.
 * @param offset Byte offset in the disk image to start analyzing from.
 * @param type Type of volume system (including auto detect)
 *
 * @return NULL on error.
 */
TSK_VS_INFO *
tsk_vs_open(TSK_IMG_INFO * img_info, TSK_DADDR_T offset,
    TSK_VS_TYPE_ENUM type)
{
    if (img_info == NULL) {
        /* Opening the image file(s) failed, if attempted. */
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_NOFILE);
        tsk_error_set_errstr("mm_open");
        return NULL;
    }

	if (img_info->itype == TSK_IMG_TYPE_LOGICAL) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_VS_UNSUPTYPE);
		tsk_error_set_errstr("Logical image type can not have a volume system");
		return NULL;
	}

    /* Autodetect mode
     * We need to try all of them in case there are multiple
     * installations
     *
     * NOte that errors that are encountered during the testing process
     * will not be reported
     */
    if (type == TSK_VS_TYPE_DETECT) {
        TSK_VS_INFO *vs, *prev_vs = NULL;
        char *prev_type = NULL;

        if ((vs = tsk_vs_dos_open(img_info, offset, 1)) != NULL) {
            prev_type = "DOS";
            prev_vs = vs;
        }
        else {
            tsk_error_reset();
        }

        if ((vs = tsk_vs_bsd_open(img_info, offset)) != NULL) {
            // if (prev_type == NULL) {
            // In this case, BSD takes priority because BSD partitions start off with
            // the DOS magic value in the first sector with the boot code.
            prev_type = "BSD";
            prev_vs = vs;
            /*
               }
               else {
               prev_vs->close(prev_vs);
               vs->close(vs);
               tsk_error_reset();
               tsk_error_set_errno(TSK_ERR_VS_UNKTYPE);
               tsk_error_set_errstr(
               "BSD or %s at %" PRIuDADDR, prev_type, offset);
               tsk_errstr2[0] = '\0';
               return NULL;
               }
             */
        }
        else {
            tsk_error_reset();
        }

        if ((vs = tsk_vs_gpt_open(img_info, offset)) != NULL) {

            if ((prev_type != NULL) && (strcmp(prev_type, "DOS") == 0) && (vs->is_backup)) {
                /* In this case we've found a DOS partition and a backup GPT partition.
                 * The DOS partition takes priority in this case (and are already in prev_type and prev_vs) */
                vs->close(vs);
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "mm_open: Ignoring secondary GPT Partition\n");
            }
            else {
                if (prev_type != NULL) {

                    /* GPT drives have a DOS Safety partition table.
                     * Test to see if the GPT has a safety partiiton
                     * and then we can igore the DOS */
                    if (strcmp(prev_type, "DOS") == 0) {
                        TSK_VS_PART_INFO *tmp_set;
                        for (tmp_set = prev_vs->part_list; tmp_set;
                            tmp_set = tmp_set->next) {
                            if ((tmp_set->desc)
                                && (strncmp(tmp_set->desc, "GPT Safety",
                                    10) == 0)
                                && (tmp_set->start <= 63)) {

                                if (tsk_verbose)
                                    tsk_fprintf(stderr,
                                        "mm_open: Ignoring DOS Safety GPT Partition\n");
                                prev_type = NULL;
                                prev_vs->close(prev_vs);
                                prev_vs = NULL;
                                break;
                            }
                        }
                    }

                    /* If we never found the safety, then we have a conflict. */
                    if (prev_type != NULL) {
                        prev_vs->close(prev_vs);
                        vs->close(vs);
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_VS_MULTTYPE);
                        tsk_error_set_errstr("GPT or %s at %" PRIuDADDR, prev_type,
                            offset);
                        return NULL;
                    }
                }
                prev_type = "GPT";
                prev_vs = vs;
            }
        }
        else {
            tsk_error_reset();
        }

        if ((vs = tsk_vs_sun_open(img_info, offset)) != NULL) {
            if (prev_type == NULL) {
                prev_type = "Sun";
                prev_vs = vs;
            }
            else {
                prev_vs->close(prev_vs);
                vs->close(vs);
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_VS_MULTTYPE);
                tsk_error_set_errstr("Sun or %s at %" PRIuDADDR, prev_type,
                    offset);
                return NULL;
            }
        }
        else {
            tsk_error_reset();
        }

        if ((vs = tsk_vs_mac_open(img_info, offset)) != NULL) {
            if (prev_type == NULL) {
                prev_type = "Mac";
                prev_vs = vs;
            }
            else {
                prev_vs->close(prev_vs);
                vs->close(vs);
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_VS_MULTTYPE);
                tsk_error_set_errstr("Mac or %s at %" PRIuDADDR, prev_type,
                    offset);
                return NULL;
            }
        }
        else {
            tsk_error_reset();
        }

        if (prev_vs == NULL) {
            tsk_error_reset();

            // Check whether the volume system appears to be encrypted.
            // Note that detectDiskEncryption does not do an entropy calculation - high entropy
            // files will be reported by tsk_fs_open_img().
            encryption_detected_result* result = detectDiskEncryption(img_info, offset);
            if (result != NULL) {
                if (result->encryptionType == ENCRYPTION_DETECTED_SIGNATURE) {
                    tsk_error_set_errno(TSK_ERR_VS_ENCRYPTED);
                    tsk_error_set_errstr("%s", result->desc);
                }
                free(result);
                result = NULL;
            }
            else {
                tsk_error_set_errno(TSK_ERR_VS_UNKTYPE);
            }
            return NULL;
        }

        return prev_vs;
    }

    // Not autodetect
    else {

        switch (type) {
        case TSK_VS_TYPE_DOS:
            return tsk_vs_dos_open(img_info, offset, 0);
        case TSK_VS_TYPE_MAC:
            return tsk_vs_mac_open(img_info, offset);
        case TSK_VS_TYPE_BSD:
            return tsk_vs_bsd_open(img_info, offset);
        case TSK_VS_TYPE_SUN:
            return tsk_vs_sun_open(img_info, offset);
        case TSK_VS_TYPE_GPT:
            return tsk_vs_gpt_open(img_info, offset);
        case TSK_VS_TYPE_APFS: // Not supported yet
        case TSK_VS_TYPE_LVM: // Not supported yet
        case TSK_VS_TYPE_UNSUPP:
        default:
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_UNSUPTYPE);
            tsk_error_set_errstr("%d", type);
            return NULL;
        }
    }
}

/**
 * \ingroup vslib
 * Closes an open volume system
 * @param a_vs Pointer to the open volume system structure.
 */
void
tsk_vs_close(TSK_VS_INFO * a_vs)
{
    if (a_vs == NULL) {
        return;
    }
    a_vs->close((TSK_VS_INFO *) a_vs);
}
