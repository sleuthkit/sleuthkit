/*
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2005 Brian Carrier.  All rights reserved
 *
 * raw
 *
 * This software is distributed under the Common Public License 1.0
 *
 */


/**
 * \file img_writer.c
 * Internal code to create an image on disk from a raw data source
 */

#include "tsk_img_i.h"
#include "img_writer.h"
#include "raw.h"

#ifdef TSK_WIN32
#include <winioctl.h>
#endif

TSK_RETVAL_ENUM tsk_img_writer_add(TSK_IMG_WRITER* img_writer, TSK_OFF_T addr, char *buffer, size_t len) {
#ifndef TSK_WIN32
    return TSK_ERR;
#else
    if (tsk_verbose) {
        tsk_fprintf(stderr,
            "tsk_img_writer_add: Adding data at offset: %"
            PRIuOFF " len: %" PRIuOFF "\n", addr,
            (TSK_OFF_T)len);
    }
    return TSK_OK;
#endif
}
TSK_RETVAL_ENUM tsk_img_writer_close(TSK_IMG_WRITER* img_writer) {
#ifndef TSK_WIN32
    return TSK_ERR;
#else
    if (tsk_verbose) {
        tsk_fprintf(stderr,
            "tsk_img_writer_close: Closing image writer");
    }
    return TSK_OK;
#endif
}
TSK_RETVAL_ENUM tsk_img_writer_finish_image(TSK_IMG_WRITER* img_writer) {
#ifndef TSK_WIN32
    return TSK_ERR;
#else
    if (tsk_verbose) {
        tsk_fprintf(stderr,
            "tsk_img_writer_finish_image: Finishing image");
    }
    img_writer->is_finished = 1;
    return TSK_OK;
#endif
}

/*
 * Create and initailize the TSK_IMG_WRITER struct and save reference in img_info
 */
TSK_RETVAL_ENUM tsk_img_writer_create(TSK_IMG_INFO * img_info, const TSK_TCHAR * directory,
    const TSK_TCHAR * basename) {

#ifndef TSK_WIN32
    return TSK_ERR;
#else
    if (tsk_verbose) {
        tsk_fprintf(stderr,
            "tsk_img_writer_create: Creating image writer in directory %s with basename %s\n",
            directory, basename);
    }

    IMG_RAW_INFO* raw_info = (IMG_RAW_INFO *)img_info;

    /* This should not be run on split images*/
    if (raw_info->num_img != 1) {
        return TSK_ERR;
    }

    if ((raw_info->img_writer = (TSK_IMG_WRITER *)tsk_malloc(sizeof(TSK_IMG_WRITER))) == NULL)
        return TSK_ERR;
    raw_info->img_writer->is_finished = 0;
    raw_info->img_writer->add = tsk_img_writer_add;
    raw_info->img_writer->close = tsk_img_writer_close;
    raw_info->img_writer->finish_image = tsk_img_writer_finish_image;

    return TSK_OK;
#endif
}


