/*
 * The Sleuth Kit - Image BFIO handle
 *
 * Copyright (c) 2022 Joachim Metz <joachim.metz@gmail.com>
 *
 * This software is distributed under the Common Public License 1.0
 */

#if !defined( _IMG_BFIO_HANDLE_H )
#define _IMG_BFIO_HANDLE_H

#include "tsk/base/tsk_base_i.h"

#ifdef HAVE_LIBBFIO

#include <libbfio.h>

#include "tsk/img/tsk_img.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct img_bfio_handle img_bfio_handle_t;

struct img_bfio_handle
{
	TSK_IMG_INFO *image;
	TSK_OFF_T base_offset;
	TSK_OFF_T logical_offset;
	int access_flags;
};

int img_bfio_handle_initialize(
     libbfio_handle_t **handle,
     TSK_IMG_INFO *image,
     TSK_OFF_T offset,
     libbfio_error_t **error );

int img_bfio_handle_free(
     img_bfio_handle_t **img_bfio_handle,
     libbfio_error_t **error );

int img_bfio_handle_clone(
     img_bfio_handle_t **destination_img_bfio_handle,
     img_bfio_handle_t *source_img_bfio_handle,
     libbfio_error_t **error );

int img_bfio_handle_open(
     img_bfio_handle_t *img_bfio_handle,
     int access_flags,
     libbfio_error_t **error );

int img_bfio_handle_close(
     img_bfio_handle_t *img_bfio_handle,
     libbfio_error_t **error );

ssize_t img_bfio_handle_read(
         img_bfio_handle_t *img_bfio_handle,
         uint8_t *buffer,
         size_t size,
         libbfio_error_t **error );

off64_t img_bfio_handle_seek_offset(
         img_bfio_handle_t *img_bfio_handle,
         off64_t offset,
         int whence,
         libbfio_error_t **error );

int img_bfio_handle_exists(
     img_bfio_handle_t *img_bfio_handle,
     libbfio_error_t **error );

int img_bfio_handle_is_open(
     img_bfio_handle_t *img_bfio_handle,
     libbfio_error_t **error );

int img_bfio_handle_get_size(
     img_bfio_handle_t *img_bfio_handle,
     size64_t *size,
     libbfio_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* HAVE_LIBBFIO */

#endif /* !defined( _IMG_BFIO_HANDLE_H ) */

