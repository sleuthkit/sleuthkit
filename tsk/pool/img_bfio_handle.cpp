/*
 * The Sleuth Kit - Image BFIO handle
 *
 * Copyright (c) 2022 Joachim Metz <joachim.metz@gmail.com>
 *
 * This software is distributed under the Common Public License 1.0
 */

#include "tsk/base/tsk_base_i.h"

#ifdef HAVE_LIBBFIO

#include "img_bfio_handle.h"

#include <libbfio.h>

#include "tsk/img/tsk_img.h"

/* Initializes the image BFIO handle
 * Returns 1 if successful or -1 on error
 */
int img_bfio_handle_initialize(
     libbfio_handle_t **handle,
     TSK_IMG_INFO *image,
     TSK_OFF_T offset,
     libbfio_error_t **error )
{
	img_bfio_handle_t *img_bfio_handle = NULL;

	img_bfio_handle = (img_bfio_handle_t *) tsk_malloc( sizeof( img_bfio_handle_t ) );

	if( img_bfio_handle == NULL )
	{
		return( -1 );
	}
	img_bfio_handle->image = image;
	img_bfio_handle->base_offset = offset;
	img_bfio_handle->logical_offset = 0;
	img_bfio_handle->access_flags = LIBBFIO_ACCESS_FLAG_READ;

	if( libbfio_handle_initialize(
	     handle,
	     (intptr_t *) img_bfio_handle,
	     (int (*)(intptr_t **, libbfio_error_t **)) img_bfio_handle_free,
	     NULL,
	     (int (*)(intptr_t *, int, libbfio_error_t **)) img_bfio_handle_open,
	     (int (*)(intptr_t *, libbfio_error_t **)) img_bfio_handle_close,
	     (ssize_t (*)(intptr_t *, uint8_t *, size_t, libbfio_error_t **)) img_bfio_handle_read,
	     NULL,
	     (off64_t (*)(intptr_t *, off64_t, int, libbfio_error_t **)) img_bfio_handle_seek_offset,
	     (int (*)(intptr_t *, libbfio_error_t **)) img_bfio_handle_exists,
	     (int (*)(intptr_t *, libbfio_error_t **)) img_bfio_handle_is_open,
	     (int (*)(intptr_t *, size64_t *, libbfio_error_t **)) img_bfio_handle_get_size,
	     LIBBFIO_FLAG_IO_HANDLE_MANAGED | LIBBFIO_FLAG_IO_HANDLE_CLONE_BY_FUNCTION,
	     error ) != 1 )
	{
		free(
		 img_bfio_handle );

		return( -1 );
	}
	return( 1 );
}

/* Frees an image BFIO handle
 * Returns 1 if succesful or -1 on error
 */
int img_bfio_handle_free(
  img_bfio_handle_t **img_bfio_handle,
  [[maybe_unused]] libbfio_error_t **error)
{
	if( img_bfio_handle == NULL )
	{
		return( -1 );
	}
	if( *img_bfio_handle != NULL )
	{
		free(
		 *img_bfio_handle );

		*img_bfio_handle = NULL;
	}
	return( 1 );
}

/* Opens the image BFIO handle
 * Returns 1 if successful or -1 on error
 */
int img_bfio_handle_open(
  img_bfio_handle_t *img_bfio_handle,
  int access_flags,
  [[maybe_unused]] libbfio_error_t **error)
{
	if( img_bfio_handle == NULL )
	{
		return( -1 );
	}
	if( img_bfio_handle->image == NULL )
	{
		return( -1 );
	}
	if( ( ( access_flags & LIBBFIO_ACCESS_FLAG_READ ) != 0 )
	 && ( ( access_flags & LIBBFIO_ACCESS_FLAG_WRITE ) != 0 ) )
	{
		return( -1 );
	}
	if( ( access_flags & LIBBFIO_ACCESS_FLAG_WRITE ) != 0 )
	{
		return( -1 );
	}
	/* No need to do anything here, because the file object is already open
	 */
	img_bfio_handle->access_flags = access_flags;

	return( 1 );
}

/* Closes the image BFIO handle
 * Returns 0 if successful or -1 on error
 */
int img_bfio_handle_close(
  img_bfio_handle_t *img_bfio_handle,
  [[maybe_unused]] libbfio_error_t **error)
{
	if( img_bfio_handle == NULL )
	{
		return( -1 );
	}
	if( img_bfio_handle->image == NULL )
	{
		return( -1 );
	}
	/* Do not close the image, have Sleuthkit deal with it
	 */
	img_bfio_handle->access_flags = 0;

	return( 0 );
}

/* Reads a buffer from the image BFIO handle
 * Returns the number of bytes read if successful, or -1 on error
 */
ssize_t img_bfio_handle_read(
  img_bfio_handle_t *img_bfio_handle,
  uint8_t *buffer,
  size_t size,
  [[maybe_unused]] libbfio_error_t **error)
{
	ssize_t read_count = 0;

	if( img_bfio_handle == NULL )
	{
		return( -1 );
	}
	read_count = tsk_img_read(
	              img_bfio_handle->image,
	              img_bfio_handle->base_offset + img_bfio_handle->logical_offset,
	              (char *) buffer,
	              size );

	if( read_count == -1 )
	{
		return( -1 );
	}
	return( read_count );
}

/* Seeks a certain offset within the image BFIO handle
 * Returns the offset if the seek is successful or -1 on error
 */
off64_t img_bfio_handle_seek_offset(
  img_bfio_handle_t *img_bfio_handle,
  off64_t offset,
  int whence,
  [[maybe_unused]] libbfio_error_t **error)
{
	if( img_bfio_handle == NULL )
	{
		return( -1 );
	}
/* TODO add support for SEEK_CUR and SEEK_CUR */
	if( whence != SEEK_SET )
	{
		return( -1 );
	}
	img_bfio_handle->logical_offset = offset;

	return( offset );
}

/* Function to determine if a file exists
 * Returns 1 if file exists, 0 if not or -1 on error
 */
int img_bfio_handle_exists(
  img_bfio_handle_t *img_bfio_handle,
  [[maybe_unused]] libbfio_error_t **error)
{
	if( img_bfio_handle == NULL )
	{
		return( -1 );
	}
	if( img_bfio_handle->image == NULL )
	{
		return( 0 );
	}
	return( 1 );
}

/* Check if the file is open
 * Returns 1 if open, 0 if not or -1 on error
 */
int img_bfio_handle_is_open(
  img_bfio_handle_t *img_bfio_handle,
  [[maybe_unused]] libbfio_error_t **error)
{
	if( img_bfio_handle == NULL )
	{
		return( -1 );
	}
	if( img_bfio_handle->image == NULL )
	{
		return( -1 );
	}
	/* As far as BFIO is concerned the file object is always open
	 */
	return( 1 );
}

/* Retrieves the file size
 * Returns 1 if successful or -1 on error
 */
int img_bfio_handle_get_size(
  img_bfio_handle_t *img_bfio_handle,
  size64_t *size,
  [[maybe_unused]] libbfio_error_t **error)
{
	if( img_bfio_handle == NULL )
	{
		return( -1 );
	}
	if( img_bfio_handle->image == NULL )
	{
		return( -1 );
	}
	if( size == NULL )
	{
		return( -1 );
	}
	*size = img_bfio_handle->image->size;

	return( 1 );
}

#endif /* HAVE_LIBBFIO */

