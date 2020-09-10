#include "../libtsk.h"
#include "tsk_fs_i.h"
#include "decmpfs.h"

#ifdef HAVE_LIBZ
#include <zlib.h>
#endif

#include "lzvn.h"
#include "tsk_hfs.h"

#ifdef HAVE_LIBZ

/***************** ZLIB stuff *******************************/

// Adapted from zpipe.c (part of zlib) at http://zlib.net/zpipe.c
#define CHUNK 16384

/*
 * Invokes the zlib library to inflate (uncompress) data.
 *
 * Returns and error code.  Places the uncompressed data in a buffer supplied by the caller.  Also
 * returns the uncompressed length, and the number of compressed bytes consumed.
 *
 * Will stop short of the end of compressed data, if a natural end of a compression unit is reached.  Using
 * bytesConsumed, the caller can then advance the source pointer, and re-invoke the function.  This will then
 * inflate the next following compression unit in the data stream.
 *
 * @param source - buffer of compressed data
 * @param sourceLen  - length of the compressed data.
 * @param dest  -- buffer to  hold the uncompressed results
 * @param destLen -- length of the dest buffer
 * @param uncompressedLength  -- return of the length of the uncompressed data found.
 * @param bytesConsumed  -- return of the number of input bytes of compressed data used.
 * @return 0 on success, a negative number on error
 */
int
zlib_inflate(char *source, uint64_t sourceLen, char *dest, uint64_t destLen, uint64_t * uncompressedLength, unsigned long *bytesConsumed)       // this is unsigned long because that's what zlib uses.
{

    int ret;
    unsigned have;
    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    // Some vars to help with copying bytes into "in"
    char *srcPtr = source;
    char *destPtr = dest;
    uint64_t srcAvail = sourceLen;      //uint64_t
    uint64_t amtToCopy;
    uint64_t copiedSoFar = 0;

    /* allocate inflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit(&strm);
    if (ret != Z_OK) {
        error_detected(TSK_ERR_FS_READ,
            "zlib_inflate: failed to initialize inflation engine (%d)",
            ret);
        return ret;
    }

    /* decompress until deflate stream ends or end of file */
    do {

        // Copy up to CHUNK bytes into "in" from source, advancing the pointer, and
        // setting strm.avail_in equal to the number of bytes copied.
        if (srcAvail >= CHUNK) {
            amtToCopy = CHUNK;
            srcAvail -= CHUNK;
        }
        else {
            amtToCopy = srcAvail;
            srcAvail = 0;
        }
        // wipe out any previous value, copy in the bytes, advance the pointer, record number of bytes.
        memset(in, 0, CHUNK);
        if (amtToCopy > SIZE_MAX || amtToCopy > UINT_MAX) {
            error_detected(TSK_ERR_FS_READ,
                "zlib_inflate: amtToCopy in one chunk is too large");
            return -100;
        }
        memcpy(in, srcPtr, (size_t) amtToCopy); // cast OK because of above test
        srcPtr += amtToCopy;
        strm.avail_in = (uInt) amtToCopy;       // cast OK because of above test

        if (strm.avail_in == 0)
            break;
        strm.next_in = in;

        /* run inflate() on input until output buffer not full */
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, Z_NO_FLUSH);
            if (ret == Z_NEED_DICT)
                ret = Z_DATA_ERROR;     // we don't have a custom dict
            if (ret < 0 && ret != Z_BUF_ERROR) { // Z_BUF_ERROR is not fatal
                error_detected(TSK_ERR_FS_READ,
                    " zlib_inflate: zlib returned error %d (%s)", ret,
                    strm.msg);
                (void) inflateEnd(&strm);
                return ret;
            }

            have = CHUNK - strm.avail_out;
            // Is there enough space in dest to copy the current chunk?
            if (copiedSoFar + have > destLen) {
                // There is not enough space, so better return an error
                error_detected(TSK_ERR_FS_READ,
                    " zlib_inflate: not enough space in inflation destination\n");
                (void) inflateEnd(&strm);
                return -200;
            }

            // Copy "have" bytes from out to destPtr, advance destPtr
            memcpy(destPtr, out, have);
            destPtr += have;
            copiedSoFar += have;

        } while ((strm.avail_out == 0) && (ret != Z_STREAM_END));


        /* done when inflate() says it's done */
    } while (ret != Z_STREAM_END);

    if (ret == Z_STREAM_END)
        *uncompressedLength = copiedSoFar;

    *bytesConsumed = strm.total_in;
    /* clean up and return */
    (void) inflateEnd(&strm);
    return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}

#endif

typedef struct {
    uint32_t offset;
    uint32_t length;
} CMP_OFFSET_ENTRY;

/**
 * \internal
 * Reads the ZLIB compression block table from the attribute.
 *
 * @param rAtttr the attribute to read
 * @param offsetTableOut block table
 * @param tableSizeOut size of block table
 * @param tableOffsetOut the offset of the block table in the resource fork
 * @return 1 on success, 0 on error
 */
static int
decmpfs_read_zlib_block_table(const TSK_FS_ATTR *rAttr, CMP_OFFSET_ENTRY** offsetTableOut, uint32_t* tableSizeOut, uint32_t* tableOffsetOut) {
    ssize_t attrReadResult;
    hfs_resource_fork_header rfHeader;
    uint32_t dataOffset;
    uint32_t offsetTableOffset;
    char fourBytes[4];          // Size of the offset table, little endian
    uint32_t tableSize;         // Size of the offset table
    char *offsetTableData = NULL;
    CMP_OFFSET_ENTRY *offsetTable = NULL;
    size_t indx;

    // Read the resource fork header
    attrReadResult = tsk_fs_attr_read(rAttr, 0, (char *) &rfHeader,
        sizeof(hfs_resource_fork_header), TSK_FS_FILE_READ_FLAG_NONE);
    if (attrReadResult != sizeof(hfs_resource_fork_header)) {
        error_returned
            (" %s: trying to read the resource fork header", __func__);
        return 0;
    }

    // Begin to parse the resource fork. For now, we just need the data offset.
    dataOffset = tsk_getu32(TSK_BIG_ENDIAN, rfHeader.dataOffset);

    // The resource's data begins with an offset table, which defines blocks
    // of (optionally) zlib-compressed data (so that the OS can do file seeks
    // efficiently; each uncompressed block is 64KB).
    offsetTableOffset = dataOffset + 4;

    // read 4 bytes, the number of table entries, little endian
    attrReadResult =
        tsk_fs_attr_read(rAttr, offsetTableOffset, fourBytes, 4,
        TSK_FS_FILE_READ_FLAG_NONE);
    if (attrReadResult != 4) {
        error_returned
            (" %s: trying to read the offset table size, "
            "return value of %u should have been 4", __func__, attrReadResult);
        return 0;
    }
    tableSize = tsk_getu32(TSK_LIT_ENDIAN, fourBytes);

    // Each table entry is 8 bytes long
    offsetTableData = tsk_malloc(tableSize * 8);
    if (offsetTableData == NULL) {
        error_returned
            (" %s: space for the offset table raw data", __func__);
        return 0;
    }

    offsetTable =
        (CMP_OFFSET_ENTRY *) tsk_malloc(tableSize *
        sizeof(CMP_OFFSET_ENTRY));
    if (offsetTable == NULL) {
        error_returned
            (" %s: space for the offset table", __func__);
        goto on_error;
    }

    attrReadResult = tsk_fs_attr_read(rAttr, offsetTableOffset + 4,
        offsetTableData, tableSize * 8, TSK_FS_FILE_READ_FLAG_NONE);
    if (attrReadResult != (ssize_t) tableSize * 8) {
        error_returned
            (" %s: reading in the compression offset table, "
            "return value %u should have been %u", __func__, attrReadResult,
            tableSize * 8);
        goto on_error;
    }

    for (indx = 0; indx < tableSize; ++indx) {
        offsetTable[indx].offset =
            tsk_getu32(TSK_LIT_ENDIAN, offsetTableData + indx * 8);
        offsetTable[indx].length =
            tsk_getu32(TSK_LIT_ENDIAN, offsetTableData + indx * 8 + 4);
    }

    free(offsetTableData);

    *offsetTableOut = offsetTable;
    *tableSizeOut = tableSize;
    *tableOffsetOut = offsetTableOffset;
    return 1;

on_error:
    free(offsetTable);
    free(offsetTableData);
    return 0;
}

/**
 * \internal
 * Reads the LZVN compression block table from the attribute.
 *
 * @param rAtttr the attribute to read
 * @param offsetTableOut block table
 * @param tableSizeOut size of block table
 * @param tableOffsetOut the offset of the block table in the resource fork
 * @return 1 on success, 0 on error
 */
static int
decmpfs_read_lzvn_block_table(const TSK_FS_ATTR *rAttr, CMP_OFFSET_ENTRY** offsetTableOut, uint32_t* tableSizeOut, uint32_t* tableOffsetOut) {
    ssize_t attrReadResult;
    char fourBytes[4];
    uint32_t tableDataSize;
    uint32_t tableSize;         // Size of the offset table
    char *offsetTableData = NULL;
    CMP_OFFSET_ENTRY *offsetTable = NULL;

    // The offset table is a sequence of 4-byte offsets of compressed
    // blocks. The first 4 bytes is thus the offset of the first block,
    // but also 4 times the number of entries in the table.
    attrReadResult = tsk_fs_attr_read(rAttr, 0, fourBytes, 4,
                                      TSK_FS_FILE_READ_FLAG_NONE);
    if (attrReadResult != 4) {
        error_returned
            (" %s: trying to read the offset table size, "
            "return value of %u should have been 4", __func__, attrReadResult);
        return 0;
    }

    tableDataSize = tsk_getu32(TSK_LIT_ENDIAN, fourBytes);

    offsetTableData = tsk_malloc(tableDataSize);
    if (offsetTableData == NULL) {
        error_returned
            (" %s: space for the offset table raw data", __func__);
        return 0;
    }

    // table entries are 4 bytes, last entry is end of data
    tableSize = tableDataSize / 4 - 1;

    offsetTable =
        (CMP_OFFSET_ENTRY *) tsk_malloc(tableSize *
        sizeof(CMP_OFFSET_ENTRY));
    if (offsetTable == NULL) {
        error_returned
            (" %s: space for the offset table", __func__);
        goto on_error;
    }

    attrReadResult = tsk_fs_attr_read(rAttr, 0,
        offsetTableData, tableDataSize, TSK_FS_FILE_READ_FLAG_NONE);
    if (attrReadResult != (ssize_t) tableDataSize) {
        error_returned
            (" %s: reading in the compression offset table, "
            "return value %u should have been %u", __func__, attrReadResult,
            tableDataSize);
        goto on_error;
    }

    uint32_t a = tableDataSize;
    uint32_t b;
    size_t i;

    for (i = 0; i < tableSize; ++i) {
        b = tsk_getu32(TSK_LIT_ENDIAN, offsetTableData + 4*(i+1));
        offsetTable[i].offset = a;
        offsetTable[i].length = b - a;
        a = b;
    }

    free(offsetTableData);

    *offsetTableOut = offsetTable;
    *tableSizeOut = tableSize;
    *tableOffsetOut = 0;
    return 1;

on_error:
    free(offsetTable);
    free(offsetTableData);
    return 0;
}

/**
 * \internal
 * "Decompress" a block which was stored uncompressed.
 *
 * @param rawBuf the compressed data
 * @param len length of the compressed data
 * @param uncBuf the decompressed data
 * @param uncLen length of the decompressed data
 * @return 1 on success, 0 on error
 */
static int decmpfs_decompress_noncompressed_block(char* rawBuf, uint32_t len, char* uncBuf, uint64_t* uncLen) {
    // actually an uncompressed block of data; just copy
    if (tsk_verbose)
        tsk_fprintf(stderr,
           "%s: Copying an uncompressed compression unit\n", __func__);

    if ((len - 1) > COMPRESSION_UNIT_SIZE) {
        error_detected(TSK_ERR_FS_READ,
            "%s: uncompressed block length %u is longer "
            "than compression unit size %u", __func__, len - 1,
            COMPRESSION_UNIT_SIZE);
        return 0;
    }
    memcpy(uncBuf, rawBuf + 1, len - 1);
    *uncLen = len - 1;
    return 1;
}


#ifdef HAVE_LIBZ
/**
 * \internal
 * Decompress a block which was stored with ZLIB.
 *
 * @param rawBuf the compressed data
 * @param len length of the compressed data
 * @param uncBuf the decompressed data
 * @param uncLen length of the decompressed data
 * @return 1 on success, 0 on error
 */
static int decmpfs_decompress_zlib_block(char* rawBuf, uint32_t len, char* uncBuf, uint64_t* uncLen)
{
    // see if this block is compressed
    if (len > 0 && (rawBuf[0] & 0x0F) != 0x0F) {
        // Uncompress the chunk of data
        if (tsk_verbose)
            tsk_fprintf(stderr,
                        "%s: Inflating the compression unit\n", __func__);

        unsigned long bytesConsumed;
        int infResult = zlib_inflate(rawBuf, (uint64_t) len,
            uncBuf, (uint64_t) COMPRESSION_UNIT_SIZE,
            uncLen, &bytesConsumed);
        if (infResult != 0) {
            error_returned
                  (" %s: zlib inflation (uncompression) failed",
                  __func__, infResult);
            return 0;
        }

        if (bytesConsumed != len) {
            error_detected(TSK_ERR_FS_READ,
                " %s, decompressor did not consume the whole compressed data",
                __func__);
            return 0;
        }

        return 1;
    }
    else {
        // actually an uncompressed block of data; just copy
        return decmpfs_decompress_noncompressed_block(rawBuf, len, uncBuf, uncLen);
    }
}
#endif

/**
 * \internal
 * Decompress a block which was stored with LZVN.
 *
 * @param rawBuf the compressed data
 * @param len length of the compressed data
 * @param uncBuf the decompressed data
 * @param uncLen length of the decompressed data
 * @return 1 on success, 0 on error
 */
static int decmpfs_decompress_lzvn_block(char* rawBuf, uint32_t len, char* uncBuf, uint64_t* uncLen)
{
    // see if this block is compressed
    if (len > 0 && rawBuf[0] != 0x06) {
        *uncLen = lzvn_decode_buffer(uncBuf, COMPRESSION_UNIT_SIZE, rawBuf, len);
        return 1;  // apparently this can't fail
    }
    else {
        // actually an uncompressed block of data; just copy
        return decmpfs_decompress_noncompressed_block(rawBuf, len, uncBuf, uncLen);
    }
}

/**
 * \internal
 * Decompress a block.
 *
 * @param rAttr the attribute to read
 * @param rawBuf the compressed data
 * @param uncBuf the decompressed data
 * @param offsetTable table of compressed block offsets
 * @param offsetTableSize size of table of compressed block offsets
 * @param offsetTableOffset offset of table of compressed block offsets
 * @param indx index of block to read
 * @param decompress_block pointer to decompression function
 * @return decompressed size on success, -1 on error
 */
static ssize_t read_and_decompress_block(
  const TSK_FS_ATTR* rAttr,
  char* rawBuf,
  char* uncBuf,
  const CMP_OFFSET_ENTRY* offsetTable,
  uint32_t offsetTableSize,
  uint32_t offsetTableOffset,
  size_t indx,
  int (*decompress_block)(char* rawBuf,
                          uint32_t len,
                          char* uncBuf,
                          uint64_t* uncLen)
)
{
    // @@@ BC: Looks like we should have bounds checks that indx < offsetTableSize, but we should confirm
    ssize_t attrReadResult;
    uint32_t offset = offsetTableOffset + offsetTable[indx].offset;
    uint32_t len = offsetTable[indx].length;
    uint64_t uncLen;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "%s: Reading compression unit %d, length %d\n",
            __func__, indx, len);

    /* Github #383 referenced that if len is 0, then the below code causes
     * problems. Added this check, but I don't have data to verify this on.
     * it looks like it should at least not crash, but it isn't clear if it
     * will also do the right thing and if should actually break here
     * instead. */
    if (len == 0) {
        return 0;
    }

    if (len > COMPRESSION_UNIT_SIZE + 1) {
      error_detected(TSK_ERR_FS_READ,
          "%s: block size is too large: %u", __func__, len);
      return -1;
    }

    // Read in the block of compressed data
    attrReadResult = tsk_fs_attr_read(rAttr, offset,
        rawBuf, len, TSK_FS_FILE_READ_FLAG_NONE);
    if (attrReadResult != (ssize_t) len) {
        char msg[] =
            "%s%s: reading in the compression offset table, "
            "return value %u should have been %u";

        if (attrReadResult < 0 ) {
            error_returned(msg, " ", __func__, attrReadResult, len);
        }
        else {
            error_detected(TSK_ERR_FS_READ, "", __func__, attrReadResult, len);
        }
        return -1;
    }

    if (!decompress_block(rawBuf, len, uncBuf, &uncLen)) {
        return -1;
    }
/*
    // If size is a multiple of COMPRESSION_UNIT_SIZE,
    // expected uncompressed length is COMPRESSION_UNIT_SIZE
    const uint32_t expUncLen = indx == offsetTableSize - 1 ?
        ((rAttr->fs_file->meta->size - 1) % COMPRESSION_UNIT_SIZE) + 1 :
        COMPRESSION_UNIT_SIZE;

    if (uncLen != expUncLen) {
        error_detected(TSK_ERR_FS_READ,
            "%s: compressed block decompressed to %u bytes, "
            "should have been %u bytes", __func__, uncLen, expUncLen);
        return -1;
    }
*/

    // There are now uncLen bytes of uncompressed data available from
    // this comp unit.
    return (ssize_t)uncLen;
}

/**
 * \internal
 * Attr walk callback function for compressed resources
 *
 * @param fs_attr the attribute to read
 * @param flags
 * @param a_action action callback
 * @param ptr context for the action callback
 * @param read_block_table pointer to block table read function
 * @param decompress_block pointer to decompression function
 * @return 0 on success, 1 on error
 */
static uint8_t
decmpfs_attr_walk_compressed_rsrc(const TSK_FS_ATTR * fs_attr,
    int flags, TSK_FS_FILE_WALK_CB a_action, void *ptr,
    int (*read_block_table)(const TSK_FS_ATTR *rAttr,
                            CMP_OFFSET_ENTRY** offsetTableOut,
                            uint32_t* tableSizeOut,
                            uint32_t* tableOffsetOut),
    int (*decompress_block)(char* rawBuf,
                            uint32_t len,
                            char* uncBuf,
                            uint64_t* uncLen))
{
    TSK_FS_INFO *fs;
    TSK_FS_FILE *fs_file;
    const TSK_FS_ATTR *rAttr;   // resource fork attribute
    char *rawBuf = NULL;               // compressed data
    char *uncBuf = NULL;               // uncompressed data
    uint32_t offsetTableOffset;
    uint32_t offsetTableSize;         // The number of table entries
    CMP_OFFSET_ENTRY *offsetTable = NULL;
    size_t indx;                // index for looping over the offset table
    TSK_OFF_T off = 0;          // the offset in the uncompressed data stream consumed thus far

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "%s:  Entered, because this is a compressed file with compressed data in the resource fork\n", __func__);

    // clean up any error messages that are lying around
    tsk_error_reset();
    if ((fs_attr == NULL) || (fs_attr->fs_file == NULL)
        || (fs_attr->fs_file->meta == NULL)
        || (fs_attr->fs_file->fs_info == NULL)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: Null arguments given\n", __func__);
        return 1;
    }

    // Check that the ATTR being read is the main DATA resource, 128-0,
    // because this is the only one that can be compressed in HFS+
    if ((fs_attr->id != HFS_FS_ATTR_ID_DATA) ||
        (fs_attr->type != TSK_FS_ATTR_TYPE_HFS_DATA)) {
        error_detected(TSK_ERR_FS_ARG,
            "%s: arg specified an attribute %u-%u that is not the data fork, "
            "Only the data fork can be compressed.", __func__, fs_attr->type,
            fs_attr->id);
        return 1;
    }

    /* This MUST be a compressed attribute     */
    if (!(fs_attr->flags & TSK_FS_ATTR_COMP)) {
        error_detected(TSK_ERR_FS_FWALK,
            "%s: called with non-special attribute: %x",
            __func__, fs_attr->flags);
        return 1;
    }

    fs = fs_attr->fs_file->fs_info;
    fs_file = fs_attr->fs_file;

    /********  Open the Resource Fork ***********/

    // find the attribute for the resource fork
    rAttr =
        tsk_fs_file_attr_get_type(fs_file, TSK_FS_ATTR_TYPE_HFS_RSRC,
        HFS_FS_ATTR_ID_RSRC, FALSE);
    if (rAttr == NULL) {
        error_returned
            (" %s: could not get the attribute for the resource fork of the file", __func__);
        return 1;
    }

    // read the offset table from the fork header
    if (!read_block_table(rAttr, &offsetTable, &offsetTableSize, &offsetTableOffset)) {
      return 1;
    }

    // Allocate two buffers for the raw and uncompressed data
    /* Raw data can be COMPRESSION_UNIT_SIZE+1 if the data is not
     * compressed and there is a 1-byte flag that indicates that
     * the data is not compressed. */
    rawBuf = (char *) tsk_malloc(COMPRESSION_UNIT_SIZE + 1);
    if (rawBuf == NULL) {
        error_returned
            (" %s: buffers for reading and uncompressing", __func__);
        goto on_error;
    }

    uncBuf = (char *) tsk_malloc(COMPRESSION_UNIT_SIZE);
    if (uncBuf == NULL) {
        error_returned
            (" %s: buffers for reading and uncompressing", __func__);
        goto on_error;
    }

    // FOR entry in the table DO
    for (indx = 0; indx < offsetTableSize; ++indx) {
        ssize_t uncLen;        // uncompressed length
        unsigned int blockSize;
        uint64_t lumpSize;
        uint64_t remaining;
        char *lumpStart;

        switch ((uncLen = read_and_decompress_block(
                    rAttr, rawBuf, uncBuf,
                    offsetTable, offsetTableSize, offsetTableOffset, indx,
                    decompress_block)))
        {
        case -1:
            goto on_error;
        case  0:
            continue;
        default:
            break;
        }

        // Call the a_action callback with "Lumps"
        // that are at most the block size.
        blockSize = fs->block_size;
        remaining = uncLen;
        lumpStart = uncBuf;

        while (remaining > 0) {
            int retval;         // action return value
            lumpSize = remaining <= blockSize ? remaining : blockSize;

            // Apply the callback function
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "%s: Calling action on lump of size %"
                    PRIu64 " offset %" PRIu64 " in the compression unit\n",
                    __func__, lumpSize, uncLen - remaining);
            if (lumpSize > SIZE_MAX) {
                error_detected(TSK_ERR_FS_FWALK,
                    " %s: lumpSize is too large for the action", __func__);
                goto on_error;
            }

            retval = a_action(fs_attr->fs_file, off, 0, lumpStart,
                (size_t) lumpSize,   // cast OK because of above test
                TSK_FS_BLOCK_FLAG_COMP, ptr);

            if (retval == TSK_WALK_ERROR) {
                error_detected(TSK_ERR_FS | 201,
                    "%s: callback returned an error", __func__);
                goto on_error;
            }
            else if (retval == TSK_WALK_STOP) {
                break;
            }

            // Find the next lump
            off += lumpSize;
            remaining -= lumpSize;
            lumpStart += lumpSize;
        }
    }

    // Done, so free up the allocated resources.
    free(offsetTable);
    free(rawBuf);
    free(uncBuf);
    return 0;

on_error:
    free(offsetTable);
    free(rawBuf);
    free(uncBuf);
    return 1;
}


#ifdef HAVE_LIBZ
/**
 * \internal
 * Attr walk callback function for ZLIB compressed resources
 *
 * @param fs_attr the attribute to read
 * @param flags
 * @param a_action action callback
 * @param ptr context for the action callback
 * @return 0 on success, 1 on error
 */
uint8_t
decmpfs_attr_walk_zlib_rsrc(const TSK_FS_ATTR * fs_attr,
    int flags, TSK_FS_FILE_WALK_CB a_action, void *ptr)
{
    return decmpfs_attr_walk_compressed_rsrc(
      fs_attr, flags, a_action, ptr,
      decmpfs_read_zlib_block_table,
      decmpfs_decompress_zlib_block
    );
}
#endif

/**
 * \internal
 * Attr walk callback function for LZVN compressed resources
 *
 * @param fs_attr the attribute to read
 * @param flags
 * @param a_action action callback
 * @param ptr context for the action callback
 * @return 0 on success, 1 on error
 */
uint8_t
decmpfs_attr_walk_lzvn_rsrc(const TSK_FS_ATTR * fs_attr,
    int flags, TSK_FS_FILE_WALK_CB a_action, void *ptr)
{
    return decmpfs_attr_walk_compressed_rsrc(
      fs_attr, flags, a_action, ptr,
      decmpfs_read_lzvn_block_table,
      decmpfs_decompress_lzvn_block
    );
}


/**
 * \internal
 * Read a compressed resource
 *
 * @param fs_attr the attribute to read
 * @param a_offset the offset from which to read
 * @param a_buf the buffer into which to read
 * @param a_len the length of the buffer
 * @param read_block_table pointer to block table read function
 * @param decompress_block pointer to decompression function
 * @return number of bytes read or -1 on error (incl if offset is past EOF)
 */
static ssize_t
decmpfs_file_read_compressed_rsrc(const TSK_FS_ATTR * a_fs_attr,
    TSK_OFF_T a_offset, char *a_buf, size_t a_len,
    int (*read_block_table)(const TSK_FS_ATTR *rAttr,
                            CMP_OFFSET_ENTRY** offsetTableOut,
                            uint32_t* tableSizeOut,
                            uint32_t* tableOffsetOut),
    int (*decompress_block)(char* rawBuf,
                            uint32_t len,
                            char* uncBuf,
                            uint64_t* uncLen))
{
    TSK_FS_FILE *fs_file;
    const TSK_FS_ATTR *rAttr;
    char *rawBuf = NULL;
    char *uncBuf = NULL;
    uint32_t offsetTableOffset;
    uint32_t offsetTableSize;         // Size of the offset table
    CMP_OFFSET_ENTRY *offsetTable = NULL;
    TSK_OFF_T indx;                // index for looping over the offset table
    TSK_OFF_T startUnit = 0;
    uint32_t startUnitOffset = 0;
    TSK_OFF_T endUnit = 0;
    uint64_t bytesCopied;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "%s: called because this file is compressed, with data in the resource fork\n", __func__);

    // Reading zero bytes?  OK at any offset, I say!
    if (a_len == 0)
        return 0;

    if (a_offset < 0) {
        error_detected(TSK_ERR_FS_ARG,
            "%s: reading from file at a negative offset",
             __func__);
        return -1;
    }

    if (a_len > SIZE_MAX / 2) {
        error_detected(TSK_ERR_FS_ARG,
            "%s: trying to read more than SIZE_MAX/2 is not supported.",
            __func__);
        return -1;
    }

    if ((a_fs_attr == NULL) || (a_fs_attr->fs_file == NULL)
        || (a_fs_attr->fs_file->meta == NULL)
        || (a_fs_attr->fs_file->fs_info == NULL)) {
        error_detected(TSK_ERR_FS_ARG,
            "%s: NULL parameters passed", __func__);
        return -1;
    }

    // This should be a compressed file.  If not, that's an error!
    if (!(a_fs_attr->flags & TSK_FS_ATTR_COMP)) {
        error_detected(TSK_ERR_FS_ARG,
            "%s: called with non-special attribute: %x",
            __func__, a_fs_attr->flags);
        return -1;
    }

    // Check that the ATTR being read is the main DATA resource, 4352-0,
    // because this is the only one that can be compressed in HFS+
    if ((a_fs_attr->id != HFS_FS_ATTR_ID_DATA) ||
        (a_fs_attr->type != TSK_FS_ATTR_TYPE_HFS_DATA)) {
        error_detected(TSK_ERR_FS_ARG,
            "%s: arg specified an attribute %u-%u that is not the data fork, "
            "Only the data fork can be compressed.", __func__,
            a_fs_attr->type, a_fs_attr->id);
        return -1;
    }

    /********  Open the Resource Fork ***********/
    // The file
    fs_file = a_fs_attr->fs_file;

    // find the attribute for the resource fork
    rAttr =
        tsk_fs_file_attr_get_type(fs_file, TSK_FS_ATTR_TYPE_HFS_RSRC,
        HFS_FS_ATTR_ID_RSRC, FALSE);
    if (rAttr == NULL) {
        error_returned
            (" %s: could not get the attribute for the resource fork of the file", __func__);
        return -1;
    }

    // read the offset table from the fork header
    if (!read_block_table(rAttr, &offsetTable, &offsetTableSize, &offsetTableOffset)) {
      return -1;
    }

    // Compute the range of compression units needed for the request
    startUnit = a_offset / COMPRESSION_UNIT_SIZE;
    startUnitOffset = a_offset % COMPRESSION_UNIT_SIZE;
    endUnit = (a_offset + a_len - 1) / COMPRESSION_UNIT_SIZE;

    if (startUnit >= offsetTableSize || endUnit >= offsetTableSize) {
        error_detected(TSK_ERR_FS_ARG,
            "%s: range of bytes requested %lld - %lld falls past the "
            "end of the uncompressed stream %llu\n",
            __func__, a_offset, a_offset + a_len,
            offsetTable[offsetTableSize-1].offset +
            offsetTable[offsetTableSize-1].length);
        goto on_error;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "%s: reading compression units: %" PRIdOFF
            " to %" PRIdOFF "\n", __func__, startUnit, endUnit);
   bytesCopied = 0;

    // Allocate buffers for the raw and uncompressed data
    /* Raw data can be COMPRESSION_UNIT_SIZE+1 if the zlib data is not
     * compressed and there is a 1-byte flag that indicates that
     * the data is not compressed. */
    rawBuf = (char *) tsk_malloc(COMPRESSION_UNIT_SIZE + 1);
    if (rawBuf == NULL) {
        error_returned
            (" %s: buffers for reading and uncompressing", __func__);
        goto on_error;
    }

    uncBuf = (char *) tsk_malloc(COMPRESSION_UNIT_SIZE);
    if (uncBuf == NULL) {
        error_returned
            (" %s: buffers for reading and uncompressing", __func__);
        goto on_error;
    }

    // Read from the indicated comp units
    for (indx = startUnit; indx <= endUnit; ++indx) {
        uint64_t uncLen;
        char *uncBufPtr = uncBuf;
        size_t bytesToCopy;

        switch ((uncLen = read_and_decompress_block(
                    rAttr, rawBuf, uncBuf,
                    offsetTable, offsetTableSize, offsetTableOffset, (size_t)indx,
                    decompress_block)))
        {
        case -1:
            goto on_error;
        case  0:
            continue;
        default:
            break;
        }

        // If this is the first comp unit, then we must skip over the
        // startUnitOffset bytes.
        if (indx == startUnit) {
            uncLen -= startUnitOffset;
            uncBufPtr += startUnitOffset;
        }

        // How many bytes to copy from this compression unit?

        if (bytesCopied + uncLen < (uint64_t) a_len)    // cast OK because a_len > 0
            bytesToCopy = (size_t) uncLen;      // uncLen <= size of compression unit, which is small, so cast is OK
        else
            bytesToCopy = (size_t) (((uint64_t) a_len) - bytesCopied);  // diff <= compression unit size, so cast is OK

        // Copy into the output buffer, and update bookkeeping.
        memcpy(a_buf + bytesCopied, uncBufPtr, bytesToCopy);
        bytesCopied += bytesToCopy;
    }

    // Well, we don't know (without a lot of work) what the
    // true uncompressed size of the stream is.  All we know is the "upper bound" which
    // assumes that all of the compression units expand to their full size.  If we did
    // know the true size, then we could reject requests that go beyond the end of the
    // stream.  Instead, we treat the stream as if it is padded out to the full size of
    // the last compression unit with zeros.

    // Have we read and copied all of the bytes requested?
    if (bytesCopied < a_len) {
        // set the remaining bytes to zero
        memset(a_buf + bytesCopied, 0, a_len - (size_t) bytesCopied);   // cast OK because diff must be < compression unit size
    }

    free(offsetTable);
    free(rawBuf);
    free(uncBuf);

    return (ssize_t) bytesCopied;       // cast OK, cannot be greater than a_len which cannot be greater than SIZE_MAX/2 (rounded down).

on_error:
    free(offsetTable);
    free(rawBuf);
    free(uncBuf);
    return -1;
}


#ifdef HAVE_LIBZ
/**
 * \internal
 * Read a ZLIB compressed resource
 *
 * @param fs_attr the attribute to read
 * @param a_offset the offset from which to read
 * @param a_buf the buffer into which to read
 * @param a_len the length of the buffer
 * @return number of bytes read or -1 on error (incl if offset is past EOF)
 */
ssize_t
decmpfs_file_read_zlib_rsrc(const TSK_FS_ATTR * a_fs_attr,
    TSK_OFF_T a_offset, char *a_buf, size_t a_len)
{
    return decmpfs_file_read_compressed_rsrc(
        a_fs_attr, a_offset, a_buf, a_len,
        decmpfs_read_zlib_block_table,
        decmpfs_decompress_zlib_block
    );
}
#endif

/**
 * Read an LZVN compressed resource
 *
 * @param fs_attr the attribute to read
 * @param a_offset the offset from which to read
 * @param a_buf the buffer into which to read
 * @param a_len the length of the buffer
 * @return number of bytes read or -1 on error (incl if offset is past EOF)
 */
ssize_t
decmpfs_file_read_lzvn_rsrc(const TSK_FS_ATTR * a_fs_attr,
    TSK_OFF_T a_offset, char *a_buf, size_t a_len)
{
    return decmpfs_file_read_compressed_rsrc(
        a_fs_attr, a_offset, a_buf, a_len,
        decmpfs_read_lzvn_block_table,
        decmpfs_decompress_lzvn_block
    );
}

/**
 * \internal
 * "Decompress" an uncompressed attr
 *
 * HFS+ compression schemes allow for some blocks to be stored uncompressed.
 *
 * @param rawBuf source buffer
 * @param rawSize size of source buffer
 * @param uncSize expected uncompressed size
 * @param dstBuf destination buffer
 * @param dstSize size of destination buffer
 * @param dstBufFree true iff the caller must free the destination buffer
 * @return 1
 */
static int decmpfs_decompress_noncompressed_attr(char* rawBuf, uint32_t rawSize, uint64_t uncSize, char** dstBuf, uint64_t* dstSize, int* dstBufFree) {
    if (tsk_verbose)
        tsk_fprintf(stderr,
            "%s: Leading byte, 0x%02x, indicates that the data is not really compressed.\n"
            "%s:  Loading the default DATA attribute.", __func__, rawBuf[0], __func__);

    *dstBuf = rawBuf + 1;  // + 1 indicator byte
    *dstSize = uncSize;
    *dstBufFree = FALSE;
    return 1;
}

/**
 * \internal
 * Decompress a ZLIB compressed attr
 *
 * @param rawBuf source buffer
 * @param rawSize size of source buffer
 * @param uncSize expected uncompressed size
 * @param dstBuf destination buffer
 * @param dstSize size of destination buffer
 * @param dstBufFree true iff the caller must free the destination buffer
 * @return 1 on success, 0 on error
 */
static int decmpfs_decompress_zlib_attr(char* rawBuf, uint32_t rawSize, uint64_t uncSize, char** dstBuf, uint64_t* dstSize, int* dstBufFree)
{
    // ZLIB blocks cannot start with 0xF as the low nibble, so that's used
    // as the flag for noncompressed blocks
    if ((rawBuf[0] & 0x0F) == 0x0F) {
        return decmpfs_decompress_noncompressed_attr(
            rawBuf, rawSize, uncSize, dstBuf, dstSize, dstBufFree);
    }
    else {
#ifdef HAVE_LIBZ
        char* uncBuf = NULL;
        uint64_t uLen;
        unsigned long bytesConsumed;
        int infResult;

        if (tsk_verbose)
            tsk_fprintf(stderr,
                        "%s: Uncompressing (inflating) data.", __func__);
        // Uncompress the remainder of the attribute, and load as 128-0
        // Note: cast is OK because uncSize will be quite modest, < 4000.

        uncBuf = (char *) tsk_malloc((size_t) uncSize + 100); // add some extra space
        if (uncBuf == NULL) {
            error_returned
                (" - %s, space for the uncompressed attr", __func__);
            return 0;
        }

        infResult = zlib_inflate(rawBuf, (uint64_t) rawSize,
                                 uncBuf, (uint64_t) (uncSize + 100),
                                 &uLen, &bytesConsumed);
        if (infResult != 0) {
            error_returned
                (" %s, zlib could not uncompress attr", __func__);
            free(uncBuf);
            return 0;
        }

        if (bytesConsumed != rawSize) {
            error_detected(TSK_ERR_FS_READ,
                " %s, decompressor did not consume the whole compressed data",
                __func__);
            free(uncBuf);
            return 0;
        }

        *dstBuf = uncBuf;
        *dstSize = uncSize;
        *dstBufFree = TRUE;
#else
        // ZLIB compression library is not available, so we will load a
        // zero-length default DATA attribute. Without this, icat may
        // misbehave.

        if (tsk_verbose)
            tsk_fprintf(stderr,
                        "%s: ZLIB not available, so loading an empty default DATA attribute.\n", __func__);

        // Dummy is one byte long, so the ptr is not null, but we set the
        // length to zero bytes, so it is never read.
        static uint8_t dummy[1];

        *dstBuf = dummy;
        *dstSize = 0;
        *dstBufFree = FALSE;
#endif
    }

    return 1;
}

/**
 * \internal
 * Decompress an LZVN compressed attr
 *
 * @param rawBuf source buffer
 * @param rawSize size of source buffer
 * @param uncSize expected uncompressed size
 * @param dstBuf destination buffer
 * @param dstSize size of destination buffer
 * @param dstBufFree true iff the caller must free the destination buffer
 * @return 1 on success, 0 on error
 */
static int decmpfs_decompress_lzvn_attr(char* rawBuf, uint32_t rawSize, uint64_t uncSize, char** dstBuf, uint64_t* dstSize, int* dstBufFree)
{
    // LZVN blocks cannot start with 0x06, so that's used as the flag for
    // noncompressed blocks
    if (rawBuf[0] == 0x06) {
        return decmpfs_decompress_noncompressed_attr(
            rawBuf, rawSize, uncSize, dstBuf, dstSize, dstBufFree);
    }

    char* uncBuf = (char *) tsk_malloc((size_t) uncSize);
    *dstSize = lzvn_decode_buffer(uncBuf, uncSize, rawBuf, rawSize);
    *dstBuf = uncBuf;
    *dstBufFree = TRUE;

    return 1;
}

/**
 * \internal
 * Read a compressed attr
 *
 * @param fs_file the file
 * @param cmpType compression type
 * @param buffer destination buffer
 * @param attributeLength length of the attribute
 * @param uncSize uncompressed size
 * @param decompress_attr pointer to the decompression function
 * @return 1 on success, 0 on error
 */
static int
decmpfs_file_read_compressed_attr(TSK_FS_FILE* fs_file,
                              uint8_t cmpType,
                              char* buffer,
                              TSK_OFF_T attributeLength,
                              uint64_t uncSize,
                              int (*decompress_attr)(char* rawBuf,
                                                     TSK_OFF_T rawSize,
                                                     uint64_t uncSize,
                                                     char** dstBuf,
                                                     uint64_t* dstSize,
                                                     int* dstBufFree))
{
    // Data is inline. We will load the uncompressed data as a
    // resident attribute.
    if (tsk_verbose)
        tsk_fprintf(stderr,
            "%s: Compressed data is inline in the attribute, will load this as the default DATA attribute.\n", __func__);

    if (attributeLength <= 16) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "%s: WARNING, Compression Record of type %u is not followed by"
                " compressed data. No data will be loaded into the DATA"
                " attribute.\n", __func__, cmpType);

        // oddly, this is not actually considered an error
        return 1;
    }

    TSK_FS_ATTR *fs_attr_unc;

    // There is data following the compression record, as there should be.
    if ((fs_attr_unc = tsk_fs_attrlist_getnew(
          fs_file->meta->attr, TSK_FS_ATTR_RES)) == NULL)
    {
        error_returned(" - %s, FS_ATTR for uncompressed data", __func__);
        return 0;
    }

    char* dstBuf;
    uint64_t dstSize;
    int dstBufFree = FALSE;

    if (!decompress_attr(buffer + 16, attributeLength - 16, uncSize,
                         &dstBuf, &dstSize, &dstBufFree)) {
        return 0;
    }

    if (dstSize != uncSize) {
        error_detected(TSK_ERR_FS_READ,
            " %s, actual uncompressed size not equal to the size in the compression record", __func__);
        goto on_error;
    }

    if (tsk_verbose)
       tsk_fprintf(stderr,
                   "%s: Loading decompressed data as default DATA attribute.",
                   __func__);

    // Load the remainder of the attribute as 128-0
    // set the details in the fs_attr structure.
    // Note, we are loading this as a RESIDENT attribute.
    if (tsk_fs_attr_set_str(fs_file,
                            fs_attr_unc, "DECOMP",
                            TSK_FS_ATTR_TYPE_HFS_DATA, 
                            TSK_FS_ATTR_ID_DEFAULT, 
                            dstBuf,
                            dstSize))
    {
        error_returned(" - %s", __func__);
        goto on_error;
    }

    if (dstBufFree) {
        free(dstBuf);
    }
    return 1;

on_error:
    if (dstBufFree) {
        free(dstBuf);
    }
    return 0;
}

/**
 * \internal
 * Read a ZLIB compressed attr
 *
 * @param fs_file the file
 * @param buffer destination buffer
 * @param attributeLength length of the attribute
 * @param uncSize uncompressed size
 * @return 1 on success, 0 on error
 */
int decmpfs_file_read_zlib_attr(TSK_FS_FILE* fs_file,
                            char* buffer,
                            TSK_OFF_T attributeLength,
                            uint64_t uncSize)
{
    return decmpfs_file_read_compressed_attr(
        fs_file, DECMPFS_TYPE_ZLIB_ATTR,
        buffer, attributeLength, uncSize,
        decmpfs_decompress_zlib_attr
    );
}

/**
 * \internal
 * Read an LZVN compressed attr
 *
 * @param fs_file the file
 * @param buffer destination buffer
 * @param attributeLength length of the attribute
 * @param uncSize uncompressed size
 * @return 1 on success, 0 on error
 */
int decmpfs_file_read_lzvn_attr(TSK_FS_FILE* fs_file,
                            char* buffer,
                            TSK_OFF_T attributeLength,
                            uint64_t uncSize)
{
    return decmpfs_file_read_compressed_attr(
        fs_file, DECMPFS_TYPE_LZVN_ATTR,
        buffer, attributeLength, uncSize,
        decmpfs_decompress_lzvn_attr
    );
}