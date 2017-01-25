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

/* This is a little lower than the actual maximum size for the VHD */
#define VHD_MAX_IMAGE_SIZE 2000000000000
#define VHD_SECTOR_SIZE 0x200
#define VHD_FOOTER_LENGTH 0x200
#define VHD_DISK_HEADER_LENGTH 0x400

TSK_RETVAL_ENUM writeFooter(TSK_IMG_WRITER* writer);

bool getBit(unsigned char * buffer, TSK_OFF_T index) {
	unsigned char b = buffer[index / 8];
	return (b >> (7 - (index % 8)) & 0x01) == 1;
}

void setBit(unsigned char * buffer, TSK_OFF_T index, bool val) {
	unsigned char b = buffer[index / 8];
	unsigned char mask = 0xff ^ (1 << (7 - (index % 8)));
	b = (b & mask) | (val << (7 - (index % 8)));
	buffer[index / 8] = b;
}

TSK_RETVAL_ENUM seekToOffset(TSK_IMG_WRITER * writer, TSK_OFF_T offset) {
	LARGE_INTEGER li;
	li.QuadPart = offset;

	li.LowPart = SetFilePointer(writer->outputFileHandle, li.LowPart,
		&li.HighPart, FILE_BEGIN);

	if ((li.LowPart == INVALID_SET_FILE_POINTER) &&
		(GetLastError() != NO_ERROR)) {
		int lastError = (int)GetLastError();
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_IMG_SEEK);
		tsk_error_set_errstr("img_writer::seekToOffset: offset %" PRIuOFF " seek - %d",
			offset,
			lastError);
		return TSK_ERR;
	}
	return TSK_OK;
}

TSK_RETVAL_ENUM seekAhead(TSK_IMG_WRITER * writer, TSK_OFF_T dist) {
	LARGE_INTEGER li;
	li.QuadPart = dist;

	li.LowPart = SetFilePointer(writer->outputFileHandle, li.LowPart,
		&li.HighPart, FILE_CURRENT);

	if ((li.LowPart == INVALID_SET_FILE_POINTER) &&
		(GetLastError() != NO_ERROR)) {
		int lastError = (int)GetLastError();
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_IMG_SEEK);
		tsk_error_set_errstr("img_writer::seekAhead: offset %" PRIuOFF " seek - %d",
			dist,
			lastError);
		return TSK_ERR;
	}
	return TSK_OK;
}

void checkIfBlockIsFinished(TSK_IMG_WRITER* writer, TSK_OFF_T blockNum) {

	/* This may not ever mark the last block as finished - need to work on that */

	unsigned char * sectBitmap = writer->blockToSectorBitmap[blockNum];
	for (int i = 0; i < writer->sectorsPerBlock; i++) {
		if (false == getBit(sectBitmap, i)) {
			/* At least one sector has not been written */
			return;
		}
	}

	/* Mark the block as finished and free the memory for its sector bitmap */
	writer->blockStatus[blockNum] = IMG_WRITER_BLOCK_STATUS_FINISHED;
	if (writer->blockToSectorBitmap[blockNum] != NULL) {
		free(writer->blockToSectorBitmap[blockNum]);
	}

}

TSK_RETVAL_ENUM addToExistingBlock(TSK_IMG_WRITER* writer, TSK_OFF_T addr, char *buffer,
	size_t len, TSK_OFF_T blockNum) {

	tsk_fprintf(stdout, "Block %d adding to existing block starting at rel offset 0x%llx\n",
		blockNum, addr % writer->blockSize);

	/* Seek to where this buffer should start in the image */
	if (TSK_OK != seekToOffset(writer, writer->blockToOffset[blockNum] + writer->sectorBitmapLength +
			(addr % writer->blockSize))) {
		return TSK_ERR;
	}

	/* Copy each sector that isn't already there */
	for (TSK_OFF_T inputOffset = 0; inputOffset < len; inputOffset += VHD_SECTOR_SIZE) {
		uint32_t currentSector = (addr % writer->blockSize + inputOffset) / VHD_SECTOR_SIZE;

		if (getBit(writer->blockToSectorBitmap[blockNum], currentSector)) {
			if (TSK_OK != seekAhead(writer, VHD_SECTOR_SIZE)) {
				return TSK_ERR;
			}
		}
		else {
			
			DWORD bytesWritten;
			if (FALSE == WriteFile(writer->outputFileHandle, &(buffer[inputOffset]), VHD_SECTOR_SIZE, 
					&bytesWritten, NULL)) {
				int lastError = GetLastError();
				tsk_error_reset();
				tsk_error_set_errno(TSK_ERR_IMG_WRITE);
				tsk_error_set_errstr("addToExistingBlock: error writing sector",
					lastError);
				return TSK_ERR;
			}
			setBit(writer->blockToSectorBitmap[blockNum], currentSector, true);
		}
	}

	/* Update the sector bitmap */
	if (TSK_OK != seekToOffset(writer, writer->blockToOffset[blockNum])) {
		return TSK_ERR;
	}
	
	DWORD bytesWritten;
	if (FALSE == WriteFile(writer->outputFileHandle, writer->blockToSectorBitmap[blockNum], 
			writer->sectorBitmapArrayLength, &bytesWritten, NULL)) {
		int lastError = GetLastError();
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_IMG_WRITE);
		tsk_error_set_errstr("addToExistingBlock: error writing sector",
			lastError);
		return TSK_ERR;
	}

	return TSK_OK;
}

TSK_RETVAL_ENUM addNewBlock(TSK_IMG_WRITER* writer, TSK_OFF_T addr, char *buffer, size_t len, TSK_OFF_T blockNum) {

	writer->blockStatus[blockNum] = IMG_WRITER_BLOCK_STATUS_ALLOC;
	writer->blockToOffset[blockNum] = writer->nextDataOffset;

	char * fullBuffer = (char *)tsk_malloc(writer->blockSize * sizeof(char));
	char * sectorBitmap = (char *)tsk_malloc(writer->sectorBitmapLength * sizeof(char));
	unsigned char * completedSectors = (unsigned char *)tsk_malloc(((writer->sectorBitmapArrayLength) * sizeof(char)));

	/* Create the full new block and record the sectors written */
	TSK_OFF_T startingOffset = addr % writer->blockSize;
	for (size_t i = 0; i < len; i++) {

		if (((startingOffset + i) % VHD_SECTOR_SIZE) == 0) {
			TSK_OFF_T currentSector = (startingOffset + i) / VHD_SECTOR_SIZE;
			setBit(completedSectors, currentSector, true);
			sectorBitmap[currentSector / 8] = completedSectors[currentSector / 8];
		}

		fullBuffer[startingOffset + i] = buffer[i];
	}
	writer->blockToSectorBitmap[blockNum] = completedSectors;

	/* Prepare the new block offset */
	TSK_OFF_T nextDataOffsetSector = writer->nextDataOffset / VHD_SECTOR_SIZE;
	unsigned char newBlockOffset[4];
	newBlockOffset[0] = (nextDataOffsetSector >> 24) & 0xff;
	newBlockOffset[1] = (nextDataOffsetSector >> 16) & 0xff;
	newBlockOffset[2] = (nextDataOffsetSector >> 8) & 0xff;
	newBlockOffset[3] = nextDataOffsetSector & 0xff;

	/* Write the new offset to the BAT */
	if (TSK_OK != seekToOffset(writer, writer->batOffset + 4 * blockNum)) {
		return TSK_ERR;
	}
	DWORD bytesWritten;
	if (FALSE == WriteFile(writer->outputFileHandle, newBlockOffset, 4, &bytesWritten, NULL)) {
		int lastError = GetLastError();
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_IMG_WRITE);
		tsk_error_set_errstr("addNewBlock: error writing BAT entry",
			lastError);
		return TSK_ERR;
	}

	/* Write the sector bitmap and the data */
	if (TSK_OK != seekToOffset(writer, writer->nextDataOffset)) {
		return TSK_ERR;
	}
	if (FALSE == WriteFile(writer->outputFileHandle, sectorBitmap, writer->sectorBitmapLength, &bytesWritten, NULL)) {
		int lastError = GetLastError();
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_IMG_WRITE);
		tsk_error_set_errstr("addNewBlock: error writing sector bitmap",
			lastError);
		return TSK_ERR;
	}
	if (FALSE == WriteFile(writer->outputFileHandle, fullBuffer, writer->blockSize, &bytesWritten, NULL)) {
		int lastError = GetLastError();
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_IMG_WRITE);
		tsk_error_set_errstr("addNewBlock: error writing block data",
			lastError);
		return TSK_ERR;
	}

	writer->nextDataOffset += writer->sectorBitmapLength + writer->blockSize;

	/* Always add the footer on to make it a valid VHD */
	writeFooter(writer);

	free(fullBuffer);
	free(sectorBitmap);

	return TSK_OK;
}

TSK_RETVAL_ENUM addBlock(TSK_IMG_WRITER* writer, TSK_OFF_T addr, char *buffer, size_t len) {
	TSK_OFF_T blockNum = addr / writer->blockSize;

	if (writer->blockStatus[blockNum] == IMG_WRITER_BLOCK_STATUS_FINISHED){
		return TSK_OK;
	}
	fflush(stderr);

	if (writer->blockStatus[blockNum] == IMG_WRITER_BLOCK_STATUS_ALLOC) {
		addToExistingBlock(writer, addr, buffer, len, blockNum);
	}
	else {
		addNewBlock(writer, addr, buffer, len, blockNum);
	}

	/* Check whether the block is now done */
	checkIfBlockIsFinished(writer, blockNum);

	return TSK_OK;
}

static TSK_RETVAL_ENUM tsk_img_writer_add(TSK_IMG_WRITER* writer, TSK_OFF_T addr, char *buffer, size_t len) {
#ifndef TSK_WIN32
	return TSK_ERR;
#else
	if (tsk_verbose) {
		tsk_fprintf(stderr,
			"tsk_img_writer_add: Adding data at offset: %"
			PRIuOFF " len: %" PRIuOFF "\n", addr,
			(TSK_OFF_T)len);
	}

	/* This should never happen, but best to check */
	if (addr % VHD_SECTOR_SIZE != 0) {
		return TSK_ERR;
	}

	if (addr % writer->blockSize == 0) {
		/* The buffer matches up with the blocks */
		return addBlock(writer, addr, buffer, len);
	}
	else {
		/* The buffer spans two blocks */
		TSK_OFF_T firstPartLength = writer->blockSize - (addr % writer->blockSize);
		addBlock(writer, addr, buffer, firstPartLength);
		if (addr + firstPartLength < writer->imageSize) {
			addBlock(writer, addr + firstPartLength, buffer + firstPartLength, addr % writer->blockSize);
		}
	}

	return TSK_OK;
#endif
}

static TSK_RETVAL_ENUM tsk_img_writer_close(TSK_IMG_WRITER* img_writer) {
#ifndef TSK_WIN32
    return TSK_ERR;
#else
    if (tsk_verbose) {
        tsk_fprintf(stderr,
            "tsk_img_writer_close: Closing image writer");
    }
    if (img_writer->outputFileHandle != 0) {
        CloseHandle(img_writer->outputFileHandle);
        img_writer->outputFileHandle = 0;

		/* TODO: Free the data */
    }	

    return TSK_OK;
#endif
}
static TSK_RETVAL_ENUM tsk_img_writer_finish_image(TSK_IMG_WRITER* img_writer) {
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
 * Utility function to write integer values to the VHD headers.
 * Will write val as an nBytes-long value to the buffer at the given offset.
 * Byte ordering is big endian
 */
void addIntToBuffer(unsigned char * buffer, int offset, TSK_OFF_T val, int nBytes) {
    for (int i = 0; i < nBytes; i++) {
        buffer[offset + i] = (val >> (8 * (nBytes - 1 - i))) & 0xff;
    }
}

/* 
 * Utility function to write strings to the VHD headers.
 */
void addStringToBuffer(unsigned char * buffer, int offset, char const * str, int nBytes) {
    for (int i = 0; i < nBytes; i++) {
        buffer[offset + i] = str[i];
    }
}

/*
 * Calculate the checksum for the header. It's the one's complement of the sum of
 * all the bytes (apart from the checksum)
 */
uint32_t generateChecksum(unsigned char * buffer, int len) {

    uint32_t sum = 0;
    for (int i = 0; i < len; i++) {
        sum += buffer[i];
    }

    return (~sum);
}

/* 
 * Write the footer (which is also the first sector) to the file.
 * Will write to the current file position.
 * Save it so we only have to generate it once.
 */
TSK_RETVAL_ENUM writeFooter(TSK_IMG_WRITER* writer) {
    if (writer->footer == NULL) {
        writer->footer = (unsigned char *)tsk_malloc(VHD_FOOTER_LENGTH * sizeof(unsigned char));

        /* First calculate geometry values */
        uint32_t cylinders;
        uint32_t heads;
        uint32_t sectorsPerTrack;
        uint32_t totalSectors = uint32_t(writer->imageSize / VHD_SECTOR_SIZE);
        if (writer->imageSize % VHD_SECTOR_SIZE != 0) {
            totalSectors++;
        }

        uint32_t cylinderTimesHeads;
        if (totalSectors > 65535 * 16 * 255){
            totalSectors = 65535 * 16 * 255;
        }

        if (totalSectors >= 65535 * 16 * 63){
            sectorsPerTrack = 255;
            heads = 16;
            cylinderTimesHeads = totalSectors / sectorsPerTrack;
        } else {
            sectorsPerTrack = 17;
            cylinderTimesHeads = totalSectors / sectorsPerTrack;
            heads = (cylinderTimesHeads + 1023) / 1024;
            if (heads < 4){
                heads = 4;
            }
            if (cylinderTimesHeads >= (heads * 1024) || heads > 16){
                sectorsPerTrack = 31;
                heads = 16;
                cylinderTimesHeads = totalSectors / sectorsPerTrack;
            }
            if (cylinderTimesHeads >= (heads * 1024)){
                sectorsPerTrack = 63;
                heads = 16;
                cylinderTimesHeads = totalSectors / sectorsPerTrack;
            }
        }
        cylinders = cylinderTimesHeads / heads;

        /* Write the footer */
        addStringToBuffer(writer->footer, 0, "conectix", 8);
        addIntToBuffer(writer->footer, 8, 2, 4);         // Features
        addIntToBuffer(writer->footer, 0xc, 0x10000, 4); // File format version
        addIntToBuffer(writer->footer, 0x10, 0x200, 8);  // Data offset
        // 0x14 is a four byte timestamp - leave blank
        addStringToBuffer(writer->footer, 0x1c, "win ", 4);  // Creator app
        addIntToBuffer(writer->footer, 0x20, 0x60001, 4);    // Creator version
        addStringToBuffer(writer->footer, 0x24, "Wi2k", 4);  // Creator host OS
        addIntToBuffer(writer->footer, 0x28, writer->imageSize, 8);  // Original size
        addIntToBuffer(writer->footer, 0x30, writer->imageSize, 8);  // Current size
        addIntToBuffer(writer->footer, 0x38, cylinders, 2);        // Geometry
        addIntToBuffer(writer->footer, 0x3a, heads, 1);            // Geometry
        addIntToBuffer(writer->footer, 0x3b, sectorsPerTrack, 1);  // Geometry
        addIntToBuffer(writer->footer, 0x3c, 3, 4);                // Disk type
        addIntToBuffer(writer->footer, 0x40, generateChecksum(writer->footer, VHD_FOOTER_LENGTH), 4); // Checksum
    }

    DWORD bytesWritten;
    if (FALSE == WriteFile(writer->outputFileHandle, writer->footer, VHD_FOOTER_LENGTH, &bytesWritten, NULL)) {
        int lastError = GetLastError();
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_WRITE);
        tsk_error_set_errstr("writeFooter: error writing VHD footer",
            lastError);
        return TSK_ERR;
    }
    return TSK_OK;
}

/*
 * Write the dynamic disk header to the file
 */
TSK_RETVAL_ENUM writeDynamicDiskHeader(TSK_IMG_WRITER * writer) {
    unsigned char * diskHeader = (unsigned char *)malloc(VHD_DISK_HEADER_LENGTH * sizeof(unsigned char));
    for (int i = 0; i < VHD_DISK_HEADER_LENGTH; i++) {
        diskHeader[i] = 0;
    }

    addStringToBuffer(diskHeader, 0, "cxsparse", 8); // Cookie
    addIntToBuffer(diskHeader, 8, 0xffffffff, 4);    // Data offset (1)
    addIntToBuffer(diskHeader, 0xc, 0xffffffff, 4);  // Data offset (2)
    addIntToBuffer(diskHeader, 0x10, 0x600, 8);      // BAT offset
    addIntToBuffer(diskHeader, 0x18, 0x10000, 4);    // Header version
    addIntToBuffer(diskHeader, 0x1c, writer->totalBlocks, 4); // Blocks on disk
    addIntToBuffer(diskHeader, 0x20, writer->blockSize, 4);   // Block size
    addIntToBuffer(diskHeader, 0x24, generateChecksum(diskHeader, 0x400), 4); // Checksum

    DWORD bytesWritten;
    if (FALSE == WriteFile(writer->outputFileHandle, diskHeader, VHD_DISK_HEADER_LENGTH, &bytesWritten, NULL)) {
        int lastError = GetLastError();
        tsk_error_reset();
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_WRITE);
        tsk_error_set_errstr("writeFooter: error writing VHD header",
            lastError);
        return TSK_ERR;
    }
    return TSK_OK;
}

/*
 * Create and initailize the TSK_IMG_WRITER struct and save reference in img_info,
 * then write the headers to the output file
 */
TSK_RETVAL_ENUM tsk_img_writer_create(TSK_IMG_INFO * img_info, const TSK_TCHAR * directory,
    const TSK_TCHAR * basename) {

#ifndef TSK_WIN32
    return TSK_ERR;
#else
    if (tsk_verbose) {
        tsk_fprintf(stderr,
            "tsk_img_writer_create: Creating image writer in directory %" PRIttocTSK" with basename %" PRIttocTSK"\n",
            directory, basename);
    }

    IMG_RAW_INFO* raw_info = (IMG_RAW_INFO *)img_info;

    /* This should not be run on split images*/
    if (raw_info->num_img != 1) {
        return TSK_ERR;
    }

    /* Initialize the img_writer object */
    if ((raw_info->img_writer = (TSK_IMG_WRITER *)tsk_malloc(sizeof(TSK_IMG_WRITER))) == NULL)
        return TSK_ERR;
    TSK_IMG_WRITER* writer = raw_info->img_writer;
    writer->is_finished = 0;
    writer->footer = NULL;
    writer->add = tsk_img_writer_add;
    writer->close = tsk_img_writer_close;
    writer->finish_image = tsk_img_writer_finish_image;

    /* Calculation time */
    writer->imageSize = raw_info->img_info.size;
    if (writer->imageSize > VHD_MAX_IMAGE_SIZE) {
        return TSK_ERR;
    }
    writer->blockSize = TSK_IMG_INFO_CACHE_LEN;
    writer->totalBlocks = uint32_t(writer->imageSize / writer->blockSize);
    if (writer->imageSize % writer->blockSize != 0) {
        writer->totalBlocks++;
    }
    writer->sectorsPerBlock = writer->blockSize / VHD_SECTOR_SIZE;
	writer->sectorBitmapArrayLength = writer->sectorsPerBlock / 8;
	if (writer->sectorBitmapArrayLength % 8 != 0) {
		writer->sectorBitmapArrayLength++;
	}
	writer->sectorBitmapLength = writer->sectorBitmapArrayLength;
	if (0 != writer->sectorBitmapLength % VHD_SECTOR_SIZE) {
		writer->sectorBitmapLength += VHD_SECTOR_SIZE - (writer->sectorBitmapLength % VHD_SECTOR_SIZE);
	}

    /* Set up the output file */
    size_t len = TSTRLEN(directory) + TSTRLEN(basename) + 10;
    writer->fileName = (TSK_TCHAR *)malloc(len * sizeof(TSK_TCHAR));
    TSTRNCPY(writer->fileName, directory, TSTRLEN(directory) + 1);
    TSTRNCAT(writer->fileName, _TSK_T("\\"), 2);
    TSTRNCAT(writer->fileName, basename, TSTRLEN(basename) + 1);
    TSTRNCAT(writer->fileName, _TSK_T(".vhd"), 5);
    if (tsk_verbose) {
        tsk_fprintf(stderr,
            "tsk_img_writer_create: Output file: %" PRIttocTSK"\n", writer->fileName);
    }

    /* TODO: Decide what to do if the file already exisits. For now, always overwrite */
    writer->outputFileHandle = CreateFile(writer->fileName, FILE_WRITE_DATA,
        FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0,
        NULL);
    if (writer->outputFileHandle == INVALID_HANDLE_VALUE) {
        int lastError = (int)GetLastError();
        writer->outputFileHandle = 0; /* so we don't close it next time */
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);
        tsk_error_set_errstr("tsk_img_writer_create: file \"%" PRIttocTSK
            "\" - %d", writer->fileName, lastError);
        return TSK_ERR;
    }

    /* Write the backup copy of the footer */
    TSK_RETVAL_ENUM retval = writeFooter(writer);
    if (retval != TSK_OK) {
        return retval;
    }
    retval = writeDynamicDiskHeader(writer);
    if (retval != TSK_OK) {
        return retval;
    }

    /* Write the (empty) Block Allocation Table */
    writer->batOffset = VHD_FOOTER_LENGTH + VHD_DISK_HEADER_LENGTH;
    uint32_t batLengthOnDisk = 4 * writer->totalBlocks;
    if ((batLengthOnDisk % 0x200) != 0) {
        /* Pad out to the next sector boundary */
        batLengthOnDisk += (0x200 - ((4 * writer->totalBlocks) % 0x200));
    }

    DWORD bytesWritten;
    unsigned char batBuf[4] = { 0xff, 0xff, 0xff, 0xff };
    for (unsigned int i = 0; i < batLengthOnDisk / 4; i++) {
        /* My understanding is that Windows will buffer all these making it no less efficient than 
           writing the whole thing at once */
        if (FALSE == WriteFile(writer->outputFileHandle, batBuf, 4, &bytesWritten, NULL)) {
            int lastError = GetLastError();
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_IMG_WRITE);
            tsk_error_set_errstr("tsk_img_writer_create: Error writing block allocation table", lastError);
            return TSK_ERR;
        }
    }

    /* Offset for the first data block - 0x600 bytes for the two headers plus the BAT length*/
    writer->nextDataOffset = 0x600 + batLengthOnDisk;

	/* Initialze all the bookkeeping arrays */
	writer->blockStatus = (IMG_WRITER_BLOCK_STATUS_ENUM*)tsk_malloc(writer->totalBlocks * sizeof(IMG_WRITER_BLOCK_STATUS_ENUM));

	writer->blockToOffset = (TSK_OFF_T*)tsk_malloc(writer->totalBlocks * sizeof(TSK_OFF_T));
	writer->blockToSectorBitmap = (unsigned char **)tsk_malloc(writer->totalBlocks * sizeof(unsigned char *));

    return TSK_OK;
#endif
}


