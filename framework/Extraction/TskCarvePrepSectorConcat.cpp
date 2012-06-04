/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file TskCarvePrepSectorConcat.cpp
 * Implementation of a class that concatenates unallocated sectors as a
 * series of files with a configurable maximum size. The files are optionally
 * scheduled for carving. Instances of this class are also able to treat a 
 * file as a run of unallocated sectors.
 */

// Include the class definition first to ensure it does not depend on
// subsequent includes in this file.
#include "TskCarvePrepSectorConcat.h" 

// TSK framework includes
#include "Services/TskImgDB.h"
#include "Services/TskServices.h"
#include "Services/Log.h"
#include "Utilities/TskUtilities.h"

// Standard library includes
#include <assert.h>
#include <string>
#include <sstream>

// Poco library includes. Include last to avoid applying Poco pragmas to 
// non-Poco files.
#include "Poco/File.h"
#include "Poco/Exception.h"

TskCarvePrepSectorConcat::TskCarvePrepSectorConcat(const std::wstring &outputFileName, uint64_t maxOutputFileSize) :
    m_outputFileName(outputFileName), m_maxOutputFileSize(maxOutputFileSize)
{
}

int TskCarvePrepSectorConcat::processSectors(bool scheduleCarving)
{
    try {
        prepareOutputFolder();

        // Write contents of unallocated sectors to output files suitable for carving.
        std::auto_ptr<SectorRuns> sectorRuns(TskServices::Instance().getImgDB().getFreeSectors());
        if (sectorRuns.get())
            createFilesToBeCarved(*sectorRuns, scheduleCarving);
    }
    catch (TskException &ex) {
        // This function takes responsiblity for logging errors.
        LOGERROR(TskUtilities::toUTF16(ex.message()));
        return 1;
    }

    return 0;
}

void TskCarvePrepSectorConcat::processFiles(const std::string &fileName, bool scheduleCarving) const
{
    prepareOutputFolder();

    // Get the file ids for any files with the the specified file name.
    TskImgDB &imgDB = TskServices::Instance().getImgDB();
    std::stringstream condition;
    condition << "WHERE files.name = " << fileName;

    // Write contents of file to output files suitable for carving.
    std::auto_ptr<SectorRuns> sectorRuns;
    std::vector<uint64_t> fileIds = imgDB.getFileIds(condition.str());
    for (std::vector<uint64_t>::const_iterator it = fileIds.begin(); it != fileIds.end(); ++it)
    {
        sectorRuns.reset(imgDB.getFileSectors(*it));
        if (sectorRuns.get()) {
            createFilesToBeCarved(*sectorRuns, scheduleCarving);
        }
    }
}

std::wstring TskCarvePrepSectorConcat::outputFolderPath() const
{
    static std::wstring folderPath;

    if (folderPath.empty())
    {
        std::wstringstream pathBuilder;
        pathBuilder << TskServices::Instance().getSystemProperties().get(TskSystemProperties::OUT_DIR) << L"\\Carve";
        folderPath = pathBuilder.str();
    }

    return folderPath;
}

void TskCarvePrepSectorConcat::onFileCreated(int unallocImgId, bool scheduleCarving) const
{
    TskImgDB &imgDB = TskServices::Instance().getImgDB();
    if (scheduleCarving) {
        if (TskServices::Instance().getScheduler().schedule(Scheduler::Carve, unallocImgId, unallocImgId) == 0)
            imgDB.setUnallocImgStatus(unallocImgId, TskImgDB::IMGDB_UNALLOC_IMG_STATUS_SCHEDULE_OK);
        else {
            imgDB.setUnallocImgStatus(unallocImgId, TskImgDB::IMGDB_UNALLOC_IMG_STATUS_SCHEDULE_ERR);
            std::stringstream msg;
            msg << "TskCarvePrepSectorConcat failed to schedule carving of unallocated image file " << unallocImgId; 
            throw TskException(msg.str());
        }
    }
}

void TskCarvePrepSectorConcat::prepareOutputFolder() const
{
    // This function is designed to be safely called by multiple calls to
    // processSectors() and/or processFiles().
    static bool folderCreationAttempted = false;
    static bool folderCreated = false;

    if (!folderCreationAttempted) {
        folderCreationAttempted = true;
        folderCreated = createFolder(outputFolderPath());
    }

    if (!folderCreated) {
        std::stringstream msg;
        msg << "TskCarvePrepSectorConcat failed to create output folder " << TskUtilities::toUTF8(outputFolderPath());
        throw TskException(msg.str());
    }
}

void TskCarvePrepSectorConcat::createFilesToBeCarved(SectorRuns &sectorRuns, bool scheduleCarving) const
{
    TskImgDB &imgDB = TskServices::Instance().getImgDB();
   
    // Write each sector run in the sector runs passed into the function
    // to one or more output files. The maximum size of any single output file 
    // will not exceed m_maxOutputFileSize and each output file will contain
    // sectors from only a single image volume.
    int imgVolumeID = -1;
    char sectorBuffer[SECTORS_PER_READ * 512];
    int outputFileNumber = 0;
    HANDLE outputFileHandle;
    uint64_t currentFileOffset = 0; // In bytes
    do {
        // Keep track of the starting offsets in the output file (in bytes) and 
        // in the image (in sectors) of the sector run or part of a sector run 
        // being written to the current output file. This data will be needed 
        // to store a mapping of the sectors in the output file to the corresponding  
        // sectors in the image.
        uint64_t startingFileOffset = currentFileOffset; // In bytes
        uint64_t startingImageOffset = sectorRuns.getDataStart(); // In sectors 
        
        // Read the contents of the sectors in the current run in chunks.
        for (uint64_t sectorRunOffset = 0; sectorRunOffset < sectorRuns.getDataLen(); ) {
            // Calculate how many sectors to read in the current chunk.
            uint64_t sectorsToRead = SECTORS_PER_READ;
            if (sectorsToRead > sectorRuns.getDataLen() - sectorRunOffset)
                sectorsToRead = sectorRuns.getDataLen() - sectorRunOffset;

            // If the read will make the output file exceed the maximum file size, or if a volume boundary
            // has been reached, close the current output file and open a new output file. Note that the 
            // first time this loop is entered, the initial output file will be created here 
            // since the image volume ID was initialized to an invalid value.
            if ((sectorRuns.getVolID() != imgVolumeID) || ((sectorsToRead * 512) + currentFileOffset > m_maxOutputFileSize)) {
                // Store the mapping of the sectors written to the output file to the corresponding
                // sectors in the image.
                if (currentFileOffset != startingFileOffset) {
                    storeOutputfileToImageMapping(outputFileNumber, outputFileHandle, startingFileOffset, currentFileOffset, sectorRuns.getVolID(), startingImageOffset);

                    // Advance the starting image offset to accurately reflect the starting image offset
                    // for the next output file.  
                    startingImageOffset += (currentFileOffset - startingFileOffset) / 512;
                }

                // Close the current output file.
                if (outputFileNumber) 
                    CloseHandle(outputFileHandle);

                // Schedule the current output file for carving. Note that derived classes
                // can change this behavior by overriding onFileCreated.
                if (currentFileOffset > 0) 
                    onFileCreated(outputFileNumber, scheduleCarving); 

                // Get the next output file number. 
                if (imgDB.addUnallocImg(outputFileNumber) == -1) {
                    throw TskException("TskCarvePrepSectorConcat failed to get next output file number");
                }

                // Create the next output file.
                createOutputFile(outputFileNumber, outputFileHandle);

                // Reset the output file offsets and volume ID.
                currentFileOffset = 0;
                startingFileOffset = 0;
                imgVolumeID = sectorRuns.getVolID();
            }

            // Read another chunk of sectors from this run.
            int sectorsRead = sectorRuns.getData(sectorRunOffset, static_cast<int>(sectorsToRead), sectorBuffer);
            if (sectorsRead == -1)
                throw TskException("TskCarvePrepSectorConcat encountered error reading sector contents from sector run");

            // Write the chunk of sectors to the output file.
            DWORD nBytesWritten;
            if (WriteFile(outputFileHandle, sectorBuffer, sectorsRead * 512, &nBytesWritten, NULL) == FALSE) {
                imgDB.setUnallocImgStatus(outputFileNumber, TskImgDB::IMGDB_UNALLOC_IMG_STATUS_CARVED_ERR);
                throw TskException("TskCarvePrepSectorConcat encountered error writing to output file");
            }

            // Update the output file and sector run offsets to reflect the sucessful read.
            currentFileOffset += nBytesWritten;
            sectorRunOffset += sectorsRead;

            if (sectorsRead == 0) 
                break;
        }

        // Store the mapping of the sectors written to the output file to the corresponding
        // sectors in the image.
        if (currentFileOffset != startingFileOffset)
            storeOutputfileToImageMapping(outputFileNumber, outputFileHandle, startingFileOffset, currentFileOffset, sectorRuns.getVolID(), startingImageOffset);
    } 
    while(sectorRuns.next() != -1);

    // Close and schedule the final output file.
    if (outputFileNumber) 
        CloseHandle(outputFileHandle);
    if (currentFileOffset > 0)
        onFileCreated(outputFileNumber, scheduleCarving);
}

void TskCarvePrepSectorConcat::createOutputFile(int outputFileNumber, HANDLE& outputFileHandle) const
{
    // Create a subdirectory named for the file number.
    std::wstringstream path;
    path << outputFolderPath() << L"\\" << outputFileNumber;
    createFolder(path.str());
    
    // Create an output file in the subdirectory.
    path << "\\" << m_outputFileName;
    outputFileHandle = CreateFileW(path.str().c_str(), GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (outputFileHandle == INVALID_HANDLE_VALUE) {
        TskServices::Instance().getImgDB().setUnallocImgStatus(outputFileNumber, TskImgDB::IMGDB_UNALLOC_IMG_STATUS_CARVED_ERR);
        std::stringstream msg;
        msg << "TskCarvePrepSectorConcat failed to create output file " << path;
        throw TskException(msg.str());
    }
}

bool TskCarvePrepSectorConcat::createFolder(const std::wstring &path) const
{
    try {
        Poco::File folder(TskUtilities::toUTF8(path));
        if (folder.exists())
            folder.remove(true);
        return folder.createDirectory();
    }
    catch (Poco::Exception& ex) {
        std::wstringstream msg;
        msg << L"TskCarvePrepSectorConcat failed to create folder " << path << L": " << ex.message().c_str();
        LOGERROR(msg.str());    
        return false;
    }
}

void TskCarvePrepSectorConcat::storeOutputfileToImageMapping(int outputFileNumber, HANDLE outputFileHandle, uint64_t startingFileOffset, uint64_t endingFileOffset, int imgVolumeID, uint64_t startingImageOffset) const
{
    // Convert the starting offset in the output file from a byte offset to a sector offset and 
    // calculate the number of sectors written to the file.
    uint64_t startingFileOffsetInSectors = startingFileOffset / 512;
    uint64_t sectorsWritten = (endingFileOffset - startingFileOffset) / 512;

    // Store the mapping of the output file sectors to image sectors.
    if (TskServices::Instance().getImgDB().addAllocUnallocMapInfo(imgVolumeID, outputFileNumber, startingFileOffsetInSectors, sectorsWritten, startingImageOffset) != 0) {
        CloseHandle(outputFileHandle); 
        std::stringstream msg;
        msg << "TskCarvePrepSectorConcat failed to add mapping to image for output file " << outputFileNumber;
        throw TskException(msg.str());
    }
}