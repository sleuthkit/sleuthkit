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
 * Contains the implementation of the TskCarvePrepSectorConcat class.
 */

// Include the class definition first to ensure it does not depend on subsequent includes in this file.
#include "TskCarvePrepSectorConcat.h" 

// TSK Framework includes
#include "tsk/framework/services/TskImgDB.h"
#include "tsk/framework/services/TskServices.h"
#include "tsk/framework/services/Log.h"
#include "tsk/framework/utilities/TskUtilities.h"

// Poco includes
#include "Poco/File.h"
#include "Poco/Exception.h"
#include "Poco/Path.h"
#include "Poco/String.h"

// C/C++ library includes
#include <assert.h>
#include <string>
#include <sstream>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <memory>

namespace
{
    const size_t SECTOR_SIZE = 512;
    const size_t DEFAULT_SECTORS_PER_READ = 32;
    static const char zeroBuffer[DEFAULT_SECTORS_PER_READ * SECTOR_SIZE] = { 0 };
}

TskCarvePrepSectorConcat::TskCarvePrepSectorConcat()
{
}

int TskCarvePrepSectorConcat::processSectors()
{
    try 
    {
        std::string outputFolderPath;
        std::string outputFileName;
        size_t maxOutputFileSize;
        setUpForCarvePrep(outputFolderPath, outputFileName, maxOutputFileSize);

        std::auto_ptr<SectorRuns> sectorRuns(TskServices::Instance().getImgDB().getFreeSectors());
        if (sectorRuns.get())
        {
            createUnallocSectorsImgFiles(outputFolderPath, outputFileName, maxOutputFileSize, *sectorRuns);
        }
    }
    catch (TskException &ex) 
    {
        LOGERROR(ex.message());
        return 1;
    }

    return 0;
}

void TskCarvePrepSectorConcat::processFiles(const std::string &fileName) const
{
    assert(!fileName.empty());
    if (fileName.empty())
    {
        throw TskException("TskCarvePrepSectorConcat::processFiles : empty file name argument");
    }

	std::string outputFolderPath;
    std::string outputFileName;
    size_t maxOutputFileSize;
    setUpForCarvePrep(outputFolderPath, outputFileName, maxOutputFileSize);

    // Get the file ids for any files with the the specified file name.
    TskImgDB &imgDB = TskServices::Instance().getImgDB();
    std::stringstream condition;
    condition << "WHERE files.name = " << "'" << fileName << "'";
    std::vector<uint64_t> fileIds = imgDB.getFileIds(condition.str());

    std::auto_ptr<SectorRuns> sectorRuns;
    for (std::vector<uint64_t>::const_iterator it = fileIds.begin(); it != fileIds.end(); ++it)
    {
        sectorRuns.reset(imgDB.getFileSectors(*it));
        if (sectorRuns.get()) 
        {
            createUnallocSectorsImgFiles(outputFolderPath, outputFileName, maxOutputFileSize, *sectorRuns);
        }
    }
}

void TskCarvePrepSectorConcat::onUnallocSectorsImgFileCreated(int unallocSectorsImgId) const
{
    // Schedule the file for carving.
    TskImgDB &imgDB = TskServices::Instance().getImgDB();

    if (TskServices::Instance().getScheduler().schedule(Scheduler::Carve, unallocSectorsImgId, unallocSectorsImgId) == 0)
    {
        imgDB.setUnallocImgStatus(unallocSectorsImgId, TskImgDB::IMGDB_UNALLOC_IMG_STATUS_SCHEDULE_OK);
    }
    else 
    {
        imgDB.setUnallocImgStatus(unallocSectorsImgId, TskImgDB::IMGDB_UNALLOC_IMG_STATUS_SCHEDULE_ERR);
        std::stringstream msg;
        msg << "TskCarvePrepSectorConcat::onUnallocSectorsImgFileCreated : failed to schedule carving of unallocated image file " << unallocSectorsImgId; 
        throw TskException(msg.str());
    }
}

void TskCarvePrepSectorConcat::setUpForCarvePrep(std::string &outputFolderPath, std::string &outputFileName, size_t &maxOutputFileSize) const
{
    try
    {
        // Create the output folder. Since multiple calls to processSectors() and/or processFiles() are possible, check to see if the folder already exists.
        outputFolderPath = GetSystemProperty("CARVE_DIR");
        Poco::File folder(outputFolderPath);
        if (!folder.exists())
        {
            folder.createDirectory();
        }

        outputFileName = GetSystemProperty("UNALLOC_SECTORS_IMG_FILE_NAME");
        maxOutputFileSize = strtoul(GetSystemProperty("MAX_UNALLOC_SECTORS_IMG_FILE_SIZE").c_str(), NULL, 10);
    }
    catch (Poco::Exception &ex) 
    {
        std::stringstream msg;
        msg << "TskCarvePrepSectorConcat::createFolder : Poco exception: " << ex.displayText();
        throw TskException(msg.str());
    }
}

void TskCarvePrepSectorConcat::createUnallocSectorsImgFiles(const std::string &outputFolderPath, const std::string &outputFileName, size_t maxOutputFileSize, SectorRuns &sectorRuns) const
{
    char *sectorBuffer = NULL;
    try
    {
        // Create a buffer for data from sector runs. If not breaking output files only on volume boundaries (i.e., max output file size is zero), 
        // be sure sectors to read is less than or equal to max output file size.
        size_t sectorsPerRead = DEFAULT_SECTORS_PER_READ;
        if ((maxOutputFileSize > 0) && (sectorsPerRead * SECTOR_SIZE > maxOutputFileSize))
        {
            sectorsPerRead = maxOutputFileSize / SECTOR_SIZE;
        }
        sectorBuffer = new char[sectorsPerRead * SECTOR_SIZE];

        TskImgDB &imgDB = TskServices::Instance().getImgDB();       
        int volumeID = -1;
        int unallocSectorsImgId = 0;
        std::ofstream outfile;
        uint64_t currentFileOffset = 0; // In bytes
        Poco::File currentFile;

        do 
        {
            // Keep track of the starting offsets in the output file (in bytes) and in the image (in sectors) of the sector run or part of a sector run 
            // being written to the current output file. This data will be needed to store a mapping of the sectors in the output file to the corresponding  
            // sectors in the image.
            uint64_t startingFileOffset = currentFileOffset; // In bytes
            uint64_t startingImageOffset = sectorRuns.getDataStart(); // In sectors 
            
            // Read the contents of the sectors in the current run in chunks.
            for (uint64_t sectorRunOffset = 0; sectorRunOffset < sectorRuns.getDataLen(); ) 
            {
                // Calculate how many sectors to read in the current chunk.
                uint64_t sectorsToRead = sectorsPerRead;
                if (sectorsToRead > sectorRuns.getDataLen() - sectorRunOffset)
                {
                    sectorsToRead = sectorRuns.getDataLen() - sectorRunOffset;
                }

                // If the read will make the output file exceed the maximum file size, or if a volume boundary
                // has been reached, close the current output file and open a new output file. Note that the 
                // first time this loop is entered, the initial output file will be created here 
                // since the image volume ID was initialized to an invalid value.
                if ((sectorRuns.getVolID() != volumeID) || ((maxOutputFileSize > 0) && ((sectorsToRead * 512) + currentFileOffset > maxOutputFileSize))) 
                {
                    // Store the mapping of the sectors written to the output file to the corresponding sectors in the image.
                    if (currentFileOffset != startingFileOffset) 
                    {
                        mapFileToImage(unallocSectorsImgId, outfile, startingFileOffset, currentFileOffset, sectorRuns.getVolID(), startingImageOffset);

                        // Advance the starting image offset to accurately reflect the starting image offset for the next output file.  
                        startingImageOffset += (currentFileOffset - startingFileOffset) / 512;
                    }

                    closeAndSchedule(unallocSectorsImgId, currentFile, outfile);

                    // Get the next output file number. 
                    if (imgDB.addUnallocImg(unallocSectorsImgId) == -1) 
                    {
                        throw TskException("TskCarvePrepSectorConcat::createUnallocSectorsImgFiles : failed to get next output file number");
                    }

                    // Create a subdirectory named for the file number.
                    std::stringstream path;
                    path << outputFolderPath.c_str() << Poco::Path::separator() << unallocSectorsImgId;
                    createFolder(path.str());
                    
                    // Create an output file in the subdirectory.
                    path << Poco::Path::separator() << outputFileName.c_str();
                    currentFile = path.str();
                    outfile.open(path.str().c_str(), std::ios_base::out|std::ios_base::binary);
                    if (outfile.fail())
                    {
                        TskServices::Instance().getImgDB().setUnallocImgStatus(unallocSectorsImgId, TskImgDB::IMGDB_UNALLOC_IMG_STATUS_CARVED_ERR);

                        std::stringstream msg;
                        msg << "TskCarvePrepSectorConcat::createUnallocSectorsImgFiles : failed to create output file " << unallocSectorsImgId;
                        throw TskException(msg.str());
                    }
                    // Reset the output file offsets and volume ID.
                    currentFileOffset = 0;
                    startingFileOffset = 0;
                    volumeID = sectorRuns.getVolID();
                }

                // Read another chunk of sectors from this run. 
                int sectorsRead = sectorRuns.getData(sectorRunOffset, static_cast<int>(sectorsToRead), sectorBuffer);
                if (sectorsRead == -1)
                {
                    imgDB.setUnallocImgStatus(unallocSectorsImgId, TskImgDB::IMGDB_UNALLOC_IMG_STATUS_CARVED_ERR);
                    LOGERROR("TskCarvePrepSectorConcat::createUnallocSectorsImgFiles : error reading sector contents from sector run");
                    break;
                }

                // If we are at the start of a new output file and the chunk we've just read
                // contains nothing but zeros there is no need to write it to the file.
                // This allows us skip carving for potentially large areas that contain nothing.
                if (currentFileOffset == 0 && sectorBuffer[0] == 0 && !memcmp(sectorBuffer, zeroBuffer, sectorsRead * SECTOR_SIZE))
                {
                    sectorRunOffset += sectorsRead;
                    startingImageOffset += sectorsRead;
                    continue;
                }

                // Write the chunk of sectors to the output file.
                outfile.write(sectorBuffer, sectorsRead * 512);
                if (outfile.bad())
                {
                    imgDB.setUnallocImgStatus(unallocSectorsImgId, TskImgDB::IMGDB_UNALLOC_IMG_STATUS_CARVED_ERR);
                    std::stringstream msg;
                    msg << "TskCarvePrepSectorConcat::createUnallocSectorsImgFiles : error writing to output file " << unallocSectorsImgId;
                    throw TskException(msg.str());
                }

                // Update the output file and sector run offsets to reflect the sucessful read.
                currentFileOffset += sectorsRead * 512;
                sectorRunOffset += sectorsRead;

                if (sectorsRead == 0) 
                {
                    break;
                }
            }

            // Store the mapping of the sectors written to the output file to the corresponding sectors in the image.
            if (currentFileOffset != startingFileOffset)
            {
                mapFileToImage(unallocSectorsImgId, outfile, startingFileOffset, currentFileOffset, sectorRuns.getVolID(), startingImageOffset);
            }
        }
        while(sectorRuns.next() != -1);

        closeAndSchedule(unallocSectorsImgId, currentFile, outfile);

        if (sectorBuffer != NULL)
        {
            delete [] sectorBuffer;
        }
    }
    catch(...)
    {
        if (sectorBuffer != NULL)
        {
            delete [] sectorBuffer;
        }

        throw;
    }
}

void TskCarvePrepSectorConcat::createFolder(const std::string &path) const
{
    try 
    {
        Poco::File folder(path);
        if (folder.exists())
        {
            folder.remove(true);
        }
        
        folder.createDirectory();
    }
    catch (Poco::Exception& ex) 
    {
        std::stringstream msg;
        msg << "TskCarvePrepSectorConcat::createFolder : failed to create folder '" << path << "': " << ex.message();
        throw TskException(msg.str());
    }
}

void TskCarvePrepSectorConcat::mapFileToImage(int unallocSectorsImgId, std::ofstream & outfile, uint64_t startingFileOffset, uint64_t endingFileOffset, int volumeID, uint64_t startingImageOffset) const
{
    // Convert the starting offset in the output file from a byte offset to a sector offset and calculate the number of sectors written to the file.
    uint64_t startingFileOffsetInSectors = startingFileOffset / 512;
    uint64_t sectorsWritten = (endingFileOffset - startingFileOffset) / 512;

    // Store the mapping of the output file sectors to image sectors.
    if (TskServices::Instance().getImgDB().addAllocUnallocMapInfo(volumeID, unallocSectorsImgId, startingFileOffsetInSectors, sectorsWritten, startingImageOffset) != 0) 
    {
        outfile.close();
        std::stringstream msg;
        msg << "TskCarvePrepSectorConcat::mapFileToImage : failed to add mapping to image for output file " << unallocSectorsImgId;
        throw TskException(msg.str());
    }
}

void TskCarvePrepSectorConcat::closeAndSchedule(const int unallocSectorsImgId, Poco::File& outFile, std::ofstream& outFileStream) const
{
    if (unallocSectorsImgId == 0)
        return;

    outFileStream.close();

    // If this is a zero length file we remove it and skip carving.
    if (outFile.getSize() == 0)
    {
        outFile.remove();
        TskServices::Instance().getImgDB().setUnallocImgStatus(unallocSectorsImgId, TskImgDB::IMGDB_UNALLOC_IMG_STATUS_CARVED_NOT_NEEDED);
    }
    else
    {
        onUnallocSectorsImgFileCreated(unallocSectorsImgId);
    }
}