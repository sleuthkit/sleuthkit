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
 * Implementation of a class that concatenates unallocated sectors from an 
 * image as a series of files with a configurable maximum size. These files 
 * are optionally scheduled for carving. Instances of this class are also 
 * able to treat a file as a run of unallocated sectors. Instances of the class
 * use the following system properties: CARVE_PREP_OUTPUT_PATH, 
 * CARVE_PREP_OUTPUT_FILE_NAME, and CARVE_PREP_MAX_OUTPUT_FILE_SIZE. 
 *
 * This class assumes the availability of the Microsoft Windows API.
 * @@@ TODO: Use Poco API instead.
 */

// Include the class definition first to ensure it does not depend on
// subsequent includes in this file.
#include "TskCarvePrepSectorConcat.h" 

// TSK framework includes
#include "Services/TskImgDB.h"
#include "Services/TskServices.h"
#include "Services/Log.h"
#include "Utilities/TskUtilities.h"

// System includes
#include <assert.h>
#include <string>
#include <sstream>
#include <cstdlib>

// Poco library includes 
#include "Poco/File.h"
#include "Poco/Exception.h"
#include "Poco/Path.h"

int TskCarvePrepSectorConcat::processSectors(bool scheduleCarving)
{
    try 
    {
        std::string outputFolderPath = prepareOutputFolder();

        // Write contents of unallocated sectors to output files suitable for carving.
        std::auto_ptr<SectorRuns> sectorRuns(TskServices::Instance().getImgDB().getFreeSectors());
        if (sectorRuns.get())
        {
            createOutputFiles(outputFolderPath, *sectorRuns, scheduleCarving);
        }
    }
    catch (TskException &ex) 
    {
        LOGERROR(TskUtilities::toUTF16(ex.message()));
        return 1;
    }

    return 0;
}

void TskCarvePrepSectorConcat::processFiles(const std::string &fileName, bool scheduleCarving) const
{
    if (fileName.empty())
    {
        throw TskException("TskCarvePrepSectorConcat::processFiles passed empty file name");
    }

    std::string outputFolderPath = prepareOutputFolder();

    // Get the file ids for any files with the the specified file name.
    TskImgDB &imgDB = TskServices::Instance().getImgDB();
    std::stringstream condition;
    condition << "WHERE files.name = " << "'" << fileName << "'";
    std::vector<uint64_t> fileIds = imgDB.getFileIds(condition.str());

    // Write contents of file to output files suitable for carving.
    std::auto_ptr<SectorRuns> sectorRuns;
    for (std::vector<uint64_t>::const_iterator it = fileIds.begin(); it != fileIds.end(); ++it)
    {
        sectorRuns.reset(imgDB.getFileSectors(*it));
        if (sectorRuns.get()) 
        {
            createOutputFiles(outputFolderPath, *sectorRuns, scheduleCarving);
        }
    }
}

void TskCarvePrepSectorConcat::onOutputFileCreated(int unallocSectorsImgId, bool scheduleCarving) const
{
    TskImgDB &imgDB = TskServices::Instance().getImgDB();
    if (scheduleCarving) 
    {
        if (TskServices::Instance().getScheduler().schedule(Scheduler::Carve, unallocSectorsImgId, unallocSectorsImgId) == 0)
        {
            imgDB.setUnallocImgStatus(unallocSectorsImgId, TskImgDB::IMGDB_UNALLOC_IMG_STATUS_SCHEDULE_OK);
        }
        else 
        {
            imgDB.setUnallocImgStatus(unallocSectorsImgId, TskImgDB::IMGDB_UNALLOC_IMG_STATUS_SCHEDULE_ERR);
            std::stringstream msg;
            msg << "TskCarvePrepSectorConcat::onOutputFileCreated failed to schedule carving of unallocated image file " << unallocSectorsImgId; 
            throw TskException(msg.str());
        }
    }
}

std::string TskCarvePrepSectorConcat::prepareOutputFolder() const
{
    // This function is designed to be safely called by multiple calls to processSectors() and/or processFiles().
    static std::string outputFolderPath;

    if (outputFolderPath.empty()) 
    {
        outputFolderPath = GetSystemProperty("CARVE_PREP_OUTPUT_PATH");

        if (outputFolderPath.empty())
        {
            // Default to a subfolder of the output directory. This should work because the output folder is a required system property.
            std::stringstream pathBuilder;
            pathBuilder << GetSystemProperty(TskSystemProperties::OUT_DIR) << Poco::Path::separator() << "Carving";
            outputFolderPath = pathBuilder.str();

            // Set the property for the carve extract implementation(s).
            SetSystemProperty("CARVE_PREP_OUTPUT_PATH", outputFolderPath);            
        }

        createFolder(outputFolderPath);
    }

    return outputFolderPath;
}

void TskCarvePrepSectorConcat::createOutputFiles(const std::string &outputFolderPath, SectorRuns &sectorRuns, bool scheduleCarving) const
{
    TskImgDB &imgDB = TskServices::Instance().getImgDB();

    // The output files all have the same name, but are written to subdirectories bearing the name of the unallocated sectors image id corresponding to the file.
    std::string outputFileName = GetSystemProperty("CARVE_PREP_OUTPUT_FILE_NAME");
    if (outputFileName.empty())
    {
        outputFileName = "unalloc.bin"; 
        SetSystemProperty("CARVE_PREP_OUTPUT_FILE_NAME", outputFileName);            
    }

    // Get the maximum size for each output file.
    // @@@ TODO: Replace strtoul() call with a strtoull() call when a newer version of C++ is available.
    std::string maxOutputFileSizeStr = GetSystemProperty("CARVE_PREP_MAX_OUTPUT_FILE_SIZE");
    if (maxOutputFileSizeStr.empty())
    {
        maxOutputFileSizeStr = "1000000000";
        SetSystemProperty("CARVE_PREP_MAX_OUTPUT_FILE_SIZE", maxOutputFileSizeStr);            
    }
    uint64_t maxOutputFileSize = strtoul(maxOutputFileSizeStr.c_str(), NULL, 10);
   
    int volumeID = -1;
    char sectorBuffer[SECTORS_PER_READ * 512];
    int unallocSectorsImgId = 0;
    HANDLE outputFileHandle;
    uint64_t currentFileOffset = 0; // In bytes
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
            uint64_t sectorsToRead = SECTORS_PER_READ;
            if (sectorsToRead > sectorRuns.getDataLen() - sectorRunOffset)
            {
                sectorsToRead = sectorRuns.getDataLen() - sectorRunOffset;
            }

            // If the read will make the output file exceed the maximum file size, or if a volume boundary
            // has been reached, close the current output file and open a new output file. Note that the 
            // first time this loop is entered, the initial output file will be created here 
            // since the image volume ID was initialized to an invalid value.
            if ((sectorRuns.getVolID() != volumeID) || ((sectorsToRead * 512) + currentFileOffset > maxOutputFileSize)) 
            {
                // Store the mapping of the sectors written to the output file to the corresponding sectors in the image.
                if (currentFileOffset != startingFileOffset) 
                {
                    storeOutputfileToImageMapping(unallocSectorsImgId, outputFileHandle, startingFileOffset, currentFileOffset, sectorRuns.getVolID(), startingImageOffset);

                    // Advance the starting image offset to accurately reflect the starting image offset for the next output file.  
                    startingImageOffset += (currentFileOffset - startingFileOffset) / 512;
                }

                // Close the current output file.
                if (unallocSectorsImgId) 
                {
                    CloseHandle(outputFileHandle);
                }

                // Schedule the current output file for carving. Note that derived classes can change this behavior by overriding onOutputFileCreated.
                if (currentFileOffset > 0) 
                {
                    onOutputFileCreated(unallocSectorsImgId, scheduleCarving); 
                }

                // Get the next output file number. 
                if (imgDB.addUnallocImg(unallocSectorsImgId) == -1) 
                {
                    throw TskException("TskCarvePrepSectorConcat::createOutputFiles failed to get next output file number");
                }

                // Create a subdirectory named for the file number.
                std::stringstream path;
                path << outputFolderPath.c_str() << Poco::Path::separator() << unallocSectorsImgId;
                createFolder(path.str());
                
                // Create an output file in the subdirectory.
                path << Poco::Path::separator() << outputFileName.c_str();
                outputFileHandle = CreateFileW(TskUtilities::toUTF16(path.str()).c_str(), GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (outputFileHandle == INVALID_HANDLE_VALUE) 
                {
                    TskServices::Instance().getImgDB().setUnallocImgStatus(unallocSectorsImgId, TskImgDB::IMGDB_UNALLOC_IMG_STATUS_CARVED_ERR);

                    std::stringstream msg;
                    msg << "TskCarvePrepSectorConcat::createOutputFiles failed to create output file " << unallocSectorsImgId;
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
                throw TskException("TskCarvePrepSectorConca::createOutputFilest encountered error reading sector contents from sector run");
            }

            // Write the chunk of sectors to the output file.
            DWORD nBytesWritten;
            if (WriteFile(outputFileHandle, sectorBuffer, sectorsRead * 512, &nBytesWritten, NULL) == FALSE) 
            {
                imgDB.setUnallocImgStatus(unallocSectorsImgId, TskImgDB::IMGDB_UNALLOC_IMG_STATUS_CARVED_ERR);
                std::stringstream msg;
                msg << "TskCarvePrepSectorConcat::createOutputFiles encountered error writing to output file " << unallocSectorsImgId;
                throw TskException(msg.str());
            }

            // Update the output file and sector run offsets to reflect the sucessful read.
            currentFileOffset += nBytesWritten;
            sectorRunOffset += sectorsRead;

            if (sectorsRead == 0) 
            {
                break;
            }
        }

        // Store the mapping of the sectors written to the output file to the corresponding sectors in the image.
        if (currentFileOffset != startingFileOffset)
        {
            storeOutputfileToImageMapping(unallocSectorsImgId, outputFileHandle, startingFileOffset, currentFileOffset, sectorRuns.getVolID(), startingImageOffset);
        }
    } 
    while(sectorRuns.next() != -1);

    // Close the final output file.
    if (unallocSectorsImgId) 
    {
        CloseHandle(outputFileHandle);
    }

    // Schedule the final output file.
    if (currentFileOffset > 0)
    {
        onOutputFileCreated(unallocSectorsImgId, scheduleCarving);
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
        // Replace the Poco exception with a TSK exception.
        std::stringstream msg;
        msg << "TskCarvePrepSectorConcat::createFolder failed to create folder '" << path << L"': " << ex.message();
        throw TskException(msg.str());
    }
}

void TskCarvePrepSectorConcat::storeOutputfileToImageMapping(uint64_t unallocSectorsImgId, HANDLE outputFileHandle, uint64_t startingFileOffset, uint64_t endingFileOffset, int volumeID, uint64_t startingImageOffset) const
{
    // Convert the starting offset in the output file from a byte offset to a sector offset and calculate the number of sectors written to the file.
    uint64_t startingFileOffsetInSectors = startingFileOffset / 512;
    uint64_t sectorsWritten = (endingFileOffset - startingFileOffset) / 512;

    // Store the mapping of the output file sectors to image sectors.
    if (TskServices::Instance().getImgDB().addAllocUnallocMapInfo(volumeID, unallocSectorsImgId, startingFileOffsetInSectors, sectorsWritten, startingImageOffset) != 0) 
    {
        CloseHandle(outputFileHandle); 
        std::stringstream msg;
        msg << "TskCarvePrepSectorConcat::storeOutputfileToImageMapping failed to add mapping to image for output file " << unallocSectorsImgId;
        throw TskException(msg.str());
    }
}