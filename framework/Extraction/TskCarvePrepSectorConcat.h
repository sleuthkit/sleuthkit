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
 * \file TskCarvePrepSectorConcat.h
 * Contains the interface of the TskCarvePrepSectorConcat class.
 */

#ifndef _TSK_CARVE_PREP_CONCAT_H
#define _TSK_CARVE_PREP_CONCAT_H

// TSK Framework includes
#include "CarvePrep.h"

// C/C++ library includes
#include <string>

/**
 * The TskCarvePrepSectorConcat class implements the CarvePrep abstract 
 * interface. It concatenates unallocated sector runs from an image and writes
 * the contents to one or more unallocated sectors image files with a 
 * configurable maximum size. These output files are optionally scheduled for
 * carving. Instances of this class are also able to treat a file as a run of
 * unallocated sectors. TskCarvePrepSectorConcat objects use the following 
 * system properties, if the properties are set: CARVE_DIR, 
 * CARVE_PREP_FILE_NAME, and CARVE_PREP_MAX_FILE_SIZE. 
 *
 * This class assumes the availability of the Microsoft Windows API.
 * @@@ TODO: Use Poco API instead.
 */
class TSK_FRAMEWORK_API TskCarvePrepSectorConcat : public CarvePrep
{
public:
    virtual int processSectors(bool scheduleCarving);

    /**
     * Treats the contents of a set of files as unallocated sector runs and 
     * writes the contents of the files to zero to many unallocated sectors 
     * image files for later carving. This may be useful for carving page
     * files, hibernation files, etc.
     *
     * @param fileName Output files for all files with this name will be 
     * generated.
     * @param scheduleCarving Set to true if carving of the output files should
     * be scheduled.
     * @return Throws TskException on error.
     */
    void processFiles(const std::string &fileName, bool scheduleCarving) const;

protected:

    /**
     * Called by createUnallocSectorsImgFiles to allow specialization of 
     * behavior when an unallocated sectors image file is produced (i.e., uses 
     * the Template Method design pattern). The default implementation is simply 
     * to optionally schedule carving of the output file.
     *
     * @param unallocSectorsImgId Id assigned to the file by 
     * TskImgDB::addUnallocImg().
     * @param scheduleCarving Set to true if carving of the output file should
     * be scheduled.
     * @return Default implementation throws TskException on error.
     */
    virtual void onUnallocSectorsImgFileCreated(int unallocSectorsImgId, bool scheduleCarving) const; 

private:
    /**
     * Reads in the CARVE_DIR, CARVE_PREP_FILE_NAME, and 
     * CARVE_PREP_MAX_FILE_SIZE system properties and creates the output folder
     * if it doesn't already exist.
     *
     * @param outputFolderPath The value of the CARVE_DIR system property 
     * or a default value.
     * @param outputFileName  The value of the CARVE_PREP_FILE_NAME system 
     * property or a default value.
     * @param maxOutputFileSize  The value of the CARVE_PREP_MAX_FILE_SIZE 
     * system property or a default value.
     * @return Throws TskException on error.
     */
    void setUpForCarvePrep(std::string &outputFolderPath, std::string &outputFileName, uint64_t &maxOutputFileSize) const;

    /** 
     * Writes each sector run in the sector runs passed into the function
     * to one or more unallocated sectors image files. The maximum size of any
     * single output file will not exceed the value of the 
     * MAX_UNALLOC_IMG_FILE_SIZE system property and each output file will 
     * contain sectors from only a single volume. 
     * 
     * @param outputFolderPath Folder to which the output files are written.
     * @param outputFileName  Name given to the output files.
     * @param maxOutputFileSize  Maximum output file size.
     * @param sectorRuns Sector runs to be written to the output files.
     * @param scheduleCarving Whether or not to schedule carving of the output 
     * files.
     * @return Throws TskException on error.
     */
    void createUnallocSectorsImgFiles(const std::string &outputFolderPath, const std::string &outputFileName, uint64_t maxOutputFileSize, SectorRuns &sectorRuns, bool scheduleCarving) const;

    /** 
     *  Creates a folder. If the specified folder already exists, delete it first.
     * 
     *  @param path Path of the folder to be created.
     *  @return Throws TskException on error
     */
    void createFolder(const std::string &path) const;

    /** 
     *  Maps the sectors written to an unallocated sectors image file to the 
     *  corresponding sectors in the image and writes the results to the image 
     *  database.
     * 
     *  @param unallocSectorsImgId Id assigned to the unallocated sectors image
     *  file by TskImgDB::addUnallocImg().
     *  @param outputFileHandle File handle used to access the unallocated sectors 
     *  image file.
     *  @param startingFileOffset Starting offset in the unallocated sectors 
     *  image file (in bytes) of the unallocated sectors run or part of a 
     *  sectors run that was written to the file. 
     *  @param endingFileOffset Ending offset in the unallocated sectors image
     *  file (in bytes) of the unallocated sectors run or part of a sectors run
     *  that was written to the file.
     *  @param volumeID Volume Id of the volume that was the source of the 
     *  unallocated sectors run or part of a sectors run that was written to the
     *  unallocated sectors image file.
     *  @param startingImageOffset Starting offset in the image (in sectors) of 
     *  the unallocated sectors run or part of a sectors run that was written to 
     *  the unallocated sectors image file.  
     *  @return Throws TskException on error.
     */
    void mapFileToImage(int unallocSectorsImgId, HANDLE outputFileHandle, uint64_t startingFileOffset, uint64_t endingFileOffset, int volumeID, uint64_t startingImageOffset) const;

    /** 
     * Constant that defines the chunk size for reading from unallocated 
     * sectors runs. 
     */
    static const uint64_t SECTORS_PER_READ = 32; 
};

#endif
