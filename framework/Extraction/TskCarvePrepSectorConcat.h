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
 * Definition of a class that concatenates unallocated sectors from an 
 * image as a series of files with a configurable maximum size. These files 
 * are optionally scheduled for carving. Instances of this class are also 
 * able to treat a file as a run of unallocated sectors. Instances of the class
 * use the following system properties: CARVE_PREP_OUTPUT_PATH, 
 * CARVE_PREP_OUTPUT_FILE_NAME, and CARVE_PREP_MAX_OUTPUT_FILE_SIZE. 
 *
 * This class assumes the availability of the Microsoft Windows API.
 * @@@ TODO: Use Poco API instead.
 */

#ifndef _TSK_CARVE_PREP_CONCAT_H
#define _TSK_CARVE_PREP_CONCAT_H

// TSK Framework includes
#include "CarvePrep.h"

// System includes
#include <string>

class TSK_FRAMEWORK_API TskCarvePrepSectorConcat : public CarvePrep
{
public:
    /**
     * Implementation of CarvePrep interface. Concatenates unallocated sector 
     * runs and writes the contents of the sectors to zero to many unallocated
     * sectors image files for later carving. 
     *
     * @param scheduleCarving True if carving of the output files should be
     * scheduled.
     * @returns Returns 0 on success or logs errors and returns 1 to indicate 
     * failure.
     */
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
     * Called by createOutputFiles to allow specialization of behavior when
     * an unallocated sectors image file is produced (i.e., uses the Template 
     * Method design pattern). The default implementation is to optionally 
     * schedule carving of the output file.
     *
     * @param unallocSectorsImgId Id assigned to the file by 
     * TskImgDB::addUnallocImg().
     * @param scheduleCarving Set to true if carving of the output file should
     * be scheduled.
     * @return Default implementation throws TskException on error.
     */
    virtual void onOutputFileCreated(int unallocSectorsImgId, bool scheduleCarving) const; 

private:
    // Creates the output folder indicated by the CARVE_PREP_OUTPUT_PATH 
    // system property. If the output folder already exists, it is deleted.
    //
    // @return Throws TskException on error.
    std::string prepareOutputFolder() const;

    // Writes each sector run in the sector runs passed into the function
    // to one or more unallocated sectors image files. The maximum size of any
    // single output file will not exceed the value of the 
    // MAX_UNALLOC_IMG_FILE_SIZE system property and each output file will 
    // contain sectors from only a single volume. 
    //
    // @param sectorRuns Sector runs to be written to the output files.
    // @param scheduleCarving Whether or not to schedule carving of the output 
    // files.
    // @return Throws TskException on error.
    void createOutputFiles(const std::string &outputFolderPath, SectorRuns &sectorRuns, bool scheduleCarving) const;

    // Creates a folder. If the specified folder already exists, delete it first.
    //
    // @param path Path of the folder to be created.
    // @return Throws TskException on error
    void createFolder(const std::string &path) const;

    // Maps the sectors written to an unallocated sectors image file to the 
    // corresponding sectors in the image and writes the results to the image 
    // database.
    //
    // @param unallocSectorsImgId Id assigned to the unallocated sectors image
    // file by TskImgDB::addUnallocImg().
    // @param outputFileHandle File handle used to access the unallocated sectors 
    // image file.
    // @param startingFileOffset Starting offset in the unallocated sectors 
    // image file (in bytes) of the unallocated sectors run or part of a 
    // sectors run that was written to the file. 
    // @param endingFileOffset Ending offset in the unallocated sectors image
    // file (in bytes) of the unallocated sectors run or part of a sectors run
    // that was written to the file.
    // @param volumeID Volume Id of the volume that was the source of the 
    // unallocated sectors run or part of a sectors run that was written to the
    // unallocated sectors image file.
    // @param startingImageOffset Starting offset in the image (in sectors) of 
    // the unallocated sectors run or part of a sectors run that was written to 
    // the unallocated sectors image file.  
    // @return Throws TskException on error.
    void storeOutputfileToImageMapping(uint64_t unallocSectorsImgId, HANDLE outputFileHandle, uint64_t startingFileOffset, uint64_t endingFileOffset, int volumeID, uint64_t startingImageOffset) const;

    static const uint64_t SECTORS_PER_READ = 32; 
};

#endif
