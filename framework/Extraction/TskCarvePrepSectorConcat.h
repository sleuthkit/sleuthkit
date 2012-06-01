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
 * Definition of a class that concatenates unallocated sectors as a
 * series of files with a configurable maximum size. The output files are
 * optionally scheduled for carving.
 */

#ifndef _TSK_CARVE_PREP_CONCAT_H
#define _TSK_CARVE_PREP_CONCAT_H

#include "CarvePrep.h"
#include <string>

class TSK_FRAMEWORK_API TskCarvePrepSectorConcat : public CarvePrep
{
public:
    /**
     * Constructor.
     * @param outputFolderPath Absolute path of directory where output files are to be written
     * @param outputFileName Filename to be used for each output file; the files will be distinguished
     * by storing them in subdirectories named for the output file number.
     * @param maxOutputFileSize 
     */
     TskCarvePrepSectorConcat(const std::wstring &outputFolderPath, const std::wstring &outputFileName, uint64_t maxOutputFileSize);

    /**
     * Implementation of CarvePrep interface. Concatenates unallocated sector runs 
     * and writes the contents of the sectors to zero to many output files for later carving. 
     * @param scheduleCarving True if carving of the output files should be scheduled.
     * @returns Returns 0 on success or logs errors and returns 1 to indicate failure
     */
    virtual int processSectors(bool scheduleCarving);

    /**
     * Treats the contents of a set of file as sector runs and writes the contents of the 
     * files to zero to many output files for later carving. 
     * @param fileName Will prep all files with this name for carving
     * @param scheduleCarving True if carving of the output files should be scheduled.
     * @return Throws TskException on error
     */
    void processFiles(const std::string& fileName, bool scheduleCarving) const;

protected:
    /**
     * Called by createFilesToBeCarved to allow specialization of behvior when
     * an output file is produced. The default implementation is to optionally 
     * schedule carving of the output file.
     * @param unallocImgId Id assigned to the file in the unallocated 
     * image files table
     * @param scheduleCarving True if carving of the output file should be
     * scheduled.
     * @return Default implementation throws TskException on error
     */
    virtual void onFileCreated(int unallocImgId, bool scheduleCarving) const; 

private:
    /**
     * Creates the output folder with the path passed in to the constructor. 
     * If the output folder already exists, it is deleted.
     * @return Throws TskException on error
     */
    void prepareOutputFolder() const;

    /**
     * Writes each sector run in the sector runs passed into the function
     * to one or more output files. The maximum size of any single output file 
     * will not exceed the maximum output file size passed to the constructor and 
     * each output file will contain sectors from only a single volume. 
     * @param sectorRuns Sector runs to be written to the output files
     * @param scheduleCarving Whether or not to schedule carving of files created
     * @return Throws TskException on error
     */
    void createFilesToBeCarved(SectorRuns &sectorRuns, bool scheduleCarving) const;

    /**
     * Create an output file. The name of the file will be the file name passed to the
     * constructor. Files will be distinguished by storing them in subdirectories named 
     * for the output file number.
     * @param outputFileNumber Number assigned to the file by TskImgDB::addUnallocImg()
     * @param outputFileHandle File handle the caller will use to access the file
     * @return Throws TskException on error
     */
    void createOutputFile(int outputFileNumber, HANDLE& outputFileHandle) const;

    /**
     * Create a folder. If the specified folder already exists, delete it first.
     * @param path Path of the folder to be created.
     * @return Throws TskException on error
     */
    bool createFolder(const std::wstring &path) const;

    /**
     * Stores a mapping of some sectors written to the output file to the corresponding
     * sectors in the image.
     * @param outputFileNumber Number assigned to the output file by TskImgDB::addUnallocImg()
     * @param outputFileHandle File handle used to access the output file
     * @param startingFileOffset Starting offset in the output file (in bytes) of the sector run 
     * or part of a sector run that was written to the file 
     * @param endingFileOffset Ending offset in the output file (in bytes) of the sector run 
     * or part of a sector run that was written to the file
     * @param imgVolumeID Volume Id of the volume that was the source of the sector run 
     * or part of a sector run that was written to the file
     * @param startingImageOffset Starting offset in the image (in sectors) of the sector run 
     * or part of a sector run that was written to the file  
     * @return Throws TskException on error
     */ 
    void storeOutputfileToImageMapping(int outputFileNumber, HANDLE outputFileHandle, uint64_t startingFileOffset, uint64_t endingFileOffset, int imgVolumeID, uint64_t startingImageOffset) const;

    const std::wstring m_outputFolderPath; 
    const std::wstring m_outputFileName; 
    uint64_t m_maxOutputFileSize;
    static const uint64_t SECTORS_PER_READ = 32; 
};

#endif
