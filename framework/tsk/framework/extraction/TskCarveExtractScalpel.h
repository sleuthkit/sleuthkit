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
 * \file TskCarveExtractScalpel.h
 * Contains the interface of the TskCarveExtractScalpel class.
 */

#ifndef _TSK_CARVEEXTRACTSCALPEL_H
#define _TSK_CARVEEXTRACTSCALPEL_H

// TSK Framework includes
#include "tsk/framework/extraction/CarveExtract.h"

// Poco includes
#include "Poco/Pipe.h"

// C/C++ library includes
#include <string>
#include <vector>

/**
 * The TskCarveExtractScalpel class implements the CarveExtract interface to 
 * carve unallocated sectors image files using Scalpel.
 */
class TSK_FRAMEWORK_API TskCarveExtractScalpel : public CarveExtract
{
public:
    TskCarveExtractScalpel(bool createUnusedSectorFiles = false)
        : m_createUnusedSectorFiles(createUnusedSectorFiles) {}

    virtual int processFile(int unallocImgId);

private:
    // Whether to generate unused sector files after carving.
    bool m_createUnusedSectorFiles;

    /**
     * Uses Scalpel to attempt carving an unallocated sectors image file.
     *
     * @param unallocImgPath The path to the unallocated sectors image file to 
     * be carved.
     * @param outputFolderPath The directory to which any carved files are
     * to be written.
     * @param stdOutFilePath The file in which output written by Scalpel to
     * standard out is to be stored.
     * @param stdErrFilePath The file in which output written by Scalpel to
     * standard err is to be stored.
     * @return Throws TskException on error.
     */
    void carveFile(const std::string &unallocImgPath, const std::string &outputFolderPath, const std::string &stdOutFilePath, const std::string &stdErrFilePath) const;

    /**
     * Bundles information concerning a carved file produced by Scalpel.
     */
    struct CarvedFile
    {
        CarvedFile(int unallocImgId, const std::string &fileName, const std::string &offsetInBytes, const std::string &lengthInBytes);
        int id;
        std::string name;
        unsigned long offset;
        unsigned long length;
    };

    /**
     * Parses a Scalpel carving results file to determine what files, if any, 
     * Scalpel carved out of an unallocated sectors image file.
     *
     * @param unallocImgId The identifier of the unallocated sectors image 
     * file that was carved.
     & @param resultsFilePath The path to the Scalpel carving results file 
     * to be parsed.
     * @return A possibly empty vector of CarvedFile objects representing 
     * carved files. Throws TskException on error.
     */
    std::vector<CarvedFile> parseCarvingResultsFile(int unallocImgId, const std::string &resultsFilePath) const;

    /**
     * Writes the unallocated sectors mapping of a set of carved files to the 
     * image database and saves copies of the carved files.
     *
     * @param outputFolderPath The directory to which any carved files were
     * written.
     * @param carvedFiles A vector of CarvedFile objects representing carved
     * files.
     * @return Throws TskException on error.
     */
    void processCarvedFiles(const std::string &outputFolderPath, const std::vector<CarvedFile> &carvedFiles) const;
};

#endif
