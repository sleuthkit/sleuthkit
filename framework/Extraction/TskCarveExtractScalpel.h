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

#include "Extraction/CarveExtract.h"
#include <string>
#include <vector>
#include "Poco/Pipe.h"

/**
 * The TskCarveExtractScalpel class implements the CarveExtract interface to 
 * carve unallocated sectors image files using Scalpel. Instances of the class
 * use the following system properties: SCALPEL_DIR, SCALPEL_CONFIG_FILE, 
 * CARVE_PREP_DIR, CARVE_PREP_FILE_NAME, CARVE_EXTRACT_KEEP_INPUT_FILES, and 
 * CARVE_EXTRACT_KEEP_OUTPUT_FILES.
 */
class TSK_FRAMEWORK_API TskCarveExtractScalpel : public CarveExtract
{
public:
    /**
     * Default constructor.
     */
    TskCarveExtractScalpel() : configState(NOT_ATTEMPTED), deleteInputFiles(true), deleteOutputFiles(true) {}

    virtual int processFile(int unallocImgId);

private:
    /**
     * Enumeration of the three possible states the TskCarveExtractScalpel can
     * be in when processFile is called.
     */
    enum CONFIG_STATE
    {
        NOT_ATTEMPTED,
        FAILED,
        SUCCEEDED
    };

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
     * Configures the TskCarveExtractScalpel using system  properties and sets
     * the state of the object to one of the states defined by the 
     * TskCarveExtractScalpel::CONFIG_STATE enum.
     *
     * @return Throws TskException on error.
     */
    void configure();

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
    std::vector<CarvedFile> TskCarveExtractScalpel::parseCarvingResultsFile(int unallocImgId, const std::string &resultsFilePath) const;

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

    /**
     * The file name of the Scalpel executable.
     */
    static const std::string SCALPEL_EXE_FILE_NAME;

    /**
     * The file name of the default Scalpel configuration file.
     */
    static const std::string SCALPEL_DEFAULT_CONFIG_FILE_NAME;

    /**
     * The file name of the Scalpel results file.
     */
    static const std::string SCALPEL_RESULTS_FILE_NAME;

    /**
     * The file name used for the file that stores what Scalpel writes to 
     * standard output.
     */
    static const std::string STD_OUT_DUMP_FILE_NAME;

    /**
     * The file name used for the file that stores what Scalpel writes to 
     * standard error.
     */
    static const std::string STD_ERR_DUMP_FILE_NAME;

    /**
     * Tracks the state of the object when processFile is called.
     */
    CONFIG_STATE configState;

    /**
     * Stores the path to the Scalpel executable, constructed using the 
     * SCALPEL_DIR system property.
     */
    std::string scalpelExePath;

    /**
     * Stores the SCALPEL_CONFIG_FILE system property.
     */
    std::string scalpelConfigFilePath;

    /**
     * Stores the CARVE_PREP_DIR system property.
     */
    std::string carvePrepOutputPath;

    /**
     * Stores the CARVE_PREP_FILE_NAME system property.
     */
    std::string carvePrepOutputFileName;

    /**
     * Stores the CARVE_EXTRACT_KEEP_INPUT_FILES system property as a boolean 
     * flag.
     */
    bool deleteInputFiles;

    /**
     * Stores the CARVE_EXTRACT_KEEP_OUTPUT_FILES system property as a boolean 
     * flag.
     */
    bool deleteOutputFiles;
};

#endif
