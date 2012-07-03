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
 * Definition of a class that implements the CarveExtract interface to carve
 * unallocated sectors image files using Scalpel. Instances of the class
 * use the following system properties: CARVE_PREP_OUTPUT_PATH and 
 * CARVE_PREP_OUTPUT_FILE_NAME.
 */

#ifndef _TSK_CARVEEXTRACTSCALPEL_H
#define _TSK_CARVEEXTRACTSCALPEL_H

// TSK framework includes
#include "Extraction/CarveExtract.h"

// System includes
#include <string>
#include <vector>

#include "Poco/Pipe.h"

/**
 * Definition of a class that implements the CarveExtract interface to carve
 * unallocated sectors image files using Scalpel. Instances of the class
 * use the following system properties: SCALPEL_DIR, SCALPEL_CONFIG_FILE_PATH, 
 * CARVE_PREP_OUTPUT_PATH, CARVE_PREP_OUTPUT_FILE_NAME, 
 * CARVE_EXTRACT_KEEP_INPUT_FILES, and CARVE_EXTRACT_KEEP_OUTPUT_FILES.
 */
class TSK_FRAMEWORK_API TskCarveExtractScalpel : public CarveExtract
{
public:
    /**
     * Default constructor.
     */
    TskCarveExtractScalpel() : configState(NOT_ATTEMPTED), deleteInputFiles(true), deleteOutputFiles(true) {}

    /**
     * Carve a specified unallocated sectors image file. 
     *
     * @param unallocImgId Id of the file to carve.
     * @returns 1 on error 0 otherwise. 
     */
    virtual int processFile(int unallocImgId);

private:
    enum CONFIG_STATE
    {
        NOT_ATTEMPTED,
        FAILED,
        SUCCEEDED
    };

    struct CarvedFile
    {
        CarvedFile(int unallocImgId, const std::string &fileName, const std::string &offsetInBytes, const std::string &lengthInBytes);
        int id;
        std::string name;
        unsigned long offset;
        unsigned long length;
    };

    void configure();
    void carveFile(const std::string &unallocImgPath, const std::string &outputFolderPath, const std::string &stdOutFilePath, const std::string &stdErrFilePath) const;
    std::vector<CarvedFile> TskCarveExtractScalpel::parseCarvingResultsFile(int unallocImgId, const std::string &resultsFilePath) const;
    void processCarvedFiles(const std::string &outputFolderPath, const std::vector<CarvedFile> &carvedFiles) const;

    static const std::string SCALPEL_EXE_FILE_NAME;
    static const std::string SCALPEL_DEFAULT_CONFIG_FILE_NAME;
    static const std::string SCALPEL_RESULTS_FILE_NAME;
    static const std::string STD_OUT_DUMP_FILE_NAME;
    static const std::string STD_ERR_DUMP_FILE_NAME;

    CONFIG_STATE configState;
    std::string scalpelExePath;
    std::string scalpelConfigFilePath;
    std::string carvePrepOutputPath;
    std::string carvePrepOutputFileName;
    bool deleteInputFiles;
    bool deleteOutputFiles;
};

#endif
