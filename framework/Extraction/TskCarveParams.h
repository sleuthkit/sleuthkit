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
 * \file TskCarveParams.h
 * Contains default values for carving parameters used by implementations of 
 * the CarvePrep and CarveExtract interfaces.
 */
#ifndef _TSK_CARVEPARAMS_H
#define _TSK_CARVEPARAMS_H

// Poco includes
#include "Poco/Path.h"

// C/C++ Library includes
#include <string>

namespace
{
    /**
     * Default location where classes that implement the CarvePrep interface 
     * create unallocated sectors image files to be carved by classes that
     * implement the CarveExtract interface.
     */
    const std::string DEFAULT_CARVE_DIR = std::string("#OUT_DIR#") + Poco::Path::separator() + std::string("Carving");

    /**
     * Default file name given to unallocated sectors image files created by 
     * classes that implement the CarvePrep interface. The files will be 
     * written to subdirectories named using the unallocated sectors image IDs 
     * of the files.
     */
    const std::string DEFAULT_UNALLOC_SECTORS_IMG_FILE_NAME = "unalloc.bin";

    /** 
     * Default maximum size of unallocated sectors image files produced by 
     * classes that implement the CarvePrep interface. Size 0 indicates
     * breaking files on volume boundaries only.
     */
    const std::string DEFAULT_MAX_UNALLOC_SECTORS_IMG_FILE_SIZE = "0";
}

#endif
