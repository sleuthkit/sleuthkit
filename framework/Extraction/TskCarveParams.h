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
 * Contains default values for carving parameters.
 */
#ifndef _TSK_CARVEPARAMS_H
#define _TSK_CARVEPARAMS_H

// C/C++ Library includes
#include <string>

namespace
{
    const std::string DEFAULT_CARVE_DIR = "#OUT_DIR#/Carving";
    const std::string DEFAULT_CARVE_PREP_FILE_NAME = ""; // RJCTODO
    const uint64_t DEFAULT_CARVE_PREP_MAX_FILE_SIZE = 0; // RJCTODO
}

#endif
