/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _TSK_MODULEDEV_H
#define _TSK_MODULEDEV_H

/** 
 * Include this .h file when writing a dynamic link library
 */

#include "Services/TskServices.h"
#include "Utilities/TskUtilities.h"
#include "Pipeline/TskModule.h"

#if defined(_WIN32)
    #define TSK_MODULE_EXPORT __declspec(dllexport)
#else
    #define TSK_MODULE_EXPORT __declspec(dllimport)
#endif

#endif
