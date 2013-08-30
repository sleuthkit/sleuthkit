/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _TSK_MODULEDEV_H
#define _TSK_MODULEDEV_H

/** 
 * Include this .h file when writing a dynamic link library
 */

#include "tsk/framework/TskVersionInfo.h"
#include "tsk/framework/services/TskServices.h"
#include "tsk/framework/utilities/TskUtilities.h"
#include "tsk/framework/pipeline/TskModule.h"

#if defined(_WIN32)
#if !defined(TSK_MODULE_IMPORT)
    #define TSK_MODULE_EXPORT __declspec(dllexport)
#else
    #define TSK_MODULE_EXPORT __declspec(dllimport)
#endif
#else
    #define TSK_MODULE_EXPORT
#endif

#ifdef __cplusplus
extern "C"
{
#endif
    /**
     * Returns the compiler that the module was built with.
     */
    TSK_MODULE_EXPORT TskVersionInfo::Compiler getCompiler()
    {
        return TskVersionInfo::getCompiler();
    }

    /**
     * Returns the version of the compiler that the module was built with.
     */
    TSK_MODULE_EXPORT int getCompilerVersion()
    {
        return TskVersionInfo::getCompilerVersion();
    }

    /**
     * Returns the version of the TSK framework that the module was built against.
     */
    TSK_MODULE_EXPORT int getFrameWorkVersion()
    {
        return TskVersionInfo::getFrameworkVersion();
    }

    /**
     * Returns whether this is a debug or release build of the module.
     */
    TSK_MODULE_EXPORT TskVersionInfo::BuildType getBuildType()
    {
        return TskVersionInfo::getBuildType();
    }
#ifdef __cplusplus
}
#endif
#endif
