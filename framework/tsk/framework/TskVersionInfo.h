/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _TSK_VERSIONINFO_H
#define _TSK_VERSIONINFO_H

#include "tsk/base/tsk_base.h"

/** 
 * Class that allows us to determine framework version,
 * compiler version and build type (debug or release).
 */
class TskVersionInfo
{
public:
    enum BuildType
    {
        DEBUG,
        RELEASE
    };

    enum Compiler
    {
        MSVC,
        UNKNOWN
    };

    /**
     * Returns whether the component was built in debug or release mode.
     * Only applicable if built by MSVC compiler.
     */
    static BuildType getBuildType()
    {
#if defined _WIN32 && defined _DEBUG
        return DEBUG;
#else
        return RELEASE;
#endif
    }
    
    /**
     * Returned the compiler that was used to build the component.
     */
    static Compiler getCompiler()
    {
#if defined _WIN32
        return MSVC;
#else
        return UNKNOWN;
#endif
    }

    /**
     * Returns the version number of the compiler.
     * Initial implementation only supports MSVC compiler.
     */
    static int getCompilerVersion()
    {
#if defined _MSC_VER
        return _MSC_VER;
#else
        return 0;
#endif
    }

    /**
     * Returns the version of the Sleuthkit framework the component was compiled with.
     */
    static int getFrameworkVersion()
    {
        return TSK_VERSION_NUM;
    }
};

#endif
