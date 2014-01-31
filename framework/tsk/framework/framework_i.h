/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _TSK_OSSLIBTSK_I_H
#define _TSK_OSSLIBTSK_I_H

#include <stdlib.h>
#include <stdio.h>
#include <tsk/libtsk.h>

#define MAX_BUFF_LENGTH 1024


#if defined(TSK_WIN32) 
#if defined(TSK_EXPORTS)
    #define TSK_FRAMEWORK_API __declspec(dllexport)
#else
    #define TSK_FRAMEWORK_API __declspec(dllimport)
#endif
// non-win32
#else
    #define TSK_FRAMEWORK_API 
#endif

#if defined(_MSC_VER)
#pragma warning(disable:4251) // ... needs to have dll-interface warning
#endif

#endif
