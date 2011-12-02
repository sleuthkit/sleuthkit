/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _TSK_OSSLIBTSK_I_H
#define _TSK_OSSLIBTSK_I_H

#include <stdlib.h>
#include <stdio.h>

#define MAX_BUFF_LENGTH 1024

typedef unsigned __int64 uint64_t;
typedef __int64 int64_t;
typedef unsigned __int32 uint32_t;
typedef __int32 int32_t;
typedef unsigned __int8 uint8_t;
typedef __int8 int8_t;

#if defined(_WIN32) && defined(TSK_EXPORTS)
    #define TSK_FRAMEWORK_API __declspec(dllexport)
#else
    #define TSK_FRAMEWORK_API __declspec(dllimport)
#endif

#endif
