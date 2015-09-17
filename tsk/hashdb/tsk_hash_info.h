/*
* The Sleuth Kit
*
* Brian Carrier [carrier <at> sleuthkit [dot] org]
* Copyright (c) 2003-2013 Brian Carrier.  All rights reserved
*/

/**
* \file tsk_hash_info.h
*/

/**
* \defgroup hashdblib C Hash Database Functions
* \defgroup hashdblib_cpp C++ Hash Database Classes
*/


#ifndef _TSK_SQLITE_INDEX_H
#define _TSK_SQLITE_INDEX_H

#include <string>
#include <vector>

struct TskHashInfo
{
    int64_t id;
    std::string hashMd5;
    std::string hashSha1;
    std::string hashSha2_256;
    std::vector<std::string> fileNames;
    std::vector<std::string> comments; 
};

#endif
