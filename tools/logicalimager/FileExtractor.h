/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2019 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

#pragma once

#include "tsk/libtsk.h"

/**
* Defines the File Extractor
*
*/
class FileExtractor {
public:
    FileExtractor(bool createVHD, const std::wstring &cwd, const std::string &directoryPath);
    ~FileExtractor() {};
    void initializePerImage(const std::string &imageDirName);
    TSK_RETVAL_ENUM extractFile(TSK_FS_FILE *fs_file, const char *path, std::string &extractedFilePath);

private:
    FileExtractor(const FileExtractor &) = delete;

    void generateDirForFiles();
    void createDirectoryRecursively(const std::wstring &path);
    bool dirExists(const std::wstring &dirName);
    std::string getRootImageDirPrefix() const;

    bool m_createVHD;
    int m_dirCounter;
    int m_fileCounter;
    std::string m_rootDirectoryPath;
    std::string m_imageDirName;
    std::wstring m_cwd;
    const int maxFilesInDir = 1000;
};