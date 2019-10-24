/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2019 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
* \file FileExtractor.cpp
* Contains C++ code that implement the File Extractor class.
*/

#include <direct.h>
#include "shlwapi.h"

#include "FileExtractor.h"
#include "ReportUtil.h"
#include "TskHelper.h"

/*
* @param createVHD If true, extract file to VHD.If false, extract to actual file
* @param cwd Current working directory
* @param directoryPath Logical imager top output directory
*/
FileExtractor::FileExtractor(bool createVHD, const std::wstring &cwd, const std::string &directoryPath) :
    m_createVHD(createVHD), m_cwd(cwd), m_rootDirectoryPath(directoryPath) {
}

/*
* Initialize a directory name per image.
* Call this method once per image at the start of analyzing a drive image.
* This method creates a directory with the subDir name to store extracted files.
*
* @param imageDirName Directory name for this image
*/
void FileExtractor::initializePerImage(const std::string &imageDirName) {
    m_dirCounter = 1; // reset for each image
    m_fileCounter = 1;
    m_imageDirName = imageDirName;
    if (!m_createVHD) {
        createDirectoryRecursively(TskHelper::toWide((std::string(m_rootDirectoryPath + getRootImageDirPrefix() + std::to_string(m_dirCounter)))));
    }
}

/**
* Extract a file. tsk_img_writer_create must have been called prior to this method.
* Exit the program if file creation failed.
*
* @param fs_file File details
* @param path Parent path of the file
* @param [out] extractedFilePath If createVHD is false, return the extract file path
* @returns TSK_RETVAL_ENUM TSK_OK if file is extracted, TSK_ERR otherwise.
*/
TSK_RETVAL_ENUM FileExtractor::extractFile(TSK_FS_FILE *fs_file, const char *path, std::string &extractedFilePath) {
    TSK_OFF_T offset = 0;
    size_t bufferLen = 16 * 1024;
    char buffer[16 * 1024];
    FILE *file = (FILE *)NULL;
    std::string filename;
    TSK_RETVAL_ENUM result = TSK_OK;

    if (fs_file->meta == NULL) {
        // Prevent creating an empty file, tsk_fs_file_read will fail when meta is null.
        return TSK_ERR;
    }

    if (!m_createVHD) {
        if (m_fileCounter > maxFilesInDir) {
            FileExtractor::generateDirForFiles();
            m_fileCounter = 1;
        }
        extractedFilePath = getRootImageDirPrefix() + std::to_string(m_dirCounter) + "/f-" + std::to_string(m_fileCounter) + (char *)PathFindExtensionA(fs_file->name->name);
        m_fileCounter++;
        filename = m_rootDirectoryPath + "/" + extractedFilePath;
        file = _wfopen(TskHelper::toWide(filename).c_str(), L"wb");
        if (file == NULL) {
            // This can happen when the extension is invalid under Windows. Try again with no extension.
            ReportUtil::consoleOutput(stderr, "ERROR: extractFile failed for %s, reason: %s\nTrying again with fixed file extension\n", filename.c_str(), _strerror(NULL));
            extractedFilePath = getRootImageDirPrefix() + std::to_string(m_dirCounter) + "/f-" + std::to_string(m_fileCounter - 1);
            filename = m_rootDirectoryPath + "/" + extractedFilePath;
            file = _wfopen(TskHelper::toWide(filename).c_str(), L"wb");
            if (file == NULL) {
                ReportUtil::consoleOutput(stderr, "ERROR: extractFile failed for %s, reason: %s\n", filename.c_str(), _strerror(NULL));
                ReportUtil::handleExit(1);
            }
        }
        TskHelper::replaceAll(extractedFilePath, "/", "\\");
    }

    while (true) {
        ssize_t bytesRead = tsk_fs_file_read(fs_file, offset, buffer, bufferLen, TSK_FS_FILE_READ_FLAG_NONE);
        if (bytesRead == -1) {
            if (fs_file->meta) {
                if (fs_file->meta->size == 0) {
                    if (fs_file->meta->addr != 0) {
                        // ts_fs_file_read returns -1 with empty files, don't report it.
                        result = TSK_OK;
                    } else {
                        // if addr is 0, the drive maybe disconnected, extraction failed.
                        ReportUtil::printDebug("extractFile: tsk_fs_file_read returns -1 filename=%s\toffset=%" PRIxOFF "\n", fs_file->name->name, offset);
                        ReportUtil::consoleOutput(stderr, "ERROR: Failed to extract file, filename=%s\tpath=%s\n", fs_file->name->name, path);
                        result = TSK_ERR;
                    }
                    break;
                }
                else if (fs_file->meta->flags & TSK_FS_NAME_FLAG_UNALLOC) {
                    // don't report it
                    result = TSK_ERR;
                    break;
                }
                else {
                    ReportUtil::printDebug("extractFile: tsk_fs_file_read returns -1 filename=%s\toffset=%" PRIxOFF "\n", fs_file->name->name, offset);
                    ReportUtil::consoleOutput(stderr, "ERROR: Failed to extract file, filename=%s\tpath=%s\n", fs_file->name->name, path);
                    result = TSK_ERR;
                    break;
                }
            }
            else { // meta is NULL
                // don't report it
                result = TSK_ERR;
                break;
            }
        }
        else if (bytesRead == 0) {
            result = TSK_ERR;
            break;
        }
        if (!m_createVHD && file) {
            size_t bytesWritten = fwrite((const void *)buffer, sizeof(char), bytesRead, file);
            if (bytesWritten != bytesRead) {
                ReportUtil::consoleOutput(stderr, "ERROR: Failed to write file: %s reason: %s\n", filename.c_str(), _strerror(NULL));
                result = TSK_ERR;
                break; // don't read anymore once we have a write failure
            }
        }
        offset += bytesRead;
        if (offset >= fs_file->meta->size) {
            break;
        }
    }

    if (!m_createVHD && file) {
        fclose(file);
    }

    return result;
}

/*
* Return a string for the /root/<m_imageDirName>/d- prefix
* @return The prefix string
*/
std::string FileExtractor::getRootImageDirPrefix() const {
    return std::string("/root/" + m_imageDirName + "/d-");
}

/*
* Create a directory to store extracted files, using an incremented directory counter.
* The directory name has a "d-<nnn>" format where <nnn> is the directory counter.
* Exit the program if directory creation failed.
*
*/
void FileExtractor::generateDirForFiles() {
    m_dirCounter++;
    std::string newDir = std::string(m_rootDirectoryPath + getRootImageDirPrefix() + std::to_string(m_dirCounter));
    if (_mkdir(newDir.c_str()) != 0) {
        if (errno != EEXIST) {
            ReportUtil::consoleOutput(stderr, "ERROR: mkdir failed for %s\n", newDir.c_str());
            ReportUtil::handleExit(1);
        }
    }
}

/**
* Test if directory exists.
*
* @param dirName directory name
* @return bool true if directory exist, false otherwise.
*/
bool FileExtractor::dirExists(const std::wstring &dirName) {
    DWORD ftyp = GetFileAttributesW(dirName.c_str());
    if (ftyp == INVALID_FILE_ATTRIBUTES)
        return false;  //something is wrong with your path!

    if (ftyp & FILE_ATTRIBUTE_DIRECTORY)
        return true;   // this is a directory!

    return false;    // this is not a directory!
}

/**
* Recursively create directory given by path.
* Does not exit if the directory already exists.
* Exit the program if a directory creation failed.
*
* @param path directory
*/
void FileExtractor::createDirectoryRecursively(const std::wstring &path) {
    if (dirExists(path)) {
        return;
    }

    std::wstring path2 = path;
    TskHelper::replaceAll(path2, L"/", L"\\");

    size_t pos = 0;
    do
    {
        pos = path2.find_first_of(L"\\", pos + 1);
        if (CreateDirectoryW(std::wstring(L"\\\\?\\" + m_cwd + L"\\" + path2.substr(0, pos)).c_str(), NULL) == 0) {
            if (GetLastError() != ERROR_ALREADY_EXISTS) {
                ReportUtil::consoleOutput(stderr, "ERROR: Fail to create directory %s Reason: %s\n", TskHelper::toNarrow(path).c_str(),
                    ReportUtil::GetErrorStdStr(GetLastError()).c_str());
                ReportUtil::handleExit(1);
            }
        }
    } while (pos != std::string::npos);
}
