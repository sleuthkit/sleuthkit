/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file FileManager.cpp
 * Contains the implementation for the FileManager class.
 */

#include "FileManager.h"

FileManager::FileManager()
{
}

FileManager::~FileManager()
{
}

/**
 *
 */
File FileManager::getFile(const uint64_t fileId)
{
    // Check to see if a file named fileId exists and
    // call the relevant File constructor.

    return NULL;
}

/**
 *
 */
std::wstring FileManager::getPath(const uint64_t fileId)
{
    return std::wstring(L"");
}

/**
 *
 */
void FileManager::saveFile(const File &fileToSave, const std::wstring& path)
{
    // Make sure that the file doesn't already exist.
    // Create a new file in the location by path and using File.id() as the name
    // Call File.read() to get the file content and write to new file.
}

/**
 *
 */
void FileManager::saveFile(const File &fileToSave)
{
    // Determine what the path should be based on File.id()
    // and call saveFile(fileToSave, path)
}

/**
 *
 */
void FileManager::deleteFile(File &fileToDelete)
{
    // Determine what the path should be based on File.id(),
    // check to see if a file exists at that location and delete.
}
