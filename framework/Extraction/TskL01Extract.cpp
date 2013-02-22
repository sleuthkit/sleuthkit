/*
 *
 *  The Sleuth Kit
 *
 *  Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 *  Copyright (c) 2013 Basis Technology Corporation. All Rights
 *  reserved.
 *
 *  This software is distributed under the Common Public License 1.0
 */

/**
 * \file
 * 
 */

#include <iostream>
#include <istream>
#include <sstream>
#include <algorithm>

#include "Poco/SharedPtr.h"
#include "Poco/Path.h"
#include "Poco/File.h"
#include "Poco/FileStream.h"
#include "Poco/MemoryStream.h"

// Framework includes
#include "framework_i.h" // to get TSK_FRAMEWORK_API
#include "TskL01Extract.h"
#include "Services/TskServices.h"
#include "Utilities/TskUtilities.h"
#include "tsk3/base/tsk_base_i.h"

#ifndef HAVE_LIBEWF
#define HAVE_LIBEWF 1
#endif

namespace ewf
{
    #include "ewf.h"
}


TskL01Extract::TskL01Extract(const std::wstring &archivePath) :
    m_archivePath(archivePath),
    m_db(TskServices::Instance().getImgDB()),
    m_imgInfo(NULL)
{
}

TskL01Extract::~TskL01Extract()
{
    close();
}


void TskL01Extract::close()
{
    if (m_imgInfo)
    {
        tsk_img_close(m_imgInfo);
        m_imgInfo = NULL;
    }

    m_archivePath.clear();
}

/*
 *   If containerFile is NULL, then we don't use that as a source for paths and we set the parent ID to 0.
 */
int TskL01Extract::extractFiles(TskFile * containerFile /*= NULL*/)
{
    static const std::string MSG_PREFIX = "TskL01Extract::extractFiles : ";
    
    try
    {
        m_parentFile = containerFile;

        if (m_archivePath.empty())
        {
            throw TskException(MSG_PREFIX + "No path to archive provided.");
        }

        if (openContainer() != 0)
        {
            return -1;
        }

        if (m_imgInfo == NULL)
        {
            throw TskException(MSG_PREFIX +"Images not open yet");
        }

        TskImgDB& imgDB = TskServices::Instance().getImgDB();

		// Create a map of directory names to file ids to use to 
		// associate files/directories with the correct parent.
		std::map<std::string, uint64_t> directoryMap;

#if 0
        m_db.addImageInfo((int)m_imgInfo->itype, m_imgInfo->sector_size);

        char *img_ptr = NULL;
#ifdef TSK_WIN32
        char img2[1024];
        UTF8 *ptr8;
        UTF16 *ptr16;

        ptr8 = (UTF8 *) img2;
        ptr16 = (UTF16 *) m_archivePath.c_str();

        TSKConversionResult retval =
            tsk_UTF16toUTF8_lclorder((const UTF16 **) &ptr16, (UTF16 *)
            & ptr16[wcslen(m_archivePath.c_str()) + 1], &ptr8,
            (UTF8 *) ((uintptr_t) ptr8 + 1024), TSKlenientConversion);
        if (retval != TSKconversionOK) 
        {
            throw TskException("TskL01Extract::extractFiles: Error converting image to UTF-8");
        }
        img_ptr = img2;
#else
        img_ptr = (char *) m_archivePath;
#endif

        m_db.addImageName(img_ptr);
#endif

        std::vector<ArchivedFile>::iterator it = m_archivedFiles.begin();
        for (; it != m_archivedFiles.end(); ++it)
        {
            Poco::Path path(it->path);
            Poco::Path parent = it->path.parent();
            std::string name;

            if (path.isDirectory())
            {
                name = path[path.depth() - 1];
            }
            else
            {
                name = path[path.depth()];
            }

            // Determine the parent id of the file.
            uint64_t parentId = 0;
            if (path.depth() == 0 || path.isDirectory() && path.depth() == 1)
            {
                // This file or directory lives at the root so our parent id
                // is the containing file id (if a containing file was provided).
                if (m_parentFile != NULL)
                {
                    parentId = m_parentFile->getId();
                }
            }
            else
            {
                // We are not at the root so we need to lookup the id of our
                // parent directory.
                std::map<std::string, uint64_t>::const_iterator pos;
                pos = directoryMap.find(parent.toString());

                if (pos == directoryMap.end())
                {
                    //error!
                    std::stringstream msg;
                    msg << "extractFiles: parent ID not mapped for " << it->path.toString();
                    LOGERROR(msg.str());
                }
                else
                {
                    parentId = pos->second;
                }
            }

            // Store some extra details about the derived (i.e, extracted) file.
            std::stringstream details;  ///@todo anything here?

            std::string fullpath = "";
            if (m_parentFile != NULL)
            {
                fullpath.append(m_parentFile->getFullPath());
            }
            fullpath.append("\\");
            fullpath.append(path.toString());

            ///@todo file timestamp?
            uint64_t fileId;
            if (imgDB.addDerivedFileInfo(name,
                parentId,
                path.isDirectory(),
                it->size,
                details.str(), 
                0, // ctime
                0, // crtime
                0, // atime
                0, //utc time
                fileId, fullpath) == -1) 
            {
                    std::wstringstream msg;
                    msg << L"addDerivedFileInfo failed for name="
                        << name.c_str();
                    LOGERROR(msg.str());
            }

            if (path.isDirectory())
            {
                directoryMap[path.toString()] = fileId;
            }
            else
            {
                // For file nodes, recreate file locally
                // Will save zero-length files
                saveFile(fileId, *it);
            }

            // Schedule
            imgDB.updateFileStatus(fileId, TskImgDB::IMGDB_FILES_STATUS_READY_FOR_ANALYSIS);
        }

    }
    catch (TskException &ex)
    {
        std::ostringstream msg;
        msg << MSG_PREFIX << "TskException: " << ex.message();
        LOGERROR(msg.str());
        return -1;
    }
    catch (std::exception &ex)
    {
        std::ostringstream msg;
        msg << MSG_PREFIX << "std::exception: " << ex.what();
        LOGERROR(msg.str());
        return -1;
    }
    catch (...)
    {
        LOGERROR(MSG_PREFIX + "unrecognized exception");
        return -1;
    }

    return 0; //success
}


int TskL01Extract::openContainer()
{
    static const std::string MSG_PREFIX = "TskL01Extract::openContainer : ";
    ewf::libewf_error_t *ewfError = NULL;
    try
    {
        if (m_archivePath.empty())
        {
            throw TskException("Error: archive path is empty.");
        }

        m_imgInfo = tsk_img_open_sing(m_archivePath.c_str(), TSK_IMG_TYPE_EWF_EWF, 512);
        if (m_imgInfo == NULL) 
        {
            std::stringstream logMessage;
            logMessage << "Error with tsk_img_open_sing: " << tsk_error_get() << std::endl;
            throw TskException(logMessage.str());
        }

        /// TSK stores different struct objs to the same pointer
        ///@todo does C++ <> cast work on this?
        ewf::IMG_EWF_INFO *ewfInfo = (ewf::IMG_EWF_INFO*)m_imgInfo;
        m_imgInfo = &(ewfInfo->img_info);

        ewf::libewf_file_entry_t *root = NULL;
        int ret = ewf::libewf_handle_get_root_file_entry(ewfInfo->handle, &root, &ewfError);
        if (ret == -1)
        {
            std::stringstream logMessage;
            logMessage << "Error with libewf_handle_get_root_file_entry: ";
            throw TskException(logMessage.str());
        }

        if (ret > 0)
        {
            ewf::uint8_t nameString[512];
            nameString[0] = '\0';
            ewfError = NULL;
            if (ewf::libewf_file_entry_get_utf8_name(root, nameString, 512, &ewfError) == -1)
            {
                std::stringstream logMessage;
                logMessage << "Error with libewf_file_entry_get_utf8_name: ";
                throw TskException(logMessage.str());
            }

            traverse(root);
        }
    }
    catch (TskException &ex)
    {
        std::ostringstream msg;
        msg << MSG_PREFIX << "TskException: " << ex.message();
        if (ewfError)
        {
            char errorString[512];
            errorString[0] = '\0';
            ewf::libewf_error_backtrace_sprint(ewfError, errorString, 512);
            msg << "libewf error: " << errorString << std::endl;
        }
        LOGERROR(msg.str());
        return -1;
    }
    catch (std::exception &ex)
    {
        std::ostringstream msg;
        msg << MSG_PREFIX << "std::exception: " << ex.what();
        LOGERROR(msg.str());
        return -1;
    }
    catch (...)
    {
        LOGERROR(MSG_PREFIX + "unrecognized exception");
        return -1;
    }

    return 0;   //success
}

/*
    Traverse the hierarchy inside the container
 */
void TskL01Extract::traverse(ewf::libewf_file_entry_t *parent)
{
    static Poco::Path currPath;

    TskL01Extract::ArchivedFile fileInfo;
    fileInfo.entry   = parent;
    fileInfo.type    = getFileType(parent);
    fileInfo.size    = getFileSize(parent);

    std::string name = getName(parent);

    bool saveDirectory = false;
    if ((fileInfo.type == 'd') && !name.empty())
    {
        saveDirectory = true;
    }

    if (saveDirectory)
    {
        currPath.pushDirectory(name);
        fileInfo.path = currPath;
        m_archivedFiles.push_back(fileInfo);
    }
    else if (fileInfo.type == 'f')
    {
        Poco::Path tempPath = currPath;
        tempPath.setFileName(name);
        fileInfo.path = tempPath;
        m_archivedFiles.push_back(fileInfo);
    }

    int num = 0;
    ewf::libewf_error_t *ewfError = NULL;
    ewf::libewf_file_entry_get_number_of_sub_file_entries(parent, &num, &ewfError);
    
    //std::cerr << "number of sub file entries = " << num << std::endl;

    if (num > 0)
    {
        //recurse
        for (int i=0; i < num; ++i)
        {
            ewf::libewf_file_entry_t *child = NULL;
            ewfError = NULL;
            if (ewf::libewf_file_entry_get_sub_file_entry(parent, i, &child, &ewfError) == -1)
            {
                throw TskException("TskL01Extract::traverse - Error with libewf_file_entry_get_sub_file_entry: ");
            }

            traverse(child);
        }
    }

    if (saveDirectory)
    {
        currPath.popDirectory();
    }
}


const std::string TskL01Extract::getName(ewf::libewf_file_entry_t *node)
{
    ///@todo use libewf_file_entry_get_utf8_name_size

    ewf::uint8_t nameString[512];
    nameString[0] = '\0';
    ewf::libewf_error_t *ewfError = NULL;
    if (ewf::libewf_file_entry_get_utf8_name(node, nameString, 512, &ewfError) == -1)
    {
        std::stringstream logMessage;
        char errorString[512];
        errorString[0] = '\0';
        ewf::libewf_error_backtrace_sprint(ewfError, errorString, 512);
        logMessage << "TskL01Extract::getName - Error with libewf_file_entry_get_utf8_name: " << errorString << std::endl;
        throw TskException(logMessage.str());
    }
    //std::cerr << "File name = " << nameString << std::endl;
    std::string s;
    s.assign((char*)&nameString[0]);
    return s;
}


const ewf::uint8_t TskL01Extract::getFileType(ewf::libewf_file_entry_t *node)
{
    ewf::uint8_t type = 0;
    ewf::libewf_error_t *ewfError = NULL;
    if (ewf::libewf_file_entry_get_type(node, &type, &ewfError) == -1)
    {
        throw TskException("TskL01Extract::getFileType - Error with libewf_file_entry_get_utf8_name: ");
    }

    ewf::uint32_t flags = 0;
    ewfError = NULL;
    if (ewf::libewf_file_entry_get_flags(node, &flags, &ewfError) == -1)
    {
        throw TskException("TskL01Extract::getFileType - Error with libewf_file_entry_get_flags: ");
    }

    //std::cerr << "File type = " << type << std::endl;
    //std::cerr << "File flags = " << flags << std::endl;
    return type;
}


const uint64_t TskL01Extract::getFileSize(ewf::libewf_file_entry_t *node)
{
    ewf::size64_t fileSize = 0;
    ewf::libewf_error_t *ewfError = NULL;
    if (ewf::libewf_file_entry_get_size(node, &fileSize, &ewfError) == -1)
    {
        std::stringstream logMessage;
        char errorString[512];
        errorString[0] = '\0';
        ewf::libewf_error_backtrace_sprint(ewfError, errorString, 512);
        logMessage << "TskL01Extract::getFileSize - Error with libewf_file_entry_get_utf8_name: " << errorString << std::endl;
        throw TskException(logMessage.str());
    }
    //std::cerr << "File size = " << (int)fileSize << std::endl;
    return fileSize;
}


char * TskL01Extract::getFileData(ewf::libewf_file_entry_t *node, const size_t dataSize)
{
    if (dataSize > 0)
    {
        //Poco::SharedPtr<unsigned char, Poco::ReferenceCounter, ArrayReleasePolicy> buffer(new unsigned char[dataSize]);
        char *buffer = new char[dataSize];
        ewf::libewf_error_t *ewfError = NULL;
        ewf::ssize_t bytesRead = ewf::libewf_file_entry_read_buffer(node, buffer, dataSize, &ewfError);
        if (bytesRead == -1)
        {
            std::stringstream logMessage;
            char errorString[512];
            errorString[0] = '\0';
            ewf::libewf_error_backtrace_sprint(ewfError, errorString, 512);
            logMessage << "TskL01Extract::getFileData - Error : " << errorString << std::endl;
            LOGERROR(logMessage.str());
            return NULL;
        }
        //std::cerr << "Data bytes read = " << (int)bytesRead<< std::endl;

        return buffer;
    }
    return NULL;
}



/* Create an uncompressed version of the file on the local file system.
 * Note this will save zero-length files.
 */
void TskL01Extract::saveFile(const uint64_t fileId, const ArchivedFile &archivedFile)
{
    char *dataBuf = NULL;
    try
    {
        // Get data from archive
        dataBuf = getFileData(archivedFile.entry, archivedFile.size);

        if ((dataBuf != NULL) || (archivedFile.size == 0))
        {
            // Save it as a file to local filesystem
            Poco::BasicMemoryStreamBuf< char, std::char_traits<char> >  b(dataBuf, archivedFile.size);
            std::istream in(&b);
            TskServices::Instance().getFileManager().addFile(fileId, in);
        }

        delete [] dataBuf;
    }
    catch (Poco::Exception& ex)
    {
        delete [] dataBuf;
        std::wstringstream msg;
        msg << L"TskL01Extract::addFile - Error saving file from stream : " << ex.displayText().c_str();
        LOGERROR(msg.str());
        throw TskFileException("Error saving file from stream.");
    }
}

