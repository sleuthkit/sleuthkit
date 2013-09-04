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
#include <memory>

#include "Poco/SharedPtr.h"
#include "Poco/Path.h"
#include "Poco/File.h"
#include "Poco/FileStream.h"
#include "Poco/MemoryStream.h"

// Framework includes
#include "tsk/framework/framework_i.h" // to get TSK_FRAMEWORK_API
#include "TskL01Extract.h"
#include "tsk/framework/services/TskServices.h"
#include "tsk/framework/utilities/TskUtilities.h"
#include "tsk/base/tsk_base_i.h"
#include "tsk/img/tsk_img_i.h"

#ifndef HAVE_LIBEWF
#define HAVE_LIBEWF 1
#endif

namespace ewf
{
    #include "tsk/img/ewf.h"
}

namespace
{
    static const unsigned int ExtractChunkSize = 65536;

    // This is needed in order to use Poco::SharedPtr on arrays
    // and have them properly delete.
    template <class C>
    class ArrayReleasePolicy
    {
    public:
        static void release(C* pObj)
        /// Delete the object.
        /// Note that pObj can be 0.
        {
            delete [] pObj;
        }
    };

    // Copied from tsk3/img/ewf.c
    void ewf_image_close(TSK_IMG_INFO * img_info)
    {
        int i;
        ewf::IMG_EWF_INFO *ewf_info = (ewf::IMG_EWF_INFO *) img_info;

        ewf::libewf_handle_close(ewf_info->handle, NULL);
        ewf::libewf_handle_free(&(ewf_info->handle), NULL);

        // this stuff crashes if we used glob. v2 of the API has a free method.
        // not clear from the docs what we should do in v1...
        // @@@ Probably a memory leak in v1 unless libewf_close deals with it
        if (ewf_info->used_ewf_glob == 0) {
            for (i = 0; i < ewf_info->num_imgs; i++) {
                free(ewf_info->images[i]);
            }
            free(ewf_info->images);
        }

        tsk_deinit_lock(&(ewf_info->read_lock));
        free(img_info);
    }

    // Function to plug in as func ptr to TSK_IMG_INFO structure.
    ssize_t null_read(TSK_IMG_INFO * img_info, TSK_OFF_T offset, char *buf, size_t len)
    {
        // Do nothing.
        return 0;
    }

    // Function to plug in as func ptr to TSK_IMG_INFO structure.
    void null_imgstat(TSK_IMG_INFO * img_info, FILE * hFile)
    {
        // Do nothing.
    }

}

TskL01Extract::TskL01Extract(const std::string &archivePath) :
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
        m_containerFile = containerFile;

        if (m_archivePath.empty())
        {
            throw TskException(MSG_PREFIX + "No path to archive provided.");
        }

        std::string L01Path = m_archivePath;
        if (m_containerFile != NULL)
        {
            L01Path = m_containerFile->getPath();
        }

        //m_db.addImageInfo((int)m_img_info->itype, m_img_info->sector_size);
        m_db.addImageName(L01Path.c_str());

        if (openContainer() != 0)
        {
            return -1;
        }

        if (m_imgInfo == NULL)
        {
            throw TskException(MSG_PREFIX +"Images not open yet");
        }

		// Create a map of directory names to file ids to use to 
		// associate files/directories with the correct parent.
		std::map<std::string, uint64_t> directoryMap;

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
            if (path.depth() == 0 || (path.isDirectory() && path.depth() == 1))
            {
                // This file or directory lives at the root so our parent id
                // is the containing file id (if a containing file was provided).
                if (m_containerFile != NULL)
                {
                    parentId = m_containerFile->getId();
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
            if (m_containerFile != NULL)
            {
                fullpath.append(m_containerFile->getFullPath());
            }
            fullpath.append("\\");
            fullpath.append(path.toString());

            uint64_t fileId;
            if (m_db.addDerivedFileInfo(name,
                parentId,
                path.isDirectory(),
                it->size,
                details.str(), 
                static_cast<int>(it->ctime),
                static_cast<int>(it->crtime),
                static_cast<int>(it->atime),
                static_cast<int>(it->mtime),
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
                if (saveFile(fileId, *it) == 0)
                {
                    m_db.updateFileStatus(fileId, TskImgDB::IMGDB_FILES_STATUS_READY_FOR_ANALYSIS);
                    m_fileIdsToSchedule.insert(fileId);
                }
            }
        }

        // Schedule files for analysis
        scheduleFiles();
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

        //m_imgInfo = tsk_img_open_sing(m_archivePath.c_str(), TSK_IMG_TYPE_EWF_EWF, 512);
        m_imgInfo = openEwfSimple();
        if (m_imgInfo == NULL) 
        {
            std::stringstream logMessage;
            logMessage << "Error with tsk_img_open_sing: " << tsk_error_get() << std::endl;
            throw TskException(logMessage.str());
        }

        /// TSK stores different struct objs to the same pointer
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
            uint8_t nameString[512];
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


/**
    Originally we used tsk_img_open_sing(), but that leads to calling ewf_open(),
    which in turn will fail if the L01 file has an incorrect filename extension.
    This function is a simpler version of ewf_open() which will not fail if the
    filename extension is wrong.
*/
TSK_IMG_INFO * TskL01Extract::openEwfSimple()
{
    const int a_num_img = 1;
    unsigned int a_ssize = 512;
    int result = 0;
    TSK_IMG_INFO *img_info = NULL;
    ewf::libewf_error_t *ewfError = NULL;
    ewf::IMG_EWF_INFO *ewf_info = NULL;

    try
    {
        // Make an absolute path (if it's relative) so that libewf doesn't cause 
        // an error when it tries to make it absolute.
        Poco::Path tempPath(m_archivePath);
        tempPath.makeAbsolute();
        
        const TSK_TCHAR * ewfArchivePath;
        
    #if defined( TSK_WIN32 )
        std::wstring utf16Path = TskUtilities::toUTF16(tempPath.toString());
        ewfArchivePath = utf16Path.c_str();
    #else
        ewfArchivePath = tempPath.toString().c_str();
    #endif
    
        if ((ewf_info = (ewf::IMG_EWF_INFO *) tsk_img_malloc(sizeof(ewf::IMG_EWF_INFO))) == NULL)
        {
            throw TskException("tsk_img_malloc");
        }
        img_info = (TSK_IMG_INFO *) ewf_info;

        if (ewf::libewf_handle_initialize(&(ewf_info->handle), &ewfError) != 1)
        {
            throw TskException("libewf_handle_initialize");
        }

        //int i;
        ewf_info->num_imgs = a_num_img;
        if ((ewf_info->images = (TSK_TCHAR **) tsk_malloc(a_num_img * sizeof(TSK_TCHAR *))) == NULL)
        {
            throw TskException("tsk_malloc");
        }

        if ((ewf_info->images[0] =
            (TSK_TCHAR *) tsk_malloc((TSTRLEN(ewfArchivePath) + 1) * sizeof(TSK_TCHAR))) == NULL)
        {
            throw TskException("tsk_malloc 2");
        }
        TSTRNCPY(ewf_info->images[0], ewfArchivePath, TSTRLEN(ewfArchivePath) + 1);

        ///NOTE: libewf_handle_open_wide() will not open the file if the filename length is < 4 chars long.
        ewfError = NULL;
    #if defined( TSK_WIN32 )
        if (ewf::libewf_handle_open_wide(ewf_info->handle, (TSK_TCHAR * const *) ewf_info->images,
            ewf_info->num_imgs, ewf::LIBEWF_ACCESS_FLAG_READ, &ewfError) != 1)
    #else
        if (ewf::libewf_handle_open(ewf_info->handle,
                (char *const *) ewf_info->images,
                ewf_info->num_imgs, ewf::LIBEWF_ACCESS_FLAG_READ, &ewfError) != 1)
    #endif
        {
            throw TskException("libewf_handle_open_wide");
        }

        ewfError = NULL;
        if (ewf::libewf_handle_get_media_size(ewf_info->handle,
                (ewf::size64_t *) & (img_info->size), &ewfError) != 1)
        {
            throw TskException("libewf_handle_get_media_size");
        }

        ewfError = NULL;
        result = ewf::libewf_handle_get_utf8_hash_value_md5(ewf_info->handle,
            (uint8_t *) ewf_info->md5hash, 33, &ewfError);

        if (result == -1)
        {
            throw TskException("libewf_handle_get_utf8_hash_value_md5");
        }
        ewf_info->md5hash_isset = result;

        if (a_ssize != 0)
        {
            img_info->sector_size = a_ssize;
        }
        else
        {
            img_info->sector_size = 512;
        }

        img_info->itype   = TSK_IMG_TYPE_EWF_EWF;
        img_info->close   = ewf_image_close;
        img_info->read    = null_read;
        img_info->imgstat = null_imgstat;

        // initialize the read lock
        tsk_init_lock(&(ewf_info->read_lock));

        return img_info;
    }
    catch (TskException &ex)
    {
        std::ostringstream msg;
        msg << "openEwfSimple: TskException: " << ex.message();
        if (ewfError)
        {
            char errorString[512];
            errorString[0] = '\0';
            ewf::libewf_error_backtrace_sprint(ewfError, errorString, 512);
            msg << " - libewf error: " << errorString << std::endl;
        }
        LOGERROR(msg.str());
        free(ewf_info);
        return NULL;
    }
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
    fileInfo.ctime   = getEntryChangeTime(parent);
    fileInfo.crtime  = getCreationTime(parent);
    fileInfo.atime   = getAccessTime(parent);
    fileInfo.mtime   = getModifiedTime(parent);
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

    uint8_t nameString[512];
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

    std::string s;
    s.assign((char*)&nameString[0]);
    return s;
}


const uint8_t TskL01Extract::getFileType(ewf::libewf_file_entry_t *node)
{
    uint8_t type = 0;
    ewf::libewf_error_t *ewfError = NULL;
    if (ewf::libewf_file_entry_get_type(node, &type, &ewfError) == -1)
    {
        throw TskException("TskL01Extract::getFileType - Error with libewf_file_entry_get_utf8_name: ");
    }

    uint32_t flags = 0;
    ewfError = NULL;
    if (ewf::libewf_file_entry_get_flags(node, &flags, &ewfError) == -1)
    {
        throw TskException("TskL01Extract::getFileType - Error with libewf_file_entry_get_flags: ");
    }

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

    return fileSize;
}


const uint32_t TskL01Extract::getEntryChangeTime(ewf::libewf_file_entry_t *node)
{
    uint32_t timeValue = 0;
    ewf::libewf_error_t *ewfError = NULL;
    if (ewf::libewf_file_entry_get_entry_modification_time(node, &timeValue, &ewfError) == -1)
    {
        std::stringstream logMessage;
        char errorString[512];
        errorString[0] = '\0';
        ewf::libewf_error_backtrace_sprint(ewfError, errorString, 512);
        logMessage << "TskL01Extract::getEntryChangeTime - Error: " << errorString << std::endl;
        LOGERROR(logMessage.str());
        return 0;
    }

    return timeValue;
}

const uint32_t TskL01Extract::getCreationTime(ewf::libewf_file_entry_t *node)
{
    uint32_t timeValue = 0;
    ewf::libewf_error_t *ewfError = NULL;
    if (ewf::libewf_file_entry_get_creation_time(node, &timeValue, &ewfError) == -1)
    {
        std::stringstream logMessage;
        char errorString[512];
        errorString[0] = '\0';
        ewf::libewf_error_backtrace_sprint(ewfError, errorString, 512);
        logMessage << "TskL01Extract::getCreationTime - Error: " << errorString << std::endl;
        LOGERROR(logMessage.str());
        return 0;
    }

    return timeValue;
}


const uint32_t TskL01Extract::getAccessTime(ewf::libewf_file_entry_t *node)
{
    uint32_t timeValue = 0;
    ewf::libewf_error_t *ewfError = NULL;
    if (ewf::libewf_file_entry_get_access_time(node, &timeValue, &ewfError) == -1)
    {
        std::stringstream logMessage;
        char errorString[512];
        errorString[0] = '\0';
        ewf::libewf_error_backtrace_sprint(ewfError, errorString, 512);
        logMessage << "TskL01Extract::getAccessTime - Error: " << errorString << std::endl;
        LOGERROR(logMessage.str());
        return 0;
    }

    return timeValue;
}


const uint32_t TskL01Extract::getModifiedTime(ewf::libewf_file_entry_t *node)
{
    uint32_t timeValue = 0;
    ewf::libewf_error_t *ewfError = NULL;
    if (ewf::libewf_file_entry_get_modification_time(node, &timeValue, &ewfError) == -1)
    {
        std::stringstream logMessage;
        char errorString[512];
        errorString[0] = '\0';
        ewf::libewf_error_backtrace_sprint(ewfError, errorString, 512);
        logMessage << "TskL01Extract::getModifiedTime - Error: " << errorString << std::endl;
        LOGERROR(logMessage.str());
        return 0;
    }

    return timeValue;
}

/// Deprecated
char * TskL01Extract::getFileData(ewf::libewf_file_entry_t *node, const size_t dataSize)
{
    if (dataSize > 0)
    {
        //Poco::SharedPtr<unsigned char, Poco::ReferenceCounter, ArrayReleasePolicy> buffer(new unsigned char[dataSize]);
        char *buffer = new char[dataSize];
        ewf::libewf_error_t *ewfError = NULL;
        ssize_t bytesRead = ewf::libewf_file_entry_read_buffer(node, buffer, dataSize, &ewfError);
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

        return buffer;
    }
    return NULL;
}



/* Create an uncompressed version of the file on the local file system.
 * Note this will save zero-length files.
 */
int TskL01Extract::saveFile(const uint64_t fileId, const ArchivedFile &archivedFile)
{
    try
    {
        // If a file with this id already exists we raise an error
        std::auto_ptr<TskFile> pFile(TskServices::Instance().getFileManager().getFile(fileId));
        if (pFile.get() != NULL && pFile->exists())
        {
            std::stringstream msg;
            msg << "File id " << fileId << " already exists.";
            throw TskFileException(msg.str());
        }

        // Create a blank file
        Poco::Path destPath(TskUtilities::toUTF8(TskServices::Instance().getFileManager().getPath(fileId)));
        Poco::File destFile(destPath);
        destFile.createFile();

        // Get data from archive
        if (archivedFile.size > 0)
        {
            Poco::FileOutputStream fos(destFile.path(), std::ios::binary);

            uint64_t chunkSize = ExtractChunkSize;
            if (archivedFile.size < ExtractChunkSize)
            {
                chunkSize = archivedFile.size;
            }

            Poco::SharedPtr<char, Poco::ReferenceCounter, ArrayReleasePolicy<char> > dataBuf(new char[chunkSize]);

            uint64_t accum = 0;
            ewf::libewf_error_t *ewfError = NULL;

            // Read and save data in chunks so that we only put <= ExtractChunkSize bytes on the heap at a time
            while (accum < archivedFile.size)
            {
                ssize_t bytesRead = ewf::libewf_file_entry_read_buffer(archivedFile.entry, dataBuf, chunkSize, &ewfError);
                if (bytesRead == -1)
                {
                    std::stringstream logMessage;
                    char errorString[512];
                    errorString[0] = '\0';
                    ewf::libewf_error_backtrace_sprint(ewfError, errorString, 512);
                    logMessage << "TskL01Extract::saveFile - Error : " << errorString << std::endl;
                    LOGERROR(logMessage.str());
                    return -1;
                }
               
                fos.write(dataBuf, bytesRead);
                accum += bytesRead;
            }
            fos.close();
        }
        return 0;
    }
    catch (Poco::Exception& ex)
    {
        std::wstringstream msg;
        msg << L"TskL01Extract::saveFile - Error saving file from stream : " << ex.displayText().c_str();
        LOGERROR(msg.str());
        return -2;
    }
}

void TskL01Extract::scheduleFiles()
{
    if (m_fileIdsToSchedule.empty())
        return;

    Scheduler& scheduler = TskServices::Instance().getScheduler();

    std::set<uint64_t>::const_iterator it = m_fileIdsToSchedule.begin();
    uint64_t startId = *it, endId = *it;

    while (++it != m_fileIdsToSchedule.end())
    {
        if (*it > endId + 1)
        {
            scheduler.schedule(Scheduler::FileAnalysis, startId, endId);
            startId = endId = *it;
        }
        else
        {
            endId++;
        }
    }

    scheduler.schedule(Scheduler::FileAnalysis, startId, endId);
    m_fileIdsToSchedule.clear();
}
