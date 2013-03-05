/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2013 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file
 * 
 */
#ifndef _TSK_L01EXTRACT_H
#define _TSK_L01EXTRACT_H

#include <vector>
#include <map>

#include "Poco/Path.h"

#include "TskExtract.h"
#include "Services/TskImgDB.h"
#include "Services/Log.h"
#include "tsk3/libtsk.h"


namespace ewf
{
#include <libewf.h>
}


/**
 * 
 * 
 */
class TskL01Extract : public TskArchiveExtraction::TskExtract
{
public:
    explicit TskL01Extract(const std::wstring &archivePath);
    virtual ~TskL01Extract();

    // Interface 
    virtual int extractFiles(TskFile * containerFile = NULL);

private:
    struct ArchivedFile
    {
        ewf::libewf_file_entry_t *entry;
        Poco::Path    path;
        ewf::uint64_t size;
        ewf::uint8_t  type;
        ewf::uint32_t ctime;  // Time file system file entry was changed.
        ewf::uint32_t crtime; // Time the file was created.
        ewf::uint32_t atime;  // Last access time.
        ewf::uint32_t mtime;  // Last modified time.
    };

    TskL01Extract();
    // No copying
    TskL01Extract(const TskL01Extract&);
    TskL01Extract& operator=(const TskL01Extract&);

    void                close();
    int                 openContainer();
    void                traverse(ewf::libewf_file_entry_t *parent);
    const std::string   getName(ewf::libewf_file_entry_t *node);
    const ewf::uint8_t  getFileType(ewf::libewf_file_entry_t *node);
    const ewf::uint64_t getFileSize(ewf::libewf_file_entry_t *node);
    char *              getFileData(ewf::libewf_file_entry_t *node, const size_t dataSize);
    const ewf::uint32_t getEntryChangeTime(ewf::libewf_file_entry_t *node);
    const ewf::uint32_t getCreationTime(ewf::libewf_file_entry_t *node);
    const ewf::uint32_t getAccessTime(ewf::libewf_file_entry_t *node);
    const ewf::uint32_t getModifiedTime(ewf::libewf_file_entry_t *node);
    void                saveFile(const uint64_t fileId, const ArchivedFile &archivedFile);

    std::wstring  m_archivePath;
    TskFile      *m_containerFile;
    TskImgDB     &m_db;
    TSK_IMG_INFO *m_imgInfo;
    std::vector<ArchivedFile> m_archivedFiles;
};

#endif
