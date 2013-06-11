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
#include <set>

#include "Poco/Path.h"

#include "TskExtract.h"
#include "tsk/framework/services/TskImgDB.h"
#include "tsk/framework/services/Log.h"
#include "tsk/libtsk.h"


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
    explicit TskL01Extract(const std::string &archivePath);
    virtual ~TskL01Extract();

    // Interface 
    virtual int extractFiles(TskFile * containerFile = NULL);

private:
    struct ArchivedFile
    {
        ewf::libewf_file_entry_t *entry;
        Poco::Path    path;
        uint64_t size;
        uint8_t  type;
        uint32_t ctime;  // Time file system file entry was changed.
        uint32_t crtime; // Time the file was created.
        uint32_t atime;  // Last access time.
        uint32_t mtime;  // Last modified time.
    };

    TskL01Extract();
    // No copying
    TskL01Extract(const TskL01Extract&);
    TskL01Extract& operator=(const TskL01Extract&);

    void                close();
    int                 openContainer();
    TSK_IMG_INFO *      openEwfSimple();
    void                traverse(ewf::libewf_file_entry_t *parent);
    const std::string   getName(ewf::libewf_file_entry_t *node);
    const uint8_t  getFileType(ewf::libewf_file_entry_t *node);
    const uint64_t getFileSize(ewf::libewf_file_entry_t *node);
    char *              getFileData(ewf::libewf_file_entry_t *node, const size_t dataSize);
    const uint32_t getEntryChangeTime(ewf::libewf_file_entry_t *node);
    const uint32_t getCreationTime(ewf::libewf_file_entry_t *node);
    const uint32_t getAccessTime(ewf::libewf_file_entry_t *node);
    const uint32_t getModifiedTime(ewf::libewf_file_entry_t *node);
    int                 saveFile(const uint64_t fileId, const ArchivedFile &archivedFile);
    void                scheduleFiles();

    std::string  m_archivePath;
    TskFile      *m_containerFile;
    TskImgDB     &m_db;
    TSK_IMG_INFO *m_imgInfo;
    std::vector<ArchivedFile> m_archivedFiles;
    std::set<uint64_t> m_fileIdsToSchedule;
};

#endif
