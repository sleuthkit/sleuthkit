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
#include "TskImageFile.h"
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
class TskL01Extract : public TskExtract
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
        Poco::Path     path;
        uint64_t       size;
        ewf::uint8_t   type;
    };

    TskL01Extract();
    // No copying
    TskL01Extract(const TskL01Extract&);
    TskL01Extract& operator=(const TskL01Extract&);

    void               close();
    int                openContainer();
    void               traverse(ewf::libewf_file_entry_t *parent);
    const std::string  getName(ewf::libewf_file_entry_t *node);
    const ewf::uint8_t getFileType(ewf::libewf_file_entry_t *node);
    const uint64_t     getFileSize(ewf::libewf_file_entry_t *node);
    char *             getFileData(ewf::libewf_file_entry_t *node, const size_t dataSize);
    void               saveFile(const uint64_t fileId, const ArchivedFile &archivedFile);

    std::wstring  m_archivePath;
    TskFile      *m_parentFile;
    TskImgDB     &m_db;
    TSK_IMG_INFO *m_imgInfo;
    std::vector<ArchivedFile> m_archivedFiles;
};

#endif
