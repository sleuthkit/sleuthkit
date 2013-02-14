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

#include "TskExtractInterface.h"
#include "TskImageFile.h"
#include "Services/TskImgDB.h"
#include "Services/Log.h"
#include "tsk3/libtsk.h"

#include <vector>
#include <map>
#include <streambuf>

namespace ewf
{
//    #include "ewf.h"
//#include <libewf/types.h>
#include <libewf.h>
}


// Since std::streambuf::pubsetbuf() has compiler dependent behavior, we
// will instead derive from it in order to set the internal buffer.
class BufStreamBuf : public std::streambuf
{
public:
    BufStreamBuf(char *gbegin, char *gend)
    {
        setg(gbegin, gbegin, gend);
    }
};


/**
 * 
 * 
 */
class TskL01Extract : public TskExtractInterface
{
public:
    TskL01Extract();
    virtual ~TskL01Extract();

    // Interface 
    virtual int extractFiles(const std::wstring &archivePath, TskFile * parent = NULL);

private:
    struct ArchivedFile
    {
        ewf::libewf_file_entry_t *entry;
        std::string    name;
        uint64_t       size;
        ewf::uint8_t   type;
        char          *dataBuf;
    };
    
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

    TskImgDB          &m_db;
    TSK_IMG_INFO      *m_img_info;
    //ewf::IMG_EWF_INFO *m_ewfInfo;

    //std::wstring m_containerFilename; 
    std::vector<ArchivedFile> m_archivedFiles;
};

#endif
