/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2013 Basis Technology Corporation. All Rights
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

#include "TskImageFile.h"
#include "Services/TskImgDB.h"
#include "Services/Log.h"
#include "tsk3/libtsk.h"

#include <vector>
#include <map>
#include <streambuf>

#ifndef HAVE_LIBEWF
#define HAVE_LIBEWF 1
#endif

///@todo use interface idiom or pimpl idiom

namespace ewf
{
    #include "ewf.h"
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
 * @todo derive from a new base class (or none at all)? and simplify the interface
 * 
 */
class TSK_FRAMEWORK_API TskL01Extract : public TskImageFile
{
public:
    TskL01Extract();

    virtual ~TskL01Extract();

    virtual int open(const std::vector<std::wstring> &images);
    virtual int open(const TSK_TCHAR *imageFile);
    virtual int open();
    virtual void close();

    virtual std::vector<std::wstring> filenames() const { std::vector<std::wstring> dummy; return dummy; }

    virtual int getSectorData(const uint64_t sect_start, 
                              const uint64_t sect_len, 
                              char *buffer);

    virtual int getByteData(const uint64_t byte_start, 
                            const uint64_t byte_len, 
                            char *buffer);

    virtual int extractFiles();

    virtual int openFile(const uint64_t fileId);

    virtual int readFile(const int handle, 
                         const uint64_t byte_offset, 
                         const size_t byte_len, 
                         char * buffer);

    virtual int closeFile(const int handle);

private:
    struct ArchivedFile
    {
        ewf::libewf_file_entry_t * entry;
        std::string    name;
        uint64_t       size;
        ewf::uint8_t   type;
        char *dataBuf;
    };

    int openContainer();
    void traverse(ewf::libewf_file_entry_t *parent);
    const std::string getName(ewf::libewf_file_entry_t *node);
    const ewf::uint8_t getFileType(ewf::libewf_file_entry_t *node);
    const uint64_t getFileSize(ewf::libewf_file_entry_t *node);
    char * getFileData(ewf::libewf_file_entry_t *node, const size_t dataSize);
    void saveFile(const uint64_t fileId, const ArchivedFile &archivedFile);

    TskImgDB &m_db;
    TSK_IMG_INFO *m_img_info;
    ewf::IMG_EWF_INFO *m_ewfInfo;

    std::wstring m_containerFilename; 
    std::vector<ArchivedFile> m_archivedFiles;

};

#endif
