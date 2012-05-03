#ifndef _TSK_COMPAREDIR_H
#define _TSK_COMPAREDIR_H

#include <set>
#include <stdlib.h>

struct ltstr
{
  bool operator()(char* s1, char* s2) const
  {
    return strcmp(s1, s2) > 0;
  }
};

class TskCompareDir : public TskAuto {
public:
    uint8_t compareDirs(TSK_OFF_T soffset, TSK_INUM_T inum, TSK_FS_TYPE_ENUM a_fstype, const TSK_TCHAR * lcl_dir);
    virtual uint8_t handleError();

private:
    std::set<char*, ltstr> m_filesInImg; 
    bool m_missDirFile;
    const TSK_TCHAR *m_lclDir;
    
    virtual TSK_RETVAL_ENUM processFile(TSK_FS_FILE * fs_file, const char *path); 
	virtual TSK_FILTER_ENUM filterVol(const TSK_VS_PART_INFO * vs_part);
    uint8_t processLclDir(const TSK_TCHAR *dir);
};

#endif
