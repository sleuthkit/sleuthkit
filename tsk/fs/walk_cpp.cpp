#include "tsk_fs_i.h"
#include "tsk/vs/tsk_vs_i.h"

/**
* \internal
* call back function 
*/
TSK_WALK_RET_ENUM tsk_fs_block_cpp_c_cb (const TSK_FS_BLOCK *a_block, void *a_ptr)
{
    TSK_FS_BLOCK_WALK_CPP_DATA *data = (TSK_FS_BLOCK_WALK_CPP_DATA *)a_ptr;
    TskFsBlock block(a_block);
    return data->cppAction(&block, data->cPtr);
}

/**
* \internal
* call back function 
*/
TSK_WALK_RET_ENUM tsk_fs_file_cpp_c_cb (TSK_FS_FILE *a_file, TSK_OFF_T a_off, TSK_DADDR_T a_addr, char *a_buf,
                                        size_t a_len, TSK_FS_BLOCK_FLAG_ENUM a_flags, void *a_ptr)
{
    TSK_FS_FILE_WALK_CPP_DATA *data = (TSK_FS_FILE_WALK_CPP_DATA *)a_ptr;
    TskFsFile fsFile(a_file);
    return data->cppAction(&fsFile,a_off,a_addr,a_buf,a_len,a_flags,data->cPtr);
}

/**
* \internal
* call back function 
*/
TSK_WALK_RET_ENUM tsk_fs_jblk_cpp_c_cb (TSK_FS_INFO *a_fsInfo, char *a_string,
                                        int a_num, void *a_ptr){
    TSK_FS_JBLK_WALK_CPP_DATA *data = (TSK_FS_JBLK_WALK_CPP_DATA *)a_ptr;
    TskFsInfo fsInfo(a_fsInfo);
    return data->cppAction(&fsInfo, a_string, a_num, data->cPtr);                                         
}

/**
* \internal
* call back function 
*/
TSK_WALK_RET_ENUM tsk_fs_jentry_cpp_c_cb (TSK_FS_INFO *a_fsInfo, TSK_FS_JENTRY *a_jentry,
                                          int a_num, void *a_ptr){
    TSK_FS_JENTRY_WALK_CPP_DATA *data = (TSK_FS_JENTRY_WALK_CPP_DATA *)a_ptr;
    TskFsInfo fsInfo(a_fsInfo);
    TskFsJEntry fsJEntry(a_jentry);
    return data->cppAction(&fsInfo, &fsJEntry, a_num, data->cPtr);
}

/**
* \internal
* call back function 
*/
TSK_WALK_RET_ENUM tsk_fs_meta_walk_cpp_c_cb (TSK_FS_FILE *a_file, void *a_ptr){
    TSK_FS_META_WALK_CPP_DATA *data = (TSK_FS_META_WALK_CPP_DATA *)a_ptr;
    TskFsFile fsFile(a_file);
    return data->cppAction(&fsFile, data->cPtr);
}

/**
* \internal
* call back function 
*/
TSK_WALK_RET_ENUM tsk_fs_dir_walk_cpp_c_cb (TSK_FS_FILE *a_file,  const char *a_path, void *a_ptr){
    TSK_FS_DIR_WALK_CPP_DATA *data = (TSK_FS_DIR_WALK_CPP_DATA *)a_ptr;
    TskFsFile fsFile(a_file);
    return data->cppAction(&fsFile, a_path, data->cPtr);
}

/**
* \internal
* call back function 
*/
TSK_WALK_RET_ENUM tsk_vs_part_walk_cpp_c_cb (TSK_VS_INFO *a_vs, const TSK_VS_PART_INFO * a_vs_part, void *a_ptr){
    TSK_VS_PART_WALK_CPP_DATA *data = (TSK_VS_PART_WALK_CPP_DATA *)a_ptr;
    TskVsInfo vsInfo(a_vs);
    TskVsPartInfo vsPartInfo(const_cast<TSK_VS_PART_INFO *>(a_vs_part));
    return data->cppAction(&vsInfo, &vsPartInfo, data->cPtr);
}

