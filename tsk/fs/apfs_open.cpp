/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2019-2020 Brian Carrier.  All Rights reserved
 * Copyright (c) 2018-2019 BlackBag Technologies.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */
#include "../libtsk.h"

#include "apfs_compat.hpp"
#include "../img/pool.hpp"
#include "tsk_fs_i.h"

TSK_FS_INFO* apfs_open_auto_detect(TSK_IMG_INFO * img_info, TSK_OFF_T offset,
    TSK_FS_TYPE_ENUM fstype, const char* a_pass, uint8_t test) {

    return apfs_open(img_info, offset, fstype, a_pass);
}

/*
 * Get APFS password from environment variable.
 */
char* getEnvPassword(TSK_IMG_INFO * m_img_info) {
	// get the image name from path
	TSK_TCHAR * name = TSTRRCHR(m_img_info->images[0], '\\');
	if (name == NULL) {
		name = TSTRRCHR(m_img_info->images[0], '/');
	}
	if (name == NULL) {
		name = m_img_info->images[0];
	}
	else {
		name += 1;
	}
	
	char passkey[1024];
	memset(passkey, '\0', sizeof(char) * 1024);

#ifdef TSK_WIN32
	wcstombs(passkey, name, 1024 - 10);
#else
	strncpy(passkey, name, 1024 - 10);
#endif

	strcat(passkey, "_PASSWORD");

	char* password = getenv(passkey);
	if (password == NULL) {
		password = "";
	}

	return password;
}

TSK_FS_INFO* apfs_open(TSK_IMG_INFO * img_info, TSK_OFF_T offset,
                       TSK_FS_TYPE_ENUM fstype, const char* pass) {
  tsk_error_reset();

  if (img_info->itype != TSK_IMG_TYPE_POOL) {
      tsk_error_reset();
      tsk_error_set_errno(TSK_ERR_FS_ARG);
      tsk_error_set_errstr("tsk_apfs_open: Not a pool image");
      return nullptr;
  }
  IMG_POOL_INFO *pool_img = (IMG_POOL_INFO*)img_info; 

  if (pool_img->pool_info == nullptr) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_ARG);
    tsk_error_set_errstr("tsk_apfs_open: Null pool_info");
    return nullptr;
  }

  if (fstype != TSK_FS_TYPE_APFS) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_ARG);
    tsk_error_set_errstr("tsk_apfs_open: invalid fstype");
    return nullptr;
  }

  if (pass == NULL || strlen(pass) == 0) {
	  pass = getEnvPassword(img_info);
  }

  try {
    auto fs = new APFSFSCompat(img_info, pool_img->pool_info, pool_img->pvol_block, pass);
    return &fs->fs_info();
  } catch (std::runtime_error& e) {
    tsk_error_set_errno(TSK_ERR_FS_GENFS);
    tsk_error_set_errstr("tsk_apfs_open: %s", e.what());
    return nullptr;
  }
}
