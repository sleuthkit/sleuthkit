/*
** The Sleuth Kit
**
** Copyright (c) 2022 Basis Technology Corp.  All rights reserved
** Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
**
** This software is distributed under the Common Public License 1.0
**
*/

#ifndef _FILE_SYSTEM_UTILS_H_
#define _FILE_SYSTEM_UTILS_H_

#ifdef TSK_WIN32
extern int is_windows_device_path(const TSK_TCHAR * image_name);
#endif

extern TSK_OFF_T get_size_of_file_on_disk(const TSK_TCHAR * a_file, uint8_t a_is_winobj);

#endif