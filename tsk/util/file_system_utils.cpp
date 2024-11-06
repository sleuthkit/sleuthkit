
/*
** The Sleuth Kit
**
** Copyright (c) 2022 Basis Technology Corp.  All rights reserved
** Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
**
** This software is distributed under the Common Public License 1.0
**
*/

/*
 * Common code used by the raw and logical images.
 */

#include "tsk/base/tsk_base_i.h"
#include "tsk/img/tsk_img_i.h"
#include "file_system_utils.h"

#ifdef __APPLE__
#include <sys/disk.h>
#endif

#ifdef TSK_WIN32
#include <winioctl.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#ifndef S_IFMT
#define S_IFMT __S_IFMT
#endif

#ifndef S_IFDIR
#define S_IFDIR __S_IFDIR
#endif

/**
* Test if the image is a Windows device
* @param The path to test
*
* Return 1 if the path represents a Windows device, 0 otherwise
*/
#ifdef TSK_WIN32
int is_windows_device_path(const TSK_TCHAR * image_name) {
	return (TSTRNCMP(image_name, _TSK_T("\\\\.\\"), 4) == 0);
}
#endif

/**
* Get the size in bytes of the given file.
*
* @param a_file The file to test
* @param is_winobj 1 if the file is a windows object and not a real file
*
* @return the size in bytes, or -1 on error/unknown,
*         -2 if unreadable, -3 if it's a directory.
*/
TSK_OFF_T
get_size_of_file_on_disk(const TSK_TCHAR * a_file, uint8_t a_is_winobj)
{
	TSK_OFF_T size = -1;
	struct STAT_STR sb;

	if (TSTAT(a_file, &sb) < 0) {
		if (a_is_winobj) {
			/* stat can fail for Windows objects; ignore that */
			if (tsk_verbose) {
				tsk_fprintf(stderr,
					"raw_open: ignoring stat result on Windows device %"
					PRIttocTSK "\n", a_file);
			}
		}
		else {
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_IMG_STAT);
			tsk_error_set_errstr("raw_open: image \"%" PRIttocTSK
				"\" - %s", a_file, strerror(errno));
			return -2;
		}
	}
	else if ((sb.st_mode & S_IFMT) == S_IFDIR) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_IMG_MAGIC);
		tsk_error_set_errstr("raw_open: image \"%" PRIttocTSK
			"\" - is a directory", a_file);
		return -3;
	}

#ifdef TSK_WIN32
	{
		HANDLE fd;
		DWORD dwHi, dwLo;

		if ((fd = CreateFile(a_file, FILE_READ_DATA,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			OPEN_EXISTING, 0, NULL)) ==
			INVALID_HANDLE_VALUE) {
			int lastError = (int)GetLastError();
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_IMG_OPEN);
			// print string of commonly found errors
			if (lastError == ERROR_ACCESS_DENIED) {
				tsk_error_set_errstr("raw_open: file \"%" PRIttocTSK
					"\" - access denied", a_file);
			}
			else if (lastError == ERROR_SHARING_VIOLATION) {
				tsk_error_set_errstr("raw_open: file \"%" PRIttocTSK
					"\" - sharing violation", a_file);
			}
			else if (lastError == ERROR_FILE_NOT_FOUND) {
				tsk_error_set_errstr("raw_open: file \"%" PRIttocTSK
					"\" - file not found", a_file);
			}
			else {
				tsk_error_set_errstr("raw_open: file \"%" PRIttocTSK
					"\" - (error %d)", a_file, lastError);
			}
			return -2;
		}

		/* We need different techniques to determine the size of Windows physical
		* devices versus normal files */
		if (a_is_winobj == 0) {
			dwLo = GetFileSize(fd, &dwHi);
			if (dwLo == 0xffffffff) {
				int lastError = (int)GetLastError();
				tsk_error_reset();
				tsk_error_set_errno(TSK_ERR_IMG_OPEN);
				tsk_error_set_errstr("raw_open: file \"%" PRIttocTSK
					"\" - GetFileSize: %d", a_file, lastError);
				size = -1;
			}
			else {
				size = dwLo | ((TSK_OFF_T)dwHi << 32);
			}
		}
		else {

			//use GET_PARTITION_INFO_EX prior to IOCTL_DISK_GET_DRIVE_GEOMETRY
			// to determine the physical disk size because
			//calculating it with the help of GET_DRIVE_GEOMETRY gives only
			// approximate number
			DWORD junk;

			PARTITION_INFORMATION_EX partition;
			if (FALSE == DeviceIoControl(fd,
				IOCTL_DISK_GET_PARTITION_INFO_EX,
				NULL, 0, &partition, sizeof(partition), &junk,
				(LPOVERLAPPED)NULL)) {
				DISK_GEOMETRY pdg;

				if (FALSE == DeviceIoControl(fd, IOCTL_DISK_GET_DRIVE_GEOMETRY,
					NULL, 0, &pdg, sizeof(pdg), &junk, (LPOVERLAPPED)NULL)) {
					int lastError = (int)GetLastError();
					tsk_error_reset();
					tsk_error_set_errno(TSK_ERR_IMG_OPEN);
					tsk_error_set_errstr("raw_open: file \"%" PRIttocTSK
						"\" - DeviceIoControl: %d", a_file,
						lastError);
					size = -1;
				}
				else {
					size = pdg.Cylinders.QuadPart *
						(TSK_OFF_T)pdg.TracksPerCylinder *
						(TSK_OFF_T)pdg.SectorsPerTrack *
						(TSK_OFF_T)pdg.BytesPerSector;
				}
			}
			else {
				size = partition.PartitionLength.QuadPart;
			}
		}

		CloseHandle(fd);
	}
#else

	int fd;

	if ((fd = open(a_file, O_RDONLY | O_BINARY)) < 0) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_IMG_OPEN);
		tsk_error_set_errstr("raw_open: file \"%" PRIttocTSK "\" - %s",
			a_file, strerror(errno));
		return -2;
	}

#ifdef __APPLE__
	/* OS X doesn't support SEEK_END on char devices */
	if ((sb.st_mode & S_IFMT) != S_IFCHR) {
		size = lseek(fd, 0, SEEK_END);
	}

	if (size <= 0) {
		int blkSize;
		long long blkCnt;

		if (ioctl(fd, DKIOCGETBLOCKSIZE, &blkSize) >= 0) {
			if (ioctl(fd, DKIOCGETBLOCKCOUNT, &blkCnt) >= 0) {
				size = blkCnt * (long long)blkSize;
			}
		}
	}
#else
	/* We don't use the stat output because it doesn't work on raw
	* devices and such */
	size = lseek(fd, 0, SEEK_END);
#endif

	close(fd);

#endif

	return size;
}