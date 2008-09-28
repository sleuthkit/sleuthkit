
#ifndef _DISK_IDE_H
#define _DISK_IDE_H

#ifdef __cplusplus
extern "C" {
#endif

// not all of these are defined in previous Linux includes
#ifndef IDE_DRIVE_TASK_NO_DATA
#define IDE_DRIVE_TASK_NO_DATA 0
#endif

#ifndef WIN_IDENTIFY
#define WIN_IDENTIFY 0xEC
#endif

#ifndef WIN_PIDENTIFY
#define WIN_PIDENTIFY 0xA1
#endif

#ifndef WIN_READ_NATIVE_MAX
#define WIN_READ_NATIVE_MAX 0xF8
#endif

#ifndef WIN_READ_NATIVE_MAX_EXT
#define WIN_READ_NATIVE_MAX_EXT 0x27
#endif

#ifndef HDIO_DRIVE_CMD
#define HDIO_DRIVE_CMD 0x031F
#endif

#define DISK_HAS_48_SUPPORT	0x01
#define DISK_HAS_HPA_SUPPORT 0x02
#define DISK_HAS_REMOVABLE_SUPPORT	0x04

typedef struct {
    uint64_t native_max;    ///< the actual maximum sector
    uint64_t user_max;      ///< The maximum user sector (before HPA)
	uint8_t	flags;
    int fd;
} DISK_INFO;


DISK_INFO * device_open (int fd);
void set_max (int fd, uint64_t addr);


// from include/linux/ide.h

#ifndef IDE_COMMAND_OFFSET
#define IDE_COMMAND_OFFSET 7
#endif

#ifndef IDE_STATUS_OFFSET
#define IDE_STATUS_OFFSET 7
#endif

#ifndef IDE_SELECT_OFFSET
#define IDE_SELECT_OFFSET 6
#endif

#ifndef IDE_HCYL_OFFSET
#define IDE_HCYL_OFFSET 5
#endif

#ifndef IDE_LCYL_OFFSET
#define IDE_LCYL_OFFSET 4
#endif

#ifndef IDE_SECTOR_OFFSET
#define IDE_SECTOR_OFFSET 3
#endif

#ifdef __cplusplus
}
#endif

#endif
