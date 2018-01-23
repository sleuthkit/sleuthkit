/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file dos.c
 * Contains the internal functions to process DOS Partition tables
 */

#include "tsk_vs_i.h"
#include "tsk_dos.h"


/* Check the extended partition flags */
#define dos_is_ext(x)	\
	((((x) == 0x05) || ((x) == 0x0F) || ((x) == 0x85)) ? 1 : 0)

/*
 * dos_get_desc
 *
 * Return a buffer with a string description of the partition type
 *
 * From: http://www.win.tue.nl/~aeb/partitions/partition_types-1.html
 */
static char *
dos_get_desc(uint8_t ptype)
{
#define DESC_LEN 64
    char *str = tsk_malloc(DESC_LEN);
    if (str == NULL)
        return "";

    switch (ptype) {
    case 0x00:
        snprintf(str, DESC_LEN, "Empty (0x00)");
        break;
    case 0x01:
        snprintf(str, DESC_LEN, "DOS FAT12 (0x01)");
        break;
    case 0x02:
        snprintf(str, DESC_LEN, "XENIX root (0x02)");
        break;
    case 0x03:
        snprintf(str, DESC_LEN, "XENIX /usr (0x03)");
        break;
    case 0x04:
    case 0x06:
        snprintf(str, DESC_LEN, "DOS FAT16 (0x%.2x)", ptype);
        break;
    case 0x05:
        snprintf(str, DESC_LEN, "DOS Extended (0x05)");
        break;
    case 0x07:
        snprintf(str, DESC_LEN, "NTFS / exFAT (0x07)");
        break;
    case 0x08:
        snprintf(str, DESC_LEN, "AIX Boot (0x08)");
        break;
    case 0x09:
        snprintf(str, DESC_LEN, "AIX Data (0x09)");
        break;
    case 0x0a:
        snprintf(str, DESC_LEN, "OS/2 Boot Manager (0x0a)");
        break;
        /*
           case 0x0a:
           snprintf(str, DESC_LEN, "Coherent swap (0x0a)");
           break;
           case 0x0a:
           snprintf(str, DESC_LEN, "OPUS (0x0a)");
           break;
         */
    case 0x0b:
    case 0x0c:
        snprintf(str, DESC_LEN, "Win95 FAT32 (0x%.2x)", ptype);
        break;
    case 0x0e:
        snprintf(str, DESC_LEN, "Win95 FAT16 (0x0e)");
        break;
    case 0x0f:
        snprintf(str, DESC_LEN, "Win95 Extended (0x0f)");
        break;
    case 0x10:
        snprintf(str, DESC_LEN, "OPUS (0x10)");
        break;
    case 0x11:
        snprintf(str, DESC_LEN, "DOS FAT12 Hidden (0x11)");
        break;
    case 0x12:
        snprintf(str, DESC_LEN, "Hibernation (0x12)");
        break;
    case 0x14:
    case 0x16:
        snprintf(str, DESC_LEN, "DOS FAT16 Hidden (0x%.2x)", ptype);
        break;
    case 0x17:
        snprintf(str, DESC_LEN, "Hidden IFS/HPFS (0x17)");
        break;
    case 0x18:
        snprintf(str, DESC_LEN, "AST SmartSleep (0x18)");
        break;
    case 0x19:
    case 0x1b:
    case 0x1c:
        snprintf(str, DESC_LEN, "Win95 FAT32 Hidden (0x%.2x)", ptype);
        break;
    case 0x1e:
        snprintf(str, DESC_LEN, "Win95 FAT16 Hidden (0x1e)");
        break;
    case 0x20:
    case 0x22:
    case 0x7e:
    case 0x7f:
    case 0xed:
    case 0xf7:
        snprintf(str, DESC_LEN, "Unused (0x%.2x)", ptype);
        break;
    case 0x21:
    case 0x23:
    case 0x26:
    case 0x31:
    case 0x33:
    case 0x34:
    case 0x36:
    case 0x71:
    case 0x73:
    case 0x76:
    case 0xf3:
        snprintf(str, DESC_LEN, "Reserved (0x%.2x)", ptype);
        break;
    case 0x24:
        snprintf(str, DESC_LEN, "NEC DOS 3.x (0x24)");
        break;
    case 0x32:
        snprintf(str, DESC_LEN, "NOS (0x32)");
        break;
    case 0x35:
        snprintf(str, DESC_LEN, "JFS on OS/2 or eCS  (0x35)");
        break;
    case 0x38:
        snprintf(str, DESC_LEN, "THEOS v3.2 2gb (0x38)");
        break;
    case 0x39:
        snprintf(str, DESC_LEN, "THEOS v4 Spanned (0x39)");
        break;
        /*
           case 0x39:
           snprintf(str, DESC_LEN, "Plan 9 (0x39)");
           break;
         */
    case 0x3a:
        snprintf(str, DESC_LEN, "THEOS v4 4gb (0x3a)");
        break;
    case 0x3b:
        snprintf(str, DESC_LEN, "THEOS v4 Extended (0x3b)");
        break;
    case 0x3c:
        snprintf(str, DESC_LEN, "PartitionMagic Recovery (0x3c)");
        break;
    case 0x3d:
        snprintf(str, DESC_LEN, "Hidden NetWare (0x3d)");
        break;
    case 0x40:
        snprintf(str, DESC_LEN, "Venix 80286 (0x40)");
        break;
    case 0x41:
        snprintf(str, DESC_LEN,
            "Linux/MINIX (Sharing Disk with DR-DOS) (0x41)");
        break;
        /*
           case 0x41:
           snprintf(str, DESC_LEN, "Personal RISC Boot (0x41)");
           break;
           case 0x41:
           snprintf(str, DESC_LEN, "PPC PReP Boot (0x41)");
           break;
         */
    case 0x42:
        snprintf(str, DESC_LEN, "Win LVM / Secure FS (0x42)");
        break;
    case 0x43:
        snprintf(str, DESC_LEN,
            "Linux Native (Sharing Disk with DR-DOS) (0x43)");
        break;
    case 0x44:
        snprintf(str, DESC_LEN, "GoBack (0x44)");
        break;
    case 0x45:
        snprintf(str, DESC_LEN, "Boot-US Boot Manager (0x45)");
        break;
        /*
           case 0x45:
           snprintf(str, DESC_LEN, "Priam (0x45)");
           break;
           case 0x45:
           snprintf(str, DESC_LEN, "EUMEL/Elan  (0x45)");
           break;
         */
    case 0x46:
        snprintf(str, DESC_LEN, "EUMEL/Elan  (0x46)");
        break;
    case 0x47:
        snprintf(str, DESC_LEN, "EUMEL/Elan  (0x47)");
        break;
    case 0x48:
        snprintf(str, DESC_LEN, "EUMEL/Elan  (0x48)");
        break;
    case 0x4a:
        snprintf(str, DESC_LEN,
            "Mark Aitchison's ALFS/THIN Lightweight Filesystem (0x4a)");
        break;
        /*case 0x4a:
           snprintf(str, DESC_LEN, "AdaOS Aquila (0x4a)");
           break; */
    case 0x4c:
        snprintf(str, DESC_LEN, "Oberon (0x4c)");
        break;
    case 0x4d:
    case 0x4e:
    case 0x4f:
        snprintf(str, DESC_LEN, "QNX 4.x (0x%.2x)", ptype);
        break;
        /*case 0x4f:
           snprintf(str, DESC_LEN, "Oberon (0x4f)");
           break; */
        /*case 0x52:
           snprintf(str, DESC_LEN, "CP/M (0x52)");
           break; */
    case 0x50:
    case 0x51:
    case 0x53:
    case 0x54:
        snprintf(str, DESC_LEN, "OnTrack Disk Manager (0x%.2x)", ptype);
        break;
    case 0x52:
        snprintf(str, DESC_LEN, "Microport SysV/AT (0x52)");
        break;
    case 0x55:
        snprintf(str, DESC_LEN, "EZ-Drive (0x55)");
        break;
    case 0x56:
        snprintf(str, DESC_LEN,
            "AT&T MS-DOS 3.x Logically Sectored FAT (0x56)");
        break;
        /*case 0x56:
           snprintf(str, DESC_LEN, "Golden Bow VFeature Partitioned Volume (0x56)");
           break; */
        /*case 0x56:
           snprintf(str, DESC_LEN, "DM Converted to EZ-BIOS (0x56)");
           break; */
    case 0x57:
        snprintf(str, DESC_LEN, "DrivePro (0x57)");
        break;
    case 0x5c:
        snprintf(str, DESC_LEN, "Priam EDisk (0x5c)");
        break;
    case 0x61:
        snprintf(str, DESC_LEN, "SpeedStor (0x61)");
        break;
    case 0x63:
        snprintf(str, DESC_LEN, "UNIX System V (0x63)");
        break;
    case 0x64:
    case 0x65:
    case 0x66:
    case 0x67:
    case 0x68:
    case 0x69:
        snprintf(str, DESC_LEN, "Novell Netware (0x%.2x)", ptype);
        break;
    case 0x70:
        snprintf(str, DESC_LEN, "DiskSecure Multi-Boot (0x70)");
        break;
    case 0x74:
        snprintf(str, DESC_LEN, "Scramdisk (0x74)");
        break;
    case 0x75:
        snprintf(str, DESC_LEN, "IBM PC/IX (0x75)");
        break;
    case 0x77:
        snprintf(str, DESC_LEN, "VNDI (0x77)");
        break;
        /*case 0x77:
           snprintf(str, DESC_LEN, "M2FS/M2CS (0x77)");
           break; */
    case 0x78:
        snprintf(str, DESC_LEN, "XOSL FS (0x78)");
        break;
    case 0x80:
        snprintf(str, DESC_LEN, "MINIX <=v1.4a (0x80)");
        break;
    case 0x81:
        snprintf(str, DESC_LEN, "MINIX >=v1.4b, Early Linux (0x81)");
        break;
        /*case 0x81:
           snprintf(str, DESC_LEN, "Mitac Disk Manager (0x81)");
           break; */
    case 0x82:
        snprintf(str, DESC_LEN, "Linux Swap / Solaris x86 (0x82)");
        break;
    case 0x83:
        snprintf(str, DESC_LEN, "Linux (0x83)");
        break;
    case 0x84:
        snprintf(str, DESC_LEN, "Hibernation (0x84)");
        break;
    case 0x85:
        snprintf(str, DESC_LEN, "Linux Extended (0x85)");
        break;
    case 0x86:
        snprintf(str, DESC_LEN, "NTFS Volume Set (0x86)");
        break;
    case 0x87:
        snprintf(str, DESC_LEN, "NTFS Volume Set (0x87)");
        break;
    case 0x8a:
        snprintf(str, DESC_LEN, "Linux Kernel (0x8a)");
        break;
    case 0x8b:
        snprintf(str, DESC_LEN, "Legacy Fault Tolerant FAT32 (0x8b)");
        break;
    case 0x8c:
        snprintf(str, DESC_LEN,
            "Legacy Fault Tolerant FAT32 using BIOS extd INT 13h (0x8c)");
        break;
    case 0x8d:
        snprintf(str, DESC_LEN,
            "Free FDISK Hidden Primary DOS FAT12 (0x8d)");
        break;
    case 0x8e:
        snprintf(str, DESC_LEN, "Linux Logical Volume Manager (0x8e)");
        break;
    case 0x90:
        snprintf(str, DESC_LEN,
            "Free FDISK Hidden Primary DOS FAT16 (0x90)");
        break;
    case 0x91:
        snprintf(str, DESC_LEN, "Free FDISK Hidden DOS Extended (0x91)");
        break;
    case 0x92:
        snprintf(str, DESC_LEN,
            "Free FDISK Hidden Primary DOS Large FAT16 (0x92)");
        break;
    case 0x93:
        snprintf(str, DESC_LEN, "Linux Hidden (0x93)");
        break;
    case 0x94:
        snprintf(str, DESC_LEN, "Amoeba Bad Block Table (0x94)");
        break;
    case 0x95:
        snprintf(str, DESC_LEN, "MIT EXOPC (0x95)");
        break;
    case 0x97:
        snprintf(str, DESC_LEN,
            "Free FDISK Hidden Primary DOS FAT32 (0x97)");
        break;
    case 0x98:
        snprintf(str, DESC_LEN,
            "Free FDISK Hidden Primary DOS FAT32 LBA (0x98)");
        break;
        /*case 0x98:
           snprintf(str, DESC_LEN, "Datalight ROM-DOS Super-Boot (0x98)");
           break; */
    case 0x99:
        snprintf(str, DESC_LEN, "DCE376 Logical Drive (0x99)");
        break;
    case 0x9a:
        snprintf(str, DESC_LEN,
            "Free FDISK Hidden Primary DOS FAT16 LBA (0x9a)");
        break;
    case 0x9b:
        snprintf(str, DESC_LEN,
            "Free FDISK Hidden DOS Extended LBA (0x9b)");
        break;
    case 0x9f:
        snprintf(str, DESC_LEN, "BSD/OS (0x9f)");
        break;
    case 0xa0:
    case 0xa1:
        snprintf(str, DESC_LEN, "Hibernation (0x%.2x)", ptype);
        break;
    case 0xa3:
        snprintf(str, DESC_LEN,
            "HP Volume Expansion (SpeedStor Variant) (0xa3)");
        break;
    case 0xa4:
        snprintf(str, DESC_LEN,
            "HP Volume Expansion (SpeedStor Variant) (0xa4)");
        break;
    case 0xa5:
        snprintf(str, DESC_LEN, "BSD/386, 386BSD, NetBSD, FreeBSD (0xa5)");
        break;
    case 0xa6:
        snprintf(str, DESC_LEN, "OpenBSD (0xa6)");
        break;
    case 0xa7:
        snprintf(str, DESC_LEN, "NeXTSTEP (0xa7)");
        break;
    case 0xa8:
        snprintf(str, DESC_LEN, "Mac OS X (0xa8)");
        break;
    case 0xa9:
        snprintf(str, DESC_LEN, "NetBSD (0xa9)");
        break;
    case 0xaa:
        snprintf(str, DESC_LEN, "Olivetti Fat 12 1.44MB Service (0xaa)");
        break;
    case 0xab:
        snprintf(str, DESC_LEN, "Mac OS X Boot Partition (0xab)");
        break;
    case 0xae:
        snprintf(str, DESC_LEN, "ShagOS Filesystem (0xae)");
        break;
    case 0xaf:
        snprintf(str, DESC_LEN, "Mac OS X HFS (0xaf)");
        break;
    case 0xb0:
        snprintf(str, DESC_LEN, "BootStar Dummy (0xb0)");
        break;
    case 0xb1:
        snprintf(str, DESC_LEN,
            "HP Volume Expansion (SpeedStor Variant) (0xb1)");
        break;
    case 0xb3:
        snprintf(str, DESC_LEN,
            "HP Volume Expansion (SpeedStor Variant) (0xb3)");
        break;
    case 0xb4:
        snprintf(str, DESC_LEN,
            "HP Volume Expansion (SpeedStor Variant) (0xb4)");
        break;
    case 0xb6:
        snprintf(str, DESC_LEN,
            "Corrupted Windows NT Mirror Set Master FAT16 (0xb6)");
        break;
        /*case 0xb6:
           snprintf(str, DESC_LEN, "HP Volume Expansion (SpeedStor Variant) (0xb6)");
           break; */
    case 0xb7:
        snprintf(str, DESC_LEN, "BSDI (0xb7)");
        break;
    case 0xb8:
        snprintf(str, DESC_LEN, "BSDI Swap (0xb8)");
        break;
    case 0xbb:
        snprintf(str, DESC_LEN, "Boot Wizard Hidden (0xbb)");
        break;
    case 0xbe:
        snprintf(str, DESC_LEN, "Solaris 8 Boot (0xbe)");
        break;
    case 0xc0:
        snprintf(str, DESC_LEN, "DR-DOS Secured (0xc0)");
        break;
        /*case 0xc0:
           snprintf(str, DESC_LEN, "CTOS (0xc0)");
           break; */
        /*case 0xc0:
           snprintf(str, DESC_LEN, "REAL/32 Secure Small (0xc0)");
           break; */
        /*case 0xc0:
           snprintf(str, DESC_LEN, "NTFT (0xc0)");
           break; */
    case 0xc1:
        snprintf(str, DESC_LEN, "DR-DOS Secured FAT12 (0xc1)");
        break;
    case 0xc2:
        snprintf(str, DESC_LEN, "Hidden Linux (0xc2)");
        break;
    case 0xc3:
        snprintf(str, DESC_LEN, "Hidden Linux Swap (0xc3)");
        break;
    case 0xc4:
        snprintf(str, DESC_LEN, "DR-DOS Secured FAT16 <32M (0xc4)");
        break;
    case 0xc5:
        snprintf(str, DESC_LEN, "DR-DOS Secured Extended (0xc5)");
        break;
    case 0xc6:
    case 0xc7:
        snprintf(str, DESC_LEN,
            "Corrupted Windows NT Volume / Stripe Set (0x%.2x)", ptype);
        break;
    case 0xc8:
        snprintf(str, DESC_LEN, "Reserved for DR-DOS 8.0+ (0xc8)");
        break;
    case 0xc9:
        snprintf(str, DESC_LEN, "Reserved for DR-DOS 8.0+ (0xc9)");
        break;
    case 0xca:
        snprintf(str, DESC_LEN, "Reserved for DR-DOS 8.0+ (0xca)");
        break;
    case 0xcb:
        snprintf(str, DESC_LEN, "DR-DOS 7.04+ Secured FAT32 CHS (0xcb)");
        break;
    case 0xcc:
        snprintf(str, DESC_LEN, "DR-DOS 7.04+ Secured FAT32 LBA (0xcc)");
        break;
    case 0xcd:
        snprintf(str, DESC_LEN, "CTOS Memdump? (0xcd)");
        break;
    case 0xce:
        snprintf(str, DESC_LEN, "DR-DOS 7.04+ FAT16X LBA (0xce)");
        break;
    case 0xcf:
        snprintf(str, DESC_LEN, "DR-DOS 7.04+ Secured EXT DOS LBA (0xcf)");
        break;
    case 0xd0:
        snprintf(str, DESC_LEN, "Multiuser DOS Secured (0xd0)");
        break;
        /*case 0xd0:
           snprintf(str, DESC_LEN, "REAL/32 Secure Big (0xd0)");
           break; */
    case 0xd1:
        snprintf(str, DESC_LEN, "Old Multiuser DOS Secured FAT12 (0xd1)");
        break;
    case 0xd4:
        snprintf(str, DESC_LEN,
            "Old Multiuser DOS Secured FAT16 <32M (0xd4)");
        break;
    case 0xd5:
        snprintf(str, DESC_LEN,
            "Old Multiuser DOS Secured extended (0xd5)");
        break;
    case 0xd6:
        snprintf(str, DESC_LEN,
            "Old Multiuser DOS Secured FAT16 >=32M (0xd6)");
        break;
    case 0xd8:
        snprintf(str, DESC_LEN, "CP/M-86 (0xd8)");
        break;
    case 0xda:
        snprintf(str, DESC_LEN, "Non-FS Data (0xda)");
        break;
    case 0xdb:
        snprintf(str, DESC_LEN,
            "Digital Research CP/M, Concurrent CP/M, Concurrent DOS (0xdb)");
        break;
        /*case 0xdb:
           snprintf(str, DESC_LEN, "Unisys CTOS (0xdb)");
           break; */
        /*case 0xdb:
           snprintf(str, DESC_LEN, "KDG Telemetry SCPU boot (0xdb)");
           break; */
    case 0xdd:
        snprintf(str, DESC_LEN, "Hidden CTOS Memdump?  (0xdd)");
        break;
    case 0xde:
        snprintf(str, DESC_LEN, "Dell Utilities FAT (0xde)");
        break;
        /*case 0xdf:
           snprintf(str, DESC_LEN, "DG/UX Virtual Disk Manager (0xdf)");
           break; */
        /*case 0xdf:
           snprintf(str, DESC_LEN, "BootIt EMBRM (0xdf)");
           break; */
    case 0xe0:
        snprintf(str, DESC_LEN,
            "Reserved by STMicroelectronics for ST AVFS. (0xe0)");
        break;
    case 0xe1:
        snprintf(str, DESC_LEN,
            "DOS Access or SpeedStor 12-bit FAT Extended (0xe1)");
        break;
    case 0xe3:
        snprintf(str, DESC_LEN, "DOS R/O or SpeedStor (0xe3)");
        break;
    case 0xe4:
        snprintf(str, DESC_LEN,
            "SpeedStor 16-bit FAT Extended <1024 cyl. (0xe4)");
        break;
    case 0xe5:
        snprintf(str, DESC_LEN,
            "Tandy MS-DOS with Logically Sectored FAT (0xe5)");
        break;
    case 0xe6:
        snprintf(str, DESC_LEN, "Storage Dimensions SpeedStor (0xe6)");
        break;
    case 0xeb:
        snprintf(str, DESC_LEN, "BeOS BFS (0xeb)");
        break;
    case 0xee:
        snprintf(str, DESC_LEN, "GPT Safety Partition (0xee)");
        break;
    case 0xef:
        snprintf(str, DESC_LEN, "EFI File System (0xef)");
        break;
    case 0xf0:
        snprintf(str, DESC_LEN, "Linux/PA-RISC Boot Loader (0xf0)");
        break;
    case 0xf1:
        snprintf(str, DESC_LEN, "Storage Dimensions SpeedStor (0xf1)");
        break;
    case 0xf2:
        snprintf(str, DESC_LEN, "DOS 3.3+ Secondary (0xf2)");
        break;
    case 0xf4:
        snprintf(str, DESC_LEN, "SpeedStor Large (0xf4)");
        break;
        /*case 0xf4:
           snprintf(str, DESC_LEN, "Prologue Single-Volume (0xf4)");
           break; */
    case 0xf5:
        snprintf(str, DESC_LEN, "Prologue Multi-Volume (0xf5)");
        break;
    case 0xf6:
        snprintf(str, DESC_LEN, "Storage Dimensions SpeedStor (0xf6)");
        break;
    case 0xf9:
        snprintf(str, DESC_LEN, "pCache (0xf9)");
        break;
    case 0xfa:
        snprintf(str, DESC_LEN, "Bochs (0xfa)");
        break;
    case 0xfb:
        snprintf(str, DESC_LEN, "VMWare File System (0xfb)");
        break;
    case 0xfc:
        snprintf(str, DESC_LEN, "VMWare Swap (0xfc)");
        break;
    case 0xfd:
        snprintf(str, DESC_LEN, "Linux RAID (0xfd)");
        break;
    case 0xfe:
        snprintf(str, DESC_LEN,
            "Windows NT Disk Administrator Hidden (0xfe)");
        break;
        /*case 0xfe:
           snprintf(str, DESC_LEN, "SpeedStor >1024 cyl. (0xfe)");
           break; */
        /*case 0xfe:
           snprintf(str, DESC_LEN, "LANstep (0xfe)");
           break; */
        /*case 0xfe:
           snprintf(str, DESC_LEN, "IBM PS/2 IML (0xfe)");
           break; */
        /*case 0xfe:
           snprintf(str, DESC_LEN, "Old Linux Logical Volume Manager (0xfe)");
           break; */
    case 0xff:
        snprintf(str, DESC_LEN, "Xenix Bad Block Table (0xff)");
        break;
    default:
        snprintf(str, DESC_LEN, "Unknown Type (0x%.2x)", ptype);
        break;
    }

    return str;
}

/*
 * Load an extended partition table into the structure in TSK_VS_INFO.
 *
 * sect_cur: The sector where the extended table is located
 * sect_ext_base: The sector of the primary extended table (this does
 *   not change for recursive calls)
 * table: a counter that identifies the table depth
 *   (increases by 1 for each recursive call)
 *
 * For the primary extended table, sect_cur == sect_ext_base
 *
 * Return 1 on error and 0 on success
 *
 */
static uint8_t
dos_load_ext_table(TSK_VS_INFO * vs, TSK_DADDR_T sect_cur,
    TSK_DADDR_T sect_ext_base, int table)
{
    dos_sect *sect;
    char *sect_buf;
    int i;
    char *table_str;
    ssize_t cnt;
    TSK_DADDR_T max_addr = (vs->img_info->size - vs->offset) / vs->block_size;  // max sector

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "dos_load_ext: Table Sector: %" PRIuDADDR
            ", Primary Base Sector: %" PRIuDADDR "\n", sect_cur,
            sect_ext_base);

    if ((sect_buf = tsk_malloc(vs->block_size)) == NULL)
        return 1;
    sect = (dos_sect *) sect_buf;

    /* Read the partition table sector */
    cnt = tsk_vs_read_block(vs, sect_cur, sect_buf, vs->block_size);
    if (cnt != vs->block_size) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_READ);
        }
        tsk_error_set_errstr2("Extended DOS table sector %" PRIuDADDR,
            sect_cur);
        free(sect_buf);
        return 1;
    }

    /* Sanity Check */
    if (tsk_getu16(vs->endian, sect->magic) != DOS_MAGIC) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_MAGIC);
        tsk_error_set_errstr("Extended DOS partition table in sector %"
            PRIuDADDR, sect_cur);
        free(sect_buf);
        return 1;
    }

    /* Add an entry of 1 length for the table  to the internal structure */
    if ((table_str = tsk_malloc(32)) == NULL) {
        free(sect_buf);
        return 1;
    }

    snprintf(table_str, 32, "Extended Table (#%d)", table);
    if (NULL == tsk_vs_part_add(vs, (TSK_DADDR_T) sect_cur,
            (TSK_DADDR_T) 1, TSK_VS_PART_FLAG_META, table_str, table,
            -1)) {
        free(sect_buf);
        return 1;
    }

    /* Cycle through the four partitions in the table
     *
     * When another extended partition is found, it is processed
     * inside of the loop
     */
    for (i = 0; i < 4; i++) {
        dos_part *part = &sect->ptable[i];

        /* Get the starting sector and size, we currently
         * ignore CHS */
        uint32_t part_start = tsk_getu32(vs->endian, part->start_sec);
        uint32_t part_size = tsk_getu32(vs->endian, part->size_sec);

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "load_ext: %d:%d    Start: %" PRIu32 "   Size: %"
                PRIu32 "  Type: %d\n", table, i, part_start, part_size,
                part->ptype);

        /* part_start == 0 would cause infinite recursion */
        if (part_size == 0 || part_start == 0)
            continue;

        /* partitions are addressed differently
         * in extended partitions */
        if (dos_is_ext(part->ptype)) {

            TSK_VS_PART_INFO *part_info;

            /* Sanity check to prevent infinite recursion in dos_load_ext_table.
             * If we already have a partition with this starting address then
             * return an error. This will prevent any more partitions from being
             * added but will leave any existing partitions alone. */
            part_info = vs->part_list;
            while (part_info != NULL) {
                if (part_info->start == (TSK_DADDR_T)(sect_ext_base + part_start)) {
                    if (tsk_verbose)
                        tsk_fprintf(stderr,
                            "Starting sector %" PRIuDADDR
                            " of extended partition has already been used\n",
                            (TSK_DADDR_T)(sect_ext_base + part_start));
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_VS_BLK_NUM);
                    tsk_error_set_errstr
                        ("dos_load_ext_table: Loop in partition table detected");
                    return 1;
                }
                part_info = part_info->next;
            }

            /* part start is added to the start of the
             * first extended partition (the primary
             * extended partition) */

            if (NULL == tsk_vs_part_add(vs,
                    (TSK_DADDR_T) (sect_ext_base + part_start),
                    (TSK_DADDR_T) part_size, TSK_VS_PART_FLAG_META,
                    dos_get_desc(part->ptype), table, i)) {
                free(sect_buf);
                return 1;
            }

            if (sect_ext_base + part_start > max_addr) {
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "Starting sector %" PRIuDADDR
                        " of extended partition too large for image\n",
                        sect_ext_base + part_start);
            }
            /* Process the extended partition */
            else if (dos_load_ext_table(vs, sect_ext_base + part_start,
                    sect_ext_base, table + 1)) {
                free(sect_buf);
                return 1;
            }
        }

        else {
            /* part_start is added to the start of the
             * current partition for the actual
             * starting location */

            // we ignore the max_addr checks on extended partitions...

            if (NULL == tsk_vs_part_add(vs,
                    (TSK_DADDR_T) (sect_cur + part_start),
                    (TSK_DADDR_T) part_size, TSK_VS_PART_FLAG_ALLOC,
                    dos_get_desc(part->ptype), table, i)) {
                free(sect_buf);
                return 1;
            }
        }
    }

    free(sect_buf);
    return 0;
}


/*
 * Load the primary partition table (MBR) into the internal
 * data structures in TSK_VS_INFO
 *
 * This will automatically call load_ext_table for extended
 * partitions
 *
 * sect_cur is the address of the table to load
 *
 * 0 is returned if the load is successful and 1 if error
 */
static uint8_t
dos_load_prim_table(TSK_VS_INFO * vs, uint8_t test)
{
    dos_sect *sect;
    char *sect_buf;
    int i, added = 0;
    char *table_str;
    ssize_t cnt;
    TSK_DADDR_T taddr = vs->offset / vs->block_size + DOS_PART_SOFFSET;
    TSK_DADDR_T max_addr = (vs->img_info->size - vs->offset) / vs->block_size;  // max sector

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "dos_load_prim: Table Sector: %" PRIuDADDR "\n", taddr);

    if ((sect_buf = tsk_malloc(vs->block_size)) == NULL)
        return 1;
    sect = (dos_sect *) sect_buf;

    /* Read the table */
    cnt = tsk_vs_read_block
        (vs, DOS_PART_SOFFSET, sect_buf, vs->block_size);

    if (cnt != vs->block_size) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_READ);
        }
        tsk_error_set_errstr2("Primary DOS table sector %" PRIuDADDR,
            taddr);
        free(sect_buf);
        return 1;
    }


    /* Sanity Check */
    if (tsk_vs_guessu16(vs, sect->magic, DOS_MAGIC)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_MAGIC);
        tsk_error_set_errstr
            ("File is not a DOS partition (invalid primary magic) (Sector: %"
            PRIuDADDR ")", taddr);
        if (tsk_verbose)
            fprintf(stderr,
                "File is not a DOS partition (invalid primary magic) (Sector: %"
                PRIuDADDR ")", taddr);
        free(sect_buf);
        return 1;
    }

    /* Because FAT and NTFS use the same magic - check for a
     * standard MS OEM name and sizes.  Not a great check, but we can't
     * really test the table entries.
     */
    if (test) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "dos_load_prim_table: Testing FAT/NTFS conditions\n");

        if (strncmp("MSDOS", sect->oemname, 5) == 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_MAGIC);
            tsk_error_set_errstr
                ("dos_load_prim_table: MSDOS OEM name exists");
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "dos_load_prim_table: MSDOS OEM name exists\n");
            free(sect_buf);
            return 1;
        }
        else if (strncmp("MSWIN", sect->oemname, 5) == 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_MAGIC);
            tsk_error_set_errstr
                ("dos_load_prim_table: MSWIN OEM name exists");
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "dos_load_prim_table: MSWIN OEM name exists\n");
            free(sect_buf);
            return 1;
        }
        else if (strncmp("NTFS", sect->oemname, 4) == 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_MAGIC);
            tsk_error_set_errstr
                ("dos_load_prim_table: NTFS OEM name exists");
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "dos_load_prim_table: NTFS OEM name exists\n");
            free(sect_buf);
            return 1;
        }
        else if (strncmp("FAT", sect->oemname, 4) == 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_MAGIC);
            tsk_error_set_errstr
                ("dos_load_prim_table: FAT OEM name exists");
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "dos_load_prim_table: FAT OEM name exists\n");
            free(sect_buf);
            return 1;
        }
    }

    /* Add an entry of 1 sector for the table  to the internal structure */
    if ((table_str = tsk_malloc(32)) == NULL) {
        free(sect_buf);
        return 1;
    }

    snprintf(table_str, 32, "Primary Table (#0)");
    if (NULL == tsk_vs_part_add(vs, DOS_PART_SOFFSET, (TSK_DADDR_T) 1,
            TSK_VS_PART_FLAG_META, table_str, -1, -1)) {
        free(sect_buf);
        return 1;
    }

    /* Cycle through the partition table */
    for (i = 0; i < 4; i++) {
        dos_part *part = &sect->ptable[i];

        /* We currently ignore CHS */
        uint32_t part_start = tsk_getu32(vs->endian, part->start_sec);
        uint32_t part_size = tsk_getu32(vs->endian, part->size_sec);

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "load_pri:0:%d    Start: %" PRIu32 "   Size: %" PRIu32
                "  Type: %d\n", i, part_start, part_size, part->ptype);

        if (part_size == 0)
            continue;

        // make sure the first couple are in the image bounds
        if ((i < 2) && (part_start > max_addr)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_BLK_NUM);
            tsk_error_set_errstr
                ("dos_load_prim_table: Starting sector too large for image");
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "Starting sector %" PRIu32 " too large for image\n",
                    part_start);
            free(sect_buf);
            return 1;
        }
#if 0
// I'm not sure if this is too strict ...
        else if ((part_start + part_size) > max_addr) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_BLK_NUM);
            tsk_error_set_errstr
                ("dos_load_prim_table: Partition ends after image");
            return 1;
        }
#endif

        added = 1;

        /* Add the partition to the internal structure
         * If it is an extended partition, process it now */
        if (dos_is_ext(part->ptype)) {
            if (NULL == tsk_vs_part_add(vs, (TSK_DADDR_T) part_start,
                    (TSK_DADDR_T) part_size, TSK_VS_PART_FLAG_META,
                    dos_get_desc(part->ptype), 0, i)) {
                free(sect_buf);
                return 1;
            }

            if (dos_load_ext_table(vs, part_start, part_start, 1)) {
                if (tsk_verbose) {
                    fprintf(stderr,
                        "Error loading extended table, moving on");
                    tsk_error_print(stderr);
                }
                tsk_error_reset();
            }
        }
        else {
            if (NULL == tsk_vs_part_add(vs, (TSK_DADDR_T) part_start,
                    (TSK_DADDR_T) part_size, TSK_VS_PART_FLAG_ALLOC,
                    dos_get_desc(part->ptype), 0, i)) {
                free(sect_buf);
                return 1;
            }
        }
    }
    free(sect_buf);

    if (added == 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "dos_load_prim: No valid entries\n");

        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_MAGIC);
        tsk_error_set_errstr
            ("dos_load_prim_table: No valid entries in primary table");
        return 1;
    }
    return 0;
}


static void
dos_close(TSK_VS_INFO * vs)
{
    vs->tag = 0;
    tsk_vs_part_free(vs);
    free(vs);
}


/*
 * Given the path to the file, open it and load the internal
 * partition table structure
 *
 * offset is the byte offset to the start of the volume system
 *
 * If test is 1 then additional tests are performed to make sure
 * it isn't a FAT or NTFS file system. This is used when autodetection
 * is being used to detect the volume system type.
 */
TSK_VS_INFO *
tsk_vs_dos_open(TSK_IMG_INFO * img_info, TSK_DADDR_T offset, uint8_t test)
{
    TSK_VS_INFO *vs;

    // clean up any errors that are lying around
    tsk_error_reset();

    if (img_info->sector_size == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_ARG);
        tsk_error_set_errstr("tsk_vs_dos_open: sector size is 0");
        return NULL;
    }

    vs = (TSK_VS_INFO *) tsk_malloc(sizeof(*vs));
    if (vs == NULL)
        return NULL;

    vs->vstype = TSK_VS_TYPE_DOS;
    vs->tag = TSK_VS_INFO_TAG;
    vs->img_info = img_info;

    vs->offset = offset;

    /* initialize settings */
    vs->part_list = NULL;
    vs->part_count = 0;
    vs->endian = 0;
    vs->block_size = img_info->sector_size;
    

    /* Assign functions */
    vs->close = dos_close;

    /* Load the partitions into the sorted list */
    if (dos_load_prim_table(vs, test)) {
        dos_close(vs);
        return NULL;
    }

    /* fill in the sorted list with the 'unknown' values */
    if (tsk_vs_part_unused(vs)) {
        dos_close(vs);
        return NULL;
    }

    return vs;
}
