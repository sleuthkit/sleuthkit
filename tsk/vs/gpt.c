/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2004-2005 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file gpt.c
 * The internal functions required to process the GPT GUID Partiition Table.
 */
#include "tsk_vs_i.h"
#include "tsk_gpt.h"
#include "tsk_dos.h"


/**
 * Check if GUID matches a given value.
 *
 * @param g The GUID to match.
 * @param d1 First 4 bytes of the given value.
 * @param d2 Next 2 bytes of the given value following d1.
 * @param d3 Next 2 bytes of the given value following d2.
 * @param d4 Next 8 bytes of the given value following d3.
 * @returns 1 if they match, 0 if they do not.
 *
 */
static int
gpt_guid_match(gpt_guid * g, uint32_t d1, uint16_t d2, uint16_t d3, uint64_t d4)
{
    if(g->data_1 != d1 || g->data_2 != d2 || g->data_3 != d3)
        return 0;

    uint64_t p4 = (uint64_t)g->data_4[0];
    int i;
    for(i=1; i<8; ++i){
        p4 = p4 << 8;
        p4 += (uint64_t)g->data_4[i];
    }

    if(p4 != d4)
        return 0;
    else
        return 1;
}



/**
 *
 * Get partition type by reading GUID value.
 * Source: https://en.wikipedia.org/wiki/GUID_Partition_Table
 *
 * @param desc C-string to store the description.
 * @param g Type GUID to compare.
 * @returns 1 if matched type found, 0 if not.
 *
 */
static int
gpt_guid_type(char * desc, gpt_guid * g)
{
    if(gpt_guid_match(g, 0, 0, 0, 0))
        snprintf(desc, GUID_DESC_LEN, "Unused entry");
    else if(gpt_guid_match(g, 0x024DEE41, 0x33E7, 0x11D3, 0x9D690008C781F39F))
        snprintf(desc, GUID_DESC_LEN, "MBR partition scheme");
    else if(gpt_guid_match(g, 0xC12A7328, 0xF81F, 0x11D2, 0xBA4B00A0C93EC93B))
        snprintf(desc, GUID_DESC_LEN, "EFI System partition");
    else if(gpt_guid_match(g, 0x21686148, 0x6449, 0x6E6F, 0x744E656564454649))
        snprintf(desc, GUID_DESC_LEN, "BIOS Boot partition");
    else if(gpt_guid_match(g, 0xD3BFE2DE, 0x3DAF, 0x11DF, 0xBA40E3A556D89593))
        snprintf(desc, GUID_DESC_LEN, "Intel Fast Flash partition");
    else if(gpt_guid_match(g, 0xF4019732, 0x066E, 0x4E12, 0x8273346C5641494F))
        snprintf(desc, GUID_DESC_LEN, "Sony boot partition");
    else if(gpt_guid_match(g, 0xBFBFAFE7, 0xA34F, 0x448A, 0x9A5B6213EB736C22))
        snprintf(desc, GUID_DESC_LEN, "Lenovo boot partition");

    else if(gpt_guid_match(g, 0xE3C9E316, 0x0B5C, 0x4DB8, 0x817DF92DF00215AE))
        snprintf(desc, GUID_DESC_LEN, "Microsoft Reserved Partition");
    else if(gpt_guid_match(g, 0xDE94BBA4, 0x06D1, 0x4D40, 0xA16ABFD50179D6AC))
        snprintf(desc, GUID_DESC_LEN, "Windows Recovery Environment");
    else if(gpt_guid_match(g, 0xEBD0A0A2, 0xB9E5, 0x4433, 0x87C068B6B72699C7))
        snprintf(desc, GUID_DESC_LEN, "Basic data partition");
    else if(gpt_guid_match(g, 0x5808C8AA, 0x7E8F, 0x42E0, 0x85D2E1E90434CFB3))
        snprintf(desc, GUID_DESC_LEN, "Logical Disk Manager metadata partition");
    else if(gpt_guid_match(g, 0xAF9B60A0, 0x1431, 0x4F62, 0xBC683311714A69AD))
        snprintf(desc, GUID_DESC_LEN, "Logical Disk Manager data partition");
    else if(gpt_guid_match(g, 0x37AFFC90, 0xEF7D, 0x4E96, 0x91C32D7AE055B174))
        snprintf(desc, GUID_DESC_LEN, "GPFS partition");
    else if(gpt_guid_match(g, 0xE75CAF8F, 0xF680, 0x4CEE, 0xAFA3B001E56EFC2D))
        snprintf(desc, GUID_DESC_LEN, "Storage Spaces partition");

    else if(gpt_guid_match(g, 0x75894C1E, 0x3AEB, 0x11D3, 0xB7C17B03A0000000))
        snprintf(desc, GUID_DESC_LEN, "HP-UX Data partition");
    else if(gpt_guid_match(g, 0xE2A1E728, 0x32E3, 0x11D6, 0xA6827B03A0000000))
        snprintf(desc, GUID_DESC_LEN, "HP-UX Data partition");

    else if(gpt_guid_match(g, 0x0FC63DAF, 0x8483, 0x4772, 0x8E793D69D8477DE4))
        snprintf(desc, GUID_DESC_LEN, "Linux filesystem data");
    else if(gpt_guid_match(g, 0xA19D880F, 0x05FC, 0x4D3B, 0xA006743F0F84911E))
        snprintf(desc, GUID_DESC_LEN, "Linux RAID partition");
    else if(gpt_guid_match(g, 0x44479540, 0xF297, 0x41B2, 0x9AF7D131D5F0458A))
        snprintf(desc, GUID_DESC_LEN, "Linux Root partition (x86)");
    else if(gpt_guid_match(g, 0x4F68BCE3, 0xE8CD, 0x4DB1, 0x96E7FBCAF984B709))
        snprintf(desc, GUID_DESC_LEN, "Linux Root partition (x86-64)");
    else if(gpt_guid_match(g, 0x69DAD710, 0x2CE4, 0x4E3C, 0xB16C21A1D49ABED3))
        snprintf(desc, GUID_DESC_LEN, "Linux Root partition (32-bit ARM)");
    else if(gpt_guid_match(g, 0x0657FD6D, 0xA4AB, 0x43C4, 0x84E50933C84B4F4F))
        snprintf(desc, GUID_DESC_LEN, "Linux swap partition");
    else if(gpt_guid_match(g, 0x933AC7E1, 0x2EB4, 0x4F13, 0xB8440E14E2AEF915))
        snprintf(desc, GUID_DESC_LEN, "Linux /home partition");
    else if(gpt_guid_match(g, 0x3B8F8425, 0x20E0, 0x4F3B, 0x907F1A25A76F98E8))
        snprintf(desc, GUID_DESC_LEN, "/srv (server data) partition");
    else if(gpt_guid_match(g, 0x7FFEC5C9, 0x2D00, 0x49B7, 0x89413EA10A5586B7))
        snprintf(desc, GUID_DESC_LEN, "Plain dm-crypt partition");
    else if(gpt_guid_match(g, 0xCA7D7CCB, 0x63ED, 0x4C53, 0x861C1742536059CC))
        snprintf(desc, GUID_DESC_LEN, "LUKS partition");
    else if(gpt_guid_match(g, 0x8DA63339, 0x0007, 0x60C0, 0xC436083AC8230908))
        snprintf(desc, GUID_DESC_LEN, "Reserved");

    else if(gpt_guid_match(g, 0x83BD6B9D, 0x7F41, 0x11DC, 0xBE0B001560B84F0F))
        snprintf(desc, GUID_DESC_LEN, "FreeBSD Boot partition");
    else if(gpt_guid_match(g, 0x516E7CB4, 0x6ECF, 0x11D6, 0x8FF800022D09712B))
        snprintf(desc, GUID_DESC_LEN, "FreeBSD Data partition");
    else if(gpt_guid_match(g, 0x516E7CB5, 0x6ECF, 0x11D6, 0x8FF800022D09712B))
        snprintf(desc, GUID_DESC_LEN, "FreeBSD Swap partition");
    else if(gpt_guid_match(g, 0x516E7CB6, 0x6ECF, 0x11D6, 0x8FF800022D09712B))
        snprintf(desc, GUID_DESC_LEN, "FreeBSD Unix File System (UFS) partition");
    else if(gpt_guid_match(g, 0x516E7CB8, 0x6ECF, 0x11D6, 0x8FF800022D09712B))
        snprintf(desc, GUID_DESC_LEN, "FreeBSD Vinum volume manager partition");
    else if(gpt_guid_match(g, 0x516E7CBA, 0x6ECF, 0x11D6, 0x8FF800022D09712B))
        snprintf(desc, GUID_DESC_LEN, "FreeBSD ZFS partition");

    else if(gpt_guid_match(g, 0x48465300, 0x0000, 0x11AA, 0xAA1100306543ECAC))
        snprintf(desc, GUID_DESC_LEN, "OS X Hierarchical File System Plus (HFS+) partition");
    else if(gpt_guid_match(g, 0x55465300, 0x0000, 0x11AA, 0xAA1100306543ECAC))
        snprintf(desc, GUID_DESC_LEN, "OS X Apple UFS");
    else if(gpt_guid_match(g, 0x6A898CC3, 0x1DD2, 0x11B2, 0x99A6080020736631))
        snprintf(desc, GUID_DESC_LEN, "OS X ZFS");
    else if(gpt_guid_match(g, 0x52414944, 0x0000, 0x11AA, 0xAA1100306543ECAC))
        snprintf(desc, GUID_DESC_LEN, "OS X Apple RAID partition");
    else if(gpt_guid_match(g, 0x52414944, 0x5F4F, 0x11AA, 0xAA1100306543ECAC))
        snprintf(desc, GUID_DESC_LEN, "OS X Apple RAID partition, offline");
    else if(gpt_guid_match(g, 0x426F6F74, 0x0000, 0x11AA, 0xAA1100306543ECAC))
        snprintf(desc, GUID_DESC_LEN, "OS X Apple Boot partition (Recovery HD)");
    else if(gpt_guid_match(g, 0x4C616265, 0x6C00, 0x11AA, 0xAA1100306543ECAC))
        snprintf(desc, GUID_DESC_LEN, "OS X Apple Label");
    else if(gpt_guid_match(g, 0x5265636F, 0x7665, 0x11AA, 0xAA1100306543ECAC))
        snprintf(desc, GUID_DESC_LEN, "OS X Apple TV Recovery partition");
    else if(gpt_guid_match(g, 0x53746F72, 0x6167, 0x11AA, 0xAA1100306543ECAC))
        snprintf(desc, GUID_DESC_LEN, "OS X Apple Core Storage (i.e. Lion FileVault) partition");
    else if(gpt_guid_match(g, 0x6A82CB45, 0x1DD2, 0x11B2, 0x99A6080020736631))

        snprintf(desc, GUID_DESC_LEN, "Solaris Boot partition");
    else if(gpt_guid_match(g, 0x6A85CF4D, 0x1DD2, 0x11B2, 0x99A6080020736631))
        snprintf(desc, GUID_DESC_LEN, "Solaris Root partition");
    else if(gpt_guid_match(g, 0x6A87C46F, 0x1DD2, 0x11B2, 0x99A6080020736631))
        snprintf(desc, GUID_DESC_LEN, "Solaris Swap partition");
    else if(gpt_guid_match(g, 0x6A8B642B, 0x1DD2, 0x11B2, 0x99A6080020736631))
        snprintf(desc, GUID_DESC_LEN, "Solaris Backup partition");
    else if(gpt_guid_match(g, 0x6A898CC3, 0x1DD2, 0x11B2, 0x99A6080020736631))
        snprintf(desc, GUID_DESC_LEN, "Solaris /usr partition");
    else if(gpt_guid_match(g, 0x6A8EF2E9, 0x1DD2, 0x11B2, 0x99A6080020736631))
        snprintf(desc, GUID_DESC_LEN, "Solaris /var partition");
    else if(gpt_guid_match(g, 0x6A90BA39, 0x1DD2, 0x11B2, 0x99A6080020736631))
        snprintf(desc, GUID_DESC_LEN, "Solaris /home partition");
    else if(gpt_guid_match(g, 0x6A9283A5, 0x1DD2, 0x11B2, 0x99A6080020736631))
        snprintf(desc, GUID_DESC_LEN, "Solaris Alternate sector");
    else if(gpt_guid_match(g, 0x6A945A3B, 0x1DD2, 0x11B2, 0x99A6080020736631))
        snprintf(desc, GUID_DESC_LEN, "Solaris Reserved partition");
    else if(gpt_guid_match(g, 0x6A9630D1, 0x1DD2, 0x11B2, 0x99A6080020736631))
        snprintf(desc, GUID_DESC_LEN, "Solaris Reserved partition");
    else if(gpt_guid_match(g, 0x6A980767, 0x1DD2, 0x11B2, 0x99A6080020736631))
        snprintf(desc, GUID_DESC_LEN, "Solaris Reserved partition");
    else if(gpt_guid_match(g, 0x6A96237F, 0x1DD2, 0x11B2, 0x99A6080020736631))
        snprintf(desc, GUID_DESC_LEN, "Solaris Reserved partition");
    else if(gpt_guid_match(g, 0x6A8D2AC7, 0x1DD2, 0x11B2, 0x99A6080020736631))
        snprintf(desc, GUID_DESC_LEN, "Solaris Reserved partition");

    else if(gpt_guid_match(g, 0x49F48D32, 0xB10E, 0x11DC, 0xB99B0019D1879648))
        snprintf(desc, GUID_DESC_LEN, "NetBSD Swap partition");
    else if(gpt_guid_match(g, 0x49F48D5A, 0xB10E, 0x11DC, 0xB99B0019D1879648))
        snprintf(desc, GUID_DESC_LEN, "NetBSD FFS partition");
    else if(gpt_guid_match(g, 0x49F48D82, 0xB10E, 0x11DC, 0xB99B0019D1879648))
        snprintf(desc, GUID_DESC_LEN, "NetBSD LFS partition");
    else if(gpt_guid_match(g, 0x49F48DAA, 0xB10E, 0x11DC, 0xB99B0019D1879648))
        snprintf(desc, GUID_DESC_LEN, "NetBSD RAID partition");
    else if(gpt_guid_match(g, 0x2DB519C4, 0xB10F, 0x11DC, 0xB99B0019D1879648))
        snprintf(desc, GUID_DESC_LEN, "NetBSD Concatenated partition");
    else if(gpt_guid_match(g, 0x2DB519EC, 0xB10F, 0x11DC, 0xB99B0019D1879648))
        snprintf(desc, GUID_DESC_LEN, "NetBSD Encrypted partition");

    else if(gpt_guid_match(g, 0xFE3A2A5D, 0x4F32, 0x41A7, 0xB725ACCC3285A309))
        snprintf(desc, GUID_DESC_LEN, "ChromeOS kernel");
    else if(gpt_guid_match(g, 0x3CB8E202, 0x3B7E, 0x47DD, 0x8A3C7FF2A13CFCEC))
        snprintf(desc, GUID_DESC_LEN, "ChromeOS rootfs");
    else if(gpt_guid_match(g, 0x2E0A753D, 0x9E48, 0x43B0, 0x8337B15192CB1B5E))
        snprintf(desc, GUID_DESC_LEN, "ChromeOS future use");

    else if(gpt_guid_match(g, 0x42465331, 0x3BA3, 0x10F1, 0x802A4861696B7521))
        snprintf(desc, GUID_DESC_LEN, "Haiku BFS");

    else if(gpt_guid_match(g, 0x85D5E45E, 0x237C, 0x11E1, 0xB4B3E89A8F7FC3A7))
        snprintf(desc, GUID_DESC_LEN, "MidnightBSD Boot partition");
    else if(gpt_guid_match(g, 0x85D5E45A, 0x237C, 0x11E1, 0xB4B3E89A8F7FC3A7))
        snprintf(desc, GUID_DESC_LEN, "MidnightBSD Data partition");
    else if(gpt_guid_match(g, 0x85D5E45B, 0x237C, 0x11E1, 0xB4B3E89A8F7FC3A7))
        snprintf(desc, GUID_DESC_LEN, "MidnightBSD Swap partition");
    else if(gpt_guid_match(g, 0x0394EF8B, 0x237E, 0x11E1, 0xB4B3E89A8F7FC3A7))
        snprintf(desc, GUID_DESC_LEN, "MidnightBSD Unix File System (UFS) partition");
    else if(gpt_guid_match(g, 0x85D5E45C, 0x237C, 0x11E1, 0xB4B3E89A8F7FC3A7))
        snprintf(desc, GUID_DESC_LEN, "MidnightBSD Vinum volume manager partition");
    else if(gpt_guid_match(g, 0x85D5E45D, 0x237C, 0x11E1, 0xB4B3E89A8F7FC3A7))
        snprintf(desc, GUID_DESC_LEN, "MidnightBSD ZFS partition");

    else if(gpt_guid_match(g, 0x45B0969E, 0x9B03, 0x4F30, 0xB4C6B4B80CEFF106))
        snprintf(desc, GUID_DESC_LEN, "Ceph Journal");
    else if(gpt_guid_match(g, 0x45B0969E, 0x9B03, 0x4F30, 0xB4C65EC00CEFF106))
        snprintf(desc, GUID_DESC_LEN, "Ceph dm-crypt Encrypted Journal");
    else if(gpt_guid_match(g, 0x4FBD7E29, 0x9D25, 0x41B8, 0xAFD0062C0CEFF05D))
        snprintf(desc, GUID_DESC_LEN, "Ceph OSD");
    else if(gpt_guid_match(g, 0x4FBD7E29, 0x9D25, 0x41B8, 0xAFD05EC00CEFF05D))
        snprintf(desc, GUID_DESC_LEN, "Ceph dm-crypt OSD");
    else if(gpt_guid_match(g, 0x89C57F98, 0x2FE5, 0x4DC0, 0x89C1F3AD0CEFF2BE))
        snprintf(desc, GUID_DESC_LEN, "Ceph disk in creation");
    else if(gpt_guid_match(g, 0x89C57F98, 0x2FE5, 0x4DC0, 0x89C15EC00CEFF2BE))
        snprintf(desc, GUID_DESC_LEN, "Ceph dm-crypt disk in creation");

    else if(gpt_guid_match(g, 0x824CC7A0, 0x36A8, 0x11E3, 0x890A952519AD3F61))
        snprintf(desc, GUID_DESC_LEN, "OpenBSD Data partition");

    else if(gpt_guid_match(g, 0xCEF5A9AD, 0x73BC, 0x4601, 0x89F3CDEEEEE321A1))
        snprintf(desc, GUID_DESC_LEN, "QNX Power-safe (QNX6) file system");

    else if(gpt_guid_match(g, 0xC91818F9, 0x8025, 0x47AF, 0x89D2F030D7000C2C))
        snprintf(desc, GUID_DESC_LEN, "Plan 9 partition");
    else if(gpt_guid_match(g, 0x9D275380, 0x40AD, 0x11DB, 0xBF97000C2911D1B8))
        snprintf(desc, GUID_DESC_LEN, "vmkcore (coredump partition)");
    else if(gpt_guid_match(g, 0xAA31E02A, 0x400F, 0x11DB, 0x9590000C2911D1B8))
        snprintf(desc, GUID_DESC_LEN, "VMFS filesystem partition");
    else if(gpt_guid_match(g, 0x9198EFFC, 0x31C0, 0x11DB, 0x8F78000C2911D1B8))
        snprintf(desc, GUID_DESC_LEN, "VMware Reserved");

    else if(gpt_guid_match(g, 0x2568845D, 0x2332, 0x4675, 0xBC398FA5A4748D15))
        snprintf(desc, GUID_DESC_LEN, "Android-IA Bootloader");
    else if(gpt_guid_match(g, 0x114EAFFE, 0x1552, 0x4022, 0xB26E9B053604CF84))
        snprintf(desc, GUID_DESC_LEN, "Android-IA Bootloader2");
    else if(gpt_guid_match(g, 0x49A4D17F, 0x93A3, 0x45C1, 0xA0DEF50B2EBE2599))
        snprintf(desc, GUID_DESC_LEN, "Android-IA Boot");
    else if(gpt_guid_match(g, 0x4177C722, 0x9E92, 0x4AAB, 0x864443502BFD5506))
        snprintf(desc, GUID_DESC_LEN, "Android-IA Recovery");
    else if(gpt_guid_match(g, 0xEF32A33B, 0xA409, 0x486C, 0x91419FFB711F6266))
        snprintf(desc, GUID_DESC_LEN, "Android-IA Misc");
    else if(gpt_guid_match(g, 0x20AC26BE, 0x20B7, 0x11E3, 0x84C56CFDB94711E9))
        snprintf(desc, GUID_DESC_LEN, "Android-IA Metadata");
    else if(gpt_guid_match(g, 0x38F428E6, 0xD326, 0x425D, 0x91406E0EA133647C))
        snprintf(desc, GUID_DESC_LEN, "Android-IA System");
    else if(gpt_guid_match(g, 0xA893EF21, 0xE428, 0x470A, 0x9E550668FD91A2D9))
        snprintf(desc, GUID_DESC_LEN, "Android-IA Cache");
    else if(gpt_guid_match(g, 0xDC76DDA9, 0x5AC1, 0x491C, 0xAF42A82591580C0D))
        snprintf(desc, GUID_DESC_LEN, "Android-IA Data");
    else if(gpt_guid_match(g, 0xEBC597D0, 0x2053, 0x4B15, 0x8B64E0AAC75F4DB1))
        snprintf(desc, GUID_DESC_LEN, "Android-IA Persistent");
    else if(gpt_guid_match(g, 0x8F68CC74, 0xC5E5, 0x48DA, 0xBE91A0C8C15E9C80))
        snprintf(desc, GUID_DESC_LEN, "Android-IA Factory");
    else if(gpt_guid_match(g, 0x767941D0, 0x2085, 0x11E3, 0xAD3B6CFDB94711E9))
        snprintf(desc, GUID_DESC_LEN, "Android-IA Fastboot / Tertiary");
    else if(gpt_guid_match(g, 0xAC6D7924, 0xEB71, 0x4DF8, 0xB48DE267B27148FF))
        snprintf(desc, GUID_DESC_LEN, "Android-IA OEM");

    else if(gpt_guid_match(g, 0x7412F7D5, 0xA156, 0x4B13, 0x81DC867174929325))
        snprintf(desc, GUID_DESC_LEN, "ONIE Boot");
    else if(gpt_guid_match(g, 0xD4E6E2CD, 0x4469, 0x46F3, 0xB5CB1BFF57AFC149))
        snprintf(desc, GUID_DESC_LEN, "ONIE Config");

    else if(gpt_guid_match(g, 0x9E1A2D38, 0xC612, 0x4316, 0xAA268B49521E5A8B))
        snprintf(desc, GUID_DESC_LEN, "PowerPC PReP boot");

    else if(gpt_guid_match(g, 0xBC13C2FF, 0x59E6, 0x4262, 0xA352B275FD6F7172))
        snprintf(desc, GUID_DESC_LEN, "Freedesktop Extended Boot Partition ($BOOT)");

    else {
        snprintf(desc, GUID_DESC_LEN, "[Unkown type]");
        return 0;
    }

    return 1;
}


/*
 * Process the partition table at the sector address
 *
 * It is loaded into the internal sorted list
 */
static uint8_t
gpt_load_table(TSK_VS_INFO * vs, GPT_LOCATION_ENUM gpt_type)
{
    gpt_head *head;
    gpt_entry *ent;
    dos_sect *dos_part;
    unsigned int i, a;
    uint32_t ent_size;
    char *safe_str, *head_str, *tab_str, *ent_buf;
    ssize_t cnt;
    char *sect_buf;
    TSK_DADDR_T max_addr = (vs->img_info->size - vs->offset) / vs->block_size;  // max sector
    TSK_DADDR_T gpt_relative_addr;
    TSK_DADDR_T gpt_absolute_addr;

    if(gpt_type == PRIMARY_TABLE){
        gpt_relative_addr = GPT_PART_SOFFSET + 1;
        gpt_absolute_addr = vs->offset / vs->block_size + GPT_PART_SOFFSET + 1;
    } else {
        gpt_relative_addr = ((vs->img_info->size - vs->offset) / vs->block_size) - 1;
        gpt_absolute_addr = (vs->img_info->size / vs->block_size) - 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr, "gpt_load_table: Sector: %" PRIuDADDR "\n",
            gpt_absolute_addr);

    if ((sect_buf = tsk_malloc(vs->block_size)) == NULL)
        return 1;

    if(gpt_type == PRIMARY_TABLE){
        TSK_DADDR_T dos_sect_relative_addr = GPT_PART_SOFFSET;
        TSK_DADDR_T dos_sect_absolute_addr = vs->offset / vs->block_size + GPT_PART_SOFFSET;
        dos_part = (dos_sect *) sect_buf;

        cnt = tsk_vs_read_block
            (vs, dos_sect_relative_addr, sect_buf, vs->block_size);
        /* if -1, then tsk_errno is already set */
        if (cnt != vs->block_size) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_VS_READ);
            }
            tsk_error_set_errstr2
                ("Error reading DOS safety partition table in Sector: %"
                PRIuDADDR, dos_sect_absolute_addr);
            free(sect_buf);
            return 1;
        }

        /* Sanity Check */
        if (tsk_vs_guessu16(vs, dos_part->magic, DOS_MAGIC)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_MAGIC);
            tsk_error_set_errstr
                ("Missing DOS safety partition (invalid magic) (Sector: %"
                PRIuDADDR ")", dos_sect_absolute_addr);
            free(sect_buf);
            return 1;
        }

        if (dos_part->ptable[0].ptype != GPT_DOS_TYPE) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_MAGIC);
            tsk_error_set_errstr
                ("Missing DOS safety partition (invalid type in table: %d)",
                dos_part->ptable[0].ptype);
            free(sect_buf);
            return 1;
        }
    }

    /* Read the GPT header */
    head = (gpt_head *) sect_buf;
    cnt = tsk_vs_read_block
        (vs, gpt_relative_addr, sect_buf, vs->block_size);
    if (cnt != vs->block_size) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_READ);
        }
        tsk_error_set_errstr2("GPT Header structure in Sector: %"
            PRIuDADDR, gpt_absolute_addr);
        free(sect_buf);
        return 1;
    }

    /* Do the endianness test for the secondary table since the test in the dos safety table was skipped */
    if(gpt_type == SECONDARY_TABLE){
        if (tsk_vs_guessu64(vs, head->signature, GPT_HEAD_SIG)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_MAGIC);
            tsk_error_set_errstr("GPT Header: %" PRIx64, tsk_getu64(vs->endian,
                &head->signature));
            free(sect_buf);
            return 1;
        }
    }

    if (tsk_getu64(vs->endian, &head->signature) != GPT_HEAD_SIG) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_MAGIC);
        tsk_error_set_errstr("GPT Header: %" PRIx64, tsk_getu64(vs->endian,
                &head->signature));
        free(sect_buf);
        return 1;
    }

    // now that we checked the sig, lets make the meta  entries
    if (gpt_type == PRIMARY_TABLE) {
        if ((safe_str = tsk_malloc(16)) == NULL) {
            free(sect_buf);
            return 1;
        }
        snprintf(safe_str, 16, "Safety Table");
        if (NULL == tsk_vs_part_add(vs, (TSK_DADDR_T) 0, (TSK_DADDR_T) 1,
                TSK_VS_PART_FLAG_META, safe_str, -1, -1)) {
            free(sect_buf);
            return 1;
        }
    }

    if ((head_str = tsk_malloc(16)) == NULL) {
        free(sect_buf);
        return 1;
    }

    snprintf(head_str, 16, "GPT Header");
    if (NULL == tsk_vs_part_add(vs, gpt_relative_addr,
            (TSK_DADDR_T) ((tsk_getu32(vs->endian,
                        &head->head_size_b) + (vs->block_size -
                        1)) / vs->block_size), TSK_VS_PART_FLAG_META,
            head_str, -1, -1)) {
        free(sect_buf);
        return 1;
    }

    /* Allocate a buffer for each table entry */
    ent_size = tsk_getu32(vs->endian, &head->tab_size_b);
    if (ent_size < sizeof(gpt_entry)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_MAGIC);
        tsk_error_set_errstr("Header reports partition entry size of %"
            PRIu32 " and not %" PRIuSIZE "", ent_size, sizeof(gpt_entry));
        free(sect_buf);
        return 1;
    }

    if ((tab_str = tsk_malloc(20)) == NULL) {
        free(sect_buf);
        return 1;
    }

    snprintf(tab_str, 20, "Partition Table");
    if (NULL == tsk_vs_part_add(vs, (TSK_DADDR_T) tsk_getu64(vs->endian,
                &head->tab_start_lba),
            (TSK_DADDR_T) ((ent_size * tsk_getu32(vs->endian,
                        &head->tab_num_ent) + (vs->block_size -
                        1)) / vs->block_size), TSK_VS_PART_FLAG_META,
            tab_str, -1, -1)) {
        free(sect_buf);
        return 1;
    }


    /* Process the partition table */
    if ((ent_buf = tsk_malloc(vs->block_size)) == NULL) {
        free(sect_buf);
        return 1;
    }

    i = 0;
    for (a = 0; i < tsk_getu32(vs->endian, &head->tab_num_ent); a++) {
        char *name;

        /* Read a sector */
        cnt = tsk_vs_read_block(vs,
            tsk_getu64(vs->endian, &head->tab_start_lba) + a,
            ent_buf, vs->block_size);
        if (cnt != vs->block_size) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_VS_READ);
            }
            tsk_error_set_errstr2
                ("Error reading GPT partition table sector : %" PRIuDADDR,
                tsk_getu64(vs->endian, &head->tab_start_lba) + a);
            free(ent_buf);
            free(sect_buf);
            return 1;
        }

        /* Process the sector */
        ent = (gpt_entry *) ent_buf;
        for (; (uintptr_t) ent < (uintptr_t) ent_buf + vs->block_size &&
            i < tsk_getu32(vs->endian, &head->tab_num_ent); i++) {

            UTF16 *name16;
            UTF8 *name8;
            int retVal;

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "gpt_load: %d  Starting Sector: %" PRIu64
                    "  End: %" PRIu64 " Flag: %" PRIx64 "\n", i,
                    tsk_getu64(vs->endian, ent->start_lba),
                    tsk_getu64(vs->endian, ent->end_lba),
                    tsk_getu64(vs->endian, ent->flags));


            if (tsk_getu64(vs->endian, ent->start_lba) == 0) {
                ent++;
                continue;
            }

            // make sure the first couple are in the image bounds
            if ((i < 2)
                && (tsk_getu64(vs->endian, ent->start_lba) > max_addr)) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_VS_BLK_NUM);
                tsk_error_set_errstr
                    ("gpt_load_table: Starting sector too large for image");
                free(sect_buf);
                free(ent_buf);
                return 1;
            }


            if ((name = tsk_malloc(GUID_DESC_LEN)) == NULL) {
                free(sect_buf);
                free(ent_buf);
                return 1;
            }


            /*Find GUID partition type and use as description.*/
            /*If GUID type is unknown, use description stored in gpt entry.*/
            if( ! gpt_guid_type(name, &(ent->type_guid))) {
                name16 = (UTF16 *) ((uintptr_t) ent->name);
                name8 = (UTF8 *) name;

                retVal =
                    tsk_UTF16toUTF8(vs->endian, (const UTF16 **) &name16,
                    (UTF16 *) ((uintptr_t) name16 + sizeof(ent->name)),
                    &name8,
                    (UTF8 *) ((uintptr_t) name8 + 256), TSKlenientConversion);

                if (retVal != TSKconversionOK) {
                    if (tsk_verbose)
                        tsk_fprintf(stderr,
                            "gpt_load_table: Error converting name to UTF8: %d\n",
                            retVal);
                    *name = '\0';
                }
            }


            if (NULL == tsk_vs_part_add(vs,
                    (TSK_DADDR_T) tsk_getu64(vs->endian, ent->start_lba),
                    (TSK_DADDR_T) (tsk_getu64(vs->endian,
                            ent->end_lba) - tsk_getu64(vs->endian,
                            ent->start_lba) + 1), TSK_VS_PART_FLAG_ALLOC,
                    name, -1, i)) {
                free(sect_buf);
                free(ent_buf);
                return 1;
            }

            ent++;
        }
    }

    free(sect_buf);
    free(ent_buf);
    return 0;
}

static void
gpt_close(TSK_VS_INFO * vs)
{
    vs->tag = 0;
    tsk_vs_part_free(vs);
    free(vs);
}

TSK_VS_INFO *
tsk_vs_gpt_open(TSK_IMG_INFO * img_info, TSK_DADDR_T offset)
{
    TSK_VS_INFO *vs;

    // clean up any errors that are lying around
    tsk_error_reset();

    if (img_info->sector_size == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_ARG);
        tsk_error_set_errstr("tsk_vs_gpt_open: sector size is 0");
        return NULL;
    }

    vs = (TSK_VS_INFO *) tsk_malloc(sizeof(*vs));
    if (vs == NULL)
        return NULL;

    vs->img_info = img_info;
    vs->vstype = TSK_VS_TYPE_GPT;
    vs->tag = TSK_VS_INFO_TAG;

    /* If an offset was given, then use that too */
    vs->offset = offset;

    /* initialize settings */
    vs->part_list = NULL;
    vs->part_count = 0;
    vs->endian = 0;
    vs->block_size = img_info->sector_size;
    vs->is_backup = 0;

    /* Assign functions */
    vs->close = gpt_close;

    /* Load the partitions into the sorted list */
    if (gpt_load_table(vs, PRIMARY_TABLE)) {
        tsk_vs_part_free(vs);
        int found = 0;
        if (tsk_verbose)
            tsk_fprintf(stderr, "gpt_open: Trying other sector sizes\n");

        /* Before we give up, lets try some other sector sizes */
        vs->block_size = 512;
        while (vs->block_size <= 8192) {
            if (tsk_verbose)
                tsk_fprintf(stderr, "gpt_open: Trying sector size: %d\n",
                    vs->block_size);

            if (gpt_load_table(vs, PRIMARY_TABLE)) {
                tsk_vs_part_free(vs);
                vs->block_size *= 2;
                continue;
            }
            found = 1;
            break;
        }

        if (found == 0) {
            /* Look for the secondary GPT at the end of the image */
            if (tsk_verbose)
                tsk_fprintf(stderr, "gpt_open: Trying secondary table\n");
            vs->block_size = img_info->sector_size;
            vs->is_backup = 1;
            if(gpt_load_table(vs, SECONDARY_TABLE)){

                /* Try other sector sizes again */
                tsk_vs_part_free(vs);
                vs->block_size = 512;
                while (vs->block_size <= 8192) {
                    if (tsk_verbose)
                        tsk_fprintf(stderr, "gpt_open: Trying secondary table sector size: %d\n",
                            vs->block_size);

                    if (gpt_load_table(vs, SECONDARY_TABLE)) {
                        tsk_vs_part_free(vs);
                        vs->block_size *= 2;
                        continue;
                    }
                    found = 1;
                    break;
                }

                if(found == 0){
                    gpt_close(vs);
                    return NULL;
                }
            }

        }
    }


    /* fill in the sorted list with the 'unknown' values */
    if (tsk_vs_part_unused(vs)) {
        gpt_close(vs);
        return NULL;
    }

    return vs;
}
