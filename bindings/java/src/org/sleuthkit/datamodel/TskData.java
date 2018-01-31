/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.EnumSet;
import java.util.Set;

/**
 * Contains enums for the integer values stored in the database and returned by
 * the various data model objects.
 */
public class TskData {

	private static ResourceBundle bundle = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle");

	/**
	 * The type of the file system file, as reported in the name structure of
	 * the file system. This is the dir_type column in the tsk_files table.
	 */
	public enum TSK_FS_NAME_TYPE_ENUM {

		UNDEF(0, "-"), ///< Unknown type
		FIFO(1, "p"), ///< Named pipe NON-NLS
		CHR(2, "c"), ///< Character device NON-NLS
		DIR(3, "d"), ///< Directory NON-NLS
		BLK(4, "b"), ///< Block device NON-NLS
		REG(5, "r"), ///< Regular file NON-NLS
		LNK(6, "l"), ///< Symbolic link NON-NLS
		SOCK(7, "s"), ///< Socket NON-NLS
		SHAD(8, "h"), ///< Shadow inode (solaris) NON-NLS
		WHT(9, "w"), ///< Whiteout (openbsd) NON-NLS
		VIRT(10, "v"),     ///< Special (TSK added "Virtual" files) NON-NLS
		VIRT_DIR(11, "V");     ///< Special (TSK added "Virtual" directories) NON-NLS

		private short dirType;
		String label;

		private TSK_FS_NAME_TYPE_ENUM(int type, String label) {
			this.dirType = (short) type;
			this.label = label;
		}

		/**
		 * Get dir type
		 *
		 * @return the dir type long value
		 */
		public short getValue() {
			return dirType;
		}

		/**
		 * Get the label string
		 *
		 * @return the label string value
		 */
		public String getLabel() {
			return this.label;
		}

		/**
		 * Convert to the enum type from the short value
		 *
		 * @param dir_type enum type value to convert
		 *
		 * @return converted long value
		 */
		static public TSK_FS_NAME_TYPE_ENUM valueOf(short dir_type) {
			for (TSK_FS_NAME_TYPE_ENUM v : TSK_FS_NAME_TYPE_ENUM.values()) {
				if (v.dirType == dir_type) {
					return v;
				}
			}
			throw new IllegalArgumentException(
					MessageFormat.format(bundle.getString("TskData.tskFsNameTypeEnum.exception.msg1.text"), dir_type));
		}
	}

	/**
	 * The type of the file system file, as reported in the metadata structure
	 * of the file system. This is the meta_type column in the tsk_files table.
	 */
	public enum TSK_FS_META_TYPE_ENUM {

		TSK_FS_META_TYPE_UNDEF(0, "-"),
		TSK_FS_META_TYPE_REG(1, "r"), ///< Regular file NON-NLS
		TSK_FS_META_TYPE_DIR(2, "d"), ///< Directory file NON-NLS
		TSK_FS_META_TYPE_FIFO(3, "p"), ///< Named pipe (fifo) NON-NLS
		TSK_FS_META_TYPE_CHR(4, "c"), ///< Character device NON-NLS
		TSK_FS_META_TYPE_BLK(5, "b"), ///< Block device NON-NLS
		TSK_FS_META_TYPE_LNK(6, "l"), ///< Symbolic link NON-NLS
		TSK_FS_META_TYPE_SHAD(7, "s"), ///< SOLARIS ONLY NON-NLS
		TSK_FS_META_TYPE_SOCK(8, "h"), ///< UNIX domain socket NON-NLS
		TSK_FS_META_TYPE_WHT(9, "w"), ///< Whiteout NON-NLS
		TSK_FS_META_TYPE_VIRT(10, "v"),      ///< "Virtual File" created by TSK for file system areas NON-NLS
		TSK_FS_META_TYPE_VIRT_DIR(11, "v");      ///< "Virtual Directory" created by TSK for Orphan Files NON-NLS

		private short metaType;
		private String metaTypeStr;

		private TSK_FS_META_TYPE_ENUM(int type, String metaTypeStr) {
			this.metaType = (short) type;
			this.metaTypeStr = metaTypeStr;
		}

		/**
		 * Get meta type short value
		 *
		 * @return the meta type long value
		 */
		public short getValue() {
			return metaType;
		}

		@Override
		public String toString() {
			return metaTypeStr;
		}

		public static TSK_FS_META_TYPE_ENUM valueOf(short metaType) {
			for (TSK_FS_META_TYPE_ENUM type : TSK_FS_META_TYPE_ENUM.values()) {
				if (type.getValue() == metaType) {
					return type;
				}
			}
			throw new IllegalArgumentException(
					MessageFormat.format(bundle.getString("TskData.tskFsMetaTypeEnum.exception.msg1.text"), metaType));
		}
	}

	/**
	 * The allocated status of a file system file, as reported in the name
	 * structure of the file system. This is the dir_flags column in the
	 * tsk_files table.
	 */
	public enum TSK_FS_NAME_FLAG_ENUM {

		ALLOC(1, bundle.getString("TskData.tskFsNameFlagEnum.allocated")), ///< Name is in an allocated state
		UNALLOC(2, bundle.getString("TskData.tskFsNameFlagEnum.unallocated"));    ///< Name is in an unallocated state

		private short dirFlag;
		private String dirFlagStr;

		private TSK_FS_NAME_FLAG_ENUM(int flag, String dirFlagStr) {
			this.dirFlag = (short) flag;
			this.dirFlagStr = dirFlagStr;
		}

		/**
		 * Get short value of the flag
		 *
		 * @return the long flag value
		 */
		public short getValue() {
			return dirFlag;
		}

		@Override
		public String toString() {
			return dirFlagStr;
		}

		/**
		 * Convert dirFlag int value to the enum type
		 *
		 * @param dirFlag int value to convert
		 *
		 * @return the enum type corresponding to dirFlag
		 */
		public static TSK_FS_NAME_FLAG_ENUM valueOf(int dirFlag) {
			for (TSK_FS_NAME_FLAG_ENUM flag : TSK_FS_NAME_FLAG_ENUM.values()) {
				if (flag.dirFlag == dirFlag) {
					return flag;
				}
			}
			throw new IllegalArgumentException(
					MessageFormat.format(bundle.getString("TskData.tskFsNameFlagEnum.exception.msg1.text"), dirFlag));
		}
	}

	/**
	 * The allocated status of the file system file, as reported in the metadata
	 * structure of the file system. This is the meta_flags column in the
	 * tsk_files table.
	 */
	public enum TSK_FS_META_FLAG_ENUM {

		ALLOC(1, bundle.getString("TskData.tskFsMetaFlagEnum.allocated")), ///< Metadata structure is currently in an allocated state
		UNALLOC(2, bundle.getString("TskData.tskFsMetaFlagEnum.unallocated")), ///< Metadata structure is currently in an unallocated state
		USED(4, bundle.getString("TskData.tskFsMetaFlagEnum.used")), ///< Metadata structure has been allocated at least once
		UNUSED(8, bundle.getString("TskData.tskFsMetaFlagEnum.unused")), ///< Metadata structure has never been allocated.
		COMP(16, bundle.getString("TskData.tskFsMetaFlagEnum.compressed")), ///< The file contents are compressed.
		ORPHAN(32, bundle.getString("TskData.tskFsMetaFlagEnum.orphan"));       ///< Return only metadata structures that have no file name pointing to the (inode_walk flag only)

		private short meta_flag;
		private String label;

		private TSK_FS_META_FLAG_ENUM(int flag, String label) {
			this.meta_flag = (short) flag;
			this.label = label;
		}

		/**
		 * Get meta flags short value
		 *
		 * @return the long value of meta flags
		 */
		public short getValue() {
			return meta_flag;
		}

		/**
		 * Get string label of the metal flags
		 *
		 * @return string meta flags label
		 */
		@Override
		public String toString() {
			return label;
		}

		/**
		 * Returns all the enum elements that match the flags in metaFlag
		 *
		 * @param metaFlags Flags to convert to Enums.
		 *
		 * @return matching TSK_FS_META_FLAG_ENUM elements
		 */
		public static Set<TSK_FS_META_FLAG_ENUM> valuesOf(short metaFlags) {
			Set<TSK_FS_META_FLAG_ENUM> matchedFlags = EnumSet.noneOf(TSK_FS_META_FLAG_ENUM.class);

			for (TSK_FS_META_FLAG_ENUM v : TSK_FS_META_FLAG_ENUM.values()) {
				long flag = v.getValue();

				if ((metaFlags & flag) == flag) {
					matchedFlags.add(v);
				}
			}

			return matchedFlags;
		}

		public static short toInt(Set<TSK_FS_META_FLAG_ENUM> metaFlags) {
			short val = 0;
			for (TSK_FS_META_FLAG_ENUM flag : metaFlags) {
				val |= flag.getValue();
			}
			return val;
		}

	}

	/**
	 * Type of data that is stored in the attribute for a file system file. This
	 * is the attr_type column in the tsk_files table.
	 */
	public enum TSK_FS_ATTR_TYPE_ENUM {

		TSK_FS_ATTR_TYPE_NOT_FOUND(0x00), // 0
		TSK_FS_ATTR_TYPE_DEFAULT(0x01), // 1
		TSK_FS_ATTR_TYPE_NTFS_SI(0x10), // 16
		TSK_FS_ATTR_TYPE_NTFS_ATTRLIST(0x20), // 32
		TSK_FS_ATTR_TYPE_NTFS_FNAME(0x30), // 48
		TSK_FS_ATTR_TYPE_NTFS_VVER(0x40), // 64 (NT)
		TSK_FS_ATTR_TYPE_NTFS_OBJID(0x40), // 64 (2K)
		TSK_FS_ATTR_TYPE_NTFS_SEC(0x50), // 80
		TSK_FS_ATTR_TYPE_NTFS_VNAME(0x60), // 96
		TSK_FS_ATTR_TYPE_NTFS_VINFO(0x70), // 112
		TSK_FS_ATTR_TYPE_NTFS_DATA(0x80), // 128
		TSK_FS_ATTR_TYPE_NTFS_IDXROOT(0x90), // 144
		TSK_FS_ATTR_TYPE_NTFS_IDXALLOC(0xA0), // 160
		TSK_FS_ATTR_TYPE_NTFS_BITMAP(0xB0), // 176
		TSK_FS_ATTR_TYPE_NTFS_SYMLNK(0xC0), // 192 (NT)
		TSK_FS_ATTR_TYPE_NTFS_REPARSE(0xC0), // 192 (2K)
		TSK_FS_ATTR_TYPE_NTFS_EAINFO(0xD0), // 208
		TSK_FS_ATTR_TYPE_NTFS_EA(0xE0), // 224
		TSK_FS_ATTR_TYPE_NTFS_PROP(0xF0), //  (NT)
		TSK_FS_ATTR_TYPE_NTFS_LOG(0x100), //  (2K)
		TSK_FS_ATTR_TYPE_UNIX_INDIR(0x1001), //  Indirect blocks for UFS and ExtX file systems

		// Types for HFS+ File Attributes
		TSK_FS_ATTR_TYPE_HFS_DEFAULT(0x01), // 1    Data fork of fs special files and misc
		TSK_FS_ATTR_TYPE_HFS_DATA(0x1100), // 4352 Data fork of regular files
		TSK_FS_ATTR_TYPE_HFS_RSRC(0x1101), // 4353 Resource fork of regular files
		TSK_FS_ATTR_TYPE_HFS_EXT_ATTR(0x1102), // 4354 Extended Attributes) except compression records
		TSK_FS_ATTR_TYPE_HFS_COMP_REC(0x1103); // 4355 Compression records

		private int val;

		private TSK_FS_ATTR_TYPE_ENUM(int val) {
			this.val = val;
		}

		public int getValue() {
			return val;
		}

		public static TSK_FS_ATTR_TYPE_ENUM valueOf(int val) {
			for (TSK_FS_ATTR_TYPE_ENUM type : TSK_FS_ATTR_TYPE_ENUM.values()) {
				if (type.val == val) {
					return type;
				}
			}
			throw new IllegalArgumentException(
					MessageFormat.format(bundle.getString("TskData.tskFsAttrTypeEnum.exception.msg1.text"), val));
		}
	};

	/**
	 * Flags for a partition in the disk image. This is the flags column in the
	 * tsk_vs_parts table.
	 */
	public enum TSK_VS_PART_FLAG_ENUM {

		TSK_VS_PART_FLAG_ALLOC(1), ///< Sectors are allocated to a volume in the volume system
		TSK_VS_PART_FLAG_UNALLOC(2), ///< Sectors are not allocated to a volume
		TSK_VS_PART_FLAG_META(4), ///< Sectors contain volume system metadata and could also be ALLOC or UNALLOC
		TSK_VS_PART_FLAG_ALL(7);        ///< Show all sectors in the walk.

		private long vs_flag;

		private TSK_VS_PART_FLAG_ENUM(long flag) {
			vs_flag = flag;
		}

		/**
		 * Get long value of the vs flag
		 *
		 * @return the long value of the flag
		 */
		public long getVsFlag() {
			return vs_flag;
		}

	}

	/**
	 * The permissions of a file system file. This is the mode column in the
	 * tsk_files table.
	 */
	public enum TSK_FS_META_MODE_ENUM {
		/*
		 * The following describe the file permissions
		 */

		TSK_FS_META_MODE_ISUID(0004000), ///< set user id on execution
		TSK_FS_META_MODE_ISGID(0002000), ///< set group id on execution
		TSK_FS_META_MODE_ISVTX(0001000), ///< sticky bit

		TSK_FS_META_MODE_IRUSR(0000400), ///< R for owner
		TSK_FS_META_MODE_IWUSR(0000200), ///< W for owner
		TSK_FS_META_MODE_IXUSR(0000100), ///< X for owner

		TSK_FS_META_MODE_IRGRP(0000040), ///< R for group
		TSK_FS_META_MODE_IWGRP(0000020), ///< W for group
		TSK_FS_META_MODE_IXGRP(0000010), ///< X for group

		TSK_FS_META_MODE_IROTH(0000004), ///< R for other
		TSK_FS_META_MODE_IWOTH(0000002), ///< W for other
		TSK_FS_META_MODE_IXOTH(0000001);       ///< X for other

		private short mode;

		private TSK_FS_META_MODE_ENUM(int mode) {
			this.mode = (short) mode;
		}

		/**
		 * Get short value of the meta mode
		 *
		 * @return the long value of the meta mode
		 */
		public short getMode() {
			return mode;
		}

		/**
		 * Returns all the TSK_FS_META_MODE_ENUM enum elements that match the
		 * given modes
		 *
		 * @param modes
		 *
		 * @return matching TSK_FS_META_MODE_ENUM elements
		 */
		public static Set<TSK_FS_META_MODE_ENUM> valuesOf(short modes) {
			Set<TSK_FS_META_MODE_ENUM> matchedFlags = EnumSet.noneOf(TSK_FS_META_MODE_ENUM.class);

			for (TSK_FS_META_MODE_ENUM v : TSK_FS_META_MODE_ENUM.values()) {
				long flag = v.getMode();

				if ((modes & flag) == flag) {
					matchedFlags.add(v);
				}
			}

			return matchedFlags;
		}

		/**
		 * @param modes the set of modes to convert
		 *
		 * @return the short int representing the given set of modes
		 */
		public static short toInt(Set<TSK_FS_META_MODE_ENUM> modes) {
			short modesInt = 0;
			for (TSK_FS_META_MODE_ENUM mode : modes) {
				modesInt |= mode.getMode();
			}
			return modesInt;
		}
	};

	/**
	 * The type of the file system. This is the fs_type column in the
	 * tsk_fs_info table.
	 */
	public enum TSK_FS_TYPE_ENUM {

		TSK_FS_TYPE_DETECT(0x00000000, bundle.getString("TskData.tskFsTypeEnum.autoDetect")), ///< Use autodetection methods
		TSK_FS_TYPE_NTFS(0x00000001, "NTFS"), ///< NTFS file system
		TSK_FS_TYPE_NTFS_DETECT(0x00000001, bundle.getString("TskData.tskFsTypeEnum.NTFSautoDetect")), ///< NTFS auto detection
		TSK_FS_TYPE_FAT12(0x00000002, "FAT12"), ///< FAT12 file system
		TSK_FS_TYPE_FAT16(0x00000004, "FAT16"), ///< FAT16 file system
		TSK_FS_TYPE_FAT32(0x00000008, "FAT32"), ///< FAT32 file system
		TSK_FS_TYPE_EXFAT(0x0000000A, "ExFAT"), ///< ExFAT file system
		TSK_FS_TYPE_FAT_DETECT(0x0000000e, bundle.getString("TskData.tskFsTypeEnum.FATautoDetect")), ///< FAT auto detection
		TSK_FS_TYPE_FFS1(0x00000010, "UFS1"), ///< UFS1 (FreeBSD, OpenBSD, BSDI ...)
		TSK_FS_TYPE_FFS1B(0x00000020, "UFS1b"), ///< UFS1b (Solaris - has no type)
		TSK_FS_TYPE_FFS2(0x00000040, "UFS2"), ///< UFS2 - FreeBSD, NetBSD 
		TSK_FS_TYPE_FFS_DETECT(0x00000070, "UFS"), ///< UFS auto detection
		TSK_FS_TYPE_EXT2(0x00000080, "Ext2"), ///< Ext2 file system
		TSK_FS_TYPE_EXT3(0x00000100, "Ext3"), ///< Ext3 file system
		TSK_FS_TYPE_EXT_DETECT(0x00000180, bundle.getString("TskData.tskFsTypeEnum.ExtXautoDetect")), ///< ExtX auto detection
		TSK_FS_TYPE_SWAP(0x00000200, "SWAP"), ///< SWAP file system
		TSK_FS_TYPE_SWAP_DETECT(0x00000200, bundle.getString("TskData.tskFsTypeEnum.SWAPautoDetect")), ///< SWAP auto detection
		TSK_FS_TYPE_RAW(0x00000400, "RAW"), ///< RAW file system
		TSK_FS_TYPE_RAW_DETECT(0x00000400, bundle.getString("TskData.tskFsTypeEnum.RAWautoDetect")), ///< RAW auto detection
		TSK_FS_TYPE_ISO9660(0x00000800, "ISO9660"), ///< ISO9660 file system
		TSK_FS_TYPE_ISO9660_DETECT(0x00000800, bundle.getString("TskData.tskFsTypeEnum.ISO9660autoDetect")), ///< ISO9660 auto detection
		TSK_FS_TYPE_HFS(0x00001000, "HFS"), ///< HFS file system
		TSK_FS_TYPE_HFS_DETECT(0x00001000, bundle.getString("TskData.tskFsTypeEnum.HFSautoDetect")), ///< HFS auto detection
		TSK_FS_TYPE_EXT4(0x00002000, "Ext4"), ///< Ext4 file system
		TSK_FS_TYPE_YAFFS2(0x00004000, "YAFFS2"), ///< YAFFS2 file system
		TSK_FS_TYPE_YAFFS2_DETECT(0x00004000, bundle.getString("TskData.tskFsTypeEnum.YAFFS2autoDetect")), ///< YAFFS2 auto detection
		TSK_FS_TYPE_UNSUPP(0xffffffff, bundle.getString("TskData.tskFsTypeEnum.unsupported"));        ///< Unsupported file system

		private int value;
		private String displayName;

		private TSK_FS_TYPE_ENUM(int value, String displayName) {
			this.value = value;
			this.displayName = displayName;
		}

		/**
		 * get the value for the enum type
		 *
		 * @return int value for the enum type
		 */
		public int getValue() {
			return value;
		}
		
		/**
		 * Get display name of the enum
		 * 
		 * @return the displayName
		 */
		public String getDisplayName() {
			return displayName;
		}

		/**
		 * Convert fs type int value to the enum type - get the first matching
		 * enum type
		 *
		 * @param fsTypeValue int value to convert
		 *
		 * @return the enum type - first enum type matching the fsTypeValue
		 */
		public static TSK_FS_TYPE_ENUM valueOf(int fsTypeValue) {
			for (TSK_FS_TYPE_ENUM type : TSK_FS_TYPE_ENUM.values()) {
				if (type.value == fsTypeValue) {
					return type;
				}
			}
			throw new IllegalArgumentException(
					MessageFormat.format(bundle.getString("TskData.tskFsTypeEnum.exception.msg1.text"), fsTypeValue));
		}

	};

	/**
	 * The type of the disk image. This is the types column in the
	 * tsk_images_info table.
	 */
	public enum TSK_IMG_TYPE_ENUM {

		TSK_IMG_TYPE_DETECT(0, bundle.getString("TskData.tskImgTypeEnum.autoDetect")), // Auto Detection
		TSK_IMG_TYPE_RAW_SING(1, bundle.getString("TskData.tskImgTypeEnum.rawSingle")), // Single raw file (dd)
		TSK_IMG_TYPE_RAW_SPLIT(2, bundle.getString("TskData.tskImgTypeEnum.rawSplit")), // Split raw files
		TSK_IMG_TYPE_AFF_AFF(4, "AFF"), // Advanced Forensic Format NON-NLS
		TSK_IMG_TYPE_AFF_AFD(8, "AFD"), // AFF Multiple File NON-NLS
		TSK_IMG_TYPE_AFF_AFM(16, "AFM"), // AFF with external metadata NON-NLS
		TSK_IMG_TYPE_AFF_ANY(32, "AFF"), // All AFFLIB image formats (including beta ones) NON-NLS
		TSK_IMG_TYPE_EWF_EWF(64, "E01"), // Expert Witness format (encase) NON-NLS
		TSK_IMG_TYPE_VMDK_VMDK(128, "VMDK"), // VMware Virtual Disk (VMDK) NON-NLS
		TSK_IMG_TYPE_VHD_VHD(256, "VHD"), // Virtual Hard Disk (VHD) image format NON-NLS
		TSK_IMG_TYPE_UNSUPP(65535, bundle.getString("TskData.tskImgTypeEnum.unknown"));   // Unsupported Image Type

		private long imgType;
		private String name;

		private TSK_IMG_TYPE_ENUM(long type, String name) {
			this.imgType = type;
			this.name = name;
		}

		public static TSK_IMG_TYPE_ENUM valueOf(long imgType) {
			for (TSK_IMG_TYPE_ENUM type : TSK_IMG_TYPE_ENUM.values()) {
				if (type.getValue() == imgType) {
					return type;
				}
			}
			throw new IllegalArgumentException(
					MessageFormat.format(bundle.getString("TskData.tskImgTypeEnum.exception.msg1.text"), imgType));
		}

		/**
		 * Get long value of the image type
		 *
		 * @return the long value of the image type
		 */
		public long getValue() {
			return imgType;
		}

		/**
		 * Get the name of the image type
		 *
		 * @return
		 */
		public String getName() {
			return name;
		}
	};

	/**
	 * The type of the partition in the partition table. This is the flags
	 * column in the tsk_vs_parts table.
	 */
	public enum TSK_VS_TYPE_ENUM {

		TSK_VS_TYPE_DETECT(0x0000, bundle.getString("TskData.tskVSTypeEnum.autoDetect")), ///< Use autodetection methods
		TSK_VS_TYPE_DOS(0x0001, "DOS"), ///< DOS Partition table NON-NLS
		TSK_VS_TYPE_BSD(0x0002, "BSD"), ///< BSD Partition table NON-NLS
		TSK_VS_TYPE_SUN(0x0004, "SUN VTOC"), ///< Sun VTOC NON-NLS
		TSK_VS_TYPE_MAC(0x0008, "Mac"), ///< Mac partition table NON-NLS
		TSK_VS_TYPE_GPT(0x0010, "GPT"), ///< GPT partition table NON-NLS
		TSK_VS_TYPE_DBFILLER(0x00F0, bundle.getString("TskData.tskVSTypeEnum.fake")), ///< fake partition table type for loaddb (for images that do not have a volume system)
		TSK_VS_TYPE_UNSUPP(0xFFFF, bundle.getString("TskData.tskVSTypeEnum.unsupported"));    ///< Unsupported

		private long vsType;
		private String name;

		private TSK_VS_TYPE_ENUM(long type, String name) {
			this.vsType = type;
			this.name = name;
		}

		public static TSK_VS_TYPE_ENUM valueOf(long vsType) {
			for (TSK_VS_TYPE_ENUM type : TSK_VS_TYPE_ENUM.values()) {
				if (type.getVsType() == vsType) {
					return type;
				}
			}
			throw new IllegalArgumentException(
					MessageFormat.format(bundle.getString("TskData.tskVSTypeEnum.exception.msg1.text"), vsType));
		}

		/**
		 * Get long value of the vs type
		 *
		 * @return the long value of the vs type
		 */
		public long getVsType() {
			return vsType;
		}

		/**
		 * Get the name of the volume system type.
		 *
		 * @return
		 */
		public String getName() {
			return name;
		}
	};

	/**
	 * High-level type of an object from the database. This is the type column
	 * in the tsk_objects table.
	 */
	public enum ObjectType {

		IMG(0), ///< Disk Image - see tsk_image_info for more details
		VS(1), ///< Volume System - see tsk_vs_info for more details
		VOL(2), ///< Volume - see tsk_vs_parts for more details
		FS(3), ///< File System - see tsk_fs_info for more details
		ABSTRACTFILE(4), ///< File - see tsk_files for more details
		ARTIFACT(5),	/// Artifact - see blackboard_artifacts for more details
		REPORT(6)	///< Report - see reports for more details
		; 
		private short objectType;

		private ObjectType(int objectType) {
			this.objectType = (short) objectType;
		}

		/**
		 * Get short value of the object type
		 *
		 * @return the long value of the object type
		 */
		public short getObjectType() {
			return objectType;
		}

		/**
		 * Convert object type short value to the enum type
		 *
		 * @param objectType long value to convert
		 *
		 * @return the enum type
		 */
		public static ObjectType valueOf(short objectType) {
			for (ObjectType v : ObjectType.values()) {
				if (v.objectType == objectType) {
					return v;
				}
			}
			throw new IllegalArgumentException(
					MessageFormat.format(bundle.getString("TskData.objectTypeEnum.exception.msg1.text"), objectType));
		}
	}

	/**
	 * The type of file in a database, such as file system versus local file.
	 * This is the type field in the tsk_files table.
	 */
	public enum TSK_DB_FILES_TYPE_ENUM {

		FS(0, "File System"), ///< File that can be found in file system tree. 
		CARVED(1, "Carved"), ///< Set of blocks for a file found from carving.  Could be on top of a TSK_DB_FILES_TYPE_UNALLOC_BLOCKS range. 
		DERIVED(2, "Derived"), ///< File derived from a parent file (i.e. from ZIP)
		LOCAL(3, "Local"), ///< Local file that was added (not from a disk image)
		UNALLOC_BLOCKS(4, "Unallocated Blocks"), ///< Set of blocks not allocated by file system.  Parent should be image, volume, or file system.  Many columns in tsk_files will be NULL. Set layout in tsk_file_layout. 
		UNUSED_BLOCKS(5, "Unused Blocks"), ///< Set of blocks that are unallocated AND not used by a carved or other file type.  Parent should be UNALLOC_BLOCKS, many columns in tsk_files will be NULL, set layout in tsk_file_layout. 
		VIRTUAL_DIR(6, "Virtual Directory"), ///< Virtual directory (not on fs) with no meta-data entry that can be used to group files of types other than TSK_DB_FILES_TYPE_FS. Its parent is either another TSK_DB_FILES_TYPE_FS or a root directory or type TSK_DB_FILES_TYPE_FS.
		SLACK(7, "Slack"), ///< Slack space for a single file
		LOCAL_DIR(8, "Local Directory"), ///< Local directory that was added (not from a disk image)
		;

		private final short fileType;
		private final String name;

		private TSK_DB_FILES_TYPE_ENUM(int fileType, String name) {
			this.fileType = (short) fileType;
			this.name = name;
		}

		/**
		 * Convert db files type short value to the enum type
		 *
		 * @param fileType long value to convert
		 *
		 * @return the enum type
		 */
		public static TSK_DB_FILES_TYPE_ENUM valueOf(short fileType) {
			for (TSK_DB_FILES_TYPE_ENUM type : TSK_DB_FILES_TYPE_ENUM.values()) {
				if (type.fileType == fileType) {
					return type;
				}
			}
			throw new IllegalArgumentException(
					MessageFormat.format(bundle.getString("TskData.tskDbFilesTypeEnum.exception.msg1.text"), fileType));
		}

		/**
		 * Get short value of the file type
		 *
		 * @return the long value of the file type
		 */
		public short getFileType() {
			return fileType;
		}

		public String getName() {
			return name;
		}
	}

	/**
	 * Identifies if a file was in a hash database or not. This is the known
	 * column in the tsk_files table.
	 */
	public enum FileKnown {

		UNKNOWN(0, bundle.getString("TskData.fileKnown.unknown")), ///< File marked as unknown by hash db
		KNOWN(1, bundle.getString("TskData.fileKnown.known")), ///< File marked as a known by hash db
		BAD(2, bundle.getString("TskData.fileKnown.knownBad")); ///< File marked as known and bad/notable/interesting by hash db

		private byte known;
		private String name;

		private FileKnown(int known, String name) {
			this.known = (byte) known;
			this.name = name;
		}

		/**
		 * Convert file known type byte value to the enum type
		 *
		 * @param known long value to convert
		 *
		 * @return the enum type
		 */
		public static FileKnown valueOf(byte known) {
			for (FileKnown v : FileKnown.values()) {
				if (v.known == known) {
					return v;
				}
			}
			throw new IllegalArgumentException(
					MessageFormat.format(bundle.getString("TskData.fileKnown.exception.msg1.text"), known));
		}

		public String getName() {
			return this.name;
		}

		/**
		 * Get byte value of the file known status
		 *
		 * @return the long value of the file known status
		 */
		public byte getFileKnownValue() {
			return this.known;
		}
	}

	/**
	 * DbType is the enum covering database type. It tells you what underlying
	 * database you can use in Autopsy and TSK.
	 */
	public enum DbType {

		// Add any additional remote database types here, and keep it in sync
		// with the Sleuthkit version of this enum located at:
		// sleuthkit/tsk/auto/db_connection_info.h
		// Be sure to add to settingsValid() if you add a type here.
		SQLITE(0),
		POSTGRESQL(1);

		private int value;

		DbType(int val) {
			this.value = val;
		}

		public int getValue() {
			return this.value;
		}
	}
	
	/**
	 * Encoding type records whether locally stored files have been encoded
	 * or not, and the method used to do so. This is the encoding_type column
	 * in the tsk_files_path table.
	 * Files are encoded using EncodedFileOutputStream and are saved to the
	 * database as derived files with the appropriate encoding type argument.
	 */
	public enum EncodingType{
		// Update EncodedFileUtil.java to handle any new types
		NONE(0),
		XOR1(1);
		
		private final int type;
		
		private EncodingType(int type){
			this.type = type;
		}
		
		public int getType(){
			return type;
		}
		
		public static EncodingType valueOf(int type) {
			for (EncodingType v : EncodingType.values()) {
				if (v.type == type) {
					return v;
				}
			}
			throw new IllegalArgumentException(
					MessageFormat.format(bundle.getString("TskData.encodingType.exception.msg1.text"), type));
		}
	}
}
