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

import java.util.EnumSet;
import java.util.Set;

/**
 * Maps data integer and binary data stored into the database
 * into string or enum form. 
 */
public class TskData {

	// Enum for Directory Type
	public enum TSK_FS_NAME_TYPE_ENUM {
		UNDEF(0, "-"),     ///< Unknown type
		FIFO(1, "p"),      ///< Named pipe
		CHR(2, "c"),       ///< Character device
		DIR(3, "d"),       ///< Directory
		BLK(4, "b"),       ///< Block device
		REG(5, "r"),       ///< Regular file
		LNK(6, "l"),       ///< Symbolic link
		SOCK(7, "s"),      ///< Socket
		SHAD(8, "h"),      ///< Shadow inode (solaris)
		WHT(9, "w"),       ///< Whiteout (openbsd)
		VIRT(10, "v");     ///< Special (TSK added "Virtual" files)

		private short dirType;
		String label;

		private TSK_FS_NAME_TYPE_ENUM(int type, String label){
			this.dirType = (short)type;
			this.label = label;
		}

		/**
		 * Get dir type 
		 * @return the dir type long value
		 */
		public short getValue(){
			return dirType;
		}
		
		/**
		 * Get the label string
		 * @return the label string value
		 */
		public String getLabel() {
			return this.label;
		}
		
		/**
		 * Convert to the enum type from the short value
		 * @param dir_type enum type value to convert
		 * @return converted long value
		 */
		static public TSK_FS_NAME_TYPE_ENUM valueOf(short dir_type) {
			for (TSK_FS_NAME_TYPE_ENUM v : TSK_FS_NAME_TYPE_ENUM.values()) {
				if (v.dirType == dir_type) {
					return v;
				}
			}
			throw new IllegalArgumentException("No TSK_FS_NAME_TYPE_ENUM matching type: " + dir_type);
		}
	}
	
	/**
	 * Meta Type
	 */
	public enum TSK_FS_META_TYPE_ENUM {
		TSK_FS_META_TYPE_UNDEF(0, "-"),
		TSK_FS_META_TYPE_REG(1, "r"),        ///< Regular file
		TSK_FS_META_TYPE_DIR(2, "d"),        ///< Directory file
		TSK_FS_META_TYPE_FIFO(3, "p"),       ///< Named pipe (fifo)
		TSK_FS_META_TYPE_CHR(4, "c"),        ///< Character device
		TSK_FS_META_TYPE_BLK(5, "b"),        ///< Block device
		TSK_FS_META_TYPE_LNK(6, "l"),        ///< Symbolic link
		TSK_FS_META_TYPE_SHAD(7, "s"),       ///< SOLARIS ONLY
		TSK_FS_META_TYPE_SOCK(8, "h"),       ///< UNIX domain socket
		TSK_FS_META_TYPE_WHT(9, "w"),        ///< Whiteout
		TSK_FS_META_TYPE_VIRT(10, "v");      ///< "Virtual File" created by TSK for file system areas

		private short metaType;
		private String metaTypeStr;

		private TSK_FS_META_TYPE_ENUM(int type, String metaTypeStr) {
			this.metaType = (short)type;
			this.metaTypeStr = metaTypeStr;
		}

		/**
		 * Get meta type short value
		 * @return the meta type long value
		 */
		public short getValue(){
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
			throw new IllegalArgumentException("No TSK_FS_META_TYPE_ENUM of value: " + metaType);
		}
	}

	/**
	 * FS Flags
	 */
	public enum TSK_FS_NAME_FLAG_ENUM {
		ALLOC(1, "Allocated"),      ///< Name is in an allocated state
		UNALLOC(2, "Unallocated");    ///< Name is in an unallocated state

		private short dirFlag;
		private String dirFlagStr;

		private TSK_FS_NAME_FLAG_ENUM(int flag, String dirFlagStr){
			this.dirFlag = (short)flag;
			this.dirFlagStr = dirFlagStr;
		}

		/**
		 * Get short value of the flag
		 * @return the long flag value
		 */
		public short getValue(){
			return dirFlag;
		}
		
		@Override
		public String toString() {
			return dirFlagStr;
		}
		
		/**
		 * Convert dirFlag int value to the enum type
		 * @param dirFlag int value to convert
		 * @return the enum type corresponding to dirFlag
		 */
		public static TSK_FS_NAME_FLAG_ENUM valueOf(int dirFlag) {
			for(TSK_FS_NAME_FLAG_ENUM flag : TSK_FS_NAME_FLAG_ENUM.values()) {
				if(flag.dirFlag == dirFlag) {
					return flag;
				}
			}
			throw new IllegalArgumentException("No TSK_FS_NAME_FLAG_ENUM of value: " + dirFlag);
		}
	}


	
	/**
	 * META flags
	 */
	public enum TSK_FS_META_FLAG_ENUM {
		ALLOC(1, "Allocated"),      ///< Metadata structure is currently in an allocated state
		UNALLOC(2, "Unallocated"),  ///< Metadata structure is currently in an unallocated state
		USED(4, "Used"),            ///< Metadata structure has been allocated at least once
		UNUSED(8, "Unused"),        ///< Metadata structure has never been allocated.
		COMP(16, "Compressed"),     ///< The file contents are compressed.
		ORPHAN(32, "Orphan");       ///< Return only metadata structures that have no file name pointing to the (inode_walk flag only)

		private short meta_flag;
		private String label;

		private TSK_FS_META_FLAG_ENUM(int flag, String label){
			this.meta_flag = (short)flag;
			this.label = label;
		}

		/**
		 * Get meta flags short value
		 * @return the long value of meta flags
		 */
		public short getValue(){
			return meta_flag;
		}
		
		
		/**
		 * Get string label of the metal flags
		 * @return string meta flags label
		 */
		@Override
		public String toString(){
			return label;
		}
		
		
		/**
		 * Returns all the enum elements that match the flags in metaFlag
		 * @param metaFlags Flags to convert to Enums. 
		 * @return matching TSK_FS_META_FLAG_ENUM elements
		 */
		public static Set<TSK_FS_META_FLAG_ENUM> valuesOf(short metaFlags) {
			Set<TSK_FS_META_FLAG_ENUM> matchedFlags = EnumSet.noneOf(TSK_FS_META_FLAG_ENUM.class);
			
			for (TSK_FS_META_FLAG_ENUM v : TSK_FS_META_FLAG_ENUM.values()) {
				long flag = v.getValue();

				if((metaFlags & flag) == flag){
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
    * These are based on the NTFS type values. 
     * Added types for HFS+.
    */
    public enum TSK_FS_ATTR_TYPE_ENUM {
        TSK_FS_ATTR_TYPE_NOT_FOUND(0x00),      // 0
        TSK_FS_ATTR_TYPE_DEFAULT(0x01),        // 1
        TSK_FS_ATTR_TYPE_NTFS_SI(0x10),        // 16
        TSK_FS_ATTR_TYPE_NTFS_ATTRLIST(0x20),  // 32
        TSK_FS_ATTR_TYPE_NTFS_FNAME(0x30),     // 48
        TSK_FS_ATTR_TYPE_NTFS_VVER(0x40),      // 64 (NT)
        TSK_FS_ATTR_TYPE_NTFS_OBJID(0x40),     // 64 (2K)
        TSK_FS_ATTR_TYPE_NTFS_SEC(0x50),       // 80
        TSK_FS_ATTR_TYPE_NTFS_VNAME(0x60),     // 96
        TSK_FS_ATTR_TYPE_NTFS_VINFO(0x70),     // 112
        TSK_FS_ATTR_TYPE_NTFS_DATA(0x80),      // 128
        TSK_FS_ATTR_TYPE_NTFS_IDXROOT(0x90),   // 144
        TSK_FS_ATTR_TYPE_NTFS_IDXALLOC(0xA0),  // 160
        TSK_FS_ATTR_TYPE_NTFS_BITMAP(0xB0),    // 176
        TSK_FS_ATTR_TYPE_NTFS_SYMLNK(0xC0),    // 192 (NT)
        TSK_FS_ATTR_TYPE_NTFS_REPARSE(0xC0),   // 192 (2K)
        TSK_FS_ATTR_TYPE_NTFS_EAINFO(0xD0),    // 208
        TSK_FS_ATTR_TYPE_NTFS_EA(0xE0),        // 224
        TSK_FS_ATTR_TYPE_NTFS_PROP(0xF0),      //  (NT)
        TSK_FS_ATTR_TYPE_NTFS_LOG(0x100),      //  (2K)
        TSK_FS_ATTR_TYPE_UNIX_INDIR(0x1001),   //  Indirect blocks for UFS and ExtX file systems

        // Types for HFS+ File Attributes
        TSK_FS_ATTR_TYPE_HFS_DEFAULT(0x01),    // 1    Data fork of fs special files and misc
        TSK_FS_ATTR_TYPE_HFS_DATA(0x1100),     // 4352 Data fork of regular files
        TSK_FS_ATTR_TYPE_HFS_RSRC(0x1101),     // 4353 Resource fork of regular files
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
			for(TSK_FS_ATTR_TYPE_ENUM type : TSK_FS_ATTR_TYPE_ENUM.values()) {
				if(type.val == val) {
					return type;
				}
			}
			throw new IllegalArgumentException("No TSK_FS_ATTR_TYPE_ENUM of value: " + val);
		}
    };

	/**
	 * Volume system flags
	 */
	public enum TSK_VS_PART_FLAG_ENUM{
		TSK_VS_PART_FLAG_ALLOC(1),      ///< Sectors are allocated to a volume in the volume system
		TSK_VS_PART_FLAG_UNALLOC(2),    ///< Sectors are not allocated to a volume
		TSK_VS_PART_FLAG_META(4),       ///< Sectors contain volume system metadata and could also be ALLOC or UNALLOC
		TSK_VS_PART_FLAG_ALL(7);        ///< Show all sectors in the walk.

		private long vs_flag;

		private TSK_VS_PART_FLAG_ENUM(long flag){
			vs_flag = flag;
		}

		/**
		 * Get long value of the vs flag
		 * @return the long value of the flag
		 */
		public long getVsFlag(){
			return vs_flag;
		}
		
	} 

	/**
	 * Meta mode
	 */
	public enum TSK_FS_META_MODE_ENUM {
		/* The following describe the file permissions */
		TSK_FS_META_MODE_ISUID(0004000),       ///< set user id on execution
		TSK_FS_META_MODE_ISGID(0002000),       ///< set group id on execution
		TSK_FS_META_MODE_ISVTX(0001000),       ///< sticky bit

		TSK_FS_META_MODE_IRUSR(0000400),       ///< R for owner
		TSK_FS_META_MODE_IWUSR(0000200),       ///< W for owner
		TSK_FS_META_MODE_IXUSR(0000100),       ///< X for owner

		TSK_FS_META_MODE_IRGRP(0000040),       ///< R for group
		TSK_FS_META_MODE_IWGRP(0000020),       ///< W for group
		TSK_FS_META_MODE_IXGRP(0000010),       ///< X for group

		TSK_FS_META_MODE_IROTH(0000004),       ///< R for other
		TSK_FS_META_MODE_IWOTH(0000002),       ///< W for other
		TSK_FS_META_MODE_IXOTH(0000001);       ///< X for other

		private short mode;

		private TSK_FS_META_MODE_ENUM(int mode){
			this.mode = (short)mode;
		}

		/**
		 * Get short value of the meta mode
		 * @return the long value of the meta mode
		 */
		public short getMode(){
			return mode;
		}
		
		/**
		 * Returns all the TSK_FS_META_MODE_ENUM enum elements that match the given modes
		 * @param modes
		 * @return matching TSK_FS_META_MODE_ENUM elements
		 */
		public static Set<TSK_FS_META_MODE_ENUM> valuesOf(short modes) {
			Set<TSK_FS_META_MODE_ENUM> matchedFlags = EnumSet.noneOf(TSK_FS_META_MODE_ENUM.class);
			
			for (TSK_FS_META_MODE_ENUM v : TSK_FS_META_MODE_ENUM.values()) {
				long flag = v.getMode();

				if((modes & flag) == flag){
					matchedFlags.add(v);
				}
			}
		
			return matchedFlags;
		}
		
		/**
		 * @param modes the set of modes to convert
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
	 * File system type enum
	 */
	 public enum TSK_FS_TYPE_ENUM {
        TSK_FS_TYPE_DETECT(0x00000000),        ///< Use autodetection methods
        TSK_FS_TYPE_NTFS (0x00000001),  ///< NTFS file system
        TSK_FS_TYPE_NTFS_DETECT (0x00000001),   ///< NTFS auto detection
        TSK_FS_TYPE_FAT12 (0x00000002), ///< FAT12 file system
        TSK_FS_TYPE_FAT16 (0x00000004), ///< FAT16 file system
        TSK_FS_TYPE_FAT32 (0x00000008), ///< FAT32 file system
        TSK_FS_TYPE_FAT_DETECT (0x0000000e),    ///< FAT auto detection
        TSK_FS_TYPE_FFS1 (0x00000010),  ///< UFS1 (FreeBSD, OpenBSD, BSDI ...)
        TSK_FS_TYPE_FFS1B (0x00000020), ///< UFS1b (Solaris - has no type)
        TSK_FS_TYPE_FFS2 (0x00000040),  ///< UFS2 - FreeBSD, NetBSD 
        TSK_FS_TYPE_FFS_DETECT (0x00000070),    ///< UFS auto detection
        TSK_FS_TYPE_EXT2 (0x00000080),  ///< Ext2 file system
        TSK_FS_TYPE_EXT3 (0x00000100),  ///< Ext3 file system
        TSK_FS_TYPE_EXT_DETECT (0x00000180),    ///< ExtX auto detection
        TSK_FS_TYPE_SWAP (0x00000200),  ///< SWAP file system
        TSK_FS_TYPE_SWAP_DETECT (0x00000200),   ///< SWAP auto detection
        TSK_FS_TYPE_RAW (0x00000400),   ///< RAW file system
        TSK_FS_TYPE_RAW_DETECT (0x00000400),    ///< RAW auto detection
        TSK_FS_TYPE_ISO9660 (0x00000800),       ///< ISO9660 file system
        TSK_FS_TYPE_ISO9660_DETECT (0x00000800),        ///< ISO9660 auto detection
        TSK_FS_TYPE_HFS (0x00001000),   ///< HFS file system
        TSK_FS_TYPE_HFS_DETECT (0x00001000),    ///< HFS auto detection
        TSK_FS_TYPE_EXT4 (0x00002000),  ///< Ext4 file system
        TSK_FS_TYPE_YAFFS2(0x00004000),  ///< YAFFS2 file system
        TSK_FS_TYPE_YAFFS2_DETECT(0x00004000),   ///< YAFFS2 auto detection
        TSK_FS_TYPE_UNSUPP (0xffffffff);        ///< Unsupported file system
		
		private int value;
		private TSK_FS_TYPE_ENUM(int value) {
			this.value = value;
		}
		
		/**
		 * get the value for the enum type
		 * @return int value for the enum type
		 */
		public int getValue() {
			return value;
		}
		
		/**
		 * Convert fs type int value to the enum type - get the first matching enum type
		 * @param fsTypeValue int value to convert
		 * @return the enum type - first enum type matching the fsTypeValue
		 */
		public static TSK_FS_TYPE_ENUM valueOf(int fsTypeValue) {
			for(TSK_FS_TYPE_ENUM type : TSK_FS_TYPE_ENUM.values()) {
				if(type.value == fsTypeValue) {
					return type;
				}
			}
			throw new IllegalArgumentException("No TSK_FS_TYPE_ENUM of value: " + fsTypeValue);
		}
		
    };

	/**
	 * Image type
	 */
	public enum TSK_IMG_TYPE_ENUM {
		/* The following describe the image type */
		TSK_IMG_TYPE_DETECT(0, "Auto Detect"),       // Auto Detection
		TSK_IMG_TYPE_RAW_SING(1, "Raw Single"),     // Single raw file (dd)
		TSK_IMG_TYPE_RAW_SPLIT(2, "Raw Split"),    // Split raw files
		TSK_IMG_TYPE_AFF_AFF(4, "AFF"),      // Advanced Forensic Format
		TSK_IMG_TYPE_AFF_AFD(8, "AFD"),      // AFF Multiple File
		TSK_IMG_TYPE_AFF_AFM(16, "AFM"),     // AFF with external metadata
		TSK_IMG_TYPE_AFF_ANY(32, "AFF"),     // All AFFLIB image formats (including beta ones)
		TSK_IMG_TYPE_EWF_EWF(64, "E01"),     // Expert Witness format (encase)
		TSK_IMG_TYPE_UNSUPP(65535, "Unknown");   // Unsupported Image Type

		private long imgType;
		private String name;

		private TSK_IMG_TYPE_ENUM (long type, String name){
			this.imgType = type;
			this.name = name;
		}

		public static TSK_IMG_TYPE_ENUM valueOf(long imgType) {
			for (TSK_IMG_TYPE_ENUM type : TSK_IMG_TYPE_ENUM.values()) {
				if (type.getValue() == imgType) {
					return type;
				}
			}
			throw new IllegalArgumentException("No TSK_IMG_TYPE_ENUM of value: " + imgType);
		}
		
		/**
		 * Get long value of the image type
		 * @return the long value of the image type
		 */
		public long getValue(){
			return imgType;
		}
		
		/**
		 * Get the name of the image type
		 * @return 
		 */
		public String getName() {
			return name;
		}
	};
    
	/**
	 * Volume System type
	 */
    public enum TSK_VS_TYPE_ENUM {
        TSK_VS_TYPE_DETECT(0x0000, "Auto Detect"),    ///< Use autodetection methods
        TSK_VS_TYPE_DOS(0x0001, "DOS"),       ///< DOS Partition table
        TSK_VS_TYPE_BSD(0x0002, "BSD"),       ///< BSD Partition table
        TSK_VS_TYPE_SUN(0x0004, "SUN VTOC"),       ///< Sun VTOC
        TSK_VS_TYPE_MAC(0x0008, "Mac"),       ///< Mac partition table
        TSK_VS_TYPE_GPT(0x0010, "GPT"),       ///< GPT partition table
        TSK_VS_TYPE_DBFILLER(0x00F0, "Fake"),  ///< fake partition table type for loaddb (for images that do not have a volume system)
        TSK_VS_TYPE_UNSUPP(0xFFFF, "Unsupported");    ///< Unsupported
        
        private long vsType;
		private String name;
        private TSK_VS_TYPE_ENUM(long type, String name){
            this.vsType = type;
			this.name = name;
        }
		
		public static TSK_VS_TYPE_ENUM valueOf(long vsType) {
			for (TSK_VS_TYPE_ENUM type : TSK_VS_TYPE_ENUM.values()) {
				if (type.getVsType() == vsType) {
					return type;
				}
			}
			throw new IllegalArgumentException("No TSK_VS_TYPE_ENUM of value: " + vsType);
		}
        
		
		/**
		 * Get long value of the vs type
		 * @return the long value of the vs type
		 */
        public long getVsType() {
            return vsType;
        }
		
		/**
		 * Get the name of the volume system type.
		 * @return 
		 */
		public String getName() {
			return name;
		}
    };
	
	
	/**
	 * Object type
	 */
	public enum ObjectType {
		IMG(0),
		VS(1),
		VOL(2),
		FS(3),
		ABSTRACTFILE(4);

		
		private short objectType;
		
		private ObjectType(int objectType) {
			this.objectType = (short)objectType;
		}
		
		/**
		 * Get short value of the object type
		 * @return the long value of the object type
		 */
		public short getObjectType(){
			return objectType;
		}
		
		
		/**
		 * Convert object type short value to the enum type
		 * @param objectType long value to convert
		 * @return the enum type
		 */
		public static ObjectType valueOf(short objectType) {
			for (ObjectType v : ObjectType.values()) {
				if (v.objectType == objectType) {
					return v;
				}
			}
			throw new IllegalArgumentException("No ObjectType of value: " + objectType);
		}
	}
	
	
	/**
	 * DB files type
	 */
	public enum TSK_DB_FILES_TYPE_ENUM {
		FS(0), ///< File that can be found in file system tree. 
		CARVED(1), ///< Set of blocks for a file found from carving.  Could be on top of a TSK_DB_FILES_TYPE_UNALLOC_BLOCKS range. 
		DERIVED(2), ///< File derived from a parent file (i.e. from ZIP)
		LOCAL(3), ///< Local file that was added (not from a disk image)
		UNALLOC_BLOCKS(4), ///< Set of blocks not allocated by file system.  Parent should be image, volume, or file system.  Many columns in tsk_files will be NULL. Set layout in tsk_file_layout. 
		UNUSED_BLOCKS(5), ///< Set of blocks that are unallocated AND not used by a carved or other file type.  Parent should be UNALLOC_BLOCKS, many columns in tsk_files will be NULL, set layout in tsk_file_layout. 
		VIRTUAL_DIR(6), ///< Virtual directory (not on fs) with no meta-data entry that can be used to group files of types other than TSK_DB_FILES_TYPE_FS. Its parent is either another TSK_DB_FILES_TYPE_FS or a root directory or type TSK_DB_FILES_TYPE_FS.
		;
		
		private short fileType;
		
		private TSK_DB_FILES_TYPE_ENUM(int fileType) {
			this.fileType = (short)fileType;
		}
		
		
		/**
		 * Convert db files type short value to the enum type
		 * @param fileType long value to convert
		 * @return the enum type
		 */
		public static TSK_DB_FILES_TYPE_ENUM valueOf(short fileType) {
			for(TSK_DB_FILES_TYPE_ENUM type : TSK_DB_FILES_TYPE_ENUM.values()) {
				if(type.fileType == fileType) {
					return type;
				}
			}
			throw new IllegalArgumentException("No TSK_FILE_TYPE_ENUM of value: " + fileType);
		}
		
		
		/**
		 * Get short value of the file type
		 * @return the long value of the file type
		 */
		public short getFileType() {
			return fileType;
		}
	}
	
	
	/**
	 * FileKnown status
	 */
	public enum FileKnown {
		UKNOWN(0, "unknown"), ///< File marked as unknown by hash db
		KNOWN(1, "known"),  ///< File marked as a known by hash db
		BAD(2, "known bad"); ///< File marked as known and bad/notable/interesting by hash db
		
		private byte known;
		private String name;
		
		private FileKnown(int known, String name) {
			this.known = (byte)known;
			this.name = name;
		}
		
		
		/**
		 * Convert file known type byte value to the enum type
		 * @param known long value to convert
		 * @return the enum type
		 */
		public static FileKnown valueOf(byte known) {
			for (FileKnown v : FileKnown.values()) {
				if (v.known == known) {
					return v;
				}
			}
			throw new IllegalArgumentException("No FileKnown of value: " + known);
		}
		
		
		public String getName() {
			return this.name;
		}
		
		/**
		 * Get byte value of the file known status
		 * @return the long value of the file known status
		 */
		public byte getFileKnownValue() {
			return this.known;
		}
	}
}
