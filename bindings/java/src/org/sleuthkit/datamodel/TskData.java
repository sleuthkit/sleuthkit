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
 * The class that stores the "ENUM" for the data conversion.
 *
 * @author jantonius
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

		private long dir_type;
		String label;

		private TSK_FS_NAME_TYPE_ENUM(long type, String label){
			this.dir_type = type;
			this.label = label;
		}

		public long getDirType(){
			return dir_type;
		}
		
		public String getLabel() {
			return this.label;
		}
		
		static public TSK_FS_NAME_TYPE_ENUM fromType(long dir_type) {
			for (TSK_FS_NAME_TYPE_ENUM v : TSK_FS_NAME_TYPE_ENUM.values()) {
				if (v.dir_type == dir_type) {
					return v;
				}
			}
			throw new IllegalArgumentException("No TSK_FS_NAME_TYPE_ENUM matching type: " + dir_type);
		}
	}



	// Enum and Array for Meta Type
	public enum TSK_FS_META_TYPE_ENUM {
		TSK_FS_META_TYPE_UNDEF(0),
		TSK_FS_META_TYPE_REG(1),        ///< Regular file
		TSK_FS_META_TYPE_DIR(2),        ///< Directory file
		TSK_FS_META_TYPE_FIFO(3),       ///< Named pipe (fifo)
		TSK_FS_META_TYPE_CHR(4),        ///< Character device
		TSK_FS_META_TYPE_BLK(5),        ///< Block device
		TSK_FS_META_TYPE_LNK(6),        ///< Symbolic link
		TSK_FS_META_TYPE_SHAD(7),       ///< SOLARIS ONLY
		TSK_FS_META_TYPE_SOCK(8),       ///< UNIX domain socket
		TSK_FS_META_TYPE_WHT(9),        ///< Whiteout
		TSK_FS_META_TYPE_VIRT(10),      ///< "Virtual File" created by TSK for file system areas
		TSK_FS_META_TYPE_STR_MAX(11);   ///< Number of file types in shortname array

		private long meta_type;

		private TSK_FS_META_TYPE_ENUM(long type){
			meta_type = type;
		}

		public long getMetaType(){
			return meta_type;
		}
	}

	public static String[] tsk_fs_meta_type_str = { "-", "r", "d", "p", "c", "b", "l", "s", "h", "w", "v"};

	// Enum for Directory Flags
	public enum TSK_FS_NAME_FLAG_ENUM {
		TSK_FS_NAME_FLAG_ALLOC(1),      ///< Name is in an allocated state
		TSK_FS_NAME_FLAG_UNALLOC(2);    ///< Name is in an unallocated state

		private long dir_flag;

		private TSK_FS_NAME_FLAG_ENUM(long flag){
			dir_flag = flag;
		}

		public long getDirFlag(){
			return dir_flag;
		}
	}


	// Enum for Meta Flags
	public enum TSK_FS_META_FLAG_ENUM {
		ALLOC(1, "Allocated"),      ///< Metadata structure is currently in an allocated state
		UNALLOC(2, "Unallocated"),    ///< Metadata structure is currently in an unallocated state
		USED(4, "Used"),       ///< Metadata structure has been allocated at least once
		UNUSED(8, "Unused"),     ///< Metadata structure has never been allocated.
		COMP(16, "Compressed"),      ///< The file contents are compressed.
		ORPHAN(32, "Orphan");    ///< Return only metadata structures that have no file name pointing to the (inode_walk flag only)

		private long meta_flag;
		private String label;

		private TSK_FS_META_FLAG_ENUM(long flag, String label){
			this.meta_flag = flag;
			this.label = label;
		}

		public long getMetaFlag(){
			return meta_flag;
		}
		
		public String getLabel(){
			return label;
		}
		
		
		/**
		 * Returns all the emum elements that match the flags in metaFlag
		 * @param metaFlag
		 * @return matching TSK_FS_META_FLAG_ENUM elemetns
		 */
		public static Set<TSK_FS_META_FLAG_ENUM> getFlags(long metaFlag) {
			Set<TSK_FS_META_FLAG_ENUM> matchedFlags = EnumSet.noneOf(TSK_FS_META_FLAG_ENUM.class);
			
			for (TSK_FS_META_FLAG_ENUM v : TSK_FS_META_FLAG_ENUM.values()) {
				long flag = v.getMetaFlag();

				if((metaFlag & flag) == flag){
					matchedFlags.add(v);
				}
			}
		
			return matchedFlags;
		}
	}

	// Enum for Volume System Flags
	public enum TSK_VS_PART_FLAG_ENUM{
		TSK_VS_PART_FLAG_ALLOC(1),      ///< Sectors are allocated to a volume in the volume system
		TSK_VS_PART_FLAG_UNALLOC(2),    ///< Sectors are not allocated to a volume
		TSK_VS_PART_FLAG_META(4),       ///< Sectors contain volume system metadata and could also be ALLOC or UNALLOC
		TSK_VS_PART_FLAG_ALL(7);        ///< Show all sectors in the walk.

		private long vs_flag;

		private TSK_VS_PART_FLAG_ENUM(long flag){
			vs_flag = flag;
		}

		public long getVsFlag(){
			return vs_flag;
		}
	} 

	// Enum for Mode
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

		private long mode;

		private TSK_FS_META_MODE_ENUM(long mode){
			this.mode = mode;
		}

		public long getMode(){
			return mode;
		}
	};

	// Enum for Image Type
	public enum TSK_IMG_TYPE_ENUM {
		/* The following describe the image type */
		TSK_IMG_TYPE_DETECT(0),       // Auto Detection
		TSK_IMG_TYPE_RAW_SING(1),     // Single raw file (dd)
		TSK_IMG_TYPE_RAW_SPLIT(2),    // Split raw files
		TSK_IMG_TYPE_AFF_AFF(4),      // Advanced Forensic Format
		TSK_IMG_TYPE_AFF_AFD(8),      // AFF Multiple File
		TSK_IMG_TYPE_AFF_AFM(16),     // AFF with external metadata
		TSK_IMG_TYPE_AFF_ANY(32),     // All AFFLIB image formats (including beta ones)
		TSK_IMG_TYPE_EWF_EWF(64),     // Expert Witness format (encase)
		TSK_IMG_TYPE_UNSUPP(65535);   // Unsupported Image Type

		private long imgType;

		private TSK_IMG_TYPE_ENUM (long type){
			this.imgType = type;
		}

		public long getImageType(){
			return imgType;
		}
	};
    
    // Enum for Volume System Type.  
    public enum TSK_VS_TYPE_ENUM {
        TSK_VS_TYPE_DETECT(0x0000),    ///< Use autodetection methods
        TSK_VS_TYPE_DOS(0x0001),       ///< DOS Partition table
        TSK_VS_TYPE_BSD(0x0002),       ///< BSD Partition table
        TSK_VS_TYPE_SUN(0x0004),       ///< Sun VTOC
        TSK_VS_TYPE_MAC(0x0008),       ///< Mac partition table
        TSK_VS_TYPE_GPT(0x0010),       ///< GPT partition table
        TSK_VS_TYPE_DBFILLER(0x00F0),  ///< fake partition table type for loaddb (for images that do not have a volume system)
        TSK_VS_TYPE_UNSUPP(0xFFFF);    ///< Unsupported
        
        private long vsType;
        private TSK_VS_TYPE_ENUM(long type){
            this.vsType = type;
        }
        
        public long getVsType() {
            return vsType;
        }
    };
	
	
	public enum ObjectType {
		IMG(0),
		VS(1),
		VOL(2),
		FS(3),
		FILE(4);

		
		private long objectType;
		
		private ObjectType(long objectType) {
			this.objectType = objectType;
		}
		
		public long getObjectType(){
			return objectType;
		}
		
		public static ObjectType valueOf(long objectType) {
			for (ObjectType v : ObjectType.values()) {
				if (v.objectType == objectType) {
					return v;
				}
			}
			throw new IllegalArgumentException("No ObjectType of value: " + objectType);
		}
	}
	
	public enum FileKnown {
		UKNOWN(0, "unknown"),
		KNOWN(1, "known"),
		BAD(2, "known bad");
		
		private long known;
		private String name;
		
		private FileKnown(long known, String name) {
			this.known = known;
			this.name = name;
		}
		
		public static FileKnown valueOf(long known) {
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
		
		public long toLong() {
			return this.known;
		}
	}
	

}
