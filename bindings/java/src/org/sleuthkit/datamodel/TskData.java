/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.sleuthkit.datamodel;

/**
 * The class that stores the "ENUM" for the data conversion.
 *
 * @author jantonius
 */
public class TskData {

    // Enum and Arrya for Directory Type
    public enum TSK_FS_NAME_TYPE_ENUM {
        TSK_FS_NAME_TYPE_UNDEF(0),     ///< Unknown type
        TSK_FS_NAME_TYPE_FIFO(1),      ///< Named pipe
        TSK_FS_NAME_TYPE_CHR(2),       ///< Character device
        TSK_FS_NAME_TYPE_DIR(3),       ///< Directory
        TSK_FS_NAME_TYPE_BLK(4),       ///< Block device
        TSK_FS_NAME_TYPE_REG(5),       ///< Regular file
        TSK_FS_NAME_TYPE_LNK(6),       ///< Symbolic link
        TSK_FS_NAME_TYPE_SOCK(7),      ///< Socket
        TSK_FS_NAME_TYPE_SHAD(8),      ///< Shadow inode (solaris)
        TSK_FS_NAME_TYPE_WHT(9),       ///< Whiteout (openbsd)
        TSK_FS_NAME_TYPE_VIRT(10),     ///< Special (TSK added "Virtual" files)
        TSK_FS_NAME_TYPE_STR_MAX(11);  ///< Number of types that have a short string name

        private long dir_type;

        private TSK_FS_NAME_TYPE_ENUM(long type){
            dir_type = type;
        }

        public long getDirType(){
            return dir_type;
        }
    }

    public static String[] tsk_fs_name_type_str = { "-", "p", "c", "d", "b", "r", "l", "s", "h", "w", "v"};


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
        TSK_FS_META_FLAG_ALLOC(1),      ///< Metadata structure is currently in an allocated state
        TSK_FS_META_FLAG_UNALLOC(2),    ///< Metadata structure is currently in an unallocated state
        TSK_FS_META_FLAG_USED(4),       ///< Metadata structure has been allocated at least once
        TSK_FS_META_FLAG_UNUSED(8),     ///< Metadata structure has never been allocated.
        TSK_FS_META_FLAG_COMP(16),      ///< The file contents are compressed.
        TSK_FS_META_FLAG_ORPHAN(32);    ///< Return only metadata structures that have no file name pointing to the (inode_walk flag only)

        private long meta_flag;

        private TSK_FS_META_FLAG_ENUM(long flag){
            meta_flag = flag;
        }

        public long getMetaFlag(){
            return meta_flag;
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

}
