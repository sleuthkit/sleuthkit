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

import org.sleuthkit.datamodel.TskData.FileKnown;

/**
 * Generalized class that stores metadata that are common to both 
 * files and directories.
 */
public abstract class FsContent extends AbstractContent {

	/*
	 * database fields
	 */
	protected long fs_obj_id, meta_addr, attr_type, attr_id, dirtype, meta_type, dir_type, dir_flags,
	meta_flags, size, ctime, crtime, atime, mtime, uid, gid, mode, known;
	/*
	 * path of parent directory
	 */
	protected String parent_path;
	/**
	 * name from the database
	 */
	protected String name;
	/**
	 * parent file system
	 */
	protected FileSystem parentFileSystem;
	/**
	 * file Handle
	 */
	protected long fileHandle = 0;
	
	FsContent(SleuthkitCase db, long obj_id, long fs_obj_id) {
		super(db, obj_id);
		this.fs_obj_id = fs_obj_id;
	}

	/**
	 * sets the parent, called by parent on creation
	 * @param parent parent file system object
	 */
	protected void setFileSystem(FileSystem parent){
		parentFileSystem = parent;
	}


	@Override
	public int read(byte[] buf, long offset, long len) throws TskException{
		if (fileHandle == 0){
			fileHandle = SleuthkitJNI.openFile(parentFileSystem.getFileSystemHandle(), meta_addr);
		}
		return SleuthkitJNI.readFile(fileHandle, buf, offset, len);
	}
	

	//methods get exact data from database. could be manipulated to get more
	//meaningful data.
	/**
	 * is this a file?
	 * @return false unless overridden by a subclass (specifically the file subclass)
	 */
	public boolean isFile(){
		return false;
	}
	/**
	 * is this a directory?
	 * @return false unless overridden by a subclass (specifically the directory subclass)
	 */
	public boolean isDir(){
		return false;
	}
	
	/**
	 * Is this the root of its parent filesystem?
	 * @return true if this is the root inode
	 */
	public boolean isRoot() {
		return parentFileSystem.getRoot_inum() == this.getMeta_addr(); 
	}
	
	public Directory getParentDirectory() throws TskException {
		return db.getParentDirectory(this);
	}

	/**
	 * get the parent file system
	 * @return the file system object of the parent
	 */
	public FileSystem getFileSystem(){
		return parentFileSystem;
	}

	/**
	 * get the sleuthkit database object
	 * @return the sleuthkit object
	 */
	public SleuthkitCase getSleuthkit(){
		return db;
	}

	/**
	 * get the name
	 * @return name
	 */
	public String getName(){
		return name;
	}

	/**
	 * get the attribute type
	 * @return attribute type
	 */
	public long getAttr_type(){
		return attr_type;
	}

	/**
	 * get the attribute id
	 * @return attribute id
	 */
	public long getAttr_id(){
		return attr_id;
	}

	/**
	 * get the directory type
	 * @return directory type
	 */
	public long getDirtype(){
		return dirtype;
	}

	/**
	 * get the meta data type
	 * @return meta data type
	 */
	public long getMeta_type(){
		return meta_type;
	}
	/**
	 * get the meta data type as String
	 * @return meta data type as String
	 */
	public String getMetaTypeAsString(){
		return FsContent.metaTypeToString(meta_type);
	}

	/**
	 * get the directory type
	 * @return directory type
	 */
	public long getDir_type(){
		return dir_type;
	}
	/**
	 * get the directory type as String
	 * @return directory type as String
	 */
	public String getDirTypeAsString(){
		return FsContent.dirTypeToString(dir_type);
	}

	/**
	 * get the directory flags
	 * @return directory flags
	 */
	public long getDir_flags(){
		return dir_flags;
	}
	/**
	 * get the directory flags as String
	 * @return directory flags as String
	 */
	public String getDirFlagsAsString(){
		return FsContent.dirFlagToString(dir_flags);
	}
	
	/**
	 * get the file address
	 * @return Address of the meta data structure for this file. 
	 */
	public long getMeta_addr() {
		return meta_addr;
	}
	

	/**
	 * get the meta data flags
	 * @return meta data flags
	 */
	public long getMeta_flags(){
		return meta_flags;
	}
	/**
	 * get the meta data flags as String
	 * @return meta data flags as String
	 */
	public String getMetaFlagsAsString(){
		return FsContent.metaFlagToString(meta_flags);
	}

	/**
	 * get the size of the content
	 * @return size of the content
	 */
	@Override
	public long getSize(){
		return size;
	}
	/**
	 * get the change time
	 * @return change time
	 */
	public long getCtime(){
		return ctime;
	}
	/**
	 * get the change time as Date
	 * @return change time as Date
	 */
	public String getCtimeAsDate(){
		return FsContent.epochToTime(ctime);
	}

	/**
	 * get the creation time
	 * @return creation time
	 */
	public long getCrtime(){
		return crtime;
	}
	/**
	 * get the creation time as Date
	 * @return creation time as Date
	 */
	public String getCrtimeAsDate(){
		return FsContent.epochToTime(crtime);
	}

	/**
	 * get the access time
	 * @return access time
	 */
	public long getAtime(){
		return atime;
	}
	/**
	 * get the access time as Date
	 * @return access time as Date
	 */
	public String getAtimeAsDate(){
		return FsContent.epochToTime(atime);
	}

	/**
	 * get the modified time
	 * @return modified time
	 */
	public long getMtime(){
		return mtime;
	}
	/**
	 * get the modified time as Date
	 * @return modified time as Date
	 */
	public String getMtimeAsDate(){
		return FsContent.epochToTime(mtime);
	}

	/**
	 * get the user id
	 * @return user id
	 */
	public long getUid(){
		return uid;
	}
	/**
	 * get the group id
	 * @return group id
	 */
	public long getGid(){
		return gid;
	}

	/**
	 * get the mode
	 * @return mode
	 */
	public long getMode(){
		return mode;
	}
	/**
	 * get the mode as String
	 * @return mode as String
	 */
	public String getModeAsString(){
		return FsContent.modeToString(mode, meta_type);
	}
	
	public FileKnown getKnown() {
		return FileKnown.valueOf(this.known);
	}
	
	public String getParentPath() {
		return this.parent_path;
	}
	
	@Override
	public void finalize(){
		if(fileHandle != 0){
			SleuthkitJNI.closeFile(fileHandle);
		}
	}

	/*
	 * -------------------------------------------------------------------------
	 * All the methods below are used to convert / map the data
	 * -------------------------------------------------------------------------
	 */

	// return the epoch into string in ISO 8601 dateTime format
	public static String epochToTime(long epoch){
		String time = "0000-00-00 00:00:00";
		if(epoch != 0){
			// Note: new java.util.Date(long date) -> date represent the specific number of milliseconds since the standard base time known.
			// Therefore we need to times the date / epoch with 1000.
			time = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date(epoch*1000));
		}
		return time;
	}

	// return the date in the ISO 8601 dateTime format into epoch
	public static long timeToEpoch(String time){
		long epoch = 0;
		try{
			epoch = new java.text.SimpleDateFormat ("yyyy-MM-dd HH:mm:ss").parse(time).getTime() / 1000;
		}
		catch(Exception e){}

		return epoch;
	}

	// --- Here are all the methods for Directory Type conversion / mapping ---
	public static String dirTypeToValue(long dirType){

		String result = "";

		for (TskData.TSK_FS_NAME_TYPE_ENUM type : TskData.TSK_FS_NAME_TYPE_ENUM.values()){
			if(type.getDirType() == dirType){
				result = type.toString();
			}
		}
		return result;
	}

	public static long valueToDirType(String dirType){

		long result = 0;

		for (TskData.TSK_FS_NAME_TYPE_ENUM type : TskData.TSK_FS_NAME_TYPE_ENUM.values()){
			if(type.toString().equals(dirType)){
				result = type.getDirType();
			}
		}
		return result;
	}

	public static String dirTypeToString(long dirType){
		return TskData.TSK_FS_NAME_TYPE_ENUM.fromType(dirType).getLabel();
	}


	// -------- Here all the methods for Meta Type conversion / mapping --------
	public static String metaTypeToValue(long metaType){

		String result = "";

		for (TskData.TSK_FS_META_TYPE_ENUM type : TskData.TSK_FS_META_TYPE_ENUM.values()){
			if(type.getMetaType() == metaType){
				result = type.toString();
			}
		}
		return result;
	}

	public static long valueToMetaType(String metaType){

		long result = 0;

		for (TskData.TSK_FS_META_TYPE_ENUM type : TskData.TSK_FS_META_TYPE_ENUM.values()){
			if(type.toString().equals(metaType)){
				result = type.getMetaType();
			}
		}
		return result;
	}

	public static String metaTypeToString(long metaType){
		return TskData.tsk_fs_meta_type_str[(int)metaType];
	}

	// ----- Here all the methods for Directory Flags conversion / mapping -----
	public static String dirFlagToValue(long dirFlag){

		String result = "";

		for (TskData.TSK_FS_NAME_FLAG_ENUM flag : TskData.TSK_FS_NAME_FLAG_ENUM.values()){
			if(flag.getDirFlag() == dirFlag){
				result = flag.toString();
			}
		}
		return result;
	}

	public static long valueToDirFlag(String dirFlag){

		long result = 0;

		for (TskData.TSK_FS_NAME_FLAG_ENUM flag : TskData.TSK_FS_NAME_FLAG_ENUM.values()){
			if(flag.toString().equals(dirFlag)){
				result = flag.getDirFlag();
			}
		}
		return result;
	}

	public static String dirFlagToString(long dirFlag){

		String result = "";

		long allocFlag = TskData.TSK_FS_NAME_FLAG_ENUM.TSK_FS_NAME_FLAG_ALLOC.getDirFlag();
		long unallocFlag = TskData.TSK_FS_NAME_FLAG_ENUM.TSK_FS_NAME_FLAG_UNALLOC.getDirFlag();

		if((dirFlag & allocFlag) == allocFlag){
			result = "Allocated";
		}
		if((dirFlag & unallocFlag) == unallocFlag){
			result = "Unallocated";
		}

		return result;
	}

	// ----- Here all the methods for Meta Flags conversion / mapping -----
	public static String metaFlagToValue(long metaFlag){

		String result = "";

		for (TskData.TSK_FS_META_FLAG_ENUM flag : TskData.TSK_FS_META_FLAG_ENUM.values()){
			if(flag.getMetaFlag() == metaFlag){
				result = flag.toString();
			}
		}
		return result;
	}

	public static long valueToMetaFlag(String metaFlag){

		long result = 0;

		for (TskData.TSK_FS_META_FLAG_ENUM flag : TskData.TSK_FS_META_FLAG_ENUM.values()){
			if(flag.toString().equals(metaFlag)){
				result = flag.getMetaFlag();
			}
		}
		return result;
	}

	public static String metaFlagToString(long metaFlag){

		String result = "";

		long allocFlag = TskData.TSK_FS_META_FLAG_ENUM.ALLOC.getMetaFlag();
		long unallocFlag = TskData.TSK_FS_META_FLAG_ENUM.UNALLOC.getMetaFlag();

		// some variables that might be needed in the future
		long usedFlag = TskData.TSK_FS_META_FLAG_ENUM.USED.getMetaFlag();
		long unusedFlag = TskData.TSK_FS_META_FLAG_ENUM.UNUSED.getMetaFlag();
		long compFlag = TskData.TSK_FS_META_FLAG_ENUM.COMP.getMetaFlag();
		long orphanFlag = TskData.TSK_FS_META_FLAG_ENUM.ORPHAN.getMetaFlag();

		if((metaFlag & allocFlag) == allocFlag){
			result = TskData.TSK_FS_META_FLAG_ENUM.ALLOC.getLabel();
			}
		if((metaFlag & unallocFlag) == unallocFlag){
			result = TskData.TSK_FS_META_FLAG_ENUM.UNALLOC.getLabel();
		}


		return result;
	}

	// ----- Here is the method to convert Mode to String -----
	public static String modeToString(long mode, long metaType){

		String result = "";

		long metaTypeMax = TskData.TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_STR_MAX.getMetaType();

		long isuid = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_ISUID.getMode(); 
		long isgid = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_ISGID.getMode();
		long isvtx = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_ISVTX.getMode();

		long irusr = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IRUSR.getMode();
		long iwusr = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IWUSR.getMode();
		long ixusr = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IXUSR.getMode();

		long irgrp = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IRGRP.getMode();
		long iwgrp = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IWGRP.getMode();
		long ixgrp= TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IXGRP.getMode();

		long iroth = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IROTH.getMode();
		long iwoth = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IWOTH.getMode();
		long ixoth = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IXOTH.getMode();

		// first character = the Meta Type
		if(metaType < metaTypeMax){
			result += FsContent.metaTypeToString(metaType);
		}
		else{result += "-";}

		// second and third characters = user permissions
		if((mode & irusr) == irusr){
			result += "r";
		}
		else{result += "-";}
		if((mode & iwusr) == iwusr){
			result += "w";
		}
		else{result += "-";}

		// fourth character = set uid
		if((mode & isuid) == isuid){
			if((mode & ixusr) == ixusr){
				result += "s";
			}
			else{
				result += "S";
			}
		}
		else{
			if((mode & ixusr) == ixusr){
				result += "x";
			}
			else{
				result += "-";
			}
		}

		// fifth and sixth characters = group permissions
		if((mode & irgrp) == irgrp){
			result += "r";
		}
		else{result += "-";}
		if((mode & iwgrp) == iwgrp){
			result += "w";
		}
		else{result += "-";}

		// seventh character = set gid
		if((mode & isgid) == isgid){
			if((mode & ixgrp) == ixgrp){
				result += "s";
			}
			else{
				result += "S";
			}
		}
		else{
			if((mode & ixgrp) == ixgrp){
				result += "x";
			}
			else{
				result += "-";
			}
		}

		// eighth and ninth character = other permissions
		if((mode & iroth) == iroth){
			result += "r";
		}
		else{result += "-";}
		if((mode & iwoth) == iwoth){
			result += "w";
		}
		else{result += "-";}

		// tenth character = sticky bit
		if((mode & isvtx) == isvtx){
			if((mode & ixoth) == ixoth){
				result += "t";
			}
			else{
				result += "T";
			}
		}
		else{
			if((mode & ixoth) == ixoth){
				result += "x";
			}
			else{
				result += "-";
			}
		}

		// check the result
		if(result.length() != 10){
			// throw error here
			result = "ERROR";
		}
		return result;
	}

}
