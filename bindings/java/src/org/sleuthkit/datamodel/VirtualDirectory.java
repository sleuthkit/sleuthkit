/*
 * Autopsy Forensic Browser
 * 
 * Copyright 2012 Basis Technology Corp.
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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Layout directory object representation of a virtual layout directory stored
 * in tsk_files table.
 *
 * Layout directories are not fs directories, but "virtual" directories used to
 * organize LayoutFiles. Since they are not real fs dirs, they have similar
 * attributes to LayoutFiles and they also have children like real Directories.
 *
 */
public class VirtualDirectory extends AbstractFile {

	private Content parent;
	
	//TODO move up to AbstractFile class
	private long size;
	//TODO use enums for types and flags
	private short meta_type, dir_type, dir_flags, meta_flags;
	private String parent_path;

	protected VirtualDirectory(SleuthkitCase db, long obj_id, String name, long size, 
			short meta_type, short dir_type, short dir_flags,
			short meta_flags, String parent_path) {
		super(db, obj_id, name, TskData.TSK_DB_FILES_TYPE_ENUM.VIRTUAL_DIR);
		
		this.meta_type = meta_type;
		this.dir_type = dir_type;
		this.dir_flags = dir_flags;
		this.meta_flags = meta_flags;
		this.parent_path = parent_path;
	}

	public short getMeta_type() {
		return meta_type;
	}

	public short getDir_type() {
		return dir_type;
	}

	public short getDir_flags() {
		return dir_flags;
	}

	public short getMeta_flags() {
		return meta_flags;
	}

	public String getParent_path() {
		return parent_path;
	}

	/**
	 * Get the directory flags as String
	 *
	 * @return directory flags as String
	 */
	public String getDirFlagsAsString() {
		return FsContent.dirFlagToString(dir_flags);
	}
	
	/**
	 * Get the meta data flags as String
	 *
	 * @return meta data flags as String
	 */
	public String getMetaFlagsAsString() {
		return FsContent.metaFlagToString(meta_flags);
	}
	
	
	public String getMetaTypeAsString() {
		return TskData.tsk_fs_meta_type_str[meta_type];
	}
	


	public String getDirTypeAsString() {
		return TskData.TSK_FS_NAME_TYPE_ENUM.fromType(dir_type).getLabel();
	}
	

	
	
	/**
	 * Set the parent class, will be called by the parent
	 *
	 * @param p parent
	 */
	protected void setParent(Content p) {
		parent = p;
	}

	@Override
	public List<Content> getChildren() throws TskCoreException {
		return getSleuthkitCase().getLayoutDirectoryChildren(this);
	}
	
	@Override
	public List<Long> getChildrenIds() throws TskCoreException {
		return getSleuthkitCase().getLayoutDirectoryChildrenIds(this);
	}

	@Override
	public List<TskFileRange> getRanges() throws TskCoreException {
		 return Collections.<TskFileRange>emptyList();
	}

	@Override
	public int read(byte[] buf, long offset, long len) throws TskCoreException {
		throw new UnsupportedOperationException("Reading LayoutDirectory is not supported.");
	}
		

	@Override
	public long getSize() {
		return 0;
	}

	@Override
	public boolean isDir() {
		return true;
	}

	@Override
	public boolean isFile() {
		return false;
	}
	
	@Override
	public boolean isRoot() {
		return false;
	}

	@Override
	public <T> T accept(ContentVisitor<T> v) {
		return v.visit(this);
	}

	@Override
	public <T> T accept(SleuthkitItemVisitor<T> v) {
		return v.visit(this);
	}

	/**
	 * Get parent content object (either filesystem, or volume)
	 *
	 * @return the parent content object
	 */
	public Content getParent() {
		return parent;
	}

	@Override
	public Image getImage() throws TskCoreException {
		return getParent().getImage();
	}

	@Override
	public boolean isVirtual() {
		return true;
	}
}
