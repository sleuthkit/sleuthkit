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

import java.util.Collections;
import java.util.List;
import java.util.Set;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;

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

	//TODO move up to AbstractFile class
	private long size;
	//TODO use enums for types and flags
	private TSK_FS_NAME_TYPE_ENUM dirType;
	private Set<TSK_FS_META_FLAG_ENUM> metaFlags;
	private TSK_FS_META_TYPE_ENUM metaType;
	private TSK_FS_NAME_FLAG_ENUM dirFlags;
	private String parent_path;

	protected VirtualDirectory(SleuthkitCase db, long obj_id, String name, long size, 
			TSK_FS_META_TYPE_ENUM metaType, TSK_FS_NAME_TYPE_ENUM dir_type, TSK_FS_NAME_FLAG_ENUM dirFlags,
			short metaFlags, String parent_path) {
		super(db, obj_id, name, TskData.TSK_DB_FILES_TYPE_ENUM.VIRTUAL_DIR);

		this.metaType = metaType;
		this.dirType = dir_type;
		this.dirFlags = dirFlags;
		this.metaFlags = TSK_FS_META_FLAG_ENUM.valuesOf(metaFlags);
		this.parent_path = parent_path;
	}

	public TSK_FS_META_TYPE_ENUM getMetaType() {
		return metaType;
	}

	public TSK_FS_NAME_TYPE_ENUM getDirType() {
		return dirType;
	}

	public TSK_FS_NAME_FLAG_ENUM getDirFlags() {
		return dirFlags;
	}

	public short getMetaFlags() {
		return TSK_FS_META_FLAG_ENUM.toInt(metaFlags);
	}

	public String getParent_path() {
		return parent_path;
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

	@Override
	public Image getImage() throws TskCoreException {
		return getParent().getImage();
	}

	@Override
	public boolean isVirtual() {
		return true;
	}
}
