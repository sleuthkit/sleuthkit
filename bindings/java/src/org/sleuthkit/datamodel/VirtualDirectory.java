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
import org.sleuthkit.datamodel.TskData.FileKnown;
import org.sleuthkit.datamodel.TskData.TSK_FS_ATTR_TYPE_ENUM;
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

	//some built-in virtual directory names
	public static final String NAME_UNALLOC = "$Unalloc";
	public static final String NAME_CARVED = "$CarvedFiles";
	
	protected VirtualDirectory(SleuthkitCase db, long objId, String name, TSK_FS_NAME_TYPE_ENUM dirType, 
			TSK_FS_META_TYPE_ENUM metaType, TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags, 
			long size, String md5Hash, FileKnown knownState, String parentPath) {
		super(db, objId, TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, (short)0, name, 
				TskData.TSK_DB_FILES_TYPE_ENUM.VIRTUAL_DIR, 0L, dirType, metaType, dirFlag, 
				metaFlags, 0L, 0L, 0L, 0L, 0L, (short)0, 0, 0, md5Hash, knownState, parentPath);
	}

	@Override
	public List<Content> getChildren() throws TskCoreException {
		return getSleuthkitCase().getVirtualDirectoryChildren(this);
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
	public void close() {
		//nothing to be closed
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
		Content parent =  getParent();
		if (parent != null) {
			return parent.getImage();
		}
		else {
			//root-level VirtualDirectory, such as local files container
			return null;
		}

	}

	@Override
	public String toString(boolean preserveState){
		return super.toString(preserveState) + "VirtualDirectory [\t" + "]\t";
	}		
}
