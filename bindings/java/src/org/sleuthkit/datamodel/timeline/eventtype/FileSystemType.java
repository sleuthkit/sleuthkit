/*
 * Sleuth Kit Data Model
 *
 * Copyright 2018 Basis Technology Corp.
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
package org.sleuthkit.datamodel.timeline.eventtype;

import com.google.common.collect.ImmutableList;
import java.util.Collections;
import java.util.ResourceBundle;
import org.sleuthkit.datamodel.timeline.EventTypeZoomLevel;

/**
 *
 */
public final class FileSystemType extends AbstractEventType {

	private static final ResourceBundle BUNDLE = ResourceBundle.getBundle("org.sleuthkit.datamodel.timeline.eventtype.Bundle");  // NON-NLS

	public static final FileSystemType FILE_MODIFIED
			= new FileSystemType(BUNDLE.getString("FileSystemTypes.fileModified.name")); // NON-NLS
	public static final FileSystemType FILE_ACCESSED
			= new FileSystemType(BUNDLE.getString("FileSystemTypes.fileAccessed.name")); // NON-NLS
	public static final FileSystemType FILE_CREATED
			= new FileSystemType(BUNDLE.getString("FileSystemTypes.fileCreated.name")); // NON-NLS
	public static final FileSystemType FILE_CHANGED
			= new FileSystemType(BUNDLE.getString("FileSystemTypes.fileChanged.name")); // NON-NLS

	private static final ImmutableList<FileSystemType> VALUES
			= ImmutableList.of(FILE_MODIFIED, FILE_ACCESSED, FILE_CREATED, FILE_CHANGED);

	static ImmutableList<FileSystemType> values() {
		return VALUES;
	}

	private FileSystemType(String displayName) {
		super(displayName, EventTypeZoomLevel.SUB_TYPE, BaseType.FILE_SYSTEM, Collections.emptySet());
	}

	@Override
	public int getTypeID() {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}
}
