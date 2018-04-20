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

import com.google.common.collect.ImmutableSortedSet;
import java.util.ResourceBundle;
import org.sleuthkit.datamodel.timeline.EventTypeZoomLevel;

/**
 *
 */
public final class FileSystemType extends AbstractEventType {

	private static final ResourceBundle BUNDLE = ResourceBundle.getBundle("org.sleuthkit.datamodel.timeline.eventtype.Bundle");  // NON-NLS

	public static final FileSystemType FILE_MODIFIED
			= new FileSystemType(4, BUNDLE.getString("FileSystemTypes.fileModified.name")); // NON-NLS
	public static final FileSystemType FILE_ACCESSED
			= new FileSystemType(5, BUNDLE.getString("FileSystemTypes.fileAccessed.name")); // NON-NLS
	public static final FileSystemType FILE_CREATED
			= new FileSystemType(6, BUNDLE.getString("FileSystemTypes.fileCreated.name")); // NON-NLS
	public static final FileSystemType FILE_CHANGED
			= new FileSystemType(7, BUNDLE.getString("FileSystemTypes.fileChanged.name")); // NON-NLS

	@SuppressWarnings("deprecation")
	private static final ImmutableSortedSet<FileSystemType> VALUES
			= ImmutableSortedSet.of(FILE_MODIFIED, FILE_ACCESSED, FILE_CREATED, FILE_CHANGED);

	public static ImmutableSortedSet<FileSystemType> values() {
		return VALUES;
	}

	private FileSystemType(int id, String displayName) {
		super(id, displayName, EventTypeZoomLevel.SUB_TYPE, BaseType.FILE_SYSTEM, ImmutableSortedSet.of());
	}

}
