/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011-2016 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import java.util.ResourceBundle;

/**
 * Class representing information about an ingest module, used in ingest job
 * info to show which ingest modules were run.
 */
public final class IngestModuleInfo {

	private static final ResourceBundle bundle = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle");

	/**
	 * Used to keep track of the module types
	 */
	public static enum IngestModuleType {
		//DO NOT CHANGE ORDER
		DATA_SOURCE_LEVEL(bundle.getString("IngestModuleInfo.IngestModuleType.DataSourceLevel.displayName")),
		FILE_LEVEL(bundle.getString("IngestModuleInfo.IngestModuleType.FileLevel.displayName"));
		
		private String displayName;
		
		private IngestModuleType(String displayName) {
			this.displayName = displayName;
		}

		public static IngestModuleType fromID(int typeId) {
			for (IngestModuleType moduleType : IngestModuleType.values()) {
				if (moduleType.ordinal() == typeId) {
					return moduleType;
				}
			}
			return null;
		}

		/**
		 * @return the displayName
		 */
		public String getDisplayName() {
			return displayName;
		}

	}

	private final long ingestModuleId;
	private final String displayName;
	private final String uniqueName;
	private final IngestModuleType type;
	private final String version;

	/**
	 *
	 * @param ingestModuleId The id of the ingest module
	 * @param displayName    The display name of the ingest module
	 * @param uniqueName     The unique name of the ingest module.
	 * @param type           The ingest module type of the module.
	 * @param version        The version number of the module.
	 */
	IngestModuleInfo(long ingestModuleId, String displayName, String uniqueName, IngestModuleType type, String version) {
		this.ingestModuleId = ingestModuleId;
		this.displayName = displayName;
		this.uniqueName = uniqueName;
		this.type = type;
		this.version = version;
	}

	/**
	 * @return the ingestModuleId
	 */
	public long getIngestModuleId() {
		return ingestModuleId;
	}

	/**
	 * @return the displayName
	 */
	public String getDisplayName() {
		return displayName;
	}

	/**
	 * @return the uniqueName
	 */
	public String getUniqueName() {
		return uniqueName;
	}

	/**
	 * @return the typeID
	 */
	public IngestModuleType getType() {
		return type;
	}

	/**
	 * @return the version
	 */
	public String getVersion() {
		return version;
	}

}
