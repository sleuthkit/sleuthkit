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
 *  http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

/**
 * Metadata for a data source (e.g., an image, a local disk, a logical file,
 * etc.)
 */
public final class DataSourceInfo {

	private final long objectId;
	private final String dataSourceId;

	/**
	 * Metadata for a data source (e.g., an image, a local disk, a logical file,
	 * etc.)
	 *
	 * @param objectId The object id of the data source.
	 * @param dataSourceId An ASCII-printable identifier for the data source
	 * that is unique across multiple cases (e.g., a UUID).
	 */
	DataSourceInfo(long objectId, String dataSourceId) {
		this.objectId = objectId;
		this.dataSourceId = dataSourceId;
	}

	/**
	 * Gets the object id of this data source.
	 *
	 * @return The object id.
	 */
	public long getObjectId() {
		return this.objectId;
	}

	/**
	 * Gets the data source id of this data source. The id is an ASCII-printable
	 * identifier for the data source that is unique across multiple cases
	 * (e.g., a UUID).
	 *
	 * @return The data source id, may be null
	 */
	public String getDataSourceId() {
		return this.dataSourceId;
	}
}
