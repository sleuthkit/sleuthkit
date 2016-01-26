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
 * A data source (e.g., an image, a local disk, a virtual directory of logical
 * files, etc.)
 */
public final class DataSource {

	private final long objectId;
	private final String uniqueId;

	/**
	 * Constructs a data source (e.g., an image, a local disk, a virtual
	 * directory of logical files, etc.)
	 *
	 * @param objectId The object id of the data source.
	 * @param uniqueId An ASCII-printable identifier for the data source that is
	 * intended to be unique across multiple cases (e.g., a UUID).
	 */
	DataSource(long objectId, String uniqueId) {
		this.objectId = objectId;
		this.uniqueId = uniqueId;
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
	 * Gets the ASCII-printable unique identifier for the data source. This
	 * identifier is intended to be unique across multiple cases (e.g., a UUID).
	 *
	 * @return The data source id, may be null.
	 */
	public String getUniqueId() {
		return this.uniqueId;
	}

}
