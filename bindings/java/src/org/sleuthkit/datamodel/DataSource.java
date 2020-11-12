/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011-2018 Basis Technology Corp.
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
 * files, etc.).
 */
public interface DataSource extends Content {

	/**
	 * Gets the ASCII-printable identifier for the device associated with the
	 * data source. This identifier is intended to be unique across multiple
	 * cases (e.g., a UUID).
	 *
	 * @return The device id.
	 */
	String getDeviceId();

	/**
	 * Gets the time zone that was used to process the data source.
	 *
	 * @return The time zone.
	 */
	String getTimeZone();
	
	/**
	 * Set the name for this data source.
	 * 
	 * @param newName       The new name for the data source
	 * 
	 * @throws TskCoreException Thrown if an error occurs while updating the database
	 */
	void setDisplayName(String newName) throws TskCoreException;

	/**
	 * Gets the size of the contents of the data source in bytes. This size can
	 * change as archive files within the data source are expanded, files are
	 * carved, etc., and is different from the size of the data source as
	 * returned by Content.getSize, which is the size of the data source as a
	 * file.
	 *
	 * @param sleuthkitCase The sleuthkit case instance from which to make calls
	 *                      to the database.
	 *
	 * @return The size in bytes.
	 *
	 * @throws TskCoreException Thrown when there is an issue trying to retrieve
	 *                          data from the database.
	 */
	long getContentSize(SleuthkitCase sleuthkitCase) throws TskCoreException;

	/**
	 * Sets the acquisition details field in the case database.
	 * 
	 * @param details The acquisition details
	 * 
	 * @throws TskCoreException Thrown if the data can not be written
	 */
	default void setAcquisitionDetails(String details) throws TskCoreException {
		setAcquisitionDetails(details, null, null, null);
	}

	/**
	 * Sets the acquisition details along with any settings used as well as
	 * module name and module version.
	 *
	 * @param details             The acquisition details
	 * @param acquisitionSettings Any settings specific to the acquisition. May
	 *                            be Null.
	 * @param moduleName          The module name. May be Null
	 * @param moduleVersion       The module's version number. May be Null.
	 *
	 * @throws TskCoreException Thrown if the data can not be written
	 */
	public void setAcquisitionDetails(String details, String acquisitionSettings, String moduleName, String moduleVersion) throws TskCoreException;
	
	/**
	 * Gets the acquisition details field from the case database.
	 * 
	 * @return The acquisition details
	 * 
	 * @throws TskCoreException Thrown if the data can not be read
	 */
	String getAcquisitionDetails() throws TskCoreException;
}
