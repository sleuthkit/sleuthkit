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
	void setAcquisitionDetails(String details) throws TskCoreException;

	/**
	 * Sets the acquisition tool details such as its name, version number and
	 * any settings used during the acquisition to acquire data.
	 *
	 * @param name     The name of the acquisition tool. May be NULL.
	 * @param version  The acquisition tool version number. May be NULL.
	 * @param settings The settings used by the acquisition tool. May be NULL.
	 *
	 * @throws TskCoreException Thrown if the data can not be written
	 */
	void setAcquisitionToolDetails(String name, String version, String settings) throws TskCoreException;
	
	/**
	 * Gets the acquisition details field from the case database.
	 * 
	 * @return The acquisition details
	 * 
	 * @throws TskCoreException Thrown if the data can not be read
	 */
	String getAcquisitionDetails() throws TskCoreException;

	/**
	 * Gets the acquisition tool settings field from the case database.
	 *
	 * @return The acquisition tool settings. May be Null if not set.
	 *
	 * @throws TskCoreException Thrown if the data can not be read
	 */
	String getAcquisitionToolSettings() throws TskCoreException;

	/**
	 * Gets the acquisition tool name field from the case database.
	 *
	 * @return The acquisition tool name. May be Null if not set.
	 *
	 * @throws TskCoreException Thrown if the data can not be read
	 */
	String getAcquisitionToolName() throws TskCoreException;

	/**
	 * Gets the acquisition tool version field from the case database.
	 *
	 * @return The acquisition tool version. May be Null if not set. 
	 *
	 * @throws TskCoreException Thrown if the data can not be read
	 */
	String getAcquisitionToolVersion() throws TskCoreException;

	/**
	 * Gets the added date field from the case database.
	 *
	 * @return The date time when the image was added in epoch seconds.
	 *
	 * @throws TskCoreException Thrown if the data can not be read
	 */
	Long getDateAdded() throws TskCoreException;
}
