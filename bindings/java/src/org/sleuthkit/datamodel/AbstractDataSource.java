/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011-2017 Basis Technology Corp.
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

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A data source (e.g., an image, a local disk, a virtual directory of logical
 * files, etc.).
 *
 * NOTE: The DataSource interface is an emerging feature and at present is only
 * useful for obtaining the object id and the device id, an ASCII-printable
 * identifier for the device associated with the data source that is intended to
 * be unique across multiple cases (e.g., a UUID). In the future, this interface
 * will extend the Content interface and this class will become an abstract
 * superclass.
 */
class AbstractDataSource implements DataSource {

	private final long objectId;
	private final String deviceId;
	private final String timeZone;

	private static final Logger LOGGER = Logger.getLogger(AbstractDataSource.class.getName());

	/**
	 * Constructs a data source (e.g., an image, a local disk, a virtual
	 * directory of logical files, etc.).
	 *
	 * @param objectId The object id of the data source.
	 * @param deviceId An ASCII-printable identifier for the device associated
	 *                 with the data source that is intended to be unique across
	 *                 multiple cases (e.g., a UUID).
	 * @param timeZone The time zone that was used to process the data source.
	 */
	AbstractDataSource(long objectId, String deviceId, String timeZone) {
		this.objectId = objectId;
		this.deviceId = deviceId;
		this.timeZone = timeZone;
	}

	/**
	 * Gets the object id of this data source.
	 *
	 * @return The object id.
	 */
	@Override
	public long getId() {
		return objectId;
	}

	/**
	 * Gets the ASCII-printable identifier for the device associated with the
	 * data source. This identifier is intended to be unique across multiple
	 * cases (e.g., a UUID).
	 *
	 * @return The device id.
	 */
	@Override
	public String getDeviceId() {
		return deviceId;
	}

	/**
	 * Gets the time zone that was used to process the data source.
	 *
	 * @return The time zone.
	 */
	@Override
	public String getTimeZone() {
		return timeZone;
	}

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
	 */
	@Override
	public long getContentSize(SleuthkitCase sleuthkitCase) {
		return getContentSize(sleuthkitCase, objectId);
	}

	/**
	 * Gets the size of the contents of the data source in bytes given a data
	 * source object ID. This size can change as archive files within the data
	 * source are expanded, files are carved, etc., and is different from the
	 * size of the data source as returned by Content.getSize, which is the size
	 * of the data source as a file.
	 *
	 * @param sleuthkitCase The sleuthkit case instance from which to make calls
	 *                      to the database.
	 *
	 * @return The size in bytes.
	 */
	static long getContentSize(SleuthkitCase sleuthkitCase, long dataSourceObjId) {
		SleuthkitCase.CaseDbConnection connection;
		Statement statement = null;
		ResultSet resultSet = null;
		long contentSize = 0;

		try {
			connection = sleuthkitCase.getConnection();

			try {
				statement = connection.createStatement();
				resultSet = connection.executeQuery(statement, "SELECT SUM (size) FROM tsk_files WHERE tsk_files.data_source_obj_id = " + dataSourceObjId);
				if (resultSet.next()) {
					contentSize = resultSet.getLong("sum");
				}
			} catch (SQLException ex) {
				LOGGER.log(Level.SEVERE, String.format("There was a problem while querying the database for size data for object ID %d.", dataSourceObjId), ex); //NON-NLS
			} finally {
				closeResultSet(resultSet);
				closeStatement(statement);
				connection.close();
			}
		} catch (TskCoreException ex) {
			LOGGER.log(Level.SEVERE, "An error occurred attempting to establish a database connection.", ex); //NON-NLS
		}

		return contentSize;
	}

	private static void closeResultSet(ResultSet resultSet) {
		if (resultSet != null) {
			try {
				resultSet.close();
			} catch (SQLException ex) {
				LOGGER.log(Level.SEVERE, "Error closing ResultSet", ex); //NON-NLS
			}
		}
	}

	private static void closeStatement(Statement statement) {
		if (statement != null) {
			try {
				statement.close();
			} catch (SQLException ex) {
				LOGGER.log(Level.SEVERE, "Error closing Statement", ex); //NON-NLS
			}
		}
	}

}
