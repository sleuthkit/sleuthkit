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
 * A local/logical files and/or directories data source.
 *
 * NOTE: The DataSource interface is an emerging feature and at present is only
 * useful for obtaining the object id and the device id, an ASCII-printable
 * identifier for the device associated with the data source that is intended to
 * be unique across multiple cases (e.g., a UUID). In the future, this interface
 * will extend the Content interface and the AbstractDataSource will become an
 * abstract superclass.
 */
public class LocalFilesDataSource extends VirtualDirectory implements DataSource {

	private final long objectId;
	private final String deviceId;
	private final String timezone;

	private static final Logger LOGGER = Logger.getLogger(LocalFilesDataSource.class.getName());

	/**
	 * Constructs a local/logical files and/or directories data source.
	 *
	 * @param db                 The case database.
	 * @param objId              The object id of the virtual directory.
	 * @param dataSourceObjectId The object id of the data source for the
	 *                           virtual directory; same as objId if the virtual
	 *                           directory is a data source.
	 * @param name               The name of the virtual directory.
	 * @param dirType            The TSK_FS_NAME_TYPE_ENUM for the virtual
	 *                           directory.
	 * @param deviceId           The device ID for the data source.
	 * @param metaType           The TSK_FS_META_TYPE_ENUM for the virtual
	 *                           directory.
	 * @param dirFlag            The TSK_FS_META_TYPE_ENUM for the virtual
	 *                           directory.
	 * @param metaFlags          The meta flags for the virtual directory.
	 * @param timezone           The timezone for the data source.
	 * @param md5Hash            The MD5 hash for the virtual directory.
	 * @param knownState         The known state for the virtual directory
	 * @param parentPath         The parent path for the virtual directory,
	 *                           should be "/" if the virtual directory is a
	 *                           data source.
	 */
	public LocalFilesDataSource(SleuthkitCase db, long objId, long dataSourceObjectId, String deviceId, String name, TskData.TSK_FS_NAME_TYPE_ENUM dirType, TskData.TSK_FS_META_TYPE_ENUM metaType, TskData.TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags, String timezone, String md5Hash, TskData.FileKnown knownState, String parentPath) {
		super(db, objId, dataSourceObjectId, name, dirType, metaType, dirFlag, metaFlags, md5Hash, knownState, parentPath);
		this.objectId = objId;
		this.deviceId = deviceId;
		this.timezone = timezone;
	}

	/**
	 * Returns the VirtualDirectory instance. /deprecated LocalFilesDataSource
	 * is already a VirtualDirectory.
	 *
	 * @return This object.
	 *
	 * @deprecated LocalFilesDataSource is already a VirtualDirectory.
	 */
	@Deprecated
	public VirtualDirectory getRootDirectory() {
		return this;
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
		return timezone;
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
	 *
	 * @throws TskCoreException Thrown when there is an issue trying to retrieve
	 *                          data from the database.
	 */
	@Override
	public long getContentSize(SleuthkitCase sleuthkitCase) throws TskCoreException {
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
	 *
	 * @throws TskCoreException Thrown when there is an issue trying to retrieve
	 *                          data from the database.
	 */
	static long getContentSize(SleuthkitCase sleuthkitCase, long dataSourceObjId) throws TskCoreException {
		SleuthkitCase.CaseDbConnection connection;
		Statement statement = null;
		ResultSet resultSet = null;
		long contentSize = 0;

		connection = sleuthkitCase.getConnection();

		try {
			statement = connection.createStatement();
			resultSet = connection.executeQuery(statement, "SELECT SUM (size) FROM tsk_files WHERE tsk_files.data_source_obj_id = " + dataSourceObjId);
			if (resultSet.next()) {
				contentSize = resultSet.getLong("sum");
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("There was a problem while querying the database for size data for object ID %d.", dataSourceObjId), ex);
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			connection.close();
		}

		return contentSize;
	}

	/**
	 * Close a ResultSet.
	 *
	 * @param resultSet The ResultSet to be closed.
	 */
	private static void closeResultSet(ResultSet resultSet) {
		if (resultSet != null) {
			try {
				resultSet.close();
			} catch (SQLException ex) {
				LOGGER.log(Level.SEVERE, "Error closing ResultSet", ex); //NON-NLS
			}
		}
	}

	/**
	 * Close a Statement.
	 *
	 * @param statement The Statement to be closed.
	 */
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
