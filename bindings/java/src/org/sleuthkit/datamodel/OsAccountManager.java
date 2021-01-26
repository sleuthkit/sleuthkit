/*
 * Sleuth Kit Data Model
 *
 * Copyright 2020 Basis Technology Corp.
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

import com.google.common.base.Strings;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;

/**
 * Responsible for creating/updating/retrieving the OS user accounts for files
 * and artifacts.
 *
 */
public class OsAccountManager {

	private static final Logger LOGGER = Logger.getLogger(OsAccountManager.class.getName());

	private final SleuthkitCase db;

	/**
	 * Construct a OsUserManager for the given SleuthkitCase.
	 *
	 * @param skCase The SleuthkitCase
	 *
	 */
	OsAccountManager(SleuthkitCase skCase) {
		this.db = skCase;
	}

	/**
	 * Gets or creates a OS user account with given unique id or given user name
	 * for the given data source.
	 *
	 * @param dataSourceId    Data source object id.
	 * @param uniqueAccountId User sid/uid.
	 * @param userName        User name.
	 * @param realm           Realm within which the accountId/userName is
	 *                        unique.
	 * @param transaction     Transaction to use for database operation.
	 *
	 * @return Row id of the row matching the given user id and data source.
	 */
	long createOrGetOsAccount(long dataSourceId, String uniqueAccountId, String userName, String realm, CaseDbTransaction transaction) throws TskCoreException {

		// ensure at least one of the two is supplied - unique id or user name
		if (Strings.isNullOrEmpty(uniqueAccountId) && Strings.isNullOrEmpty(userName)) {
			throw new IllegalArgumentException("Cannot create OS User with both uniqueId and userName as null.");
		}

		CaseDbConnection connection = transaction.getConnection();

		// First search for user by uniqueId
		OsAccount osAccount = getOsAccountByUniqueId(dataSourceId, uniqueAccountId, connection);
		if (osAccount != null) {
			return osAccount.getRowId();
		}

		// search by user name
		osAccount = getOsAccountByName(dataSourceId, userName, realm, connection);
		if (osAccount != null) {
			return osAccount.getRowId();
		}

		// could'nt find it, create a new account
		return createOsAccount(dataSourceId, uniqueAccountId, userName, realm, connection);

	}

	/**
	 * Creates a user with the given uid, name, and realm.
	 *
	 * @param dataSourceId Data source object id.
	 * @param uniqueId     User sid/uid. May be null/empty.
	 * @param userName     User name. may be null or empty.
	 * @param realm	       Realm - domain or host name.
	 * @param connection   Database connection to use.
	 *
	 * @return
	 *
	 * @throws TskCoreException
	 */
	private long createOsAccount(long dataSourceId, String uniqueId, String userName, String realm, CaseDbConnection connection) throws TskCoreException {

		String signature;
		if (Strings.isNullOrEmpty(uniqueId) == false) {
			signature = uniqueId;
		} else {
			if (Strings.isNullOrEmpty(realm)) {
				signature = userName;
			} else {
				signature = String.format("%s/%s", realm, userName);
			}
		}

		db.acquireSingleUserCaseWriteLock();
		try {
			String userInsertSQL = "INSERT INTO tsk_os_accounts(data_source_obj_id, user_name, realm, unique_id, signature, artifact_obj_id)"
					+ " VALUES (?, ?, ?, ?, ?, ?)"; // NON-NLS

			PreparedStatement preparedStatement = connection.getPreparedStatement(userInsertSQL, Statement.RETURN_GENERATED_KEYS);
			preparedStatement.clearParameters();

			preparedStatement.setLong(1, dataSourceId);
			preparedStatement.setString(2, userName);
			preparedStatement.setString(3, realm);
			preparedStatement.setString(4, uniqueId);
			preparedStatement.setString(5, signature);
			preparedStatement.setNull(6, java.sql.Types.BIGINT);
			

			connection.executeUpdate(preparedStatement);

			// Read back the row id
			try (ResultSet resultSet = preparedStatement.getGeneratedKeys();) {
				if (resultSet.next()) {
					return resultSet.getLong(1); //last_insert_rowid()
				} else {
					throw new SQLException("Error executing  " + userInsertSQL);
				}
			}
		} catch (SQLException ex) {
			LOGGER.log(Level.SEVERE, null, ex);
			throw new TskCoreException(String.format("Error adding user with uniqueId = %s, userName = %s for data source object id %d", uniqueId, userName, dataSourceId), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Get the OsUser with the given unique user id and the specified data
	 * source. This should be called only if its certain that this user with
	 * uniqueId exists in the database.
	 *
	 * @param dataSourceId Data source object id.
	 * @param uniqueId     User sid/uid.
	 *
	 * @return OsUser.
	 *
	 * @throws TskCoreException         If there is an error getting the user.
	 * @throws IllegalArgumentException If no matching user is found.
	 */
	public OsAccount getOsAccount(long dataSourceId, String uniqueId) throws TskCoreException {

		try (CaseDbConnection connection = this.db.getConnection()) {

			OsAccount osAccount = getOsAccountByUniqueId(dataSourceId, uniqueId, connection);
			if (osAccount == null) {
				throw new IllegalArgumentException(String.format("No user found with id %s and data source object id = %d ", uniqueId, dataSourceId));
			}

			return osAccount;
		}
	}

	/**
	 * Gets a user by the uniqueId. Returns null if no matching user is found.
	 *
	 * @param dataSourceId
	 * @param uniqueId
	 * @param connection
	 *
	 * @return OsUser, null if no user with matching uniqueId is found.
	 *
	 * @throws TskCoreException
	 */
	private OsAccount getOsAccountByUniqueId(long dataSourceId, String uniqueId, CaseDbConnection connection) throws TskCoreException {

		String queryString = "SELECT * FROM tsk_os_accounts"
				+ " WHERE data_source_obj_id = " + dataSourceId
				+ " AND LOWER(unique_id) = LOWER('" + uniqueId + "')";

		try (Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				return null;	// no match found
			} else {
				return new OsAccount(rs.getLong("id"), rs.getLong("data_source_obj_id"), rs.getString("user_name"), rs.getString("realm"), rs.getString("unique_id"), rs.getString("signature"), rs.getLong("artifact_obj_id"));
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting OS user account for unique id = %s,  data source  objId = %d ", uniqueId, dataSourceId), ex);
		}
	}

	/**
	 * Gets a user by the realm/userName. Returns null if no matching user is
	 * found.
	 *
	 * @param dataSourceId Data source object id.
	 * @param userName     User name.
	 * @param realm	       Realm - domain or host name.
	 * @param connection   Database connection to use.
	 *
	 * @return OsUser, null if no user with matching uniqueId is found.
	 *
	 * @throws TskCoreException
	 */
	private OsAccount getOsAccountByName(long dataSourceId, String userName, String realm, CaseDbConnection connection) throws TskCoreException {

		String queryString = "SELECT * FROM tsk_os_accounts"
				+ " WHERE data_source_obj_id = " + dataSourceId
				+ " AND LOWER(user_name) = LOWER('" + userName + "')"
				+ " AND LOWER(realm) = LOWER('" + realm + "')";

		try (Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				return null;	// no match found
			} else {
				return new OsAccount(rs.getLong("id"), rs.getLong("data_source_obj_id"), rs.getString("user_name"), rs.getString("realm"), rs.getString("unique_id"), rs.getString("signature"), rs.getLong("artifact_obj_id"));
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting OS user account for realm = %s and userName = %s,  data source  objId = %d ", realm, userName, dataSourceId), ex);
		}
	}

	/**
	 * Get the OsUser with the given row id.
	 *
	 * @param userRowId Row id for the user account.
	 *
	 * @return OsUser.
	 *
	 * @throws TskCoreException         If there is an error getting the user.
	 * @throws IllegalArgumentException If no matching user is found.
	 */
	public OsAccount getOsAccount(long userRowId) throws TskCoreException {

		String queryString = "SELECT * FROM tsk_os_accounts"
				+ " WHERE id = " + userRowId;

		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				throw new IllegalArgumentException(String.format("No user found with  row id = %d ", userRowId));
			} else {
				Long artifactObjId = rs.getLong("artifact_obj_id");
				if (rs.wasNull()) {
					throw new TskCoreException(String.format("No artifact created yet for user, row id = %d ", userRowId));
				}

				// BlackboardArtifact accountArtifact = db.getArtifactById(artifactObjId);
				return new OsAccount(rs.getLong("id"), rs.getLong("data_source_obj_id"), rs.getString("user_name"),
						rs.getString("realm"), rs.getString("unique_id"), rs.getString("signature"), artifactObjId);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting OS user account ", ex);
		}
	}

	/**
	 * Updates the artifact object id for the user with specified row id.
	 *
	 * @param userRowId     Row id of the row to be updated
	 * @param artifactObjId Artifact object id to be updated with.
	 * @param transaction   Transaction to use for database operation.
	 *
	 * @throws TskCoreException
	 */
	public void updateOsAccount(long userRowId, long artifactObjId, CaseDbTransaction transaction) throws TskCoreException {

		CaseDbConnection connection = transaction.getConnection();

		db.acquireSingleUserCaseWriteLock();
		try (Statement updateStatement = connection.createStatement()) {
			connection.executeUpdate(updateStatement, "UPDATE tsk_os_accounts SET artifact_obj_id = " + artifactObjId + " WHERE id = " + userRowId);
		} catch (SQLException ex) {
			LOGGER.log(Level.SEVERE, null, ex);
			throw new TskCoreException(String.format("Error updating user row id %s", userRowId), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}
}
