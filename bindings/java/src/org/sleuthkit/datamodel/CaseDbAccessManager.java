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
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import static org.sleuthkit.datamodel.SleuthkitCase.closeStatement;
import org.sleuthkit.datamodel.TskData.DbType;

/**
 * This class provides modules with access to the case database 
 * to create custom tables/indexes and to query them.
 *
 */
public final class CaseDbAccessManager {
	
	/**
	 *  Callback interface to process the result of DB query run through DBAccessManager
	 */
	public interface CaseDbAccessQueryCallback {

	   /**
		* Processes the ResultSet from CaseDbAccessManager query.
		*
		* This is called synchronously by CaseDbAccessManager, 
		* and should avoid any long running operations.
		* 
		* @param resultSet ResultSet from query.
		*/
	   void process(ResultSet resultSet);

   }


	private static final Logger logger = Logger.getLogger(CaseDbAccessManager.class.getName());

	private final SleuthkitCase tskDB;

	/**
	 * Constructor
	 *
	 * @param skCase The SleuthkitCase
	 *
	 */
	CaseDbAccessManager(SleuthkitCase skCase) {
		this.tskDB = skCase;
	}

	/**
	 * Creates a table with the specified name and schema.
	 * 
	 * If the table already exists, it does nothing, and no error is generated 
	 * 
	 * It is recommended that clients of the API use module specific prefixes
	 * to prevent name collisions.
	 * 
	 * @param tableName name of the table to create
	 * @param tableSchema table schema
	 * 
	 * @throws TskCoreException 
	 */
	public void createTable(final String tableName, final String tableSchema) throws TskCoreException {

		validateTableName(tableName);
		validateSQL(tableSchema);

		CaseDbConnection connection = tskDB.getConnection();
		tskDB.acquireSingleUserCaseWriteLock();

		Statement statement = null;
		String createSQL = "CREATE TABLE IF NOT EXISTS " + tableName + " " + tableSchema;
		try {
			statement = connection.createStatement();
			statement.execute(createSQL);
		} catch (SQLException ex) {
			throw new TskCoreException("Error creating table " + tableName, ex);
		} finally {
			closeStatement(statement);
			connection.close();
			tskDB.releaseSingleUserCaseWriteLock();
		}

	}

	/**
	 * Creates an index on the specified table, on specified column(s).
	 * 
	 * If the index already exists, it does nothing, and no error is generated.
	 * 
	 * It is recommended that clients of the API use module specific prefixes
	 * to prevent name collisions.
	 * 
	 * @param indexName name of index to create
	 * @param tableName name of table to create the index on
	 * @param colsSQL - columns on which to index
	 * 
	 * @throws TskCoreException 
	 */
	public void createIndex(final String indexName, final String tableName, final String colsSQL) throws TskCoreException {

		validateTableName(tableName);
		validateIndexName(indexName);
		validateSQL(colsSQL);

		CaseDbConnection connection = tskDB.getConnection();
		tskDB.acquireSingleUserCaseWriteLock();

		Statement statement = null;
		String indexSQL = "CREATE INDEX IF NOT EXISTS " + indexName + " ON " + tableName + " " + colsSQL; // NON-NLS
		try {
			statement = connection.createStatement();
			statement.execute(indexSQL);
		} catch (SQLException ex) {
			throw new TskCoreException("Error creating index " + tableName, ex);
		} finally {
			closeStatement(statement);
			connection.close();
			tskDB.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Inserts a row in the specified table.
	 * If the primary key is duplicate, the existing row is updated.
	 * 
	 * Note: For PostGreSQL, the caller must include the ON CONFLICT clause to handle 
	 * duplicates
	 * 
	 * @param tableName - table to insert into.
	 * @param sql - SQL string specifying column values.
	 *
	 * @return - rowID of the row inserted/updated
	 *
	 * @throws TskCoreException
	 */
	public long insertOrUpdate(final String tableName, final String sql) throws TskCoreException {
		
		long rowId = 0;

		validateTableName(tableName);
		validateSQL(sql);

		CaseDbConnection connection = tskDB.getConnection();
		tskDB.acquireSingleUserCaseWriteLock();

		PreparedStatement statement = null;
		ResultSet resultSet;
		String insertSQL = "INSERT";
		if (DbType.SQLITE == tskDB.getDatabaseType()) {
			insertSQL += " OR REPLACE";
		}
		
		insertSQL += " INTO " + tableName + " " + sql; // NON-NLS
		try {
			statement = connection.prepareStatement(insertSQL, Statement.RETURN_GENERATED_KEYS);
			connection.executeUpdate(statement);

			resultSet = statement.getGeneratedKeys();
			resultSet.next();
			rowId = resultSet.getLong(1); //last_insert_rowid()
		} catch (SQLException ex) {
			throw new TskCoreException("Error inserting row in table " + tableName + " with sql = "+ insertSQL, ex);
		} finally {
			closeStatement(statement);
			connection.close();
			tskDB.releaseSingleUserCaseWriteLock();
		}

		return rowId;
	}
	
	/**
	 * Updates row(s) in the specified table.
	 * 
	 * @param tableName - table to insert into.
	 * @param sql - SQL string specifying column values and conditions.
	 * 
	 * @throws TskCoreException
	 */
	public void update(final String tableName, final String sql) throws TskCoreException {
		
		validateTableName(tableName);
		validateSQL(sql);

		CaseDbConnection connection = tskDB.getConnection();
		tskDB.acquireSingleUserCaseWriteLock();

		Statement statement = null;
		String updateSQL = "UPDATE " + tableName + " " + sql; // NON-NLS

		try {
			statement = connection.createStatement();
			statement.executeUpdate(updateSQL);
		} catch (SQLException ex) {
			throw new TskCoreException("Error Updating table " + tableName, ex);
		} finally {
			closeStatement(statement);
			connection.close();
			tskDB.releaseSingleUserCaseWriteLock();
		}
	}
	
	/**
	 * Runs the specified SELECT query and then calls the specified callback with the result.
	 * 
	 * @param sql SQL string specifying the columns to select, tables to select from and the WHERE clause.
	 * @param queryCallback Callback object to process the result.
	 * 
	 * @throws TskCoreException 
	 */
	public void select(final String sql, final CaseDbAccessQueryCallback queryCallback) throws TskCoreException {

		if (queryCallback == null) {
            throw new TskCoreException("Callback is null");
        }
		
		validateSQL(sql);
		
		CaseDbConnection connection = tskDB.getConnection();
		tskDB.acquireSingleUserCaseReadLock();

		Statement statement = null;
		ResultSet resultSet;
		String selectSQL = "SELECT " +  sql; // NON-NLS
		try {
			statement = connection.createStatement();
			resultSet = statement.executeQuery(selectSQL);
			queryCallback.process(resultSet);
		} catch (SQLException ex) {
			throw new TskCoreException("Error running SELECT query.", ex);
		} finally {
			closeStatement(statement);
			connection.close();
			tskDB.releaseSingleUserCaseReadLock();
		}
	}
	
	/**
	 * Deletes a row in the specified table.
	 * 
	 * @param tableName table from which to delete the row
	 * @param sql - SQL string specifying the condition to identify the row to delete
	 * 
	 * @throws TskCoreException 
	 */
	public void delete(final String tableName, final String sql ) throws TskCoreException {
		validateTableName(tableName);
		validateSQL(sql);

		CaseDbConnection connection = tskDB.getConnection();
		tskDB.acquireSingleUserCaseWriteLock();

		Statement statement = null;
		String deleteSQL = "DELETE FROM " + tableName + " " + sql; // NON-NLS
		try {
			statement = connection.createStatement();
			statement.executeUpdate(deleteSQL);
		} catch (SQLException ex) {
			throw new TskCoreException("Error deleting row from table " + tableName, ex);
		} finally {
			closeStatement(statement);
			connection.close();
			tskDB.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Validates table name. 
	 * Specifically, it ensures the table doesn't begin with 'tsk_' 
	 * to avoid modifications to core TSK tables
	 * 
	 * @param tableName
	 * @throws TskCoreException 
	 */
	private void validateTableName(String tableName) throws TskCoreException {
		
		// TODO: EUR-1002, we sould be doing a more strigent validation of table name
		if (tableName.toLowerCase().startsWith("tsk_")) {
			throw new TskCoreException("Attempt to modify a core TSK table " + tableName);
		}
	}

	/**
	 * Validates index name. 
	 * Specifically, it ensures the index name doesn't collide with any of our core indexes
	 * in CaseDB
	 * 
	 * @param indexName
	 * @throws TskCoreException 
	 */
	private void validateIndexName(String indexName) throws TskCoreException {
		
		// TODO: EUR-1002 - we should be validating index name against our core index names
		if (indexName.isEmpty()) {
			throw new TskCoreException("Invalid index name " + indexName);	
		}
		
	}
	
	/**
	 * Validates given SQL string.
	 * 
	 * Specifically, it ensurer the SQL  doesn't have a ";" 
	 * 
	 * @param sql
	 * 
	 * @throws TskCoreException 
	 */
	private void validateSQL(String sql) throws TskCoreException {

		if (sql.contains(";")) {
			throw new TskCoreException("SQL unsafe to execute, it contains a ; ");
		}
	}

}
