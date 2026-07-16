/*
 * Sleuth Kit Data Model
 *
 * Copyright 2018-2019 Basis Technology Corp.
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

import com.google.common.annotations.Beta;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Time;
import java.sql.Timestamp;
import java.text.MessageFormat;
import java.sql.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;
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
	 * Checks if a column exists in a table.
	 *
	 * @param tableName name of the table
	 * @param columnName column name to check
	 * 
	 * @return true if the column already exists, false otherwise
	 * @throws TskCoreException 
	 */
	public boolean columnExists(String tableName, String columnName) throws TskCoreException {
		
		boolean doesColumnExists = false;
		CaseDbTransaction localTrans = tskDB.beginTransaction();
        try {
			doesColumnExists = columnExists(tableName, columnName, localTrans);
			localTrans.commit();
			localTrans = null;
        } 
		finally {
			if (null != localTrans) {
				try {
					localTrans.rollback();
				} catch (TskCoreException ex) {
					logger.log(Level.SEVERE, "Failed to rollback transaction after exception", ex);
				}
			}
		}
		
        return doesColumnExists;
    }
	
	/**
	 * Checks if a column exists in a table.
	 *
	 * @param tableName name of the table
	 * @param columnName column name to check
	 * @param transaction transaction 
	 * 
	 * @return true if the column already exists, false otherwise
	 * @throws TskCoreException 
	 */
	public boolean columnExists(String tableName, String columnName, CaseDbTransaction transaction) throws TskCoreException {
		
		boolean columnExists = false;
        Statement statement = null;
		ResultSet resultSet = null;
        try {
			CaseDbConnection connection = transaction.getConnection();
			statement = connection.createStatement();
			if (DbType.SQLITE == tskDB.getDatabaseType()) {
				String tableInfoQuery = "PRAGMA table_info(%s)";  //NON-NLS
				resultSet = statement.executeQuery(String.format(tableInfoQuery, tableName));
				while (resultSet.next()) {
					if (resultSet.getString("name").equalsIgnoreCase(columnName)) {
						columnExists = true;
						break;
					}
				}
			}
			else {
				String tableInfoQueryTemplate = "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='%s' AND column_name='%s')";  //NON-NLS	
				resultSet = statement.executeQuery(String.format(tableInfoQueryTemplate, tableName.toLowerCase(), columnName.toLowerCase()));
				if (resultSet.next()) {
					columnExists = resultSet.getBoolean(1);
				}
			}
        } 
		catch (SQLException ex) {
			throw new TskCoreException("Error checking if column  " + columnName + "exists ", ex);
		} 
		finally {
			if (resultSet != null) {
				try {
					resultSet.close();
				} catch (SQLException ex2) {
					logger.log(Level.WARNING, "Failed to to close resultset after checking column", ex2);
				}
			}
            closeStatement(statement);
        }
        return columnExists;
    }
	
	/**
	 * Checks if a table exists in the case database.
	 *
	 * @param tableName name of the table to check
	 * 
	 * @return true if the table already exists, false otherwise
	 * @throws TskCoreException 
	 */
	public boolean tableExists(String tableName) throws TskCoreException {
		
		boolean doesTableExist = false;
		CaseDbTransaction localTrans = tskDB.beginTransaction();
        try {
			doesTableExist = tableExists(tableName, localTrans);
			localTrans.commit();
			localTrans = null;
        } 
		finally {
			if (null != localTrans) {
				try {
					localTrans.rollback();
				} catch (TskCoreException ex) {
					logger.log(Level.SEVERE, "Failed to rollback transaction after exception", ex); //NON-NLS
				}
			}
		}
		
        return doesTableExist;
    }
	
	/**
	 * Checks if a table exists in the case database.
	 *
	 * @param tableName name of the table to check
	 * @param transaction transaction 
	 * 
	 * @return true if the table already exists, false otherwise
	 * @throws TskCoreException 
	 */
	public boolean tableExists(String tableName, CaseDbTransaction transaction) throws TskCoreException {
		
		boolean tableExists = false;
        Statement statement = null;
		ResultSet resultSet = null;
        try {
			CaseDbConnection connection = transaction.getConnection();
			statement = connection.createStatement();
			if (DbType.SQLITE == tskDB.getDatabaseType()) {
				resultSet = statement.executeQuery("SELECT name FROM sqlite_master WHERE type='table'");  //NON-NLS
				while (resultSet.next()) {
					if (resultSet.getString("name").equalsIgnoreCase(tableName)) { //NON-NLS
						tableExists = true;
						break;
					}
				}
			}
			else {
				String tableInfoQueryTemplate = "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='%s')";  //NON-NLS	
				resultSet = statement.executeQuery(String.format(tableInfoQueryTemplate, tableName.toLowerCase()));
				if (resultSet.next()) {
					tableExists = resultSet.getBoolean(1);
				}
			}
        } 
		catch (SQLException ex) {
			throw new TskCoreException("Error checking if table  " + tableName + "exists ", ex);
		} finally {
			if (resultSet != null) {
				try {
					resultSet.close();
				} catch (SQLException ex2) {
					logger.log(Level.WARNING, "Failed to to close resultset after checking table", ex2);
				}
			}
            closeStatement(statement);
        }
        return tableExists;
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

		tskDB.acquireSingleUserCaseWriteLock();
		String createSQL = "CREATE TABLE IF NOT EXISTS " + tableName + " " + tableSchema;
		try (CaseDbConnection connection = tskDB.getConnection();
				Statement statement = connection.createStatement();) {
			statement.execute(createSQL);
		} catch (SQLException ex) {
			throw new TskCoreException("Error creating table " + tableName, ex);
		} finally {
			tskDB.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Alters a table with the specified name.
	 * 
	 * @param tableName name of the table to alter
	 * @param alterSQL SQL to alter the table
	 * 
	 * @throws TskCoreException 
	 */
	public void alterTable(final String tableName, final String alterSQL) throws TskCoreException {
		
		CaseDbTransaction localTrans = tskDB.beginTransaction();
		try {
			alterTable(tableName, alterSQL, localTrans);
			localTrans.commit();
			localTrans = null;
		} finally {
			if (null != localTrans) {
				try {
					localTrans.rollback();
				} catch (TskCoreException ex) {
					logger.log(Level.SEVERE, "Failed to rollback transaction after exception", ex);
				}
			}
		} 
	}
		
	/**
	 * Alters a table with the specified name.
	 * 
	 * @param tableName name of the table to alter
	 * @param alterSQL SQL to alter the table
	 * @param transaction transaction
	 * 
	 * @throws TskCoreException 
	 */
	public void alterTable(final String tableName, final String alterSQL, final CaseDbTransaction transaction) throws TskCoreException {

		validateTableName(tableName);
		validateSQL(alterSQL);

		CaseDbConnection connection = transaction.getConnection();

		Statement statement = null;
		String sql = "ALTER TABLE " + tableName + " " + alterSQL;
		
		try {
			statement = connection.createStatement();
			statement.execute(sql);
		} catch (SQLException ex) {
			// SQLite occasionally returns false for columnExists() if a table was just created with that column
			// leading to "duplicate column name" exception.
			// We ignore this exception
			if (DbType.SQLITE == tskDB.getDatabaseType() &&
					alterSQL.toLowerCase().contains("add column") &&
					ex.getMessage().toLowerCase().contains("duplicate column name")) {
				logger.log(Level.WARNING, String.format("Column being added by SQL = %s already exists in table %s", alterSQL, tableName));
				return;
			}
			throw new TskCoreException(String.format("Error altering table  %s with SQL = %s", tableName, sql), ex);
		} finally {
			closeStatement(statement);
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

		tskDB.acquireSingleUserCaseWriteLock();
		String indexSQL = "CREATE INDEX IF NOT EXISTS " + indexName + " ON " + tableName + " " + colsSQL; // NON-NLS
		try (CaseDbConnection connection = tskDB.getConnection();
			Statement statement = connection.createStatement(); ) {
			statement.execute(indexSQL);
		} catch (SQLException ex) {
			throw new TskCoreException("Error creating index " + tableName, ex);
		} finally {
			tskDB.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Inserts a row in the specified table.
	 * 
	 * @param tableName - table to insert into.
	 * @param sql - SQL string specifying column values.
	 *
	 * @return - rowID of the row
	 *
	 * @throws TskCoreException
	 */
	public long insert(final String tableName, final String sql) throws TskCoreException {
		
		CaseDbTransaction localTrans = tskDB.beginTransaction();
		try {
			long rowId = insert(tableName, sql, localTrans);
			localTrans.commit();
			localTrans = null;
			return rowId;
		} finally {
			if (null != localTrans) {
				try {
					localTrans.rollback();
				} catch (TskCoreException ex) {
					logger.log(Level.SEVERE, "Failed to rollback transaction after exception", ex);
				}
			}
		} 
		
	}
	
	/**
	 * Inserts a row in the specified table, as part of the specified transaction.
	 * If the primary key is duplicate, it does nothing.
	 * 
	 * Note: For PostGreSQL, the caller must include the ON CONFLICT DO NOTHING clause
	 * 
	 * Caller is responsible for committing the transaction.
	 * 
	 * @param tableName - table to insert into.
	 * @param sql - SQL string specifying column values.
	 * @param transaction transaction in which the insert/update is done
	 *
	 * @return - rowID of the row inserted
	 *
	 * @throws TskCoreException
	 */
	public long insert(final String tableName, final String sql, final CaseDbTransaction transaction) throws TskCoreException {
		long rowId = 0;

		validateTableName(tableName);
		validateSQL(sql);

		CaseDbConnection connection = transaction.getConnection();

		PreparedStatement statement = null;
		ResultSet resultSet;
		String insertSQL = "INSERT";
		if (DbType.SQLITE == tskDB.getDatabaseType()) {
			insertSQL += " OR IGNORE";
		}
		
		insertSQL = insertSQL+ " INTO " + tableName + " " + sql; // NON-NLS
		try {
			statement = connection.prepareStatement(insertSQL, Statement.RETURN_GENERATED_KEYS);
			connection.executeUpdate(statement);
			
			resultSet = statement.getGeneratedKeys();
			if (resultSet.next()) {
				rowId = resultSet.getLong(1); //last_insert_rowid()
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error inserting row in table " + tableName + " with sql = "+ insertSQL, ex);
		} finally {
			closeStatement(statement);
		}

		return rowId;
	}
	
	/**
	 * Inserts a row in the specified table.
	 * If the primary key is duplicate, the existing row is updated.
	 * 
	 * Note: For PostGreSQL, the caller must include the ON CONFLICT UPDATE clause to handle 
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
		
		CaseDbTransaction localTrans = tskDB.beginTransaction();
		try {
			long rowId = insertOrUpdate(tableName, sql, localTrans);
			localTrans.commit();
			localTrans = null;
			return rowId;
		} finally {
			if (null != localTrans) {
				try {
					localTrans.rollback();
				} catch (TskCoreException ex) {
					logger.log(Level.SEVERE, "Failed to rollback transaction after exception", ex);
				}
			}
		} 
		
	}
	
	/**
	 * Inserts a row in the specified table, as part of the specified transaction.
	 * If the primary key is duplicate, the existing row is updated.
	 * Caller is responsible for committing the transaction.
	 * 
	 * Note: For PostGreSQL, the caller must include the ON CONFLICT UPDATE clause to handle 
	 * duplicates
	 * 
	 * @param tableName - table to insert into.
	 * @param sql - SQL string specifying column values.
	 * @param transaction transaction in which the insert/update is done
	 *
	 * @return - rowID of the row inserted/updated
	 *
	 * @throws TskCoreException
	 */
	public long insertOrUpdate(final String tableName, final String sql, final CaseDbTransaction transaction) throws TskCoreException {
		long rowId = 0;

		validateTableName(tableName);
		validateSQL(sql);

		CaseDbConnection connection = transaction.getConnection();

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
		}

		return rowId;
	}
	
	/**
	 * Creates a prepared statement object for the purposes of running an update
	 * statement. The given SQL should not include the starting "UPDATE" 
	 * or the name of the table.
	 *
	 * @param tableName The name of the table being updated.
	 * @param sql       The insert statement without the starting "UPDATE (table name)" part.
	 * @param trans     The open transaction.
	 *
	 * @return The prepared statement object.
	 *
	 * @throws TskCoreException
	 */
	@Beta
	public CaseDbPreparedStatement prepareUpdate(String tableName, String sql, CaseDbTransaction trans) throws TskCoreException {
		validateTableName(tableName);
		validateSQL(sql);

		String updateSQL = "UPDATE " + tableName + " " + sql; // NON-NLS
	
		try {
			return new CaseDbPreparedStatement(StatementType.UPDATE, updateSQL, trans);
		} catch (SQLException ex) {
			throw new TskCoreException("Error creating update prepared statement for query:\n" + updateSQL, ex);
		}
	}
	
	/**
	 * Performs an update statement query with the given case prepared statement.
	 *
	 * @param preparedStatement The case prepared statement.
	 * 
	 * @throws TskCoreException
	 */
	@Beta
	public void update(CaseDbPreparedStatement preparedStatement) throws TskCoreException {
		
		if (!preparedStatement.getType().equals(StatementType.UPDATE)) {
			throw new TskCoreException("CaseDbPreparedStatement has incorrect type for update operation");
		}
		
		try {
			preparedStatement.getStatement().executeUpdate();
		} catch (SQLException ex) {
			throw new TskCoreException("Error updating row in table " + "" + " with sql = "+ "", ex);
		}
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
		CaseDbTransaction localTrans = tskDB.beginTransaction();
		try {
			update(tableName, sql, localTrans);
			localTrans.commit();
			localTrans = null;
		} finally {
			if (null != localTrans) {
				try {
					localTrans.rollback();
				} catch (TskCoreException ex) {
					logger.log(Level.SEVERE, "Failed to rollback transaction after exception", ex);
				}
			}
		} 
	}
	

	/**
	 * Updates row(s) in the specified table, as part of the specified transaction.
	 * Caller is responsible for committing the transaction.
	 * 
	 * @param tableName - table to insert into.
	 * @param sql - SQL string specifying column values and conditions.
	 * @param transaction - transaction under which the update is performed.
	 * 
	 * @throws TskCoreException
	 */
	public void update(final String tableName, final String sql, CaseDbTransaction transaction ) throws TskCoreException {
		
		validateTableName(tableName);
		validateSQL(sql);

		CaseDbConnection connection = transaction.getConnection();

		Statement statement = null;
		String updateSQL = "UPDATE " + tableName + " " + sql; // NON-NLS

		try {
			statement = connection.createStatement();
			statement.executeUpdate(updateSQL);
		} catch (SQLException ex) {
			throw new TskCoreException("Error Updating table " + tableName, ex);
		} finally {
			closeStatement(statement);
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
		
		tskDB.acquireSingleUserCaseReadLock();
		String selectSQL = "SELECT " +  sql; // NON-NLS
		try (CaseDbConnection connection = tskDB.getConnection();
			Statement statement = connection.createStatement();
			ResultSet resultSet = statement.executeQuery(selectSQL)) {
			queryCallback.process(resultSet);
		} catch (SQLException ex) {
			throw new TskCoreException("Error running SELECT query.", ex);
		} finally {
			tskDB.releaseSingleUserCaseReadLock();
		}
	}
	
	/**
	 * Creates a prepared statement object for the purposes of running a select
	 * statement.
	 *
	 * NOTE: Creating the CaseDbPreparedStatement opens a connection and
	 * acquires a read lock on the case database. For this reason, it is
	 * recommended to close the prepared statement as soon as it is no longer
	 * needed, through either a try-with-resources block or calling close().
	 * Additionally, calling other methods that access or update the database
	 * should be avoided while the prepared statement is open to prevent
	 * possible deadlocks.
	 *
	 * @param sql The select statement without the starting select keyword.
	 *
	 * @return The prepared statement object.
	 *
	 * @throws TskCoreException
	 */
	@Beta
	public CaseDbPreparedStatement prepareSelect(String sql) throws TskCoreException {
		String selectSQL = "SELECT " + sql; // NON-NLS
		try {
			return new CaseDbPreparedStatement(StatementType.SELECT, selectSQL, false);
		} catch (SQLException ex) {
			throw new TskCoreException("Error creating select prepared statement for query:\n" + selectSQL, ex);
		}
	}
	
	/**
	 * Creates a prepared statement object for the purposes of running a select
	 * statement. The given SQL should not include the starting "SELECT" keyword.
	 *
	 * @param sql       The select statement without the starting select keyword.
	 * @param trans     The open transaction.
	 *
	 * @return The prepared statement object.
	 *
	 * @throws TskCoreException
	 */
	@Beta
	public CaseDbPreparedStatement prepareSelect(String sql, CaseDbTransaction trans) throws TskCoreException {
		validateSQL(sql);

		String selectSQL = "SELECT " + sql; // NON-NLS

		try {
			return new CaseDbPreparedStatement(StatementType.SELECT, selectSQL, trans);
		} catch (SQLException ex) {
			throw new TskCoreException("Error creating select prepared statement for query:\n" + selectSQL, ex);
		}
	}


	/**
	 * Performs a select statement query with the given case prepared statement.
	 *
	 * @param preparedStatement The case prepared statement.
	 * @param queryCallback     The callback to handle the result set.
	 *
	 * @throws TskCoreException
	 */
	@Beta
	public void select(CaseDbPreparedStatement preparedStatement, CaseDbAccessQueryCallback queryCallback) throws TskCoreException {
		if (!preparedStatement.getType().equals(StatementType.SELECT)) {
			throw new TskCoreException("CaseDbPreparedStatement has incorrect type for select operation");
		}
		
		try (ResultSet resultSet = preparedStatement.getStatement().executeQuery()) {
			queryCallback.process(resultSet);
		} catch (SQLException ex) {
			throw new TskCoreException(MessageFormat.format("Error running SELECT query:\n{0}", preparedStatement.getOriginalSql()), ex);
		}
	}
	
	/**
	 * Refreshes the case database's query-planner statistics so queries that run
	 * after a large data change (bulk insert/update/delete) plan against
	 * up-to-date row estimates instead of stale ones. Single entry point for both
	 * database types.
	 *
	 * PostgreSQL: a plain ANALYZE. Statistics are server-side, so the refresh is
	 * immediately visible to every pooled connection.
	 *
	 * SQLite: a bounded ANALYZE (PRAGMA analysis_limit caps the rows sampled per
	 * index, keeping it fast and the write-lock hold short), gated by the
	 * single-user write lock like every other SQLite write. SQLite caches
	 * sqlite_stat1 per connection at schema-parse time, so the connection pool is
	 * then soft-reset to make later connections re-read the refreshed statistics.
	 *
	 * @throws TskCoreException
	 */
	@Beta
	public void refreshQueryPlannerStats() throws TskCoreException {
		if (tskDB.getDatabaseType() == DbType.SQLITE) {
			tskDB.acquireSingleUserCaseWriteLock();
			try {
				try (CaseDbConnection connection = tskDB.getConnection();
						Statement statement = connection.createStatement()) {
					statement.execute("PRAGMA analysis_limit=600");
					statement.executeUpdate("ANALYZE");
				} catch (SQLException ex) {
					throw new TskCoreException("An error occurred while attempting to run ANALYZE", ex);
				}
				// sqlite_stat1 is cached per connection at schema-parse time; recycle idle
				// pooled connections so later queries re-read the refreshed statistics.
				tskDB.softResetCaseDbConnectionPool();
			} finally {
				tskDB.releaseSingleUserCaseWriteLock();
			}
		} else {
			CaseDbTransaction localTrans = tskDB.beginTransaction();

			try {
				CaseDbConnection connection = localTrans.getConnection();

				try (Statement statement = connection.createStatement()) {
					statement.executeUpdate("ANALYZE");
				} catch (SQLException ex) {
					throw new TskCoreException("An error occurred while attempting to run ANALYZE", ex);
				}
				localTrans.commit();
				localTrans = null;
			} finally {
				if (null != localTrans) {
					try {
						localTrans.rollback();
					} catch (TskCoreException ex) {
						logger.log(Level.SEVERE, "Failed to rollback transaction after exception", ex);
					}
				}
			}
		}
	}
	
	/**
	 * Creates a prepared statement object for the purposes of running an insert
	 * statement. The given SQL should not include the starting "INSERT INTO" 
	 * or the name of the table.
	 * 
	 * For PostGreSQL, the caller must include the ON CONFLICT DO NOTHING clause
	 *
	 * @param tableName The name of the table being updated.
	 * @param sql       The insert statement without the starting "INSERT INTO (table name)" part.
	 * @param trans     The open transaction.
	 *
	 * @return The prepared statement object.
	 *
	 * @throws TskCoreException
	 */
	@Beta
	public CaseDbPreparedStatement prepareInsert(String tableName, String sql, CaseDbTransaction trans) throws TskCoreException {
		validateTableName(tableName);
		validateSQL(sql);
		
		String insertSQL = "INSERT";
		if (DbType.SQLITE == tskDB.getDatabaseType()) {
			insertSQL += " OR IGNORE";
		}
		insertSQL = insertSQL + " INTO " + tableName + " " + sql; // NON-NLS
	
		try {
			return new CaseDbPreparedStatement(StatementType.INSERT, insertSQL, trans);
		} catch (SQLException ex) {
			throw new TskCoreException("Error creating insert prepared statement for query:\n" + insertSQL, ex);
		}
	}
	
	/**
	 * Performs a insert statement query with the given case prepared statement.
	 *
	 * @param preparedStatement The case prepared statement.
	 * 
	 * @throws TskCoreException
	 */
	@Beta
	public void insert(CaseDbPreparedStatement preparedStatement) throws TskCoreException {

		if (!preparedStatement.getType().equals(StatementType.INSERT)) {
			throw new TskCoreException("CaseDbPreparedStatement has incorrect type for insert operation");
		}

		try {
			preparedStatement.getStatement().executeUpdate();
		} catch (SQLException ex) {
			throw new TskCoreException("Error inserting row in table " + "" + " with sql = "+ "", ex);
		}
	}

	/**
	 * Adds the current parameter state of the prepared statement to its
	 * driver-side batch. Does not execute. The caller is expected to call
	 * {@link #insertBatch} once a batch's worth of rows has been added.
	 *
	 * <p>Mirrors {@link #insert(CaseDbPreparedStatement)} — the statement
	 * must be of INSERT type. Use the usual {@code setLong}/{@code setString}/...
	 * methods on the {@code CaseDbPreparedStatement} between {@code addToBatch}
	 * calls to bind each row. Every column should be rebound for every row.</p>
	 *
	 * @param preparedStatement INSERT-type case prepared statement.
	 *
	 * @throws TskCoreException if the statement is not of INSERT type, or
	 *                          if the underlying {@code addBatch} call fails.
	 */
	@Beta
	public void addToBatch(CaseDbPreparedStatement preparedStatement) throws TskCoreException {

		if (!preparedStatement.getType().equals(StatementType.INSERT)) {
			throw new TskCoreException("CaseDbPreparedStatement has incorrect type for batch insert operation");
		}

		try {
			preparedStatement.getStatement().addBatch();
		} catch (SQLException ex) {
			throw new TskCoreException("Error adding row to batch", ex);
		}
	}

	/**
	 * Executes the accumulated batch on the prepared statement and returns
	 * the per-row update counts.
	 *
	 * <p>On PostgreSQL with the JDBC URL parameter
	 * {@code reWriteBatchedInserts=true} set on the case-DB connection pool,
	 * the driver fuses the batched rows into a single multi-VALUES INSERT at
	 * the wire level. Without that flag, {@code executeBatch} still sends one
	 * INSERT statement per row; the round-trip cost is unchanged.</p>
	 *
	 * <p>This method does NOT return generated keys. Callers using batch
	 * insert must supply their own row identifiers.</p>
	 *
	 * <p>Failure semantics: if the underlying {@code executeBatch} throws,
	 * this method wraps the exception in a {@link TskCoreException}. The
	 * transaction is left as the caller configured it; the caller is
	 * responsible for rolling back on failure (same contract as
	 * {@link #insert(CaseDbPreparedStatement)}).</p>
	 *
	 * @param preparedStatement INSERT-type case prepared statement.
	 *
	 * @return Per-row update counts as returned by
	 *         {@link PreparedStatement#executeBatch}.
	 *
	 * @throws TskCoreException if the statement is not of INSERT type, or
	 *                          if the underlying {@code executeBatch} fails.
	 */
	@Beta
	public int[] insertBatch(CaseDbPreparedStatement preparedStatement) throws TskCoreException {

		if (!preparedStatement.getType().equals(StatementType.INSERT)) {
			throw new TskCoreException("CaseDbPreparedStatement has incorrect type for batch insert operation");
		}

		try {
			return preparedStatement.getStatement().executeBatch();
		} catch (SQLException ex) {
			throw new TskCoreException("Error executing batch insert", ex);
		}
	}

	/**
	 * Returns a conservative upper bound on the number of rows that can be
	 * accumulated via {@link #addToBatch} before {@link #insertBatch} must be
	 * called.
	 *
	 * <p>The bound is derived from the prepared statement's parameter count
	 * and the PostgreSQL wire-protocol ceiling of 65,535 bind parameters per
	 * statement. With {@code reWriteBatchedInserts=true} the driver fuses
	 * batched rows into a single multi-VALUES INSERT, and each batched row
	 * contributes its columns as bind parameters, so the row ceiling is
	 * approximately {@code 65,535 / columns}. A small margin is left below
	 * the wire-level ceiling for safety.</p>
	 *
	 * <p>This bound does NOT account for driver-side memory pressure from
	 * large string or blob columns. Callers writing wide rows with large
	 * payloads (e.g. JSON, long text) should cap further at their own
	 * discretion.</p>
	 *
	 * <p>SQLite has different parameter ceilings, but its JDBC driver
	 * executes batches as a loop of single-row updates, so this bound is
	 * not strictly necessary there; the value returned is still safe to
	 * use.</p>
	 *
	 * @param preparedStatement Any case prepared statement.
	 *
	 * @return Maximum rows per batch driven by the PostgreSQL bind-parameter
	 *         ceiling. Returns {@link Integer#MAX_VALUE} if the statement has
	 *         no bind parameters.
	 *
	 * @throws TskCoreException if parameter metadata cannot be retrieved.
	 */
	@Beta
	public int getMaxBatchSize(CaseDbPreparedStatement preparedStatement) throws TskCoreException {
		try {
			int paramsPerRow = preparedStatement.getStatement().getParameterMetaData().getParameterCount();
			if (paramsPerRow <= 0) {
				return Integer.MAX_VALUE;
			}
			return Math.max(1, 65000 / paramsPerRow);
		} catch (SQLException ex) {
			throw new TskCoreException("Error determining max batch size for prepared statement", ex);
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

		tskDB.acquireSingleUserCaseWriteLock();
		String deleteSQL = "DELETE FROM " + tableName + " " + sql; // NON-NLS
		try (CaseDbConnection connection = tskDB.getConnection();
			Statement statement = connection.createStatement();) {
			statement.executeUpdate(deleteSQL);
		} catch (SQLException ex) {
			throw new TskCoreException("Error deleting row from table " + tableName, ex);
		} finally {
			tskDB.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Validates table name. 
	 * Specifically, it ensures the table doesn't begin with 'tsk_' 
	 * to avoid modifications to core TSK tables
	 * 
	 * @param tableName
	 * @throws TskCoreException, if the table name is invalid.
	 */
	private void validateTableName(String tableName) throws TskCoreException {
		
		if (SleuthkitCase.getCoreTableNames().contains(tableName.toLowerCase())) {
			throw new TskCoreException("Attempt to modify a core TSK table " + tableName);
		}
		if (tableName.toLowerCase().startsWith("tsk_")) {
			throw new TskCoreException("Modifying tables with tsk_ prefix is not allowed. ");
		}
	}

	/**
	 * Validates index name. 
	 * Specifically, it ensures the index name doesn't collide with any of our core indexes
	 * in CaseDB
	 * 
	 * @param indexName
	 * @throws TskCoreException, if the index name is invalid.
	 */
	private void validateIndexName(String indexName) throws TskCoreException {
		
		if (indexName.isEmpty()) {
			throw new TskCoreException("Invalid index name " + indexName);	
		}
		
		if (SleuthkitCase.getCoreIndexNames().contains(indexName.toLowerCase())) {
			throw new TskCoreException("Attempt to modify a core TSK index " + indexName);	
		}
	}
	
	/**
	 * Validates given SQL string.
	 * 
	 * @param sql The SQL to validate.
	 * 
	 * @throws TskCoreException Thrown if the SQL is not valid.
	 */
	private void validateSQL(String sql) throws TskCoreException {
		/*
		 * TODO (JIRA-5950): Need SQL injection defense in CaseDbAccessManager 
		 */
	}
	
	/**
	 * Enum to track which type of lock the CaseDbPreparedStatement holds.
	 */
	private enum LockType {
		READ,
		WRITE,
		NONE;
	}
	
	/**
	 * Enum to track which type of statement the CaseDbPreparedStatement holds.
	 */
	private enum StatementType {
		SELECT,
		INSERT,
		UPDATE;
	}
	
	/**
	 * A wrapper around a PreparedStatement to execute queries against the
	 * database.
	 */
	@Beta
	public class CaseDbPreparedStatement implements AutoCloseable {

		private final CaseDbConnection connection;
		private final PreparedStatement preparedStatement;
		private final String originalSql;
		private final LockType lockType;
		private final StatementType type;
		
		/**
		 * Construct a prepared statement. This should not be used if a transaction
		 * is already open.
		 *
		 * NOTE: Creating the CaseDbPreparedStatement opens a connection and
		 * acquires a read lock on the case database. For this reason, it is
		 * recommended to close the prepared statement as soon as it is no
		 * longer needed, through either a try-with-resources block or calling
		 * close(). Additionally, calling other methods that access or update
		 * the database should be avoided while the prepared statement is open
		 * to prevent possible deadlocks.
		 *
		 * @param type                The type of statement.
		 * @param query               The query string.
		 * @param isWriteLockRequired Whether or not a write lock is required.
		 *                            If a write lock is not required, just a
		 *                            read lock is acquired.
		 *
		 * @throws SQLException
		 * @throws TskCoreException
		 */
		private CaseDbPreparedStatement(StatementType type, String query, boolean isWriteLockRequired) throws SQLException, TskCoreException {		
			if (isWriteLockRequired) {
				CaseDbAccessManager.this.tskDB.acquireSingleUserCaseWriteLock();
				this.lockType = LockType.WRITE;
			} else {
				CaseDbAccessManager.this.tskDB.acquireSingleUserCaseReadLock();
				this.lockType = LockType.READ;
			}
			this.connection = tskDB.getConnection();
			this.preparedStatement = connection.getPreparedStatement(query, Statement.NO_GENERATED_KEYS);
			this.originalSql = query;
			this.type = type;
		}
		
		/**
		 * Construct a prepared statement using an already open transaction.
		 *
		 * @param type                The type of statement.
		 * @param query               The query string.
		 * @param trans               The open transaction.
		 *
		 * @throws SQLException
		 * @throws TskCoreException
		 */
		private CaseDbPreparedStatement(StatementType type, String query, CaseDbTransaction trans) throws SQLException, TskCoreException {		
			this.lockType = LockType.NONE;
			this.connection = trans.getConnection();
			this.preparedStatement = connection.getPreparedStatement(query, Statement.NO_GENERATED_KEYS);
			this.originalSql = query;
			this.type = type;
		}

		/**
		 * Returns the delegate prepared statement.
		 *
		 * @return The delegate prepared statement.
		 */
		private PreparedStatement getStatement() {
			return preparedStatement;
		}
		
		/**
		 * Get the type of statement.
		 * 
		 * @return The statement type (select or insert).
		 */
		private StatementType getType() {
			return type;
		}

		/**
		 * Returns the original sql query.
		 *
		 * @return The original sql query.
		 */
		private String getOriginalSql() {
			return originalSql;
		}
		
		/**
		 * Resets the parameters in the prepared statement.
		 *
		 * @throws TskCoreException
		 */
		public void reset() throws TskCoreException {
			try {
				preparedStatement.clearParameters();
			} catch (SQLException ex) {
				throw new TskCoreException("An error occurred while clearing parameters.", ex);
			}
		}

		/**
		 * Sets the value at the given parameter index to the given value.
		 *
		 * @param parameterIndex The index.
		 * @param x              The value to set at that index.
		 *
		 * @throws TskCoreException
		 */
		public void setBoolean(int parameterIndex, boolean x) throws TskCoreException {
			try {
				preparedStatement.setBoolean(parameterIndex, x);
			} catch (SQLException ex) {
				throw new TskCoreException(MessageFormat.format("There was an error setting the value at index: {0} to {1}", parameterIndex, x), ex);
			}
		}

		/**
		 * Sets the value at the given parameter index to the given value.
		 *
		 * @param parameterIndex The index.
		 * @param x              The value to set at that index.
		 *
		 * @throws TskCoreException
		 */
		public void setByte(int parameterIndex, byte x) throws TskCoreException {
			try {
				preparedStatement.setByte(parameterIndex, x);
			} catch (SQLException ex) {
				throw new TskCoreException(MessageFormat.format("There was an error setting the value at index: {0} to {1}", parameterIndex, x), ex);
			}
		}

		/**
		 * Sets the value at the given parameter index to the given value.
		 *
		 * @param parameterIndex The index.
		 * @param x              The value to set at that index.
		 *
		 * @throws TskCoreException
		 */
		public void setInt(int parameterIndex, int x) throws TskCoreException {
			try {
				preparedStatement.setInt(parameterIndex, x);
			} catch (SQLException ex) {
				throw new TskCoreException(MessageFormat.format("There was an error setting the value at index: {0} to {1}", parameterIndex, x), ex);
			}
		}

		/**
		 * Sets the value at the given parameter index to the given value.
		 *
		 * @param parameterIndex The index.
		 * @param x              The value to set at that index.
		 *
		 * @throws TskCoreException
		 */
		public void setLong(int parameterIndex, long x) throws TskCoreException {
			try {
				preparedStatement.setLong(parameterIndex, x);
			} catch (SQLException ex) {
				throw new TskCoreException(MessageFormat.format("There was an error setting the value at index: {0} to {1}", parameterIndex, x), ex);
			}
		}

		/**
		 * Sets the value at the given parameter index to the given value.
		 *
		 * @param parameterIndex The index.
		 * @param x              The value to set at that index.
		 *
		 * @throws TskCoreException
		 */
		public void setDouble(int parameterIndex, double x) throws TskCoreException {
			try {
				preparedStatement.setDouble(parameterIndex, x);
			} catch (SQLException ex) {
				throw new TskCoreException(MessageFormat.format("There was an error setting the value at index: {0} to {1}", parameterIndex, x), ex);
			}
		}

		/**
		 * Sets the value at the given parameter index to the given value.
		 *
		 * @param parameterIndex The index.
		 * @param x              The value to set at that index.
		 *
		 * @throws TskCoreException
		 */
		public void setString(int parameterIndex, String x) throws TskCoreException {
			try {
				preparedStatement.setString(parameterIndex, x);
			} catch (SQLException ex) {
				throw new TskCoreException(MessageFormat.format("There was an error setting the value at index: {0} to {1}", parameterIndex, x), ex);
			}
		}

		/**
		 * Sets the value at the given parameter index to the given value.
		 *
		 * @param parameterIndex The index.
		 * @param x              The value to set at that index.
		 *
		 * @throws TskCoreException
		 */
		public void setDate(int parameterIndex, Date x) throws TskCoreException {
			try {
				preparedStatement.setDate(parameterIndex, x);
			} catch (SQLException ex) {
				throw new TskCoreException(MessageFormat.format("There was an error setting the value at index: {0} to {1}", parameterIndex, x), ex);
			}
		}

		/**
		 * Sets the value at the given parameter index to the given value.
		 *
		 * @param parameterIndex The index.
		 * @param x              The value to set at that index.
		 *
		 * @throws TskCoreException
		 */
		public void setTime(int parameterIndex, Time x) throws TskCoreException {
			try {
				preparedStatement.setTime(parameterIndex, x);
			} catch (SQLException ex) {
				throw new TskCoreException(MessageFormat.format("There was an error setting the value at index: {0} to {1}", parameterIndex, x), ex);
			}
		}

		/**
		 * Sets the value at the given parameter index to the given value.
		 *
		 * @param parameterIndex The index.
		 * @param x              The value to set at that index.
		 *
		 * @throws TskCoreException
		 */
		public void setTimestamp(int parameterIndex, Timestamp x) throws TskCoreException {
			try {
				preparedStatement.setTimestamp(parameterIndex, x);
			} catch (SQLException ex) {
				throw new TskCoreException(MessageFormat.format("There was an error setting the value at index: {0} to {1}", parameterIndex, x), ex);
			}
		}

		/**
		 * Sets the value at the given parameter index to the given value. The
		 * sql type is determined in the same manner as
		 * java.sql.PreparedStatement.setObject.
		 *
		 * @param parameterIndex The index.
		 * @param x              The value to set at that index.
		 *
		 * @throws TskCoreException
		 */
		public void setObject(int parameterIndex, Object x) throws TskCoreException {
			try {
				preparedStatement.setObject(parameterIndex, x);
			} catch (SQLException ex) {
				throw new TskCoreException(MessageFormat.format("There was an error setting the value at index: {0} to {1}", parameterIndex, x), ex);
			}
		}

		@Override
		public void close() throws SQLException {
			
			// Don't close the statement/connection or release a lock if we were supplied a transaction.
			// Everything will be handled when the transaction is closed.
			if (lockType.equals(LockType.NONE)) {
				return;
			}
			
			connection.close();
			if (lockType.equals(LockType.WRITE)) {
				CaseDbAccessManager.this.tskDB.releaseSingleUserCaseWriteLock();
			} else {
				CaseDbAccessManager.this.tskDB.releaseSingleUserCaseReadLock();
			}
		}
	}

}
