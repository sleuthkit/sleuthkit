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

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.databaseutils.DatabaseQueryHelper;
import org.sleuthkit.datamodel.databaseutils.PostgreSQLQueryHelper;
import org.sleuthkit.datamodel.databaseutils.SQLiteQueryHelper;

/**
 *
 */
class CaseDatabaseFactory {
	private static final Logger logger = Logger.getLogger(CaseDatabaseFactory.class.getName());
	
	private final DatabaseQueryHelper dbQueryHelper;
	private final DbCreationHelper dbCreationHelper;
		
	/**
	 * Create a new SQLite case
	 * 
	 * @param dbPath Full path to the database
	 */
	CaseDatabaseFactory(String dbPath) {		
		this.dbQueryHelper = new SQLiteQueryHelper();
		this.dbCreationHelper = new SQLiteDbCreationHelper(dbPath);
	}
	
	/**
	 * Create a new PostgreSQL case
	 * 
	 * @param caseName    The name of the case. It will be used to create a case
	 *                    database name that can be safely used in SQL commands
	 *                    and will not be subject to name collisions on the case
	 *                    database server. Use getDatabaseName to get the
	 *                    created name.
	 * @param info        The information to connect to the database.
	 * @param caseDirPath The case directory path.
	 */
	CaseDatabaseFactory(String caseName, CaseDbConnectionInfo info, String caseDirPath) {
		this.dbQueryHelper = new PostgreSQLQueryHelper();
		this.dbCreationHelper = new PostgreSQLDbCreationHelper(caseName, info, caseDirPath);
	}
	
	/**
	 * Creates and initializes the case database.
	 * Currently the case must be reopened after creation.
	 * 
	 * @throws TskCoreException 
	 */
	void createCaseDatabase() throws TskCoreException {
		
		createDatabase();
		initializeSchema();
	}
	
	/**
	 * Create the database
	 * 
	 * @throws TskCoreException 
	 */
	private void createDatabase() throws TskCoreException {
		dbCreationHelper.createDatabase();
	}
	
	/**
	 * Initialize the database schema
	 * 
	 * @throws TskCoreException 
	 */
	private void initializeSchema() throws TskCoreException {
		Connection conn = dbCreationHelper.getConnection();
		if (conn == null) {
			throw new TskCoreException("Error connecting to database");
		}
		
		try {
			// Perform any needed steps before creating the tables
			dbCreationHelper.performPreInitialization(conn);

			// Add schema version
			addDbInfo(conn);

			// Add tables
			addTables(conn);
			dbCreationHelper.performPostTableInitialization(conn);
		
			// Add indexes
			createIndexes(conn);
		
		} finally {
			try {
				conn.close();
			} catch (SQLException ex) {
				logger.log(Level.SEVERE, "Error closing connection.", ex);
			}
		}
	}
	
	/**
	 * Create and populate the db_info tables
	 * 
	 * @param conn the database connection
	 * 
	 * @throws TskCoreException 
	 */
	private void addDbInfo(Connection conn) throws TskCoreException {
		
		/* Version of code in number form.
		 * Upper byte is A, next is B, and next byte is C in version A.B.C.
		 * Lowest byte is 0xff, except in beta releases, in which case it
		 * increments from 1.  
		 * For example, 3.1.2 would be stored as 0x030102FF.
		 */
		CaseDbSchemaVersionNumber version = SleuthkitCase.CURRENT_DB_SCHEMA_VERSION;
		long tskVersionNum = version.getMajor() << 24
								| version.getMinor() << 16
								| version.getPatch() << 8
								| 0xff;
		
		try (Statement stmt = conn.createStatement()) {
			stmt.execute("CREATE TABLE tsk_db_info (schema_ver INTEGER, tsk_ver INTEGER, schema_minor_ver INTEGER)");
			stmt.execute("INSERT INTO tsk_db_info (schema_ver, tsk_ver, schema_minor_ver) VALUES (" + 
					version.getMajor() + ", " + tskVersionNum + ", " + version.getMinor() + ");");

			stmt.execute("CREATE TABLE tsk_db_info_extended (name TEXT PRIMARY KEY, value TEXT NOT NULL);");
			stmt.execute("INSERT INTO tsk_db_info_extended (name, value) VALUES ('TSK_VERSION', '" + tskVersionNum + "');");
			stmt.execute("INSERT INTO tsk_db_info_extended (name, value) VALUES ('SCHEMA_MAJOR_VERSION', '" + version.getMajor() + "');");
			stmt.execute("INSERT INTO tsk_db_info_extended (name, value) VALUES ('SCHEMA_MINOR_VERSION', '" + version.getMinor() + "');");
			stmt.execute("INSERT INTO tsk_db_info_extended (name, value) VALUES ('CREATION_SCHEMA_MAJOR_VERSION', '" + version.getMajor() + "');");
			stmt.execute("INSERT INTO tsk_db_info_extended (name, value) VALUES ('CREATION_SCHEMA_MINOR_VERSION', '" + version.getMinor() + "');");
		} catch (SQLException ex) {
			throw new TskCoreException("Error initializing db_info tables", ex);
		}
	}
	
	/**
	 * Add and initialize the database tables 
	 * 
	 * @param conn the database connection
	 * 
	 * @throws TskCoreException 
	 */
	private void addTables(Connection conn) throws TskCoreException {
		try (Statement stmt = conn.createStatement()) {
			stmt.execute("CREATE TABLE tsk_objects (obj_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, par_obj_id " + dbQueryHelper.getBigIntType() 
					+ ", type INTEGER NOT NULL, FOREIGN KEY (par_obj_id) REFERENCES tsk_objects (obj_id) ON DELETE CASCADE)");
			
			stmt.execute("CREATE TABLE tsk_image_info (obj_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, type INTEGER, ssize INTEGER, " 
					+ "tzone TEXT, size " + dbQueryHelper.getBigIntType() + ", md5 TEXT, sha1 TEXT, sha256 TEXT, display_name TEXT, "
					+ "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE)");
            
			stmt.execute("CREATE TABLE tsk_image_names (obj_id " + dbQueryHelper.getBigIntType() + " NOT NULL, name TEXT NOT NULL, "
					+ "sequence INTEGER NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE)");
            
			stmt.execute("CREATE TABLE tsk_vs_info (obj_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, vs_type INTEGER NOT NULL, "
					+ "img_offset " + dbQueryHelper.getBigIntType() + " NOT NULL, block_size BIGINT NOT NULL, "
					+ "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE)");
            
			stmt.execute("CREATE TABLE data_source_info (obj_id " + dbQueryHelper.getBigIntType() + " PRIMARY KEY, device_id TEXT NOT NULL, "
					+ "time_zone TEXT NOT NULL, acquisition_details TEXT, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE)");
            
			stmt.execute("CREATE TABLE tsk_fs_info (obj_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
					+ "img_offset " + dbQueryHelper.getBigIntType() + " NOT NULL, fs_type INTEGER NOT NULL, block_size BIGINT NOT NULL, "
					+ "block_count BIGINT NOT NULL, root_inum BIGINT NOT NULL, first_inum BIGINT NOT NULL, last_inum BIGINT NOT NULL, "
					+ "display_name TEXT, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE)");
            
			stmt.execute("CREATE TABLE tsk_files (obj_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
					+ "fs_obj_id " + dbQueryHelper.getBigIntType() + ", data_source_obj_id BIGINT NOT NULL, attr_type INTEGER, attr_id INTEGER, " 
					+ "name TEXT NOT NULL, meta_addr BIGINT, meta_seq BIGINT, type INTEGER, has_layout INTEGER, has_path INTEGER, "
					+ "dir_type INTEGER, meta_type INTEGER, dir_flags INTEGER, meta_flags INTEGER, size BIGINT, ctime BIGINT, "
					+ "crtime BIGINT, atime BIGINT, mtime BIGINT, mode INTEGER, uid INTEGER, gid INTEGER, md5 TEXT, known INTEGER, "
					+ "parent_path TEXT, mime_type TEXT, extension TEXT, "
					+ "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE, "
					+ "FOREIGN KEY(fs_obj_id) REFERENCES tsk_fs_info(obj_id) ON DELETE CASCADE, "
					+ "FOREIGN KEY(data_source_obj_id) REFERENCES data_source_info(obj_id) ON DELETE CASCADE)");
            
			stmt.execute("CREATE TABLE file_encoding_types (encoding_type INTEGER PRIMARY KEY, name TEXT NOT NULL)");
            
			stmt.execute("CREATE TABLE tsk_files_path (obj_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, path TEXT NOT NULL, "
					+ "encoding_type INTEGER, FOREIGN KEY(encoding_type) references file_encoding_types(encoding_type), "
					+ "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE)");
            
			stmt.execute("CREATE TABLE tsk_files_derived (obj_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
					+ "derived_id " + dbQueryHelper.getBigIntType() + " NOT NULL, rederive TEXT, "
					+ "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE)");
			
			stmt.execute("CREATE TABLE tsk_files_derived_method (derived_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
				+ "tool_name TEXT NOT NULL, tool_version TEXT NOT NULL, other TEXT)");
       
			stmt.execute("CREATE TABLE tag_names (tag_name_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, display_name TEXT UNIQUE, "
					+ "description TEXT NOT NULL, color TEXT NOT NULL, knownStatus INTEGER NOT NULL)");

			stmt.execute("CREATE TABLE blackboard_artifact_types (artifact_type_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
					+ "type_name TEXT NOT NULL, display_name TEXT)");
 
			stmt.execute("CREATE TABLE blackboard_attribute_types (attribute_type_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
					+ "type_name TEXT NOT NULL, display_name TEXT, value_type INTEGER NOT NULL)");
			
			stmt.execute("CREATE TABLE review_statuses (review_status_id INTEGER PRIMARY KEY, "
					+ "review_status_name TEXT NOT NULL, "
					+ "display_name TEXT NOT NULL)");
            
			stmt.execute("CREATE TABLE blackboard_artifacts (artifact_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
					+ "obj_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
					+ "artifact_obj_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
					+ "data_source_obj_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
					+ "artifact_type_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
					+ "review_status_id INTEGER NOT NULL, "
					+ "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE, "
					+ "FOREIGN KEY(artifact_obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE, "
					+ "FOREIGN KEY(data_source_obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE, "
					+ "FOREIGN KEY(artifact_type_id) REFERENCES blackboard_artifact_types(artifact_type_id), "
					+ "FOREIGN KEY(review_status_id) REFERENCES review_statuses(review_status_id))");
			
			/* Binary representation of BYTEA is a bunch of bytes, which could
			* include embedded nulls so we have to pay attention to field length.
			* http://www.postgresql.org/docs/9.4/static/libpq-example.html
			*/
			stmt.execute("CREATE TABLE blackboard_attributes (artifact_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
					+ "artifact_type_id BIGINT NOT NULL, source TEXT, context TEXT, attribute_type_id BIGINT NOT NULL, "
					+ "value_type INTEGER NOT NULL, value_byte " + dbQueryHelper.getBlobType() + ", "
					+ "value_text TEXT, value_int32 INTEGER, value_int64 " + dbQueryHelper.getBigIntType() + ", value_double NUMERIC(20, 10), "
					+ "FOREIGN KEY(artifact_id) REFERENCES blackboard_artifacts(artifact_id) ON DELETE CASCADE, "
					+ "FOREIGN KEY(artifact_type_id) REFERENCES blackboard_artifact_types(artifact_type_id), "
					+ "FOREIGN KEY(attribute_type_id) REFERENCES blackboard_attribute_types(attribute_type_id))");
            
			stmt.execute("CREATE TABLE tsk_vs_parts (obj_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
					+ "addr " + dbQueryHelper.getBigIntType() + " NOT NULL, start BIGINT NOT NULL, length BIGINT NOT NULL, "
					+ dbQueryHelper.getVSDescColName() + " TEXT, "
					+ "flags INTEGER NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE);");
            
			stmt.execute("CREATE TABLE tsk_pool_info (obj_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
					+ "pool_type INTEGER NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE);");
            
			stmt.execute("CREATE TABLE ingest_module_types (type_id INTEGER PRIMARY KEY, type_name TEXT NOT NULL)");
            
			stmt.execute("CREATE TABLE ingest_job_status_types (type_id INTEGER PRIMARY KEY, type_name TEXT NOT NULL)");
            
			stmt.execute("CREATE TABLE ingest_modules (ingest_module_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
					+ "display_name TEXT NOT NULL, unique_name TEXT UNIQUE NOT NULL, type_id INTEGER NOT NULL, "
					+ "version TEXT NOT NULL, FOREIGN KEY(type_id) REFERENCES ingest_module_types(type_id) ON DELETE CASCADE);");
            
			stmt.execute("CREATE TABLE ingest_jobs (ingest_job_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
					+ "obj_id " + dbQueryHelper.getBigIntType() + " NOT NULL, host_name TEXT NOT NULL, "
					+ "start_date_time BIGINT NOT NULL, end_date_time BIGINT NOT NULL, status_id INTEGER NOT NULL, "
					+ "settings_dir TEXT, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE, "
					+ "FOREIGN KEY(status_id) REFERENCES ingest_job_status_types(type_id) ON DELETE CASCADE);");
            
			stmt.execute("CREATE TABLE ingest_job_modules (ingest_job_id INTEGER, ingest_module_id INTEGER, "
					+ "pipeline_position INTEGER, PRIMARY KEY(ingest_job_id, ingest_module_id), "
					+ "FOREIGN KEY(ingest_job_id) REFERENCES ingest_jobs(ingest_job_id) ON DELETE CASCADE, "
					+ "FOREIGN KEY(ingest_module_id) REFERENCES ingest_modules(ingest_module_id) ON DELETE CASCADE);");
            
			stmt.execute("CREATE TABLE reports (obj_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, path TEXT NOT NULL, "
					+ "crtime INTEGER NOT NULL, src_module_name TEXT NOT NULL, report_name TEXT NOT NULL, "
					+ "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE);");
			
			stmt.execute("CREATE TABLE account_types (account_type_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
					+ "type_name TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL)");
            
			stmt.execute("CREATE TABLE accounts (account_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
					+ "account_type_id INTEGER NOT NULL, account_unique_identifier TEXT NOT NULL, "
					+ "UNIQUE(account_type_id, account_unique_identifier), "
					+ "FOREIGN KEY(account_type_id) REFERENCES account_types(account_type_id))");
            
			stmt.execute("CREATE TABLE account_relationships  (relationship_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
					+ "account1_id INTEGER NOT NULL, account2_id INTEGER NOT NULL, "
					+ "relationship_source_obj_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
					+ "date_time BIGINT, relationship_type INTEGER NOT NULL, data_source_obj_id BIGINT NOT NULL, "
					+ "UNIQUE(account1_id, account2_id, relationship_source_obj_id), "
					+ "FOREIGN KEY(account1_id) REFERENCES accounts(account_id), "
					+ "FOREIGN KEY(account2_id) REFERENCES accounts(account_id), "
					+ "FOREIGN KEY(relationship_source_obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE, "
					+ "FOREIGN KEY(data_source_obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE)");
            
			stmt.execute("CREATE TABLE tsk_event_types ("
					+ " event_type_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY,"
					+ " display_name TEXT UNIQUE NOT NULL , "
					+ " super_type_id INTEGER REFERENCES tsk_event_types(event_type_id) )");
             
			stmt.execute(
					"INSERT INTO tsk_event_types(event_type_id, display_name, super_type_id) VALUES(0, 'Event Types', null);"
					+ "INSERT INTO tsk_event_types(event_type_id, display_name, super_type_id) VALUES(1, 'File System', 0);"
					+ "INSERT INTO tsk_event_types(event_type_id, display_name, super_type_id) VALUES(2, 'Web Activity', 0);"
					+ "INSERT INTO tsk_event_types(event_type_id, display_name, super_type_id) VALUES(3, 'Misc Types', 0);"
					+ "INSERT INTO tsk_event_types(event_type_id, display_name, super_type_id) VALUES(4, 'Modified', 1);"
					+ "INSERT INTO tsk_event_types(event_type_id, display_name, super_type_id) VALUES(5, 'Accessed', 1);"
					+ "INSERT INTO tsk_event_types(event_type_id, display_name, super_type_id) VALUES(6, 'Created', 1);"
					+ "INSERT INTO tsk_event_types(event_type_id, display_name, super_type_id) VALUES(7, 'Changed', 1);");
			/*
			* Regarding the timeline event tables schema, note that several columns
			* in the tsk_event_descriptions table seem, at first glance, to be
			* attributes of events rather than their descriptions and would appear
			* to belong in tsk_events table instead. The rationale for putting the
			* data source object ID, content object ID, artifact ID and the flags
			* indicating whether or not the event source has a hash set hit or is
			* tagged were motivated by the fact that these attributes are identical
			* for each event in a set of file system file MAC time events. The
			* decision was made to avoid duplication and save space by placing this
			* data in the tsk_event-descriptions table.
			*/			
			stmt.execute(
				"CREATE TABLE tsk_event_descriptions ( "
				+ " event_description_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
				+ " full_description TEXT NOT NULL, "
				+ " med_description TEXT, "
				+ " short_description TEXT,"
				+ " data_source_obj_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ " content_obj_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ " artifact_id " + dbQueryHelper.getBigIntType() + ", "
				+ " hash_hit INTEGER NOT NULL, " //boolean 
				+ " tagged INTEGER NOT NULL, " //boolean 
				+ " FOREIGN KEY(data_source_obj_id) REFERENCES data_source_info(obj_id) ON DELETE CASCADE, "
				+ " FOREIGN KEY(content_obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE, "
				+ " FOREIGN KEY(artifact_id) REFERENCES blackboard_artifacts(artifact_id) ON DELETE CASCADE,"
				+ " UNIQUE (full_description, content_obj_id, artifact_id))");
            
			stmt.execute(
				"CREATE TABLE tsk_events ("
				+ " event_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
				+ " event_type_id " + dbQueryHelper.getBigIntType() + " NOT NULL REFERENCES tsk_event_types(event_type_id) ,"
				+ " event_description_id " + dbQueryHelper.getBigIntType() + " NOT NULL REFERENCES tsk_event_descriptions(event_description_id) ON DELETE CASCADE ,"
				+ " time " + dbQueryHelper.getBigIntType() + " NOT NULL , "
				+ " UNIQUE (event_type_id, event_description_id, time))");
				
			stmt.execute("CREATE TABLE tsk_examiners (examiner_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
					+ "login_name TEXT NOT NULL, display_name TEXT, UNIQUE(login_name))");
            
			stmt.execute("CREATE TABLE content_tags (tag_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
					+ "obj_id " + dbQueryHelper.getBigIntType() + " NOT NULL, tag_name_id BIGINT NOT NULL, "
							+ "comment TEXT NOT NULL, begin_byte_offset BIGINT NOT NULL, end_byte_offset BIGINT NOT NULL, "
							+ "examiner_id BIGINT, "
							+ "FOREIGN KEY(examiner_id) REFERENCES tsk_examiners(examiner_id), "
							+ "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE, "
							+ "FOREIGN KEY(tag_name_id) REFERENCES tag_names(tag_name_id))");
            
			stmt.execute("CREATE TABLE blackboard_artifact_tags (tag_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
					+ "artifact_id " + dbQueryHelper.getBigIntType() + " NOT NULL, tag_name_id BIGINT NOT NULL, "
					+ "comment TEXT NOT NULL,  examiner_id BIGINT, "
					+ "FOREIGN KEY(examiner_id) REFERENCES tsk_examiners(examiner_id), "
					+ "FOREIGN KEY(artifact_id) REFERENCES blackboard_artifacts(artifact_id) ON DELETE CASCADE, "
							+ "FOREIGN KEY(tag_name_id) REFERENCES tag_names(tag_name_id))");
            
			stmt.execute("CREATE TABLE tsk_file_layout (obj_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
					+ "byte_start BIGINT NOT NULL, byte_len BIGINT NOT NULL, "
					+ "sequence INTEGER NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE);");

		} catch (SQLException ex) {
			throw new TskCoreException("Error initializing tables", ex);
		}
	}
	
	/**
	 * Add indexes
	 * 
	 * @param conn the database connection
	 * @throws TskCoreException 
	 */
	private void addIndexes(Connection conn) throws TskCoreException {
	
	}
	
	private abstract class DbCreationHelper {
		
		/**
		 * Create and initialize the database
		 * 
		 * @throws TskCoreException 
		 */
		abstract void createDatabase() throws TskCoreException;
		
		/**
		 * Get an connection to the database
		 * 
		 * @return the connection
		 */
		abstract Connection getConnection();
		
		/**
		 * Do initialization before creating the tables.
		 * This is where SQLite pragmas are set up.
		 * 
		 * @param conn The database connection
		 * 
		 * @throws TskCoreException 
		 */
		void performPreInitialization(Connection conn) throws TskCoreException {
			// By default do nothing
		}
		
		/**
		 * Do any additional steps after the tables are created.
		 * 
		 * @param conn The database connection
		 * @throws TskCoreException 
		 */
		void performPostTableInitialization(Connection conn) throws TskCoreException {
			// By default do nothing
		}
	}
	
	private class PostgreSQLDbCreationHelper extends DbCreationHelper {
		
		PostgreSQLDbCreationHelper(String caseName, CaseDbConnectionInfo info, String caseDirPath) {
			
		}
		
		@Override
		void createDatabase() {}
		
		@Override
		Connection getConnection() { return null; }
		
		@Override
		void performPostTableInitialization(Connection conn) throws TskCoreException {
			
			// TODO TODO
			//stmt.execute("ALTER SEQUENCE blackboard_artifacts_artifact_id_seq minvalue -9223372036854775808 restart with -9223372036854775808");
		}

	}
	
	private class SQLiteDbCreationHelper extends DbCreationHelper {
		
		private final static String PRAGMA_SYNC_OFF = "PRAGMA synchronous = OFF";
		private final static String PRAGMA_READ_UNCOMMITTED_TRUE = "PRAGMA read_uncommitted = True";
		private final static String PRAGMA_ENCODING_UTF8 = "PRAGMA encoding = 'UTF-8'";
		private final static String PRAGMA_PAGE_SIZE_4096 = "PRAGMA page_size = 4096";
		private final static String PRAGMA_FOREIGN_KEYS_ON = "PRAGMA foreign_keys = ON";
		
		private final static String JDBC_DRIVER = "org.sqlite.JDBC"; // NON-NLS
        private final static String JDBC_BASE_URI = "jdbc:sqlite:"; // NON-NLS
		
		String dbPath;
		
		SQLiteDbCreationHelper(String dbPath) {
			this.dbPath = dbPath;
		}
		
		@Override
		void createDatabase() throws TskCoreException {
			// SQLite doesn't need to explicitly create the case database, so
			// just check that the folder exists and the database does not
			File dbFile = new File(dbPath);
			if (dbFile.exists()) {
				throw new TskCoreException("Case database already exists : " + dbPath);
			}
			
			if (dbFile.getParentFile() != null && !dbFile.getParentFile().exists()) {
				throw new TskCoreException("Case database folder does not exist : " + dbFile.getParent());
			}
		}
		
		@Override
		Connection getConnection() {
			
			StringBuilder url = new StringBuilder();
			url.append(JDBC_BASE_URI);
			url.append(dbPath);
			
			Connection conn;
			try {
				Class.forName(JDBC_DRIVER);
				conn = DriverManager.getConnection(url.toString());
			} catch (ClassNotFoundException | SQLException ex) {
				logger.log(Level.SEVERE, "Failed to acquire ephemeral connection to sqlite.", ex); // NON-NLS
				conn = null;
			}
			return conn;
		}
		
		@Override
		void performPreInitialization(Connection conn) throws TskCoreException {
		
			try (Statement stmt = conn.createStatement()) {
				stmt.execute(PRAGMA_SYNC_OFF);
				stmt.execute(PRAGMA_READ_UNCOMMITTED_TRUE);
				stmt.execute(PRAGMA_ENCODING_UTF8);
				stmt.execute(PRAGMA_PAGE_SIZE_4096);
				stmt.execute(PRAGMA_FOREIGN_KEYS_ON);
			} catch (SQLException ex) {
				throw new TskCoreException("Error setting pragmas", ex);
			}
			
			/* TODO? Implement this C code
			    // increase the DB by 1MB at a time -- supposed to help performance when populating
				int chunkSize = 1024 * 1024;
				if (sqlite3_file_control(m_db, NULL, SQLITE_FCNTL_CHUNK_SIZE, &chunkSize) != SQLITE_OK)
				{
					tsk_error_reset();
					tsk_error_set_errno(TSK_ERR_AUTO_DB);
					tsk_error_set_errstr("TskDbSqlite::initialize: error setting chunk size %s", sqlite3_errmsg(m_db));
					return 1;
				}
			*/
		}	
	}
}
