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
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;
import java.util.logging.Logger;
import java.util.logging.Level;
import org.sleuthkit.datamodel.SQLHelper.PostgreSQLHelper;
import org.sleuthkit.datamodel.SQLHelper.SQLiteHelper;

/**
 * Creates a SQLite or PostgreSQL case database.
 */
class CaseDatabaseFactory {
	
	private static final Logger logger = Logger.getLogger(CaseDatabaseFactory.class.getName());
	private final SQLHelper dbQueryHelper;
	private final DbCreationHelper dbCreationHelper;
		
	/**
	 * Create a new SQLite case
	 * 
	 * @param dbPath Full path to the database
	 */
	CaseDatabaseFactory(String dbPath) {		
		this.dbQueryHelper = new SQLiteHelper();
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
	 */
	CaseDatabaseFactory(String caseName, CaseDbConnectionInfo info) {
		this.dbQueryHelper = new PostgreSQLHelper();
		this.dbCreationHelper = new PostgreSQLDbCreationHelper(caseName, info);
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
	 * Create the database itself (if necessary)
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
		try (Connection conn = dbCreationHelper.getConnection()) {
			// Perform any needed steps before creating the tables
			dbCreationHelper.performPreInitialization(conn);

			// Add schema version
			addDbInfo(conn);

			// Add tables
			addTables(conn);
			dbCreationHelper.performPostTableInitialization(conn);
		
			// Add indexes
			addIndexes(conn);
		} catch (SQLException ex) {
			throw new TskCoreException("Error initializing case database", ex);
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
		CaseDbSchemaVersionNumber version = SleuthkitCase.CURRENT_DB_SCHEMA_VERSION;
		long tskVersionNum = SleuthkitJNI.getSleuthkitVersion(); // This is the current version of TSK
		
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
			createFileTables(stmt);
			createArtifactTables(stmt);
			createAnalysisResultsTables(stmt);
			createTagTables(stmt);
			createIngestTables(stmt);
			createAccountTables(stmt);
			createEventTables(stmt);
			createAttributeTables(stmt);
		} catch (SQLException ex) {
			throw new TskCoreException("Error initializing tables", ex);
		}
	}
	
	private void createFileTables(Statement stmt) throws SQLException {
		// The UNIQUE here on the object ID is to create an index
		stmt.execute("CREATE TABLE tsk_objects (obj_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, par_obj_id " + dbQueryHelper.getBigIntType() 
				+ ", type INTEGER NOT NULL, UNIQUE (obj_id), FOREIGN KEY (par_obj_id) REFERENCES tsk_objects (obj_id) ON DELETE CASCADE)");

		stmt.execute("CREATE TABLE tsk_image_info (obj_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, type INTEGER, ssize INTEGER, " 
				+ "tzone TEXT, size " + dbQueryHelper.getBigIntType() + ", md5 TEXT, sha1 TEXT, sha256 TEXT, display_name TEXT, "
				+ "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE)");

		stmt.execute("CREATE TABLE tsk_image_names (obj_id " + dbQueryHelper.getBigIntType() + " NOT NULL, name TEXT NOT NULL, "
				+ "sequence INTEGER NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE)");

		stmt.execute("CREATE TABLE tsk_vs_info (obj_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, vs_type INTEGER NOT NULL, "
				+ "img_offset " + dbQueryHelper.getBigIntType() + " NOT NULL, block_size " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE)");

		stmt.execute("CREATE TABLE tsk_vs_parts (obj_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
				+ "addr " + dbQueryHelper.getBigIntType() + " NOT NULL, start " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "length " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ dbQueryHelper.getVSDescColName() + " TEXT, "
				+ "flags INTEGER NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE);");		
		
		stmt.execute("CREATE TABLE tsk_pool_info (obj_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
				+ "pool_type INTEGER NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE);");

		stmt.execute("CREATE TABLE data_source_info (obj_id " + dbQueryHelper.getBigIntType() + " PRIMARY KEY, device_id TEXT NOT NULL, "
				+ "time_zone TEXT NOT NULL, acquisition_details TEXT, added_date_time "+ dbQueryHelper.getBigIntType() + ", "
				+ "acquisition_tool_settings TEXT, acquisition_tool_name TEXT, acquisition_tool_version TEXT, "
				+ "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE)");

		stmt.execute("CREATE TABLE tsk_fs_info (obj_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
				+ "data_source_obj_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "img_offset " + dbQueryHelper.getBigIntType() + " NOT NULL, fs_type INTEGER NOT NULL, "
				+ "block_size " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "block_count " + dbQueryHelper.getBigIntType() + " NOT NULL, root_inum " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "first_inum " + dbQueryHelper.getBigIntType() + " NOT NULL, last_inum " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "display_name TEXT, " 
				+ "FOREIGN KEY(data_source_obj_id) REFERENCES data_source_info(obj_id) ON DELETE CASCADE, "
				+ "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE)");

		stmt.execute("CREATE TABLE tsk_files (obj_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
				+ "fs_obj_id " + dbQueryHelper.getBigIntType() + ", data_source_obj_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "attr_type INTEGER, attr_id INTEGER, " 
				+ "name TEXT NOT NULL, meta_addr " + dbQueryHelper.getBigIntType() + ", meta_seq " + dbQueryHelper.getBigIntType() + ", "
				+ "type INTEGER, has_layout INTEGER, has_path INTEGER, "
				+ "dir_type INTEGER, meta_type INTEGER, dir_flags INTEGER, meta_flags INTEGER, size " + dbQueryHelper.getBigIntType() + ", "
				+ "ctime " + dbQueryHelper.getBigIntType() + ", "
				+ "crtime " + dbQueryHelper.getBigIntType() + ", atime " + dbQueryHelper.getBigIntType() + ", "
				+ "mtime " + dbQueryHelper.getBigIntType() + ", mode INTEGER, uid INTEGER, gid INTEGER, md5 TEXT, sha256 TEXT, "
				+ "known INTEGER, "
				+ "parent_path TEXT, mime_type TEXT, extension TEXT, "
				+ "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE, "
				+ "FOREIGN KEY(fs_obj_id) REFERENCES tsk_fs_info(obj_id) ON DELETE CASCADE, "
				+ "FOREIGN KEY(data_source_obj_id) REFERENCES data_source_info(obj_id) ON DELETE CASCADE)");

		stmt.execute("CREATE TABLE file_encoding_types (encoding_type INTEGER PRIMARY KEY, name TEXT NOT NULL)");

		stmt.execute("CREATE TABLE tsk_files_path (obj_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, path TEXT NOT NULL, "
				+ "encoding_type INTEGER NOT NULL, FOREIGN KEY(encoding_type) references file_encoding_types(encoding_type), "
				+ "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE)");

		stmt.execute("CREATE TABLE tsk_files_derived (obj_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
				+ "derived_id " + dbQueryHelper.getBigIntType() + " NOT NULL, rederive TEXT, "
				+ "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE)");

		stmt.execute("CREATE TABLE tsk_files_derived_method (derived_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
				+ "tool_name TEXT NOT NULL, tool_version TEXT NOT NULL, other TEXT)");		
		
		stmt.execute("CREATE TABLE tsk_file_layout (obj_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "byte_start " + dbQueryHelper.getBigIntType() + " NOT NULL, byte_len " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "sequence INTEGER NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE);");
		
		stmt.execute("CREATE TABLE reports (obj_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, path TEXT NOT NULL, "
				+ "crtime INTEGER NOT NULL, src_module_name TEXT NOT NULL, report_name TEXT NOT NULL, "
				+ "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE);");		
	}
	
	private void createArtifactTables(Statement stmt) throws SQLException {
		stmt.execute("CREATE TABLE blackboard_artifact_types (artifact_type_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
				+ "type_name TEXT NOT NULL, display_name TEXT,"
				+ "category_type INTEGER DEFAULT 0)");

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
				+ "UNIQUE (artifact_obj_id),"
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
				+ "artifact_type_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "source TEXT, context TEXT, attribute_type_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "value_type INTEGER NOT NULL, value_byte " + dbQueryHelper.getBlobType() + ", "
				+ "value_text TEXT, value_int32 INTEGER, value_int64 " + dbQueryHelper.getBigIntType() + ", value_double NUMERIC(20, 10), "
				+ "FOREIGN KEY(artifact_id) REFERENCES blackboard_artifacts(artifact_id) ON DELETE CASCADE, "
				+ "FOREIGN KEY(artifact_type_id) REFERENCES blackboard_artifact_types(artifact_type_id), "
				+ "FOREIGN KEY(attribute_type_id) REFERENCES blackboard_attribute_types(attribute_type_id))");		
	}
	
	private void createAnalysisResultsTables(Statement stmt) throws SQLException  {
		stmt.execute("CREATE TABLE tsk_analysis_results (obj_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "conclusion TEXT, "
				+ "significance INTEGER NOT NULL, "
				+ "confidence INTEGER NOT NULL, "
				+ "configuration TEXT, justification TEXT, "
				+ "ignore_score INTEGER DEFAULT 0, " // boolean	
				+ "FOREIGN KEY(obj_id) REFERENCES blackboard_artifacts(artifact_obj_id) ON DELETE CASCADE"
				+ ")");		
		
		stmt.execute("CREATE TABLE tsk_aggregate_score( obj_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "data_source_obj_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "significance INTEGER NOT NULL, "
				+ "confidence INTEGER NOT NULL, "
				+ "UNIQUE (obj_id),"
				+ "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE, "
				+ "FOREIGN KEY(data_source_obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE "
				+ ")");	
		
	}
	private void createTagTables(Statement stmt) throws SQLException {
		stmt.execute("CREATE TABLE tsk_tag_sets (tag_set_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, name TEXT UNIQUE)");
		stmt.execute("CREATE TABLE tag_names (tag_name_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, display_name TEXT UNIQUE, "
				+ "description TEXT NOT NULL, color TEXT NOT NULL, knownStatus INTEGER NOT NULL,"
				+ " tag_set_id " + dbQueryHelper.getBigIntType() + ", rank INTEGER, FOREIGN KEY(tag_set_id) REFERENCES tsk_tag_sets(tag_set_id) ON DELETE SET NULL)");
		
		stmt.execute("CREATE TABLE tsk_examiners (examiner_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
				+ "login_name TEXT NOT NULL, display_name TEXT, UNIQUE(login_name))");

		stmt.execute("CREATE TABLE content_tags (tag_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
				+ "obj_id " + dbQueryHelper.getBigIntType() + " NOT NULL, tag_name_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "comment TEXT NOT NULL, begin_byte_offset " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "end_byte_offset " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "examiner_id " + dbQueryHelper.getBigIntType() + ", "
				+ "FOREIGN KEY(examiner_id) REFERENCES tsk_examiners(examiner_id) ON DELETE CASCADE, "
				+ "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE, "
				+ "FOREIGN KEY(tag_name_id) REFERENCES tag_names(tag_name_id) ON DELETE CASCADE)");

		stmt.execute("CREATE TABLE blackboard_artifact_tags (tag_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
				+ "artifact_id " + dbQueryHelper.getBigIntType() + " NOT NULL, tag_name_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "comment TEXT NOT NULL,  examiner_id " + dbQueryHelper.getBigIntType() + ", "
				+ "FOREIGN KEY(examiner_id) REFERENCES tsk_examiners(examiner_id) ON DELETE CASCADE, "
				+ "FOREIGN KEY(artifact_id) REFERENCES blackboard_artifacts(artifact_id) ON DELETE CASCADE, "
				+ "FOREIGN KEY(tag_name_id) REFERENCES tag_names(tag_name_id) ON DELETE CASCADE)");
	}
	
	/**
	 * Add indexes
	 * 
	 * @param conn the database connection
	 * @throws TskCoreException 
	 */
	private void addIndexes(Connection conn) throws TskCoreException {
		try (Statement stmt = conn.createStatement()) {
			// tsk_objects index
			stmt.execute("CREATE INDEX parObjId ON tsk_objects(par_obj_id)");
			
			// file layout index
			stmt.execute("CREATE INDEX layout_objID ON tsk_file_layout(obj_id)");
			
			// blackboard indexes
			stmt.execute("CREATE INDEX artifact_objID ON blackboard_artifacts(obj_id)");
			stmt.execute("CREATE INDEX artifact_artifact_objID ON blackboard_artifacts(artifact_obj_id)");
			stmt.execute("CREATE INDEX artifact_typeID ON blackboard_artifacts(artifact_type_id)");
			stmt.execute("CREATE INDEX attrsArtifactID ON blackboard_attributes(artifact_id)");
			
			//file type indexes
			stmt.execute("CREATE INDEX mime_type ON tsk_files(dir_type,mime_type,type)");
			stmt.execute("CREATE INDEX file_extension ON tsk_files(extension)");
			
			// account indexes
			stmt.execute("CREATE INDEX relationships_account1 ON account_relationships(account1_id)");
			stmt.execute("CREATE INDEX relationships_account2 ON account_relationships(account2_id)");
			stmt.execute("CREATE INDEX relationships_relationship_source_obj_id ON account_relationships(relationship_source_obj_id)");
			stmt.execute("CREATE INDEX relationships_date_time ON account_relationships(date_time)");
			stmt.execute("CREATE INDEX relationships_relationship_type ON account_relationships(relationship_type)");
			stmt.execute("CREATE INDEX relationships_data_source_obj_id ON account_relationships(data_source_obj_id)");
			
			//tsk_events indices
			stmt.execute("CREATE INDEX events_data_source_obj_id ON tsk_event_descriptions(data_source_obj_id)");
			stmt.execute("CREATE INDEX events_content_obj_id ON tsk_event_descriptions(content_obj_id)");
			stmt.execute("CREATE INDEX events_artifact_id ON tsk_event_descriptions(artifact_id)");
			stmt.execute("CREATE INDEX events_sub_type_time ON tsk_events(event_type_id,  time)");
			stmt.execute("CREATE INDEX events_time ON tsk_events(time)");
			
			// analysis results and scores indices
			stmt.execute("CREATE INDEX score_significance_confidence ON tsk_aggregate_score(significance,confidence)");
			stmt.execute("CREATE INDEX score_datasource_obj_id ON tsk_aggregate_score(data_source_obj_id)");
			
		} catch (SQLException ex) {
			throw new TskCoreException("Error initializing db_info tables", ex);
		}
	}
	
	private void createIngestTables(Statement stmt) throws SQLException {
		stmt.execute("CREATE TABLE ingest_module_types (type_id INTEGER PRIMARY KEY, type_name TEXT NOT NULL)");
            
		stmt.execute("CREATE TABLE ingest_job_status_types (type_id INTEGER PRIMARY KEY, type_name TEXT NOT NULL)");

		stmt.execute("CREATE TABLE ingest_modules (ingest_module_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
				+ "display_name TEXT NOT NULL, unique_name TEXT UNIQUE NOT NULL, type_id INTEGER NOT NULL, "
				+ "version TEXT NOT NULL, FOREIGN KEY(type_id) REFERENCES ingest_module_types(type_id) ON DELETE CASCADE);");

		stmt.execute("CREATE TABLE ingest_jobs (ingest_job_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
				+ "obj_id " + dbQueryHelper.getBigIntType() + " NOT NULL, host_name TEXT NOT NULL, "
				+ "start_date_time " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "end_date_time " + dbQueryHelper.getBigIntType() + " NOT NULL, status_id INTEGER NOT NULL, "
				+ "settings_dir TEXT, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE, "
				+ "FOREIGN KEY(status_id) REFERENCES ingest_job_status_types(type_id) ON DELETE CASCADE);");

		stmt.execute("CREATE TABLE ingest_job_modules (ingest_job_id INTEGER, ingest_module_id INTEGER, "
				+ "pipeline_position INTEGER, PRIMARY KEY(ingest_job_id, ingest_module_id), "
				+ "FOREIGN KEY(ingest_job_id) REFERENCES ingest_jobs(ingest_job_id) ON DELETE CASCADE, "
				+ "FOREIGN KEY(ingest_module_id) REFERENCES ingest_modules(ingest_module_id) ON DELETE CASCADE);");
	}
	
	private void createAccountTables(Statement stmt) throws SQLException {
		stmt.execute("CREATE TABLE account_types (account_type_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
				+ "type_name TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL)");

		stmt.execute("CREATE TABLE accounts (account_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
				+ "account_type_id INTEGER NOT NULL, account_unique_identifier TEXT NOT NULL, "
				+ "UNIQUE(account_type_id, account_unique_identifier), "
				+ "FOREIGN KEY(account_type_id) REFERENCES account_types(account_type_id))");

		stmt.execute("CREATE TABLE account_relationships (relationship_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY, "
				+ "account1_id INTEGER NOT NULL, account2_id INTEGER NOT NULL, "
				+ "relationship_source_obj_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "date_time " + dbQueryHelper.getBigIntType() + ", relationship_type INTEGER NOT NULL, "
				+ "data_source_obj_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "UNIQUE(account1_id, account2_id, relationship_source_obj_id), "
				+ "FOREIGN KEY(account1_id) REFERENCES accounts(account_id), "
				+ "FOREIGN KEY(account2_id) REFERENCES accounts(account_id), "
				+ "FOREIGN KEY(relationship_source_obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE, "
				+ "FOREIGN KEY(data_source_obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE)");
	}
	
	private void createEventTables(Statement stmt) throws SQLException {
		stmt.execute("CREATE TABLE tsk_event_types ("
				+ " event_type_id " + dbQueryHelper.getPrimaryKey() + " PRIMARY KEY,"
				+ " display_name TEXT UNIQUE NOT NULL , "
				+ " super_type_id INTEGER REFERENCES tsk_event_types(event_type_id) )");

		stmt.execute("INSERT INTO tsk_event_types(event_type_id, display_name, super_type_id) VALUES(0, 'Event Types', null)");
		stmt.execute("INSERT INTO tsk_event_types(event_type_id, display_name, super_type_id) VALUES(1, 'File System', 0)");
		stmt.execute("INSERT INTO tsk_event_types(event_type_id, display_name, super_type_id) VALUES(2, 'Web Activity', 0)");
		stmt.execute("INSERT INTO tsk_event_types(event_type_id, display_name, super_type_id) VALUES(3, 'Misc Types', 0)");
		stmt.execute("INSERT INTO tsk_event_types(event_type_id, display_name, super_type_id) VALUES(4, 'Modified', 1)");
		stmt.execute("INSERT INTO tsk_event_types(event_type_id, display_name, super_type_id) VALUES(5, 'Accessed', 1)");
		stmt.execute("INSERT INTO tsk_event_types(event_type_id, display_name, super_type_id) VALUES(6, 'Created', 1)");
		stmt.execute("INSERT INTO tsk_event_types(event_type_id, display_name, super_type_id) VALUES(7, 'Changed', 1)");
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
	}

	private void createAttributeTables(Statement stmt) throws SQLException {
		/*
		 * Binary representation of BYTEA is a bunch of bytes, which could
		 * include embedded nulls so we have to pay attention to field length.
		 * http://www.postgresql.org/docs/9.4/static/libpq-example.html
		 */
		stmt.execute("CREATE TABLE tsk_file_attributes (obj_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "attribute_type_id " + dbQueryHelper.getBigIntType() + " NOT NULL, "
				+ "value_type INTEGER NOT NULL, value_byte " + dbQueryHelper.getBlobType() + ", "
				+ "value_text TEXT, value_int32 INTEGER, value_int64 " + dbQueryHelper.getBigIntType() + ", value_double NUMERIC(20, 10), "
				+ "FOREIGN KEY(obj_id) REFERENCES tsk_files(obj_id) ON DELETE CASCADE, "
				+ "FOREIGN KEY(attribute_type_id) REFERENCES blackboard_attribute_types(attribute_type_id))");
	}
	
	/**
	 * Helper class for holding code unique to each database type.
	 */
	private abstract class DbCreationHelper {
		
		/**
		 * Create the database itself (if necessary)
		 * 
		 * @throws TskCoreException 
		 */
		abstract void createDatabase() throws TskCoreException;
		
		/**
		 * Get an connection to the case database
		 * 
		 * @return the connection
		 */
		abstract Connection getConnection() throws TskCoreException;
		
		/**
		 * Do any needed initialization before creating the tables.
		 * This is where SQLite pragmas are set up.
		 * 
		 * @param conn The database connection
		 * 
		 * @throws TskCoreException 
		 */
		abstract void performPreInitialization(Connection conn) throws TskCoreException;
		
		/**
		 * Do any additional steps after the tables are created.
		 * 
		 * @param conn The database connection
		 * @throws TskCoreException 
		 */
		abstract void performPostTableInitialization(Connection conn) throws TskCoreException;
	}
	
	/**
	 * Implements the PostgreSQL-specific methods for creating the case
	 */
	private class PostgreSQLDbCreationHelper extends DbCreationHelper {
		
		private final static String JDBC_BASE_URI = "jdbc:postgresql://"; // NON-NLS
		private final static String JDBC_DRIVER = "org.postgresql.Driver"; // NON-NLS
		
		final private String caseName;
		final private CaseDbConnectionInfo info;
		
		PostgreSQLDbCreationHelper(String caseName, CaseDbConnectionInfo info) {
			this.caseName = caseName;
			this.info = info;
		}
		
		@Override
		void createDatabase() throws TskCoreException{
			try(Connection conn = getPostgresConnection();
					Statement stmt = conn.createStatement()) {
				stmt.execute("CREATE DATABASE \"" + caseName + "\" WITH ENCODING='UTF8'");		
			} catch (SQLException ex) {
				throw new TskCoreException("Error creating PostgreSQL case " + caseName, ex);
			}
		}
		
		@Override
		Connection getConnection() throws TskCoreException {
			return getConnection(caseName);
		}		
		
		/**
		 * Connects to the "postgres" database for creating new databases.
		 * 
		 * @return the connection to the "postgres" database
		 */
		Connection getPostgresConnection() throws TskCoreException {
			return getConnection("postgres");
		}
		
		/**
		 * Connects to an existing database with the given name.
		 * 
		 * @param databaseName the name of the database
		 * 
		 * @return the connection to the database
		 */
		Connection getConnection(String databaseName) throws TskCoreException {
			String encodedDbName;
			try {
				encodedDbName = URLEncoder.encode(databaseName, "UTF-8");
			} catch (UnsupportedEncodingException ex) {
				// Print the warning and continue with the unencoded name
				logger.log(Level.WARNING, "Error encoding database name " + databaseName, ex);
				encodedDbName = databaseName;
			}
			
			StringBuilder url = new StringBuilder();
			url.append(JDBC_BASE_URI)
				.append(info.getHost())
				.append('/') // NON-NLS
				.append(encodedDbName);
			
			Connection conn;
			try {
				Properties props = new Properties();
				props.setProperty("user", info.getUserName());     // NON-NLS
				props.setProperty("password", info.getPassword()); // NON-NLS

				Class.forName(JDBC_DRIVER);
				conn = DriverManager.getConnection(url.toString(), props);
			} catch (ClassNotFoundException | SQLException ex) {
				throw new TskCoreException("Failed to acquire ephemeral connection to PostgreSQL database " + databaseName, ex); // NON-NLS
			}
			return conn;
		}	
		
		@Override
		void performPreInitialization(Connection conn) throws TskCoreException {
			// Nothing to do here for PostgreSQL
		}
		
		@Override
		void performPostTableInitialization(Connection conn) throws TskCoreException {
			try (Statement stmt = conn.createStatement()) {
				stmt.execute("ALTER SEQUENCE blackboard_artifacts_artifact_id_seq minvalue -9223372036854775808 restart with -9223372036854775808");
			} catch (SQLException ex) {
				throw new TskCoreException("Error altering artifact ID sequence", ex);
			}
		}
	}
	
	/**
	 * Implements the SQLite-specific methods for creating the case
	 */
	private class SQLiteDbCreationHelper extends DbCreationHelper {
		
		private final static String PRAGMA_SYNC_OFF = "PRAGMA synchronous = OFF"; // NON-NLS
		private final static String PRAGMA_READ_UNCOMMITTED_TRUE = "PRAGMA read_uncommitted = True"; // NON-NLS
		private final static String PRAGMA_ENCODING_UTF8 = "PRAGMA encoding = 'UTF-8'"; // NON-NLS
		private final static String PRAGMA_PAGE_SIZE_4096 = "PRAGMA page_size = 4096"; // NON-NLS
		private final static String PRAGMA_FOREIGN_KEYS_ON = "PRAGMA foreign_keys = ON"; // NON-NLS
		
		private final static String JDBC_DRIVER = "org.sqlite.JDBC"; // NON-NLS
        private final static String JDBC_BASE_URI = "jdbc:sqlite:"; // NON-NLS
		
		String dbPath;
		
		SQLiteDbCreationHelper(String dbPath) {
			this.dbPath = dbPath;
		}
		
		@Override
		void createDatabase() throws TskCoreException {
			// SQLite doesn't need to explicitly create the case database but we will
			// check that the folder exists and the database does not
			File dbFile = new File(dbPath);
			if (dbFile.exists()) {
				throw new TskCoreException("Case database already exists : " + dbPath);
			}

			if (dbFile.getParentFile() != null && !dbFile.getParentFile().exists()) {
				throw new TskCoreException("Case database folder does not exist : " + dbFile.getParent());
			}
		}
		
		@Override
		Connection getConnection() throws TskCoreException {
			
			StringBuilder url = new StringBuilder();
			url.append(JDBC_BASE_URI)
				.append(dbPath);
			
			Connection conn;
			try {
				Class.forName(JDBC_DRIVER);
				conn = DriverManager.getConnection(url.toString());
			} catch (ClassNotFoundException | SQLException ex) {
				throw new TskCoreException("Failed to acquire ephemeral connection SQLite database " + dbPath, ex); // NON-NLS
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
		}	

		@Override
		void performPostTableInitialization(Connection conn) throws TskCoreException {
			// Nothing to do here for SQLite
		}
	}
}
