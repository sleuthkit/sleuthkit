/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011-2023 Basis Technology Corp.
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
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ImmutableSet;
import com.google.common.eventbus.EventBus;
import com.google.gson.Gson;
import com.mchange.v2.c3p0.ComboPooledDataSource;
import com.mchange.v2.c3p0.DataSources;
import com.mchange.v2.c3p0.PooledDataSource;
import com.zaxxer.sparsebits.SparseBitSet;
import java.beans.PropertyVetoException;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.Date;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.Objects;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture; 
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.postgresql.util.PSQLState;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE;
import org.sleuthkit.datamodel.BlackboardArtifact.Category;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;
import org.sleuthkit.datamodel.BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE;
import org.sleuthkit.datamodel.IngestJobInfo.IngestJobStatusType;
import org.sleuthkit.datamodel.IngestModuleInfo.IngestModuleType;
import org.sleuthkit.datamodel.SleuthkitJNI.CaseDbHandle.AddImageProcess;
import org.sleuthkit.datamodel.TimelineManager.TimelineEventAddedEvent;
import org.sleuthkit.datamodel.TskData.DbType;
import static org.sleuthkit.datamodel.TskData.DbType.POSTGRESQL;
import static org.sleuthkit.datamodel.TskData.DbType.SQLITE;
import org.sleuthkit.datamodel.TskData.FileKnown;
import org.sleuthkit.datamodel.TskData.ObjectType;
import org.sleuthkit.datamodel.TskData.TSK_DB_FILES_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_ATTR_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;
import org.sqlite.SQLiteConfig;
import org.sqlite.SQLiteDataSource;
import org.sqlite.SQLiteJDBCLoader;

/**
 * Represents the case database with methods that provide abstractions for
 * database operations.
 */
public class SleuthkitCase {

	private static final int MAX_DB_NAME_LEN_BEFORE_TIMESTAMP = 47;

	static final CaseDbSchemaVersionNumber CURRENT_DB_SCHEMA_VERSION
			= new CaseDbSchemaVersionNumber(9, 6);

	private static final long BASE_ARTIFACT_ID = Long.MIN_VALUE; // Artifact ids will start at the lowest negative value
	private static final Logger logger = Logger.getLogger(SleuthkitCase.class.getName());
	private static final ResourceBundle bundle = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle");
	private static final int IS_REACHABLE_TIMEOUT_MS = 1000;
	private static final String SQL_ERROR_CONNECTION_GROUP = "08";
    // either one of these mean connection was rejected by Postgres server
    private static final String SQL_CONNECTION_REJECTED = "08004";
    private static final String UNABLE_TO_VERIFY_SSL = "08006";
	
	private static final String SQL_ERROR_AUTHENTICATION_GROUP = "28";
	private static final String SQL_ERROR_PRIVILEGE_GROUP = "42";
	private static final String SQL_ERROR_RESOURCE_GROUP = "53";
	private static final String SQL_ERROR_LIMIT_GROUP = "54";
	private static final String SQL_ERROR_INTERNAL_GROUP = "xx";

	private static final Set<String> CORE_TABLE_NAMES = ImmutableSet.of(
			"tsk_events",
			"tsk_event_descriptions",
			"tsk_event_types",
			"tsk_db_info",
			"tsk_objects",
			"tsk_image_info",
			"tsk_image_names",
			"tsk_vs_info",
			"tsk_vs_parts",
			"tsk_fs_info",
			"tsk_file_layout",
			"tsk_files",
			"tsk_files_path",
			"tsk_files_derived",
			"tsk_files_derived_method",
			"tag_names",
			"content_tags",
			"blackboard_artifact_tags",
			"blackboard_artifacts",
			"blackboard_attributes",
			"blackboard_artifact_types",
			"blackboard_attribute_types",
			"data_source_info",
			"file_encoding_types",
			"file_collection_status_types",
			"ingest_module_types",
			"ingest_job_status_types",
			"ingest_modules",
			"ingest_jobs",
			"ingest_job_modules",
			"account_types",
			"accounts",
			"account_relationships",
			"review_statuses",
			"reports,");

	private static final Set<String> CORE_INDEX_NAMES = ImmutableSet.of(
			"parObjId",
			"layout_objID",
			"artifact_objID",
			"artifact_artifact_objID",
			"artifact_typeID",
			"attrsArtifactID",
			"mime_type",
			"file_extension",
			"relationships_account1",
			"relationships_account2",
			"relationships_relationship_source_obj_id",
			"relationships_date_time",
			"relationships_relationship_type",
			"relationships_data_source_obj_id",
			"events_time",
			"events_type",
			"events_data_source_obj_id",
			"events_file_obj_id",
			"events_artifact_id");

	private static final String TSK_VERSION_KEY = "TSK_VER";
	private static final String SCHEMA_MAJOR_VERSION_KEY = "SCHEMA_MAJOR_VERSION";
	private static final String SCHEMA_MINOR_VERSION_KEY = "SCHEMA_MINOR_VERSION";
	private static final String CREATION_SCHEMA_MAJOR_VERSION_KEY = "CREATION_SCHEMA_MAJOR_VERSION";
	private static final String CREATION_SCHEMA_MINOR_VERSION_KEY = "CREATION_SCHEMA_MINOR_VERSION";
	
	// key in acquisition tool settings; the password for decrypting an image
	static final String IMAGE_PASSWORD_KEY = "imagePassword";

	private final ConnectionPool connections;
	private final Object carvedFileDirsLock = new Object();
	private final static int MAX_CARVED_FILES_PER_FOLDER = 2000;
	private final Map<Long, CarvedFileDirInfo> rootIdsToCarvedFileDirs = new HashMap<>();
	private final Map<Long, FileSystem> fileSystemIdMap = new HashMap<>(); // Cache for file system files.
	private final List<ErrorObserver> sleuthkitCaseErrorObservers = new ArrayList<>();
	private final String databaseName;
	private final String dbPath;
	private final DbType dbType;
	private final String caseDirPath;
	private SleuthkitJNI.CaseDbHandle caseHandle;
	private final String caseHandleIdentifier; // Used to identify this case in the JNI cache.
	private String dbBackupPath;
	private AtomicBoolean timelineEventsDisabled = new AtomicBoolean(false);

	private CaseDbSchemaVersionNumber caseDBSchemaCreationVersion;

	// Objects for caching the result of isRootDirectory(). Lock is for visibility only.
	private final Object rootDirectoryMapLock = new Object();
	private final Map<RootDirectoryKey, Long> rootDirectoryMap = new HashMap<>();
	private final Cache<Long, Boolean> isRootDirectoryCache
			= CacheBuilder.newBuilder().maximumSize(200000).expireAfterAccess(5, TimeUnit.MINUTES).build();
	// custom provider for file bytes (can be null)
	private final ContentStreamProvider contentProvider;
	private final LockResources lockResources;
	
	/*
	 * First parameter is used to specify the SparseBitSet to use, as object IDs
	 * can be larger than the max size of a SparseBitSet
	 */
	private final Map<Long, SparseBitSet> hasChildrenBitSetMap = new HashMap<>();
	// Lock to serialize access to the bitset.
	private final ReentrantLock childrenBitSetLock = new ReentrantLock();
	// Latch to enforce a happens before relation
	private final CountDownLatch childrenBitSetInitLatch = new CountDownLatch(1);
	

	private long nextArtifactId; // Used to ensure artifact ids come from the desired range.
	// This read/write lock is used to implement a layer of locking on top of
	// the locking protocol provided by the underlying SQLite database. The Java
	// locking protocol improves performance for reasons that are not currently
	// understood. Note that the lock is contructed to use a fairness policy.
	private final ReentrantReadWriteLock rwLock = new ReentrantReadWriteLock(true);

	private CommunicationsManager communicationsMgr;
	private TimelineManager timelineMgr;
	private Blackboard blackboard;
	private CaseDbAccessManager dbAccessManager;
	private FileManager fileManager;
	private TaggingManager taggingMgr;
	private ScoringManager scoringManager;
	private OsAccountRealmManager osAccountRealmManager;
	private OsAccountManager osAccountManager;
	private HostManager hostManager;
	private PersonManager personManager;
	private HostAddressManager hostAddressManager;

	private final Map<String, Set<Long>> deviceIdToDatasourceObjIdMap = new HashMap<>();

	private final EventBus eventBus = new EventBus("SleuthkitCase-EventBus");

	public void registerForEvents(Object listener) {
		eventBus.register(listener);
	}

	public void unregisterForEvents(Object listener) {
		eventBus.unregister(listener);
	}

	void fireTSKEvent(Object event) {
		eventBus.post(event);
	}

	// Cache of frequently used content objects (e.g. data source, file system).
	private final Map<Long, Content> frequentlyUsedContentMap = new HashMap<>();

	private Examiner cachedCurrentExaminer = null;

	static {
		Properties p = new Properties(System.getProperties());
		p.put("com.mchange.v2.log.MLog", "com.mchange.v2.log.FallbackMLog");
		p.put("com.mchange.v2.log.FallbackMLog.DEFAULT_CUTOFF_LEVEL", "SEVERE");
		System.setProperties(p);
	}

	/**
	 * Attempts to connect to the database with the passed in settings, throws
	 * if the settings are not sufficient to connect to the database type
	 * indicated. Only attempts to connect to remote databases.
	 *
	 * When issues occur, it attempts to diagnose them by looking at the
	 * exception messages, returning the appropriate user-facing text for the
	 * exception received. This method expects the Exceptions messages to be in
	 * English and compares against English text.
	 *
	 * @param info The connection information
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public static void tryConnect(CaseDbConnectionInfo info) throws TskCoreException {
		// Check if we can talk to the database.
		if (info.getHost() == null || info.getHost().isEmpty()) {
			throw new TskCoreException(bundle.getString("DatabaseConnectionCheck.MissingHostname")); //NON-NLS
		} else if (info.getPort() == null || info.getPort().isEmpty()) {
			throw new TskCoreException(bundle.getString("DatabaseConnectionCheck.MissingPort")); //NON-NLS
		} else if (info.getUserName() == null || info.getUserName().isEmpty()) {
			throw new TskCoreException(bundle.getString("DatabaseConnectionCheck.MissingUsername")); //NON-NLS
		} else if (info.getPassword() == null || info.getPassword().isEmpty()) {
			throw new TskCoreException(bundle.getString("DatabaseConnectionCheck.MissingPassword")); //NON-NLS
		}

		try {
			Class.forName("org.postgresql.Driver"); //NON-NLS
			String connectionURL = "jdbc:postgresql://" + info.getHost() + ":" + info.getPort() + "/postgres";
			if (info.isSslEnabled()) {				
				if (info.isSslVerify()) {
					if (info.getCustomSslValidationClassName().isBlank()) {
						connectionURL += CaseDatabaseFactory.SSL_VERIFY_DEFAULT_URL;
					} else {
						// use custom SSL certificate validation class
						connectionURL += CaseDatabaseFactory.getCustomPostrgesSslVerificationUrl(info.getCustomSslValidationClassName());
					}
				} else {
					connectionURL += CaseDatabaseFactory.SSL_NONVERIFY_URL;
				}
			}
			Connection conn = DriverManager.getConnection(connectionURL, info.getUserName(), info.getPassword()); //NON-NLS
			if (conn != null) {
				conn.close();
			}
		} catch (SQLException ex) {
			String result;
			String sqlState = ex.getSQLState().toLowerCase();
			if (sqlState.startsWith(SQL_ERROR_CONNECTION_GROUP)) {				
				if (SQL_CONNECTION_REJECTED.equals(ex.getSQLState())) {
					if (info.isSslEnabled()) {
						result = "Server rejected the SSL connection attempt. Check SSL configuration.";
					} else {
						result = "Server rejected the connection attempt. Check server configuration.";
					}					
				} else if (UNABLE_TO_VERIFY_SSL.equals(ex.getSQLState())) {
					result = "Unable to verify SSL certificates. Check SSL configuration.";
				} else {
					try {
						if (InetAddress.getByName(info.getHost()).isReachable(IS_REACHABLE_TIMEOUT_MS)) {
							// if we can reach the host, then it's probably port problem
							result = bundle.getString("DatabaseConnectionCheck.Port"); //NON-NLS
						} else {
							result = bundle.getString("DatabaseConnectionCheck.HostnameOrPort"); //NON-NLS
						}
					} catch (IOException | MissingResourceException any) {
						// it may be anything
						result = bundle.getString("DatabaseConnectionCheck.Everything"); //NON-NLS
					}
				}
			} else if (sqlState.startsWith(SQL_ERROR_AUTHENTICATION_GROUP)) {
				result = bundle.getString("DatabaseConnectionCheck.Authentication"); //NON-NLS
			} else if (sqlState.startsWith(SQL_ERROR_PRIVILEGE_GROUP)) {
				result = bundle.getString("DatabaseConnectionCheck.Access"); //NON-NLS
			} else if (sqlState.startsWith(SQL_ERROR_RESOURCE_GROUP)) {
				result = bundle.getString("DatabaseConnectionCheck.ServerDiskSpace"); //NON-NLS
			} else if (sqlState.startsWith(SQL_ERROR_LIMIT_GROUP)) {
				result = bundle.getString("DatabaseConnectionCheck.ServerRestart"); //NON-NLS
			} else if (sqlState.startsWith(SQL_ERROR_INTERNAL_GROUP)) {
				result = bundle.getString("DatabaseConnectionCheck.InternalServerIssue"); //NON-NLS
			} else {
				result = bundle.getString("DatabaseConnectionCheck.Connection"); //NON-NLS
			}
			throw new TskCoreException(result);
		} catch (ClassNotFoundException ex) {
			throw new TskCoreException(bundle.getString("DatabaseConnectionCheck.Installation")); //NON-NLS
		}
	}

	/**
	 * Private constructor, clients must use newCase() or openCase() method to
	 * create an instance of this class.
	 *
	 * @param dbPath                 The full path to a SQLite case database
	 *                               file.
	 * @param caseHandle             A handle to a case database object in the
	 *                               native code SleuthKit layer.
	 * @param dbType                 The type of database we're dealing with
	 * @param contentProvider        Custom provider for file content (can be
	 *                               null).
	 * @param lockingApplicationName The name of the application locking the
	 *                               case database (null value prevents
	 *                               locking; 500 character maximum).
	 *
	 * @throws Exception
	 */
	private SleuthkitCase(String dbPath, SleuthkitJNI.CaseDbHandle caseHandle, DbType dbType, ContentStreamProvider contentProvider, String lockingApplicationName) throws Exception {
		Class.forName("org.sqlite.JDBC");
		this.dbPath = dbPath;
		this.dbType = dbType;
		File dbFile = new File(dbPath);
		this.caseDirPath = dbFile.getParentFile().getAbsolutePath();
		this.databaseName = dbFile.getName();

		this.lockResources = lockingApplicationName == null
				? null
				: LockResources.tryAcquireFileLock(this.caseDirPath, this.databaseName, lockingApplicationName);

		this.connections = new SQLiteConnections(dbPath);
		this.caseHandle = caseHandle;
		this.caseHandleIdentifier = caseHandle.getCaseDbIdentifier();
		this.contentProvider = contentProvider;
		init();
		logSQLiteJDBCDriverInfo();
	}

	/**
	 * Private constructor, clients must use newCase() or openCase() method to
	 * create an instance of this class.
	 * 
	 * @param info		  CaseDbConnectionInfo object with database connection info
	 * @param dbName      The name of the case database.
	 * @param caseHandle  A handle to a case database object in the native code
	 * @param caseDirPath The path to the root case directory.
	 * @param contentProvider Custom provider for file content (can be null).
	 * @throws Exception 
	 */
	private SleuthkitCase(CaseDbConnectionInfo info, String dbName, SleuthkitJNI.CaseDbHandle caseHandle, String caseDirPath, ContentStreamProvider contentProvider) throws Exception {
		this.dbPath = "";
		this.databaseName = dbName;
		this.dbType = info.getDbType();
		this.caseDirPath = caseDirPath;
		this.connections = new PostgreSQLConnections(info, dbName);
		this.caseHandle = caseHandle;
		this.caseHandleIdentifier = caseHandle.getCaseDbIdentifier();
		this.contentProvider = contentProvider;
		this.lockResources = null;
		init();
	}

	private void init() throws Exception {
		blackboard = new Blackboard(this);
		updateDatabaseSchema(null); 
		try (CaseDbConnection connection = connections.getConnection()) {
			blackboard.initBlackboardArtifactTypes(connection);
			blackboard.initBlackboardAttributeTypes(connection);
			initNextArtifactId(connection);
			initIngestModuleTypes(connection);
			initIngestStatusTypes(connection);
			initReviewStatuses(connection);
			initEncodingTypes(connection);
			initCollectedStatusTypes(connection);
			populateHasChildrenMap(true);
			updateExaminers(connection);
			initDBSchemaCreationVersion(connection);
		} 

		fileManager = new FileManager(this);
		communicationsMgr = new CommunicationsManager(this);
		timelineMgr = new TimelineManager(this);
		dbAccessManager = new CaseDbAccessManager(this);
		taggingMgr = new TaggingManager(this);
		scoringManager = new ScoringManager(this);
		osAccountRealmManager = new OsAccountRealmManager(this);
		osAccountManager = new OsAccountManager(this);
		hostManager = new HostManager(this);
		personManager = new PersonManager(this);
		hostAddressManager = new HostAddressManager(this); 
	}
	
	/**
	 * Returns the custom content provider for this case if one exists.
	 * Otherwise, returns null.
	 *
	 * @return The custom content provider for this case if one exists.
	 *         Otherwise, returns null.
	 */
	ContentStreamProvider getContentProvider() {
		return this.contentProvider;
	}

	/**
	 * Returns a set of core table names in the SleuthKit Case database.
	 *
	 * @return set of core table names
	 */
	static Set<String> getCoreTableNames() {
		return Collections.unmodifiableSet(CORE_TABLE_NAMES);
	}

	/**
	 * Returns a set of core index names in the SleuthKit case database.
	 *
	 * @return set of core index names
	 */
	static Set<String> getCoreIndexNames() {
		return Collections.unmodifiableSet(CORE_INDEX_NAMES);
	}

	/**
	 * Use the internal map to determine whether the content object has children
	 * (of any type).
	 *
	 * @param content
	 *
	 * @return true if the content has children, false otherwise
	 */
	boolean getHasChildren(Content content) {
		
		try {
			// Await initialization 
			childrenBitSetInitLatch.await();
		} catch (InterruptedException ex) {
			throw new AssertionError("Interrupted Exception awaiting Children bit set initialization", ex); //NON-NLS
		}
		childrenBitSetLock.lock();
		try {
			long objId = content.getId();
			long mapIndex = objId / Integer.MAX_VALUE;
			int mapValue = (int) (objId % Integer.MAX_VALUE);

			if (hasChildrenBitSetMap.containsKey(mapIndex)) {
				return hasChildrenBitSetMap.get(mapIndex).get(mapValue);
			}
			return false;

		} finally {
			childrenBitSetLock.unlock();
		}
	}

	/**
	 * Add this objId to the list of objects that have children (of any type)
	 *
	 * @param objId
	 */
	private void setHasChildren(Long objId) {
		setHasChildren(objId, false);
	}

	/**
	 * Add this objId to the list of objects that have children (of any type)
	 * @param objId
	 * @param initializing set to true if invoked from initialization
	 */
	private void setHasChildren(Long objId, boolean initializing) {
		try {
			if (!initializing) {
				// Await initialization 
				childrenBitSetInitLatch.await();
			}
		} catch (InterruptedException ex) {
			throw new AssertionError("Interrupted Exception awaiting Children bit set initialization",ex); //NON-NLS
		}

		childrenBitSetLock.lock();
		try {
			long mapIndex = objId / Integer.MAX_VALUE;
			int mapValue = (int) (objId % Integer.MAX_VALUE);

			if (hasChildrenBitSetMap.containsKey(mapIndex)) {
				hasChildrenBitSetMap.get(mapIndex).set(mapValue);
			} else {
				SparseBitSet bitSet = new SparseBitSet();
				bitSet.set(mapValue);
				hasChildrenBitSetMap.put(mapIndex, bitSet);
			}
		} finally {
			childrenBitSetLock.unlock();
		}
	}

	/**
	 * Gets the communications manager for this case.
	 *
	 * @return The per case CommunicationsManager object.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public CommunicationsManager getCommunicationsManager() throws TskCoreException {
		return communicationsMgr;
	}

	/**
	 * Gets the artifacts blackboard for this case.
	 *
	 * @return The per case Blackboard object.
	 */
	public Blackboard getBlackboard() {
		return blackboard;
	}

	/**
	 * Gets the file manager for this case.
	 *
	 * @return The per case FileManager object.
	 */
	public FileManager getFileManager() {
		return fileManager;
	}

	/**
	 * Gets the communications manager for this case.
	 *
	 * @return The per case TimelineManager object.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public TimelineManager getTimelineManager() throws TskCoreException {
		return timelineMgr;
	}

	/*
	 * Gets the case database access manager for this case.
	 *
	 * @return The per case CaseDbAccessManager object.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public synchronized CaseDbAccessManager getCaseDbAccessManager() throws TskCoreException {
		return dbAccessManager;
	}

	/**
	 * Get the case database TaggingManager object.
	 *
	 * @return The per case TaggingManager object.
	 */
	public synchronized TaggingManager getTaggingManager() {
		return taggingMgr;
	}

	/**
	 * Gets the scoring manager for this case.
	 *
	 * @return The per case ScoringManager object.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public ScoringManager getScoringManager() throws TskCoreException {
		return scoringManager;
	}

	/**
	 * Gets the OS account realm manager for this case.
	 *
	 * @return The per case OsAccountRealmManager object.
	 *
	 * @throws TskCoreException
	 */
	public OsAccountRealmManager getOsAccountRealmManager() throws TskCoreException {
		return osAccountRealmManager;
	}

	/**
	 * Gets the OS account manager for this case.
	 *
	 * @return The per case OsAccountManager object.
	 *
	 * @throws TskCoreException
	 */
	public OsAccountManager getOsAccountManager() throws TskCoreException {
		return osAccountManager;
	}

	/**
	 * Gets the Hosts manager for this case.
	 *
	 * @return The per case HostManager object.
	 *
	 * @throws TskCoreException
	 */
	public HostManager getHostManager() throws TskCoreException {
		return hostManager;
	}

	/**
	 * Gets the Person manager for this case.
	 *
	 * @return The per case PersonManager object.
	 *
	 * @throws TskCoreException
	 */
	public PersonManager getPersonManager() throws TskCoreException {
		return personManager;
	}

	/**
	 * Gets the HostAddress manager for this case.
	 *
	 * @return The per case HostAddressManager object.
	 *
	 * @throws TskCoreException
	 */
	public HostAddressManager getHostAddressManager() throws TskCoreException {
		return hostAddressManager;
	}

	/**
	 * Initializes the next artifact id. If there are entries in the
	 * blackboard_artifacts table we will use max(artifact_id) + 1 otherwise we
	 * will initialize the value to 0x8000000000000000 (the maximum negative
	 * signed long).
	 *
	 * @throws SQLException Thrown if there is an error querying the
	 *                      blackboard_artifacts table.
	 */
	private void initNextArtifactId(CaseDbConnection connection) throws SQLException {
		acquireSingleUserCaseReadLock();
		try (Statement statement = connection.createStatement()) {
			ResultSet resultSet = connection.executeQuery(statement, "SELECT MAX(artifact_id) AS max_artifact_id FROM blackboard_artifacts"); //NON-NLS
			resultSet.next();
			nextArtifactId = resultSet.getLong("max_artifact_id") + 1;
			if (nextArtifactId == 1) {
				nextArtifactId = BASE_ARTIFACT_ID;
			}
		} finally {
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Initialize ingest module types by adding them into the
	 * ingest_module_types database.
	 *
	 * @throws SQLException
	 * @throws TskCoreException
	 */
	private void initIngestModuleTypes(CaseDbConnection connection) throws SQLException, TskCoreException {
		Statement statement = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseWriteLock();
		try {
			statement = connection.createStatement();
			for (IngestModuleType type : IngestModuleType.values()) {
				try {
					String query = "INSERT INTO ingest_module_types (type_id, type_name) VALUES (" + type.ordinal() + ", '" + type.toString() + "')"; // NON-NLS
					if (getDatabaseType().equals(DbType.POSTGRESQL)) {
						query += " ON CONFLICT ON CONSTRAINT ingest_module_types_pkey DO NOTHING"; // NON-NLS
					}
					statement.execute(query);
				} catch (SQLException ex) {
					resultSet = connection.executeQuery(statement, "SELECT COUNT(*) as count FROM ingest_module_types WHERE type_id = " + type.ordinal() + ";"); //NON-NLS
					resultSet.next();
					if (resultSet.getLong("count") == 0) {
						throw ex;
					}
					resultSet.close();
					resultSet = null;
				}
			}
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Initialize ingest status types by adding them into the
	 * ingest_job_status_types database.
	 *
	 * @throws SQLException
	 * @throws TskCoreException
	 */
	private void initIngestStatusTypes(CaseDbConnection connection) throws SQLException, TskCoreException {
		Statement statement = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseWriteLock();
		try {
			statement = connection.createStatement();
			for (IngestJobStatusType type : IngestJobStatusType.values()) {
				try {
					String query = "INSERT INTO ingest_job_status_types (type_id, type_name) VALUES (" + type.ordinal() + ", '" + type.toString() + "')"; // NON-NLS
					if (getDatabaseType().equals(DbType.POSTGRESQL)) {
						query += " ON CONFLICT ON CONSTRAINT ingest_job_status_types_pkey DO NOTHING"; // NON-NLS
					}
					statement.execute(query);
				} catch (SQLException ex) {
					resultSet = connection.executeQuery(statement, "SELECT COUNT(*) as count FROM ingest_job_status_types WHERE type_id = " + type.ordinal() + ";"); //NON-NLS
					resultSet.next();
					if (resultSet.getLong("count") == 0) {
						throw ex;
					}
					resultSet.close();
					resultSet = null;
				}
			}
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Initialize the review statuses lookup table from the ReviewStatus enum.
	 *
	 * @throws SQLException
	 * @throws TskCoreException if there is an error initializing the table.
	 */
	private void initReviewStatuses(CaseDbConnection connection) throws SQLException, TskCoreException {
		Statement statement = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseWriteLock();
		try {
			statement = connection.createStatement();
			for (BlackboardArtifact.ReviewStatus status : BlackboardArtifact.ReviewStatus.values()) {
				try {
					String query = "INSERT INTO review_statuses (review_status_id, review_status_name, display_name) " //NON-NLS
							+ "VALUES (" + status.getID() + ",'" + status.getName() + "','" + status.getDisplayName() + "')";
					if (getDatabaseType().equals(DbType.POSTGRESQL)) {
						query += " ON CONFLICT ON CONSTRAINT review_statuses_pkey DO NOTHING"; // NON-NLS
					}
					statement.execute(query);
				} catch (SQLException ex) {
					resultSet = connection.executeQuery(statement, "SELECT COUNT(*) as count FROM review_statuses WHERE review_status_id = " + status.getID()); //NON-NLS
					resultSet.next();
					if (resultSet.getLong("count") == 0) {
						throw ex;
					}
					resultSet.close();
					resultSet = null;
				}
			}
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Put the file encoding types into the table. This must be called after the
	 * database upgrades or the encoding_types table will not exist.
	 *
	 * @throws SQLException
	 * @throws TskCoreException
	 */
	private void initEncodingTypes(CaseDbConnection connection) throws SQLException, TskCoreException {
		Statement statement = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseWriteLock();
		try {
			statement = connection.createStatement();
			for (TskData.EncodingType type : TskData.EncodingType.values()) {
				try {
					String query = "INSERT INTO file_encoding_types (encoding_type, name) VALUES (" + type.getType() + " , '" + type.name() + "')"; // NON-NLS
					if (getDatabaseType().equals(DbType.POSTGRESQL)) {
						query += " ON CONFLICT ON CONSTRAINT file_encoding_types_pkey DO NOTHING"; // NON-NLS
					}
					statement.execute(query);
				} catch (SQLException ex) {
					resultSet = connection.executeQuery(statement, "SELECT COUNT(*) as count FROM file_encoding_types WHERE encoding_type = " + type.getType()); //NON-NLS
					resultSet.next();
					if (resultSet.getLong("count") == 0) {
						throw ex;
					}
					resultSet.close();
					resultSet = null;
				}
			}
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Put the collected status types into the table. This must be called after the
	 * database upgrades or the file_collection_status_types table will not exist.
	 *
	 * @throws SQLException
	 * @throws TskCoreException
	 */
	private void initCollectedStatusTypes(CaseDbConnection connection) throws SQLException, TskCoreException {
		Statement statement = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseWriteLock();
		try {
			statement = connection.createStatement();
			for (TskData.CollectedStatus type : TskData.CollectedStatus.values()) {
				try {
					String query = "INSERT INTO file_collection_status_types (collection_status_type, name) VALUES (" + type.getType() + " , '" + type.name() + "')"; // NON-NLS
					if (getDatabaseType().equals(DbType.POSTGRESQL)) {
						query += " ON CONFLICT ON CONSTRAINT file_collection_status_types_pkey DO NOTHING"; // NON-NLS
					}
					statement.execute(query);
				} catch (SQLException ex) {
					resultSet = connection.executeQuery(statement, "SELECT COUNT(*) as count FROM file_collection_status_types WHERE collection_status_type = " + type.getType()); //NON-NLS
					resultSet.next();
					if (resultSet.getLong("count") == 0) {
						throw ex;
					}
					resultSet.close();
					resultSet = null;
				}
			}
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Records the current examiner name in the tsk_examiners table
	 *
	 * @param CaseDbConnection
	 *
	 * @throws SQLException
	 * @throws TskCoreException
	 */
	private void updateExaminers(CaseDbConnection connection) throws SQLException, TskCoreException {

		String loginName = System.getProperty("user.name");
		if (loginName.isEmpty()) {
			logger.log(Level.SEVERE, "Cannot determine logged in user name");
			return;
		}

		acquireSingleUserCaseWriteLock();
		try {
			PreparedStatement statement;
			switch (getDatabaseType()) {
				case POSTGRESQL:
					statement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_EXAMINER_POSTGRESQL);
					break;
				case SQLITE:
					statement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_EXAMINER_SQLITE);
					break;
				default:
					throw new TskCoreException("Unknown DB Type: " + getDatabaseType().name());
			}
			statement.clearParameters();
			statement.setString(1, loginName);
			connection.executeUpdate(statement);
		} catch (SQLException ex) {
			throw new TskCoreException("Error inserting row in tsk_examiners. login name: " + loginName, ex);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Set up or update the hasChildren map using the tsk_objects table.
	 * 
	 * @throws TskCoreException
	 */
	private void populateHasChildrenMap(boolean async) throws TskCoreException {
		
		Runnable childrenBitSetLockInitRunnable =  () -> {
			
			/**
			 * This lock is insufficient to handle the case where this thread 
			 * starts non-deterministically. {@link #childrenBitSetInitLatch} 
			 * is countdown at the end of the initialization to provide the necessary guarantees. 
			 */
			childrenBitSetLock.lock();
			// The distinct parent objeect id lookup is expensive in postgresql 
			// This is offloaded into a thread and the incident open proceeds. 
			// The access to the results are guarded by an object lock on hasChildrenBitSetMap. 
			// The issue with this approach is that the SQLException will not cause a TSKCOreException. 
			// Since this is running async, it also acquires a new connection from the pool
			
			long timestamp = System.currentTimeMillis();

			Statement statement = null;
			ResultSet resultSet = null;
			acquireSingleUserCaseWriteLock();			
			try (CaseDbConnection neoConnection = connections.getConnection()) {
				statement = neoConnection.createStatement();
				String query = "select distinct par_obj_id from tsk_objects";
				if (dbType == DbType.POSTGRESQL) {
					query = "select distinct ON (par_obj_id) par_obj_id from tsk_objects";
				}

				resultSet = statement.executeQuery(query); //NON-NLS

				/**
				 * Operating under the re-entrant lock {@link #childrenBitSetLock}
				 */
				while (resultSet.next()) {
					setHasChildren(resultSet.getLong("par_obj_id"), true);
				}

				long delay = System.currentTimeMillis() - timestamp;
				logger.log(Level.INFO, "Time to initialize parent node cache: {0} ms", delay); //NON-NLS
			} catch (SQLException ex) {
				logger.log(Level.SEVERE, "Error populating parent node cache", ex); //NON-NLS
				// Dont really expect this to be thrown, but if this happens, then it is non-recoverable. 
				throw new AssertionError("Error populating parent node cache",ex); //NON-NLS
			} catch (TskCoreException ex) {
				logger.log(Level.SEVERE, "Error acquiring connection", ex); //NON-NLS
				throw new AssertionError("Error acquiring connection",ex); //NON-NLS
			} finally {
				closeResultSet(resultSet);
				closeStatement(statement);
				releaseSingleUserCaseWriteLock();
				childrenBitSetLock.unlock();
				// Countdown the latch as initialization has completed. 
				childrenBitSetInitLatch.countDown(); 
			}
		};

		if (async) {
			CompletableFuture.runAsync(childrenBitSetLockInitRunnable);
		} else {
			childrenBitSetLockInitRunnable.run();
		}
	}

	/**
	 * Add the object IDs for a new data source to the has children map. At
	 * present, we simply reload the entire table.
	 *
	 * @throws TskCoreException
	 */
	void addDataSourceToHasChildrenMap() throws TskCoreException {
		try {
			// Await initialization. ensure no async version of the init is still running.
			childrenBitSetInitLatch.await();
		} catch (InterruptedException ex) {
			throw new AssertionError("Interrupted Exception awaiting Children bit set initialization", ex); //NON-NLS
		}
		populateHasChildrenMap(false);		 
	}

	/**
	 * Modify the case database to bring it up-to-date with the current version
	 * of the database schema.
	 *
	 * @param dbPath Path to the db file. If dbPath is null, no backup will be
	 *               made.
	 *
	 * @throws Exception
	 */
	private void updateDatabaseSchema(String dbPath) throws Exception {
		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		acquireSingleUserCaseWriteLock();
		try {
			connection = connections.getConnection();
			connection.beginTransaction();

			boolean hasMinorVersion = false;
			ResultSet columns = connection.getConnection().getMetaData().getColumns(null, null, "tsk_db_info", "schema%");
			while (columns.next()) {
				if (columns.getString("COLUMN_NAME").equals("schema_minor_ver")) {
					hasMinorVersion = true;
				}
			}

			// Get the schema version number of the case database from the tsk_db_info table.
			int dbSchemaMajorVersion;
			int dbSchemaMinorVersion = 0; //schemas before 7 have no minor version , default it to zero.

			statement = connection.createStatement();
			resultSet = connection.executeQuery(statement, "SELECT schema_ver"
					+ (hasMinorVersion ? ", schema_minor_ver" : "")
					+ " FROM tsk_db_info"); //NON-NLS
			if (resultSet.next()) {
				dbSchemaMajorVersion = resultSet.getInt("schema_ver"); //NON-NLS
				if (hasMinorVersion) {
					//if there is a minor version column, use it, else default to zero.
					dbSchemaMinorVersion = resultSet.getInt("schema_minor_ver"); //NON-NLS
				}
			} else {
				throw new TskCoreException();
			}
			CaseDbSchemaVersionNumber dbSchemaVersion = new CaseDbSchemaVersionNumber(dbSchemaMajorVersion, dbSchemaMinorVersion);

			resultSet.close();
			resultSet = null;
			statement.close();
			statement = null;
			//check schema compatibility
			if (false == CURRENT_DB_SCHEMA_VERSION.isCompatible(dbSchemaVersion)) {
				//we cannot open a db with a major schema version higher than the current one.
				throw new TskUnsupportedSchemaVersionException(
						"Unsupported DB schema version " + dbSchemaVersion + ", the highest supported schema version is " + CURRENT_DB_SCHEMA_VERSION.getMajor() + ".X");
			} else if (dbSchemaVersion.compareTo(CURRENT_DB_SCHEMA_VERSION) < 0) {
				//The schema version is compatible,possibly after upgrades.

				if (null != dbPath) {
					// Make a backup copy of the database. Client code can get the path of the backup
					// using the getBackupDatabasePath() method.
					String backupFilePath = dbPath + ".schemaVer" + dbSchemaVersion.toString() + ".backup"; //NON-NLS
					copyCaseDB(backupFilePath);
					dbBackupPath = backupFilePath;
				}

				// ***CALL SCHEMA UPDATE METHODS HERE***
				// Each method should examine the schema version passed to it and either:
				//    a. do nothing and return the schema version unchanged, or
				//    b. upgrade the database and return the schema version that the db was upgraded to.
				dbSchemaVersion = updateFromSchema2toSchema3(dbSchemaVersion, connection);
				dbSchemaVersion = updateFromSchema3toSchema4(dbSchemaVersion, connection);
				dbSchemaVersion = updateFromSchema4toSchema5(dbSchemaVersion, connection);
				dbSchemaVersion = updateFromSchema5toSchema6(dbSchemaVersion, connection);
				dbSchemaVersion = updateFromSchema6toSchema7(dbSchemaVersion, connection);
				dbSchemaVersion = updateFromSchema7toSchema7dot1(dbSchemaVersion, connection);
				dbSchemaVersion = updateFromSchema7dot1toSchema7dot2(dbSchemaVersion, connection);
				dbSchemaVersion = updateFromSchema7dot2toSchema8dot0(dbSchemaVersion, connection);
				dbSchemaVersion = updateFromSchema8dot0toSchema8dot1(dbSchemaVersion, connection);
				dbSchemaVersion = updateFromSchema8dot1toSchema8dot2(dbSchemaVersion, connection);
				dbSchemaVersion = updateFromSchema8dot2toSchema8dot3(dbSchemaVersion, connection);
				dbSchemaVersion = updateFromSchema8dot3toSchema8dot4(dbSchemaVersion, connection);
				dbSchemaVersion = updateFromSchema8dot4toSchema8dot5(dbSchemaVersion, connection);
				dbSchemaVersion = updateFromSchema8dot5toSchema8dot6(dbSchemaVersion, connection);
				dbSchemaVersion = updateFromSchema8dot6toSchema9dot0(dbSchemaVersion, connection);
				dbSchemaVersion = updateFromSchema9dot0toSchema9dot1(dbSchemaVersion, connection);
				dbSchemaVersion = updateFromSchema9dot1toSchema9dot2(dbSchemaVersion, connection);
				dbSchemaVersion = updateFromSchema9dot2toSchema9dot3(dbSchemaVersion, connection);
				dbSchemaVersion = updateFromSchema9dot3toSchema9dot4(dbSchemaVersion, connection);
				dbSchemaVersion = updateFromSchema9dot4toSchema9dot5(dbSchemaVersion, connection);
				dbSchemaVersion = updateFromSchema9dot5toSchema9dot6(dbSchemaVersion, connection);
				

				statement = connection.createStatement();
				connection.executeUpdate(statement, "UPDATE tsk_db_info SET schema_ver = " + dbSchemaVersion.getMajor() + ", schema_minor_ver = " + dbSchemaVersion.getMinor()); //NON-NLS
				connection.executeUpdate(statement, "UPDATE tsk_db_info_extended SET value = " + dbSchemaVersion.getMajor() + " WHERE name = '" + SCHEMA_MAJOR_VERSION_KEY + "'"); //NON-NLS
				connection.executeUpdate(statement, "UPDATE tsk_db_info_extended SET value = " + dbSchemaVersion.getMinor() + " WHERE name = '" + SCHEMA_MINOR_VERSION_KEY + "'"); //NON-NLS
				statement.close();
				statement = null;
			}

			connection.commitTransaction();
		} catch (Exception ex) { // Cannot do exception multi-catch in Java 6, so use catch-all.
			rollbackTransaction(connection);
			throw ex;
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			closeConnection(connection);
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Get the database schema creation version from database. This must be
	 * called after the database upgrades or the tsk_db_info_extended table may
	 * not exist.
	 *
	 * @throws SQLException
	 */
	private void initDBSchemaCreationVersion(CaseDbConnection connection) throws SQLException {

		Statement statement = null;
		ResultSet resultSet = null;
		String createdSchemaMajorVersion = "0";
		String createdSchemaMinorVersion = "0";
		acquireSingleUserCaseReadLock();
		try {
			statement = connection.createStatement();
			resultSet = connection.executeQuery(statement, "SELECT name, value FROM tsk_db_info_extended");
			while (resultSet.next()) {
				String name = resultSet.getString("name");
				if (name.equals(CREATION_SCHEMA_MAJOR_VERSION_KEY) || name.equals("CREATED_SCHEMA_MAJOR_VERSION")) {
					createdSchemaMajorVersion = resultSet.getString("value");
				} else if (name.equals(CREATION_SCHEMA_MINOR_VERSION_KEY) || name.equals("CREATED_SCHEMA_MINOR_VERSION")) {
					createdSchemaMinorVersion = resultSet.getString("value");
				}
			}

		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			releaseSingleUserCaseReadLock();
		}

		caseDBSchemaCreationVersion = new CaseDbSchemaVersionNumber(Integer.parseInt(createdSchemaMajorVersion), Integer.parseInt(createdSchemaMinorVersion));
	}

	/**
	 * Make a duplicate / backup copy of the current case database. Makes a new
	 * copy only, and continues to use the current connection.
	 *
	 * @param newDBPath Path to the copy to be created. File will be overwritten
	 *                  if it exists.
	 *
	 * @throws IOException if copying fails.
	 */
	public void copyCaseDB(String newDBPath) throws IOException {
		if (dbPath.isEmpty()) {
			throw new IOException("Copying case database files is not supported for this type of case database"); //NON-NLS
		}
		InputStream in = null;
		OutputStream out = null;
		acquireSingleUserCaseWriteLock();
		try {
			InputStream inFile = new FileInputStream(dbPath);
			in = new BufferedInputStream(inFile);
			OutputStream outFile = new FileOutputStream(newDBPath);
			out = new BufferedOutputStream(outFile);
			int bytesRead = in.read();
			while (bytesRead != -1) {
				out.write(bytesRead);
				bytesRead = in.read();
			}
		} finally {
			try {
				if (in != null) {
					in.close();
				}
				if (out != null) {
					out.flush();
					out.close();
				}
			} catch (IOException e) {
				logger.log(Level.WARNING, "Could not close streams after db copy", e); //NON-NLS
			}
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Write some SQLite JDBC driver details to the log file.
	 */
	private void logSQLiteJDBCDriverInfo() {
		try {
			SleuthkitCase.logger.info(String.format("sqlite-jdbc version %s loaded in %s mode", //NON-NLS
					SQLiteJDBCLoader.getVersion(), SQLiteJDBCLoader.isNativeMode()
					? "native" : "pure-java")); //NON-NLS
		} catch (Exception ex) {
			SleuthkitCase.logger.log(Level.SEVERE, "Error querying case database mode", ex);
		}
	}

	/**
	 * Updates a schema version 2 database to a schema version 3 database.
	 *
	 * @param schemaVersion The current schema version of the database.
	 * @param connection    A connection to the case database.
	 *
	 * @return The new database schema version.
	 *
	 * @throws SQLException     If there is an error completing a database
	 *                          operation.
	 * @throws TskCoreException If there is an error completing a database
	 *                          operation via another SleuthkitCase method.
	 */
	@SuppressWarnings("deprecation")
	private CaseDbSchemaVersionNumber updateFromSchema2toSchema3(CaseDbSchemaVersionNumber schemaVersion, CaseDbConnection connection) throws SQLException, TskCoreException {
		if (schemaVersion.getMajor() != 2) {
			return schemaVersion;
		}
		Statement statement = null;
		Statement statement2 = null;
		Statement updateStatement = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseWriteLock();
		try {
			statement = connection.createStatement();
			statement2 = connection.createStatement();

			// Add new tables for tags.
			statement.execute("CREATE TABLE tag_names (tag_name_id INTEGER PRIMARY KEY, display_name TEXT UNIQUE, description TEXT NOT NULL, color TEXT NOT NULL)"); //NON-NLS
			statement.execute("CREATE TABLE content_tags (tag_id INTEGER PRIMARY KEY, obj_id INTEGER NOT NULL, tag_name_id INTEGER NOT NULL, comment TEXT NOT NULL, begin_byte_offset INTEGER NOT NULL, end_byte_offset INTEGER NOT NULL)"); //NON-NLS
			statement.execute("CREATE TABLE blackboard_artifact_tags (tag_id INTEGER PRIMARY KEY, artifact_id INTEGER NOT NULL, tag_name_id INTEGER NOT NULL, comment TEXT NOT NULL)"); //NON-NLS

			// Add a new table for reports.
			statement.execute("CREATE TABLE reports (report_id INTEGER PRIMARY KEY, path TEXT NOT NULL, crtime INTEGER NOT NULL, src_module_name TEXT NOT NULL, report_name TEXT NOT NULL)"); //NON-NLS

			// Add new columns to the image info table.
			statement.execute("ALTER TABLE tsk_image_info ADD COLUMN size INTEGER;"); //NON-NLS
			statement.execute("ALTER TABLE tsk_image_info ADD COLUMN md5 TEXT;"); //NON-NLS
			statement.execute("ALTER TABLE tsk_image_info ADD COLUMN display_name TEXT;"); //NON-NLS

			// Add a new column to the file system info table.
			statement.execute("ALTER TABLE tsk_fs_info ADD COLUMN display_name TEXT;"); //NON-NLS

			// Add a new column to the file table.
			statement.execute("ALTER TABLE tsk_files ADD COLUMN meta_seq INTEGER;"); //NON-NLS

			// Add new columns and indexes to the attributes table and populate the
			// new column. Note that addition of the new column is a denormalization
			// to optimize attribute queries.
			statement.execute("ALTER TABLE blackboard_attributes ADD COLUMN artifact_type_id INTEGER NULL NOT NULL DEFAULT -1;"); //NON-NLS
			statement.execute("CREATE INDEX attribute_artifactTypeId ON blackboard_attributes(artifact_type_id);"); //NON-NLS
			statement.execute("CREATE INDEX attribute_valueText ON blackboard_attributes(value_text);"); //NON-NLS
			statement.execute("CREATE INDEX attribute_valueInt32 ON blackboard_attributes(value_int32);"); //NON-NLS
			statement.execute("CREATE INDEX attribute_valueInt64 ON blackboard_attributes(value_int64);"); //NON-NLS
			statement.execute("CREATE INDEX attribute_valueDouble ON blackboard_attributes(value_double);"); //NON-NLS
			resultSet = statement.executeQuery("SELECT attrs.artifact_id AS artifact_id, " //NON-NLS
					+ "arts.artifact_type_id AS artifact_type_id " //NON-NLS
					+ "FROM blackboard_attributes AS attrs " //NON-NLS
					+ "INNER JOIN blackboard_artifacts AS arts " //NON-NLS
					+ "WHERE attrs.artifact_id = arts.artifact_id;"); //NON-NLS
			updateStatement = connection.createStatement();
			while (resultSet.next()) {
				long artifactId = resultSet.getLong("artifact_id");
				int artifactTypeId = resultSet.getInt("artifact_type_id");
				updateStatement.executeUpdate(
						"UPDATE blackboard_attributes " //NON-NLS
						+ "SET artifact_type_id = " + artifactTypeId //NON-NLS
						+ " WHERE blackboard_attributes.artifact_id = " + artifactId + ";"); //NON-NLS
			}
			resultSet.close();

			// Convert existing tag artifact and attribute rows to rows in the new tags tables.
			Map<String, Long> tagNames = new HashMap<>();
			long tagNameCounter = 1;

			// Convert file tags.
			// We need data from the TSK_TAG_NAME and TSK_COMMENT attributes, and need the file size from the tsk_files table.
			resultSet = statement.executeQuery("SELECT * FROM \n"
					+ "(SELECT blackboard_artifacts.obj_id AS objId, blackboard_attributes.artifact_id AS artifactId, blackboard_attributes.value_text AS name\n"
					+ "FROM blackboard_artifacts INNER JOIN blackboard_attributes \n"
					+ "ON blackboard_artifacts.artifact_id = blackboard_attributes.artifact_id \n"
					+ "WHERE blackboard_artifacts.artifact_type_id = "
					+ BlackboardArtifact.ARTIFACT_TYPE.TSK_TAG_FILE.getTypeID()
					+ " AND blackboard_attributes.attribute_type_id = " + BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TAG_NAME.getTypeID()
					+ ") AS tagNames \n"
					+ "INNER JOIN \n"
					+ "(SELECT tsk_files.obj_id as objId2, tsk_files.size AS fileSize \n"
					+ "FROM blackboard_artifacts INNER JOIN tsk_files \n"
					+ "ON blackboard_artifacts.obj_id = tsk_files.obj_id) AS fileData \n"
					+ "ON tagNames.objId = fileData.objId2 \n"
					+ "LEFT JOIN \n"
					+ "(SELECT value_text AS comment, artifact_id AS tagArtifactId FROM blackboard_attributes WHERE attribute_type_id = "
					+ BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT.getTypeID() + ") AS tagComments \n"
					+ "ON tagNames.artifactId = tagComments.tagArtifactId");

			while (resultSet.next()) {
				long objId = resultSet.getLong("objId");
				long fileSize = resultSet.getLong("fileSize");
				String tagName = resultSet.getString("name");
				String tagComment = resultSet.getString("comment");
				if (tagComment == null) {
					tagComment = "";
				}

				if (tagName != null && !tagName.isEmpty()) {
					// Get the index for the tag name, adding it to the database if needed.
					long tagNameIndex;
					if (tagNames.containsKey(tagName)) {
						tagNameIndex = tagNames.get(tagName);
					} else {
						statement2.execute("INSERT INTO tag_names (display_name, description, color) "
								+ "VALUES(\"" + tagName + "\", \"\", \"None\")");
						tagNames.put(tagName, tagNameCounter);
						tagNameIndex = tagNameCounter;
						tagNameCounter++;
					}

					statement2.execute("INSERT INTO content_tags (obj_id, tag_name_id, comment, begin_byte_offset, end_byte_offset) "
							+ "VALUES(" + objId + ", " + tagNameIndex + ", \"" + tagComment + "\", 0, " + fileSize + ")");
				}
			}
			resultSet.close();

			// Convert artifact tags.
			// We need data from the TSK_TAG_NAME, TSK_TAGGED_ARTIFACT, and TSK_COMMENT attributes.
			resultSet = statement.executeQuery("SELECT * FROM \n"
					+ "(SELECT blackboard_artifacts.obj_id AS objId, blackboard_attributes.artifact_id AS artifactId, "
					+ "blackboard_attributes.value_text AS name\n"
					+ "FROM blackboard_artifacts INNER JOIN blackboard_attributes \n"
					+ "ON blackboard_artifacts.artifact_id = blackboard_attributes.artifact_id \n"
					+ "WHERE blackboard_artifacts.artifact_type_id = "
					+ BlackboardArtifact.ARTIFACT_TYPE.TSK_TAG_ARTIFACT.getTypeID()
					+ " AND blackboard_attributes.attribute_type_id = " + BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TAG_NAME.getTypeID()
					+ ") AS tagNames \n"
					+ "INNER JOIN \n"
					+ "(SELECT value_int64 AS taggedArtifactId, artifact_id AS associatedArtifactId FROM blackboard_attributes WHERE attribute_type_id = "
					+ BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TAGGED_ARTIFACT.getTypeID() + ") AS tagArtifacts \n"
					+ "ON tagNames.artifactId = tagArtifacts.associatedArtifactId \n"
					+ "LEFT JOIN \n"
					+ "(SELECT value_text AS comment, artifact_id AS commentArtifactId FROM blackboard_attributes WHERE attribute_type_id = "
					+ BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT.getTypeID() + ") AS tagComments \n"
					+ "ON tagNames.artifactId = tagComments.commentArtifactId");

			while (resultSet.next()) {
				long artifactId = resultSet.getLong("taggedArtifactId");
				String tagName = resultSet.getString("name");
				String tagComment = resultSet.getString("comment");
				if (tagComment == null) {
					tagComment = "";
				}
				if (tagName != null && !tagName.isEmpty()) {
					// Get the index for the tag name, adding it to the database if needed.
					long tagNameIndex;
					if (tagNames.containsKey(tagName)) {
						tagNameIndex = tagNames.get(tagName);
					} else {
						statement2.execute("INSERT INTO tag_names (display_name, description, color) "
								+ "VALUES(\"" + tagName + "\", \"\", \"None\")");
						tagNames.put(tagName, tagNameCounter);
						tagNameIndex = tagNameCounter;
						tagNameCounter++;
					}

					statement2.execute("INSERT INTO blackboard_artifact_tags (artifact_id, tag_name_id, comment) "
							+ "VALUES(" + artifactId + ", " + tagNameIndex + ", \"" + tagComment + "\")");
				}
			}
			resultSet.close();

			statement.execute(
					"DELETE FROM blackboard_attributes WHERE artifact_id IN " //NON-NLS
					+ "(SELECT artifact_id FROM blackboard_artifacts WHERE artifact_type_id = " //NON-NLS
					+ ARTIFACT_TYPE.TSK_TAG_FILE.getTypeID()
					+ " OR artifact_type_id = " + ARTIFACT_TYPE.TSK_TAG_ARTIFACT.getTypeID() + ");"); //NON-NLS
			statement.execute(
					"DELETE FROM blackboard_artifacts WHERE artifact_type_id = " //NON-NLS
					+ ARTIFACT_TYPE.TSK_TAG_FILE.getTypeID()
					+ " OR artifact_type_id = " + ARTIFACT_TYPE.TSK_TAG_ARTIFACT.getTypeID() + ";"); //NON-NLS

			return new CaseDbSchemaVersionNumber(3, 0);
		} finally {
			closeStatement(updateStatement);
			closeResultSet(resultSet);
			closeStatement(statement);
			closeStatement(statement2);
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Updates a schema version 3 database to a schema version 4 database.
	 *
	 * @param schemaVersion The current schema version of the database.
	 * @param connection    A connection to the case database.
	 *
	 * @return The new database schema version.
	 *
	 * @throws SQLException     If there is an error completing a database
	 *                          operation.
	 * @throws TskCoreException If there is an error completing a database
	 *                          operation via another SleuthkitCase method.
	 */
	private CaseDbSchemaVersionNumber updateFromSchema3toSchema4(CaseDbSchemaVersionNumber schemaVersion, CaseDbConnection connection) throws SQLException, TskCoreException {
		if (schemaVersion.getMajor() != 3) {
			return schemaVersion;
		}

		Statement statement = null;
		ResultSet resultSet = null;
		Statement queryStatement = null;
		ResultSet queryResultSet = null;
		Statement updateStatement = null;
		acquireSingleUserCaseWriteLock();
		try {
			// Add mime_type column to tsk_files table. Populate with general
			// info artifact file signature data.
			statement = connection.createStatement();
			updateStatement = connection.createStatement();
			statement.execute("ALTER TABLE tsk_files ADD COLUMN mime_type TEXT;");
			resultSet = statement.executeQuery("SELECT files.obj_id AS obj_id, attrs.value_text AS value_text "
					+ "FROM tsk_files AS files, blackboard_attributes AS attrs, blackboard_artifacts AS arts "
					+ "WHERE files.obj_id = arts.obj_id AND "
					+ "arts.artifact_id = attrs.artifact_id AND "
					+ "arts.artifact_type_id = 1 AND "
					+ "attrs.attribute_type_id = 62");
			while (resultSet.next()) {
				updateStatement.executeUpdate(
						"UPDATE tsk_files " //NON-NLS
						+ "SET mime_type = '" + resultSet.getString("value_text") + "' " //NON-NLS
						+ "WHERE tsk_files.obj_id = " + resultSet.getInt("obj_id") + ";"); //NON-NLS
			}
			resultSet.close();

			// Add value_type column to blackboard_attribute_types table.
			statement.execute("ALTER TABLE blackboard_attribute_types ADD COLUMN value_type INTEGER NOT NULL DEFAULT -1;");
			resultSet = statement.executeQuery("SELECT * FROM blackboard_attribute_types AS types"); //NON-NLS
			while (resultSet.next()) {
				int attributeTypeId = resultSet.getInt("attribute_type_id");
				String attributeLabel = resultSet.getString("type_name");
				if (attributeTypeId < Blackboard.MIN_USER_DEFINED_TYPE_ID) {
					updateStatement.executeUpdate(
							"UPDATE blackboard_attribute_types " //NON-NLS
							+ "SET value_type = " + ATTRIBUTE_TYPE.fromLabel(attributeLabel).getValueType().getType() + " " //NON-NLS
							+ "WHERE blackboard_attribute_types.attribute_type_id = " + attributeTypeId + ";"); //NON-NLS
				}
			}
			resultSet.close();

			// Add a data_sources_info table.
			queryStatement = connection.createStatement();
			statement.execute("CREATE TABLE data_source_info (obj_id INTEGER PRIMARY KEY, device_id TEXT NOT NULL, time_zone TEXT NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id));");
			resultSet = statement.executeQuery("SELECT * FROM tsk_objects WHERE par_obj_id IS NULL");
			while (resultSet.next()) {
				long objectId = resultSet.getLong("obj_id");
				String timeZone = "";
				queryResultSet = queryStatement.executeQuery("SELECT tzone FROM tsk_image_info WHERE obj_id = " + objectId);
				if (queryResultSet.next()) {
					timeZone = queryResultSet.getString("tzone");
				}
				queryResultSet.close();
				updateStatement.executeUpdate("INSERT INTO data_source_info (obj_id, device_id, time_zone) "
						+ "VALUES(" + objectId + ", '" + UUID.randomUUID().toString() + "' , '" + timeZone + "');");
			}
			resultSet.close();

			// Add data_source_obj_id column to the tsk_files table.
			//
			// NOTE: A new case database will have the following FK constraint:
			//
			// REFERENCES data_source_info (obj_id)
			//
			// The constraint is sacrificed here to avoid having to create and
			// populate a new tsk_files table.
			//
			// TODO: Do this right.
			statement.execute("ALTER TABLE tsk_files ADD COLUMN data_source_obj_id BIGINT NOT NULL DEFAULT -1;");
			resultSet = statement.executeQuery("SELECT tsk_files.obj_id AS obj_id, par_obj_id FROM tsk_files, tsk_objects WHERE tsk_files.obj_id = tsk_objects.obj_id");
			while (resultSet.next()) {
				long fileId = resultSet.getLong("obj_id");
				long dataSourceId = getDataSourceObjectId(connection, fileId);
				updateStatement.executeUpdate("UPDATE tsk_files SET data_source_obj_id = " + dataSourceId + " WHERE obj_id = " + fileId + ";");
			}
			resultSet.close();
			statement.execute("CREATE TABLE ingest_module_types (type_id INTEGER PRIMARY KEY, type_name TEXT NOT NULL)"); //NON-NLS
			statement.execute("CREATE TABLE ingest_job_status_types (type_id INTEGER PRIMARY KEY, type_name TEXT NOT NULL)"); //NON-NLS
			if (this.dbType.equals(DbType.SQLITE)) {
				statement.execute("CREATE TABLE ingest_modules (ingest_module_id INTEGER PRIMARY KEY, display_name TEXT NOT NULL, unique_name TEXT UNIQUE NOT NULL, type_id INTEGER NOT NULL, version TEXT NOT NULL, FOREIGN KEY(type_id) REFERENCES ingest_module_types(type_id));"); //NON-NLS
				statement.execute("CREATE TABLE ingest_jobs (ingest_job_id INTEGER PRIMARY KEY, obj_id BIGINT NOT NULL, host_name TEXT NOT NULL, start_date_time BIGINT NOT NULL, end_date_time BIGINT NOT NULL, status_id INTEGER NOT NULL, settings_dir TEXT, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id), FOREIGN KEY(status_id) REFERENCES ingest_job_status_types(type_id));"); //NON-NLS
			} else {
				statement.execute("CREATE TABLE ingest_modules (ingest_module_id BIGSERIAL PRIMARY KEY, display_name TEXT NOT NULL, unique_name TEXT UNIQUE NOT NULL, type_id INTEGER NOT NULL, version TEXT NOT NULL, FOREIGN KEY(type_id) REFERENCES ingest_module_types(type_id));"); //NON-NLS
				statement.execute("CREATE TABLE ingest_jobs (ingest_job_id BIGSERIAL PRIMARY KEY, obj_id BIGINT NOT NULL, host_name TEXT NOT NULL, start_date_time BIGINT NOT NULL, end_date_time BIGINT NOT NULL, status_id INTEGER NOT NULL, settings_dir TEXT, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id), FOREIGN KEY(status_id) REFERENCES ingest_job_status_types(type_id));"); //NON-NLS
			}

			statement.execute("CREATE TABLE ingest_job_modules (ingest_job_id INTEGER, ingest_module_id INTEGER, pipeline_position INTEGER, PRIMARY KEY(ingest_job_id, ingest_module_id), FOREIGN KEY(ingest_job_id) REFERENCES ingest_jobs(ingest_job_id), FOREIGN KEY(ingest_module_id) REFERENCES ingest_modules(ingest_module_id));"); //NON-NLS
			initIngestModuleTypes(connection);
			initIngestStatusTypes(connection);

			return new CaseDbSchemaVersionNumber(4, 0);

		} finally {
			closeResultSet(queryResultSet);
			closeStatement(queryStatement);
			closeStatement(updateStatement);
			closeResultSet(resultSet);
			closeStatement(statement);
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Updates a schema version 4 database to a schema version 5 database.
	 *
	 * @param schemaVersion The current schema version of the database.
	 * @param connection    A connection to the case database.
	 *
	 * @return The new database schema version.
	 *
	 * @throws SQLException     If there is an error completing a database
	 *                          operation.
	 * @throws TskCoreException If there is an error completing a database
	 *                          operation via another SleuthkitCase method.
	 */
	private CaseDbSchemaVersionNumber updateFromSchema4toSchema5(CaseDbSchemaVersionNumber schemaVersion, CaseDbConnection connection) throws SQLException, TskCoreException {
		if (schemaVersion.getMajor() != 4) {
			return schemaVersion;
		}

		Statement statement = null;
		acquireSingleUserCaseWriteLock();
		try {
			// Add the review_statuses lookup table.
			statement = connection.createStatement();
			statement.execute("CREATE TABLE review_statuses (review_status_id INTEGER PRIMARY KEY, review_status_name TEXT NOT NULL, display_name TEXT NOT NULL)");

			/*
			 * Add review_status_id column to artifacts table.
			 *
			 * NOTE: For DBs created with schema 5 we define a foreign key
			 * constraint on the review_status_column. We don't bother with this
			 * for DBs updated to schema 5 because of limitations of the SQLite
			 * ALTER TABLE command.
			 */
			statement.execute("ALTER TABLE blackboard_artifacts ADD COLUMN review_status_id INTEGER NOT NULL DEFAULT " + BlackboardArtifact.ReviewStatus.UNDECIDED.getID());

			// Add the encoding table
			statement.execute("CREATE TABLE file_encoding_types (encoding_type INTEGER PRIMARY KEY, name TEXT NOT NULL);");
			initEncodingTypes(connection);

			/*
			 * This needs to be done due to a Autopsy/TSK out of synch problem.
			 * Without this, it is possible to upgrade from version 4 to 5 and
			 * then 5 to 6, but not from 4 to 6.
			 */
			initReviewStatuses(connection);

			// Add encoding type column to tsk_files_path
			// This should really have the FOREIGN KEY constraint but there are problems
			// getting that to work, so we don't add it on this upgrade path.
			statement.execute("ALTER TABLE tsk_files_path ADD COLUMN encoding_type INTEGER NOT NULL DEFAULT 0;");

			return new CaseDbSchemaVersionNumber(5, 0);

		} finally {
			closeStatement(statement);
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Updates a schema version 5 database to a schema version 6 database.
	 *
	 * @param schemaVersion The current schema version of the database.
	 * @param connection    A connection to the case database.
	 *
	 * @return The new database schema version.
	 *
	 * @throws SQLException     If there is an error completing a database
	 *                          operation.
	 * @throws TskCoreException If there is an error completing a database
	 *                          operation via another SleuthkitCase method.
	 */
	private CaseDbSchemaVersionNumber updateFromSchema5toSchema6(CaseDbSchemaVersionNumber schemaVersion, CaseDbConnection connection) throws SQLException, TskCoreException {
		if (schemaVersion.getMajor() != 5) {
			return schemaVersion;
		}

		/*
		 * This upgrade fixes a bug where some releases had artifact review
		 * status support in the case database and others did not.
		 */
		Statement statement = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseWriteLock();
		try {
			/*
			 * Add the review_statuses lookup table, if missing.
			 */
			statement = connection.createStatement();
			statement.execute("CREATE TABLE IF NOT EXISTS review_statuses (review_status_id INTEGER PRIMARY KEY, review_status_name TEXT NOT NULL, display_name TEXT NOT NULL)");

			resultSet = connection.executeQuery(statement, "SELECT COUNT(*) AS count FROM review_statuses"); //NON-NLS
			resultSet.next();
			if (resultSet.getLong("count") == 0) {
				/*
				 * Add review_status_id column to artifacts table.
				 *
				 * NOTE: For DBs created with schema 5 or 6 we define a foreign
				 * key constraint on the review_status_column. We don't bother
				 * with this for DBs updated to schema 5 or 6 because of
				 * limitations of the SQLite ALTER TABLE command.
				 */
				statement.execute("ALTER TABLE blackboard_artifacts ADD COLUMN review_status_id INTEGER NOT NULL DEFAULT " + BlackboardArtifact.ReviewStatus.UNDECIDED.getID());
			}

			return new CaseDbSchemaVersionNumber(6, 0);

		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Updates a schema version 6 database to a schema version 7 database.
	 *
	 * @param schemaVersion The current schema version of the database.
	 * @param connection    A connection to the case database.
	 *
	 * @return The new database schema version.
	 *
	 * @throws SQLException     If there is an error completing a database
	 *                          operation.
	 * @throws TskCoreException If there is an error completing a database
	 *                          operation via another SleuthkitCase method.
	 */
	private CaseDbSchemaVersionNumber updateFromSchema6toSchema7(CaseDbSchemaVersionNumber schemaVersion, CaseDbConnection connection) throws SQLException, TskCoreException {
		if (schemaVersion.getMajor() != 6) {
			return schemaVersion;
		}

		/*
		 * This upgrade adds an indexed extension column to the tsk_files table.
		 */
		Statement statement = null;
		Statement updstatement = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseWriteLock();
		try {
			statement = connection.createStatement();
			updstatement = connection.createStatement();
			statement.execute("ALTER TABLE tsk_files ADD COLUMN extension TEXT");

			resultSet = connection.executeQuery(statement, "SELECT obj_id,name FROM tsk_files"); //NON-NLS
			while (resultSet.next()) {
				long objID = resultSet.getLong("obj_id");
				String name = resultSet.getString("name");
				updstatement.executeUpdate("UPDATE tsk_files SET extension = '" + escapeSingleQuotes(extractExtension(name)) + "' "
						+ "WHERE obj_id = " + objID);
			}

			statement.execute("CREATE INDEX file_extension ON tsk_files ( extension )");

			// Add artifact_obj_id column to blackboard_artifacts table, data conversion for old versions isn't necesarry.
			statement.execute("ALTER TABLE blackboard_artifacts ADD COLUMN artifact_obj_id INTEGER NOT NULL DEFAULT -1");

			return new CaseDbSchemaVersionNumber(7, 0);

		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			closeStatement(updstatement);
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Updates a schema version 7 database to a schema version 7.1 database.
	 *
	 * @param schemaVersion The current schema version of the database.
	 * @param connection    A connection to the case database.
	 *
	 * @return The new database schema version.
	 *
	 * @throws SQLException     If there is an error completing a database
	 *                          operation.
	 * @throws TskCoreException If there is an error completing a database
	 *                          operation via another SleuthkitCase method.
	 */
	private CaseDbSchemaVersionNumber updateFromSchema7toSchema7dot1(CaseDbSchemaVersionNumber schemaVersion, CaseDbConnection connection) throws SQLException, TskCoreException {
		if (schemaVersion.getMajor() != 7) {
			return schemaVersion;
		}

		if (schemaVersion.getMinor() != 0) {
			return schemaVersion;
		}

		/*
		 * This upgrade adds a minor version number column.
		 */
		Statement statement = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseWriteLock();
		try {
			statement = connection.createStatement();

			//add the schema minor version number column.
			if (schemaVersion.getMinor() == 0) {
				//add the schema minor version number column.
				statement.execute("ALTER TABLE tsk_db_info ADD COLUMN schema_minor_ver INTEGER DEFAULT 1");
			}
			return new CaseDbSchemaVersionNumber(7, 1);

		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Updates a schema version 7.1 database to a schema version 7.2 database.
	 *
	 * @param schemaVersion The current schema version of the database.
	 * @param connection    A connection to the case database.
	 *
	 * @return The new database schema version.
	 *
	 * @throws SQLException     If there is an error completing a database
	 *                          operation.
	 * @throws TskCoreException If there is an error completing a database
	 *                          operation via another SleuthkitCase method.
	 */
	private CaseDbSchemaVersionNumber updateFromSchema7dot1toSchema7dot2(CaseDbSchemaVersionNumber schemaVersion, CaseDbConnection connection) throws SQLException, TskCoreException {
		if (schemaVersion.getMajor() != 7) {
			return schemaVersion;
		}

		if (schemaVersion.getMinor() != 1) {
			return schemaVersion;
		}

		Statement statement = null;
		Statement updstatement = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseWriteLock();
		try {
			//add the data_source_obj_id column to blackboard_artifacts.
			statement = connection.createStatement();
			statement.execute("ALTER TABLE blackboard_artifacts ADD COLUMN data_source_obj_id INTEGER NOT NULL DEFAULT -1");

			// populate data_source_obj_id for each artifact
			updstatement = connection.createStatement();
			resultSet = connection.executeQuery(statement, "SELECT artifact_id, obj_id FROM blackboard_artifacts"); //NON-NLS
			while (resultSet.next()) {
				long artifact_id = resultSet.getLong("artifact_id");
				long obj_id = resultSet.getLong("obj_id");
				long data_source_obj_id = getDataSourceObjectId(connection, obj_id);
				updstatement.executeUpdate("UPDATE blackboard_artifacts SET data_source_obj_id = " + data_source_obj_id + " "
						+ "WHERE artifact_id = " + artifact_id);
			}
			closeResultSet(resultSet);
			closeStatement(statement);
			closeStatement(updstatement);

			/*
			 * Add a knownStatus column to the tag_names table.
			 */
			statement = connection.createStatement();
			statement.execute("ALTER TABLE tag_names ADD COLUMN knownStatus INTEGER NOT NULL DEFAULT " + TskData.FileKnown.UNKNOWN.getFileKnownValue());

			// Create account_types, accounts, and account_relationships  table
			if (this.dbType.equals(DbType.SQLITE)) {
				statement.execute("CREATE TABLE account_types (account_type_id INTEGER PRIMARY KEY, type_name TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL)");
				statement.execute("CREATE TABLE accounts (account_id INTEGER PRIMARY KEY, account_type_id INTEGER NOT NULL, account_unique_identifier TEXT NOT NULL,  UNIQUE(account_type_id, account_unique_identifier) , FOREIGN KEY(account_type_id) REFERENCES account_types(account_type_id))");
				statement.execute("CREATE TABLE account_relationships (relationship_id INTEGER PRIMARY KEY, account1_id INTEGER NOT NULL, account2_id INTEGER NOT NULL, relationship_source_obj_id INTEGER NOT NULL,  date_time INTEGER, relationship_type INTEGER NOT NULL, data_source_obj_id INTEGER NOT NULL, UNIQUE(account1_id, account2_id, relationship_source_obj_id), FOREIGN KEY(account1_id) REFERENCES accounts(account_id), FOREIGN KEY(account2_id) REFERENCES accounts(account_id), FOREIGN KEY(relationship_source_obj_id) REFERENCES tsk_objects(obj_id), FOREIGN KEY(data_source_obj_id) REFERENCES tsk_objects(obj_id))");
			} else {
				statement.execute("CREATE TABLE account_types (account_type_id BIGSERIAL PRIMARY KEY, type_name TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL)");
				statement.execute("CREATE TABLE accounts (account_id BIGSERIAL PRIMARY KEY, account_type_id INTEGER NOT NULL, account_unique_identifier TEXT NOT NULL,  UNIQUE(account_type_id, account_unique_identifier) , FOREIGN KEY(account_type_id) REFERENCES account_types(account_type_id))");
				statement.execute("CREATE TABLE account_relationships  (relationship_id BIGSERIAL PRIMARY KEY, account1_id INTEGER NOT NULL, account2_id INTEGER NOT NULL, relationship_source_obj_id INTEGER NOT NULL, date_time BIGINT, relationship_type INTEGER NOT NULL, data_source_obj_id INTEGER NOT NULL, UNIQUE(account1_id, account2_id, relationship_source_obj_id), FOREIGN KEY(account1_id) REFERENCES accounts(account_id), FOREIGN KEY(account2_id) REFERENCES accounts(account_id), FOREIGN KEY(relationship_source_obj_id) REFERENCES tsk_objects(obj_id), FOREIGN KEY(data_source_obj_id) REFERENCES tsk_objects(obj_id))");
			}

			// Create indexes
			statement.execute("CREATE INDEX artifact_artifact_objID ON blackboard_artifacts(artifact_obj_id)");
			statement.execute("CREATE INDEX relationships_account1  ON account_relationships(account1_id)");
			statement.execute("CREATE INDEX relationships_account2  ON account_relationships(account2_id)");
			statement.execute("CREATE INDEX relationships_relationship_source_obj_id  ON account_relationships(relationship_source_obj_id)");
			statement.execute("CREATE INDEX relationships_date_time  ON account_relationships(date_time)");
			statement.execute("CREATE INDEX relationships_relationship_type  ON account_relationships(relationship_type)");
			statement.execute("CREATE INDEX relationships_data_source_obj_id  ON account_relationships(data_source_obj_id)");

			return new CaseDbSchemaVersionNumber(7, 2);
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			closeStatement(updstatement);
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Updates a schema version 7.2 database to a schema version 8.0 database.
	 *
	 * @param schemaVersion The current schema version of the database.
	 * @param connection    A connection to the case database.
	 *
	 * @return The new database schema version.
	 *
	 * @throws SQLException     If there is an error completing a database
	 *                          operation.
	 * @throws TskCoreException If there is an error completing a database
	 *                          operation via another SleuthkitCase method.
	 */
	private CaseDbSchemaVersionNumber updateFromSchema7dot2toSchema8dot0(CaseDbSchemaVersionNumber schemaVersion, CaseDbConnection connection) throws SQLException, TskCoreException {
		if (schemaVersion.getMajor() != 7) {
			return schemaVersion;
		}

		if (schemaVersion.getMinor() != 2) {
			return schemaVersion;
		}

		Statement updateSchemaStatement = connection.createStatement();
		Statement getExistingReportsStatement = connection.createStatement();
		ResultSet resultSet = null;
		ResultSet existingReports = null;

		acquireSingleUserCaseWriteLock();
		try {
			// Update the schema to turn report_id into an object id.

			// Unfortunately, SQLite doesn't support adding a constraint
			// to an existing table so we have to rename the old...
			updateSchemaStatement.execute("ALTER TABLE reports RENAME TO old_reports");

			// ...create the new...
			updateSchemaStatement.execute("CREATE TABLE reports (obj_id BIGSERIAL PRIMARY KEY, path TEXT NOT NULL, crtime INTEGER NOT NULL, src_module_name TEXT NOT NULL, report_name TEXT NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id))");

			// ...add the existing report records back...
			existingReports = getExistingReportsStatement.executeQuery("SELECT * FROM old_reports");
			while (existingReports.next()) {
				String path = existingReports.getString(2);
				long crtime = existingReports.getInt(3);
				String sourceModule = existingReports.getString(4);
				String reportName = existingReports.getString(5);

				PreparedStatement insertObjectStatement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_OBJECT, Statement.RETURN_GENERATED_KEYS);
				insertObjectStatement.clearParameters();
				insertObjectStatement.setNull(1, java.sql.Types.BIGINT);
				insertObjectStatement.setLong(2, TskData.ObjectType.REPORT.getObjectType());
				connection.executeUpdate(insertObjectStatement);
				resultSet = insertObjectStatement.getGeneratedKeys();
				if (!resultSet.next()) {
					throw new TskCoreException(String.format("Failed to INSERT report %s (%s) in tsk_objects table", reportName, path));
				}
				long objectId = resultSet.getLong(1); //last_insert_rowid()

				// INSERT INTO reports (obj_id, path, crtime, src_module_name, display_name) VALUES (?, ?, ?, ?, ?)
				PreparedStatement insertReportStatement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_REPORT);
				insertReportStatement.clearParameters();
				insertReportStatement.setLong(1, objectId);
				insertReportStatement.setString(2, path);
				insertReportStatement.setLong(3, crtime);
				insertReportStatement.setString(4, sourceModule);
				insertReportStatement.setString(5, reportName);
				connection.executeUpdate(insertReportStatement);
			}

			// ...and drop the old table.
			updateSchemaStatement.execute("DROP TABLE old_reports");

			return new CaseDbSchemaVersionNumber(8, 0);
		} finally {
			closeResultSet(resultSet);
			closeResultSet(existingReports);
			closeStatement(updateSchemaStatement);
			closeStatement(getExistingReportsStatement);
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Updates a schema version 8.0 database to a schema version 8.1 database.
	 *
	 * @param schemaVersion The current schema version of the database.
	 * @param connection    A connection to the case database.
	 *
	 * @return The new database schema version.
	 *
	 * @throws SQLException     If there is an error completing a database
	 *                          operation.
	 * @throws TskCoreException If there is an error completing a database
	 *                          operation via another SleuthkitCase method.
	 */
	private CaseDbSchemaVersionNumber updateFromSchema8dot0toSchema8dot1(CaseDbSchemaVersionNumber schemaVersion, CaseDbConnection connection) throws SQLException, TskCoreException {
		if (schemaVersion.getMajor() != 8) {
			return schemaVersion;
		}

		if (schemaVersion.getMinor() != 0) {
			return schemaVersion;
		}

		acquireSingleUserCaseWriteLock();

		try (Statement statement = connection.createStatement();) {
			// create examiners table
			if (this.dbType.equals(DbType.SQLITE)) {
				statement.execute("CREATE TABLE tsk_examiners (examiner_id INTEGER PRIMARY KEY, login_name TEXT NOT NULL, display_name TEXT, UNIQUE(login_name) )");
				statement.execute("ALTER TABLE content_tags ADD COLUMN examiner_id INTEGER REFERENCES tsk_examiners(examiner_id) DEFAULT NULL");
				statement.execute("ALTER TABLE blackboard_artifact_tags ADD COLUMN examiner_id INTEGER REFERENCES tsk_examiners(examiner_id) DEFAULT NULL");
			} else {
				statement.execute("CREATE TABLE tsk_examiners (examiner_id BIGSERIAL PRIMARY KEY, login_name TEXT NOT NULL, display_name TEXT, UNIQUE(login_name))");
				statement.execute("ALTER TABLE content_tags ADD COLUMN examiner_id BIGINT REFERENCES tsk_examiners(examiner_id) DEFAULT NULL");
				statement.execute("ALTER TABLE blackboard_artifact_tags ADD COLUMN examiner_id BIGINT REFERENCES tsk_examiners(examiner_id) DEFAULT NULL");
			}

			return new CaseDbSchemaVersionNumber(8, 1);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Updates a schema version 8.1 database to a schema version 8.2 database.
	 *
	 * @param schemaVersion The current schema version of the database.
	 * @param connection    A connection to the case database.
	 *
	 * @return The new database schema version.
	 *
	 * @throws SQLException     If there is an error completing a database
	 *                          operation.
	 * @throws TskCoreException If there is an error completing a database
	 *                          operation via another SleuthkitCase method.
	 */
	private CaseDbSchemaVersionNumber updateFromSchema8dot1toSchema8dot2(CaseDbSchemaVersionNumber schemaVersion, CaseDbConnection connection) throws SQLException, TskCoreException {
		if (schemaVersion.getMajor() != 8) {
			return schemaVersion;
		}

		if (schemaVersion.getMinor() != 1) {
			return schemaVersion;
		}

		acquireSingleUserCaseWriteLock();

		try (Statement statement = connection.createStatement();) {
			statement.execute("ALTER TABLE tsk_image_info ADD COLUMN sha1 TEXT DEFAULT NULL");
			statement.execute("ALTER TABLE tsk_image_info ADD COLUMN sha256 TEXT DEFAULT NULL");

			statement.execute("ALTER TABLE data_source_info ADD COLUMN acquisition_details TEXT");

			/*
			 * Add new tsk_db_extended_info table with TSK version, creation
			 * time schema and schema version numbers as the initial data. The
			 * creation time schema version is set to 0, 0 to indicate that it
			 * is not known.
			 */
			statement.execute("CREATE TABLE tsk_db_info_extended (name TEXT PRIMARY KEY, value TEXT NOT NULL)");
			ResultSet result = statement.executeQuery("SELECT tsk_ver FROM tsk_db_info");
			result.next();
			statement.execute("INSERT INTO tsk_db_info_extended (name, value) VALUES ('" + TSK_VERSION_KEY + "', '" + result.getLong("tsk_ver") + "')");
			statement.execute("INSERT INTO tsk_db_info_extended (name, value) VALUES ('" + SCHEMA_MAJOR_VERSION_KEY + "', '8')");
			statement.execute("INSERT INTO tsk_db_info_extended (name, value) VALUES ('" + SCHEMA_MINOR_VERSION_KEY + "', '2')");
			statement.execute("INSERT INTO tsk_db_info_extended (name, value) VALUES ('" + CREATION_SCHEMA_MAJOR_VERSION_KEY + "', '0')");
			statement.execute("INSERT INTO tsk_db_info_extended (name, value) VALUES ('" + CREATION_SCHEMA_MINOR_VERSION_KEY + "', '0')");

			String primaryKeyType;
			switch (getDatabaseType()) {
				case POSTGRESQL:
					primaryKeyType = "BIGSERIAL";
					break;
				case SQLITE:
					primaryKeyType = "INTEGER";
					break;
				default:
					throw new TskCoreException("Unsupported data base type: " + getDatabaseType().toString());
			}

			//create and initialize tsk_event_types tables
			statement.execute("CREATE TABLE tsk_event_types ("
					+ " event_type_id " + primaryKeyType + " PRIMARY KEY, "
					+ " display_name TEXT UNIQUE NOT NULL, "
					+ " super_type_id INTEGER REFERENCES tsk_event_types(event_type_id) )");
			statement.execute("insert into tsk_event_types(event_type_id, display_name, super_type_id)"
					+ " values( 0, 'Event Types', null)");
			statement.execute("insert into tsk_event_types(event_type_id, display_name, super_type_id)"
					+ " values(1, 'File System', 0)");
			statement.execute("insert into tsk_event_types(event_type_id, display_name, super_type_id)"
					+ " values(2, 'Web Activity', 0)");
			statement.execute("insert into tsk_event_types(event_type_id, display_name, super_type_id)"
					+ " values(3, 'Misc Types', 0)");
			statement.execute("insert into tsk_event_types(event_type_id, display_name, super_type_id)"
					+ " values(4, 'Modified', 1)");
			statement.execute("insert into tsk_event_types(event_type_id, display_name, super_type_id)"
					+ " values(5, 'Accessed', 1)");
			statement.execute("insert into tsk_event_types(event_type_id, display_name, super_type_id)"
					+ " values(6, 'Created', 1)");
			statement.execute("insert into tsk_event_types(event_type_id, display_name, super_type_id)"
					+ " values(7, 'Changed', 1)");

			//create tsk_events tables
			statement.execute("CREATE TABLE tsk_event_descriptions ("
					+ " event_description_id " + primaryKeyType + " PRIMARY KEY, "
					+ " full_description TEXT NOT NULL, "
					+ " med_description TEXT, "
					+ " short_description TEXT,"
					+ " data_source_obj_id BIGINT NOT NULL, "
					+ " file_obj_id BIGINT NOT NULL, "
					+ " artifact_id BIGINT, "
					+ " hash_hit INTEGER NOT NULL, " //boolean 
					+ " tagged INTEGER NOT NULL, " //boolean 
					+ " FOREIGN KEY(data_source_obj_id) REFERENCES data_source_info(obj_id), "
					+ " FOREIGN KEY(file_obj_id) REFERENCES tsk_files(obj_id), "
					+ " FOREIGN KEY(artifact_id) REFERENCES blackboard_artifacts(artifact_id))"
			);

			statement.execute("CREATE TABLE tsk_events ( "
					+ " event_id " + primaryKeyType + " PRIMARY KEY, "
					+ " event_type_id BIGINT NOT NULL REFERENCES tsk_event_types(event_type_id) ,"
					+ " event_description_id BIGINT NOT NULL REFERENCES tsk_event_descriptions(event_description_id) ,"
					+ " time INTEGER NOT NULL) "
			);

			//create tsk_events indices
			statement.execute("CREATE INDEX events_time ON tsk_events(time)");
			statement.execute("CREATE INDEX events_type ON tsk_events(event_type_id)");
			statement.execute("CREATE INDEX events_data_source_obj_id  ON tsk_event_descriptions(data_source_obj_id) ");
			statement.execute("CREATE INDEX events_file_obj_id  ON tsk_event_descriptions(file_obj_id) ");
			statement.execute("CREATE INDEX events_artifact_id  ON tsk_event_descriptions(artifact_id) ");
			statement.execute("CREATE INDEX events_sub_type_time ON tsk_events(event_type_id,  time) ");
			return new CaseDbSchemaVersionNumber(8, 2);

		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Updates a schema version 8.2 database to a schema version 8.3 database.
	 *
	 * @param schemaVersion The current schema version of the database.
	 * @param connection    A connection to the case database.
	 *
	 * @return The new database schema version.
	 *
	 * @throws SQLException     If there is an error completing a database
	 *                          operation.
	 * @throws TskCoreException If there is an error completing a database
	 *                          operation via another SleuthkitCase method.
	 */
	private CaseDbSchemaVersionNumber updateFromSchema8dot2toSchema8dot3(CaseDbSchemaVersionNumber schemaVersion, CaseDbConnection connection) throws SQLException, TskCoreException {
		if (schemaVersion.getMajor() != 8) {
			return schemaVersion;
		}

		if (schemaVersion.getMinor() != 2) {
			return schemaVersion;
		}

		acquireSingleUserCaseWriteLock();

		ResultSet resultSet = null;

		try (Statement statement = connection.createStatement();) {

			// Add the uniqueness constraint to the tsk_event and tsk_event_description tables.
			// Unfortunately, SQLite doesn't support adding a constraint
			// to an existing table so we have to rename the old...
			String primaryKeyType;
			switch (getDatabaseType()) {
				case POSTGRESQL:
					primaryKeyType = "BIGSERIAL";
					break;
				case SQLITE:
					primaryKeyType = "INTEGER";
					break;
				default:
					throw new TskCoreException("Unsupported data base type: " + getDatabaseType().toString());
			}

			//create and initialize tsk_event_types tables which may or may not exist
			statement.execute("CREATE TABLE IF NOT EXISTS tsk_event_types ("
					+ " event_type_id " + primaryKeyType + " PRIMARY KEY, "
					+ " display_name TEXT UNIQUE NOT NULL, "
					+ " super_type_id INTEGER REFERENCES tsk_event_types(event_type_id) )");

			resultSet = statement.executeQuery("SELECT * from tsk_event_types");

			// If there is something in resultSet then the table must have previously 
			// existing therefore there is not need to populate
			if (!resultSet.next()) {

				statement.execute("insert into tsk_event_types(event_type_id, display_name, super_type_id)"
						+ " values( 0, 'Event Types', null)");
				statement.execute("insert into tsk_event_types(event_type_id, display_name, super_type_id)"
						+ " values(1, 'File System', 0)");
				statement.execute("insert into tsk_event_types(event_type_id, display_name, super_type_id)"
						+ " values(2, 'Web Activity', 0)");
				statement.execute("insert into tsk_event_types(event_type_id, display_name, super_type_id)"
						+ " values(3, 'Misc Types', 0)");
				statement.execute("insert into tsk_event_types(event_type_id, display_name, super_type_id)"
						+ " values(4, 'Modified', 1)");
				statement.execute("insert into tsk_event_types(event_type_id, display_name, super_type_id)"
						+ " values(5, 'Accessed', 1)");
				statement.execute("insert into tsk_event_types(event_type_id, display_name, super_type_id)"
						+ " values(6, 'Created', 1)");
				statement.execute("insert into tsk_event_types(event_type_id, display_name, super_type_id)"
						+ " values(7, 'Changed', 1)");
			}

			// Delete the old table that may have been created with the upgrade
			// from 8.1 to 8.2.
			statement.execute("DROP TABLE IF EXISTS tsk_events");

			// Delete the old table that may have been created with the upgrade
			// from 8.1 to 8.2
			statement.execute("DROP TABLE IF EXISTS tsk_event_descriptions");

			//create new tsk_event_description table
			statement.execute("CREATE TABLE tsk_event_descriptions ("
					+ " event_description_id " + primaryKeyType + " PRIMARY KEY, "
					+ " full_description TEXT NOT NULL, "
					+ " med_description TEXT, "
					+ " short_description TEXT,"
					+ " data_source_obj_id BIGINT NOT NULL, "
					+ " file_obj_id BIGINT NOT NULL, "
					+ " artifact_id BIGINT, "
					+ " hash_hit INTEGER NOT NULL, " //boolean 
					+ " tagged INTEGER NOT NULL, " //boolean 
					+ " UNIQUE(full_description, file_obj_id, artifact_id), "
					+ " FOREIGN KEY(data_source_obj_id) REFERENCES data_source_info(obj_id), "
					+ " FOREIGN KEY(file_obj_id) REFERENCES tsk_files(obj_id), "
					+ " FOREIGN KEY(artifact_id) REFERENCES blackboard_artifacts(artifact_id))"
			);

			// create a new table
			statement.execute("CREATE TABLE tsk_events ( "
					+ " event_id " + primaryKeyType + " PRIMARY KEY, "
					+ " event_type_id BIGINT NOT NULL REFERENCES tsk_event_types(event_type_id) ,"
					+ " event_description_id BIGINT NOT NULL REFERENCES tsk_event_descriptions(event_description_id) ,"
					+ " time INTEGER NOT NULL, "
					+ " UNIQUE (event_type_id, event_description_id, time))"
			);

			// Fix mistakenly set names in tsk_db_info_extended 
			statement.execute("UPDATE tsk_db_info_extended SET name = 'CREATION_SCHEMA_MAJOR_VERSION' WHERE name = 'CREATED_SCHEMA_MAJOR_VERSION'");
			statement.execute("UPDATE tsk_db_info_extended SET name = 'CREATION_SCHEMA_MINOR_VERSION' WHERE name = 'CREATED_SCHEMA_MINOR_VERSION'");

			return new CaseDbSchemaVersionNumber(8, 3);
		} finally {
			closeResultSet(resultSet);
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Updates a schema version 8.3 database to a schema version 8.4 database.
	 *
	 * This includes a bug fix update for a misnamed column in
	 * tsk_event_descriptions in the previous update code.
	 *
	 * Note that 8.4 also introduced cascading deletes on many of the database
	 * tables. We do not need to add these in the upgrade code because data
	 * sources in cases that were originally created with 8.3 or earlier can not
	 * be deleted.
	 *
	 * @param schemaVersion The current schema version of the database.
	 * @param connection    A connection to the case database.
	 *
	 * @return The new database schema version.
	 *
	 * @throws SQLException     If there is an error completing a database
	 *                          operation.
	 * @throws TskCoreException If there is an error completing a database
	 *                          operation via another SleuthkitCase method.
	 */
	private CaseDbSchemaVersionNumber updateFromSchema8dot3toSchema8dot4(CaseDbSchemaVersionNumber schemaVersion, CaseDbConnection connection) throws SQLException, TskCoreException {
		if (schemaVersion.getMajor() != 8) {
			return schemaVersion;
		}

		if (schemaVersion.getMinor() != 3) {
			return schemaVersion;
		}

		Statement statement = connection.createStatement();
		ResultSet results = null;

		acquireSingleUserCaseWriteLock();
		try {
			// This is a bug fix update for a misnamed column in tsk_event_descriptions in
			// the previous update code.
			if (null == getDatabaseType()) {
				throw new TskCoreException("Unsupported data base type: " + getDatabaseType().toString());
			}

			switch (getDatabaseType()) {
				case POSTGRESQL:
					// Check if the misnamed column is present
					results = statement.executeQuery("SELECT column_name FROM information_schema.columns "
							+ "WHERE table_name='tsk_event_descriptions' and column_name='file_obj_id'");
					if (results.next()) {
						// In PostgreSQL we can rename the column if it exists
						statement.execute("ALTER TABLE tsk_event_descriptions "
								+ "RENAME COLUMN file_obj_id TO content_obj_id");

						// In 8.2 to 8.3 upgrade, the event_id & time column in tsk_events table was erroneously created as type INTEGER, instead of BIGINT
						// Fix the schema, preserving any data if exists.
						statement.execute("CREATE TABLE temp_tsk_events ( "
								+ " event_id BIGSERIAL PRIMARY KEY, "
								+ " event_type_id BIGINT NOT NULL REFERENCES tsk_event_types(event_type_id) ,"
								+ " event_description_id BIGINT NOT NULL REFERENCES tsk_event_descriptions(event_description_id),"
								+ " time BIGINT NOT NULL, "
								+ " UNIQUE (event_type_id, event_description_id, time))"
						);

						// Copy the data
						statement.execute("INSERT INTO temp_tsk_events(event_id, event_type_id, "
								+ "event_description_id, time) SELECT * FROM tsk_events");

						// Drop the old table
						statement.execute("DROP TABLE tsk_events");

						// Rename the new table
						statement.execute("ALTER TABLE temp_tsk_events RENAME TO tsk_events");

						//create tsk_events indices that were skipped in the 8.2 to 8.3 update code
						statement.execute("CREATE INDEX events_data_source_obj_id  ON tsk_event_descriptions(data_source_obj_id) ");
						statement.execute("CREATE INDEX events_content_obj_id  ON tsk_event_descriptions(content_obj_id) ");
						statement.execute("CREATE INDEX events_artifact_id  ON tsk_event_descriptions(artifact_id) ");
						statement.execute("CREATE INDEX events_sub_type_time ON tsk_events(event_type_id,  time) ");
						statement.execute("CREATE INDEX events_time  ON tsk_events(time) ");
					}
					break;
				case SQLITE:
					boolean hasMisnamedColumn = false;
					results = statement.executeQuery("pragma table_info('tsk_event_descriptions')");
					while (results.next()) {
						if (results.getString("name") != null && results.getString("name").equals("file_obj_id")) {
							hasMisnamedColumn = true;
							break;
						}
					}

					if (hasMisnamedColumn) {
						// Since we can't rename the column we'll need to make new tables and copy the data
						statement.execute("CREATE TABLE temp_tsk_event_descriptions ("
								+ " event_description_id INTEGER PRIMARY KEY, "
								+ " full_description TEXT NOT NULL, "
								+ " med_description TEXT, "
								+ " short_description TEXT,"
								+ " data_source_obj_id BIGINT NOT NULL, "
								+ " content_obj_id BIGINT NOT NULL, "
								+ " artifact_id BIGINT, "
								+ " hash_hit INTEGER NOT NULL, " //boolean
								+ " tagged INTEGER NOT NULL, " //boolean
								+ " UNIQUE(full_description, content_obj_id, artifact_id), "
								+ " FOREIGN KEY(data_source_obj_id) REFERENCES data_source_info(obj_id), "
								+ " FOREIGN KEY(content_obj_id) REFERENCES tsk_files(obj_id), "
								+ " FOREIGN KEY(artifact_id) REFERENCES blackboard_artifacts(artifact_id))"
						);

						statement.execute("CREATE TABLE temp_tsk_events ( "
								+ " event_id INTEGER PRIMARY KEY, "
								+ " event_type_id BIGINT NOT NULL REFERENCES tsk_event_types(event_type_id) ,"
								+ " event_description_id BIGINT NOT NULL REFERENCES temp_tsk_event_descriptions(event_description_id),"
								+ " time INTEGER NOT NULL, "
								+ " UNIQUE (event_type_id, event_description_id, time))"
						);

						// Copy the data
						statement.execute("INSERT INTO temp_tsk_event_descriptions(event_description_id, full_description, "
								+ "med_description, short_description, data_source_obj_id, content_obj_id, artifact_id, "
								+ "hash_hit, tagged) SELECT * FROM tsk_event_descriptions");

						statement.execute("INSERT INTO temp_tsk_events(event_id, event_type_id, "
								+ "event_description_id, time) SELECT * FROM tsk_events");

						// Drop the old tables
						statement.execute("DROP TABLE tsk_events");
						statement.execute("DROP TABLE tsk_event_descriptions");

						// Rename the new tables
						statement.execute("ALTER TABLE temp_tsk_event_descriptions RENAME TO tsk_event_descriptions");
						statement.execute("ALTER TABLE temp_tsk_events RENAME TO tsk_events");

						//create tsk_events indices
						statement.execute("CREATE INDEX events_data_source_obj_id  ON tsk_event_descriptions(data_source_obj_id) ");
						statement.execute("CREATE INDEX events_content_obj_id  ON tsk_event_descriptions(content_obj_id) ");
						statement.execute("CREATE INDEX events_artifact_id  ON tsk_event_descriptions(artifact_id) ");
						statement.execute("CREATE INDEX events_sub_type_time ON tsk_events(event_type_id,  time) ");
						statement.execute("CREATE INDEX events_time  ON tsk_events(time) ");
					}
					break;
				default:
					throw new TskCoreException("Unsupported data base type: " + getDatabaseType().toString());
			}

			// create pool info table
			if (this.dbType.equals(DbType.SQLITE)) {
				statement.execute("CREATE TABLE tsk_pool_info (obj_id INTEGER PRIMARY KEY, pool_type INTEGER NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE)");
			} else {
				statement.execute("CREATE TABLE tsk_pool_info (obj_id BIGSERIAL PRIMARY KEY, pool_type INTEGER NOT NULL, FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE)");
			}

			// Add new account types for newly supported messaging applications, if they dont exists already.
			insertAccountTypeIfNotExists(statement, "IMO", "IMO");
			insertAccountTypeIfNotExists(statement, "LINE", "LINE");
			insertAccountTypeIfNotExists(statement, "SKYPE", "Skype");
			insertAccountTypeIfNotExists(statement, "TANGO", "Tango");
			insertAccountTypeIfNotExists(statement, "TEXTNOW", "TextNow");
			insertAccountTypeIfNotExists(statement, "THREEMA", "ThreeMa");
			insertAccountTypeIfNotExists(statement, "VIBER", "Viber");
			insertAccountTypeIfNotExists(statement, "XENDER", "Xender");
			insertAccountTypeIfNotExists(statement, "ZAPYA", "Zapya");
			insertAccountTypeIfNotExists(statement, "SHAREIT", "ShareIt");

			return new CaseDbSchemaVersionNumber(8, 4);
		} finally {
			closeResultSet(results);
			closeStatement(statement);
			releaseSingleUserCaseWriteLock();
		}
	}

	private CaseDbSchemaVersionNumber updateFromSchema8dot4toSchema8dot5(CaseDbSchemaVersionNumber schemaVersion, CaseDbConnection connection) throws SQLException, TskCoreException {
		if (schemaVersion.getMajor() != 8) {
			return schemaVersion;
		}

		if (schemaVersion.getMinor() != 4) {
			return schemaVersion;
		}

		Statement statement = connection.createStatement();
		acquireSingleUserCaseWriteLock();
		try {
			switch (getDatabaseType()) {
				case POSTGRESQL:
					statement.execute("CREATE TABLE tsk_tag_sets (tag_set_id BIGSERIAL PRIMARY KEY, name TEXT UNIQUE)");
					statement.execute("ALTER TABLE tag_names ADD COLUMN tag_set_id BIGINT REFERENCES tsk_tag_sets(tag_set_id)");
					break;
				case SQLITE:
					statement.execute("CREATE TABLE tsk_tag_sets (tag_set_id INTEGER PRIMARY KEY, name TEXT UNIQUE)");
					statement.execute("ALTER TABLE tag_names ADD COLUMN tag_set_id INTEGER REFERENCES tsk_tag_sets(tag_set_id)");
					break;
			}

			statement.execute("ALTER TABLE tag_names ADD COLUMN rank INTEGER");

			/*
			 * Update existing Project Vic tag names (from Image Gallery in
			 * Autopsy) to be part of a Tag Set. NOTE: These names are out of
			 * date and will not work with the Project VIC Report module. New
			 * cases will get the new names from Image Gallery.
			 */
			String insertStmt = "INSERT INTO tsk_tag_sets (name) VALUES ('Project VIC')";
			if (getDatabaseType() == DbType.POSTGRESQL) {
				statement.execute(insertStmt, Statement.RETURN_GENERATED_KEYS);
			} else {
				statement.execute(insertStmt);
			}
			try (ResultSet resultSet = statement.getGeneratedKeys()) {
				if (resultSet != null && resultSet.next()) {
					int tagSetId = resultSet.getInt(1);

					String updateQuery = "UPDATE tag_names SET tag_set_id = %d, color = '%s', rank = %d, display_name = '%s' WHERE display_name = '%s'";
					statement.executeUpdate(String.format(updateQuery, tagSetId, "Red", 1, "Child Exploitation (Illegal)", "CAT-1: Child Exploitation (Illegal)"));
					statement.executeUpdate(String.format(updateQuery, tagSetId, "Lime", 2, "Child Exploitation (Non-Illegal/Age Difficult)", "CAT-2: Child Exploitation (Non-Illegal/Age Difficult)"));
					statement.executeUpdate(String.format(updateQuery, tagSetId, "Yellow", 3, "CGI/Animation (Child Exploitive)", "CAT-3: CGI/Animation (Child Exploitive)"));
					statement.executeUpdate(String.format(updateQuery, tagSetId, "Purple", 4, "Exemplar/Comparison (Internal Use Only)", "CAT-4: Exemplar/Comparison (Internal Use Only)"));
					statement.executeUpdate(String.format(updateQuery, tagSetId, "Fuchsia", 5, "Non-pertinent", "CAT-5: Non-pertinent"));

					String deleteContentTag = "DELETE FROM content_tags WHERE tag_name_id IN (SELECT tag_name_id from tag_names WHERE display_name LIKE 'CAT-0: Uncategorized')";
					String deleteArtifactTag = "DELETE FROM blackboard_artifact_tags WHERE tag_name_id IN (SELECT tag_name_id from tag_names WHERE display_name LIKE 'CAT-0: Uncategorized')";
					String deleteCat0 = "DELETE FROM tag_names WHERE display_name = 'CAT-0: Uncategorized'";
					statement.executeUpdate(deleteContentTag);
					statement.executeUpdate(deleteArtifactTag);
					statement.executeUpdate(deleteCat0);

				} else {
					throw new TskCoreException("Failed to retrieve the default tag_set_id from DB");
				}
			}

			// Add data_source_obj_id column to the tsk_files table. For newly created cases
			// this column will have a foreign key constraint on the data_source_info table.
			// There does not seem to be a reasonable way to do this in an upgrade,
			// so upgraded cases will be missing the foreign key.
			switch (getDatabaseType()) {
				case POSTGRESQL:
					statement.execute("ALTER TABLE tsk_fs_info ADD COLUMN data_source_obj_id BIGINT NOT NULL DEFAULT -1;");
					break;
				case SQLITE:
					statement.execute("ALTER TABLE tsk_fs_info ADD COLUMN data_source_obj_id INTEGER NOT NULL DEFAULT -1;");
					break;
			}
			Statement updateStatement = connection.createStatement();
			try (ResultSet resultSet = statement.executeQuery("SELECT obj_id FROM tsk_fs_info")) {
				while (resultSet.next()) {
					long fsId = resultSet.getLong("obj_id");
					long dataSourceId = getDataSourceObjectId(connection, fsId);
					updateStatement.executeUpdate("UPDATE tsk_fs_info SET data_source_obj_id = " + dataSourceId + " WHERE obj_id = " + fsId + ";");
				}
			} finally {
				closeStatement(updateStatement);
			}

			return new CaseDbSchemaVersionNumber(8, 5);

		} finally {
			closeStatement(statement);
			releaseSingleUserCaseWriteLock();
		}
	}

	private CaseDbSchemaVersionNumber updateFromSchema8dot5toSchema8dot6(CaseDbSchemaVersionNumber schemaVersion, CaseDbConnection connection) throws SQLException, TskCoreException {
		if (schemaVersion.getMajor() != 8) {
			return schemaVersion;
		}

		if (schemaVersion.getMinor() != 5) {
			return schemaVersion;
		}

		Statement statement = connection.createStatement();
		acquireSingleUserCaseWriteLock();
		try {
			statement.execute("ALTER TABLE tsk_files ADD COLUMN sha256 TEXT");

			return new CaseDbSchemaVersionNumber(8, 6);

		} finally {
			closeStatement(statement);
			releaseSingleUserCaseWriteLock();
		}
	}

	@SuppressWarnings("deprecation")
	private CaseDbSchemaVersionNumber updateFromSchema8dot6toSchema9dot0(CaseDbSchemaVersionNumber schemaVersion, CaseDbConnection connection) throws SQLException, TskCoreException {
		if (schemaVersion.getMajor() != 8) {
			return schemaVersion;
		}

		if (schemaVersion.getMinor() != 6) {
			return schemaVersion;
		}

		Statement statement = connection.createStatement();
		acquireSingleUserCaseWriteLock();
		try {
			String dateDataType = "BIGINT";
			String bigIntDataType = "BIGINT";
			String blobDataType = "BYTEA";
			String primaryKeyType = "BIGSERIAL";

			if (this.dbType.equals(DbType.SQLITE)) {
				dateDataType = "INTEGER";
				bigIntDataType = "INTEGER";
				blobDataType = "BLOB";
				primaryKeyType = "INTEGER";
			}
			statement.execute("ALTER TABLE data_source_info ADD COLUMN added_date_time " + dateDataType);
			statement.execute("ALTER TABLE data_source_info ADD COLUMN acquisition_tool_settings TEXT");
			statement.execute("ALTER TABLE data_source_info ADD COLUMN acquisition_tool_name TEXT");
			statement.execute("ALTER TABLE data_source_info ADD COLUMN acquisition_tool_version TEXT");

			// Add category type and initialize the types. We use the list of artifact types that
			// were categorized as analysis results as of the 8.7 update to ensure consistency in
			// case the built-in types change in a later release.
			statement.execute("ALTER TABLE blackboard_artifact_types ADD COLUMN category_type INTEGER DEFAULT 0");
			String analysisTypeObjIdList
					= BlackboardArtifact.ARTIFACT_TYPE.TSK_KEYWORD_HIT.getTypeID() + ", "
					+ BlackboardArtifact.ARTIFACT_TYPE.TSK_HASHSET_HIT.getTypeID() + ", "
					+ BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT.getTypeID() + ", "
					+ BlackboardArtifact.ARTIFACT_TYPE.TSK_TAG_FILE.getTypeID() + ", "
					+ BlackboardArtifact.ARTIFACT_TYPE.TSK_TAG_ARTIFACT.getTypeID() + ", "
					+ BlackboardArtifact.ARTIFACT_TYPE.TSK_ENCRYPTION_DETECTED.getTypeID() + ", "
					+ BlackboardArtifact.ARTIFACT_TYPE.TSK_EXT_MISMATCH_DETECTED.getTypeID() + ", "
					+ BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_ARTIFACT_HIT.getTypeID() + ", "
					+ BlackboardArtifact.ARTIFACT_TYPE.TSK_FACE_DETECTED.getTypeID() + ", "
					+ BlackboardArtifact.ARTIFACT_TYPE.TSK_ENCRYPTION_SUSPECTED.getTypeID() + ", "
					+ BlackboardArtifact.ARTIFACT_TYPE.TSK_OBJECT_DETECTED.getTypeID() + ", "
					+ BlackboardArtifact.ARTIFACT_TYPE.TSK_VERIFICATION_FAILED.getTypeID() + ", "
					+ BlackboardArtifact.ARTIFACT_TYPE.TSK_DATA_SOURCE_USAGE.getTypeID() + ", "
					+ BlackboardArtifact.ARTIFACT_TYPE.TSK_USER_CONTENT_SUSPECTED.getTypeID() + ", "
					+ BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_ACCOUNT_TYPE.getTypeID() + ", "
					+ BlackboardArtifact.ARTIFACT_TYPE.TSK_YARA_HIT.getTypeID() + ", "
					+ BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_CATEGORIZATION.getTypeID();
			statement.execute("UPDATE blackboard_artifact_types SET category_type = " + BlackboardArtifact.Category.ANALYSIS_RESULT.getID()
					+ " WHERE artifact_type_id IN (" + analysisTypeObjIdList + ")");

			// Create tsk file attributes table
			statement.execute("CREATE TABLE tsk_file_attributes (id " + primaryKeyType + " PRIMARY KEY, "
					+ "obj_id " + bigIntDataType + " NOT NULL, "
					+ "attribute_type_id " + bigIntDataType + " NOT NULL, "
					+ "value_type INTEGER NOT NULL, value_byte " + blobDataType + ", "
					+ "value_text TEXT, value_int32 INTEGER, value_int64 " + bigIntDataType + ", value_double NUMERIC(20, 10), "
					+ "FOREIGN KEY(obj_id) REFERENCES tsk_files(obj_id) ON DELETE CASCADE, "
					+ "FOREIGN KEY(attribute_type_id) REFERENCES blackboard_attribute_types(attribute_type_id))");

			// create analysis results tables
			statement.execute("CREATE TABLE tsk_analysis_results (artifact_obj_id " + bigIntDataType + " PRIMARY KEY, "
					+ "conclusion TEXT, "
					+ "significance INTEGER NOT NULL, "
					/*
					 * method_category was a column in a little distributed
					 * version of 9.0. It was renamed to priority before public
					 * release. The 9.1 upgrade code will add the priority
					 * column. This is commented out since it was never used.
					 */
					// + "method_category INTEGER NOT NULL, "
					+ "configuration TEXT, justification TEXT, "
					+ "ignore_score INTEGER DEFAULT 0 " // boolean	
					+ ")");

			statement.execute("CREATE TABLE tsk_aggregate_score( obj_id " + bigIntDataType + " PRIMARY KEY, "
					+ "data_source_obj_id " + bigIntDataType + ", "
					+ "significance INTEGER NOT NULL, "
					// See comment above on why this is commented out
					// + "method_category INTEGER NOT NULL, "
					+ "UNIQUE (obj_id),"
					+ "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE, "
					+ "FOREIGN KEY(data_source_obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE "
					+ ")");

			// Create person table.
			statement.execute("CREATE TABLE tsk_persons (id " + primaryKeyType + " PRIMARY KEY, "
					+ "name TEXT NOT NULL, " // person name
					+ "UNIQUE(name)) ");

			// Create host table.
			statement.execute("CREATE TABLE tsk_hosts (id " + primaryKeyType + " PRIMARY KEY, "
					+ "name TEXT NOT NULL, " // host name
					+ "db_status INTEGER DEFAULT 0, " // active/merged/deleted
					+ "person_id INTEGER, "
					+ "merged_into " + bigIntDataType + ", "
					+ "FOREIGN KEY(person_id) REFERENCES tsk_persons(id) ON DELETE SET NULL, "
					+ "FOREIGN KEY(merged_into) REFERENCES tsk_hosts(id), "
					+ "UNIQUE(name)) ");

			// Create OS Account and related tables 
			statement.execute("CREATE TABLE tsk_os_account_realms (id " + primaryKeyType + " PRIMARY KEY, "
					+ "realm_name TEXT DEFAULT NULL, " // realm name - for a domain realm, may be null
					+ "realm_addr TEXT DEFAULT NULL, " // a sid/uid or some some other identifier, may be null
					+ "realm_signature TEXT NOT NULL, " // Signature exists only to prevent duplicates. It is  made up of realm address/name and scope host
					+ "scope_host_id " + bigIntDataType + " DEFAULT NULL, " // if the realm scope is a single host
					+ "scope_confidence INTEGER, " // indicates whether we know for sure the realm scope or if we are inferring it
					+ "db_status INTEGER DEFAULT 0, " // active/merged/deleted
					+ "merged_into " + bigIntDataType + " DEFAULT NULL, "
					+ "UNIQUE(realm_signature), "
					+ "FOREIGN KEY(scope_host_id) REFERENCES tsk_hosts(id),"
					+ "FOREIGN KEY(merged_into) REFERENCES tsk_os_account_realms(id) )");

			// Add host column and create a host for each existing data source.
			// We will create a host for each device id so that related data sources will 
			// be associated with the same host.
			statement.execute("ALTER TABLE data_source_info ADD COLUMN host_id INTEGER REFERENCES tsk_hosts(id)");
			Statement updateStatement = connection.createStatement();
			try (ResultSet resultSet = statement.executeQuery("SELECT obj_id, device_id FROM data_source_info")) {
				Map<String, Long> hostMap = new HashMap<>();
				long hostIndex = 1;
				while (resultSet.next()) {
					long objId = resultSet.getLong("obj_id");
					String deviceId = resultSet.getString("device_id");

					if (!hostMap.containsKey(deviceId)) {
						String hostName = "Host " + hostIndex;
						updateStatement.execute("INSERT INTO tsk_hosts (name, db_status) VALUES ('" + hostName + "', 0)");
						hostMap.put(deviceId, hostIndex);
						hostIndex++;
					}
					updateStatement.execute("UPDATE data_source_info SET host_id = " + hostMap.get(deviceId) + " WHERE obj_id = " + objId);
				}
			} finally {
				closeStatement(updateStatement);
			}

			statement.execute("CREATE TABLE tsk_os_accounts (os_account_obj_id " + bigIntDataType + " PRIMARY KEY, "
					+ "login_name TEXT DEFAULT NULL, " // login name, if available, may be null
					+ "full_name TEXT DEFAULT NULL, " // full name, if available, may be null
					+ "realm_id " + bigIntDataType + " NOT NULL, " // realm for the account
					+ "addr TEXT DEFAULT NULL, " // SID/UID, if available
					+ "signature TEXT NOT NULL, " // This exists only to prevent duplicates.  It is either the addr or the login_name whichever is not null.
					+ "status INTEGER, " // enabled/disabled/deleted
					+ "type INTEGER, " // service/interactive
					+ "created_date " + bigIntDataType + " DEFAULT NULL, "
					+ "db_status INTEGER DEFAULT 0, " // active/merged/deleted
					+ "merged_into " + bigIntDataType + " DEFAULT NULL, "
					+ "UNIQUE(signature, realm_id), "
					+ "FOREIGN KEY(os_account_obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE, "
					+ "FOREIGN KEY(realm_id) REFERENCES tsk_os_account_realms(id),"
					+ "FOREIGN KEY(merged_into) REFERENCES tsk_os_accounts(os_account_obj_id) )");

			statement.execute("CREATE TABLE tsk_os_account_attributes (id " + primaryKeyType + " PRIMARY KEY, "
					+ "os_account_obj_id " + bigIntDataType + " NOT NULL, "
					+ "host_id " + bigIntDataType + ", "
					+ "source_obj_id " + bigIntDataType + ", "
					+ "attribute_type_id " + bigIntDataType + " NOT NULL, "
					+ "value_type INTEGER NOT NULL, "
					+ "value_byte " + bigIntDataType + ", "
					+ "value_text TEXT, "
					+ "value_int32 INTEGER, value_int64 " + bigIntDataType + ", "
					+ "value_double NUMERIC(20, 10), "
					+ "FOREIGN KEY(os_account_obj_id) REFERENCES tsk_os_accounts(os_account_obj_id), "
					+ "FOREIGN KEY(host_id) REFERENCES tsk_hosts(id), "
					+ "FOREIGN KEY(source_obj_id) REFERENCES tsk_objects(obj_id) ON DELETE SET NULL, "
					+ "FOREIGN KEY(attribute_type_id) REFERENCES blackboard_attribute_types(attribute_type_id))");

			statement.execute("CREATE TABLE tsk_os_account_instances (id " + primaryKeyType + " PRIMARY KEY, "
					+ "os_account_obj_id " + bigIntDataType + " NOT NULL, "
					+ "data_source_obj_id " + bigIntDataType + " NOT NULL, "
					+ "instance_type INTEGER NOT NULL, " // PerformedActionOn/ReferencedOn
					+ "UNIQUE(os_account_obj_id, data_source_obj_id), "
					+ "FOREIGN KEY(os_account_obj_id) REFERENCES tsk_os_accounts(os_account_obj_id), "
					+ "FOREIGN KEY(data_source_obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE )");

			statement.execute("CREATE TABLE tsk_data_artifacts ( "
					+ "artifact_obj_id " + bigIntDataType + " PRIMARY KEY, "
					+ "os_account_obj_id " + bigIntDataType + ", "
					+ "FOREIGN KEY(os_account_obj_id) REFERENCES tsk_os_accounts(os_account_obj_id)) ");

			// add owner_uid & os_account_obj_id columns to tsk_files
			statement.execute("ALTER TABLE tsk_files ADD COLUMN owner_uid TEXT DEFAULT NULL");
			statement.execute("ALTER TABLE tsk_files ADD COLUMN os_account_obj_id " + bigIntDataType + " DEFAULT NULL REFERENCES tsk_os_accounts(os_account_obj_id) ");

			// create host address tables
			statement.execute("CREATE TABLE tsk_host_addresses (id " + primaryKeyType + " PRIMARY KEY, "
					+ "address_type INTEGER NOT NULL, "
					+ "address TEXT NOT NULL, "
					+ "UNIQUE(address_type, address)) ");

			statement.execute("CREATE TABLE tsk_host_address_map (id " + primaryKeyType + " PRIMARY KEY, "
					+ "host_id " + bigIntDataType + " NOT NULL, "
					+ "addr_obj_id " + bigIntDataType + " NOT NULL, "
					+ "source_obj_id " + bigIntDataType + ", " // object id of the source where this mapping was found.
					+ "time " + bigIntDataType + ", " // time at which the mapping existed
					+ "UNIQUE(host_id, addr_obj_id, time), "
					+ "FOREIGN KEY(host_id) REFERENCES tsk_hosts(id) ON DELETE CASCADE, "
					+ "FOREIGN KEY(addr_obj_id) REFERENCES tsk_host_addresses(id), "
					+ "FOREIGN KEY(source_obj_id) REFERENCES tsk_objects(obj_id) ON DELETE SET NULL )");

			// stores associations between DNS name and IP address
			statement.execute("CREATE TABLE tsk_host_address_dns_ip_map (id " + primaryKeyType + " PRIMARY KEY, "
					+ "dns_address_id " + bigIntDataType + " NOT NULL, "
					+ "ip_address_id " + bigIntDataType + " NOT NULL, "
					+ "source_obj_id " + bigIntDataType + ", "
					+ "time " + bigIntDataType + ", " // time at which the mapping existed
					+ "UNIQUE(dns_address_id, ip_address_id, time), "
					+ "FOREIGN KEY(dns_address_id) REFERENCES tsk_host_addresses(id) ON DELETE CASCADE, "
					+ "FOREIGN KEY(ip_address_id) REFERENCES tsk_host_addresses(id) ON DELETE CASCADE,"
					+ "FOREIGN KEY(source_obj_id) REFERENCES tsk_objects(obj_id) ON DELETE SET NULL )");

			// maps an address to an artifact using it 
			statement.execute("CREATE TABLE tsk_host_address_usage (id " + primaryKeyType + " PRIMARY KEY, "
					+ "addr_obj_id " + bigIntDataType + " NOT NULL, "
					+ "obj_id " + bigIntDataType + " NOT NULL, "
					+ "data_source_obj_id " + bigIntDataType + " NOT NULL, " // data source where the usage was found
					+ "UNIQUE(addr_obj_id, obj_id), "
					+ "FOREIGN KEY(addr_obj_id) REFERENCES tsk_host_addresses(id) ON DELETE CASCADE, "
					+ "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE )");

			return new CaseDbSchemaVersionNumber(9, 0);

		} finally {
			closeStatement(statement);
			releaseSingleUserCaseWriteLock();
		}
	}

	private CaseDbSchemaVersionNumber updateFromSchema9dot0toSchema9dot1(CaseDbSchemaVersionNumber schemaVersion, CaseDbConnection connection) throws SQLException, TskCoreException {
		if (schemaVersion.getMajor() != 9) {
			return schemaVersion;
		}

		if (schemaVersion.getMinor() != 0) {
			return schemaVersion;
		}

		Statement statement = connection.createStatement();
		ResultSet results = null;
		acquireSingleUserCaseWriteLock();
		try {
			// The 9.0 schema contained method_category columns that were renamed to priority.
			switch (getDatabaseType()) {
				case POSTGRESQL:
					// Check if the misnamed column is present. We'll assume here that the column will exist
					// in both tables if present in one.
					results = statement.executeQuery("SELECT column_name FROM information_schema.columns "
							+ "WHERE table_name='tsk_analysis_results' and column_name='method_category'");
					if (results.next()) {
						// In PostgreSQL we can delete the column
						statement.execute("ALTER TABLE tsk_analysis_results "
								+ "DROP COLUMN method_category");
						statement.execute("ALTER TABLE tsk_aggregate_score "
								+ "DROP COLUMN method_category");
					}
					break;
				case SQLITE:
					// Check if the misnamed column is present. We'll assume here that the column will exist
					// in both tables if present in one.
					boolean hasMisnamedColumn = false;
					results = statement.executeQuery("pragma table_info('tsk_analysis_results')");
					while (results.next()) {
						if (results.getString("name") != null && results.getString("name").equals("method_category")) {
							hasMisnamedColumn = true;
							break;
						}
					}

					if (hasMisnamedColumn) {
						// Since we can't rename the column we'll need to make a new table and copy the data.
						// We'll add the priority column later.
						statement.execute("CREATE TABLE temp_tsk_analysis_results (artifact_obj_id INTEGER PRIMARY KEY, "
								+ "conclusion TEXT, "
								+ "significance INTEGER NOT NULL, "
								+ "configuration TEXT, justification TEXT, "
								+ "ignore_score INTEGER DEFAULT 0 " // boolean	
								+ ")");
						statement.execute("CREATE TABLE temp_tsk_aggregate_score( obj_id INTEGER PRIMARY KEY, "
								+ "data_source_obj_id INTEGER, "
								+ "significance INTEGER NOT NULL, "
								+ "UNIQUE (obj_id),"
								+ "FOREIGN KEY(obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE, "
								+ "FOREIGN KEY(data_source_obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE "
								+ ")");

						// Copy the data
						statement.execute("INSERT INTO temp_tsk_analysis_results(artifact_obj_id, "
								+ "conclusion, justification, significance, configuration, ignore_score) "
								+ "SELECT artifact_obj_id, conclusion, justification, significance, configuration, ignore_score FROM tsk_analysis_results");
						statement.execute("INSERT INTO temp_tsk_aggregate_score(obj_id, "
								+ "data_source_obj_id, significance) "
								+ "SELECT obj_id, data_source_obj_id, significance FROM tsk_aggregate_score");

						// Drop the old tables
						statement.execute("DROP TABLE tsk_analysis_results");
						statement.execute("DROP TABLE tsk_aggregate_score");

						// Rename the new tables
						statement.execute("ALTER TABLE temp_tsk_analysis_results RENAME TO tsk_analysis_results");
						statement.execute("ALTER TABLE temp_tsk_aggregate_score RENAME TO tsk_aggregate_score");

					}
					break;
				default:
					throw new TskCoreException("Unsupported database type: " + getDatabaseType().toString());
			}

			// add an index on tsk_file_attributes table.
			statement.execute("CREATE INDEX tsk_file_attributes_obj_id ON tsk_file_attributes(obj_id)");

			statement.execute("ALTER TABLE tsk_analysis_results ADD COLUMN priority INTEGER NOT NULL DEFAULT " + Score.Priority.NORMAL.getId());
			statement.execute("ALTER TABLE tsk_aggregate_score ADD COLUMN priority INTEGER NOT NULL DEFAULT " + Score.Priority.NORMAL.getId());

			statement.execute("UPDATE blackboard_artifact_types SET category_type = 1 WHERE artifact_type_id = 16");

			return new CaseDbSchemaVersionNumber(9, 1);
		} finally {
			closeResultSet(results);
			closeStatement(statement);
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Upgrade the database schema from 9.1 to 9.2 This upgrade includes: -
	 * modify the UNIQUE constraint on tsk_os_account_instances to include the
	 * instance_type column.
	 *
	 * @param schemaVersion Current schema version - must be 9.1
	 * @param connection    Database connection to use.
	 *
	 * @return New schema version
	 *
	 * @throws SQLException
	 * @throws TskCoreException
	 */
	private CaseDbSchemaVersionNumber updateFromSchema9dot1toSchema9dot2(CaseDbSchemaVersionNumber schemaVersion, CaseDbConnection connection) throws SQLException, TskCoreException {
		if (schemaVersion.getMajor() != 9) {
			return schemaVersion;
		}

		if (schemaVersion.getMinor() != 1) {
			return schemaVersion;
		}

		Statement updateSchemaStatement = connection.createStatement();
		ResultSet results = null;
		acquireSingleUserCaseWriteLock();
		try {

			String bigIntDataType = "BIGINT";
			String primaryKeyType = "BIGSERIAL";

			if (this.dbType.equals(DbType.SQLITE)) {
				bigIntDataType = "INTEGER";
				primaryKeyType = "INTEGER";
			}

			// In 9.2 we modified the UNIQUE constraint on tsk_os_account_instances to include instance_type column.
			// Since SQLite does not allow to drop or alter constraints, we will create a new table, copy the data and delete the old table.
			// Rename existing table
			updateSchemaStatement.execute("ALTER TABLE tsk_os_account_instances RENAME TO old_tsk_os_account_instances");

			// New table
			updateSchemaStatement.execute("CREATE TABLE tsk_os_account_instances (id " + primaryKeyType + " PRIMARY KEY, "
					+ "os_account_obj_id " + bigIntDataType + " NOT NULL, "
					+ "data_source_obj_id " + bigIntDataType + " NOT NULL, "
					+ "instance_type INTEGER NOT NULL, " // PerformedActionOn/ReferencedOn
					+ "UNIQUE(os_account_obj_id, data_source_obj_id, instance_type), "
					+ "FOREIGN KEY(os_account_obj_id) REFERENCES tsk_os_accounts(os_account_obj_id) ON DELETE CASCADE, "
					+ "FOREIGN KEY(data_source_obj_id) REFERENCES tsk_objects(obj_id) ON DELETE CASCADE ) ");

			// Copy the data from old table, order by id preserves the primary key. 
			updateSchemaStatement.execute("INSERT INTO tsk_os_account_instances(os_account_obj_id, "
					+ "data_source_obj_id, instance_type) SELECT os_account_obj_id, data_source_obj_id, instance_type FROM old_tsk_os_account_instances ORDER BY id ASC");

			// delete old table
			updateSchemaStatement.execute("DROP TABLE old_tsk_os_account_instances");

			return new CaseDbSchemaVersionNumber(9, 2);
		} finally {
			closeResultSet(results);
			closeStatement(updateSchemaStatement);
			releaseSingleUserCaseWriteLock();
		}
	}

	private CaseDbSchemaVersionNumber updateFromSchema9dot2toSchema9dot3(CaseDbSchemaVersionNumber schemaVersion, CaseDbConnection connection) throws SQLException, TskCoreException {
		if (schemaVersion.getMajor() != 9) {
			return schemaVersion;
		}

		if (schemaVersion.getMinor() != 2) {
			return schemaVersion;
		}

		Statement statement = connection.createStatement();
		acquireSingleUserCaseWriteLock();
		try {
			// add a new column 'sha1' to tsk_files
			statement.execute("ALTER TABLE tsk_files ADD COLUMN sha1 TEXT");

			
			return new CaseDbSchemaVersionNumber(9, 3);

		} finally {
			closeStatement(statement);
			releaseSingleUserCaseWriteLock();
		}
	}
	
	private CaseDbSchemaVersionNumber updateFromSchema9dot3toSchema9dot4(CaseDbSchemaVersionNumber schemaVersion, CaseDbConnection connection) throws SQLException, TskCoreException {
		if (schemaVersion.getMajor() != 9) {
			return schemaVersion;
		}

		if (schemaVersion.getMinor() != 3) {
			return schemaVersion;
		}

		Statement statement = connection.createStatement();
		acquireSingleUserCaseWriteLock();
		try {
			// Add file_collection_status_types table
			statement.execute("CREATE TABLE file_collection_status_types (collection_status_type INTEGER PRIMARY KEY, name TEXT NOT NULL);");
			initCollectedStatusTypes(connection);
			
			// add a new column 'collected' to tsk_files
			statement.execute("ALTER TABLE tsk_files ADD COLUMN collected INTEGER NOT NULL DEFAULT " + 
					TskData.CollectedStatus.UNKNOWN.getType() + ";");

			return new CaseDbSchemaVersionNumber(9, 4);

		} finally {
			closeStatement(statement);
			releaseSingleUserCaseWriteLock();
		}
	}
	
	private CaseDbSchemaVersionNumber updateFromSchema9dot4toSchema9dot5(CaseDbSchemaVersionNumber schemaVersion, CaseDbConnection connection) throws SQLException, TskCoreException {
		if (schemaVersion.getMajor() != 9) {
			return schemaVersion;
		}

		if (schemaVersion.getMinor() != 4) {
			return schemaVersion;
		}

		Statement statement = connection.createStatement();
		acquireSingleUserCaseWriteLock();
		try { 
			// Adding indexes to the os account table
			statement.execute("CREATE INDEX tsk_os_accounts_login_name_idx  ON tsk_os_accounts(login_name, db_status, realm_id)");
			statement.execute("CREATE INDEX tsk_os_accounts_addr_idx  ON tsk_os_accounts(addr, db_status, realm_id)");
			statement.execute("CREATE INDEX tsk_os_account_realms_realm_name_idx  ON tsk_os_account_realms(realm_name)");
			statement.execute("CREATE INDEX tsk_os_account_realms_realm_addr_idx  ON tsk_os_account_realms(realm_addr)");
			
			return new CaseDbSchemaVersionNumber(9, 5);

		} finally {
			closeStatement(statement);
			releaseSingleUserCaseWriteLock();
		}
	}
	
	private CaseDbSchemaVersionNumber updateFromSchema9dot5toSchema9dot6(CaseDbSchemaVersionNumber schemaVersion, CaseDbConnection connection) throws SQLException, TskCoreException {
		if (schemaVersion.getMajor() != 9) {
			return schemaVersion;
		}

		if (schemaVersion.getMinor() != 5) {
			return schemaVersion;
		}
		
		String insertSQL = "";
		switch (getDatabaseType()) {
			case POSTGRESQL:
				insertSQL = "CREATE INDEX tsk_files_datasrc_md5_size_partial_index ON tsk_files(data_source_obj_id, md5, size) WHERE md5 IS NOT NULL AND size > 0"; //NON-NLS
				break;
			case SQLITE:
				insertSQL = "CREATE INDEX tsk_files_datasrc_md5_size_index ON tsk_files(data_source_obj_id, md5, size)";
				break;
			default:
				throw new TskCoreException("Unknown DB Type: " + getDatabaseType().name());
		}

		Statement statement = connection.createStatement();
		acquireSingleUserCaseWriteLock();
		try { 
			// Adding index to the tsk_files table
			statement.execute(insertSQL);
			
			return new CaseDbSchemaVersionNumber(9, 6);

		} finally {
			closeStatement(statement);
			releaseSingleUserCaseWriteLock();
		}
	}	

	/**
	 * Inserts a row for the given account type in account_types table, if one
	 * doesn't exist.
	 *
	 * @param statement    Statement to use to execute SQL.
	 * @param type_name    Account type name.
	 * @param display_name Account type display name.
	 *
	 * @throws TskCoreException
	 * @throws SQLException
	 */
	private void insertAccountTypeIfNotExists(Statement statement, String type_name, String display_name) throws TskCoreException, SQLException {

		String insertSQL = String.format("INTO account_types(type_name, display_name) VALUES ('%s', '%s')", type_name, display_name);
		switch (getDatabaseType()) {
			case POSTGRESQL:
				insertSQL = "INSERT " + insertSQL + " ON CONFLICT DO NOTHING"; //NON-NLS
				break;
			case SQLITE:
				insertSQL = "INSERT OR IGNORE " + insertSQL;
				break;
			default:
				throw new TskCoreException("Unknown DB Type: " + getDatabaseType().name());
		}
		statement.execute(insertSQL); //NON-NLS
	}

	/**
	 * Extract the extension from a file name.
	 *
	 * @param fileName the file name to extract the extension from.
	 *
	 * @return The extension extracted from fileName. Will not be null.
	 */
	static String extractExtension(final String fileName) {
		String ext;
		int i = fileName.lastIndexOf(".");
		// > 0 because we assume it's not an extension if period is the first character
		if ((i > 0) && ((i + 1) < fileName.length())) {
			ext = fileName.substring(i + 1);
		} else {
			return "";
		}
		// we added this at one point to deal with files that had crazy names based on URLs
		// it's too hard though to clean those up and not mess up basic extensions though.
		// We need to add '-' to the below if we use it again
		//		String[] findNonAlphanumeric = ext.split("[^a-zA-Z0-9_]");
		//		if (findNonAlphanumeric.length > 1) {
		//			ext = findNonAlphanumeric[0];
		//		}
		return ext.toLowerCase();
	}

	/**
	 * Returns case database schema version number. As of TSK 4.5.0 db schema
	 * versions are two part Major.minor. This method only returns the major
	 * part. Use getDBSchemaVersion() for the complete version.
	 *
	 * @return The schema version number as an integer.
	 *
	 * @deprecated since 4.5.0 Use getDBSchemaVersion() instead for more
	 * complete version info.
	 */
	@Deprecated
	public int getSchemaVersion() {
		return getDBSchemaVersion().getMajor();
	}

	/**
	 * Gets the database schema version in use.
	 *
	 * @return the database schema version in use.
	 */
	public VersionNumber getDBSchemaVersion() {
		return CURRENT_DB_SCHEMA_VERSION;
	}

	/**
	 * Gets the creation version of the database schema.
	 *
	 * @return the creation version for the database schema, the creation
	 *         version will be 0.0 for databases created prior to 8.2
	 */
	public CaseDbSchemaVersionNumber getDBSchemaCreationVersion() {
		return caseDBSchemaCreationVersion;
	}

	/**
	 * Returns the type of database in use.
	 *
	 * @return database type
	 */
	public DbType getDatabaseType() {
		return this.dbType;
	}

	/**
	 * Returns the path of a backup copy of the database made when a schema
	 * version upgrade has occurred.
	 *
	 * @return The path of the backup file or null if no backup was made.
	 */
	public String getBackupDatabasePath() {
		return dbBackupPath;
	}

	/**
	 * Create a new transaction on the case database. The transaction object
	 * that is returned can be passed to methods that take a CaseDbTransaction.
	 * The caller is responsible for calling either commit() or rollback() on
	 * the transaction object.
	 *
	 * Note that this beginning the transaction also acquires the single user
	 * case write lock, which will be automatically released when the
	 * transaction is closed.
	 *
	 * @return A CaseDbTransaction object.
	 *
	 * @throws TskCoreException
	 */
	public CaseDbTransaction beginTransaction() throws TskCoreException {
		return new CaseDbTransaction(this);
	}

	/**
	 * Gets the case database name.
	 *
	 * @return The case database name.
	 */
	public String getDatabaseName() {
		return databaseName;
	}

	/**
	 * Get the full path to the case directory. For a SQLite case database, this
	 * is the same as the database directory path.
	 *
	 * @return Case directory path.
	 */
	public String getDbDirPath() {
		return caseDirPath;
	}

	/**
	 * Acquires a write lock, but only if this is a single-user case. Always
	 * call this method in a try block with a call to the lock release method in
	 * an associated finally block.
	 */
	public void acquireSingleUserCaseWriteLock() {
		if (dbType == DbType.SQLITE) {
			rwLock.writeLock().lock();
		}
	}

	/**
	 * Releases a write lock, but only if this is a single-user case. This
	 * method should always be called in the finally block of a try block in
	 * which the lock was acquired.
	 */
	public void releaseSingleUserCaseWriteLock() {
		if (dbType == DbType.SQLITE) {
			rwLock.writeLock().unlock();
		}
	}

	/**
	 * Acquires a read lock, but only if this is a single-user case. Call this
	 * method in a try block with a call to the lock release method in an
	 * associated finally block.
	 */
	public void acquireSingleUserCaseReadLock() {
		if (dbType == DbType.SQLITE) {
			rwLock.readLock().lock();
		}
	}

	/**
	 * Releases a read lock, but only if this is a single-user case. This method
	 * should always be called in the finally block of a try block in which the
	 * lock was acquired.
	 */
	public void releaseSingleUserCaseReadLock() {
		if (dbType == DbType.SQLITE) {
			rwLock.readLock().unlock();
		}
	}

	/**
	 * Open an existing case database.
	 *
	 * @param dbPath Path to SQLite case database.
	 *
	 * @return Case database object.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public static SleuthkitCase openCase(String dbPath) throws TskCoreException {
		return openCase(dbPath, null);
	}
	
	/**
	 * Open an existing case database.
	 *
	 * @param dbPath Path to SQLite case database.
	 * @param contentProvider Custom provider for file content bytes (can be null).
	 *
	 * @return Case database object.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	@Beta
	public static SleuthkitCase openCase(String dbPath, ContentStreamProvider provider) throws TskCoreException {
		return openCase(dbPath, provider, null);
	}

	/**
	 * Open an existing case database.
	 *
	 * @param dbPath Path to SQLite case database.
	 * @param contentProvider Custom provider for file content bytes (can be null).
	 * @param lockingApplicationName The name of the application locking the
	 *                               case database (null value prevents
	 *                               locking; 500 character maximum).
	 * @return Case database object.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	@Beta
	public static SleuthkitCase openCase(String dbPath, ContentStreamProvider provider, String lockingApplicationName) throws TskCoreException {
		try {
			final SleuthkitJNI.CaseDbHandle caseHandle = SleuthkitJNI.openCaseDb(dbPath);
			return new SleuthkitCase(dbPath, caseHandle, DbType.SQLITE, provider, lockingApplicationName);
		} catch (TskUnsupportedSchemaVersionException ex) {
			//don't wrap in new TskCoreException
			throw ex;
		} catch (Exception ex) {
			throw new TskCoreException("Failed to open case database at " + dbPath, ex);
		}
	}
	
	


	/**
	 * Open an existing multi-user case database.
	 *
	 * @param databaseName The name of the database.
	 * @param info         Connection information for the the database.
	 * @param caseDir      The folder where the case metadata fils is stored.
	 *
	 * @return A case database object.
	 *
	 * @throws TskCoreException If there is a problem opening the database.
	 */
	public static SleuthkitCase openCase(String databaseName, CaseDbConnectionInfo info, String caseDir) throws TskCoreException {
		return openCase(databaseName, info, caseDir, null);
	}
	
	/**
	 * Open an existing multi-user case database.
	 *
	 * @param databaseName The name of the database.
	 * @param info         Connection information for the the database.
	 * @param caseDir      The folder where the case metadata fils is stored.
	 * @param contentProvider Custom provider for file content bytes (can be null).
	 *
	 * @return A case database object.
	 *
	 * @throws TskCoreException If there is a problem opening the database.
	 */
	@Beta
	public static SleuthkitCase openCase(String databaseName, CaseDbConnectionInfo info, String caseDir, ContentStreamProvider contentProvider) throws TskCoreException {
		try {
			/*
			 * The flow of this method involves trying to open case and if
			 * successful, return that case. If unsuccessful, an exception is
			 * thrown. We catch any exceptions, and use tryConnect() to attempt
			 * to obtain further information about the error. If tryConnect() is
			 * unable to successfully connect, tryConnect() will throw a
			 * TskCoreException with a message containing user-level error
			 * reporting. If tryConnect() is able to connect, flow continues and
			 * we rethrow the original exception obtained from trying to create
			 * the case. In this way, we obtain more detailed information if we
			 * are able, but do not lose any information if unable.
			 */
			final SleuthkitJNI.CaseDbHandle caseHandle = SleuthkitJNI.openCaseDb(databaseName, info);
			return new SleuthkitCase(info, databaseName, caseHandle, caseDir, contentProvider);
		} catch (PropertyVetoException exp) {
			// In this case, the JDBC driver doesn't support PostgreSQL. Use the generic message here.
			throw new TskCoreException(exp.getMessage(), exp);
		} catch (TskUnsupportedSchemaVersionException ex) {
			//don't wrap in new TskCoreException
			throw ex;
		} catch (Exception exp) {
			tryConnect(info); // attempt to connect, throw with user-friendly message if unable
			throw new TskCoreException(exp.getMessage(), exp); // throw with generic message if tryConnect() was successful
		}
	}

	/**
	 * Creates a new SQLite case database.
	 *
	 * @param dbPath Path to where SQlite case database should be created.
	 *
	 * @return A case database object.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public static SleuthkitCase newCase(String dbPath) throws TskCoreException {
		return newCase(dbPath, null);
	}
	
	/**
	 * Creates a new SQLite case database.
	 *
	 * @param dbPath Path to where SQlite case database should be created.
	 * @param contentProvider Custom provider for file bytes (can be null).
	 *
	 * @return A case database object.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	@Beta
	public static SleuthkitCase newCase(String dbPath, ContentStreamProvider contentProvider) throws TskCoreException {
		return newCase(dbPath, contentProvider, null);
	}

	/**
	 * Creates a new SQLite case database.
	 *
	 * @param dbPath                 Path to where SQlite case database should
	 *                               be created.
	 * @param contentProvider        Custom provider for file bytes (can be
	 *                               null).
	 * @param lockingApplicationName The name of the application locking the
	 *                               case database (null value prevents
	 *                               locking; 500 character maximum).
	 *
	 * @return A case database object.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	@Beta
	public static SleuthkitCase newCase(String dbPath, ContentStreamProvider contentProvider, String lockingApplicationName) throws TskCoreException {

		try {
			CaseDatabaseFactory factory = new CaseDatabaseFactory(dbPath);
			factory.createCaseDatabase();

			SleuthkitJNI.CaseDbHandle caseHandle = SleuthkitJNI.openCaseDb(dbPath);
			return new SleuthkitCase(dbPath, caseHandle, DbType.SQLITE, contentProvider, lockingApplicationName);
		} catch (Exception ex) {
			throw new TskCoreException("Failed to create case database at " + dbPath, ex);
		}
	}

	/**
	 * Creates a new PostgreSQL case database.
	 *
	 * @param caseName    The name of the case. It will be used to create a case
	 *                    database name that can be safely used in SQL commands
	 *                    and will not be subject to name collisions on the case
	 *                    database server. Use getDatabaseName to get the
	 *                    created name.
	 * @param info        The information to connect to the database.
	 * @param caseDirPath The case directory path.
	 *
	 * @return A case database object.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public static SleuthkitCase newCase(String caseName, CaseDbConnectionInfo info, String caseDirPath) throws TskCoreException {
		return newCase(caseName, info, caseDirPath, null);
	}
	
	
	/**
	 * Creates a new PostgreSQL case database.
	 *
	 * @param caseName    The name of the case. It will be used to create a case
	 *                    database name that can be safely used in SQL commands
	 *                    and will not be subject to name collisions on the case
	 *                    database server. Use getDatabaseName to get the
	 *                    created name.
	 * @param info        The information to connect to the database.
	 * @param caseDirPath The case directory path.
	 * @param contentProvider Custom provider for file bytes (can be null).
	 *
	 * @return A case database object.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	@Beta
	public static SleuthkitCase newCase(String caseName, CaseDbConnectionInfo info, String caseDirPath, ContentStreamProvider contentProvider) throws TskCoreException {
		String databaseName = createCaseDataBaseName(caseName);
		try {
			/**
			 * The flow of this method involves trying to create a new case and
			 * if successful, return that case. If unsuccessful, an exception is
			 * thrown. We catch any exceptions, and use tryConnect() to attempt
			 * to obtain further information about the error. If tryConnect() is
			 * unable to successfully connect, tryConnect() will throw a
			 * TskCoreException with a message containing user-level error
			 * reporting. If tryConnect() is able to connect, flow continues and
			 * we rethrow the original exception obtained from trying to create
			 * the case. In this way, we obtain more detailed information if we
			 * are able, but do not lose any information if unable.
			 */
			CaseDatabaseFactory factory = new CaseDatabaseFactory(databaseName, info);
			factory.createCaseDatabase();

			final SleuthkitJNI.CaseDbHandle caseHandle = SleuthkitJNI.openCaseDb(databaseName, info);
			return new SleuthkitCase(info, databaseName, caseHandle, caseDirPath, contentProvider);
		} catch (PropertyVetoException exp) {
			// In this case, the JDBC driver doesn't support PostgreSQL. Use the generic message here.
			throw new TskCoreException(exp.getMessage(), exp);
		} catch (Exception exp) {
			tryConnect(info); // attempt to connect, throw with user-friendly message if unable
			throw new TskCoreException(exp.getMessage(), exp); // throw with generic message if tryConnect() was successful
		}
	}

	/**
	 * Transforms a candidate PostgreSQL case database name into one that can be
	 * safely used in SQL commands and will not be subject to name collisions on
	 * the case database server.
	 *
	 * @param candidateDbName A candidate case database name.
	 *
	 * @return A case database name.
	 */
	private static String createCaseDataBaseName(String candidateDbName) {
		String dbName;
		if (!candidateDbName.isEmpty()) {
			/*
			 * Replace all non-ASCII characters.
			 */
			dbName = candidateDbName.replaceAll("[^\\p{ASCII}]", "_"); //NON-NLS

			/*
			 * Replace all control characters.
			 */
			dbName = dbName.replaceAll("[\\p{Cntrl}]", "_"); //NON-NLS

			/*
			 * Replace /, \, :, ?, space, ' ".
			 */
			dbName = dbName.replaceAll("[ /?:'\"\\\\]", "_"); //NON-NLS

			/*
			 * Make it all lowercase.
			 */
			dbName = dbName.toLowerCase();

			/*
			 * Must start with letter or underscore. If not, prepend an
			 * underscore.
			 */
			if ((dbName.length() > 0 && !(Character.isLetter(dbName.codePointAt(0))) && !(dbName.codePointAt(0) == '_'))) {
				dbName = "_" + dbName;
			}

			/*
			 * Truncate to 63 - 16 = 47 chars to accomodate a timestamp for
			 * uniqueness.
			 */
			if (dbName.length() > MAX_DB_NAME_LEN_BEFORE_TIMESTAMP) {
				dbName = dbName.substring(0, MAX_DB_NAME_LEN_BEFORE_TIMESTAMP);
			}

		} else {
			/*
			 * Must start with letter or underscore.
			 */
			dbName = "_";
		}
		/*
		 * Add the time stmap.
		 */
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd_HHmmss");
		Date date = new Date();
		dbName = dbName + "_" + dateFormat.format(date);

		return dbName;
	}
	
	/**
	 * Disable the creation of timeline events for new files.
	 * 
	 * This setting is not saved to the case database.
	 */
	@Beta
	public void disableTimelineEventCreation() {
		timelineEventsDisabled.set(true);
	}

	/**
	 * Returns the Examiner object for currently logged in user
	 *
	 * @return A Examiner object.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public Examiner getCurrentExaminer() throws TskCoreException {

		// return cached value if there's one
		if (cachedCurrentExaminer != null) {
			return cachedCurrentExaminer;
		}
		String loginName = System.getProperty("user.name");
		if (loginName == null || loginName.isEmpty()) {
			throw new TskCoreException("Failed to determine logged in user name.");
		}

		ResultSet resultSet = null;
		CaseDbConnection connection = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_EXAMINER_BY_LOGIN_NAME);
			statement.clearParameters();
			statement.setString(1, loginName);
			resultSet = connection.executeQuery(statement);
			if (resultSet.next()) {
				cachedCurrentExaminer = new Examiner(resultSet.getLong("examiner_id"), resultSet.getString("login_name"), resultSet.getString("display_name"));
				return cachedCurrentExaminer;
			} else {
				throw new TskCoreException("Error getting examaminer for name = " + loginName);
			}

		} catch (SQLException ex) {
			throw new TskCoreException("Error getting examaminer for name = " + loginName, ex);
		} finally {
			closeResultSet(resultSet);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}

	}

	/**
	 * Returns the Examiner object for given id
	 *
	 * @param id
	 *
	 * @return Examiner object
	 *
	 * @throws TskCoreException
	 */
	Examiner getExaminerById(long id) throws TskCoreException {

		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_EXAMINER_BY_ID);
			statement.clearParameters();
			statement.setLong(1, id);
			resultSet = connection.executeQuery(statement);
			if (resultSet.next()) {
				return new Examiner(resultSet.getLong("examiner_id"), resultSet.getString("login_name"), resultSet.getString("full_name"));
			} else {
				throw new TskCoreException("Error getting examaminer for id = " + id);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting examaminer for id = " + id, ex);
		} finally {
			closeResultSet(resultSet);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Starts the multi-step process of adding an image data source to the case
	 * by creating an object that can be used to control the process and get
	 * progress messages from it.
	 *
	 * @param timeZone        The time zone of the image.
	 * @param addUnallocSpace Set to true to create virtual files for
	 *                        unallocated space in the image.
	 * @param noFatFsOrphans  Set to true to skip processing orphan files of FAT
	 *                        file systems.
	 * @param imageCopyPath   Path to which a copy of the image should be
	 *                        written. Use the empty string to disable image
	 *                        writing.
	 *
	 * @return An object that encapsulates control of adding an image via the
	 *         SleuthKit native code layer.
	 */
	public AddImageProcess makeAddImageProcess(String timeZone, boolean addUnallocSpace, boolean noFatFsOrphans, String imageCopyPath) {
		return makeAddImageProcess(timeZone, addUnallocSpace, noFatFsOrphans, imageCopyPath, null);
	}

	/**
	 * Starts the multi-step process of adding an image data source to the case
	 * by creating an object that can be used to control the process and get
	 * progress messages from it.
	 *
	 * @param timeZone        The time zone of the image.
	 * @param addUnallocSpace Set to true to create virtual files for
	 *                        unallocated space in the image.
	 * @param noFatFsOrphans  Set to true to skip processing orphan files of FAT
	 *                        file systems.
	 * @param imageCopyPath   Path to which a copy of the image should be
	 *                        written. Use the empty string to disable image
	 *                        writing.
	 * @param password        The password for decrypting the image or null if
	 *                        not needed.
	 *
	 * @return An object that encapsulates control of adding an image via the
	 *         SleuthKit native code layer.
	 */
	@Beta
	public AddImageProcess makeAddImageProcess(String timeZone, boolean addUnallocSpace, boolean noFatFsOrphans, String imageCopyPath, String password) {
		return this.caseHandle.initAddImageProcess(timeZone, addUnallocSpace, noFatFsOrphans, imageCopyPath, password, this);
	}
	
	/**
	 * Get the list of root objects (data sources) from the case database, e.g.,
	 * image files, logical (local) files, virtual directories.
	 *
	 * @return List of content objects representing root objects.
	 *
	 * @throws TskCoreException
	 */
	public List<Content> getRootObjects() throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT obj_id, type FROM tsk_objects " //NON-NLS
					+ "WHERE par_obj_id IS NULL"); //NON-NLS
			Collection<ObjectInfo> infos = new ArrayList<ObjectInfo>();
			while (rs.next()) {
				infos.add(new ObjectInfo(rs.getLong("obj_id"), ObjectType.valueOf(rs.getShort("type")))); //NON-NLS
			}

			List<Content> rootObjs = new ArrayList<Content>();
			for (ObjectInfo i : infos) {
				if (null != i.type) {
					switch (i.type) {
						case IMG:
							rootObjs.add(getImageById(i.id));
							break;
						case ABSTRACTFILE:
							// Check if virtual dir for local files.
							AbstractFile af = getAbstractFileById(i.id);
							if (af instanceof VirtualDirectory) {
								rootObjs.add(af);
							} else {
								throw new TskCoreException("Parentless object has wrong type to be a root (ABSTRACTFILE, but not VIRTUAL_DIRECTORY: " + i.type);
							}
							break;
						case REPORT:
							break;
						case OS_ACCOUNT:
							break;
						case HOST_ADDRESS:
							break;
						case UNSUPPORTED:
							break;
						default:
							throw new TskCoreException("Parentless object has wrong type to be a root: " + i.type);
					}
				}
			}
			return rootObjs;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting root objects", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Gets the the datasource obj ids for the given device_id
	 *
	 * @param deviceId device_id
	 *
	 * @return A list of the data source object_id for the given device_id for
	 *         the case.
	 *
	 * @throws TskCoreException if there is a problem getting the data source
	 *                          obj ids.
	 */
	List<Long> getDataSourceObjIds(String deviceId) throws TskCoreException {

		// check cached map first
		synchronized (deviceIdToDatasourceObjIdMap) {
			if (deviceIdToDatasourceObjIdMap.containsKey(deviceId)) {
				return new ArrayList<Long>(deviceIdToDatasourceObjIdMap.get(deviceId));
			}

			CaseDbConnection connection = null;
			Statement s = null;
			ResultSet rs = null;
			acquireSingleUserCaseReadLock();
			try {
				connection = connections.getConnection();
				s = connection.createStatement();
				rs = connection.executeQuery(s, "SELECT obj_id FROM data_source_info WHERE device_id = '" + deviceId + "'"); //NON-NLS
				List<Long> dataSourceObjIds = new ArrayList<Long>();
				while (rs.next()) {
					dataSourceObjIds.add(rs.getLong("obj_id"));

					// Add to map of deviceID to data_source_obj_id.
					long ds_obj_id = rs.getLong("obj_id");
					if (deviceIdToDatasourceObjIdMap.containsKey(deviceId)) {
						deviceIdToDatasourceObjIdMap.get(deviceId).add(ds_obj_id);
					} else {
						deviceIdToDatasourceObjIdMap.put(deviceId, new HashSet<Long>(Arrays.asList(ds_obj_id)));
					}
				}
				return dataSourceObjIds;
			} catch (SQLException ex) {
				throw new TskCoreException("Error getting data sources", ex);
			} finally {
				closeResultSet(rs);
				closeStatement(s);
				closeConnection(connection);
				releaseSingleUserCaseReadLock();
			}
		}
	}

	/**
	 * Gets the data sources for the case. For each data source, if it is an
	 * image, an Image will be instantiated. Otherwise, a LocalFilesDataSource
	 * will be instantiated.
	 *
	 * NOTE: The DataSource interface is an emerging feature and at present is
	 * only useful for obtaining the object id and the device id, an
	 * ASCII-printable identifier for the device associated with the data source
	 * that is intended to be unique across multiple cases (e.g., a UUID). In
	 * the future, this method will be a replacement for the getRootObjects
	 * method.
	 *
	 * @return A list of the data sources for the case.
	 *
	 * @throws TskCoreException if there is a problem getting the data sources.
	 */
	public List<DataSource> getDataSources() throws TskCoreException {
		CaseDbConnection connection = null;
		Statement statement = null;
		ResultSet resultSet = null;
		Statement statement2 = null;
		ResultSet resultSet2 = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			statement = connection.createStatement();
			statement2 = connection.createStatement();
			resultSet = connection.executeQuery(statement,
					"SELECT ds.obj_id, ds.device_id, ds.time_zone, img.type, img.ssize, img.size, img.md5, img.sha1, img.sha256, img.display_name "
					+ "FROM data_source_info AS ds "
					+ "LEFT JOIN tsk_image_info AS img "
					+ "ON ds.obj_id = img.obj_id"); //NON-NLS

			List<DataSource> dataSourceList = new ArrayList<DataSource>();
			Map<Long, List<String>> imagePathsMap = getImagePaths();

			while (resultSet.next()) {
				DataSource dataSource;
				Long objectId = resultSet.getLong("obj_id");
				String deviceId = resultSet.getString("device_id");
				String timezone = resultSet.getString("time_zone");
				String type = resultSet.getString("type");

				if (type == null) {
					/*
					 * No data found in 'tsk_image_info', so we build a
					 * LocalFilesDataSource.
					 */

					resultSet2 = connection.executeQuery(statement2, "SELECT name FROM tsk_files WHERE tsk_files.obj_id = " + objectId); //NON-NLS
					String dsName = (resultSet2.next()) ? resultSet2.getString("name") : "";
					resultSet2.close();

					TSK_FS_NAME_TYPE_ENUM dirType = TSK_FS_NAME_TYPE_ENUM.DIR;
					TSK_FS_META_TYPE_ENUM metaType = TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR;
					TSK_FS_NAME_FLAG_ENUM dirFlag = TSK_FS_NAME_FLAG_ENUM.ALLOC;
					final short metaFlags = (short) (TSK_FS_META_FLAG_ENUM.ALLOC.getValue()
							| TSK_FS_META_FLAG_ENUM.USED.getValue());
					String parentPath = "/"; //NON-NLS
					dataSource = new LocalFilesDataSource(this, objectId, objectId, deviceId, dsName, dirType, metaType, dirFlag, metaFlags, timezone, null, null, null, FileKnown.UNKNOWN, parentPath);
				} else {
					/*
					 * Data found in 'tsk_image_info', so we build an Image.
					 */
					Long ssize = resultSet.getLong("ssize");
					Long size = resultSet.getLong("size");
					String md5 = resultSet.getString("md5");
					String sha1 = resultSet.getString("sha1");
					String sha256 = resultSet.getString("sha256");
					String name = resultSet.getString("display_name");

					List<String> imagePaths = imagePathsMap.get(objectId);
					if (name == null) {
						if (imagePaths.size() > 0) {
							String path = imagePaths.get(0);
							name = (new java.io.File(path)).getName();
						} else {
							name = "";
						}
					}

					dataSource = new Image(this, objectId, Long.valueOf(type), deviceId, ssize, name,
							imagePaths.toArray(new String[imagePaths.size()]), timezone, md5, sha1, sha256, size);
				}

				dataSourceList.add(dataSource);
			}

			return dataSourceList;

		} catch (SQLException ex) {
			throw new TskCoreException("Error getting data sources", ex);
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			closeResultSet(resultSet2);
			closeStatement(statement2);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Gets a specific data source for the case. If it is an image, an Image
	 * will be instantiated. Otherwise, a LocalFilesDataSource will be
	 * instantiated.
	 *
	 * NOTE: The DataSource class is an emerging feature and at present is only
	 * useful for obtaining the object id and the data source identifier, an
	 * ASCII-printable identifier for the data source that is intended to be
	 * unique across multiple cases (e.g., a UUID). In the future, this method
	 * will be a replacement for the getRootObjects method.
	 *
	 * @param objectId The object id of the data source.
	 *
	 * @return The data source.
	 *
	 * @throws TskDataException If there is no data source for the given object
	 *                          id.
	 * @throws TskCoreException If there is a problem getting the data source.
	 */
	public DataSource getDataSource(long objectId) throws TskDataException, TskCoreException {
		DataSource dataSource = null;
		CaseDbConnection connection = null;
		Statement statement = null;
		ResultSet resultSet = null;
		Statement statement2 = null;
		ResultSet resultSet2 = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			statement = connection.createStatement();
			statement2 = connection.createStatement();
			resultSet = connection.executeQuery(statement,
					"SELECT ds.device_id, ds.time_zone, img.type, img.ssize, img.size, img.md5, img.sha1, img.sha256, img.display_name "
					+ "FROM data_source_info AS ds "
					+ "LEFT JOIN tsk_image_info AS img "
					+ "ON ds.obj_id = img.obj_id "
					+ "WHERE ds.obj_id = " + objectId); //NON-NLS
			if (resultSet.next()) {
				String deviceId = resultSet.getString("device_id");
				String timezone = resultSet.getString("time_zone");
				String type = resultSet.getString("type");

				if (type == null) {
					/*
					 * No data found in 'tsk_image_info', so we build an
					 * LocalFilesDataSource.
					 */

					resultSet2 = connection.executeQuery(statement2, "SELECT name FROM tsk_files WHERE tsk_files.obj_id = " + objectId); //NON-NLS
					String dsName = (resultSet2.next()) ? resultSet2.getString("name") : "";

					TSK_FS_NAME_TYPE_ENUM dirType = TSK_FS_NAME_TYPE_ENUM.DIR;
					TSK_FS_META_TYPE_ENUM metaType = TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR;
					TSK_FS_NAME_FLAG_ENUM dirFlag = TSK_FS_NAME_FLAG_ENUM.ALLOC;
					final short metaFlags = (short) (TSK_FS_META_FLAG_ENUM.ALLOC.getValue()
							| TSK_FS_META_FLAG_ENUM.USED.getValue());
					String parentPath = "/"; //NON-NLS
					dataSource = new LocalFilesDataSource(this, objectId, objectId, deviceId, dsName, dirType, metaType, dirFlag, metaFlags, timezone, null, null, null, FileKnown.UNKNOWN, parentPath);
				} else {
					/*
					 * Data found in 'tsk_image_info', so we build an Image.
					 */
					Long ssize = resultSet.getLong("ssize");
					Long size = resultSet.getLong("size");
					String md5 = resultSet.getString("md5");
					String sha1 = resultSet.getString("sha1");
					String sha256 = resultSet.getString("sha256");
					String name = resultSet.getString("display_name");

					List<String> imagePaths = getImagePathsById(objectId, connection);
					if (name == null) {
						if (imagePaths.size() > 0) {
							String path = imagePaths.get(0);
							name = (new java.io.File(path)).getName();
						} else {
							name = "";
						}
					}

					dataSource = new Image(this, objectId, Long.valueOf(type), deviceId, ssize, name,
							imagePaths.toArray(new String[imagePaths.size()]), timezone, md5, sha1, sha256, size);
				}
			} else {
				throw new TskDataException(String.format("There is no data source with obj_id = %d", objectId));
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting data source with obj_id = %d", objectId), ex);
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			closeResultSet(resultSet2);
			closeStatement(statement2);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}

		return dataSource;
	}

	/**
	 * Get all blackboard artifacts of a given type. Does not included rejected
	 * artifacts.
	 *
	 * @param artifactTypeID artifact type id (must exist in database)
	 *
	 * @return list of blackboard artifacts.
	 *
	 * @throws TskCoreException
	 *
	 * @deprecated Use Blackboard.getArtifacts with the desired type(s) and data source(s) as arguments instead.
	 */
	@Deprecated
	public ArrayList<BlackboardArtifact> getBlackboardArtifacts(int artifactTypeID) throws TskCoreException {
		ArrayList<BlackboardArtifact> artifacts = new ArrayList<>();
		artifacts.addAll(blackboard.getArtifactsByType(blackboard.getArtifactType(artifactTypeID)));
		return artifacts;
	}

	/**
	 * Get a count of blackboard artifacts for a given content. Does not include
	 * rejected artifacts.
	 *
	 * @param objId Id of the content.
	 *
	 * @return The artifacts count for the content.
	 *
	 * @throws TskCoreException
	 */
	public long getBlackboardArtifactsCount(long objId) throws TskCoreException {
		CaseDbConnection connection = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// SELECT COUNT(*) AS count FROM blackboard_artifacts WHERE obj_id = ?
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.COUNT_ARTIFACTS_FROM_SOURCE);
			statement.clearParameters();
			statement.setLong(1, objId);
			rs = connection.executeQuery(statement);
			long count = 0;
			if (rs.next()) {
				count = rs.getLong("count");
			}
			return count;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting number of blackboard artifacts by content", ex);
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get a count of artifacts of a given type. Does not include rejected
	 * artifacts.
	 *
	 * @param artifactTypeID Id of the artifact type.
	 *
	 * @return The artifacts count for the type.
	 *
	 * @throws TskCoreException
	 */
	public long getBlackboardArtifactsTypeCount(int artifactTypeID) throws TskCoreException {
		CaseDbConnection connection = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// SELECT COUNT(*) AS count FROM blackboard_artifacts WHERE artifact_type_id = ?
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.COUNT_ARTIFACTS_OF_TYPE);
			statement.clearParameters();
			statement.setInt(1, artifactTypeID);
			rs = connection.executeQuery(statement);
			long count = 0;
			if (rs.next()) {
				count = rs.getLong("count");
			}
			return count;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting number of blackboard artifacts by type", ex);
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get a count of artifacts of a given type for the given data source. Does
	 * not include rejected artifacts.
	 *
	 * @param artifactTypeID Id of the artifact type.
	 * @param dataSourceID
	 *
	 * @return The artifacts count for the type.
	 *
	 * @throws TskCoreException
	 */
	public long getBlackboardArtifactsTypeCount(int artifactTypeID, long dataSourceID) throws TskCoreException {
		CaseDbConnection connection = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// SELECT COUNT(*) AS count FROM blackboard_artifacts WHERE artifact_type_id = ?
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.COUNT_ARTIFACTS_OF_TYPE_BY_DATA_SOURCE);
			statement.clearParameters();
			statement.setInt(2, artifactTypeID);
			statement.setLong(1, dataSourceID);
			rs = connection.executeQuery(statement);
			long count = 0;
			if (rs.next()) {
				count = rs.getLong("count");
			}
			return count;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting number of blackboard artifacts by type (%d) and data source (%d)", artifactTypeID, dataSourceID), ex);
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get all blackboard artifacts that have an attribute of the given type and
	 * String value. Does not included rejected artifacts.
	 *
	 * @param attrType attribute of this attribute type to look for in the
	 *                 artifacts
	 * @param value    value of the attribute of the attrType type to look for
	 *
	 * @return a list of blackboard artifacts with such an attribute
	 *
	 * @throws TskCoreException exception thrown if a critical error occurred
	 *                          within tsk core and artifacts could not be
	 *                          queried
	 *
	 * @deprecated Do not use.
	 */
	@Deprecated
	public List<BlackboardArtifact> getBlackboardArtifacts(BlackboardAttribute.ATTRIBUTE_TYPE attrType, String value) throws TskCoreException {
		acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = connections.getConnection(); Statement statement = connection.createStatement();
				ResultSet resultSet = connection.executeQuery(statement, "SELECT DISTINCT arts.artifact_id AS artifact_id, " //NON-NLS
						+ "arts.obj_id AS obj_id, arts.artifact_obj_id AS artifact_obj_id, arts.data_source_obj_id AS data_source_obj_id, arts.artifact_type_id AS artifact_type_id, "
						+ "types.type_name AS type_name, types.display_name AS display_name, "//NON-NLS
						+ " arts.review_status_id AS review_status_id " //NON-NLS
						+ "FROM blackboard_artifacts AS arts, blackboard_attributes AS attrs, blackboard_artifact_types AS types " //NON-NLS
						+ "WHERE arts.artifact_id = attrs.artifact_id " //NON-NLS
						+ " AND attrs.attribute_type_id = " + attrType.getTypeID() //NON-NLS
						+ " AND attrs.value_text = '" + value + "'"
						+ " AND types.artifact_type_id=arts.artifact_type_id"
						+ " AND arts.review_status_id !=" + BlackboardArtifact.ReviewStatus.REJECTED.getID());) {	 //NON-NLS

			List<Long> analysisArtifactObjIds = new ArrayList<>();
			List<Long> dataArtifactObjIds = new ArrayList<>();
			while (resultSet.next()) {
				BlackboardArtifact.Type type = blackboard.getArtifactType(resultSet.getInt("artifact_type_id"));
				if (type.getCategory() == BlackboardArtifact.Category.ANALYSIS_RESULT) {
					analysisArtifactObjIds.add(resultSet.getLong("artifact_obj_id"));
				} else {
					dataArtifactObjIds.add(resultSet.getLong("artifact_obj_id"));
				}
			}

			ArrayList<BlackboardArtifact> artifacts = new ArrayList<>();
			if (!analysisArtifactObjIds.isEmpty()) {
				artifacts.addAll(getArtifactsForValues(BlackboardArtifact.Category.ANALYSIS_RESULT, "artifacts.artifact_obj_id", analysisArtifactObjIds, connection));
			}

			if (!dataArtifactObjIds.isEmpty()) {
				artifacts.addAll(getArtifactsForValues(BlackboardArtifact.Category.DATA_ARTIFACT, "artifacts.artifact_obj_id", dataArtifactObjIds, connection));
			}
			return artifacts;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifacts by attribute", ex);
		} finally {
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get all blackboard artifacts that have an attribute of the given type and
	 * String value. Does not included rejected artifacts.
	 *
	 * @param attrType   attribute of this attribute type to look for in the
	 *                   artifacts
	 * @param subString  value substring of the string attribute of the attrType
	 *                   type to look for
	 * @param startsWith if true, the artifact attribute string should start
	 *                   with the substring, if false, it should just contain it
	 *
	 * @return a list of blackboard artifacts with such an attribute
	 *
	 * @throws TskCoreException exception thrown if a critical error occurred
	 *                          within tsk core and artifacts could not be
	 *                          queried
	 * @deprecated Do not use.
	 */
	@Deprecated
	public List<BlackboardArtifact> getBlackboardArtifacts(BlackboardAttribute.ATTRIBUTE_TYPE attrType, String subString, boolean startsWith) throws TskCoreException {
		String valSubStr = "%" + subString; //NON-NLS
		if (startsWith == false) {
			valSubStr += "%"; //NON-NLS
		}

		acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = connections.getConnection(); Statement statement = connection.createStatement();
				ResultSet resultSet = connection.executeQuery(statement, "SELECT DISTINCT arts.artifact_id AS artifact_id, " //NON-NLS
						+ " arts.obj_id AS obj_id, arts.artifact_obj_id AS artifact_obj_id, arts.data_source_obj_id AS data_source_obj_id, arts.artifact_type_id AS artifact_type_id, " //NON-NLS
						+ " types.type_name AS type_name, types.display_name AS display_name, " //NON-NLS
						+ " arts.review_status_id AS review_status_id " //NON-NLS
						+ " FROM blackboard_artifacts AS arts, blackboard_attributes AS attrs, blackboard_artifact_types AS types " //NON-NLS
						+ " WHERE arts.artifact_id = attrs.artifact_id " //NON-NLS
						+ " AND attrs.attribute_type_id = " + attrType.getTypeID() //NON-NLS
						+ " AND LOWER(attrs.value_text) LIKE LOWER('" + valSubStr + "')"
						+ " AND types.artifact_type_id=arts.artifact_type_id "
						+ " AND arts.review_status_id !=" + BlackboardArtifact.ReviewStatus.REJECTED.getID());) {
			List<Long> analysisArtifactObjIds = new ArrayList<>();
			List<Long> dataArtifactObjIds = new ArrayList<>();
			while (resultSet.next()) {
				BlackboardArtifact.Type type = blackboard.getArtifactType(resultSet.getInt("artifact_type_id"));
				if (type.getCategory() == BlackboardArtifact.Category.ANALYSIS_RESULT) {
					analysisArtifactObjIds.add(resultSet.getLong("artifact_obj_id"));
				} else {
					dataArtifactObjIds.add(resultSet.getLong("artifact_obj_id"));
				}
			}

			ArrayList<BlackboardArtifact> artifacts = new ArrayList<>();
			if (!analysisArtifactObjIds.isEmpty()) {
				artifacts.addAll(getArtifactsForValues(BlackboardArtifact.Category.ANALYSIS_RESULT, "artifacts.artifact_obj_id", analysisArtifactObjIds, connection));
			}

			if (!dataArtifactObjIds.isEmpty()) {
				artifacts.addAll(getArtifactsForValues(BlackboardArtifact.Category.DATA_ARTIFACT, "artifacts.artifact_obj_id", dataArtifactObjIds, connection));
			}
			return artifacts;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifacts by attribute. " + ex.getMessage(), ex);
		} finally {
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get all blackboard artifacts that have an attribute of the given type and
	 * integer value. Does not included rejected artifacts.
	 *
	 * @param attrType attribute of this attribute type to look for in the
	 *                 artifacts
	 * @param value    value of the attribute of the attrType type to look for
	 *
	 * @return a list of blackboard artifacts with such an attribute
	 *
	 * @throws TskCoreException exception thrown if a critical error occurred
	 *                          within tsk core and artifacts could not be
	 *                          queried
	 * @deprecated Do not use.
	 */
	@Deprecated
	public List<BlackboardArtifact> getBlackboardArtifacts(BlackboardAttribute.ATTRIBUTE_TYPE attrType, int value) throws TskCoreException {
		acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = connections.getConnection(); Statement statement = connection.createStatement();
				ResultSet resultSet = connection.executeQuery(statement, "SELECT DISTINCT arts.artifact_id AS artifact_id, " //NON-NLS
						+ " arts.obj_id AS obj_id, arts.artifact_obj_id AS artifact_obj_id, arts.data_source_obj_id AS data_source_obj_id, arts.artifact_type_id AS artifact_type_id, "
						+ " types.type_name AS type_name, types.display_name AS display_name, "
						+ " arts.review_status_id AS review_status_id  "//NON-NLS
						+ " FROM blackboard_artifacts AS arts, blackboard_attributes AS attrs, blackboard_artifact_types AS types " //NON-NLS
						+ "WHERE arts.artifact_id = attrs.artifact_id " //NON-NLS
						+ " AND attrs.attribute_type_id = " + attrType.getTypeID() //NON-NLS
						+ " AND attrs.value_int32 = " + value //NON-NLS
						+ " AND types.artifact_type_id=arts.artifact_type_id "
						+ " AND arts.review_status_id !=" + BlackboardArtifact.ReviewStatus.REJECTED.getID());) {
			List<Long> analysisArtifactObjIds = new ArrayList<>();
			List<Long> dataArtifactObjIds = new ArrayList<>();
			while (resultSet.next()) {
				BlackboardArtifact.Type type = blackboard.getArtifactType(resultSet.getInt("artifact_type_id"));
				if (type.getCategory() == BlackboardArtifact.Category.ANALYSIS_RESULT) {
					analysisArtifactObjIds.add(resultSet.getLong("artifact_obj_id"));
				} else {
					dataArtifactObjIds.add(resultSet.getLong("artifact_obj_id"));
				}
			}

			ArrayList<BlackboardArtifact> artifacts = new ArrayList<>();
			if (!analysisArtifactObjIds.isEmpty()) {
				artifacts.addAll(getArtifactsForValues(BlackboardArtifact.Category.ANALYSIS_RESULT, "artifacts.artifact_obj_id", analysisArtifactObjIds, connection));
			}

			if (!dataArtifactObjIds.isEmpty()) {
				artifacts.addAll(getArtifactsForValues(BlackboardArtifact.Category.DATA_ARTIFACT, "artifacts.artifact_obj_id", dataArtifactObjIds, connection));
			}
			return artifacts;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifacts by attribute", ex);
		} finally {
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get all blackboard artifacts that have an attribute of the given type and
	 * long value. Does not included rejected artifacts.
	 *
	 * @param attrType attribute of this attribute type to look for in the
	 *                 artifacts
	 * @param value    value of the attribute of the attrType type to look for
	 *
	 * @return a list of blackboard artifacts with such an attribute
	 *
	 * @throws TskCoreException exception thrown if a critical error occurred
	 *                          within tsk core and artifacts could not be
	 *                          queried
	 *
	 * @deprecated Do not use.
	 */
	@Deprecated
	public List<BlackboardArtifact> getBlackboardArtifacts(BlackboardAttribute.ATTRIBUTE_TYPE attrType, long value) throws TskCoreException {
		acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = connections.getConnection(); Statement statement = connection.createStatement();
				ResultSet resultSet = connection.executeQuery(statement, "SELECT DISTINCT arts.artifact_id AS artifact_id, " //NON-NLS
						+ " arts.obj_id AS obj_id, arts.artifact_obj_id AS artifact_obj_id, arts.data_source_obj_id AS data_source_obj_id, arts.artifact_type_id AS artifact_type_id, "
						+ " types.type_name AS type_name, types.display_name AS display_name, "
						+ " arts.review_status_id AS review_status_id "//NON-NLS
						+ " FROM blackboard_artifacts AS arts, blackboard_attributes AS attrs, blackboard_artifact_types AS types " //NON-NLS
						+ " WHERE arts.artifact_id = attrs.artifact_id " //NON-NLS
						+ " AND attrs.attribute_type_id = " + attrType.getTypeID() //NON-NLS
						+ " AND attrs.value_int64 = " + value //NON-NLS
						+ " AND types.artifact_type_id=arts.artifact_type_id "
						+ " AND arts.review_status_id !=" + BlackboardArtifact.ReviewStatus.REJECTED.getID());) {
			List<Long> analysisArtifactObjIds = new ArrayList<>();
			List<Long> dataArtifactObjIds = new ArrayList<>();
			while (resultSet.next()) {
				BlackboardArtifact.Type type = blackboard.getArtifactType(resultSet.getInt("artifact_type_id"));
				if (type.getCategory() == BlackboardArtifact.Category.ANALYSIS_RESULT) {
					analysisArtifactObjIds.add(resultSet.getLong("artifact_obj_id"));
				} else {
					dataArtifactObjIds.add(resultSet.getLong("artifact_obj_id"));
				}
			}

			ArrayList<BlackboardArtifact> artifacts = new ArrayList<>();
			if (!analysisArtifactObjIds.isEmpty()) {
				artifacts.addAll(getArtifactsForValues(BlackboardArtifact.Category.ANALYSIS_RESULT, "artifacts.artifact_obj_id", analysisArtifactObjIds, connection));
			}

			if (!dataArtifactObjIds.isEmpty()) {
				artifacts.addAll(getArtifactsForValues(BlackboardArtifact.Category.DATA_ARTIFACT, "artifacts.artifact_obj_id", dataArtifactObjIds, connection));
			}
			return artifacts;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifacts by attribute. " + ex.getMessage(), ex);
		} finally {
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get all blackboard artifacts that have an attribute of the given type and
	 * double value. Does not included rejected artifacts.
	 *
	 * @param attrType attribute of this attribute type to look for in the
	 *                 artifacts
	 * @param value    value of the attribute of the attrType type to look for
	 *
	 * @return a list of blackboard artifacts with such an attribute
	 *
	 * @throws TskCoreException exception thrown if a critical error occurred
	 *                          within tsk core and artifacts could not be
	 *                          queried
	 *
	 * @deprecated Do not use.
	 */
	@Deprecated
	public List<BlackboardArtifact> getBlackboardArtifacts(BlackboardAttribute.ATTRIBUTE_TYPE attrType, double value) throws TskCoreException {
		acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = connections.getConnection(); Statement statement = connection.createStatement();
				ResultSet resultSet = connection.executeQuery(statement, "SELECT DISTINCT arts.artifact_id AS artifact_id, " //NON-NLS
						+ " arts.obj_id AS obj_id, arts.artifact_obj_id AS artifact_obj_id, arts.data_source_obj_id AS data_source_obj_id, arts.artifact_type_id AS artifact_type_id, "
						+ " types.type_name AS type_name, types.display_name AS display_name, "
						+ " arts.review_status_id AS review_status_id "//NON-NLS
						+ " FROM blackboard_artifacts AS arts, blackboard_attributes AS attrs, blackboard_artifact_types AS types " //NON-NLS
						+ " WHERE arts.artifact_id = attrs.artifact_id " //NON-NLS
						+ " AND attrs.attribute_type_id = " + attrType.getTypeID() //NON-NLS
						+ " AND attrs.value_double = " + value //NON-NLS
						+ " AND types.artifact_type_id=arts.artifact_type_id "
						+ " AND arts.review_status_id !=" + BlackboardArtifact.ReviewStatus.REJECTED.getID());) {
			List<Long> analysisArtifactObjIds = new ArrayList<>();
			List<Long> dataArtifactObjIds = new ArrayList<>();
			while (resultSet.next()) {
				BlackboardArtifact.Type type = blackboard.getArtifactType(resultSet.getInt("artifact_type_id"));
				if (type.getCategory() == BlackboardArtifact.Category.ANALYSIS_RESULT) {
					analysisArtifactObjIds.add(resultSet.getLong("artifact_obj_id"));
				} else {
					dataArtifactObjIds.add(resultSet.getLong("artifact_obj_id"));
				}
			}

			ArrayList<BlackboardArtifact> artifacts = new ArrayList<>();
			if (!analysisArtifactObjIds.isEmpty()) {
				artifacts.addAll(getArtifactsForValues(BlackboardArtifact.Category.ANALYSIS_RESULT, "artifacts.artifact_obj_id", analysisArtifactObjIds, connection));
			}

			if (!dataArtifactObjIds.isEmpty()) {
				artifacts.addAll(getArtifactsForValues(BlackboardArtifact.Category.DATA_ARTIFACT, "artifacts.artifact_obj_id", dataArtifactObjIds, connection));
			}
			return artifacts;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifacts by attribute", ex);
		} finally {
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get all blackboard artifacts that have an attribute of the given type and
	 * byte value. Does not include rejected artifacts.
	 *
	 * @param attrType attribute of this attribute type to look for in the
	 *                 artifacts
	 * @param value    value of the attribute of the attrType type to look for
	 *
	 * @return a list of blackboard artifacts with such an attribute
	 *
	 * @throws TskCoreException exception thrown if a critical error occurred
	 *                          within tsk core and artifacts could not be
	 *                          queried
	 *
	 * @deprecated Do not use.
	 */
	@Deprecated
	public List<BlackboardArtifact> getBlackboardArtifacts(BlackboardAttribute.ATTRIBUTE_TYPE attrType, byte value) throws TskCoreException {

		acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = connections.getConnection(); Statement statement = connection.createStatement();
				ResultSet resultSet = connection.executeQuery(statement, "SELECT DISTINCT arts.artifact_id AS artifact_id, " //NON-NLS
						+ " arts.obj_id AS obj_id, arts.artifact_obj_id AS artifact_obj_id, arts.data_source_obj_id AS data_source_obj_id, arts.artifact_type_id AS artifact_type_id, "
						+ " types.type_name AS type_name, types.display_name AS display_name, "
						+ " arts.review_status_id AS review_status_id "//NON-NLS
						+ " FROM blackboard_artifacts AS arts, blackboard_attributes AS attrs, blackboard_artifact_types AS types " //NON-NLS
						+ " WHERE arts.artifact_id = attrs.artifact_id " //NON-NLS
						+ " AND attrs.attribute_type_id = " + attrType.getTypeID() //NON-NLS
						+ " AND attrs.value_byte = " + value //NON-NLS
						+ " AND types.artifact_type_id=arts.artifact_type_id "
						+ " AND arts.review_status_id !=" + BlackboardArtifact.ReviewStatus.REJECTED.getID());) {
			List<Long> analysisArtifactObjIds = new ArrayList<>();
			List<Long> dataArtifactObjIds = new ArrayList<>();
			while (resultSet.next()) {
				BlackboardArtifact.Type type = blackboard.getArtifactType(resultSet.getInt("artifact_type_id"));
				if (type.getCategory() == BlackboardArtifact.Category.ANALYSIS_RESULT) {
					analysisArtifactObjIds.add(resultSet.getLong("artifact_obj_id"));
				} else {
					dataArtifactObjIds.add(resultSet.getLong("artifact_obj_id"));
				}
			}

			ArrayList<BlackboardArtifact> artifacts = new ArrayList<>();
			if (!analysisArtifactObjIds.isEmpty()) {
				artifacts.addAll(getArtifactsForValues(BlackboardArtifact.Category.ANALYSIS_RESULT, "artifacts.artifact_obj_id", analysisArtifactObjIds, connection));
			}

			if (!dataArtifactObjIds.isEmpty()) {
				artifacts.addAll(getArtifactsForValues(BlackboardArtifact.Category.DATA_ARTIFACT, "artifacts.artifact_obj_id", dataArtifactObjIds, connection));
			}
			return artifacts;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifacts by attribute", ex);
		} finally {
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Gets a list of all the artifact types for this case
	 *
	 * @return a list of artifact types
	 *
	 * @throws TskCoreException when there is an error getting the types
	 */
	public Iterable<BlackboardArtifact.Type> getArtifactTypes() throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT artifact_type_id, type_name, display_name, category_type FROM blackboard_artifact_types"); //NON-NLS
			ArrayList<BlackboardArtifact.Type> artifactTypes = new ArrayList<BlackboardArtifact.Type>();
			while (rs.next()) {
				artifactTypes.add(new BlackboardArtifact.Type(rs.getInt("artifact_type_id"),
						rs.getString("type_name"), rs.getString("display_name"),
						BlackboardArtifact.Category.fromID(rs.getInt("category_type"))));
			}
			return artifactTypes;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting artifact types", ex); //NON-NLS
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get all of the standard blackboard artifact types that are in use in the
	 * blackboard.
	 *
	 * @return List of standard blackboard artifact types
	 *
	 * @throws TskCoreException
	 */
	public ArrayList<BlackboardArtifact.ARTIFACT_TYPE> getBlackboardArtifactTypesInUse() throws TskCoreException {
		String typeIdList = "";
		for (int i = 0; i < BlackboardArtifact.ARTIFACT_TYPE.values().length; ++i) {
			typeIdList += BlackboardArtifact.ARTIFACT_TYPE.values()[i].getTypeID();
			if (i < BlackboardArtifact.ARTIFACT_TYPE.values().length - 1) {
				typeIdList += ", ";
			}
		}
		String query = "SELECT DISTINCT artifact_type_id FROM blackboard_artifacts "
				+ "WHERE artifact_type_id IN (" + typeIdList + ")";
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, query);
			ArrayList<BlackboardArtifact.ARTIFACT_TYPE> usedArts = new ArrayList<BlackboardArtifact.ARTIFACT_TYPE>();
			while (rs.next()) {
				usedArts.add(ARTIFACT_TYPE.fromID(rs.getInt("artifact_type_id")));
			}
			return usedArts;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting artifact types in use", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Gets the list of all unique artifact IDs in use.
	 *
	 * Gets both static and dynamic IDs.
	 *
	 * @return The list of unique IDs
	 *
	 * @throws TskCoreException exception thrown if a critical error occurred
	 *                          within tsk core
	 */
	public List<BlackboardArtifact.Type> getArtifactTypesInUse() throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s,
					"SELECT DISTINCT arts.artifact_type_id AS artifact_type_id, "
					+ "types.type_name AS type_name, "
					+ "types.display_name AS display_name, "
					+ "types.category_type AS category_type "
					+ "FROM blackboard_artifact_types AS types "
					+ "INNER JOIN blackboard_artifacts AS arts "
					+ "ON arts.artifact_type_id = types.artifact_type_id"); //NON-NLS
			List<BlackboardArtifact.Type> uniqueArtifactTypes = new ArrayList<BlackboardArtifact.Type>();
			while (rs.next()) {
				uniqueArtifactTypes.add(new BlackboardArtifact.Type(rs.getInt("artifact_type_id"),
						rs.getString("type_name"), rs.getString("display_name"),
						BlackboardArtifact.Category.fromID(rs.getInt("category_type"))));
			}
			return uniqueArtifactTypes;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting attribute types", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Gets a list of all the attribute types for this case
	 *
	 * @return a list of attribute types
	 *
	 * @throws TskCoreException when there is an error getting the types
	 */
	public List<BlackboardAttribute.Type> getAttributeTypes() throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT attribute_type_id, type_name, display_name, value_type FROM blackboard_attribute_types"); //NON-NLS
			ArrayList<BlackboardAttribute.Type> attribute_types = new ArrayList<BlackboardAttribute.Type>();
			while (rs.next()) {
				attribute_types.add(new BlackboardAttribute.Type(rs.getInt("attribute_type_id"), rs.getString("type_name"),
						rs.getString("display_name"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.fromType(rs.getLong("value_type"))));
			}
			return attribute_types;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting attribute types", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get count of blackboard attribute types
	 *
	 * Counts both static (in enum) and dynamic attributes types (created by
	 * modules at runtime)
	 *
	 * @return count of attribute types
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public int getBlackboardAttributeTypesCount() throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT COUNT(*) AS count FROM blackboard_attribute_types"); //NON-NLS
			int count = 0;
			if (rs.next()) {
				count = rs.getInt("count");
			}
			return count;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting number of blackboard artifacts by type", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Helper method to get count of all artifacts matching the type id and
	 * object id. Does not included rejected artifacts.
	 *
	 * @param artifactTypeID artifact type id
	 * @param obj_id         associated object id
	 *
	 * @return count of matching blackboard artifacts
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	private long getArtifactsCountHelper(int artifactTypeID, long obj_id) throws TskCoreException {
		CaseDbConnection connection = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// SELECT COUNT(*) AS count FROM blackboard_artifacts WHERE obj_id = ? AND artifact_type_id = ?
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.COUNT_ARTIFACTS_BY_SOURCE_AND_TYPE);
			statement.clearParameters();
			statement.setLong(1, obj_id);
			statement.setInt(2, artifactTypeID);
			rs = connection.executeQuery(statement);
			long count = 0;
			if (rs.next()) {
				count = rs.getLong("count");
			}
			return count;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifact count", ex);
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get all blackboard artifacts of a given type for the given source (object
	 * id). Does	not included rejected artifacts.
	 *
	 * @param artifactTypeName artifact type name
	 * @param obj_id           object id
	 *
	 * @return list of blackboard artifacts
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public ArrayList<BlackboardArtifact> getBlackboardArtifacts(String artifactTypeName, long obj_id) throws TskCoreException {
		ArrayList<BlackboardArtifact> artifacts = new ArrayList<>();
		artifacts.addAll(blackboard.getArtifactsBySourceId(getArtifactType(artifactTypeName), obj_id));
		return artifacts;
	}

	/**
	 * Get all blackboard artifacts of a given type for the given object id.
	 * Does not included rejected artifacts.
	 *
	 * @param artifactTypeID artifact type id (must exist in database)
	 * @param obj_id         object id
	 *
	 * @return list of blackboard artifacts
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public ArrayList<BlackboardArtifact> getBlackboardArtifacts(int artifactTypeID, long obj_id) throws TskCoreException {
		ArrayList<BlackboardArtifact> artifacts = new ArrayList<>();
		artifacts.addAll(blackboard.getArtifactsBySourceId(blackboard.getArtifactType(artifactTypeID), obj_id));
		return artifacts;
	}

	/**
	 * Get all blackboard artifacts of a given type for the given object id.
	 * Does not included rejected artifacts.
	 *
	 * @param artifactType artifact type enum
	 * @param obj_id       object id
	 *
	 * @return list of blackboard artifacts
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public ArrayList<BlackboardArtifact> getBlackboardArtifacts(ARTIFACT_TYPE artifactType, long obj_id) throws TskCoreException {
		return getBlackboardArtifacts(artifactType.getTypeID(), obj_id);
	}

	/**
	 * Get count of all blackboard artifacts of a given type for the given
	 * object id. Does not include rejected artifacts.
	 *
	 * @param artifactTypeName artifact type name
	 * @param obj_id           object id
	 *
	 * @return count of blackboard artifacts
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public long getBlackboardArtifactsCount(String artifactTypeName, long obj_id) throws TskCoreException {
		int artifactTypeID = this.getArtifactType(artifactTypeName).getTypeID();
		if (artifactTypeID == -1) {
			return 0;
		}
		return getArtifactsCountHelper(artifactTypeID, obj_id);
	}

	/**
	 * Get count of all blackboard artifacts of a given type for the given
	 * object id. Does not include rejected artifacts.
	 *
	 * @param artifactTypeID artifact type id (must exist in database)
	 * @param obj_id         object id
	 *
	 * @return count of blackboard artifacts
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public long getBlackboardArtifactsCount(int artifactTypeID, long obj_id) throws TskCoreException {
		return getArtifactsCountHelper(artifactTypeID, obj_id);
	}

	/**
	 * Get count of all blackboard artifacts of a given type for the given
	 * object id. Does not include rejected artifacts.
	 *
	 * @param artifactType artifact type enum
	 * @param obj_id       object id
	 *
	 * @return count of blackboard artifacts
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public long getBlackboardArtifactsCount(ARTIFACT_TYPE artifactType, long obj_id) throws TskCoreException {
		return getArtifactsCountHelper(artifactType.getTypeID(), obj_id);
	}

	/**
	 * Get all blackboard artifacts of a given type. Does not included rejected
	 * artifacts.
	 *
	 * @param artifactTypeName artifact type name
	 *
	 * @return list of blackboard artifacts
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public ArrayList<BlackboardArtifact> getBlackboardArtifacts(String artifactTypeName) throws TskCoreException {
		ArrayList<BlackboardArtifact> artifacts = new ArrayList<>();
		artifacts.addAll(blackboard.getArtifactsByType(getArtifactType(artifactTypeName)));
		return artifacts;
	}

	/**
	 * Get all blackboard artifacts of a given type. Does not included rejected
	 * artifacts.
	 *
	 * @param artifactType artifact type enum
	 *
	 * @return list of blackboard artifacts
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public ArrayList<BlackboardArtifact> getBlackboardArtifacts(ARTIFACT_TYPE artifactType) throws TskCoreException {
		ArrayList<BlackboardArtifact> artifacts = new ArrayList<>();
		artifacts.addAll(blackboard.getArtifactsByType(blackboard.getArtifactType(artifactType.getTypeID())));
		return artifacts;
	}

	/**
	 * Get all blackboard artifacts of a given type with an attribute of a given
	 * type and String value. Does not included rejected artifacts.
	 *
	 * @param artifactType artifact type enum
	 * @param attrType     attribute type enum
	 * @param value        String value of attribute
	 *
	 * @return list of blackboard artifacts
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 *
	 * @deprecated Do not use.
	 */
	@Deprecated
	public List<BlackboardArtifact> getBlackboardArtifacts(ARTIFACT_TYPE artifactType, BlackboardAttribute.ATTRIBUTE_TYPE attrType, String value) throws TskCoreException {

		String dataArtifactJoin = "tsk_data_artifacts AS datarts ON datarts.artifact_obj_id = arts.artifact_obj_id";
		String analysisResultJoin = "tsk_analysis_results AS anresult ON anresult.artifact_obj_id = arts.artifact_obj_id";
		String dataArtifactColumns = ", datarts.os_account_obj_id AS os_account_obj_id";
		String analysResultColumns = ", anresult.conclusion AS conclusion, anresult.significance AS significance, anresult.priority AS priority, anresult.configuration AS configuration, anresult.justification AS justification ";

		String formatQuery = "SELECT DISTINCT arts.artifact_id AS artifact_id, " //NON-NLS
				+ "arts.obj_id AS obj_id, arts.artifact_obj_id as artifact_obj_id, arts.data_source_obj_id AS data_source_obj_id, arts.artifact_type_id AS artifact_type_id, "
				+ "types.type_name AS type_name, types.display_name AS display_name,"
				+ "arts.review_status_id AS review_status_id %s "//NON-NLS
				+ "FROM blackboard_artifacts AS arts "
				+ "JOIN blackboard_attributes AS attrs ON arts.artifact_id = attrs.artifact_id "
				+ "JOIN blackboard_artifact_types AS types ON types.artifact_type_id = arts.artifact_type_id " //NON-NLS
				+ "LEFT JOIN %s "
				+ "WHERE arts.artifact_id = attrs.artifact_id " //NON-NLS
				+ "AND attrs.attribute_type_id = %d "
				+ " AND arts.artifact_type_id = %d "
				+ " AND attrs.value_text = '%s' " //NON-NLS
				+ " AND types.artifact_type_id=arts.artifact_type_id "
				+ " AND arts.review_status_id != %d";

		String query = String.format(formatQuery,
				(artifactType.getCategory() == BlackboardArtifact.Category.ANALYSIS_RESULT ? analysResultColumns : dataArtifactColumns),
				(artifactType.getCategory() == BlackboardArtifact.Category.ANALYSIS_RESULT ? analysisResultJoin : dataArtifactJoin),
				attrType.getTypeID(),
				artifactType.getTypeID(),
				value,
				BlackboardArtifact.ReviewStatus.REJECTED.getID());

		acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = connections.getConnection(); Statement s = connection.createStatement(); ResultSet rs = connection.executeQuery(s, query)) {
			ArrayList<BlackboardArtifact> artifacts = new ArrayList<>();
			while (rs.next()) {
				if (artifactType.getCategory() == BlackboardArtifact.Category.DATA_ARTIFACT) {
					Long osAccountObjId = rs.getLong("os_account_obj_id");
					if (rs.wasNull()) {
						osAccountObjId = null;
					}

					artifacts.add(new DataArtifact(this, rs.getLong("artifact_id"), rs.getLong("obj_id"),
							rs.getLong("artifact_obj_id"),
							rs.getObject("data_source_obj_id") != null ? rs.getLong("data_source_obj_id") : null,
							rs.getInt("artifact_type_id"), rs.getString("type_name"), rs.getString("display_name"),
							BlackboardArtifact.ReviewStatus.withID(rs.getInt("review_status_id")), osAccountObjId, false));
				} else {
					artifacts.add(new AnalysisResult(this, rs.getLong("artifact_id"), rs.getLong("obj_id"),
							rs.getLong("artifact_obj_id"),
							rs.getObject("data_source_obj_id") != null ? rs.getLong("data_source_obj_id") : null,
							rs.getInt("artifact_type_id"), rs.getString("type_name"), rs.getString("display_name"),
							BlackboardArtifact.ReviewStatus.withID(rs.getInt("review_status_id")),
							new Score(Score.Significance.fromID(rs.getInt("significance")), Score.Priority.fromID(rs.getInt("priority"))),
							rs.getString("conclusion"), rs.getString("configuration"), rs.getString("justification")));
				}
			}
			return artifacts;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifacts by artifact type and attribute. " + ex.getMessage(), ex);
		} finally {
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get the blackboard artifact with the given artifact id (artifact_id in
	 * blackboard_artifacts)
	 *
	 * @param artifactID artifact ID (artifact_id column)
	 *
	 * @return blackboard artifact
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public BlackboardArtifact getBlackboardArtifact(long artifactID) throws TskCoreException {
		List<DataArtifact> dataArtifacts = blackboard.getDataArtifactsWhere("artifacts.artifact_id = " + artifactID);
		if (!dataArtifacts.isEmpty()) {
			return dataArtifacts.get(0);
		}

		List<AnalysisResult> analysisResults = blackboard.getAnalysisResultsWhere("artifacts.artifact_id = " + artifactID);
		if (!analysisResults.isEmpty()) {
			return analysisResults.get(0);
		}

		throw new TskCoreException("No blackboard artifact with id " + artifactID);
	}

	/**
	 * Add a blackboard attribute.
	 *
	 * @param attr           A blackboard attribute.
	 * @param artifactTypeId The type of artifact associated with the attribute.
	 *
	 * @throws TskCoreException thrown if a critical error occurs.
	 */
	public void addBlackboardAttribute(BlackboardAttribute attr, int artifactTypeId) throws TskCoreException {
		acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = connections.getConnection();) {
			addBlackBoardAttribute(attr, artifactTypeId, connection);
		} catch (SQLException ex) {
			throw new TskCoreException("Error adding blackboard attribute " + attr.toString(), ex);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Add a set blackboard attributes.
	 *
	 * @param attributes     A set of blackboard attribute.
	 * @param artifactTypeId The type of artifact associated with the
	 *                       attributes.
	 *
	 * @throws TskCoreException thrown if a critical error occurs.
	 */
	public void addBlackboardAttributes(Collection<BlackboardAttribute> attributes, int artifactTypeId) throws TskCoreException {
		CaseDbConnection connection = null;
		acquireSingleUserCaseWriteLock();
		try {
			connection = connections.getConnection();
			connection.beginTransaction();
			for (final BlackboardAttribute attr : attributes) {
				addBlackBoardAttribute(attr, artifactTypeId, connection);
			}
			connection.commitTransaction();
		} catch (SQLException ex) {
			rollbackTransaction(connection);
			throw new TskCoreException("Error adding blackboard attributes", ex);
		} finally {
			closeConnection(connection);
			releaseSingleUserCaseWriteLock();
		}
	}

	void addBlackBoardAttribute(BlackboardAttribute attr, int artifactTypeId, CaseDbConnection connection) throws SQLException, TskCoreException {
		PreparedStatement statement;
		switch (attr.getAttributeType().getValueType()) {
			case STRING:
			case JSON:
				statement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_STRING_ATTRIBUTE);
				statement.clearParameters();
				statement.setString(7, attr.getValueString());
				break;
			case BYTE:
				statement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_BYTE_ATTRIBUTE);
				statement.clearParameters();
				statement.setBytes(7, attr.getValueBytes());
				break;
			case INTEGER:
				statement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_INT_ATTRIBUTE);
				statement.clearParameters();
				statement.setInt(7, attr.getValueInt());
				break;
			case LONG:
				statement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_LONG_ATTRIBUTE);
				statement.clearParameters();
				statement.setLong(7, attr.getValueLong());
				break;
			case DOUBLE:
				statement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_DOUBLE_ATTRIBUTE);
				statement.clearParameters();
				statement.setDouble(7, attr.getValueDouble());
				break;
			case DATETIME:
				statement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_LONG_ATTRIBUTE);
				statement.clearParameters();
				statement.setLong(7, attr.getValueLong());
				break;
			default:
				throw new TskCoreException("Unrecognized artifact attribute value type");
		}
		statement.setLong(1, attr.getArtifactID());
		statement.setInt(2, artifactTypeId);
		statement.setString(3, attr.getSourcesCSV());
		statement.setString(4, "");
		statement.setInt(5, attr.getAttributeType().getTypeID());
		statement.setLong(6, attr.getAttributeType().getValueType().getType());
		connection.executeUpdate(statement);
	}

	void addFileAttribute(Attribute attr, CaseDbConnection connection) throws SQLException, TskCoreException {
		PreparedStatement statement;
		statement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_FILE_ATTRIBUTE, Statement.RETURN_GENERATED_KEYS);
		statement.clearParameters();

		statement.setLong(1, attr.getAttributeParentId());
		statement.setInt(2, attr.getAttributeType().getTypeID());
		statement.setLong(3, attr.getAttributeType().getValueType().getType());

		if (attr.getAttributeType().getValueType() == TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE) {
			statement.setBytes(4, attr.getValueBytes());
		} else {
			statement.setBytes(4, null);
		}

		if (attr.getAttributeType().getValueType() == TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING
				|| attr.getAttributeType().getValueType() == TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.JSON) {
			statement.setString(5, attr.getValueString());
		} else {
			statement.setString(5, null);
		}
		if (attr.getAttributeType().getValueType() == TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER) {
			statement.setInt(6, attr.getValueInt());
		} else {
			statement.setNull(6, java.sql.Types.INTEGER);
		}

		if (attr.getAttributeType().getValueType() == TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME
				|| attr.getAttributeType().getValueType() == TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG) {
			statement.setLong(7, attr.getValueLong());
		} else {
			statement.setNull(7, java.sql.Types.BIGINT);
		}

		if (attr.getAttributeType().getValueType() == TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE) {
			statement.setDouble(8, attr.getValueDouble());
		} else {
			statement.setNull(8, java.sql.Types.DOUBLE);
		}

		connection.executeUpdate(statement);
		try (ResultSet resultSet = statement.getGeneratedKeys()) {
			if (!resultSet.next()) {
				throw new TskCoreException(String.format("Failed to insert file attribute "
						+ "with id=%d. The expected key was not generated", attr.getId()));
			}

			attr.setId(resultSet.getLong(1));
		}
	}

	/**
	 * Adds a source name to the source column of one or more rows in the
	 * blackboard attributes table. The source name will be added to a CSV list
	 * in any rows that exactly match the attribute's artifact_id and value.
	 *
	 * @param attr   The artifact attribute
	 * @param source The source name.
	 *
	 * @throws TskCoreException
	 */
	String addSourceToArtifactAttribute(BlackboardAttribute attr, String source) throws TskCoreException {
		/*
		 * WARNING: This is a temporary implementation that is not safe and
		 * denormalizes the case datbase.
		 *
		 * TODO (JIRA-2294): Provide a safe and normalized solution to tracking
		 * the sources of artifact attributes.
		 */
		if (null == source || source.isEmpty()) {
			throw new TskCoreException("Attempt to add null or empty source module name to artifact attribute");
		}
		CaseDbConnection connection = null;
		acquireSingleUserCaseWriteLock();
		Statement queryStmt = null;
		Statement updateStmt = null;
		ResultSet result = null;
		String newSources = "";
		try {
			connection = connections.getConnection();
			connection.beginTransaction();
			String valueClause = "";
			BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE valueType = attr.getAttributeType().getValueType();
			if (BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE != valueType) {
				switch (valueType) {
					case STRING:
					case JSON:
						valueClause = " value_text = '" + escapeSingleQuotes(attr.getValueString()) + "'";
						break;
					case INTEGER:
						valueClause = " value_int32 = " + attr.getValueInt();
						break;
					case LONG:
					case DATETIME:
						valueClause = " value_int64 = " + attr.getValueLong();
						break;
					case DOUBLE:
						valueClause = " value_double = " + attr.getValueDouble();
						break;
					default:
						throw new TskCoreException(String.format("Unrecognized value type for attribute %s", attr.getDisplayString()));
				}
				String query = "SELECT source FROM blackboard_attributes WHERE"
						+ " artifact_id = " + attr.getArtifactID()
						+ " AND attribute_type_id = " + attr.getAttributeType().getTypeID()
						+ " AND value_type = " + attr.getAttributeType().getValueType().getType()
						+ " AND " + valueClause + ";";
				queryStmt = connection.createStatement();
				updateStmt = connection.createStatement();
				result = connection.executeQuery(queryStmt, query);
			} else {
				/*
				 * SELECT source FROM blackboard_attributes WHERE artifact_id =
				 * ? AND attribute_type_id = ? AND value_type = 4 AND value_byte
				 * = ?
				 */
				PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_ATTR_BY_VALUE_BYTE);
				statement.clearParameters();
				statement.setLong(1, attr.getArtifactID());
				statement.setLong(2, attr.getAttributeType().getTypeID());
				statement.setBytes(3, attr.getValueBytes());
				result = connection.executeQuery(statement);
			}
			while (result.next()) {
				String oldSources = result.getString("source");
				if (null != oldSources && !oldSources.isEmpty()) {
					Set<String> uniqueSources = new HashSet<String>(Arrays.asList(oldSources.split(",")));
					if (!uniqueSources.contains(source)) {
						newSources = oldSources + "," + source;
					} else {
						newSources = oldSources;
					}
				} else {
					newSources = source;
				}
				if (BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE != valueType) {
					String update = "UPDATE blackboard_attributes SET source = '" + newSources + "' WHERE"
							+ " artifact_id = " + attr.getArtifactID()
							+ " AND attribute_type_id = " + attr.getAttributeType().getTypeID()
							+ " AND value_type = " + attr.getAttributeType().getValueType().getType()
							+ " AND " + valueClause + ";";
					connection.executeUpdate(updateStmt, update);
				} else {
					/*
					 * UPDATE blackboard_attributes SET source = ? WHERE
					 * artifact_id = ? AND attribute_type_id = ? AND value_type
					 * = 4 AND value_byte = ?
					 */
					PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.UPDATE_ATTR_BY_VALUE_BYTE);
					statement.clearParameters();
					statement.setString(1, newSources);
					statement.setLong(2, attr.getArtifactID());
					statement.setLong(3, attr.getAttributeType().getTypeID());
					statement.setBytes(4, attr.getValueBytes());
					connection.executeUpdate(statement);
				}
			}
			connection.commitTransaction();
			return newSources;
		} catch (SQLException ex) {
			rollbackTransaction(connection);
			throw new TskCoreException(String.format("Error adding source module to attribute %s", attr.getDisplayString()), ex);
		} finally {
			closeResultSet(result);
			closeStatement(updateStmt);
			closeStatement(queryStmt);
			closeConnection(connection);
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Add an attribute type with the given name
	 *
	 * @param attrTypeString Name of the new attribute
	 * @param valueType      The value type of this new attribute type
	 * @param displayName    The (non-unique) display name of the attribute type
	 *
	 * @return the id of the new attribute
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within tsk core
	 *
	 * @deprecated Use Blackboard.getOrAddAttributeType() instead.
	 */
	@Deprecated
	public BlackboardAttribute.Type addArtifactAttributeType(String attrTypeString, TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE valueType, String displayName) throws TskCoreException, TskDataException {
		try {
			return blackboard.getOrAddAttributeType(attrTypeString, valueType, displayName);
		} catch (BlackboardException ex) {
			throw new TskCoreException("Error adding artifact type: " + attrTypeString, ex);
		}
	}

	/**
	 * Get the attribute type associated with an attribute type name.
	 *
	 * @param attrTypeName An attribute type name.
	 *
	 * @return An attribute type or null if the attribute type does not exist.
	 *
	 * @throws TskCoreException If an error occurs accessing the case database.
	 *
	 * @deprecated Use Blackboard.getAttributeType instead
	 */
	@Deprecated
	public BlackboardAttribute.Type getAttributeType(String attrTypeName) throws TskCoreException {
		return blackboard.getAttributeType(attrTypeName);
	}

	/**
	 * Get the artifact type associated with an artifact type name.
	 *
	 * @param artTypeName An artifact type name.
	 *
	 * @return An artifact type or null if the artifact type does not exist.
	 *
	 * @throws TskCoreException If an error occurs accessing the case database.
	 *
	 * @deprecated Use Blackboard.getArtifactType instead
	 */
	@Deprecated
	public BlackboardArtifact.Type getArtifactType(String artTypeName) throws TskCoreException {
		return blackboard.getArtifactType(artTypeName);
	}

	/**
	 * Add an artifact type with the given name. Will return an artifact Type.
	 *
	 * This assumes that the artifact type being added has the category
	 * DATA_ARTIFACT.
	 *
	 * @param artifactTypeName System (unique) name of artifact
	 * @param displayName      Display (non-unique) name of artifact
	 *
	 * @return Type of the artifact added
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * @throws TskDataException exception thrown if given data is already in db
	 *                          within tsk core
	 * @deprecated Use Blackboard.getOrAddArtifactType() instead.
	 */
	@Deprecated
	public BlackboardArtifact.Type addBlackboardArtifactType(String artifactTypeName, String displayName) throws TskCoreException, TskDataException {
		return addBlackboardArtifactType(artifactTypeName, displayName, BlackboardArtifact.Category.DATA_ARTIFACT);
	}

	/**
	 * Add an artifact type with the given name and category. Will return an
	 * artifact Type.
	 *
	 * @param artifactTypeName System (unique) name of artifact
	 * @param displayName      Display (non-unique) name of artifact
	 * @param category		       Artifact type category.
	 *
	 *
	 * @return Type of the artifact added.
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * 
	 * @deprecated Use Blackboard.getOrAddArtifactType() instead.
	 */
	@Deprecated
	BlackboardArtifact.Type addBlackboardArtifactType(String artifactTypeName, String displayName, BlackboardArtifact.Category category) throws TskCoreException, TskDataException {
		try {
			return blackboard.getOrAddArtifactType(displayName, displayName, category);
		} catch (BlackboardException ex) {
			throw new TskCoreException("Error getting or adding artifact type with name: " + artifactTypeName, ex);
		}
	}
	
	/**
	 * Get the list of attributes for the given artifact.
	 * 
	 * @param artifact The artifact to load attributes for.
	 * 
	 * @return The list of attributes.
	 * 
	 * @throws TskCoreException 
	 * 
	 * @deprecated Use Blackboard.getBlackboardAttributes instead
	 */
	@Deprecated
	public ArrayList<BlackboardAttribute> getBlackboardAttributes(final BlackboardArtifact artifact) throws TskCoreException {
		return blackboard.getBlackboardAttributes(artifact);
	}


	/**
	 * Get all attributes that match a where clause. The clause should begin
	 * with "WHERE" or "JOIN". To use this method you must know the database
	 * tables
	 *
	 * @param whereClause a sqlite where clause
	 *
	 * @return a list of matching attributes
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within tsk core \ref query_database_page
	 */
	public ArrayList<BlackboardAttribute> getMatchingAttributes(String whereClause) throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT blackboard_attributes.artifact_id AS artifact_id, "
					+ "blackboard_attributes.source AS source, blackboard_attributes.context AS context, "
					+ "blackboard_attributes.attribute_type_id AS attribute_type_id, "
					+ "blackboard_attributes.value_type AS value_type, blackboard_attributes.value_byte AS value_byte, "
					+ "blackboard_attributes.value_text AS value_text, blackboard_attributes.value_int32 AS value_int32, "
					+ "blackboard_attributes.value_int64 AS value_int64, blackboard_attributes.value_double AS value_double "
					+ "FROM blackboard_attributes " + whereClause); //NON-NLS
			ArrayList<BlackboardAttribute> matches = new ArrayList<>();
			while (rs.next()) {
				BlackboardAttribute.Type type;
				// attribute type is cached, so this does not necessarily call to the db
				type = blackboard.getAttributeType(rs.getInt("attribute_type_id"));
				BlackboardAttribute attr = new BlackboardAttribute(
						rs.getLong("artifact_id"),
						type,
						rs.getString("source"),
						rs.getString("context"),
						rs.getInt("value_int32"),
						rs.getLong("value_int64"),
						rs.getDouble("value_double"),
						rs.getString("value_text"),
						rs.getBytes("value_byte"), this
				);
				matches.add(attr);
			}
			return matches;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting attributes using this where clause: " + whereClause, ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get all artifacts that match a where clause. The clause should begin with
	 * "WHERE" or "JOIN". To use this method you must know the database tables
	 *
	 * @param whereClause a sqlite where clause
	 *
	 * @return a list of matching artifacts
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within tsk core \ref query_database_page
	 */
	public ArrayList<BlackboardArtifact> getMatchingArtifacts(String whereClause) throws TskCoreException {
		String query = "SELECT blackboard_artifacts.artifact_id AS artifact_id, "
				+ "blackboard_artifacts.obj_id AS obj_id, blackboard_artifacts.artifact_obj_id AS artifact_obj_id, blackboard_artifacts.data_source_obj_id AS data_source_obj_id, blackboard_artifacts.artifact_type_id AS artifact_type_id, "
				+ "blackboard_artifacts.review_status_id AS review_status_id  "
				+ "FROM blackboard_artifacts " + whereClause;
		acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = connections.getConnection(); Statement statement = connection.createStatement(); ResultSet resultSet = statement.executeQuery(query)) {

			List<Long> analysisArtifactObjIds = new ArrayList<>();
			List<Long> dataArtifactObjIds = new ArrayList<>();
			while (resultSet.next()) {
				BlackboardArtifact.Type type = blackboard.getArtifactType(resultSet.getInt("artifact_type_id"));
				if (type.getCategory() == BlackboardArtifact.Category.ANALYSIS_RESULT) {
					analysisArtifactObjIds.add(resultSet.getLong("artifact_obj_id"));
				} else {
					dataArtifactObjIds.add(resultSet.getLong("artifact_obj_id"));
				}
			}

			ArrayList<BlackboardArtifact> matches = new ArrayList<>();
			if (!analysisArtifactObjIds.isEmpty()) {
				matches.addAll(getArtifactsForValues(BlackboardArtifact.Category.ANALYSIS_RESULT, "artifacts.artifact_obj_id", analysisArtifactObjIds, connection));
			}

			if (!dataArtifactObjIds.isEmpty()) {
				matches.addAll(getArtifactsForValues(BlackboardArtifact.Category.DATA_ARTIFACT, "artifacts.artifact_obj_id", dataArtifactObjIds, connection));
			}

			return matches;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting attributes using this where clause: " + whereClause, ex);
		} finally {
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Add a new blackboard artifact with the given type. If that artifact type
	 * does not exist an error will be thrown. The artifact type name can be
	 * looked up in the returned blackboard artifact.
	 *
	 * @param artifactTypeID the type the given artifact should have
	 * @param obj_id         the content object id associated with this artifact
	 *
	 * @return a new blackboard artifact
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within tsk core
	 * @deprecated Please use newDataArtifact or newAnalysisResult.
	 */
	@Deprecated
	public BlackboardArtifact newBlackboardArtifact(int artifactTypeID, long obj_id) throws TskCoreException {
		BlackboardArtifact.Type type = blackboard.getArtifactType(artifactTypeID);
		if (type == null) {
			throw new TskCoreException("Unknown artifact type for id: " + artifactTypeID);
		}

		Category category = type.getCategory();
		if (category == null) {
			throw new TskCoreException(String.format("No category for %s (id: %d)",
					type.getDisplayName() == null ? "<null>" : type.getDisplayName(),
					type.getTypeID()));
		}

		Content content = getContentById(obj_id);
		if (content == null) {
			throw new TskCoreException("No content found for object id: " + obj_id);
		}

		switch (category) {
			case ANALYSIS_RESULT:
				return content.newAnalysisResult(type, Score.SCORE_UNKNOWN, null, null, null, Collections.emptyList())
						.getAnalysisResult();
			case DATA_ARTIFACT:
				return content.newDataArtifact(type, Collections.emptyList());
			default:
				throw new TskCoreException("Unknown category type: " + category.getName());
		}
	}

	/**
	 * Add a new blackboard artifact with the given type.
	 *
	 * @param artifactType the type the given artifact should have
	 * @param obj_id       the content object id associated with this artifact
	 *
	 * @return a new blackboard artifact
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within tsk core
	 * @deprecated Please use newDataArtifact or newAnalysisResult.
	 */
	@Deprecated
	@SuppressWarnings("deprecation")
	public BlackboardArtifact newBlackboardArtifact(ARTIFACT_TYPE artifactType, long obj_id) throws TskCoreException {
		return newBlackboardArtifact(artifactType.getTypeID(), obj_id);
	}

	/**
	 * Add a new blackboard artifact with the given type.
	 *
	 * @param artifactType       the type the given artifact should have
	 * @param obj_id             the content object id associated with this
	 *                           artifact
	 * @param data_source_obj_id The data source obj id associated with this
	 *                           artifact
	 *
	 * @return a new blackboard artifact
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within tsk core
	 * @deprecated Please use newDataArtifact or newAnalysisResult.
	 */
	@Deprecated
	@SuppressWarnings("deprecation")
	BlackboardArtifact newBlackboardArtifact(int artifactTypeID, long obj_id, long data_source_obj_id) throws TskCoreException {
		BlackboardArtifact.Type type = blackboard.getArtifactType(artifactTypeID);
		try (CaseDbConnection connection = connections.getConnection()) {
			return newBlackboardArtifact(artifactTypeID, obj_id, type.getTypeName(), type.getDisplayName(), data_source_obj_id, connection);
		}
	}

	@Deprecated
	private BlackboardArtifact newBlackboardArtifact(int artifact_type_id, long obj_id, String artifactTypeName, String artifactDisplayName) throws TskCoreException {
		try (CaseDbConnection connection = connections.getConnection()) {
			long data_source_obj_id = getDataSourceObjectId(connection, obj_id);
			return this.newBlackboardArtifact(artifact_type_id, obj_id, artifactTypeName, artifactDisplayName, data_source_obj_id, connection);
		}
	}

	PreparedStatement createInsertArtifactStatement(int artifact_type_id, long obj_id, long artifact_obj_id, long data_source_obj_id, CaseDbConnection connection) throws TskCoreException, SQLException {

		PreparedStatement statement;
		if (dbType == DbType.POSTGRESQL) {
			statement = connection.getPreparedStatement(PREPARED_STATEMENT.POSTGRESQL_INSERT_ARTIFACT, Statement.RETURN_GENERATED_KEYS);
			statement.clearParameters();
			statement.setLong(1, obj_id);
			statement.setLong(2, artifact_obj_id);
			statement.setLong(3, data_source_obj_id);
			statement.setInt(4, artifact_type_id);
		} else {
			statement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_ARTIFACT, Statement.RETURN_GENERATED_KEYS);
			statement.clearParameters();
			this.nextArtifactId++;
			statement.setLong(1, this.nextArtifactId);
			statement.setLong(2, obj_id);
			statement.setLong(3, artifact_obj_id);
			statement.setLong(4, data_source_obj_id);
			statement.setInt(5, artifact_type_id);
		}

		return statement;
	}

	/**
	 * Add a new blackboard artifact with the given type.
	 *
	 * @param artifact_type_id    The type the given artifact should have.
	 * @param obj_id              The parent content id.
	 * @param artifactTypeName    The artifact type name.
	 * @param artifactDisplayName The artifact type display name.
	 * @param data_source_obj_id  The id of the artifact data source.
	 * @param connection          The CaseDBConnection.
	 *
	 * @return A new blackboard artifact.
	 *
	 * @throws TskCoreException
	 *
	 * @deprecated Use type specific methods in Blackboard.
	 */
	@Deprecated
	private BlackboardArtifact newBlackboardArtifact(int artifact_type_id, long obj_id, String artifactTypeName, String artifactDisplayName, long data_source_obj_id, CaseDbConnection connection) throws TskCoreException {
		BlackboardArtifact.Type type = blackboard.getArtifactType(artifact_type_id);
		try {
			if (type.getCategory() == BlackboardArtifact.Category.ANALYSIS_RESULT) {
				return blackboard.newAnalysisResult(type, obj_id, data_source_obj_id, Score.SCORE_UNKNOWN, null, null, null, Collections.emptyList()).getAnalysisResult();
			} else {
				return blackboard.newDataArtifact(type, obj_id, data_source_obj_id, Collections.emptyList(), null);
			}
		} catch (BlackboardException ex) {
			throw new TskCoreException("Error creating a blackboard artifact", ex);
		}
	}

	/**
	 * Creates a new analysis result by inserting a row in the artifacts table
	 * and a corresponding row in the tsk_analysis_results table.
	 *
	 * @param artifactType    Analysis result artifact type.
	 * @param objId           Object id of parent.
	 * @param dataSourceObjId Data source object id, may be null.
	 * @param score           Score.
	 * @param conclusion      Conclusion, may be null or an empty string.
	 * @param configuration   Configuration used by analysis, may be null or an
	 *                        empty string.
	 * @param justification   Justification, may be null or an empty string.
	 * @param connection      Database connection to use.
	 *
	 * @return Analysis result.
	 *
	 * @throws TskCoreException
	 */
	AnalysisResult newAnalysisResult(BlackboardArtifact.Type artifactType, long objId, Long dataSourceObjId, Score score, String conclusion, String configuration, String justification, CaseDbConnection connection) throws TskCoreException {

		if (artifactType.getCategory() != BlackboardArtifact.Category.ANALYSIS_RESULT) {
			throw new TskCoreException(String.format("Artifact type (name = %s) is not of the AnalysisResult category. ", artifactType.getTypeName()));
		}

		long artifactID;
		acquireSingleUserCaseWriteLock();
		try {
			// add a row in tsk_objects
			long artifactObjId = addObject(objId, TskData.ObjectType.ARTIFACT.getObjectType(), connection);

			// add a row in blackboard_artifacts table
			PreparedStatement insertArtifactstatement;
			ResultSet resultSet = null;
			try {
				insertArtifactstatement = createInsertArtifactStatement(artifactType.getTypeID(), objId, artifactObjId, dataSourceObjId, connection);
				connection.executeUpdate(insertArtifactstatement);
				resultSet = insertArtifactstatement.getGeneratedKeys();
				resultSet.next();
				artifactID = resultSet.getLong(1); //last_insert_rowid()

				// add a row in tsk_analysis_results if any data for it is set
				if (score.getSignificance() != Score.Significance.UNKNOWN
						|| !StringUtils.isBlank(conclusion)
						|| !StringUtils.isBlank(configuration)
						|| !StringUtils.isBlank(justification)) {

					PreparedStatement analysisResultsStatement;

					analysisResultsStatement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_ANALYSIS_RESULT);
					analysisResultsStatement.clearParameters();

					analysisResultsStatement.setLong(1, artifactObjId);
					analysisResultsStatement.setString(2, (conclusion != null) ? conclusion : "");
					analysisResultsStatement.setInt(3, score.getSignificance().getId());
					analysisResultsStatement.setInt(4, score.getPriority().getId());
					analysisResultsStatement.setString(5, (configuration != null) ? configuration : "");
					analysisResultsStatement.setString(6, (justification != null) ? justification : "");

					connection.executeUpdate(analysisResultsStatement);
				}

				return new AnalysisResult(this, artifactID, objId, artifactObjId, dataSourceObjId, artifactType.getTypeID(),
						artifactType.getTypeName(), artifactType.getDisplayName(),
						BlackboardArtifact.ReviewStatus.UNDECIDED, true,
						score, (conclusion != null) ? conclusion : "",
						(configuration != null) ? configuration : "", (justification != null) ? justification : "");

			} finally {
				closeResultSet(resultSet);
			}

		} catch (SQLException ex) {
			throw new TskCoreException("Error creating a analysis result", ex);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Checks if the content object has children. Note: this is generally more
	 * efficient then preloading all children and checking if the set is empty,
	 * and facilities lazy loading.
	 *
	 * @param content content object to check for children
	 *
	 * @return true if has children, false otherwise
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within tsk core
	 */
	boolean getContentHasChildren(Content content) throws TskCoreException {
		CaseDbConnection connection = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// SELECT COUNT(obj_id) AS count FROM tsk_objects WHERE par_obj_id = ?
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.COUNT_CHILD_OBJECTS_BY_PARENT);
			statement.clearParameters();
			statement.setLong(1, content.getId());
			rs = connection.executeQuery(statement);
			boolean hasChildren = false;
			if (rs.next()) {
				hasChildren = rs.getInt("count") > 0;
			}
			return hasChildren;
		} catch (SQLException e) {
			throw new TskCoreException("Error checking for children of parent " + content, e);
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Count of all content object's children. Note: this is generally more
	 * efficient then preloading all children and counting, and facilitates lazy
	 * loading.
	 *
	 * @param content content object to check for children count
	 *
	 * @return children count
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within tsk core
	 */
	int getContentChildrenCount(Content content) throws TskCoreException {

		if (!this.getHasChildren(content)) {
			return 0;
		}

		CaseDbConnection connection = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// SELECT COUNT(obj_id) AS count FROM tsk_objects WHERE par_obj_id = ?
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.COUNT_CHILD_OBJECTS_BY_PARENT);
			statement.clearParameters();
			statement.setLong(1, content.getId());
			rs = connection.executeQuery(statement);
			int countChildren = -1;
			if (rs.next()) {
				countChildren = rs.getInt("count");
			}
			return countChildren;
		} catch (SQLException e) {
			throw new TskCoreException("Error checking for children of parent " + content, e);
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Count of the content object's children of specified types. The types are
	 * instances of TskData.TSK_FS_NAME_TYPE_ENUM types and the matching is
	 * performed against the tsk_files.dir_type column. Some usage examples are
	 * to get a count of all subdirectories, which requires searching for all
	 * children of types TskData.TSK_FS_NAME_TYPE_ENUM.DIR OR
	 * TskData.TSK_FS_NAME_TYPE_ENUM.VIRT_DIR.
	 *
	 * Note: this is generally more efficient then preloading all children and
	 * counting, and facilitates lazy loading.
	 *
	 * @param content content object to check for children count
	 * @param types   List of TskData.TSK_FS_NAME_TYPE_ENUM types.
	 *
	 * @return Total count of children of the specified types.
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within tsk core
	 */
	int getAbstractFileChildrenCountByType(Content content, List<TSK_FS_NAME_TYPE_ENUM> types) throws TskCoreException {

		if (!this.getHasChildren(content)) {
			return 0;
		}

		if (types == null || types.isEmpty()) {
			return 0;
		}

		CaseDbConnection connection = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// Construct the IN clause dynamically
			StringBuilder inClause = new StringBuilder("?");
			for (int i = 1; i < types.size(); i++) {
				inClause.append(", ?");
			}

			String sql = "SELECT COUNT(*) AS count "
					+ "FROM tsk_objects "
					+ "INNER JOIN tsk_files ON tsk_objects.obj_id = tsk_files.obj_id "
					+ "WHERE (tsk_objects.par_obj_id = ? AND tsk_files.dir_type IN (" + inClause.toString() + "))";

			PreparedStatement statement = connection.getConnection().prepareStatement(sql);
			statement.clearParameters();
			statement.setLong(1, content.getId());

			for (int i = 0; i < types.size(); i++) {
				statement.setInt(i + 2, types.get(i).getValue()); // Note: i+2 because index 1 is already taken by obj_id
			}

			rs = connection.executeQuery(statement);
			int countChildren = -1;
			if (rs.next()) {
				countChildren = rs.getInt("count");
			}
			return countChildren;
		} catch (SQLException e) {
			throw new TskCoreException("Error checking for children of parent " + content, e);
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Returns the list of AbstractFile Children of a given type for a given
	 * AbstractFileParent
	 *
	 * @param parent the content parent to get abstract file children for
	 * @param type   children type to look for, defined in
	 *               TSK_DB_FILES_TYPE_ENUM
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within tsk core
	 */
	List<Content> getAbstractFileChildren(Content parent, TSK_DB_FILES_TYPE_ENUM type) throws TskCoreException {
		CaseDbConnection connection = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_FILES_BY_PARENT_AND_TYPE);
			statement.clearParameters();
			long parentId = parent.getId();
			statement.setLong(1, parentId);
			statement.setShort(2, type.getFileType());
			rs = connection.executeQuery(statement);
			return fileChildren(rs, connection, parentId);
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting AbstractFile children for Content", ex);
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Returns the list of all AbstractFile Children for a given
	 * AbstractFileParent
	 *
	 * @param parent the content parent to get abstract file children for
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within tsk core
	 */
	List<Content> getAbstractFileChildren(Content parent) throws TskCoreException {
		CaseDbConnection connection = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_FILES_BY_PARENT);
			statement.clearParameters();
			long parentId = parent.getId();
			statement.setLong(1, parentId);
			rs = connection.executeQuery(statement);
			return fileChildren(rs, connection, parentId);
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting AbstractFile children for Content", ex);
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get list of IDs for abstract files of a given type that are children of a
	 * given content.
	 *
	 * @param parent Object to find children for
	 * @param type   Type of children to find IDs for
	 *
	 * @return
	 *
	 * @throws TskCoreException
	 */
	List<Long> getAbstractFileChildrenIds(Content parent, TSK_DB_FILES_TYPE_ENUM type) throws TskCoreException {
		CaseDbConnection connection = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_FILE_IDS_BY_PARENT_AND_TYPE);
			statement.clearParameters();
			statement.setLong(1, parent.getId());
			statement.setShort(2, type.getFileType());
			rs = connection.executeQuery(statement);
			List<Long> children = new ArrayList<Long>();
			while (rs.next()) {
				children.add(rs.getLong("obj_id"));
			}
			return children;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting AbstractFile children for Content", ex);
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get list of IDs for abstract files that are children of a given content.
	 *
	 * @param parent Object to find children for
	 *
	 * @return
	 *
	 * @throws TskCoreException
	 */
	List<Long> getAbstractFileChildrenIds(Content parent) throws TskCoreException {
		CaseDbConnection connection = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_FILE_IDS_BY_PARENT);
			statement.clearParameters();
			statement.setLong(1, parent.getId());
			rs = connection.executeQuery(statement);
			List<Long> children = new ArrayList<Long>();
			while (rs.next()) {
				children.add(rs.getLong("obj_id"));
			}
			return children;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting AbstractFile children for Content", ex);
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get list of object IDs for artifacts that are children of a given
	 * content.
	 *
	 * @param parent Object to find children for
	 *
	 * @return
	 *
	 * @throws TskCoreException
	 */
	List<Long> getBlackboardArtifactChildrenIds(Content parent) throws TskCoreException {
		CaseDbConnection connection = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_ARTIFACT_OBJECTIDS_BY_PARENT);
			statement.clearParameters();
			statement.setLong(1, parent.getId());
			rs = connection.executeQuery(statement);
			List<Long> children = new ArrayList<Long>();
			while (rs.next()) {
				children.add(rs.getLong("obj_id"));
			}
			return children;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting children for BlackboardArtifact", ex);
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get list of artifacts that are children of a given content.
	 *
	 * @param parent Object to find children for
	 *
	 * @return
	 *
	 * @throws TskCoreException
	 */
	List<Content> getBlackboardArtifactChildren(Content parent) throws TskCoreException {
		long parentId = parent.getId();
		List<Content> lc = new ArrayList<>();
		lc.addAll(blackboard.getAnalysisResults(parentId));
		lc.addAll(blackboard.getDataArtifactsBySource(parentId));
		return lc;
	}

	/**
	 * Get info about children of a given Content from the database.
	 *
	 * @param c Parent object to run query against
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within tsk core
	 */
	Collection<ObjectInfo> getChildrenInfo(Content c) throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT tsk_objects.obj_id AS obj_id, tsk_objects.type AS type " //NON-NLS
					+ "FROM tsk_objects LEFT JOIN tsk_files " //NON-NLS
					+ "ON tsk_objects.obj_id = tsk_files.obj_id " //NON-NLS
					+ "WHERE tsk_objects.par_obj_id = " + c.getId()
					+ " ORDER BY tsk_objects.obj_id"); //NON-NLS
			Collection<ObjectInfo> infos = new ArrayList<ObjectInfo>();
			while (rs.next()) {
				infos.add(new ObjectInfo(rs.getLong("obj_id"), ObjectType.valueOf(rs.getShort("type")))); //NON-NLS
			}
			return infos;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Children Info for Content", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get parent info for the parent of the content object
	 *
	 * @param c content object to get parent info for
	 *
	 * @return the parent object info with the parent object type and id
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within tsk core
	 */
	ObjectInfo getParentInfo(Content c) throws TskCoreException {
		return getParentInfo(c.getId());
	}

	/**
	 * Get parent info for the parent of the content object id
	 *
	 * @param id content object id to get parent info for
	 *
	 * @return the parent object info with the parent object type and id
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within tsk core
	 */
	ObjectInfo getParentInfo(long contentId) throws TskCoreException {
		acquireSingleUserCaseReadLock();
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT parent.obj_id AS obj_id, parent.type AS type " //NON-NLS
					+ "FROM tsk_objects AS parent INNER JOIN tsk_objects AS child " //NON-NLS
					+ "ON child.par_obj_id = parent.obj_id " //NON-NLS
					+ "WHERE child.obj_id = " + contentId); //NON-NLS
			if (rs.next()) {
				return new ObjectInfo(rs.getLong("obj_id"), ObjectType.valueOf(rs.getShort("type")));
			} else {
				return null;
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Parent Info for Content: " + contentId, ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Gets parent directory for FsContent object
	 *
	 * @param fsc FsContent to get parent dir for
	 *
	 * @return the parent Directory or null if the Content has no parent
	 *
	 * @throws TskCoreException thrown if critical error occurred within tsk
	 *                          core
	 */
	Directory getParentDirectory(FsContent fsc) throws TskCoreException {
		if (fsc.isRoot()) {
			// Given FsContent is a root object and can't have parent directory
			return null;
		} else {
			ObjectInfo parentInfo = getParentInfo(fsc);
			if (parentInfo == null) {
				return null;
			}
			Directory parent = null;
			if (parentInfo.type == ObjectType.ABSTRACTFILE) {
				parent = getDirectoryById(parentInfo.id, fsc.getFileSystem());
			} else {
				throw new TskCoreException("Parent of FsContent (id: " + fsc.getId() + ") has wrong type to be directory: " + parentInfo.type);
			}
			return parent;
		}
	}

	/**
	 * Get content object by content id
	 *
	 * @param id to get content object for
	 *
	 * @return instance of a Content object (one of its subclasses), or null if
	 *         not found.
	 *
	 * @throws TskCoreException thrown if critical error occurred within tsk
	 *                          core
	 */
	public Content getContentById(long id) throws TskCoreException {
		// First check to see if this exists in our frequently used content cache.
		Content content = frequentlyUsedContentMap.get(id);
		if (null != content) {
			return content;
		}

		long parentId;
		TskData.ObjectType type;

		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT * FROM tsk_objects WHERE obj_id = " + id + " LIMIT  1"); //NON-NLS
			if (!rs.next()) {
				return null;
			}
			parentId = rs.getLong("par_obj_id"); //NON-NLS
			type = TskData.ObjectType.valueOf(rs.getShort("type")); //NON-NLS
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Content by ID.", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}

		// Construct the object
		switch (type) {
			case IMG:
				content = getImageById(id);
				frequentlyUsedContentMap.put(id, content);
				break;
			case VS:
				content = getVolumeSystemById(id, parentId);
				break;
			case VOL:
				content = getVolumeById(id, parentId);
				frequentlyUsedContentMap.put(id, content);
				break;
			case POOL:
				content = getPoolById(id, parentId);
				break;
			case FS:
				content = getFileSystemById(id, parentId);
				frequentlyUsedContentMap.put(id, content);
				break;
			case ABSTRACTFILE:
				content = getAbstractFileById(id);

				// Add virtual and root directories to frequently used map.
				// Calling isRoot() on local directories goes up the entire directory structure
				// and they can only be the root of portable cases, so skip trying to add
				// them to the cache.
				if (((AbstractFile) content).isVirtual()
						|| ((!(content instanceof LocalDirectory)) && ((AbstractFile) content).isRoot())) {
					frequentlyUsedContentMap.put(id, content);
				}
				break;
			case ARTIFACT:
				content = getArtifactById(id);
				break;
			case REPORT:
				content = getReportById(id);
				break;
			case OS_ACCOUNT:
				content = this.osAccountManager.getOsAccountByObjectId(id);
				break;
			case HOST_ADDRESS:
				content = hostAddressManager.getHostAddress(id);
				break;
			default:
				content = new UnsupportedContent(this, id);
		}

		return content;
	}

	/**
	 * Get a path of a file in tsk_files_path table or null if there is none
	 *
	 * @param id id of the file to get path for
	 *
	 * @return file path or null
	 */
	String getFilePath(long id) {

		String filePath = null;
		CaseDbConnection connection = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_LOCAL_PATH_FOR_FILE);
			statement.clearParameters();
			statement.setLong(1, id);
			rs = connection.executeQuery(statement);
			if (rs.next()) {
				filePath = rs.getString("path");
			}
		} catch (SQLException | TskCoreException ex) {
			logger.log(Level.SEVERE, "Error getting file path for file " + id, ex); //NON-NLS
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
		return filePath;
	}

	/**
	 * Get the encoding type for a file in tsk_files_path table
	 *
	 * @param id id of the file to get path for
	 *
	 * @return Encoding type (NONE if nothing was found)
	 */
	TskData.EncodingType getEncodingType(long id) {

		TskData.EncodingType type = TskData.EncodingType.NONE;
		CaseDbConnection connection = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_ENCODING_FOR_FILE);
			statement.clearParameters();
			statement.setLong(1, id);
			rs = connection.executeQuery(statement);
			if (rs.next()) {
				type = TskData.EncodingType.valueOf(rs.getInt(1));
			}
		} catch (SQLException | TskCoreException ex) {
			logger.log(Level.SEVERE, "Error getting encoding type for file " + id, ex); //NON-NLS
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
		return type;
	}

	/**
	 * Gets the parent_path of a file.
	 *
	 * @param objectId   The object id of the file.
	 * @param connection An open database connection.
	 *
	 * @return The path of the file or null.
	 */
	String getFileParentPath(long objectId, CaseDbConnection connection) {
		String parentPath = null;
		acquireSingleUserCaseReadLock();
		ResultSet rs = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_PATH_FOR_FILE);
			statement.clearParameters();
			statement.setLong(1, objectId);
			rs = connection.executeQuery(statement);
			if (rs.next()) {
				parentPath = rs.getString("parent_path");
			}
		} catch (SQLException ex) {
			logger.log(Level.SEVERE, "Error getting file parent_path for file " + objectId, ex); //NON-NLS
		} finally {
			closeResultSet(rs);
			releaseSingleUserCaseReadLock();
		}
		return parentPath;
	}

	/**
	 * Gets the name of a file.
	 *
	 * @param objectId   The object id of the file.
	 * @param connection An open database connection.
	 *
	 * @return The path of the file or null.
	 */
	String getFileName(long objectId, CaseDbConnection connection) {
		String fileName = null;
		acquireSingleUserCaseReadLock();
		ResultSet rs = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_FILE_NAME);
			statement.clearParameters();
			statement.setLong(1, objectId);
			rs = connection.executeQuery(statement);
			if (rs.next()) {
				fileName = rs.getString("name");
			}
		} catch (SQLException ex) {
			logger.log(Level.SEVERE, "Error getting file parent_path for file " + objectId, ex); //NON-NLS
		} finally {
			closeResultSet(rs);
			releaseSingleUserCaseReadLock();
		}
		return fileName;
	}

	/**
	 * Get a derived method for a file, or null if none
	 *
	 * @param id id of the derived file
	 *
	 * @return derived method or null if not present
	 *
	 * @throws TskCoreException exception throws if core error occurred and
	 *                          method could not be queried
	 */
	DerivedFile.DerivedMethod getDerivedMethod(long id) throws TskCoreException {

		DerivedFile.DerivedMethod method = null;
		CaseDbConnection connection = null;
		ResultSet rs1 = null;
		ResultSet rs2 = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_DERIVED_FILE);
			statement.clearParameters();
			statement.setLong(1, id);
			rs1 = connection.executeQuery(statement);
			if (rs1.next()) {
				int method_id = rs1.getInt("derived_id");
				String rederive = rs1.getString("rederive");
				method = new DerivedFile.DerivedMethod(method_id, rederive);
				statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_FILE_DERIVATION_METHOD);
				statement.clearParameters();
				statement.setInt(1, method_id);
				rs2 = connection.executeQuery(statement);
				if (rs2.next()) {
					method.setToolName(rs2.getString("tool_name"));
					method.setToolVersion(rs2.getString("tool_version"));
					method.setOther(rs2.getString("other"));
				}
			}
		} catch (SQLException e) {
			logger.log(Level.SEVERE, "Error getting derived method for file: " + id, e); //NON-NLS
		} finally {
			closeResultSet(rs2);
			closeResultSet(rs1);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
		return method;
	}

	/**
	 * Get abstract file object from tsk_files table by its id
	 *
	 * @param id id of the file object in tsk_files table
	 *
	 * @return AbstractFile object populated, or null if not found.
	 *
	 * @throws TskCoreException thrown if critical error occurred within tsk
	 *                          core and file could not be queried
	 */
	public AbstractFile getAbstractFileById(long id) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		try {
			return getAbstractFileById(id, connection);
		} finally {
			closeConnection(connection);
		}
	}

	/**
	 * Get abstract file object from tsk_files table by its id on an existing
	 * connection.
	 *
	 * @param objectId   The id of the file object in tsk_files table.
	 * @param connection An open database connection.
	 *
	 * @return AbstractFile object populated, or null if not found.
	 *
	 * @throws TskCoreException thrown if critical error occurred within tsk
	 *                          core and file could not be queried
	 */
	AbstractFile getAbstractFileById(long objectId, CaseDbConnection connection) throws TskCoreException {
		acquireSingleUserCaseReadLock();
		ResultSet rs = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_FILE_BY_ID);
			statement.clearParameters();
			statement.setLong(1, objectId);
			rs = connection.executeQuery(statement);
			List<AbstractFile> files = resultSetToAbstractFiles(rs, connection);
			if (files.size() > 0) {
				return files.get(0);
			} else {
				return null;
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting file by id, id = " + objectId, ex);
		} finally {
			closeResultSet(rs);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get artifact from blackboard_artifacts table by its artifact_obj_id
	 *
	 * @param id id of the artifact in blackboard_artifacts table
	 *           (artifact_obj_id column)
	 *
	 * @return Artifact object populated, or null if not found.
	 *
	 * @throws TskCoreException thrown if critical error occurred within tsk
	 *                          core and file could not be queried
	 */
	public BlackboardArtifact getArtifactById(long id) throws TskCoreException {

		CaseDbConnection connection = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// get the artifact type.
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_ARTIFACT_TYPE_BY_ARTIFACT_OBJ_ID);
			statement.clearParameters();
			statement.setLong(1, id);

			rs = connection.executeQuery(statement);
			if (!rs.next()) {
				throw new TskCoreException("Error getting artifacttype for artifact with artifact_obj_id = " + id);
			}

			// based on the artifact type category, get the analysis result or the data artifact
			BlackboardArtifact.Type artifactType = blackboard.getArtifactType(rs.getInt("artifact_type_id"));
			switch (artifactType.getCategory()) {
				case ANALYSIS_RESULT:
					return blackboard.getAnalysisResultById(id);
				case DATA_ARTIFACT:
					return blackboard.getDataArtifactById(id);
				default:
					throw new TskCoreException(String.format("Unknown artifact category for artifact with artifact_obj_id = %d, and artifact type = %s", id, artifactType.getTypeName()));
			}

		} catch (SQLException ex) {
			throw new TskCoreException("Error getting artifacts by artifact_obj_id, artifact_obj_id = " + id, ex);
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get artifact from blackboard_artifacts table by its artifact_id
	 *
	 * @param id Artifact ID of the artifact in blackboard_artifacts table
	 *
	 * @return Artifact object populated, or null if not found.
	 *
	 * @throws TskCoreException thrown if critical error occurred within tsk
	 *                          core and file could not be queried
	 *
	 * @deprecated	Use the type specific methods in Blackboard
	 * getAnalysisResultsById and getDataArtifactById
	 */
	@Deprecated
	public BlackboardArtifact getArtifactByArtifactId(long id) throws TskCoreException {
		String query = "SELECT artifact_type_id, artifact_obj_id FROM blackboard_artifacts WHERE artifact_id = " + id;
		acquireSingleUserCaseReadLock();

		try (CaseDbConnection connection = connections.getConnection();
				Statement statement = connection.createStatement();
				ResultSet resultSet = statement.executeQuery(query);) {
			if (resultSet != null && resultSet.next()) {
				BlackboardArtifact.Type artifactType = blackboard.getArtifactType(resultSet.getInt("artifact_type_id"));
				long artifactObjId = resultSet.getLong("artifact_obj_id");
				switch (artifactType.getCategory()) {
					case ANALYSIS_RESULT:
						return blackboard.getAnalysisResultById(artifactObjId);
					case DATA_ARTIFACT:
						return blackboard.getDataArtifactById(artifactObjId);
				}
			}
			return null;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting artifacts by artifact id, artifact id = " + id, ex);
		} finally {
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get the object ID of the file system that a file is located in.
	 *
	 * Note: for FsContent files, this is the real fs for other non-fs
	 * AbstractFile files, this field is used internally for data source id (the
	 * root content obj)
	 *
	 * @param fileId     object id of the file to get fs column id for
	 * @param connection the database connection to use
	 *
	 * @return fs_id or -1 if not present
	 */
	private long getFileSystemId(long fileId, CaseDbConnection connection) {
		acquireSingleUserCaseReadLock();
		ResultSet rs = null;
		long ret = -1;
		try {
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_FILE_SYSTEM_BY_OBJECT);
			statement.clearParameters();
			statement.setLong(1, fileId);
			rs = connection.executeQuery(statement);
			if (rs.next()) {
				ret = rs.getLong("fs_obj_id");
				if (ret == 0) {
					ret = -1;
				}
			}
		} catch (SQLException e) {
			logger.log(Level.SEVERE, "Error checking file system id of a file, id = " + fileId, e); //NON-NLS
		} finally {
			closeResultSet(rs);
			releaseSingleUserCaseReadLock();
		}
		return ret;
	}

	/**
	 * Checks if the file is a (sub)child of the data source (parentless Content
	 * object such as Image or VirtualDirectory representing filesets)
	 *
	 * @param dataSource dataSource to check
	 * @param fileId     id of file to check
	 *
	 * @return true if the file is in the dataSource hierarchy
	 *
	 * @throws TskCoreException thrown if check failed
	 */
	public boolean isFileFromSource(Content dataSource, long fileId) throws TskCoreException {
		String query = String.format("SELECT COUNT(*) AS count FROM tsk_files WHERE obj_id = %d AND data_source_obj_id = %d", fileId, dataSource.getId()); //NON-NLS
		CaseDbConnection connection = null;
		Statement statement = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			statement = connection.createStatement();
			resultSet = connection.executeQuery(statement, query);
			resultSet.next();
			return (resultSet.getLong("count") > 0L);
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error executing query %s", query), ex);
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Returns true if the string contains a SQL LIKE statement wild card based
	 * on https://www.postgresql.org/docs/9.5/functions-matching.html and
	 * https://sqlite.org/lang_expr.html#the_like_glob_regexp_and_match_operators.
	 *
	 * @param str The string.
	 *
	 * @return True if it contains a LIKE wild card.
	 */
	private static boolean containsLikeWildcard(String str) {
		if (str == null) {
			return false;
		} else {
			return str.contains("%") || str.contains("_");
		}
	}

	/**
	 * @param dataSource the dataSource (Image, parent-less VirtualDirectory) to
	 *                   search for the given file name
	 * @param fileName   Pattern of the name of the file or directory to match
	 *                   (case insensitive, used in LIKE SQL statement).
	 *
	 * @return a list of AbstractFile for files/directories whose name matches
	 *         the given fileName
	 *
	 * @throws TskCoreException thrown if check failed
	 */
	public List<AbstractFile> findFiles(Content dataSource, String fileName) throws TskCoreException {
		String ext = "";
		if (!containsLikeWildcard(fileName)) {
			ext = SleuthkitCase.extractExtension(fileName);
		}

		List<AbstractFile> files = new ArrayList<>();
		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			PreparedStatement statement;
			if (ext.isEmpty()) {
				statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_FILES_BY_DATA_SOURCE_AND_NAME);
				statement.clearParameters();
				statement.setString(1, fileName.toLowerCase());
				statement.setLong(2, dataSource.getId());
			} else {
				statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_FILES_BY_EXTENSION_AND_DATA_SOURCE_AND_NAME);
				statement.clearParameters();
				statement.setString(1, ext);
				statement.setString(2, fileName.toLowerCase());
				statement.setLong(3, dataSource.getId());
			}

			resultSet = connection.executeQuery(statement);
			files.addAll(resultSetToAbstractFiles(resultSet, connection));
		} catch (SQLException e) {
			throw new TskCoreException(bundle.getString("SleuthkitCase.findFiles.exception.msg3.text"), e);
		} finally {
			closeResultSet(resultSet);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
		return files;
	}

	/**
	 * @param dataSource   the dataSource (Image, parent-less VirtualDirectory)
	 *                     to search for the given file name
	 * @param fileName     Pattern of the name of the file or directory to match
	 *                     (case insensitive, used in LIKE SQL statement).
	 * @param dirSubString Substring that must exist in parent path. Will be
	 *                     surrounded by % in LIKE query
	 *
	 * @return a list of AbstractFile for files/directories whose name matches
	 *         fileName and whose parent directory contains dirName.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public List<AbstractFile> findFiles(Content dataSource, String fileName, String dirSubString) throws TskCoreException {
		String ext = "";
		if (!containsLikeWildcard(fileName)) {
			ext = SleuthkitCase.extractExtension(fileName);
		}

		List<AbstractFile> files = new ArrayList<>();
		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			PreparedStatement statement;
			if (ext.isEmpty()) {
				statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_FILES_BY_DATA_SOURCE_AND_PARENT_PATH_AND_NAME);
				statement.clearParameters();
				statement.setString(1, fileName.toLowerCase());
				statement.setString(2, "%" + dirSubString.toLowerCase() + "%"); //NON-NLS
				statement.setLong(3, dataSource.getId());
			} else {
				statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_FILES_BY_EXTENSION_AND_DATA_SOURCE_AND_PARENT_PATH_AND_NAME);
				statement.clearParameters();
				statement.setString(1, ext);
				statement.setString(2, fileName.toLowerCase());
				statement.setString(3, "%" + dirSubString.toLowerCase() + "%"); //NON-NLS
				statement.setLong(4, dataSource.getId());
			}

			resultSet = connection.executeQuery(statement);
			files.addAll(resultSetToAbstractFiles(resultSet, connection));
		} catch (SQLException e) {
			throw new TskCoreException(bundle.getString("SleuthkitCase.findFiles3.exception.msg3.text"), e);
		} finally {
			closeResultSet(resultSet);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
		return files;
	}

	/**
	 * Adds a virtual directory to the database and returns a VirtualDirectory
	 * object representing it.
	 *
	 * @param parentId      the ID of the parent, or 0 if NULL
	 * @param directoryName the name of the virtual directory to create
	 *
	 * @return
	 *
	 * @throws TskCoreException
	 */
	public VirtualDirectory addVirtualDirectory(long parentId, String directoryName) throws TskCoreException {
		CaseDbTransaction localTrans = beginTransaction();
		try {
			VirtualDirectory newVD = addVirtualDirectory(parentId, directoryName, localTrans);
			localTrans.commit();
			localTrans = null;
			return newVD;
		} finally {
			if (null != localTrans) {
				try {
					localTrans.rollback();
				} catch (TskCoreException ex2) {
					logger.log(Level.SEVERE, "Failed to rollback transaction after exception", ex2);
				}
			}
		}
	}

	/**
	 * Add an object to the tsk_objects table. Returns the object ID for the new
	 * object.
	 *
	 * @param parentId   Parent of the new object
	 * @param objectType Type of the new object
	 * @param connection Case connection
	 *
	 * @return the object ID for the new object
	 *
	 * @throws SQLException
	 */
	long addObject(long parentId, int objectType, CaseDbConnection connection) throws SQLException {
		ResultSet resultSet = null;
		acquireSingleUserCaseWriteLock();
		try {
			// INSERT INTO tsk_objects (par_obj_id, type) VALUES (?, ?)
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_OBJECT, Statement.RETURN_GENERATED_KEYS);
			statement.clearParameters();
			if (parentId != 0) {
				statement.setLong(1, parentId);
			} else {
				statement.setNull(1, java.sql.Types.BIGINT);
			}
			statement.setInt(2, objectType);
			connection.executeUpdate(statement);
			resultSet = statement.getGeneratedKeys();

			if (resultSet.next()) {
				if (parentId != 0) {
					setHasChildren(parentId);
				}
				return resultSet.getLong(1); //last_insert_rowid()
			} else {
				throw new SQLException("Error inserting object with parent " + parentId + " into tsk_objects");
			}
		} finally {
			closeResultSet(resultSet);
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Adds a virtual directory to the database and returns a VirtualDirectory
	 * object representing it.
	 *
	 * Make sure the connection in transaction is used for all database
	 * interactions called by this method
	 *
	 * @param parentId      the ID of the parent, or 0 if NULL
	 * @param directoryName the name of the virtual directory to create
	 * @param transaction   the transaction in the scope of which the operation
	 *                      is to be performed, managed by the caller
	 *
	 * @return a VirtualDirectory object representing the one added to the
	 *         database.
	 *
	 * @throws TskCoreException
	 */
	public VirtualDirectory addVirtualDirectory(long parentId, String directoryName, CaseDbTransaction transaction) throws TskCoreException {
		if (transaction == null) {
			throw new TskCoreException("Passed null CaseDbTransaction");
		}

		ResultSet resultSet = null;
		try {
			// Get the parent path.
			CaseDbConnection connection = transaction.getConnection();

			String parentPath;
			Content parent = this.getAbstractFileById(parentId, connection);
			if (parent instanceof AbstractFile) {
				if (isRootDirectory((AbstractFile) parent, transaction)) {
					if (parent.getName().isEmpty()) {
						parentPath = "/";
					} else {
						parentPath = "/" + parent.getName() + "/";
					}
				} else {
					parentPath = ((AbstractFile) parent).getParentPath() + parent.getName() + "/"; //NON-NLS
				}
			} else {
				// The parent was either null or not an abstract file
				parentPath = "/";
			}

			// Insert a row for the virtual directory into the tsk_objects table.
			long newObjId = addObject(parentId, TskData.ObjectType.ABSTRACTFILE.getObjectType(), connection);

			// Insert a row for the virtual directory into the tsk_files table.
			// INSERT INTO tsk_files (obj_id, fs_obj_id, name, type, has_path, dir_type, meta_type,
			// dir_flags, meta_flags, size, ctime, crtime, atime, mtime, md5, sha256, sha1, known, mime_type, parent_path, data_source_obj_id,extension,owner_uid, os_account_obj_id)
			// VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?,?,?,?)
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_FILE);
			statement.clearParameters();
			statement.setLong(1, newObjId);

			// If the parent is part of a file system, grab its file system ID
			Long fileSystemObjectId = null;
			if (0 != parentId) {
				fileSystemObjectId = this.getFileSystemId(parentId, connection);
				if (fileSystemObjectId != -1) {
					statement.setLong(2, fileSystemObjectId);
				} else {
					statement.setNull(2, java.sql.Types.BIGINT);
					fileSystemObjectId = null;
				}
			} else {
				statement.setNull(2, java.sql.Types.BIGINT);
			}

			// name
			statement.setString(3, directoryName);

			//type
			statement.setShort(4, TskData.TSK_DB_FILES_TYPE_ENUM.VIRTUAL_DIR.getFileType());
			statement.setShort(5, (short) 1);

			//flags
			final TSK_FS_NAME_TYPE_ENUM dirType = TSK_FS_NAME_TYPE_ENUM.DIR;
			statement.setShort(6, dirType.getValue());
			final TSK_FS_META_TYPE_ENUM metaType = TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR;
			statement.setShort(7, metaType.getValue());

			//allocated
			final TSK_FS_NAME_FLAG_ENUM dirFlag = TSK_FS_NAME_FLAG_ENUM.ALLOC;
			statement.setShort(8, dirFlag.getValue());
			final short metaFlags = (short) (TSK_FS_META_FLAG_ENUM.ALLOC.getValue()
					| TSK_FS_META_FLAG_ENUM.USED.getValue());
			statement.setShort(9, metaFlags);

			//size
			statement.setLong(10, 0);

			//  nulls for params 11-14
			statement.setNull(11, java.sql.Types.BIGINT);
			statement.setNull(12, java.sql.Types.BIGINT);
			statement.setNull(13, java.sql.Types.BIGINT);
			statement.setNull(14, java.sql.Types.BIGINT);

			statement.setNull(15, java.sql.Types.VARCHAR); // MD5
			statement.setNull(16, java.sql.Types.VARCHAR); // SHA-256
			statement.setNull(17, java.sql.Types.VARCHAR); // SHA-1
			
			statement.setByte(18, FileKnown.UNKNOWN.getFileKnownValue()); // Known
			statement.setNull(19, java.sql.Types.VARCHAR); // MIME type	

			// parent path
			statement.setString(20, parentPath);

			// data source object id (same as object id if this is a data source)
			long dataSourceObjectId;
			if (0 == parentId) {
				dataSourceObjectId = newObjId;
			} else {
				dataSourceObjectId = getDataSourceObjectId(connection, parentId);
			}
			statement.setLong(21, dataSourceObjectId);

			//extension, since this is not really file we just set it to null
			statement.setString(22, null);

			statement.setString(23, OsAccount.NO_OWNER_ID); // ownerUid
			statement.setNull(24, java.sql.Types.BIGINT); // osAccountObjId
			statement.setLong(25, TskData.CollectedStatus.UNKNOWN.getType()); // collected
			
			connection.executeUpdate(statement);

			return new VirtualDirectory(this, newObjId, dataSourceObjectId, fileSystemObjectId, directoryName, dirType,
					metaType, dirFlag, metaFlags, null, null, null, FileKnown.UNKNOWN,
					parentPath);
		} catch (SQLException e) {
			throw new TskCoreException("Error creating virtual directory '" + directoryName + "'", e);
		} finally {
			closeResultSet(resultSet);
		}
	}

	/**
	 * Adds a local directory to the database and returns a LocalDirectory
	 * object representing it.
	 *
	 * @param parentId      the ID of the parent, or 0 if NULL
	 * @param directoryName the name of the local directory to create
	 *
	 * @return a LocalDirectory object representing the one added to the
	 *         database.
	 *
	 * @throws TskCoreException
	 */
	public LocalDirectory addLocalDirectory(long parentId, String directoryName) throws TskCoreException {
		CaseDbTransaction localTrans = beginTransaction();
		try {
			LocalDirectory newLD = addLocalDirectory(parentId, directoryName, localTrans);
			localTrans.commit();
			return newLD;
		} catch (TskCoreException ex) {
			try {
				localTrans.rollback();
			} catch (TskCoreException ex2) {
				logger.log(Level.SEVERE, String.format("Failed to rollback transaction after exception: %s", ex.getMessage()), ex2);
			}
			throw ex;
		}
	}

	/**
	 * Adds a local directory to the database and returns a LocalDirectory
	 * object representing it.
	 *
	 * Make sure the connection in transaction is used for all database
	 * interactions called by this method
	 *
	 * @param parentId      the ID of the parent, or 0 if NULL
	 * @param directoryName the name of the local directory to create
	 * @param transaction   the transaction in the scope of which the operation
	 *                      is to be performed, managed by the caller
	 *
	 * @return a LocalDirectory object representing the one added to the
	 *         database.
	 *
	 * @throws TskCoreException
	 */
	public LocalDirectory addLocalDirectory(long parentId, String directoryName, CaseDbTransaction transaction) throws TskCoreException {
		if (transaction == null) {
			throw new TskCoreException("Passed null CaseDbTransaction");
		}

		ResultSet resultSet = null;
		try {
			// Get the parent path.
			CaseDbConnection connection = transaction.getConnection();
			AbstractFile parent = getAbstractFileById(parentId, connection);
			String parentPath;
			if ((parent == null) || isRootDirectory(parent, transaction)) {
				parentPath = "/";
			} else {
				parentPath = parent.getParentPath() + parent.getName() + "/"; //NON-NLS
			}

			// Insert a row for the local directory into the tsk_objects table.
			long newObjId = addObject(parentId, TskData.ObjectType.ABSTRACTFILE.getObjectType(), connection);

			// Insert a row for the local directory into the tsk_files table.
			// INSERT INTO tsk_files (obj_id, fs_obj_id, name, type, has_path, dir_type, meta_type,
			// dir_flags, meta_flags, size, ctime, crtime, atime, mtime, md5, sha256, sha1, known, mime_type, parent_path, data_source_obj_id, extension, owner_uid, os_account_obj_id)
			// VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_FILE);
			statement.clearParameters();
			statement.setLong(1, newObjId);

			// The parent of a local directory will never be a file system
			statement.setNull(2, java.sql.Types.BIGINT);

			// name
			statement.setString(3, directoryName);

			//type
			statement.setShort(4, TskData.TSK_DB_FILES_TYPE_ENUM.LOCAL_DIR.getFileType());
			statement.setShort(5, (short) 1);

			//flags
			final TSK_FS_NAME_TYPE_ENUM dirType = TSK_FS_NAME_TYPE_ENUM.DIR;
			statement.setShort(6, dirType.getValue());
			final TSK_FS_META_TYPE_ENUM metaType = TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR;
			statement.setShort(7, metaType.getValue());

			//allocated
			final TSK_FS_NAME_FLAG_ENUM dirFlag = TSK_FS_NAME_FLAG_ENUM.ALLOC;
			statement.setShort(8, dirFlag.getValue());
			final short metaFlags = (short) (TSK_FS_META_FLAG_ENUM.ALLOC.getValue()
					| TSK_FS_META_FLAG_ENUM.USED.getValue());
			statement.setShort(9, metaFlags);

			//size
			statement.setLong(10, 0);

			//  nulls for params 11-14
			statement.setNull(11, java.sql.Types.BIGINT);
			statement.setNull(12, java.sql.Types.BIGINT);
			statement.setNull(13, java.sql.Types.BIGINT);
			statement.setNull(14, java.sql.Types.BIGINT);

			statement.setNull(15, java.sql.Types.VARCHAR); // MD5
			statement.setNull(16, java.sql.Types.VARCHAR); // SHA-256
			statement.setNull(17, java.sql.Types.VARCHAR); // SHA-1
						
			statement.setByte(18, FileKnown.UNKNOWN.getFileKnownValue()); // Known
			statement.setNull(19, java.sql.Types.VARCHAR); // MIME type			

			// parent path
			statement.setString(20, parentPath);

			// data source object id
			long dataSourceObjectId = getDataSourceObjectId(connection, parentId);
			statement.setLong(21, dataSourceObjectId);

			//extension, since this is a directory we just set it to null
			statement.setString(22, null);

			statement.setString(23, OsAccount.NO_OWNER_ID); // ownerUid
			statement.setNull(24, java.sql.Types.BIGINT); // osAccountObjId
			statement.setLong(25, TskData.CollectedStatus.UNKNOWN.getType()); // collected

			connection.executeUpdate(statement);

			return new LocalDirectory(this, newObjId, dataSourceObjectId, directoryName, dirType,
					metaType, dirFlag, metaFlags, null, null, null, FileKnown.UNKNOWN,
					parentPath);
		} catch (SQLException e) {
			throw new TskCoreException("Error creating local directory '" + directoryName + "'", e);
		} finally {
			closeResultSet(resultSet);
		}
	}

	/**
	 * Adds a local/logical files and/or directories data source.
	 *
	 * @param deviceId          An ASCII-printable identifier for the device
	 *                          associated with the data source that is intended
	 *                          to be unique across multiple cases (e.g., a
	 *                          UUID).
	 * @param rootDirectoryName The name for the root virtual directory for the
	 *                          data source.
	 * @param timeZone          The time zone used to process the data source,
	 *                          may be the empty string.
	 * @param transaction       A transaction in the scope of which the
	 *                          operation is to be performed, managed by the
	 *                          caller.
	 *
	 * @return The new local files data source.
	 *
	 * @throws TskCoreException if there is an error adding the data source.
	 */
	public LocalFilesDataSource addLocalFilesDataSource(String deviceId, String rootDirectoryName, String timeZone, CaseDbTransaction transaction) throws TskCoreException {
		return addLocalFilesDataSource(deviceId, rootDirectoryName, timeZone, null, transaction);
	}

	/**
	 * Adds a local/logical files and/or directories data source.
	 *
	 * @param deviceId          An ASCII-printable identifier for the device
	 *                          associated with the data source that is intended
	 *                          to be unique across multiple cases (e.g., a
	 *                          UUID).
	 * @param rootDirectoryName The name for the root virtual directory for the
	 *                          data source.
	 * @param timeZone          The time zone used to process the data source,
	 *                          may be the empty string.
	 * @param host              The host for the data source (may be null)
	 * @param transaction       A transaction in the scope of which the
	 *                          operation is to be performed, managed by the
	 *                          caller.
	 *
	 * @return The new local files data source.
	 *
	 * @throws TskCoreException if there is an error adding the data source.
	 */
	public LocalFilesDataSource addLocalFilesDataSource(String deviceId, String rootDirectoryName, String timeZone, Host host, CaseDbTransaction transaction) throws TskCoreException {

		Statement statement = null;
		try {
			CaseDbConnection connection = transaction.getConnection();

			// Insert a row for the root virtual directory of the data source
			// into the tsk_objects table.
			long newObjId = addObject(0, TskData.ObjectType.ABSTRACTFILE.getObjectType(), connection);

			// If no host was supplied, make one
			if (host == null) {
				host = getHostManager().newHost("LogicalFileSet_" + newObjId + " Host", transaction);
			}

			// Insert a row for the virtual directory of the data source into
			// the data_source_info table.
			statement = connection.createStatement();
			statement.executeUpdate("INSERT INTO data_source_info (obj_id, device_id, time_zone, host_id) "
					+ "VALUES(" + newObjId + ", '" + deviceId + "', '" + timeZone + "', " + host.getHostId() + ");");

			// Insert a row for the root virtual directory of the data source
			// into the tsk_files table. Note that its data source object id is
			// its own object id.
			// INSERT INTO tsk_files (obj_id, fs_obj_id, name, type, has_path,
			// dir_type, meta_type, dir_flags, meta_flags, size, ctime, crtime,
			// atime, mtime, md5, sha256, sha1, known, mime_type, parent_path, data_source_obj_id, extension, owner_uid, os_account_obj_id)
			// VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?, ?, ?, ?)
			PreparedStatement preparedStatement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_FILE);
			preparedStatement.clearParameters();
			preparedStatement.setLong(1, newObjId);
			preparedStatement.setNull(2, java.sql.Types.BIGINT);
			preparedStatement.setString(3, rootDirectoryName);
			preparedStatement.setShort(4, TskData.TSK_DB_FILES_TYPE_ENUM.VIRTUAL_DIR.getFileType());
			preparedStatement.setShort(5, (short) 1);
			TSK_FS_NAME_TYPE_ENUM dirType = TSK_FS_NAME_TYPE_ENUM.DIR;
			preparedStatement.setShort(6, TSK_FS_NAME_TYPE_ENUM.DIR.getValue());
			TSK_FS_META_TYPE_ENUM metaType = TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR;
			preparedStatement.setShort(7, metaType.getValue());
			TSK_FS_NAME_FLAG_ENUM dirFlag = TSK_FS_NAME_FLAG_ENUM.ALLOC;
			preparedStatement.setShort(8, dirFlag.getValue());
			final short metaFlags = (short) (TSK_FS_META_FLAG_ENUM.ALLOC.getValue()
					| TSK_FS_META_FLAG_ENUM.USED.getValue());
			preparedStatement.setShort(9, metaFlags);
			preparedStatement.setLong(10, 0);
			preparedStatement.setNull(11, java.sql.Types.BIGINT);
			preparedStatement.setNull(12, java.sql.Types.BIGINT);
			preparedStatement.setNull(13, java.sql.Types.BIGINT);
			preparedStatement.setNull(14, java.sql.Types.BIGINT);
			preparedStatement.setNull(15, java.sql.Types.VARCHAR); // MD5
			preparedStatement.setNull(16, java.sql.Types.VARCHAR); // SHA-256
			preparedStatement.setNull(17, java.sql.Types.VARCHAR); // SHA-1
			preparedStatement.setByte(18, FileKnown.UNKNOWN.getFileKnownValue()); // Known
			preparedStatement.setNull(19, java.sql.Types.VARCHAR); // MIME type	
			String parentPath = "/"; //NON-NLS
			preparedStatement.setString(20, parentPath);
			preparedStatement.setLong(21, newObjId);
			preparedStatement.setString(22, null); //extension, just set it to null
			preparedStatement.setString(23, OsAccount.NO_OWNER_ID); // ownerUid
			preparedStatement.setNull(24, java.sql.Types.BIGINT); // osAccountObjId
			preparedStatement.setLong(25, TskData.CollectedStatus.UNKNOWN.getType()); // collected
			
			
			connection.executeUpdate(preparedStatement);

			return new LocalFilesDataSource(this, newObjId, newObjId, deviceId, rootDirectoryName, dirType, metaType, dirFlag, metaFlags, timeZone, null, null, null, FileKnown.UNKNOWN, parentPath);

		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error creating local files data source with device id %s and directory name %s", deviceId, rootDirectoryName), ex);
		} finally {
			closeStatement(statement);
		}
	}

	/**
	 * Add an image to the database.
	 *
	 * @param type        Type of image
	 * @param sectorSize  Sector size
	 * @param size        Image size
	 * @param displayName Display name for the image
	 * @param imagePaths  Image path(s)
	 * @param timezone    Time zone
	 * @param md5         MD5 hash
	 * @param sha1        SHA1 hash
	 * @param sha256      SHA256 hash
	 * @param deviceId    Device ID
	 * @param transaction Case DB transaction
	 *
	 * @return the newly added Image
	 *
	 * @throws TskCoreException
	 */
	public Image addImage(TskData.TSK_IMG_TYPE_ENUM type, long sectorSize, long size, String displayName, List<String> imagePaths,
			String timezone, String md5, String sha1, String sha256,
			String deviceId,
			CaseDbTransaction transaction) throws TskCoreException {
		return addImage(type, sectorSize, size, displayName, imagePaths, timezone, md5, sha1, sha256, deviceId, null, transaction);
	}

	/**
	 * Add an image to the database.
	 *
	 * @param type        Type of image
	 * @param sectorSize  Sector size
	 * @param size        Image size
	 * @param displayName Display name for the image
	 * @param imagePaths  Image path(s)
	 * @param timezone    Time zone
	 * @param md5         MD5 hash
	 * @param sha1        SHA1 hash
	 * @param sha256      SHA256 hash
	 * @param deviceId    Device ID
	 * @param host        Host
	 * @param transaction Case DB transaction
	 *
	 * @return the newly added Image
	 *
	 * @throws TskCoreException
	 */
	public Image addImage(TskData.TSK_IMG_TYPE_ENUM type, long sectorSize, long size, String displayName, List<String> imagePaths,
			String timezone, String md5, String sha1, String sha256,
			String deviceId, Host host,
			CaseDbTransaction transaction) throws TskCoreException {

		return addImage(type, sectorSize, size, displayName, imagePaths, timezone, md5, sha1, sha256, deviceId, host, null, transaction);
	}

	/**
	 * Add an image to the database.
	 *
	 * @param type        Type of image
	 * @param sectorSize  Sector size
	 * @param size        Image size
	 * @param displayName Display name for the image
	 * @param imagePaths  Image path(s)
	 * @param timezone    Time zone
	 * @param md5         MD5 hash
	 * @param sha1        SHA1 hash
	 * @param sha256      SHA256 hash
	 * @param deviceId    Device ID
	 * @param host        Host
	 * @param password    The password to decrypt the image.
	 * @param transaction Case DB transaction
	 *
	 * @return the newly added Image
	 *
	 * @throws TskCoreException
	 */
	@Beta
	public Image addImage(TskData.TSK_IMG_TYPE_ENUM type, long sectorSize, long size, String displayName, List<String> imagePaths,
			String timezone, String md5, String sha1, String sha256,
			String deviceId, Host host, String password,
			CaseDbTransaction transaction) throws TskCoreException {
		Statement statement = null;
		try {
			// Insert a row for the Image into the tsk_objects table.
			CaseDbConnection connection = transaction.getConnection();
			long newObjId = addObject(0, TskData.ObjectType.IMG.getObjectType(), connection);

			// Add a row to tsk_image_info
			// INSERT INTO tsk_image_info (obj_id, type, ssize, tzone, size, md5, sha1, sha256, display_name)
			PreparedStatement preparedStatement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_IMAGE_INFO);
			preparedStatement.clearParameters();
			preparedStatement.setLong(1, newObjId);
			preparedStatement.setShort(2, (short) type.getValue());
			preparedStatement.setLong(3, sectorSize);
			preparedStatement.setString(4, timezone);
			//prevent negative size
			long savedSize = size < 0 ? 0 : size;
			preparedStatement.setLong(5, savedSize);
			preparedStatement.setString(6, md5);
			preparedStatement.setString(7, sha1);
			preparedStatement.setString(8, sha256);
			preparedStatement.setString(9, displayName);
			connection.executeUpdate(preparedStatement);

			// If there are paths, add them to tsk_image_names
			for (int i = 0; i < imagePaths.size(); i++) {
				preparedStatement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_IMAGE_NAME);
				preparedStatement.clearParameters();
				preparedStatement.setLong(1, newObjId);
				preparedStatement.setString(2, imagePaths.get(i));
				preparedStatement.setLong(3, i);
				connection.executeUpdate(preparedStatement);
			}

			// Create the display name
			String name = displayName;
			if (name == null || name.isEmpty()) {
				if (imagePaths.size() > 0) {
					String path = imagePaths.get(0);
					name = (new java.io.File(path)).getName();
				} else {
					name = "";
				}
			}

			// Create a host if needed
			if (host == null) {
				if (name.isEmpty()) {
					host = getHostManager().newHost("Image_" + newObjId + " Host", transaction);
				} else {
					host = getHostManager().newHost(name + "_" + newObjId + " Host", transaction);
				}
			}

			Map<String, Object> acquisitionToolMap = new HashMap<>();
			if (password != null) {
				acquisitionToolMap.put(IMAGE_PASSWORD_KEY, password);
			}
			String acquisitionToolJson = (new Gson()).toJson(acquisitionToolMap);

			// Add a row to data_source_info
			preparedStatement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_DATA_SOURCE_INFO);
			statement = connection.createStatement();
			preparedStatement.setLong(1, newObjId);
			preparedStatement.setString(2, deviceId);
			preparedStatement.setString(3, timezone);
			preparedStatement.setLong(4, new Date().getTime());
			preparedStatement.setLong(5, host.getHostId());
			preparedStatement.setString(6, acquisitionToolJson);
			connection.executeUpdate(preparedStatement);

			// Create the new Image object
			return new Image(this, newObjId, type.getValue(), deviceId, sectorSize, name,
					imagePaths.toArray(new String[imagePaths.size()]), timezone, md5, sha1, sha256, savedSize);
		} catch (SQLException ex) {
			if (!imagePaths.isEmpty()) {
				throw new TskCoreException(String.format("Error adding image with path %s to database", imagePaths.get(0)), ex);
			} else {
				throw new TskCoreException(String.format("Error adding image with display name %s to database", displayName), ex);
			}
		} finally {
			closeStatement(statement);
		}
	}

	/**
	 * Add a volume system to the database.
	 *
	 * @param parentObjId Object ID of the volume system's parent
	 * @param type        Type of volume system
	 * @param imgOffset   Image offset
	 * @param blockSize   Block size
	 * @param transaction Case DB transaction
	 *
	 * @return the newly added VolumeSystem
	 *
	 * @throws TskCoreException
	 */
	public VolumeSystem addVolumeSystem(long parentObjId, TskData.TSK_VS_TYPE_ENUM type, long imgOffset,
			long blockSize, CaseDbTransaction transaction) throws TskCoreException {
		try {
			// Insert a row for the VolumeSystem into the tsk_objects table.
			CaseDbConnection connection = transaction.getConnection();
			long newObjId = addObject(parentObjId, TskData.ObjectType.VS.getObjectType(), connection);

			// Add a row to tsk_vs_info
			// INSERT INTO tsk_vs_info (obj_id, vs_type, img_offset, block_size)
			PreparedStatement preparedStatement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_VS_INFO);
			preparedStatement.clearParameters();
			preparedStatement.setLong(1, newObjId);
			preparedStatement.setShort(2, (short) type.getVsType());
			preparedStatement.setLong(3, imgOffset);
			preparedStatement.setLong(4, blockSize);
			connection.executeUpdate(preparedStatement);

			// Create the new VolumeSystem object
			return new VolumeSystem(this, newObjId, "", type.getVsType(), imgOffset, blockSize);
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error creating volume system with parent ID %d and image offset %d",
					parentObjId, imgOffset), ex);
		}
	}

	/**
	 * Add a volume to the database
	 *
	 * @param parentObjId Object ID of the volume's parent
	 * @param addr			     Address of the volume
	 * @param start       Start of the volume
	 * @param length      Length of the volume
	 * @param desc        Description of the volume
	 * @param flags       Flags
	 * @param transaction Case DB transaction
	 *
	 * @return the newly created Volume
	 *
	 * @throws TskCoreException
	 */
	public Volume addVolume(long parentObjId, long addr, long start, long length, String desc,
			long flags, CaseDbTransaction transaction) throws TskCoreException {
		try {
			// Insert a row for the Volume into the tsk_objects table.
			CaseDbConnection connection = transaction.getConnection();
			long newObjId = addObject(parentObjId, TskData.ObjectType.VOL.getObjectType(), connection);

			// Add a row to tsk_vs_parts
			// INSERT INTO tsk_vs_parts (obj_id, addr, start, length, desc, flags)
			PreparedStatement preparedStatement;
			if (this.dbType == DbType.POSTGRESQL) {
				preparedStatement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_VS_PART_POSTGRESQL);
			} else {
				preparedStatement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_VS_PART_SQLITE);
			}
			preparedStatement.clearParameters();
			preparedStatement.setLong(1, newObjId);
			preparedStatement.setLong(2, addr);
			preparedStatement.setLong(3, start);
			preparedStatement.setLong(4, length);
			preparedStatement.setString(5, desc);
			preparedStatement.setShort(6, (short) flags);
			connection.executeUpdate(preparedStatement);

			// Create the new Volume object
			return new Volume(this, newObjId, addr, start, length, flags, desc);
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error creating volume with address %d and parent ID %d", addr, parentObjId), ex);
		}
	}

	/**
	 * Add a pool to the database.
	 *
	 * @param parentObjId Object ID of the pool's parent
	 * @param type        Type of pool
	 * @param transaction Case DB transaction
	 *
	 * @return the newly created Pool
	 *
	 * @throws TskCoreException
	 */
	public Pool addPool(long parentObjId, TskData.TSK_POOL_TYPE_ENUM type, CaseDbTransaction transaction) throws TskCoreException {
		try {
			// Insert a row for the Pool into the tsk_objects table.
			CaseDbConnection connection = transaction.getConnection();
			long newObjId = addObject(parentObjId, TskData.ObjectType.POOL.getObjectType(), connection);

			// Add a row to tsk_pool_info
			// INSERT INTO tsk_pool_info (obj_id, pool_type) VALUES (?, ?)
			PreparedStatement preparedStatement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_POOL_INFO);
			preparedStatement.clearParameters();
			preparedStatement.setLong(1, newObjId);
			preparedStatement.setShort(2, type.getValue());
			connection.executeUpdate(preparedStatement);

			// Create the new Pool object
			return new Pool(this, newObjId, type.getName(), type.getValue());
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error creating pool with type %d and parent ID %d", type.getValue(), parentObjId), ex);
		}
	}

	/**
	 * Add a FileSystem to the database.
	 *
	 * @param parentObjId Object ID of the file system's parent
	 * @param imgOffset   Offset in the image
	 * @param type        Type of file system
	 * @param blockSize   Block size
	 * @param blockCount  Block count
	 * @param rootInum    root inum
	 * @param firstInum   first inum
	 * @param lastInum    last inum
	 * @param displayName display name
	 * @param transaction Case DB transaction
	 *
	 * @return the newly created FileSystem
	 *
	 * @throws TskCoreException
	 */
	public FileSystem addFileSystem(long parentObjId, long imgOffset, TskData.TSK_FS_TYPE_ENUM type, long blockSize, long blockCount,
			long rootInum, long firstInum, long lastInum, String displayName,
			CaseDbTransaction transaction) throws TskCoreException {
		try {
			// Insert a row for the FileSystem into the tsk_objects table.
			CaseDbConnection connection = transaction.getConnection();
			long newObjId = addObject(parentObjId, TskData.ObjectType.FS.getObjectType(), connection);

			// Get the data source object ID
			long dataSourceId = getDataSourceObjectId(connection, newObjId);

			// Add a row to tsk_fs_info
			// INSERT INTO tsk_fs_info (obj_id, data_source_obj_id, img_offset, fs_type, block_size, block_count, root_inum, first_inum, last_inum, display_name)
			PreparedStatement preparedStatement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_FS_INFO);
			preparedStatement.clearParameters();
			preparedStatement.setLong(1, newObjId);
			preparedStatement.setLong(2, dataSourceId);
			preparedStatement.setLong(3, imgOffset);
			preparedStatement.setInt(4, type.getValue());
			preparedStatement.setLong(5, blockSize);
			preparedStatement.setLong(6, blockCount);
			preparedStatement.setLong(7, rootInum);
			preparedStatement.setLong(8, firstInum);
			preparedStatement.setLong(9, lastInum);
			preparedStatement.setString(10, displayName);
			connection.executeUpdate(preparedStatement);

			// Create the new FileSystem object
			return new FileSystem(this, newObjId, displayName, imgOffset, type, blockSize, blockCount, rootInum,
					firstInum, lastInum);
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error creating file system with image offset %d and parent ID %d",
					imgOffset, parentObjId), ex);
		}
	}

	/**
	 * Add a file system file.
	 *
	 * @param dataSourceObjId	The object id of the root data source of this
	 *                        file.
	 * @param fsObjId		       The file system object id.
	 * @param fileName		      The name of the file.
	 * @param metaAddr		      The meta address of the file.
	 * @param metaSeq		       The meta address sequence of the file.
	 * @param attrType		      The attributed type of the file.
	 * @param attrId		        The attribute id
	 * @param dirFlag		       The allocated status from the name structure
	 * @param metaFlags
	 * @param size			         The size of the file in bytes.
	 * @param ctime			        The changed time of the file.
	 * @param crtime		        The creation time of the file.
	 * @param atime			        The accessed time of the file
	 * @param mtime			        The modified time of the file.
	 ** @param isFile		        True, unless the file is a directory.
	 * @param parent		        The parent of the file (e.g., a virtual directory)
	 *
	 * @return Newly created file
	 *
	 * @throws TskCoreException
	 */
	public FsContent addFileSystemFile(long dataSourceObjId, long fsObjId,
			String fileName,
			long metaAddr, int metaSeq,
			TSK_FS_ATTR_TYPE_ENUM attrType, int attrId,
			TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags, long size,
			long ctime, long crtime, long atime, long mtime,
			boolean isFile, Content parent) throws TskCoreException {

		CaseDbTransaction transaction = beginTransaction();
		try {

			FsContent fileSystemFile = addFileSystemFile(dataSourceObjId, fsObjId, fileName,
					metaAddr, metaSeq, attrType, attrId, dirFlag, metaFlags, size,
					ctime, crtime, atime, mtime, null, null, null, isFile, parent,
					OsAccount.NO_OWNER_ID, null,
					Collections.emptyList(), transaction);

			transaction.commit();
			transaction = null;
			return fileSystemFile;
		} finally {
			if (null != transaction) {
				try {
					transaction.rollback();
				} catch (TskCoreException ex2) {
					logger.log(Level.SEVERE, "Failed to rollback transaction after exception", ex2);
				}
			}
		}
	}

	/**
	 * Add a file system file.
	 *
	 * @param dataSourceObjId The object id of the root data source of this
	 *                        file.
	 * @param fsObjId         The file system object id.
	 * @param fileName        The name of the file.
	 * @param metaAddr        The meta address of the file.
	 * @param metaSeq         The meta address sequence of the file.
	 * @param attrType        The attributed type of the file.
	 * @param attrId          The attribute id.
	 * @param dirFlag         The allocated status from the name structure
	 * @param metaFlags       The allocated status of the file, usually as
	 *                        reported in the metadata structure of the file
	 *                        system.
	 * @param size            The size of the file in bytes.
	 * @param ctime           The changed time of the file.
	 * @param crtime          The creation time of the file.
	 * @param atime           The accessed time of the file
	 * @param mtime           The modified time of the file.
	 * @param md5Hash         The MD5 hash of the file
	 * @param sha256Hash      The SHA256 hash of the file
	 * @param mimeType        The MIME type of the file
	 * @param isFile          True, unless the file is a directory.
	 * @param parent          The parent of the file (e.g., a virtual
	 *                        directory).
	 * @param ownerUid        UID of the file owner as found in the file system,
	 *                        can be null.
	 * @param osAccount       OS account of owner, may be null.
	 * @param fileAttributes  A list of file attributes. May be empty.
	 * @param transaction     A caller-managed transaction within which the add
	 *                        file operations are performed.
	 *
	 * @return Newly created file
	 *
	 * @throws TskCoreException
	 */
	public FsContent addFileSystemFile(long dataSourceObjId, long fsObjId,
			String fileName,
			long metaAddr, int metaSeq,
			TSK_FS_ATTR_TYPE_ENUM attrType, int attrId,
			TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags, long size,
			long ctime, long crtime, long atime, long mtime,
			String md5Hash, String sha256Hash, String mimeType,
			boolean isFile, Content parent, String ownerUid,
			OsAccount osAccount, List<Attribute> fileAttributes,
			CaseDbTransaction transaction) throws TskCoreException {
		
		return addFileSystemFile(dataSourceObjId, fsObjId,
				fileName,
				metaAddr, metaSeq,
				attrType, attrId,
				dirFlag, metaFlags, size,
				ctime, crtime, atime, mtime,
				md5Hash, sha256Hash, null,
				mimeType,
				isFile, parent, ownerUid,
				osAccount, fileAttributes,
				transaction);
	}
	
	/**
	 * Add a file system file.
	 *
	 * @param dataSourceObjId The object id of the root data source of this
	 *                        file.
	 * @param fsObjId         The file system object id.
	 * @param fileName        The name of the file.
	 * @param metaAddr        The meta address of the file.
	 * @param metaSeq         The meta address sequence of the file.
	 * @param attrType        The attributed type of the file.
	 * @param attrId          The attribute id.
	 * @param dirFlag         The allocated status from the name structure
	 * @param metaFlags       The allocated status of the file, usually as
	 *                        reported in the metadata structure of the file
	 *                        system.
	 * @param size            The size of the file in bytes.
	 * @param ctime           The changed time of the file.
	 * @param crtime          The creation time of the file.
	 * @param atime           The accessed time of the file
	 * @param mtime           The modified time of the file.
	 * @param md5Hash         The MD5 hash of the file
	 * @param sha256Hash      The SHA256 hash of the file
	 * @param sha1Hash        SHA1 Hash of the file. May be null.
	 * @param mimeType        The MIME type of the file
	 * @param isFile          True, unless the file is a directory.
	 * @param parent          The parent of the file (e.g., a virtual
	 *                        directory).
	 * @param ownerUid        UID of the file owner as found in the file system,
	 *                        can be null.
	 * @param osAccount       OS account of owner, may be null.
	 * @param fileAttributes  A list of file attributes. May be empty.
	 
	 * @param transaction     A caller-managed transaction within which the add
	 *                        file operations are performed.
	 *
	 * @return Newly created file
	 *
	 * @throws TskCoreException
	 */
	public FsContent addFileSystemFile(long dataSourceObjId, long fsObjId,
			String fileName,
			long metaAddr, int metaSeq,
			TSK_FS_ATTR_TYPE_ENUM attrType, int attrId,
			TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags, long size,
			long ctime, long crtime, long atime, long mtime,
			String md5Hash, String sha256Hash, String sha1Hash,
			String mimeType, boolean isFile,
			Content parent, String ownerUid,
			OsAccount osAccount, List<Attribute> fileAttributes, 
			CaseDbTransaction transaction) throws TskCoreException {
		return addFileSystemFile(dataSourceObjId, fsObjId,
				fileName,
				metaAddr, metaSeq,
				attrType, attrId,
				dirFlag, metaFlags, size,
				ctime, crtime, atime, mtime,
				md5Hash, sha256Hash, sha1Hash,
				mimeType,
				isFile, parent, ownerUid,
				osAccount, TskData.CollectedStatus.UNKNOWN, fileAttributes,
				transaction);
	}
	
	/**
	 * Add a file system file.
	 *
	 * @param dataSourceObjId The object id of the root data source of this
	 *                        file.
	 * @param fsObjId         The file system object id.
	 * @param fileName        The name of the file.
	 * @param metaAddr        The meta address of the file.
	 * @param metaSeq         The meta address sequence of the file.
	 * @param attrType        The attributed type of the file.
	 * @param attrId          The attribute id.
	 * @param dirFlag         The allocated status from the name structure
	 * @param metaFlags       The allocated status of the file, usually as
	 *                        reported in the metadata structure of the file
	 *                        system.
	 * @param size            The size of the file in bytes.
	 * @param ctime           The changed time of the file.
	 * @param crtime          The creation time of the file.
	 * @param atime           The accessed time of the file
	 * @param mtime           The modified time of the file.
	 * @param md5Hash         The MD5 hash of the file
	 * @param sha256Hash      The SHA256 hash of the file
	 * @param sha1Hash        SHA1 Hash of the file. May be null.
	 * @param mimeType        The MIME type of the file
	 * @param isFile          True, unless the file is a directory.
	 * @param parent          The parent of the file (e.g., a virtual
	 *                        directory).
	 * @param ownerUid        UID of the file owner as found in the file system,
	 *                        can be null.
	 * @param osAccount       OS account of owner, may be null.
	 * @param collected       Collected status for file content, may be null
	 * @param fileAttributes  A list of file attributes. May be empty.
	 
	 * @param transaction     A caller-managed transaction within which the add
	 *                        file operations are performed.
	 *
	 * @return Newly created file
	 *
	 * @throws TskCoreException
	 */
	public FsContent addFileSystemFile(long dataSourceObjId, long fsObjId,
			String fileName,
			long metaAddr, int metaSeq,
			TSK_FS_ATTR_TYPE_ENUM attrType, int attrId,
			TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags, long size,
			long ctime, long crtime, long atime, long mtime,
			String md5Hash, String sha256Hash, String sha1Hash,
			String mimeType, boolean isFile,
			Content parent, String ownerUid,
			OsAccount osAccount, TskData.CollectedStatus collected,
			List<Attribute> fileAttributes, 
			CaseDbTransaction transaction) throws TskCoreException {
		TimelineManager timelineManager = getTimelineManager();

		Statement queryStatement = null;
		String parentPath = "/";
		try {
			CaseDbConnection connection = transaction.getConnection();

			// Insert a row for the local/logical file into the tsk_objects table.
			// INSERT INTO tsk_objects (par_obj_id, type) VALUES (?, ?)
			long objectId = addObject(parent.getId(), TskData.ObjectType.ABSTRACTFILE.getObjectType(), connection);

			if (parent instanceof AbstractFile) {
				AbstractFile parentFile = (AbstractFile) parent;
				if (isRootDirectory(parentFile, transaction)) {
					parentPath = "/";
				} else {
					parentPath = parentFile.getParentPath() + parent.getName() + "/"; //NON-NLS
				}
			} else {
				parentPath = "/";
			}

			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_FILE_SYSTEM_FILE);
			statement.clearParameters();
			statement.setLong(1, objectId);											// obj_is
			statement.setLong(2, fsObjId);											// fs_obj_id 
			statement.setLong(3, dataSourceObjId);									// data_source_obj_id 
			statement.setShort(4, (short) attrType.getValue());						// attr_type
			statement.setInt(5, attrId);											// attr_id
			statement.setString(6, fileName);										// name
			statement.setLong(7, metaAddr);											// meta_addr
			statement.setInt(8, metaSeq);											// meta_addr
			statement.setShort(9, TskData.TSK_DB_FILES_TYPE_ENUM.FS.getFileType());	//type
			statement.setShort(10, (short) 1);										// has_path
			TSK_FS_NAME_TYPE_ENUM dirType = isFile ? TSK_FS_NAME_TYPE_ENUM.REG : TSK_FS_NAME_TYPE_ENUM.DIR;
			statement.setShort(11, dirType.getValue());								// dir_type
			TSK_FS_META_TYPE_ENUM metaType = isFile ? TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG : TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR;
			statement.setShort(12, metaType.getValue());							// meta_type
			statement.setShort(13, dirFlag.getValue());								// dir_flags
			statement.setShort(14, metaFlags);										// meta_flags
			statement.setLong(15, size < 0 ? 0 : size);
			statement.setLong(16, ctime);
			statement.setLong(17, crtime);
			statement.setLong(18, atime);
			statement.setLong(19, mtime);
			statement.setString(20, md5Hash);
			statement.setString(21, sha256Hash);
			statement.setString(22, sha1Hash);
			statement.setString(23, mimeType);
			statement.setString(24, parentPath);
			final String extension = extractExtension(fileName);
			statement.setString(25, extension);
			statement.setString(26, ownerUid);
			if (null != osAccount) {
				statement.setLong(27, osAccount.getId());
			} else {
				statement.setNull(27, java.sql.Types.BIGINT); // osAccountObjId
			}
			statement.setLong(28, collected.getType());
			
			connection.executeUpdate(statement);

			Long osAccountId = (osAccount != null) ? osAccount.getId() : null;
			DerivedFile derivedFile = new DerivedFile(this, objectId, dataSourceObjId, fsObjId, fileName, dirType, metaType, dirFlag, metaFlags,
					size, ctime, crtime, atime, mtime, md5Hash, sha256Hash, sha1Hash, null, parentPath, null, parent.getId(), mimeType, null, extension, ownerUid, osAccountId);

			if (!timelineEventsDisabled.get()) {
				timelineManager.addEventsForNewFile(derivedFile, connection);
			}

			for (Attribute fileAttribute : fileAttributes) {
				fileAttribute.setAttributeParentId(objectId);
				fileAttribute.setCaseDatabase(this);
				addFileAttribute(fileAttribute, connection);
			}

			if (osAccount != null) {
				osAccountManager.newOsAccountInstance(osAccount.getId(), dataSourceObjId, OsAccountInstance.OsAccountInstanceType.ACCESSED, connection);
			}

			return new org.sleuthkit.datamodel.File(this, objectId, dataSourceObjId, fsObjId,
					attrType, attrId, fileName, metaAddr, metaSeq,
					dirType, metaType, dirFlag, metaFlags,
					size, ctime, crtime, atime, mtime,
					(short) 0, 0, 0, md5Hash, sha256Hash, sha1Hash, null, parentPath, mimeType,
					extension, ownerUid, osAccountId, collected, fileAttributes);

		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Failed to INSERT file system file %s (%s) with parent id %d in tsk_files table", fileName, parentPath, parent.getId()), ex);
		} finally {
			closeStatement(queryStatement);
		}
	}

	/**
	 * Get IDs of the virtual folder roots (at the same level as image), used
	 * for containers such as for local files.
	 *
	 * @return IDs of virtual directory root objects.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public List<VirtualDirectory> getVirtualDirectoryRoots() throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT * FROM tsk_files WHERE" //NON-NLS
					+ " type = " + TskData.TSK_DB_FILES_TYPE_ENUM.VIRTUAL_DIR.getFileType()
					+ " AND obj_id = data_source_obj_id"
					+ " ORDER BY dir_type, LOWER(name)"); //NON-NLS
			List<VirtualDirectory> virtDirRootIds = new ArrayList<VirtualDirectory>();
			while (rs.next()) {
				virtDirRootIds.add(virtualDirectory(rs, connection));
			}
			return virtDirRootIds;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting local files virtual folder id", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Adds one or more layout files for a parent Content object to the case
	 * database.
	 *
	 * @param parent     The parent Content.
	 * @param fileRanges File range objects for the file(s).
	 *
	 * @return A list of LayoutFile objects.
	 *
	 * @throws TskCoreException If there is a problem completing a case database
	 *                          operation.
	 */
	public final List<LayoutFile> addLayoutFiles(Content parent, List<TskFileRange> fileRanges) throws TskCoreException {
		assert (null != fileRanges);
		if (null == fileRanges) {
			throw new TskCoreException("TskFileRange object is null");
		}

		assert (null != parent);
		if (null == parent) {
			throw new TskCoreException("Conent is null");
		}
		
		String parentPath;
		if (parent instanceof AbstractFile) {
			parentPath = ((AbstractFile) parent).getParentPath() + parent.getName() + '/'; //NON-NLS
		} else {
			parentPath = "/";
		}

		CaseDbTransaction transaction = null;
		Statement statement = null;
		ResultSet resultSet = null;

		try {
			transaction = beginTransaction();
			CaseDbConnection connection = transaction.getConnection();
			
			// If the parent is part of a file system, grab its file system ID
			Long fileSystemObjectId;
			if (0 != parent.getId()) {
				fileSystemObjectId = this.getFileSystemId(parent.getId(), connection);
				if (fileSystemObjectId == -1) {
					fileSystemObjectId = null;
				}
			} else {
				fileSystemObjectId = null;
			}

			List<LayoutFile> fileRangeLayoutFiles = new ArrayList<>();
			for (TskFileRange fileRange : fileRanges) {
				/*
				 * Insert a row for the Tsk file range into the tsk_objects
				 * table: INSERT INTO tsk_objects (par_obj_id, type) VALUES (?,
				 * ?)
				 */
				long fileRangeId = addObject(parent.getId(), TskData.ObjectType.ABSTRACTFILE.getObjectType(), connection);
				long end_byte_in_parent = fileRange.getByteStart() + fileRange.getByteLen() - 1;
				/*
				 * Insert a row for the Tsk file range into the tsk_files table:
				 * INSERT INTO tsk_files (obj_id, fs_obj_id, name, type,
				 * has_path, dir_type, meta_type, dir_flags, meta_flags, size,
				 * ctime, crtime, atime, mtime, md5, sha256, sha1, known, mime_type,
				 * parent_path, data_source_obj_id,extension, owner_uid,
				 * os_account_obj_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
				 * ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?, ?, ?, ?)
				 */
				PreparedStatement prepStmt = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_FILE);
				prepStmt.clearParameters();
				prepStmt.setLong(1, fileRangeId); // obj_id	from tsk_objects
				if (fileSystemObjectId != null) {
					prepStmt.setLong(2, fileSystemObjectId);// fs_obj_id
				} else {
					prepStmt.setNull(2, java.sql.Types.BIGINT); 	
				}
				prepStmt.setString(3, "Unalloc_" + parent.getId() + "_" + fileRange.getByteStart() + "_" + end_byte_in_parent); // name of form Unalloc_[image obj_id]_[start byte in parent]_[end byte in parent]
				prepStmt.setShort(4, TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS.getFileType()); // type
				prepStmt.setNull(5, java.sql.Types.BIGINT); // has_path
				prepStmt.setShort(6, TSK_FS_NAME_TYPE_ENUM.REG.getValue()); // dir_type
				prepStmt.setShort(7, TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG.getValue()); // meta_type
				prepStmt.setShort(8, TSK_FS_NAME_FLAG_ENUM.UNALLOC.getValue()); // dir_flags
				prepStmt.setShort(9, TSK_FS_META_FLAG_ENUM.UNALLOC.getValue()); // nmeta_flags
				prepStmt.setLong(10, fileRange.getByteLen()); // size 
				prepStmt.setNull(11, java.sql.Types.BIGINT); // ctime
				prepStmt.setNull(12, java.sql.Types.BIGINT); // crtime
				prepStmt.setNull(13, java.sql.Types.BIGINT); // atime
				prepStmt.setNull(14, java.sql.Types.BIGINT); // mtime
				prepStmt.setNull(15, java.sql.Types.VARCHAR); // MD5
				prepStmt.setNull(16, java.sql.Types.VARCHAR); // SHA-256
				prepStmt.setNull(17, java.sql.Types.VARCHAR); // SHA-1
				
				prepStmt.setByte(18, FileKnown.UNKNOWN.getFileKnownValue()); // Known
				prepStmt.setNull(19, java.sql.Types.VARCHAR); // MIME type
				prepStmt.setString(20, parentPath); // parent path
				prepStmt.setLong(21, parent.getId()); // data_source_obj_id

				//extension, since this is not a FS file we just set it to null
				prepStmt.setString(22, null);

				prepStmt.setString(23, OsAccount.NO_OWNER_ID); // ownerUid
				prepStmt.setNull(24, java.sql.Types.BIGINT); // osAccountObjId
				prepStmt.setLong(25, TskData.CollectedStatus.UNKNOWN.getType()); // collected
				
				connection.executeUpdate(prepStmt);

				/*
				 * Insert a row in the tsk_layout_file table for each chunk of
				 * the carved file. INSERT INTO tsk_file_layout (obj_id,
				 * byte_start, byte_len, sequence) VALUES (?, ?, ?, ?)
				 */
				prepStmt = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_LAYOUT_FILE);
				prepStmt.clearParameters();
				prepStmt.setLong(1, fileRangeId); // obj_id
				prepStmt.setLong(2, fileRange.getByteStart()); // byte_start
				prepStmt.setLong(3, fileRange.getByteLen()); // byte_len
				prepStmt.setLong(4, fileRange.getSequence()); // sequence
				connection.executeUpdate(prepStmt);

				/*
				 * Create a layout file representation of the carved file.
				 */
				fileRangeLayoutFiles.add(new LayoutFile(this,
						fileRangeId,
						parent.getId(),
						fileSystemObjectId,
						Long.toString(fileRange.getSequence()),
						TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS,
						TSK_FS_NAME_TYPE_ENUM.REG,
						TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG,
						TSK_FS_NAME_FLAG_ENUM.UNALLOC,
						TSK_FS_META_FLAG_ENUM.UNALLOC.getValue(),
						fileRange.getByteLen(),
						0L, 0L, 0L, 0L,
						null, null, null,
						FileKnown.UNKNOWN,
						parent.getUniquePath(),
						null,
						OsAccount.NO_OWNER_ID,
						OsAccount.NO_ACCOUNT));
			}

			transaction.commit();
			transaction = null;
			return fileRangeLayoutFiles;

		} catch (SQLException ex) {
			throw new TskCoreException("Failed to add layout files to case database", ex);
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);

			if (null != transaction) {
				try {
					transaction.rollback();
				} catch (TskCoreException ex2) {
					logger.log(Level.SEVERE, "Failed to rollback transaction after exception", ex2);
				}
			}
		}
	}

	/**
	 * Utility class to hold the current subfolder being used for carved files
	 * and a count of how many files are in the folder. Note that this count
	 * will not be accurate if multiple nodes are writing carved files to the
	 * same folder at once.
	 */
	private class CarvedFileDirInfo {

		final VirtualDirectory currentFolder;
		AtomicInteger count;

		CarvedFileDirInfo(VirtualDirectory currentFolder) {
			this.currentFolder = currentFolder;
			count = new AtomicInteger(0);
		}

		CarvedFileDirInfo(VirtualDirectory currentFolder, int count) {
			this.currentFolder = currentFolder;
			this.count = new AtomicInteger(count);
		}

		/**
		 * Check if the folder is "full" and we should start a new subfolder.
		 *
		 * @return True if the maximum number of files have been written to the
		 *         folder, false otherwise.
		 */
		boolean isFull() {
			return count.get() >= MAX_CARVED_FILES_PER_FOLDER;
		}

		/**
		 * Increment the file counter.
		 */
		void incrementFileCounter() {
			count.incrementAndGet();
		}
	}

	/**
	 * Find the newest subfolder of $CarvedFiles and load its data.
	 *
	 * @param carvedFilesBaseDir The $CarvedFiles directory
	 *
	 * @return The subfolder of $CarvedFiles with the highest object ID.
	 *
	 * @throws TskCoreException
	 */
	private CarvedFileDirInfo getMostRecentCarvedDirInfo(VirtualDirectory carvedFilesBaseDir) throws TskCoreException {
		VirtualDirectory mostRecentDir = null;
		for (Content child : carvedFilesBaseDir.getChildren()) {
			if (isValidCarvedFileSubfolder(child)) {
				if (mostRecentDir == null
						|| (mostRecentDir.getId() < child.getId())) {
					mostRecentDir = (VirtualDirectory) child;
				}
			}
		}

		if (mostRecentDir != null) {
			return new CarvedFileDirInfo(mostRecentDir, mostRecentDir.getChildrenCount());
		}
		return null;
	}

	/**
	 * Check if the name of the folder matches the expected pattern for a
	 * subfolder and is a virtual directory.
	 *
	 * @param subfolder The subfolder to test.
	 *
	 * @return true if the format appears valid, false otherwise.
	 */
	private boolean isValidCarvedFileSubfolder(Content subfolder) {
		if (!(subfolder instanceof VirtualDirectory)) {
			return false;
		}
		return subfolder.getName().matches("^[0-9]+$");
	}

	/**
	 * Create the next carved files subfolder. If the current subfolder is
	 * given, the new subfolder will be one higher than the name of the current
	 * subfolder.
	 *
	 * @param carvedFilesBaseDir   The base $CarvedFiles folder.
	 * @param currentSubfolderInfo Optional name of the current subfolder in use
	 *                             (can be null).
	 *
	 * @return The new subfolder for carved files.
	 *
	 * @throws TskCoreException
	 */
	private CarvedFileDirInfo createCarvedFilesSubfolder(Content carvedFilesBaseDir, CarvedFileDirInfo currentSubfolderInfo) throws TskCoreException {
		int nextIndex = 1;
		if (currentSubfolderInfo != null) {
			try {
				int currentIndex = Integer.parseInt(currentSubfolderInfo.currentFolder.getName());
				nextIndex = currentIndex + 1;
			} catch (NumberFormatException ex) {
				throw new TskCoreException("Unexpected name format for carved files subdirectory with ID: " + currentSubfolderInfo.currentFolder.getId() + " (" + currentSubfolderInfo.currentFolder.getName() + ")", ex);
			}
		}

		VirtualDirectory carvedFilesSubdir = addVirtualDirectory(carvedFilesBaseDir.getId(), Integer.toString(nextIndex));
		return new CarvedFileDirInfo(carvedFilesSubdir);
	}

	/**
	 * Adds a carving result to the case database.
	 *
	 * @param carvingResult The carving result (a set of carved files and their
	 *                      parent) to be added.
	 *
	 * @return A list of LayoutFile representations of the carved files.
	 *
	 * @throws TskCoreException If there is a problem completing a case database
	 *                          operation.
	 */
	public final List<LayoutFile> addCarvedFiles(CarvingResult carvingResult) throws TskCoreException {
		assert (null != carvingResult);
		if (null == carvingResult) {
			throw new TskCoreException("Carving is null");
		}
		assert (null != carvingResult.getParent());
		if (null == carvingResult.getParent()) {
			throw new TskCoreException("Carving result has null parent");
		}
		assert (null != carvingResult.getCarvedFiles());
		if (null == carvingResult.getCarvedFiles()) {
			throw new TskCoreException("Carving result has null carved files");
		}
		CaseDbTransaction transaction = null;
		Statement statement = null;
		ResultSet resultSet = null;
		try {

			/*
			 * Carved files are "re-parented" as children of the $CarvedFiles
			 * virtual directory of the root file system, volume, or image
			 * ancestor of the carved files parent, but if no such ancestor is
			 * found, then the parent specified in the carving result is used.
			 */
			Content root = carvingResult.getParent();
			while (null != root) {
				if (root instanceof FileSystem || root instanceof Volume || root instanceof Image) {
					break;
				}
				root = root.getParent();
			}
			if (null == root) {
				root = carvingResult.getParent();
			}

			/*
			 * Get or create the $CarvedFiles virtual directory for the root
			 * ancestor.
			 */
			CarvedFileDirInfo carvedFilesDirInfo = null;
			synchronized (carvedFileDirsLock) {
				// Get the subfolder currently in use (if there is one)
				carvedFilesDirInfo = rootIdsToCarvedFileDirs.get(root.getId());
				if (carvedFilesDirInfo != null) {
					carvedFilesDirInfo.incrementFileCounter();

					// If the current folder is full, create a new one.
					if (carvedFilesDirInfo.isFull()) {
						carvedFilesDirInfo = createCarvedFilesSubfolder(carvedFilesDirInfo.currentFolder.getParent(), carvedFilesDirInfo);
					}
				}

				if (null == carvedFilesDirInfo) {
					List<Content> rootChildren;
					if (root instanceof FileSystem) {
						rootChildren = ((FileSystem) root).getRootDirectory().getChildren();
					} else {
						rootChildren = root.getChildren();
					}
					for (Content child : rootChildren) {
						if (child instanceof VirtualDirectory && child.getName().equals(VirtualDirectory.NAME_CARVED)) {

							VirtualDirectory baseDir = (VirtualDirectory) child;

							// Get the most recent subfolder in the carved files folder.
							carvedFilesDirInfo = getMostRecentCarvedDirInfo(baseDir);

							// If there are no subfolders, create one.
							if (carvedFilesDirInfo == null) {
								carvedFilesDirInfo = createCarvedFilesSubfolder(baseDir, null);
							}

							// If there are already too many files in the subfolder, create a new one.
							if (carvedFilesDirInfo.isFull()) {
								carvedFilesDirInfo = createCarvedFilesSubfolder(baseDir, carvedFilesDirInfo);
							}

							rootIdsToCarvedFileDirs.put(root.getId(), carvedFilesDirInfo);
							break;
						}
					}
					if (carvedFilesDirInfo == null) {
						// If we get here, we didn't have a carved files base folder in the case, so we need to make that and 
						// the first subfolder.

						long parId = root.getId();
						// $CarvedFiles should be a child of the root directory, not the file system
						if (root instanceof FileSystem) {
							Content rootDir = ((FileSystem) root).getRootDirectory();
							parId = rootDir.getId();
						}
						VirtualDirectory carvedFilesBaseDir = addVirtualDirectory(parId, VirtualDirectory.NAME_CARVED);
						carvedFilesDirInfo = createCarvedFilesSubfolder(carvedFilesBaseDir, null);
						rootIdsToCarvedFileDirs.put(root.getId(), carvedFilesDirInfo);
					}
				}
			}

			/*
			 * Add the carved files to the database as children of the
			 * $CarvedFile directory of the root ancestor.
			 */
			VirtualDirectory carvedFilesBaseDir = (VirtualDirectory) carvedFilesDirInfo.currentFolder.getParent();
			transaction = beginTransaction();
			CaseDbConnection connection = transaction.getConnection();
			String parentPath = getFileParentPath(carvedFilesDirInfo.currentFolder.getId(), connection) + carvedFilesDirInfo.currentFolder.getName() + "/";
			List<LayoutFile> carvedFiles = new ArrayList<>();
			for (CarvingResult.CarvedFile carvedFile : carvingResult.getCarvedFiles()) {

				/*
				 * Check if we need to change to a new subfolder.
				 */
				VirtualDirectory carvedFilesDir = carvedFilesDirInfo.currentFolder;
				if (carvedFilesDirInfo.isFull()) {
					// To prevent deadlocks involving the case write lock and the carvedFileDirsLock, 
					// commit the current transaction and then start a new one
					// after switching to the new folder.
					transaction.commit();

					synchronized (carvedFileDirsLock) {
						// Get the current copy from the map - another thread may have just created a new folder.
						carvedFilesDirInfo = rootIdsToCarvedFileDirs.get(root.getId());
						if (carvedFilesDirInfo.isFull()) {
							carvedFilesDirInfo = createCarvedFilesSubfolder(carvedFilesBaseDir, carvedFilesDirInfo);
							rootIdsToCarvedFileDirs.put(root.getId(), carvedFilesDirInfo);
							carvedFilesDir = carvedFilesDirInfo.currentFolder;
						}
					}

					// Start a new transaction.
					transaction = beginTransaction();
					connection = transaction.getConnection();
					parentPath = getFileParentPath(carvedFilesDir.getId(), connection) + carvedFilesDir.getName() + "/";

				}
				carvedFilesDirInfo.incrementFileCounter();

				/*
				 * Insert a row for the carved file into the tsk_objects table:
				 * INSERT INTO tsk_objects (par_obj_id, type) VALUES (?, ?)
				 */
				long carvedFileId = addObject(carvedFilesDir.getId(), TskData.ObjectType.ABSTRACTFILE.getObjectType(), connection);


				/*
				 * Insert a row for the carved file into the tsk_files table:
				 * INSERT INTO tsk_files (obj_id, fs_obj_id, name, type,
				 * has_path, dir_type, meta_type, dir_flags, meta_flags, size,
				 * ctime, crtime, atime, mtime, md5, sha256, sha1, known, mime_type,
				 * parent_path, data_source_obj_id,extenion, owner_uid,
				 * os_account_obj_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
				 * ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				 */
				PreparedStatement prepStmt = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_FILE);
				prepStmt.clearParameters();
				prepStmt.setLong(1, carvedFileId); // obj_id
				Long fileSystemObjectId;
				if (root instanceof FileSystem) {
					prepStmt.setLong(2, root.getId()); // fs_obj_id
					fileSystemObjectId = root.getId();
				} else {
					prepStmt.setNull(2, java.sql.Types.BIGINT); // fs_obj_id
					fileSystemObjectId = null;
				}
				prepStmt.setString(3, carvedFile.getName()); // name
				prepStmt.setShort(4, TSK_DB_FILES_TYPE_ENUM.CARVED.getFileType()); // type
				prepStmt.setShort(5, (short) 1); // has_path
				prepStmt.setShort(6, TSK_FS_NAME_TYPE_ENUM.REG.getValue()); // dir_type
				prepStmt.setShort(7, TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG.getValue()); // meta_type
				prepStmt.setShort(8, TSK_FS_NAME_FLAG_ENUM.UNALLOC.getValue()); // dir_flags
				prepStmt.setShort(9, TSK_FS_META_FLAG_ENUM.UNALLOC.getValue()); // nmeta_flags
				prepStmt.setLong(10, carvedFile.getSizeInBytes()); // size
				prepStmt.setNull(11, java.sql.Types.BIGINT); // ctime
				prepStmt.setNull(12, java.sql.Types.BIGINT); // crtime
				prepStmt.setNull(13, java.sql.Types.BIGINT); // atime
				prepStmt.setNull(14, java.sql.Types.BIGINT); // mtime
				prepStmt.setNull(15, java.sql.Types.VARCHAR); // MD5
				prepStmt.setNull(16, java.sql.Types.VARCHAR); // SHA-256
				prepStmt.setNull(17, java.sql.Types.VARCHAR); // SHA-1
				
				prepStmt.setByte(18, FileKnown.UNKNOWN.getFileKnownValue()); // Known
				prepStmt.setNull(19, java.sql.Types.VARCHAR); // MIME type	
				prepStmt.setString(20, parentPath); // parent path
				prepStmt.setLong(21, carvedFilesDir.getDataSourceObjectId()); // data_source_obj_id
				prepStmt.setString(22, extractExtension(carvedFile.getName())); //extension

				prepStmt.setString(23, OsAccount.NO_OWNER_ID); // ownerUid
				prepStmt.setNull(24, java.sql.Types.BIGINT); // osAccountObjId
				prepStmt.setLong(25, TskData.CollectedStatus.UNKNOWN.getType()); // collected
				
				connection.executeUpdate(prepStmt);

				/*
				 * Insert a row in the tsk_layout_file table for each chunk of
				 * the carved file. INSERT INTO tsk_file_layout (obj_id,
				 * byte_start, byte_len, sequence) VALUES (?, ?, ?, ?)
				 */
				prepStmt = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_LAYOUT_FILE);
				for (TskFileRange tskFileRange : carvedFile.getLayoutInParent()) {
					prepStmt.clearParameters();
					prepStmt.setLong(1, carvedFileId); // obj_id
					prepStmt.setLong(2, tskFileRange.getByteStart()); // byte_start
					prepStmt.setLong(3, tskFileRange.getByteLen()); // byte_len
					prepStmt.setLong(4, tskFileRange.getSequence()); // sequence
					connection.executeUpdate(prepStmt);
				}

				/*
				 * Create a layout file representation of the carved file.
				 */
				carvedFiles.add(new LayoutFile(this,
						carvedFileId,
						carvedFilesDir.getDataSourceObjectId(),
						fileSystemObjectId,
						carvedFile.getName(),
						TSK_DB_FILES_TYPE_ENUM.CARVED,
						TSK_FS_NAME_TYPE_ENUM.REG,
						TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG,
						TSK_FS_NAME_FLAG_ENUM.UNALLOC,
						TSK_FS_META_FLAG_ENUM.UNALLOC.getValue(),
						carvedFile.getSizeInBytes(),
						0L, 0L, 0L, 0L,
						null, null, null,
						FileKnown.UNKNOWN,
						parentPath,
						null,
						OsAccount.NO_OWNER_ID,
						OsAccount.NO_ACCOUNT));
			}

			transaction.commit();
			transaction = null;
			return carvedFiles;

		} catch (SQLException ex) {
			throw new TskCoreException("Failed to add carved files to case database", ex);
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);

			if (null != transaction) {
				try {
					transaction.rollback();
				} catch (TskCoreException ex2) {
					logger.log(Level.SEVERE, "Failed to rollback transaction after exception", ex2);
				}
			}
		}
	}

	/**
	 * Creates a new derived file object, adds it to database and returns it.
	 *
	 * TODO add support for adding derived method
	 *
	 * @param fileName        file name the derived file
	 * @param localPath       local path of the derived file, including the file
	 *                        name. The path is relative to the database path.
	 * @param size            size of the derived file in bytes
	 * @param ctime           The changed time of the file.
	 * @param crtime          The creation time of the file.
	 * @param atime           The accessed time of the file
	 * @param mtime           The modified time of the file.
	 * @param isFile          whether a file or directory, true if a file
	 * @param parentObj		     parent content object
	 * @param rederiveDetails details needed to re-derive file (will be specific
	 *                        to the derivation method), currently unused
	 * @param toolName        name of derivation method/tool, currently unused
	 * @param toolVersion     version of derivation method/tool, currently
	 *                        unused
	 * @param otherDetails    details of derivation method/tool, currently
	 *                        unused
	 * @param encodingType    Type of encoding used on the file (or NONE if no
	 *                        encoding)
	 *
	 * @return newly created derived file object
	 *
	 * @throws TskCoreException exception thrown if the object creation failed
	 *                          due to a critical system error
	 */
	public DerivedFile addDerivedFile(String fileName, String localPath,
			long size, long ctime, long crtime, long atime, long mtime,
			boolean isFile, Content parentObj,
			String rederiveDetails, String toolName, String toolVersion,
			String otherDetails, TskData.EncodingType encodingType) throws TskCoreException {
		CaseDbTransaction transaction = beginTransaction();
		try {
			DerivedFile df = addDerivedFile(fileName, localPath,
					size, ctime, crtime, atime, mtime,
					isFile, parentObj,
					rederiveDetails, toolName, toolVersion,
					otherDetails, encodingType, transaction);
			transaction.commit();
			return df;
		} catch (TskCoreException ex) {
			transaction.rollback();
			throw ex;
		}
	}

	public DerivedFile addDerivedFile(String fileName, String localPath,
			long size, long ctime, long crtime, long atime, long mtime,
			boolean isFile, Content parentObj,
			String rederiveDetails, String toolName, String toolVersion,
			String otherDetails, TskData.EncodingType encodingType, CaseDbTransaction transaction) throws TskCoreException {
		// Strip off any leading slashes from the local path (leading slashes indicate absolute paths)
		localPath = localPath.replaceAll("^[/\\\\]+", "");

		TimelineManager timelineManager = getTimelineManager();

		CaseDbConnection connection = transaction.getConnection();
		try {
			final long parentId = parentObj.getId();
			String parentPath = "";
			if (parentObj instanceof BlackboardArtifact) {
				parentPath = parentObj.getUniquePath() + '/' + parentObj.getName() + '/';
			} else if (parentObj instanceof AbstractFile) {
				parentPath = ((AbstractFile) parentObj).getParentPath() + parentObj.getName() + '/'; //NON-NLS
			}

			// Insert a row for the derived file into the tsk_objects table.
			// INSERT INTO tsk_objects (par_obj_id, type) VALUES (?, ?)
			long newObjId = addObject(parentId, TskData.ObjectType.ABSTRACTFILE.getObjectType(), connection);

			// Insert a row for the virtual directory into the tsk_files table.
			// INSERT INTO tsk_files (obj_id, fs_obj_id, name, type, has_path, dir_type, meta_type,
			// dir_flags, meta_flags, size, ctime, crtime, atime, mtime, md5, known, mime_type,
			// parent_path, data_source_obj_id, extension)
			// VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?)
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_FILE);
			statement.clearParameters();
			statement.setLong(1, newObjId);

			// If the parentFile is part of a file system, use its file system object ID.
			Long fsObjId = this.getFileSystemId(parentId, connection);
			if (fsObjId != -1) {
				statement.setLong(2, fsObjId);
			} else {
				fsObjId = null;
				statement.setNull(2, java.sql.Types.BIGINT);
			}
			statement.setString(3, fileName);

			//type, has_path
			statement.setShort(4, TskData.TSK_DB_FILES_TYPE_ENUM.DERIVED.getFileType());
			statement.setShort(5, (short) 1);

			//flags
			final TSK_FS_NAME_TYPE_ENUM dirType = isFile ? TSK_FS_NAME_TYPE_ENUM.REG : TSK_FS_NAME_TYPE_ENUM.DIR;
			statement.setShort(6, dirType.getValue());
			final TSK_FS_META_TYPE_ENUM metaType = isFile ? TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG : TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR;
			statement.setShort(7, metaType.getValue());

			//note: using alloc under assumption that derived files derive from alloc files
			final TSK_FS_NAME_FLAG_ENUM dirFlag = TSK_FS_NAME_FLAG_ENUM.ALLOC;
			statement.setShort(8, dirFlag.getValue());
			final short metaFlags = (short) (TSK_FS_META_FLAG_ENUM.ALLOC.getValue()
					| TSK_FS_META_FLAG_ENUM.USED.getValue());
			statement.setShort(9, metaFlags);

			//size
			//prevent negative size
			long savedSize = size < 0 ? 0 : size;
			statement.setLong(10, savedSize);

			//mactimes
			//long ctime, long crtime, long atime, long mtime,
			statement.setLong(11, ctime);
			statement.setLong(12, crtime);
			statement.setLong(13, atime);
			statement.setLong(14, mtime);

			statement.setNull(15, java.sql.Types.VARCHAR); // MD5
			statement.setNull(16, java.sql.Types.VARCHAR); // SHA-256
			statement.setNull(17, java.sql.Types.VARCHAR); // SHA-1
			
			statement.setByte(18, FileKnown.UNKNOWN.getFileKnownValue()); // Known
			statement.setNull(19, java.sql.Types.VARCHAR); // MIME type	

			//parent path
			statement.setString(20, parentPath);

			// root data source object id
			long dataSourceObjId = getDataSourceObjectId(connection, parentObj);
			statement.setLong(21, dataSourceObjId);
			final String extension = extractExtension(fileName);
			//extension
			statement.setString(22, extension);

			statement.setString(23, OsAccount.NO_OWNER_ID); // ownerUid
			statement.setNull(24, java.sql.Types.BIGINT); // osAccountObjId
			statement.setLong(25, TskData.CollectedStatus.UNKNOWN.getType()); // collected
			
			connection.executeUpdate(statement);

			//add localPath
			addFilePath(connection, newObjId, localPath, encodingType);

			DerivedFile derivedFile = new DerivedFile(this, newObjId, dataSourceObjId, fsObjId, fileName, dirType, metaType, dirFlag, metaFlags,
					savedSize, ctime, crtime, atime, mtime, null, null, null, null, parentPath, localPath, parentId, null, encodingType, extension, OsAccount.NO_OWNER_ID, OsAccount.NO_ACCOUNT);

			if (!timelineEventsDisabled.get()) {
				timelineManager.addEventsForNewFile(derivedFile, connection);
			}

			//TODO add derived method to tsk_files_derived and tsk_files_derived_method
			return derivedFile;
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to add derived file to case database", ex);
		}
	}

	/**
	 * Updates an existing derived file in the database and returns a new
	 * derived file object with the updated contents
	 *
	 * @param derivedFile	    The derived file you wish to update
	 * @param localPath       local path of the derived file, including the file
	 *                        name. The path is relative to the database path.
	 * @param size            size of the derived file in bytes
	 * @param ctime           The changed time of the file.
	 * @param crtime          The creation time of the file.
	 * @param atime           The accessed time of the file
	 * @param mtime           The modified time of the file.
	 * @param isFile          whether a file or directory, true if a file
	 * @param mimeType		      The MIME type the updated file should have, null
	 *                        to unset it
	 * @param rederiveDetails details needed to re-derive file (will be specific
	 *                        to the derivation method), currently unused
	 * @param toolName        name of derivation method/tool, currently unused
	 * @param toolVersion     version of derivation method/tool, currently
	 *                        unused
	 * @param otherDetails    details of derivation method/tool, currently
	 *                        unused
	 * @param encodingType    Type of encoding used on the file (or NONE if no
	 *                        encoding)
	 *
	 * @return newly created derived file object which contains the updated data
	 *
	 * @throws TskCoreException exception thrown if the object creation failed
	 *                          due to a critical system error
	 */
	public DerivedFile updateDerivedFile(DerivedFile derivedFile, String localPath,
			long size, long ctime, long crtime, long atime, long mtime,
			boolean isFile, String mimeType,
			String rederiveDetails, String toolName, String toolVersion,
			String otherDetails, TskData.EncodingType encodingType) throws TskCoreException {

		CaseDbTransaction trans = null;
		try {
			Content parentObj = derivedFile.getParent();

			trans = beginTransaction();
			DerivedFile updatedFile = updateDerivedFile(derivedFile, localPath,
					size, ctime, crtime, atime, mtime,
					isFile, mimeType,
					rederiveDetails, toolName, toolVersion,
					otherDetails, encodingType, parentObj, trans);
			trans.commit();
			return updatedFile;
		} catch (TskCoreException ex) {
			if (trans != null) {
				trans.rollback();
			}
			throw ex;
		}
	}

	public DerivedFile updateDerivedFile(DerivedFile derivedFile, String localPath,
			long size, long ctime, long crtime, long atime, long mtime,
			boolean isFile, String mimeType,
			String rederiveDetails, String toolName, String toolVersion,
			String otherDetails, TskData.EncodingType encodingType,
			Content parentObj, CaseDbTransaction trans) throws TskCoreException {

		// Strip off any leading slashes from the local path (leading slashes indicate absolute paths)
		localPath = localPath.replaceAll("^[/\\\\]+", "");

		ResultSet rs = null;
		try {
			final long parentId = parentObj.getId();
			String parentPath = "";
			if (parentObj instanceof BlackboardArtifact) {
				parentPath = parentObj.getUniquePath() + '/' + parentObj.getName() + '/';
			} else if (parentObj instanceof AbstractFile) {
				parentPath = ((AbstractFile) parentObj).getParentPath() + parentObj.getName() + '/'; //NON-NLS
			}
			// UPDATE tsk_files SET type = ?, dir_type = ?, meta_type = ?, dir_flags = ?,  meta_flags = ?, "
			// + "size= ?, ctime= ?, crtime= ?, atime= ?, mtime= ?, mime_type = ? WHERE obj_id = ?"), //NON-NLS
			PreparedStatement statement = trans.getConnection().getPreparedStatement(PREPARED_STATEMENT.UPDATE_DERIVED_FILE);
			statement.clearParameters();

			//type
			statement.setShort(1, TskData.TSK_DB_FILES_TYPE_ENUM.DERIVED.getFileType());

			//flags
			final TSK_FS_NAME_TYPE_ENUM dirType = isFile ? TSK_FS_NAME_TYPE_ENUM.REG : TSK_FS_NAME_TYPE_ENUM.DIR;
			statement.setShort(2, dirType.getValue());
			final TSK_FS_META_TYPE_ENUM metaType = isFile ? TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG : TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR;
			statement.setShort(3, metaType.getValue());

			//note: using alloc under assumption that derived files derive from alloc files
			final TSK_FS_NAME_FLAG_ENUM dirFlag = TSK_FS_NAME_FLAG_ENUM.ALLOC;
			statement.setShort(4, dirFlag.getValue());
			final short metaFlags = (short) (TSK_FS_META_FLAG_ENUM.ALLOC.getValue()
					| TSK_FS_META_FLAG_ENUM.USED.getValue());
			statement.setShort(5, metaFlags);

			//size
			//prevent negative size
			long savedSize = size < 0 ? 0 : size;
			statement.setLong(6, savedSize);

			//mactimes
			//long ctime, long crtime, long atime, long mtime,
			statement.setLong(7, ctime);
			statement.setLong(8, crtime);
			statement.setLong(9, atime);
			statement.setLong(10, mtime);
			statement.setString(11, mimeType);
			statement.setString(12, String.valueOf(derivedFile.getId()));
			trans.getConnection().executeUpdate(statement);

			//add localPath
			updateFilePath(trans.getConnection(), derivedFile.getId(), localPath, encodingType);

			long dataSourceObjId = getDataSourceObjectId(trans.getConnection(), parentObj);
			Long fileSystemObjId = derivedFile.getFileSystemObjectId().orElse(null);
			final String extension = extractExtension(derivedFile.getName());
			return new DerivedFile(this, derivedFile.getId(), dataSourceObjId, fileSystemObjId, derivedFile.getName(), dirType, metaType, dirFlag, metaFlags,
					savedSize, ctime, crtime, atime, mtime, null, null, null, null, parentPath, localPath, parentId, null, encodingType, extension, 
					derivedFile.getOwnerUid().orElse(null), derivedFile.getOsAccountObjectId().orElse(null));
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to add derived file to case database", ex);
		} finally {
			closeResultSet(rs);
		}
	}

	/**
	 * Wraps the version of addLocalFile that takes a Transaction in a
	 * transaction local to this method.
	 *
	 * @param fileName
	 * @param localPath
	 * @param size
	 * @param ctime
	 * @param crtime
	 * @param atime
	 * @param mtime
	 * @param isFile
	 * @param encodingType
	 * @param parent
	 *
	 * @return
	 *
	 * @throws TskCoreException
	 */
	public LocalFile addLocalFile(String fileName, String localPath,
			long size, long ctime, long crtime, long atime, long mtime,
			boolean isFile, TskData.EncodingType encodingType,
			AbstractFile parent) throws TskCoreException {

		CaseDbTransaction localTrans = beginTransaction();
		try {
			LocalFile created = addLocalFile(fileName, localPath, size, ctime, crtime, atime, mtime, isFile, encodingType, parent, localTrans);
			localTrans.commit();
			localTrans = null;
			return created;
		} finally {
			if (null != localTrans) {
				try {
					localTrans.rollback();
				} catch (TskCoreException ex2) {
					logger.log(Level.SEVERE, "Failed to rollback transaction after exception", ex2);
				}
			}
		}
	}

	/**
	 * Adds a local/logical file to the case database. The database operations
	 * are done within a caller-managed transaction; the caller is responsible
	 * for committing or rolling back the transaction.
	 *
	 * @param fileName     The name of the file.
	 * @param localPath    The absolute path (including the file name) of the
	 *                     local/logical in secondary storage.
	 * @param size         The size of the file in bytes.
	 * @param ctime        The changed time of the file.
	 * @param crtime       The creation time of the file.
	 * @param atime        The accessed time of the file
	 * @param mtime        The modified time of the file.
	 * @param isFile       True, unless the file is a directory.
	 * @param encodingType Type of encoding used on the file
	 * @param parent       The parent of the file (e.g., a virtual directory)
	 * @param transaction  A caller-managed transaction within which the add
	 *                     file operations are performed.
	 *
	 * @return An object representing the local/logical file.
	 *
	 * @throws TskCoreException if there is an error completing a case database
	 *                          operation.
	 */
	public LocalFile addLocalFile(String fileName, String localPath,
			long size, long ctime, long crtime, long atime, long mtime,
			boolean isFile, TskData.EncodingType encodingType,
			Content parent, CaseDbTransaction transaction) throws TskCoreException {

		return addLocalFile(fileName, localPath,
				size, ctime, crtime, atime, mtime,
				null, null, null,
				isFile, encodingType,
				parent, transaction);
	}

	/**
	 * Adds a local/logical file to the case database. The database operations
	 * are done within a caller-managed transaction; the caller is responsible
	 * for committing or rolling back the transaction.
	 *
	 * @param fileName     The name of the file.
	 * @param localPath    The absolute path (including the file name) of the
	 *                     local/logical in secondary storage.
	 * @param size         The size of the file in bytes.
	 * @param ctime        The changed time of the file.
	 * @param crtime       The creation time of the file.
	 * @param atime        The accessed time of the file
	 * @param mtime        The modified time of the file.
	 * @param md5          The MD5 hash of the file
	 * @param sha256       the SHA-256 hash of the file.
	 * @param known        The known status of the file (can be null)
	 * @param mimeType     The MIME type of the file
	 * @param isFile       True, unless the file is a directory.
	 * @param encodingType Type of encoding used on the file
	 * @param parent       The parent of the file (e.g., a virtual directory)
	 * @param transaction  A caller-managed transaction within which the add
	 *                     file operations are performed.
	 *
	 * @return An object representing the local/logical file.
	 *
	 * @throws TskCoreException if there is an error completing a case database
	 *                          operation.
	 */
	public LocalFile addLocalFile(String fileName, String localPath,
			long size, long ctime, long crtime, long atime, long mtime,
			String md5, String sha256, FileKnown known, String mimeType,
			boolean isFile, TskData.EncodingType encodingType,
			Content parent, CaseDbTransaction transaction) throws TskCoreException {

		return addLocalFile(fileName, localPath, size, ctime, crtime, atime, mtime,
				md5, sha256, known, mimeType, isFile, encodingType,
				OsAccount.NO_ACCOUNT, OsAccount.NO_OWNER_ID, parent, transaction);

	}

	/**
	 * Adds a local/logical file to the case database. The database operations
	 * are done within a caller-managed transaction; the caller is responsible
	 * for committing or rolling back the transaction.
	 *
	 * @param fileName     The name of the file.
	 * @param localPath    The absolute path (including the file name) of the
	 *                     local/logical in secondary storage.
	 * @param size         The size of the file in bytes.
	 * @param ctime        The changed time of the file.
	 * @param crtime       The creation time of the file.
	 * @param atime        The accessed time of the file
	 * @param mtime        The modified time of the file.
	 * @param md5          The MD5 hash of the file
	 * @param sha256       the SHA-256 hash of the file.
	 * @param known        The known status of the file (can be null)
	 * @param mimeType     The MIME type of the file
	 * @param isFile       True, unless the file is a directory.
	 * @param encodingType Type of encoding used on the file
	 * @param osAccountId  OS account id (can be null)
	 * @param ownerAccount Owner account (can be null)
	 * @param parent       The parent of the file (e.g., a virtual directory)
	 * @param transaction  A caller-managed transaction within which the add
	 *                     file operations are performed.
	 *
	 * @return An object representing the local/logical file.
	 *
	 * @throws TskCoreException if there is an error completing a case database
	 *                          operation.
	 */
	public LocalFile addLocalFile(String fileName, String localPath,
			long size, long ctime, long crtime, long atime, long mtime,
			String md5, String sha256, FileKnown known, String mimeType,
			boolean isFile, TskData.EncodingType encodingType, Long osAccountId, String ownerAccount,
			Content parent, CaseDbTransaction transaction) throws TskCoreException {
		
		return addLocalFile(fileName, localPath,
			size, ctime, crtime, atime, mtime,
			md5, sha256, null, known, mimeType,
			isFile, encodingType, osAccountId, ownerAccount, 
			parent, transaction);
	}
	
	
	/**
	 * Adds a local/logical file to the case database. The database operations
	 * are done within a caller-managed transaction; the caller is responsible
	 * for committing or rolling back the transaction.
	 *
	 * @param fileName     The name of the file.
	 * @param localPath    The absolute path (including the file name) of the
	 *                     local/logical in secondary storage.
	 * @param size         The size of the file in bytes.
	 * @param ctime        The changed time of the file.
	 * @param crtime       The creation time of the file.
	 * @param atime        The accessed time of the file
	 * @param mtime        The modified time of the file.
	 * @param md5          The MD5 hash of the file
	 * @param sha256       the SHA-256 hash of the file.
	 * @param sha1Hash     SHA-1 Hash of the file, may be null.
	 * @param known        The known status of the file (can be null)
	 * @param mimeType     The MIME type of the file
	 * @param isFile       True, unless the file is a directory.
	 * @param encodingType Type of encoding used on the file
	 * @param osAccountId  OS account id (can be null)
	 * @param ownerAccount Owner account (can be null)
	 * @param parent       The parent of the file (e.g., a virtual directory)
	
	 * @param transaction  A caller-managed transaction within which the add
	 *                     file operations are performed.
	 *
	 * @return An object representing the local/logical file.
	 *
	 * @throws TskCoreException if there is an error completing a case database
	 *                          operation.
	 */
	public LocalFile addLocalFile(String fileName, String localPath,
			long size, long ctime, long crtime, long atime, long mtime,
			String md5, String sha256, String sha1Hash, FileKnown known, String mimeType,
			boolean isFile, TskData.EncodingType encodingType, Long osAccountId, String ownerAccount,
			Content parent,  CaseDbTransaction transaction) throws TskCoreException {
		CaseDbConnection connection = transaction.getConnection();
		Statement queryStatement = null;
		try {

			// Insert a row for the local/logical file into the tsk_objects table.
			// INSERT INTO tsk_objects (par_obj_id, type) VALUES (?, ?)
			long objectId = addObject(parent.getId(), TskData.ObjectType.ABSTRACTFILE.getObjectType(), connection);

			// Insert a row for the local/logical file into the tsk_files table.
			// INSERT INTO tsk_files (obj_id, fs_obj_id, name, type, has_path, dir_type, meta_type,
			// dir_flags, meta_flags, size, ctime, crtime, atime, mtime, md5, sha256, sha1, known, mime_type,
			// parent_path, data_source_obj_id,extension, uid_str, os_account_obj_id)
			// VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?, ?, ?, ?)
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_FILE);
			statement.clearParameters();
			statement.setLong(1, objectId);
			statement.setNull(2, java.sql.Types.BIGINT); // Not part of a file system
			statement.setString(3, fileName);
			statement.setShort(4, TskData.TSK_DB_FILES_TYPE_ENUM.LOCAL.getFileType());
			statement.setShort(5, (short) 1);
			TSK_FS_NAME_TYPE_ENUM dirType = isFile ? TSK_FS_NAME_TYPE_ENUM.REG : TSK_FS_NAME_TYPE_ENUM.DIR;
			statement.setShort(6, dirType.getValue());
			TSK_FS_META_TYPE_ENUM metaType = isFile ? TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG : TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR;
			statement.setShort(7, metaType.getValue());
			TSK_FS_NAME_FLAG_ENUM dirFlag = TSK_FS_NAME_FLAG_ENUM.ALLOC;
			statement.setShort(8, dirFlag.getValue());
			short metaFlags = (short) (TSK_FS_META_FLAG_ENUM.ALLOC.getValue() | TSK_FS_META_FLAG_ENUM.USED.getValue());
			statement.setShort(9, metaFlags);
			//prevent negative size
			long savedSize = size < 0 ? 0 : size;
			statement.setLong(10, savedSize);
			statement.setLong(11, ctime);
			statement.setLong(12, crtime);
			statement.setLong(13, atime);
			statement.setLong(14, mtime);
			statement.setString(15, md5);
			statement.setString(16, sha256);
			statement.setString(17, sha1Hash); // sha1
			
			if (known != null) {
				statement.setByte(18, known.getFileKnownValue());
			} else {
				statement.setByte(18, FileKnown.UNKNOWN.getFileKnownValue());
			}
			statement.setString(19, mimeType);
			String parentPath;
			long dataSourceObjId;

			if (parent instanceof AbstractFile) {
				AbstractFile parentFile = (AbstractFile) parent;
				if (isRootDirectory(parentFile, transaction)) {
					parentPath = "/";
				} else {
					parentPath = parentFile.getParentPath() + parent.getName() + "/"; //NON-NLS
				}
				dataSourceObjId = parentFile.getDataSourceObjectId();
			} else {
				parentPath = "/";
				dataSourceObjId = getDataSourceObjectId(connection, parent);
			}
			statement.setString(20, parentPath);
			statement.setLong(21, dataSourceObjId);
			final String extension = extractExtension(fileName);
			statement.setString(22, extension);

			if (ownerAccount != null) {
				statement.setString(23, ownerAccount); // ownerUid
			} else {
				statement.setNull(23, java.sql.Types.VARCHAR);
			}

			if (osAccountId != null) {
				statement.setLong(24, osAccountId); // osAccountObjId
			} else {
				statement.setNull(24, java.sql.Types.BIGINT);
			}
			
			statement.setLong(25, TskData.CollectedStatus.UNKNOWN.getType()); // collected
			
			connection.executeUpdate(statement);
			addFilePath(connection, objectId, localPath, encodingType);
			LocalFile localFile = new LocalFile(this,
					objectId,
					fileName,
					TSK_DB_FILES_TYPE_ENUM.LOCAL,
					dirType,
					metaType,
					dirFlag,
					metaFlags,
					savedSize,
					ctime, crtime, atime, mtime,
					mimeType, md5, sha256, sha1Hash, known,
					parent.getId(), parentPath,
					dataSourceObjId,
					localPath,
					encodingType, extension,
					ownerAccount, osAccountId);
			if (!timelineEventsDisabled.get()) {
				getTimelineManager().addEventsForNewFile(localFile, connection);
			}
			return localFile;

		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Failed to INSERT local file %s (%s) with parent id %d in tsk_files table", fileName, localPath, parent.getId()), ex);
		} finally {
			closeStatement(queryStatement);
		}
	}

	/**
	 * Utility class to create keys for the cache used in isRootDirectory(). The
	 * dataSourceId must be set but the fileSystemId can be null (for local
	 * directories, for example).
	 */
	private class RootDirectoryKey {

		private long dataSourceId;
		private Long fileSystemId;

		RootDirectoryKey(long dataSourceId, Long fileSystemId) {
			this.dataSourceId = dataSourceId;
			this.fileSystemId = fileSystemId;
		}

		@Override
		public int hashCode() {
			int hash = 7;
			hash = 41 * hash + Objects.hashCode(dataSourceId);
			hash = 41 * hash + Objects.hashCode(fileSystemId);
			return hash;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}

			RootDirectoryKey otherKey = (RootDirectoryKey) obj;
			if (dataSourceId != otherKey.dataSourceId) {
				return false;
			}

			if (fileSystemId != null) {
				return fileSystemId.equals(otherKey.fileSystemId);
			}
			return (otherKey.fileSystemId == null);
		}
	}

	/**
	 * Check whether a given AbstractFile is the "root" directory. True if the
	 * AbstractFile either has no parent or its parent is an image, volume,
	 * volume system, or file system.
	 *
	 * @param file        the file to test
	 * @param transaction the current transaction
	 *
	 * @return true if the file is a root directory, false otherwise
	 *
	 * @throws TskCoreException
	 */
	private boolean isRootDirectory(AbstractFile file, CaseDbTransaction transaction) throws TskCoreException {

		// First check if we know the root directory for this data source and optionally 
		// file system. There is only one root, so if we know it we can simply compare 
		// this file ID to the known root directory.
		Long fsObjId = null;
		if (file instanceof FsContent) {
			fsObjId = ((FsContent) file).getFileSystemId();
		}
		RootDirectoryKey key = new RootDirectoryKey(file.getDataSourceObjectId(), fsObjId);
		synchronized (rootDirectoryMapLock) {
			if (rootDirectoryMap.containsKey(key)) {
				return rootDirectoryMap.get(key).equals(file.getId());
			}
		}

		// Fallback cache. We store the result of each database lookup 
		// so it won't be done multiple times in a row. In practice, this will
		// only be used if this method was never called on the root directory. 
		Boolean isRoot = isRootDirectoryCache.getIfPresent(file.getId());
		if (isRoot != null) {
			return isRoot;
		}

		CaseDbConnection connection = transaction.getConnection();
		Statement statement = null;
		ResultSet resultSet = null;

		try {
			String query = String.format("SELECT ParentRow.type AS parent_type, ParentRow.obj_id AS parent_object_id "
					+ "FROM tsk_objects ParentRow JOIN tsk_objects ChildRow ON ChildRow.par_obj_id = ParentRow.obj_id "
					+ "WHERE ChildRow.obj_id = %s;", file.getId());

			statement = connection.createStatement();
			resultSet = statement.executeQuery(query);
			if (resultSet.next()) {
				long parentId = resultSet.getLong("parent_object_id");
				if (parentId == 0) {
					return true;
				}
				int type = resultSet.getInt("parent_type");
				boolean result = type == TskData.ObjectType.IMG.getObjectType()
						|| type == TskData.ObjectType.VS.getObjectType()
						|| type == TskData.ObjectType.VOL.getObjectType()
						|| type == TskData.ObjectType.FS.getObjectType();
				if (result == true) {
					synchronized (rootDirectoryMapLock) {
						// This is a root directory so save it
						rootDirectoryMap.put(key, file.getId());
					}
				}
				isRootDirectoryCache.put(file.getId(), result);
				return result;

			} else {
				// This is a root directory so save it
				synchronized (rootDirectoryMapLock) {
					rootDirectoryMap.put(key, file.getId());
				}
				isRootDirectoryCache.put(file.getId(), true);

				return true; // The file has no parent

			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Failed to lookup parent of file (%s) with id %d", file.getName(), file.getId()), ex);
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
		}
	}

	/**
	 * Add a new layout file to the database.
	 *
	 * @param fileName   The name of the file.
	 * @param size       The size of the file in bytes.
	 * @param dirFlag    The allocated status from the name structure
	 * @param metaFlag   The allocated status from the metadata structure
	 * @param ctime      The changed time of the file.
	 * @param crtime     The creation time of the file.
	 * @param atime      The accessed time of the file
	 * @param mtime      The modified time of the file.
	 * @param fileRanges The byte ranges that belong to this file (relative to
	 *                   start of image)
	 * @param parent     The parent of the file
	 *
	 * @return The new LayoutFile
	 *
	 * @throws TskCoreException
	 */
	public LayoutFile addLayoutFile(String fileName,
			long size,
			TSK_FS_NAME_FLAG_ENUM dirFlag, TSK_FS_META_FLAG_ENUM metaFlag,
			long ctime, long crtime, long atime, long mtime,
			List<TskFileRange> fileRanges,
			Content parent) throws TskCoreException {

		if (null == parent) {
			throw new TskCoreException("Parent can not be null");
		}

		String parentPath;
		if (parent instanceof AbstractFile) {
			parentPath = ((AbstractFile) parent).getParentPath() + parent.getName() + '/'; //NON-NLS
		} else {
			parentPath = "/";
		}

		CaseDbTransaction transaction = null;
		Statement statement = null;
		ResultSet resultSet = null;
		try {
			transaction = beginTransaction();
			CaseDbConnection connection = transaction.getConnection();

			/*
			 * Insert a row for the layout file into the tsk_objects table:
			 * INSERT INTO tsk_objects (par_obj_id, type) VALUES (?, ?)
			 */
			long newFileId = addObject(parent.getId(), TskData.ObjectType.ABSTRACTFILE.getObjectType(), connection);

			/*
			 * Insert a row for the file into the tsk_files table: INSERT INTO
			 * tsk_files (obj_id, fs_obj_id, name, type, has_path, dir_type,
			 * meta_type, dir_flags, meta_flags, size, ctime, crtime, atime,
			 * mtime, md5, known, mime_type, parent_path,
			 * data_source_obj_id,extenion, owner_uid, os_account_obj_id) VALUES
			 * (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			 */
			PreparedStatement prepStmt = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_FILE);
			prepStmt.clearParameters();
			prepStmt.setLong(1, newFileId); // obj_id

			// If the parent is part of a file system, grab its file system ID
			Long fileSystemObjectId;
			if (0 != parent.getId()) {
				fileSystemObjectId = this.getFileSystemId(parent.getId(), connection);
				if (fileSystemObjectId != -1) {
					prepStmt.setLong(2, fileSystemObjectId);
				} else {
					prepStmt.setNull(2, java.sql.Types.BIGINT);
					fileSystemObjectId = null;
				}
			} else {
				prepStmt.setNull(2, java.sql.Types.BIGINT);
				fileSystemObjectId = null;
			}
			prepStmt.setString(3, fileName); // name
			prepStmt.setShort(4, TSK_DB_FILES_TYPE_ENUM.LAYOUT_FILE.getFileType()); // type
			prepStmt.setShort(5, (short) 0); // has_path
			prepStmt.setShort(6, TSK_FS_NAME_TYPE_ENUM.REG.getValue()); // dir_type
			prepStmt.setShort(7, TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG.getValue()); // meta_type
			prepStmt.setShort(8, dirFlag.getValue()); // dir_flags
			prepStmt.setShort(9, metaFlag.getValue()); // meta_flags
			//prevent negative size
			long savedSize = size < 0 ? 0 : size;
			prepStmt.setLong(10, savedSize);   // size
			prepStmt.setLong(11, ctime);  // ctime
			prepStmt.setLong(12, crtime); // crtime
			prepStmt.setLong(13, atime);  // atime
			prepStmt.setLong(14, mtime);  // mtime
			prepStmt.setNull(15, java.sql.Types.VARCHAR); // MD5
			prepStmt.setNull(16, java.sql.Types.VARCHAR); // SHA-256
			prepStmt.setNull(17, java.sql.Types.VARCHAR); // SHA-1
			
			prepStmt.setByte(18, FileKnown.UNKNOWN.getFileKnownValue()); // Known
			prepStmt.setNull(19, java.sql.Types.VARCHAR); // MIME type	
			prepStmt.setString(20, parentPath); // parent path
			prepStmt.setLong(21, parent.getDataSource().getId()); // data_source_obj_id

			prepStmt.setString(22, extractExtension(fileName)); 				//extension

			prepStmt.setString(23, OsAccount.NO_OWNER_ID); // ownerUid
			prepStmt.setNull(24, java.sql.Types.BIGINT); // osAccountObjId
			prepStmt.setLong(25, TskData.CollectedStatus.UNKNOWN.getType()); // collected
			
			connection.executeUpdate(prepStmt);

			/*
			 * Insert a row in the tsk_layout_file table for each chunk of the
			 * carved file. INSERT INTO tsk_file_layout (obj_id, byte_start,
			 * byte_len, sequence) VALUES (?, ?, ?, ?)
			 */
			prepStmt = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_LAYOUT_FILE);
			for (TskFileRange tskFileRange : fileRanges) {
				prepStmt.clearParameters();
				prepStmt.setLong(1, newFileId); // obj_id
				prepStmt.setLong(2, tskFileRange.getByteStart()); // byte_start
				prepStmt.setLong(3, tskFileRange.getByteLen()); // byte_len
				prepStmt.setLong(4, tskFileRange.getSequence()); // sequence
				connection.executeUpdate(prepStmt);
			}

			/*
			 * Create a layout file representation of the carved file.
			 */
			LayoutFile layoutFile = new LayoutFile(this,
					newFileId,
					parent.getDataSource().getId(),
					fileSystemObjectId,
					fileName,
					TSK_DB_FILES_TYPE_ENUM.LAYOUT_FILE,
					TSK_FS_NAME_TYPE_ENUM.REG,
					TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG,
					dirFlag,
					metaFlag.getValue(),
					savedSize,
					ctime, crtime, atime, mtime,
					null, null, null,
					FileKnown.UNKNOWN,
					parentPath,
					null,
					OsAccount.NO_OWNER_ID,
					OsAccount.NO_ACCOUNT);

			transaction.commit();
			transaction = null;
			return layoutFile;

		} catch (SQLException ex) {
			throw new TskCoreException("Failed to add layout file " + fileName + " to case database", ex);
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);

			if (null != transaction) {
				try {
					transaction.rollback();
				} catch (TskCoreException ex2) {
					logger.log(Level.SEVERE, "Failed to rollback transaction after exception", ex2);
				}
			}
		}
	}

	/**
	 * Given a Content object, return its data source object ID. For
	 * AbstractFiles, this simply returns the data source ID field.
	 *
	 * @param connection A case database connection.
	 * @param content    The content to look up the data source object ID.
	 *
	 * @return A data source object id.
	 */
	private long getDataSourceObjectId(CaseDbConnection connection, Content content) throws TskCoreException {
		if (content == null) {
			throw new TskCoreException("Null Content parameter given");
		}
		if (content instanceof AbstractFile) {
			return ((AbstractFile) content).getDataSourceObjectId();
		} else {
			return getDataSourceObjectId(connection, content.getId());
		}
	}

	/**
	 * Given an object id, works up the tree of ancestors to the data source for
	 * the object and gets the object id of the data source. The trivial case
	 * where the input object id is for a source is handled.
	 *
	 * @param connection A case database connection.
	 * @param objectId   An object id.
	 *
	 * @return A data source object id.
	 *
	 * @throws TskCoreException if there is an error querying the case database.
	 */
	private long getDataSourceObjectId(CaseDbConnection connection, long objectId) throws TskCoreException {
		acquireSingleUserCaseReadLock();
		Statement statement = null;
		ResultSet resultSet = null;
		try {
			statement = connection.createStatement();
			long dataSourceObjId;
			long ancestorId = objectId;
			do {
				dataSourceObjId = ancestorId;
				String query = String.format("SELECT par_obj_id FROM tsk_objects WHERE obj_id = %s;", ancestorId);
				resultSet = statement.executeQuery(query);
				if (resultSet.next()) {
					ancestorId = resultSet.getLong("par_obj_id");
				} else {
					throw new TskCoreException(String.format("tsk_objects table is corrupt, SQL query returned no result: %s", query));
				}
				resultSet.close();
				resultSet = null;
			} while (0 != ancestorId); // Not NULL
			return dataSourceObjId;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error finding root data source for object (obj_id = %d)", objectId), ex);
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Add a path (such as a local path) for a content object to tsk_file_paths
	 *
	 * @param connection A case database connection.
	 * @param objId      The object id of the file for which to add the path.
	 * @param path       The path to add.
	 * @param type       The TSK encoding type of the file.
	 *
	 * @throws SQLException Thrown if database error occurred and path was not
	 *                      added.
	 */
	private void addFilePath(CaseDbConnection connection, long objId, String path, TskData.EncodingType type) throws SQLException {
		PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_LOCAL_PATH);
		statement.clearParameters();
		statement.setLong(1, objId);
		statement.setString(2, path);
		statement.setInt(3, type.getType());
		connection.executeUpdate(statement);
	}

	/**
	 * Update the path for a content object in the tsk_file_paths table
	 *
	 * @param connection A case database connection.
	 * @param objId      The object id of the file for which to update the path.
	 * @param path       The path to update.
	 * @param type       The TSK encoding type of the file.
	 *
	 * @throws SQLException Thrown if database error occurred and path was not
	 *                      updated.
	 */
	private void updateFilePath(CaseDbConnection connection, long objId, String path, TskData.EncodingType type) throws SQLException {
		PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.UPDATE_LOCAL_PATH);
		statement.clearParameters();
		statement.setString(1, path);
		statement.setInt(2, type.getType());
		statement.setLong(3, objId);
		connection.executeUpdate(statement);
	}

	/**
	 * Find all files by name and parent
	 *
	 * @param fileName   Pattern of the name of the file or directory to match
	 *                   (case insensitive, used in LIKE SQL statement).
	 * @param parentFile Object for parent file/directory to find children in
	 *
	 * @return a list of AbstractFile for files/directories whose name matches
	 *         fileName and that were inside a directory described by
	 *         parentFile.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public List<AbstractFile> findFilesInFolder(String fileName, AbstractFile parentFile) throws TskCoreException {
		String ext = "";
		if (!containsLikeWildcard(fileName)) {
			ext = SleuthkitCase.extractExtension(fileName);
		}

		CaseDbConnection connection = null;
		ResultSet rs = null;
		long parentId = parentFile.getId();

		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			PreparedStatement statement;
			if (ext.isEmpty()) {
				statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_FILES_BY_PARENT_AND_NAME);
				statement.clearParameters();
				statement.setLong(1, parentId);
				statement.setString(2, fileName);
			} else {
				statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_FILES_BY_EXTENSION_AND_PARENT_AND_NAME);
				statement.clearParameters();
				statement.setString(1, ext);
				statement.setLong(2, parentId);
				statement.setString(3, fileName);
			}

			rs = connection.executeQuery(statement);
			return resultSetToAbstractFiles(rs, connection);
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting AbstractFile children with name=" + fileName + " for Content parent with ID=" + parentFile.getId(), ex);
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Count files matching the specific Where clause
	 *
	 * @param sqlWhereClause a SQL where clause appropriate for the desired
	 *                       files (do not begin the WHERE clause with the word
	 *                       WHERE!)
	 *
	 * @return count of files each of which satisfy the given WHERE clause
	 *
	 * @throws TskCoreException \ref query_database_page
	 */
	public long countFilesWhere(String sqlWhereClause) throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT COUNT(*) AS count FROM tsk_files WHERE " + sqlWhereClause); //NON-NLS
			rs.next();
			return rs.getLong("count");
		} catch (SQLException e) {
			throw new TskCoreException("SQLException thrown when calling 'SleuthkitCase.countFilesWhere().", e);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Find and return list of all (abstract) files matching the specific Where
	 * clause. You need to know the database schema to use this, which is
	 * outlined on the
	 * <a href="http://wiki.sleuthkit.org/index.php?title=SQLite_Database_v3_Schema">wiki</a>.
	 * You should use enums from org.sleuthkit.datamodel.TskData to make the
	 * queries easier to maintain and understand.
	 *
	 * @param sqlWhereClause a SQL where clause appropriate for the desired
	 *                       files (do not begin the WHERE clause with the word
	 *                       WHERE!)
	 *
	 * @return a list of AbstractFile each of which satisfy the given WHERE
	 *         clause
	 *
	 * @throws TskCoreException \ref query_database_page
	 */
	public List<AbstractFile> findAllFilesWhere(String sqlWhereClause) throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT * FROM tsk_files WHERE " + sqlWhereClause); //NON-NLS
			return resultSetToAbstractFiles(rs, connection);
		} catch (SQLException e) {
			throw new TskCoreException("SQLException thrown when calling 'SleuthkitCase.findAllFilesWhere(): " + sqlWhereClause, e);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Find and return list of all (abstract) files matching the specific Where
	 * clause with the give parentId. You need to know the database schema to
	 * use this, which is outlined on the
	 * <a href="http://wiki.sleuthkit.org/index.php?title=SQLite_Database_v3_Schema">wiki</a>.
	 * You should use enums from org.sleuthkit.datamodel.TskData to make the
	 * queries easier to maintain and understand.
	 *
	 * @param parentId       The parentId
	 * @param sqlWhereClause a SQL where clause appropriate for the desired
	 *                       files (do not begin the WHERE clause with the word
	 *                       WHERE!)
	 *
	 * @return a list of AbstractFile each of which satisfy the given WHERE
	 *         clause
	 *
	 * @throws TskCoreException \ref query_database_page
	 */
	public List<AbstractFile> findAllFilesInFolderWhere(long parentId, String sqlWhereClause) throws TskCoreException {
		String queryTemplate = "SELECT tsk_files.* FROM tsk_files JOIN tsk_objects ON tsk_objects.obj_id = tsk_files.obj_id WHERE par_obj_id = %d AND %s";
		acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = connections.getConnection()) {
			String query = String.format(queryTemplate, parentId, sqlWhereClause);
			try (Statement s = connection.createStatement(); ResultSet rs = connection.executeQuery(s, query)) {
				return resultSetToAbstractFiles(rs, connection);
			} catch (SQLException ex) {
				throw new TskCoreException("SQLException thrown when calling 'SleuthkitCase.findAllFilesInFolderWhere(): " + query, ex);
			}
		} finally {
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Find and return list of all (abstract) ids of files matching the specific
	 * Where clause
	 *
	 * @param sqlWhereClause a SQL where clause appropriate for the desired
	 *                       files (do not begin the WHERE clause with the word
	 *                       WHERE!)
	 *
	 * @return a list of file ids each of which satisfy the given WHERE clause
	 *
	 * @throws TskCoreException \ref query_database_page
	 */
	public List<Long> findAllFileIdsWhere(String sqlWhereClause) throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT obj_id FROM tsk_files WHERE " + sqlWhereClause); //NON-NLS
			List<Long> ret = new ArrayList<>();
			while (rs.next()) {
				ret.add(rs.getLong("obj_id"));
			}
			return ret;
		} catch (SQLException e) {
			throw new TskCoreException("SQLException thrown when calling 'SleuthkitCase.findAllFileIdsWhere(): " + sqlWhereClause, e);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * @param dataSource the data source (Image, VirtualDirectory for file-sets,
	 *                   etc) to search for the given file name
	 * @param filePath   The full path to the file(s) of interest. This can
	 *                   optionally include the image and volume names. Treated
	 *                   in a case- insensitive manner.
	 *
	 * @return a list of AbstractFile that have the given file path.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public List<AbstractFile> openFiles(Content dataSource, String filePath) throws TskCoreException {

		// get the non-unique path (strip of image and volume path segments, if
		// the exist.
		String path = AbstractFile.createNonUniquePath(filePath).toLowerCase();

		// split the file name from the parent path
		int lastSlash = path.lastIndexOf('/'); //NON-NLS

		// if the last slash is at the end, strip it off
		if (lastSlash == path.length()) {
			path = path.substring(0, lastSlash - 1);
			lastSlash = path.lastIndexOf('/'); //NON-NLS
		}

		String parentPath = path.substring(0, lastSlash);
		String fileName = path.substring(lastSlash);

		return findFiles(dataSource, fileName, parentPath);
	}

	/**
	 * Get file layout ranges from tsk_file_layout, for a file with specified id
	 *
	 * @param id of the file to get file layout ranges for
	 *
	 * @return list of populated file ranges
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	public List<TskFileRange> getFileRanges(long id) throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT * FROM tsk_file_layout WHERE obj_id = " + id + " ORDER BY sequence");
			List<TskFileRange> ranges = new ArrayList<TskFileRange>();
			while (rs.next()) {
				TskFileRange range = new TskFileRange(rs.getLong("byte_start"), //NON-NLS
						rs.getLong("byte_len"), rs.getLong("sequence")); //NON-NLS
				ranges.add(range);
			}
			return ranges;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting TskFileLayoutRanges by id, id = " + id, ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get am image by the image object id
	 *
	 * @param id of the image object
	 *
	 * @return Image object populated
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	public Image getImageById(long id) throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT tsk_image_info.type, tsk_image_info.ssize, tsk_image_info.tzone, tsk_image_info.size, tsk_image_info.md5, tsk_image_info.sha1, tsk_image_info.sha256, tsk_image_info.display_name, data_source_info.device_id, tsk_image_names.name "
					+ "FROM tsk_image_info "
					+ "INNER JOIN data_source_info ON tsk_image_info.obj_id = data_source_info.obj_id "
					+ "LEFT JOIN tsk_image_names ON tsk_image_names.obj_id = data_source_info.obj_id "
					+ "WHERE tsk_image_info.obj_id = " + id); //NON-NLS

			List<String> imagePaths = new ArrayList<>();
			long type, ssize, size;
			String tzone, md5, sha1, sha256, name, device_id, imagePath;

			if (rs.next()) {
				imagePath = rs.getString("name");
				if (imagePath != null) {
					imagePaths.add(imagePath);
				}
				type = rs.getLong("type"); //NON-NLS
				ssize = rs.getLong("ssize"); //NON-NLS
				tzone = rs.getString("tzone"); //NON-NLS
				size = rs.getLong("size"); //NON-NLS
				md5 = rs.getString("md5"); //NON-NLS
				sha1 = rs.getString("sha1"); //NON-NLS
				sha256 = rs.getString("sha256"); //NON-NLS
				name = rs.getString("display_name");
				if (name == null) {
					if (imagePaths.size() > 0) {
						String path = imagePaths.get(0);
						name = (new java.io.File(path)).getName();
					} else {
						name = "";
					}
				}
				device_id = rs.getString("device_id");
			} else {
				throw new TskCoreException("No image found for id: " + id);
			}

			// image can have multiple paths, therefore there can be multiple rows in the result set
			while (rs.next()) {
				imagePath = rs.getString("name");
				if (imagePath != null) {
					imagePaths.add(imagePath);
				}
			}

			return new Image(this, id, type, device_id, ssize, name,
					imagePaths.toArray(new String[imagePaths.size()]), tzone, md5, sha1, sha256, size);
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Image by id, id = " + id, ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get a volume system by the volume system object id
	 *
	 * @param id     id of the volume system
	 * @param parent image containing the volume system
	 *
	 * @return populated VolumeSystem object
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	VolumeSystem getVolumeSystemById(long id, Content parent) throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT * FROM tsk_vs_info " //NON-NLS
					+ "where obj_id = " + id); //NON-NLS
			if (rs.next()) {
				long type = rs.getLong("vs_type"); //NON-NLS
				long imgOffset = rs.getLong("img_offset"); //NON-NLS
				long blockSize = rs.getLong("block_size"); //NON-NLS
				VolumeSystem vs = new VolumeSystem(this, id, "", type, imgOffset, blockSize);
				vs.setParent(parent);
				return vs;
			} else {
				throw new TskCoreException("No volume system found for id:" + id);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Volume System by ID.", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * @param id       ID of the desired VolumeSystem
	 * @param parentId ID of the VolumeSystem's parent
	 *
	 * @return the VolumeSystem with the given ID
	 *
	 * @throws TskCoreException
	 */
	VolumeSystem getVolumeSystemById(long id, long parentId) throws TskCoreException {
		VolumeSystem vs = getVolumeSystemById(id, null);
		vs.setParentId(parentId);
		return vs;
	}

	/**
	 * Get a file system by the object id
	 *
	 * @param id     of the filesystem
	 * @param parent parent Image of the file system
	 *
	 * @return populated FileSystem object
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	FileSystem getFileSystemById(long id, Image parent) throws TskCoreException {
		return getFileSystemByIdHelper(id, parent);
	}

	/**
	 * @param id       ID of the desired FileSystem
	 * @param parentId ID of the FileSystem's parent
	 *
	 * @return the desired FileSystem
	 *
	 * @throws TskCoreException
	 */
	FileSystem getFileSystemById(long id, long parentId) throws TskCoreException {
		Volume vol = null;
		FileSystem fs = getFileSystemById(id, vol);
		fs.setParentId(parentId);
		return fs;
	}

	/**
	 * Get a file system by the object id
	 *
	 * @param id     of the filesystem
	 * @param parent parent Volume of the file system
	 *
	 * @return populated FileSystem object
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	FileSystem getFileSystemById(long id, Volume parent) throws TskCoreException {
		return getFileSystemByIdHelper(id, parent);
	}

	/**
	 * Get a pool by the object id
	 *
	 * @param id     of the pool
	 * @param parent parent of the pool (image or volume)
	 *
	 * @return populated Pool object
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	Pool getPoolById(long id, Content parent) throws TskCoreException {
		return getPoolByIdHelper(id, parent);
	}

	/**
	 * @param id       ID of the desired Volume
	 * @param parentId ID of the Volume's parent
	 *
	 * @return the desired Volume
	 *
	 * @throws TskCoreException
	 */
	Pool getPoolById(long id, long parentId) throws TskCoreException {
		Pool pool = getPoolById(id, null);
		pool.setParentId(parentId);
		return pool;
	}

	/**
	 * Get pool by id and Content parent
	 *
	 * @param id     of the pool to get
	 * @param parent a direct parent Content object
	 *
	 * @return populated FileSystem object
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	private Pool getPoolByIdHelper(long id, Content parent) throws TskCoreException {

		acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = connections.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, "SELECT * FROM tsk_pool_info " //NON-NLS
						+ "where obj_id = " + id);) { //NON-NLS
			if (rs.next()) {
				Pool pool = new Pool(this, rs.getLong("obj_id"), TskData.TSK_POOL_TYPE_ENUM.valueOf(rs.getLong("pool_type")).getName(), rs.getLong("pool_type"));
				pool.setParent(parent);

				return pool;
			} else {
				throw new TskCoreException("No pool found for ID:" + id);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Pool by ID", ex);
		} finally {
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get file system by id and Content parent
	 *
	 * @param id     of the filesystem to get
	 * @param parent a direct parent Content object
	 *
	 * @return populated FileSystem object
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	private FileSystem getFileSystemByIdHelper(long id, Content parent) throws TskCoreException {
		// see if we already have it
		// @@@ NOTE: this is currently kind of bad in that we are ignoring the parent value,
		// but it should be the same...
		synchronized (fileSystemIdMap) {
			if (fileSystemIdMap.containsKey(id)) {
				return fileSystemIdMap.get(id);
			}
		}
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT * FROM tsk_fs_info " //NON-NLS
					+ "where obj_id = " + id); //NON-NLS
			if (rs.next()) {
				TskData.TSK_FS_TYPE_ENUM fsType = TskData.TSK_FS_TYPE_ENUM.valueOf(rs.getInt("fs_type")); //NON-NLS
				FileSystem fs = new FileSystem(this, rs.getLong("obj_id"), "", rs.getLong("img_offset"), //NON-NLS
						fsType, rs.getLong("block_size"), rs.getLong("block_count"), //NON-NLS
						rs.getLong("root_inum"), rs.getLong("first_inum"), rs.getLong("last_inum")); //NON-NLS
				fs.setParent(parent);
				// save it for the next call
				synchronized (fileSystemIdMap) {
					fileSystemIdMap.put(id, fs);
				}
				return fs;
			} else {
				throw new TskCoreException("No file system found for id:" + id);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting File System by ID", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get volume by id
	 *
	 * @param id
	 * @param parent volume system
	 *
	 * @return populated Volume object
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	Volume getVolumeById(long id, VolumeSystem parent) throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT * FROM tsk_vs_parts " //NON-NLS
					+ "where obj_id = " + id); //NON-NLS
			if (rs.next()) {
				/**
				 * TODO!! LANDMINE!! This allows the two types of databases to
				 * have slightly different schemas. SQLite uses desc as the
				 * column name in tsk_vs_parts and Postgres uses descr, as desc
				 * is a reserved keyword in Postgres. When we have to make a
				 * schema change, be sure to change this over to just one name.
				 */
				String description;
				try {
					description = rs.getString("desc");
				} catch (Exception ex) {
					description = rs.getString("descr");
				}
				Volume vol = new Volume(this, rs.getLong("obj_id"), rs.getLong("addr"), //NON-NLS
						rs.getLong("start"), rs.getLong("length"), rs.getLong("flags"), //NON-NLS
						description);
				vol.setParent(parent);
				return vol;
			} else {
				throw new TskCoreException("No volume found for id:" + id);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Volume by ID", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * @param id       ID of the desired Volume
	 * @param parentId ID of the Volume's parent
	 *
	 * @return the desired Volume
	 *
	 * @throws TskCoreException
	 */
	Volume getVolumeById(long id, long parentId) throws TskCoreException {
		Volume vol = getVolumeById(id, null);
		vol.setParentId(parentId);
		return vol;
	}

	/**
	 * Get a directory by id
	 *
	 * @param id       of the directory object
	 * @param parentFs parent file system
	 *
	 * @return populated Directory object
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	Directory getDirectoryById(long id, FileSystem parentFs) throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT * FROM tsk_files " //NON-NLS
					+ "WHERE obj_id = " + id);
			Directory temp = null; //NON-NLS
			if (rs.next()) {
				final short type = rs.getShort("type"); //NON-NLS
				if (type == TSK_DB_FILES_TYPE_ENUM.FS.getFileType()) {
					if (rs.getShort("meta_type") == TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR.getValue()
							|| rs.getShort("meta_type") == TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_VIRT_DIR.getValue()) { //NON-NLS
						temp = directory(rs, parentFs);
					}
				} else if (type == TSK_DB_FILES_TYPE_ENUM.VIRTUAL_DIR.getFileType()) {
					throw new TskCoreException("Expecting an FS-type directory, got virtual, id: " + id);
				}
			} else {
				throw new TskCoreException("No Directory found for id:" + id);
			}
			return temp;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Directory by ID", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Helper to return FileSystems in an Image
	 *
	 * @param image Image to lookup FileSystem for
	 *
	 * @return Collection of FileSystems in the image
	 *
	 * @throws TskCoreException
	 */
	public Collection<FileSystem> getImageFileSystems(Image image) throws TskCoreException {
		List<FileSystem> fileSystems = new ArrayList<>();
		String queryStr = "SELECT * FROM tsk_fs_info WHERE data_source_obj_id = " + image.getId();

		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, queryStr); //NON-NLS
			while (rs.next()) {
				TskData.TSK_FS_TYPE_ENUM fsType = TskData.TSK_FS_TYPE_ENUM.valueOf(rs.getInt("fs_type")); //NON-NLS
				FileSystem fs = new FileSystem(this, rs.getLong("obj_id"), "", rs.getLong("img_offset"), //NON-NLS
						fsType, rs.getLong("block_size"), rs.getLong("block_count"), //NON-NLS
						rs.getLong("root_inum"), rs.getLong("first_inum"), rs.getLong("last_inum")); //NON-NLS
				fs.setParent(null);
				fileSystems.add(fs);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error looking up files systems. Query: " + queryStr, ex); //NON-NLS
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
		return fileSystems;
	}

	/**
	 * Returns the list of direct children for a given Image
	 *
	 * @param img image to get children for
	 *
	 * @return list of Contents (direct image children)
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	List<Content> getImageChildren(Image img) throws TskCoreException {
		Collection<ObjectInfo> childInfos = getChildrenInfo(img);
		List<Content> children = new ArrayList<Content>();
		for (ObjectInfo info : childInfos) {
			if (null != info.type) {
				switch (info.type) {
					case VS:
						children.add(getVolumeSystemById(info.id, img));
						break;
					case POOL:
						children.add(getPoolById(info.id, img));
						break;
					case FS:
						children.add(getFileSystemById(info.id, img));
						break;
					case ABSTRACTFILE:
						AbstractFile f = getAbstractFileById(info.id);
						if (f != null) {
							children.add(f);
						}
						break;
					case ARTIFACT:
						BlackboardArtifact art = getArtifactById(info.id);
						if (art != null) {
							children.add(art);
						}
						break;
					case REPORT:
						// Do nothing for now - see JIRA-3673
						break;
					default:
						throw new TskCoreException("Image has child of invalid type: " + info.type);
				}
			}
		}
		return children;
	}

	/**
	 * Returns the list of direct children IDs for a given Image
	 *
	 * @param img image to get children for
	 *
	 * @return list of IDs (direct image children)
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	List<Long> getImageChildrenIds(Image img) throws TskCoreException {
		Collection<ObjectInfo> childInfos = getChildrenInfo(img);
		List<Long> children = new ArrayList<Long>();
		for (ObjectInfo info : childInfos) {
			if (info.type == ObjectType.VS
					|| info.type == ObjectType.POOL
					|| info.type == ObjectType.FS
					|| info.type == ObjectType.ABSTRACTFILE
					|| info.type == ObjectType.ARTIFACT) {
				children.add(info.id);
			} else if (info.type == ObjectType.REPORT) {
				// Do nothing for now - see JIRA-3673
			} else {
				throw new TskCoreException("Image has child of invalid type: " + info.type);
			}
		}
		return children;
	}

	/**
	 * Returns the list of direct children for a given Pool
	 *
	 * @param pool pool to get children for
	 *
	 * @return list of pool children objects
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	List<Content> getPoolChildren(Pool pool) throws TskCoreException {
		Collection<ObjectInfo> childInfos = getChildrenInfo(pool);
		List<Content> children = new ArrayList<Content>();
		for (ObjectInfo info : childInfos) {
			if (null != info.type) {
				switch (info.type) {
					case VS:
						children.add(getVolumeSystemById(info.id, pool));
						break;
					case ABSTRACTFILE:
						AbstractFile f = getAbstractFileById(info.id);
						if (f != null) {
							children.add(f);
						}
						break;
					case ARTIFACT:
						BlackboardArtifact art = getArtifactById(info.id);
						if (art != null) {
							children.add(art);
						}
						break;
					default:
						throw new TskCoreException("Pool has child of invalid type: " + info.type);
				}
			}
		}
		return children;
	}

	/**
	 * Returns the list of direct children IDs for a given Pool
	 *
	 * @param pool pool to get children for
	 *
	 * @return list of pool children IDs
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	List<Long> getPoolChildrenIds(Pool pool) throws TskCoreException {
		Collection<ObjectInfo> childInfos = getChildrenInfo(pool);
		List<Long> children = new ArrayList<Long>();
		for (ObjectInfo info : childInfos) {
			if (info.type == ObjectType.VS || info.type == ObjectType.ABSTRACTFILE || info.type == ObjectType.ARTIFACT) {
				children.add(info.id);
			} else {
				throw new TskCoreException("Pool has child of invalid type: " + info.type);
			}
		}
		return children;
	}

	/**
	 * Returns the list of direct children for a given VolumeSystem
	 *
	 * @param vs volume system to get children for
	 *
	 * @return list of volume system children objects
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	List<Content> getVolumeSystemChildren(VolumeSystem vs) throws TskCoreException {
		Collection<ObjectInfo> childInfos = getChildrenInfo(vs);
		List<Content> children = new ArrayList<Content>();
		for (ObjectInfo info : childInfos) {
			if (null != info.type) {
				switch (info.type) {
					case VOL:
						children.add(getVolumeById(info.id, vs));
						break;
					case ABSTRACTFILE:
						AbstractFile f = getAbstractFileById(info.id);
						if (f != null) {
							children.add(f);
						}
						break;
					case ARTIFACT:
						BlackboardArtifact art = getArtifactById(info.id);
						if (art != null) {
							children.add(art);
						}
						break;
					default:
						throw new TskCoreException("VolumeSystem has child of invalid type: " + info.type);
				}
			}
		}
		return children;
	}

	/**
	 * Returns the list of direct children IDs for a given VolumeSystem
	 *
	 * @param vs volume system to get children for
	 *
	 * @return list of volume system children IDs
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	List<Long> getVolumeSystemChildrenIds(VolumeSystem vs) throws TskCoreException {
		Collection<ObjectInfo> childInfos = getChildrenInfo(vs);
		List<Long> children = new ArrayList<Long>();
		for (ObjectInfo info : childInfos) {
			if (info.type == ObjectType.VOL || info.type == ObjectType.ABSTRACTFILE || info.type == ObjectType.ARTIFACT) {
				children.add(info.id);
			} else {
				throw new TskCoreException("VolumeSystem has child of invalid type: " + info.type);
			}
		}
		return children;
	}

	/**
	 * Returns a list of direct children for a given Volume
	 *
	 * @param vol volume to get children of
	 *
	 * @return list of Volume children
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	List<Content> getVolumeChildren(Volume vol) throws TskCoreException {
		Collection<ObjectInfo> childInfos = getChildrenInfo(vol);
		List<Content> children = new ArrayList<Content>();
		for (ObjectInfo info : childInfos) {
			if (null != info.type) {
				switch (info.type) {
					case POOL:
						children.add(getPoolById(info.id, vol));
						break;
					case FS:
						children.add(getFileSystemById(info.id, vol));
						break;
					case ABSTRACTFILE:
						AbstractFile f = getAbstractFileById(info.id);
						if (f != null) {
							children.add(f);
						}
						break;
					case ARTIFACT:
						BlackboardArtifact art = getArtifactById(info.id);
						if (art != null) {
							children.add(art);
						}
						break;
					default:
						throw new TskCoreException("Volume has child of invalid type: " + info.type);
				}
			}
		}
		return children;
	}

	/**
	 * Returns a list of direct children IDs for a given Volume
	 *
	 * @param vol volume to get children of
	 *
	 * @return list of Volume children IDs
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	List<Long> getVolumeChildrenIds(Volume vol) throws TskCoreException {
		final Collection<ObjectInfo> childInfos = getChildrenInfo(vol);
		final List<Long> children = new ArrayList<Long>();
		for (ObjectInfo info : childInfos) {
			if (info.type == ObjectType.FS || info.type == ObjectType.ABSTRACTFILE || info.type == ObjectType.ARTIFACT) {
				children.add(info.id);
			} else {
				throw new TskCoreException("Volume has child of invalid type: " + info.type);
			}
		}
		return children;
	}

	/**
	 * Adds an image to the case database.
	 *
	 * @param deviceObjId    The object id of the device associated with the
	 *                       image.
	 * @param imageFilePaths The image file paths.
	 * @param timeZone       The time zone for the image.
	 *
	 * @return An Image object.
	 *
	 * @throws TskCoreException if there is an error adding the image to case
	 *                          database.
	 */
	public Image addImageInfo(long deviceObjId, List<String> imageFilePaths, String timeZone) throws TskCoreException {
		return addImageInfo(deviceObjId, imageFilePaths, timeZone, null);
	}

	/**
	 * Adds an image to the case database.
	 *
	 * @param deviceObjId    The object id of the device associated with the
	 *                       image.
	 * @param imageFilePaths The image file paths.
	 * @param timeZone       The time zone for the image.
	 * @param host           The host for this image.
	 *
	 * @return An Image object.
	 *
	 * @throws TskCoreException if there is an error adding the image to case
	 *                          database.
	 */
	public Image addImageInfo(long deviceObjId, List<String> imageFilePaths, String timeZone, Host host) throws TskCoreException {
		return addImageInfo(deviceObjId, imageFilePaths, timeZone, host, null);
	}
	

	/**
	 * Adds an image to the case database.
	 *
	 * @param deviceObjId    The object id of the device associated with the
	 *                       image.
	 * @param imageFilePaths The image file paths.
	 * @param timeZone       The time zone for the image.
	 * @param host           The host for this image.
	 * @param password       The password to decrypt the image or null.
	 *
	 * @return An Image object.
	 *
	 * @throws TskCoreException if there is an error adding the image to case
	 *                          database.
	 */
	@Beta
	public Image addImageInfo(long deviceObjId, List<String> imageFilePaths, String timeZone, Host host, String password) throws TskCoreException {
		long imageId = this.caseHandle.addImageInfo(deviceObjId, imageFilePaths, timeZone, host, password, this);
		return getImageById(imageId);
	}

	/**
	 * Returns a map of image object IDs to a list of fully qualified file paths
	 * for that image
	 *
	 * @return map of image object IDs to file paths
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	public Map<Long, List<String>> getImagePaths() throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s1 = null;
		ResultSet rs1 = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s1 = connection.createStatement();
			rs1 = connection.executeQuery(s1, "SELECT tsk_image_info.obj_id, tsk_image_names.name FROM tsk_image_info "
					+ "LEFT JOIN tsk_image_names ON tsk_image_info.obj_id = tsk_image_names.obj_id"); //NON-NLS
			Map<Long, List<String>> imgPaths = new LinkedHashMap<Long, List<String>>();
			while (rs1.next()) {
				long obj_id = rs1.getLong("obj_id"); //NON-NLS
				String name = rs1.getString("name"); //NON-NLS
				List<String> imagePaths = imgPaths.get(obj_id);
				if (imagePaths == null) {
					List<String> paths = new ArrayList<String>();
					if (name != null) {
						paths.add(name);
					}
					imgPaths.put(obj_id, paths);
				} else {
					if (name != null) {
						imagePaths.add(name);
					}
				}
			}
			return imgPaths;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting image paths.", ex);
		} finally {
			closeResultSet(rs1);
			closeStatement(s1);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Returns a list of fully qualified file paths based on an image object ID.
	 *
	 * @param objectId   The object id of the data source.
	 * @param connection Database connection to use.
	 *
	 * @return List of file paths.
	 *
	 * @throws TskCoreException Thrown if a critical error occurred within tsk
	 *                          core
	 */
	private List<String> getImagePathsById(long objectId, CaseDbConnection connection) throws TskCoreException {
		List<String> imagePaths = new ArrayList<>();
		acquireSingleUserCaseReadLock();
		Statement statement = null;
		ResultSet resultSet = null;
		try {
			statement = connection.createStatement();
			resultSet = connection.executeQuery(statement, "SELECT name FROM tsk_image_names WHERE tsk_image_names.obj_id = " + objectId); //NON-NLS
			while (resultSet.next()) {
				imagePaths.add(resultSet.getString("name"));
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting image names with obj_id = %d", objectId), ex);
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			releaseSingleUserCaseReadLock();
		}

		return imagePaths;
	}

	/**
	 * @return a collection of Images associated with this instance of
	 *         SleuthkitCase
	 *
	 * @throws TskCoreException
	 */
	public List<Image> getImages() throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT obj_id FROM tsk_image_info"); //NON-NLS
			Collection<Long> imageIDs = new ArrayList<Long>();
			while (rs.next()) {
				imageIDs.add(rs.getLong("obj_id")); //NON-NLS
			}
			List<Image> images = new ArrayList<Image>();
			for (long id : imageIDs) {
				images.add(getImageById(id));
			}
			return images;
		} catch (SQLException ex) {
			throw new TskCoreException("Error retrieving images.", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Set the file paths for the image given by obj_id
	 *
	 * @param obj_id the ID of the image to update
	 * @param paths  the fully qualified path to the files that make up the
	 *               image
	 *
	 * @throws TskCoreException exception thrown when critical error occurs
	 *                          within tsk core and the update fails
	 */
	public void setImagePaths(long obj_id, List<String> paths) throws TskCoreException {
		CaseDbTransaction transaction = beginTransaction();
		try {
			setImagePaths(obj_id, paths, transaction);
			transaction.commit();
			transaction = null;
		} finally {
			if (transaction != null) {
				transaction.rollback();
			}
		}
	}
	
	/**
	 * Set the file paths for the image given by obj_id
	 *
	 * @param obj_id the ID of the image to update
	 * @param paths  the fully qualified path to the files that make up the
	 *               image
	 * @param trans  The case database transaction.
	 *
	 * @throws TskCoreException exception thrown when critical error occurs
	 *                          within tsk core and the update fails
	 */
	@Beta
	public void setImagePaths(long objId, List<String> paths, CaseDbTransaction trans) throws TskCoreException {	
		try {
			PreparedStatement statement = trans.getConnection().getPreparedStatement(PREPARED_STATEMENT.DELETE_IMAGE_NAME);
			statement.clearParameters();
			statement.setLong(1, objId);
			trans.getConnection().executeUpdate(statement);
			for (int i = 0; i < paths.size(); i++) {
				statement = trans.getConnection().getPreparedStatement(PREPARED_STATEMENT.INSERT_IMAGE_NAME);
				statement.clearParameters();
				statement.setLong(1, objId);
				statement.setString(2, paths.get(i));
				statement.setLong(3, i);
				trans.getConnection().executeUpdate(statement);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error updating image paths.", ex);
		} 
	}
	
	
	/**
	 * Deletes a datasource from the open case, the database has foreign keys
	 * with a delete cascade so that all the tables that have a datasource
	 * object id will have their data deleted. This is private to keep it out of
	 * the public API
	 *
	 * @param dataSourceObjectId the id of the datasource to be deleted
	 *
	 * @throws TskCoreException exception thrown when critical error occurs
	 *                          within tsk core and the update fails
	 */
	void deleteDataSource(long dataSourceObjectId) throws TskCoreException {

		// Check if this data source is the only one associated with its host. If so,
		// we will delete the host and other associated data.
		// Note that the cascading deletes were only added in schema 9.1, so we
		// would get an error trying to delete a host from older cases.
		Host hostToDelete = null;
		VersionNumber version = getDBSchemaCreationVersion();
		int major = version.getMajor();
		int minor = version.getMinor();
		if (major > 9 || (major == 9 && minor >= 1)) {
			hostToDelete = getHostManager().getHostByDataSource(dataSourceObjectId);
			if (getHostManager().getDataSourcesForHost(hostToDelete).size() != 1) {
				hostToDelete = null;
			}
		}

		CaseDbConnection connection = null;
		Statement statement;
		acquireSingleUserCaseWriteLock();
		try {
			connection = connections.getConnection();
			statement = connection.createStatement();
			connection.beginTransaction();
			// The following delete(s) uses a foreign key delete with cascade in the DB so that it will delete
			// all associated rows from tsk_object and its children.  For large data sources this may take some time.
			statement.execute("DELETE FROM tsk_objects WHERE obj_id = " + dataSourceObjectId);
			// The following delete uses a foreign key delete with cascade in the DB so that it will delete all
			// associated rows from accounts table and its children.
			String accountSql = "DELETE FROM accounts WHERE account_id in (SELECT account_id FROM accounts "
					+ "WHERE account_id NOT IN (SELECT account1_id FROM account_relationships) "
					+ "AND account_id NOT IN (SELECT account2_id FROM account_relationships))";
			statement.execute(accountSql);

			// Now delete any host that was only associated with this data source. This will cascade to delete
			// realms, os accounts, and os account attributes that were associated with the host.
			if (hostToDelete != null) {
				statement.execute("DELETE FROM tsk_hosts WHERE id = " + hostToDelete.getHostId());

				// Clean up any stray OS Account objects
				String deleteOsAcctObjectsQuery = "DELETE FROM tsk_objects "
						+ "WHERE type=" + TskData.ObjectType.OS_ACCOUNT.getObjectType() + " "
						+ "AND obj_id NOT IN (SELECT os_account_obj_id FROM tsk_os_accounts WHERE  os_account_obj_id IS NOT NULL)";
				statement.execute(deleteOsAcctObjectsQuery);
			}

			connection.commitTransaction();
		} catch (SQLException ex) {
			rollbackTransaction(connection);
			throw new TskCoreException("Error deleting data source.", ex);
		} finally {
			closeConnection(connection);
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Creates file object from a SQL query result set of rows from the
	 * tsk_files table. Assumes that the query was of the form "SELECT * FROM
	 * tsk_files WHERE XYZ".
	 *
	 * @param rs ResultSet to get content from. Caller is responsible for
	 *           closing it.
	 *
	 * @return list of file objects from tsk_files table containing the files
	 *
	 * @throws SQLException if the query fails
	 */
	/**
	 * Creates AbstractFile objects for the result set of a tsk_files table
	 * query of the form "SELECT * FROM tsk_files WHERE XYZ".
	 *
	 * @param rs         A result set from a query of the tsk_files table of the
	 *                   form "SELECT * FROM tsk_files WHERE XYZ".
	 * @param connection A case database connection.
	 *
	 * @return A list of AbstractFile objects.
	 *
	 * @throws SQLException Thrown if there is a problem iterating through the
	 *                      record set.
	 */
	List<AbstractFile> resultSetToAbstractFiles(ResultSet rs, CaseDbConnection connection) throws SQLException {
		ArrayList<AbstractFile> results = new ArrayList<AbstractFile>();
		try {
			while (rs.next()) {
				final short type = rs.getShort("type"); //NON-NLS
				if (type == TSK_DB_FILES_TYPE_ENUM.FS.getFileType()
						&& (rs.getShort("meta_type") != TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_VIRT_DIR.getValue())) {
					FsContent result;
					if (rs.getShort("meta_type") == TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR.getValue()) { //NON-NLS
						result = directory(rs, null);
					} else {
						result = file(rs, null);
					}
					results.add(result);
				} else if (type == TSK_DB_FILES_TYPE_ENUM.VIRTUAL_DIR.getFileType()
						|| (rs.getShort("meta_type") == TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_VIRT_DIR.getValue())) { //NON-NLS
					final VirtualDirectory virtDir = virtualDirectory(rs, connection);
					results.add(virtDir);
				} else if (type == TSK_DB_FILES_TYPE_ENUM.LOCAL_DIR.getFileType()) {
					final LocalDirectory localDir = localDirectory(rs);
					results.add(localDir);
				} else if (type == TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS.getFileType()
						|| type == TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS.getFileType()
						|| type == TSK_DB_FILES_TYPE_ENUM.CARVED.getFileType()
						|| type == TSK_DB_FILES_TYPE_ENUM.LAYOUT_FILE.getFileType()) {
					TSK_DB_FILES_TYPE_ENUM atype = TSK_DB_FILES_TYPE_ENUM.valueOf(type);
					String parentPath = rs.getString("parent_path"); //NON-NLS
					if (parentPath == null) {
						parentPath = "/"; //NON-NLS
					}

					Long osAccountObjId = rs.getLong("os_account_obj_id");
					if (rs.wasNull()) {
						osAccountObjId = null;
					}

					LayoutFile lf = new LayoutFile(this,
							rs.getLong("obj_id"), //NON-NLS
							rs.getLong("data_source_obj_id"),
							rs.getLong("fs_obj_id"),
							rs.getString("name"), //NON-NLS
							atype,
							TSK_FS_NAME_TYPE_ENUM.valueOf(rs.getShort("dir_type")), TSK_FS_META_TYPE_ENUM.valueOf(rs.getShort("meta_type")), //NON-NLS
							TSK_FS_NAME_FLAG_ENUM.valueOf(rs.getShort("dir_flags")), rs.getShort("meta_flags"), //NON-NLS
							rs.getLong("size"), //NON-NLS
							rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"), //NON-NLS
							rs.getString("md5"), rs.getString("sha256"), rs.getString("sha1"),
							FileKnown.valueOf(rs.getByte("known")), parentPath,
							rs.getString("mime_type"),
							rs.getString("owner_uid"), osAccountObjId); //NON-NLS
					results.add(lf);
				} else if (type == TSK_DB_FILES_TYPE_ENUM.DERIVED.getFileType()) {
					final DerivedFile df;
					df = derivedFile(rs, connection, AbstractContent.UNKNOWN_ID);
					results.add(df);
				} else if (type == TSK_DB_FILES_TYPE_ENUM.LOCAL.getFileType()) {
					final LocalFile lf;
					lf = localFile(rs, connection, AbstractContent.UNKNOWN_ID);
					results.add(lf);
				} else if (type == TSK_DB_FILES_TYPE_ENUM.SLACK.getFileType()) {
					final SlackFile sf = slackFile(rs, null);
					results.add(sf);
				}
			} //end for each resultSet
		} catch (SQLException e) {
			logger.log(Level.SEVERE, "Error getting abstract files from result set", e); //NON-NLS
		}

		return results;
	}

	// This following methods generate AbstractFile objects from a ResultSet
	/**
	 * Create a File object from the result set containing query results on
	 * tsk_files table
	 *
	 * @param rs the result set
	 * @param fs parent file system
	 *
	 * @return a newly create File
	 *
	 * @throws SQLException
	 */
	org.sleuthkit.datamodel.File file(ResultSet rs, FileSystem fs) throws SQLException {
		Long osAccountObjId = rs.getLong("os_account_obj_id");
		if (rs.wasNull()) {
			osAccountObjId = null;
		}

		org.sleuthkit.datamodel.File f = new org.sleuthkit.datamodel.File(this, rs.getLong("obj_id"), //NON-NLS
				rs.getLong("data_source_obj_id"), rs.getLong("fs_obj_id"), //NON-NLS
				TskData.TSK_FS_ATTR_TYPE_ENUM.valueOf(rs.getShort("attr_type")), //NON-NLS
				rs.getInt("attr_id"), rs.getString("name"), rs.getLong("meta_addr"), rs.getInt("meta_seq"), //NON-NLS
				TSK_FS_NAME_TYPE_ENUM.valueOf(rs.getShort("dir_type")), //NON-NLS
				TSK_FS_META_TYPE_ENUM.valueOf(rs.getShort("meta_type")), //NON-NLS
				TSK_FS_NAME_FLAG_ENUM.valueOf(rs.getShort("dir_flags")), //NON-NLS
				rs.getShort("meta_flags"), rs.getLong("size"), //NON-NLS
				rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"), //NON-NLS
				(short) rs.getInt("mode"), rs.getInt("uid"), rs.getInt("gid"), //NON-NLS
				rs.getString("md5"), rs.getString("sha256"), rs.getString("sha1"), 
				FileKnown.valueOf(rs.getByte("known")), //NON-NLS
				rs.getString("parent_path"), rs.getString("mime_type"), rs.getString("extension"), rs.getString("owner_uid"), 
				osAccountObjId, TskData.CollectedStatus.valueOf(rs.getInt("collected")), Collections.emptyList()); //NON-NLS
		f.setFileSystem(fs);
		return f;
	}

	/**
	 * Create a Directory object from the result set containing query results on
	 * tsk_files table
	 *
	 * @param rs the result set
	 * @param fs parent file system
	 *
	 * @return a newly created Directory object
	 *
	 * @throws SQLException thrown if SQL error occurred
	 */
	Directory directory(ResultSet rs, FileSystem fs) throws SQLException {
		Long osAccountObjId = rs.getLong("os_account_obj_id");
		if (rs.wasNull()) {
			osAccountObjId = null;
		}

		Directory dir = new Directory(this, rs.getLong("obj_id"), rs.getLong("data_source_obj_id"), rs.getLong("fs_obj_id"), //NON-NLS
				TskData.TSK_FS_ATTR_TYPE_ENUM.valueOf(rs.getShort("attr_type")), //NON-NLS
				rs.getInt("attr_id"), rs.getString("name"), rs.getLong("meta_addr"), rs.getInt("meta_seq"), //NON-NLS
				TSK_FS_NAME_TYPE_ENUM.valueOf(rs.getShort("dir_type")), //NON-NLS
				TSK_FS_META_TYPE_ENUM.valueOf(rs.getShort("meta_type")), //NON-NLS
				TSK_FS_NAME_FLAG_ENUM.valueOf(rs.getShort("dir_flags")), //NON-NLS
				rs.getShort("meta_flags"), rs.getLong("size"), //NON-NLS
				rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"), //NON-NLS
				rs.getShort("mode"), rs.getInt("uid"), rs.getInt("gid"), //NON-NLS
				rs.getString("md5"), rs.getString("sha256"), rs.getString("sha1"), 
				FileKnown.valueOf(rs.getByte("known")), //NON-NLS
				rs.getString("parent_path"), rs.getString("owner_uid"), osAccountObjId); //NON-NLS
		dir.setFileSystem(fs);
		return dir;
	}

	/**
	 * Create a virtual directory object from a result set.
	 *
	 * @param rs         the result set.
	 * @param connection The case database connection.
	 *
	 * @return newly created VirtualDirectory object.
	 *
	 * @throws SQLException
	 */
	VirtualDirectory virtualDirectory(ResultSet rs, CaseDbConnection connection) throws SQLException {
		String parentPath = rs.getString("parent_path"); //NON-NLS
		if (parentPath == null) {
			parentPath = "";
		}

		long objId = rs.getLong("obj_id");
		long dsObjId = rs.getLong("data_source_obj_id");
		if (objId == dsObjId) {	// virtual directory is a data source

			String deviceId = "";
			String timeZone = "";
			Statement s = null;
			ResultSet rsDataSourceInfo = null;

			acquireSingleUserCaseReadLock();
			try {
				s = connection.createStatement();
				rsDataSourceInfo = connection.executeQuery(s, "SELECT device_id, time_zone FROM data_source_info WHERE obj_id = " + objId);
				if (rsDataSourceInfo.next()) {
					deviceId = rsDataSourceInfo.getString("device_id");
					timeZone = rsDataSourceInfo.getString("time_zone");
				}
			} catch (SQLException ex) {
				logger.log(Level.SEVERE, "Error data source info for datasource id " + objId, ex); //NON-NLS
			} finally {
				closeResultSet(rsDataSourceInfo);
				closeStatement(s);
				releaseSingleUserCaseReadLock();
			}

			return new LocalFilesDataSource(this,
					objId, dsObjId,
					deviceId,
					rs.getString("name"),
					TSK_FS_NAME_TYPE_ENUM.valueOf(rs.getShort("dir_type")), //NON-NLS
					TSK_FS_META_TYPE_ENUM.valueOf(rs.getShort("meta_type")), //NON-NLS
					TSK_FS_NAME_FLAG_ENUM.valueOf(rs.getShort("dir_flags")),
					rs.getShort("meta_flags"),
					timeZone,
					rs.getString("md5"),
					rs.getString("sha256"),
					rs.getString("sha1"),
					FileKnown.valueOf(rs.getByte("known")),
					parentPath);
		} else {
			final VirtualDirectory vd = new VirtualDirectory(this,
					objId, dsObjId,
					rs.getLong("fs_obj_id"),
					rs.getString("name"), //NON-NLS
					TSK_FS_NAME_TYPE_ENUM.valueOf(rs.getShort("dir_type")), //NON-NLS
					TSK_FS_META_TYPE_ENUM.valueOf(rs.getShort("meta_type")), //NON-NLS
					TSK_FS_NAME_FLAG_ENUM.valueOf(rs.getShort("dir_flags")), //NON-NLS
					rs.getShort("meta_flags"), rs.getString("md5"), rs.getString("sha256"), rs.getString("sha1"), //NON-NLS
					FileKnown.valueOf(rs.getByte("known")), parentPath); //NON-NLS
			return vd;
		}
	}

	/**
	 * Create a virtual directory object from a result set
	 *
	 * @param rs the result set
	 *
	 * @return newly created VirtualDirectory object
	 *
	 * @throws SQLException
	 */
	LocalDirectory localDirectory(ResultSet rs) throws SQLException {
		String parentPath = rs.getString("parent_path"); //NON-NLS
		if (parentPath == null) {
			parentPath = "";
		}
		final LocalDirectory ld = new LocalDirectory(this, rs.getLong("obj_id"), //NON-NLS
				rs.getLong("data_source_obj_id"), rs.getString("name"), //NON-NLS
				TSK_FS_NAME_TYPE_ENUM.valueOf(rs.getShort("dir_type")), //NON-NLS
				TSK_FS_META_TYPE_ENUM.valueOf(rs.getShort("meta_type")), //NON-NLS
				TSK_FS_NAME_FLAG_ENUM.valueOf(rs.getShort("dir_flags")), //NON-NLS
				rs.getShort("meta_flags"), rs.getString("md5"), rs.getString("sha256"), rs.getString("sha1"), //NON-NLS
				FileKnown.valueOf(rs.getByte("known")), parentPath); //NON-NLS
		return ld;
	}

	/**
	 * Creates a DerivedFile object using the values of a given result set.
	 *
	 * @param rs         The result set.
	 * @param connection The case database connection.
	 * @param parentId   The parent id for the derived file or
	 *                   AbstractContent.UNKNOWN_ID.
	 *
	 * @return The DerivedFile object.
	 *
	 * @throws SQLException if there is an error reading from the result set or
	 *                      doing additional queries.
	 */
	private DerivedFile derivedFile(ResultSet rs, CaseDbConnection connection, long parentId) throws SQLException {
		boolean hasLocalPath = rs.getBoolean("has_path"); //NON-NLS
		long objId = rs.getLong("obj_id"); //NON-NLS
		String localPath = null;
		TskData.EncodingType encodingType = TskData.EncodingType.NONE;
		if (hasLocalPath) {
			ResultSet rsFilePath = null;
			acquireSingleUserCaseReadLock();
			try {
				PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_LOCAL_PATH_AND_ENCODING_FOR_FILE);
				statement.clearParameters();
				statement.setLong(1, objId);
				rsFilePath = connection.executeQuery(statement);
				if (rsFilePath.next()) {
					localPath = rsFilePath.getString("path");
					encodingType = TskData.EncodingType.valueOf(rsFilePath.getInt("encoding_type"));
				}
			} catch (SQLException ex) {
				logger.log(Level.SEVERE, "Error getting encoding type for file " + objId, ex); //NON-NLS
			} finally {
				closeResultSet(rsFilePath);
				releaseSingleUserCaseReadLock();
			}
		}
		String parentPath = rs.getString("parent_path"); //NON-NLS
		if (parentPath == null) {
			parentPath = "";
		}

		Long osAccountObjId = rs.getLong("os_account_obj_id");
		if (rs.wasNull()) {
			osAccountObjId = null;
		}

		final DerivedFile df = new DerivedFile(this, objId, rs.getLong("data_source_obj_id"),
				rs.getLong("fs_obj_id"),
				rs.getString("name"), //NON-NLS
				TSK_FS_NAME_TYPE_ENUM.valueOf(rs.getShort("dir_type")), //NON-NLS
				TSK_FS_META_TYPE_ENUM.valueOf(rs.getShort("meta_type")), //NON-NLS
				TSK_FS_NAME_FLAG_ENUM.valueOf(rs.getShort("dir_flags")), rs.getShort("meta_flags"), //NON-NLS
				rs.getLong("size"), //NON-NLS
				rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"), //NON-NLS
				rs.getString("md5"), rs.getString("sha256"), rs.getString("sha1"), 
				FileKnown.valueOf(rs.getByte("known")), //NON-NLS
				parentPath, localPath, parentId, rs.getString("mime_type"),
				encodingType, rs.getString("extension"),
				rs.getString("owner_uid"), osAccountObjId);
		return df;
	}

	/**
	 * Creates a LocalFile object using the data from a given result set.
	 *
	 * @param rs         The result set.
	 * @param connection The case database connection.
	 * @param parentId   The parent id for the derived file or
	 *                   AbstractContent.UNKNOWN_ID.
	 *
	 * @return The LocalFile object.
	 *
	 * @throws SQLException if there is an error reading from the result set or
	 *                      doing additional queries.
	 */
	private LocalFile localFile(ResultSet rs, CaseDbConnection connection, long parentId) throws SQLException {
		long objId = rs.getLong("obj_id"); //NON-NLS
		String localPath = null;
		TskData.EncodingType encodingType = TskData.EncodingType.NONE;
		if (rs.getBoolean("has_path")) {
			ResultSet rsFilePath = null;
			acquireSingleUserCaseReadLock();
			try {
				PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_LOCAL_PATH_AND_ENCODING_FOR_FILE);
				statement.clearParameters();
				statement.setLong(1, objId);
				rsFilePath = connection.executeQuery(statement);
				if (rsFilePath.next()) {
					localPath = rsFilePath.getString("path");
					encodingType = TskData.EncodingType.valueOf(rsFilePath.getInt("encoding_type"));
				}
			} catch (SQLException ex) {
				logger.log(Level.SEVERE, "Error getting encoding type for file " + objId, ex); //NON-NLS
			} finally {
				closeResultSet(rsFilePath);
				releaseSingleUserCaseReadLock();
			}
		}
		String parentPath = rs.getString("parent_path"); //NON-NLS
		if (null == parentPath) {
			parentPath = "";
		}
		Long osAccountObjId = rs.getLong("os_account_obj_id");
		if (rs.wasNull()) {
			osAccountObjId = null;
		}

		LocalFile file = new LocalFile(this, objId, rs.getString("name"), //NON-NLS
				TSK_DB_FILES_TYPE_ENUM.valueOf(rs.getShort("type")), //NON-NLS
				TSK_FS_NAME_TYPE_ENUM.valueOf(rs.getShort("dir_type")), //NON-NLS
				TSK_FS_META_TYPE_ENUM.valueOf(rs.getShort("meta_type")), //NON-NLS
				TSK_FS_NAME_FLAG_ENUM.valueOf(rs.getShort("dir_flags")), rs.getShort("meta_flags"), //NON-NLS
				rs.getLong("size"), //NON-NLS
				rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"), //NON-NLS
				rs.getString("mime_type"), rs.getString("md5"), rs.getString("sha256"), rs.getString("sha1"), 
				FileKnown.valueOf(rs.getByte("known")), //NON-NLS
				parentId, parentPath, rs.getLong("data_source_obj_id"),
				localPath, encodingType, rs.getString("extension"),
				rs.getString("owner_uid"), osAccountObjId);
		return file;
	}

	/**
	 * Create a Slack File object from the result set containing query results
	 * on tsk_files table
	 *
	 * @param rs the result set
	 * @param fs parent file system
	 *
	 * @return a newly created Slack File
	 *
	 * @throws SQLException
	 */
	org.sleuthkit.datamodel.SlackFile slackFile(ResultSet rs, FileSystem fs) throws SQLException {
		Long osAccountObjId = rs.getLong("os_account_obj_id");
		if (rs.wasNull()) {
			osAccountObjId = null;
		}
		org.sleuthkit.datamodel.SlackFile f = new org.sleuthkit.datamodel.SlackFile(this, rs.getLong("obj_id"), //NON-NLS
				rs.getLong("data_source_obj_id"), rs.getLong("fs_obj_id"), //NON-NLS
				TskData.TSK_FS_ATTR_TYPE_ENUM.valueOf(rs.getShort("attr_type")), //NON-NLS
				rs.getInt("attr_id"), rs.getString("name"), rs.getLong("meta_addr"), rs.getInt("meta_seq"), //NON-NLS
				TSK_FS_NAME_TYPE_ENUM.valueOf(rs.getShort("dir_type")), //NON-NLS
				TSK_FS_META_TYPE_ENUM.valueOf(rs.getShort("meta_type")), //NON-NLS
				TSK_FS_NAME_FLAG_ENUM.valueOf(rs.getShort("dir_flags")), //NON-NLS
				rs.getShort("meta_flags"), rs.getLong("size"), //NON-NLS
				rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"), //NON-NLS
				(short) rs.getInt("mode"), rs.getInt("uid"), rs.getInt("gid"), //NON-NLS
				rs.getString("md5"), rs.getString("sha256"), rs.getString("sha1"),
				FileKnown.valueOf(rs.getByte("known")), //NON-NLS
				rs.getString("parent_path"), rs.getString("mime_type"), rs.getString("extension"),
				rs.getString("owner_uid"), osAccountObjId); //NON-NLS
		f.setFileSystem(fs);
		return f;
	}

	/**
	 * Returns the list of abstractFile objects from a result of selecting many
	 * files that meet a certain criteria.
	 *
	 * @param rs
	 * @param parentId
	 *
	 * @return
	 *
	 * @throws SQLException
	 */
	List<Content> fileChildren(ResultSet rs, CaseDbConnection connection, long parentId) throws SQLException {
		List<Content> children = new ArrayList<Content>();

		while (rs.next()) {
			TskData.TSK_DB_FILES_TYPE_ENUM type = TskData.TSK_DB_FILES_TYPE_ENUM.valueOf(rs.getShort("type"));

			if (null != type) {
				switch (type) {
					case FS:
						if (rs.getShort("meta_type") != TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_VIRT_DIR.getValue()) {
							FsContent result;
							if (rs.getShort("meta_type") == TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR.getValue()) {
								result = directory(rs, null);
							} else {
								result = file(rs, null);
							}
							children.add(result);
						} else {
							VirtualDirectory virtDir = virtualDirectory(rs, connection);
							children.add(virtDir);
						}
						break;
					case VIRTUAL_DIR:
						VirtualDirectory virtDir = virtualDirectory(rs, connection);
						children.add(virtDir);
						break;
					case LOCAL_DIR:
						LocalDirectory localDir = localDirectory(rs);
						children.add(localDir);
						break;
					case UNALLOC_BLOCKS:
					case UNUSED_BLOCKS:
					case CARVED:
					case LAYOUT_FILE: {
						String parentPath = rs.getString("parent_path");
						if (parentPath == null) {
							parentPath = "";
						}
						Long osAccountObjId = rs.getLong("os_account_obj_id");
						if (rs.wasNull()) {
							osAccountObjId = null;
						}
						final LayoutFile lf = new LayoutFile(this, rs.getLong("obj_id"),
								rs.getLong("data_source_obj_id"), rs.getLong("fs_obj_id"),
								rs.getString("name"), type,
								TSK_FS_NAME_TYPE_ENUM.valueOf(rs.getShort("dir_type")),
								TSK_FS_META_TYPE_ENUM.valueOf(rs.getShort("meta_type")),
								TSK_FS_NAME_FLAG_ENUM.valueOf(rs.getShort("dir_flags")), rs.getShort("meta_flags"),
								rs.getLong("size"),
								rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"),
								rs.getString("md5"), rs.getString("sha256"), rs.getString("sha1"),
								FileKnown.valueOf(rs.getByte("known")), parentPath, rs.getString("mime_type"),
								rs.getString("owner_uid"), osAccountObjId);
						children.add(lf);
						break;
					}
					case DERIVED:
						final DerivedFile df = derivedFile(rs, connection, parentId);
						children.add(df);
						break;
					case LOCAL: {
						final LocalFile lf = localFile(rs, connection, parentId);
						children.add(lf);
						break;
					}
					case SLACK: {
						final SlackFile sf = slackFile(rs, null);
						children.add(sf);
						break;
					}
					default:
						break;
				}
			}
		}
		return children;
	}

	/**
	 * This method allows developers to run arbitrary SQL "SELECT" queries. The
	 * CaseDbQuery object will take care of acquiring the necessary database
	 * lock and when used in a try-with-resources block will automatically take
	 * care of releasing the lock. If you do not use a try-with-resources block
	 * you must call CaseDbQuery.close() once you are done processing the files
	 * of the query.
	 *
	 * Also note that if you use it within a transaction to insert something
	 * into the database, and then within that same transaction query the
	 * inserted item from the database, you will likely not see your inserted
	 * item, as the method uses new connections for each execution. With this
	 * method, you must close your transaction before successfully querying for
	 * newly-inserted items.
	 *
	 * @param query The query string to execute.
	 *
	 * @return A CaseDbQuery instance.
	 *
	 * @throws TskCoreException
	 */
	public CaseDbQuery executeQuery(String query) throws TskCoreException {
		return new CaseDbQuery(query);
	}

	/**
	 * This method allows developers to run arbitrary SQL queries, including
	 * INSERT and UPDATE. The CaseDbQuery object will take care of acquiring the
	 * necessary database lock and when used in a try-with-resources block will
	 * automatically take care of releasing the lock. If you do not use a
	 * try-with-resources block you must call CaseDbQuery.close() once you are
	 * done processing the files of the query.
	 *
	 * Also note that if you use it within a transaction to insert something
	 * into the database, and then within that same transaction query the
	 * inserted item from the database, you will likely not see your inserted
	 * item, as the method uses new connections for each execution. With this
	 * method, you must close your transaction before successfully querying for
	 * newly-inserted items.
	 *
	 * @param query The query string to execute.
	 *
	 * @return A CaseDbQuery instance.
	 *
	 * @throws TskCoreException
	 */
	public CaseDbQuery executeInsertOrUpdate(String query) throws TskCoreException {
		return new CaseDbQuery(query, true);
	}

	/**
	 * Get a case database connection.
	 *
	 * @return The case database connection.
	 *
	 * @throws TskCoreException
	 */
	CaseDbConnection getConnection() throws TskCoreException {
		return connections.getConnection();
	}

	/**
	 * Gets the string used to identify this case in the JNI cache.
	 *
	 * @return The string for this case
	 *
	 * @throws TskCoreException
	 */
	String getCaseHandleIdentifier() {
		return caseHandleIdentifier;
	}

	@SuppressWarnings("deprecation")
	@Override
	protected void finalize() throws Throwable {
		try {
			close();
		} finally {
			super.finalize();
		}
	}

	/**
	 * Call to free resources when done with instance.
	 */
	public synchronized void close() {
		acquireSingleUserCaseWriteLock();

		try {
			connections.close();
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error closing database connection pool.", ex); //NON-NLS
		}

		fileSystemIdMap.clear();

		try {
			if (this.caseHandle != null) {
				this.caseHandle.free();
				this.caseHandle = null;
			}
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error freeing case handle.", ex); //NON-NLS
		} finally {
			releaseSingleUserCaseWriteLock();
		}

		if (this.lockResources != null) {
			try {
				this.lockResources.close();
			} catch (Exception ex) {
				logger.log(Level.SEVERE, "Error closing lock resources.", ex); //NON-NLS
			}
		}
	}

	/**
	 * Store the known status for the FsContent in the database Note: will not
	 * update status if content is already 'Known Bad'
	 *
	 * @param	file      The AbstractFile object
	 * @param	fileKnown The object's known status
	 *
	 * @return	true if the known status was updated, false otherwise
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	public boolean setKnown(AbstractFile file, FileKnown fileKnown) throws TskCoreException {
		long id = file.getId();
		FileKnown currentKnown = file.getKnown();
		if (currentKnown.compareTo(fileKnown) > 0) {
			return false;
		}
		acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = connections.getConnection();
				Statement statement = connection.createStatement();) {
			connection.executeUpdate(statement, "UPDATE tsk_files " //NON-NLS
					+ "SET known='" + fileKnown.getFileKnownValue() + "' " //NON-NLS
					+ "WHERE obj_id=" + id); //NON-NLS

			file.setKnown(fileKnown);
		} catch (SQLException ex) {
			throw new TskCoreException("Error setting Known status.", ex);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
		return true;
	}

	/**
	 * Set the name of an object in the tsk_files table.
	 *
	 * @param name  The new name for the object
	 * @param objId The object ID
	 *
	 * @throws TskCoreException If there is an error updating the case database.
	 */
	void setFileName(String name, long objId) throws TskCoreException {
		acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = connections.getConnection();) {
			PreparedStatement preparedStatement = connection.getPreparedStatement(SleuthkitCase.PREPARED_STATEMENT.UPDATE_FILE_NAME);
			preparedStatement.clearParameters();
			preparedStatement.setString(1, name);
			preparedStatement.setLong(2, objId);
			connection.executeUpdate(preparedStatement);
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error updating while the name for object ID %d to %s", objId, name), ex);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Set the display name of an image in the tsk_image_info table.
	 *
	 * @param name  The new name for the image
	 * @param objId The object ID
	 *
	 * @throws TskCoreException If there is an error updating the case database.
	 */
	void setImageName(String name, long objId) throws TskCoreException {
		acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = connections.getConnection();) {
			PreparedStatement preparedStatement = connection.getPreparedStatement(SleuthkitCase.PREPARED_STATEMENT.UPDATE_IMAGE_NAME);
			preparedStatement.clearParameters();
			preparedStatement.setString(1, name);
			preparedStatement.setLong(2, objId);
			connection.executeUpdate(preparedStatement);
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error updating while the name for object ID %d to %s", objId, name), ex);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Updates the image's total size and sector size.This function may be used
	 * to update the sizes after the image was created.
	 *
	 * Can only update the sizes if they were not set before. Will throw
	 * TskCoreException if the values in the db are not 0 prior to this call.
	 *
	 * @param imgage     The image that needs to be updated
	 * @param totalSize  The total size
	 * @param sectorSize The sector size
	 *
	 * @throws TskCoreException If there is an error updating the case database.
	 *
	 */
	void setImageSizes(Image image, long totalSize, long sectorSize) throws TskCoreException {

		acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = connections.getConnection();) {
			PreparedStatement preparedStatement = connection.getPreparedStatement(SleuthkitCase.PREPARED_STATEMENT.UPDATE_IMAGE_SIZES);
			preparedStatement.clearParameters();
			preparedStatement.setLong(1, totalSize);
			preparedStatement.setLong(2, sectorSize);
			preparedStatement.setLong(3, image.getId());
			connection.executeUpdate(preparedStatement);
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error updating image sizes to %d and sector size to %d for object ID %d ", totalSize, sectorSize, image.getId()), ex);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Updates the given fields of a file entry in the database.
	 * 
	 * @param fileObjId
	 * @param size
	 * @param mtime
	 * @param atime
	 * @param ctime
	 * @param crtime
	 * @param userSid
	 * @param osAcctObjId (may be null)
	 * 
	 * @throws TskCoreException 
	 */
	@Beta
	public void updateFile(long fileObjId, long size, long mtime, long atime, long ctime, long crtime, String userSid, Long osAcctObjId) throws TskCoreException {
		
		String updateString = "UPDATE tsk_files SET size = ?, mtime = ?, atime = ?, ctime = ?, crtime = ?, "
				+ " owner_uid = ?, os_account_obj_id = ? WHERE obj_id = ?";
		
		acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = connections.getConnection();
			PreparedStatement preparedStatement = connection.getPreparedStatement(updateString, Statement.NO_GENERATED_KEYS);) {
			
			preparedStatement.clearParameters();
			
			preparedStatement.setLong(1, size);
			preparedStatement.setLong(2, mtime);
			preparedStatement.setLong(3, atime);
			preparedStatement.setLong(4, ctime);
			preparedStatement.setLong(5, crtime);
			preparedStatement.setString(6, userSid);
			
			if (osAcctObjId != null) {
				preparedStatement.setLong(7, osAcctObjId);
			} else {
				preparedStatement.setNull(7, java.sql.Types.BIGINT);
			}
			
			preparedStatement.setLong(8, fileObjId);
			
			connection.executeUpdate(preparedStatement);
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error updating file (obj_id = %s)", fileObjId), ex);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}
	
	/**
	 * Stores the MIME type of a file in the case database and updates the MIME
	 * type of the given file object.
	 *
	 * @param file     A file.
	 * @param mimeType The MIME type.
	 *
	 * @throws TskCoreException If there is an error updating the case database.
	 */
	public void setFileMIMEType(AbstractFile file, String mimeType) throws TskCoreException {
		acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = connections.getConnection();
				Statement statement = connection.createStatement()) {
			connection.executeUpdate(statement, String.format("UPDATE tsk_files SET mime_type = '%s' WHERE obj_id = %d", mimeType, file.getId()));
			file.setMIMEType(mimeType);
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error setting MIME type for file (obj_id = %s)", file.getId()), ex);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Sets the unalloc meta flags for the file in the case database, and
	 * updates the meta flags in given file object. Also updates the dir flag to
	 * unalloc.
	 *
	 * @param file A file.
	 *
	 *
	 * @throws TskCoreException If there is an error updating the case database.
	 */
	public void setFileUnalloc(AbstractFile file) throws TskCoreException {

		// get the flags, reset the ALLOC flag, and set the UNALLOC flag
		short metaFlag = file.getMetaFlagsAsInt();
		Set<TSK_FS_META_FLAG_ENUM> metaFlagAsSet = TSK_FS_META_FLAG_ENUM.valuesOf(metaFlag);
		metaFlagAsSet.remove(TSK_FS_META_FLAG_ENUM.ALLOC);
		metaFlagAsSet.add(TSK_FS_META_FLAG_ENUM.UNALLOC);

		short newMetaFlgs = TSK_FS_META_FLAG_ENUM.toInt(metaFlagAsSet);
		short newDirFlags = TSK_FS_NAME_FLAG_ENUM.UNALLOC.getValue();

		acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = connections.getConnection();
				Statement statement = connection.createStatement();) {
			connection.executeUpdate(statement, String.format("UPDATE tsk_files SET meta_flags = '%d', dir_flags = '%d'  WHERE obj_id = %d", newMetaFlgs, newDirFlags, file.getId()));

			file.removeMetaFlag(TSK_FS_META_FLAG_ENUM.ALLOC);
			file.setMetaFlag(TSK_FS_META_FLAG_ENUM.UNALLOC);

			file.setDirFlag(TSK_FS_NAME_FLAG_ENUM.UNALLOC);

		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error setting unalloc meta flag for file (obj_id = %s)", file.getId()), ex);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}
	
	/**
	 * Store the md5Hash for the file in the database
	 *
	 * @param	file    The file object
	 * @param	md5Hash The object's md5Hash
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	void setMd5Hash(AbstractFile file, String md5Hash) throws TskCoreException {
		if (md5Hash == null) {
			return;
		}
		long id = file.getId();
		acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = connections.getConnection();) {
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.UPDATE_FILE_MD5);
			statement.clearParameters();
			statement.setString(1, md5Hash.toLowerCase());
			statement.setLong(2, id);
			connection.executeUpdate(statement);
			file.setMd5Hash(md5Hash.toLowerCase());
		} catch (SQLException ex) {
			throw new TskCoreException("Error setting MD5 hash", ex);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Store the MD5 hash for the image in the database
	 *
	 * @param	img     The image object
	 * @param	md5Hash The image's MD5 hash
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	void setMd5ImageHash(Image img, String md5Hash) throws TskCoreException {
		if (md5Hash == null) {
			return;
		}
		long id = img.getId();
		acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = connections.getConnection();) {
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.UPDATE_IMAGE_MD5);
			statement.clearParameters();
			statement.setString(1, md5Hash.toLowerCase());
			statement.setLong(2, id);
			connection.executeUpdate(statement);
		} catch (SQLException ex) {
			throw new TskCoreException("Error setting MD5 hash", ex);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Get the MD5 hash of an image from the case database
	 *
	 * @param The image object
	 *
	 * @return The image's MD5 hash
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	String getMd5ImageHash(Image img) throws TskCoreException {
		long id = img.getId();
		CaseDbConnection connection = null;
		ResultSet rs = null;
		String hash = "";
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_IMAGE_MD5);
			statement.clearParameters();
			statement.setLong(1, id);
			rs = connection.executeQuery(statement);
			if (rs.next()) {
				hash = rs.getString("md5");
			}
			return hash;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting MD5 hash", ex);
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Store the SHA1 hash for the image in the database
	 *
	 * @param	img      The image object
	 * @param	sha1Hash The image's sha1 hash
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	void setSha1ImageHash(Image img, String sha1Hash) throws TskCoreException {
		if (sha1Hash == null) {
			return;
		}
		long id = img.getId();
		acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = connections.getConnection();) {
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.UPDATE_IMAGE_SHA1);
			statement.clearParameters();
			statement.setString(1, sha1Hash.toLowerCase());
			statement.setLong(2, id);
			connection.executeUpdate(statement);
		} catch (SQLException ex) {
			throw new TskCoreException("Error setting SHA1 hash", ex);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Get the SHA1 hash of an image from the case database
	 *
	 * @param The image object
	 *
	 * @return The image's SHA1 hash
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	String getSha1ImageHash(Image img) throws TskCoreException {
		long id = img.getId();
		CaseDbConnection connection = null;
		ResultSet rs = null;
		String hash = "";
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_IMAGE_SHA1);
			statement.clearParameters();
			statement.setLong(1, id);
			rs = connection.executeQuery(statement);
			if (rs.next()) {
				hash = rs.getString("sha1");
			}
			return hash;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting SHA1 hash", ex);
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Store the SHA256 hash for the file in the database
	 *
	 * @param	img        The image object
	 * @param	sha256Hash The object's md5Hash
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	void setSha256ImageHash(Image img, String sha256Hash) throws TskCoreException {
		if (sha256Hash == null) {
			return;
		}
		long id = img.getId();
		acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = connections.getConnection();) {
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.UPDATE_IMAGE_SHA256);
			statement.clearParameters();
			statement.setString(1, sha256Hash.toLowerCase());
			statement.setLong(2, id);
			connection.executeUpdate(statement);
		} catch (SQLException ex) {
			throw new TskCoreException("Error setting SHA256 hash", ex);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Get the SHA256 hash of an image from the case database
	 *
	 * @param The image object
	 *
	 * @return The image's SHA256 hash
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	String getSha256ImageHash(Image img) throws TskCoreException {
		long id = img.getId();
		CaseDbConnection connection = null;
		ResultSet rs = null;
		String hash = "";
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_IMAGE_SHA256);
			statement.clearParameters();
			statement.setLong(1, id);
			rs = connection.executeQuery(statement);
			if (rs.next()) {
				hash = rs.getString("sha256");
			}
			return hash;
		} catch (SQLException ex) {
			throw new TskCoreException("Error setting SHA256 hash", ex);
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Set the acquisition details in the data_source_info table
	 *
	 * @param datasource The data source
	 * @param details    The acquisition details
	 *
	 * @throws TskCoreException Thrown if the database write fails
	 */
	void setAcquisitionDetails(DataSource datasource, String details) throws TskCoreException {

		long id = datasource.getId();
		acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = connections.getConnection();) {
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.UPDATE_ACQUISITION_DETAILS);
			statement.clearParameters();
			statement.setString(1, details);
			statement.setLong(2, id);
			connection.executeUpdate(statement);
		} catch (SQLException ex) {
			throw new TskCoreException("Error setting acquisition details", ex);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Sets the acquisition tool details such as its name, version number and
	 * any settings used during the acquisition to acquire data.
	 *
	 * @param datasource The datasource object
	 * @param name       The name of the acquisition tool. May be NULL.
	 * @param version    The acquisition tool version number. May be NULL.
	 * @param settings   The settings used by the acquisition tool. May be NULL.
	 *
	 * @throws TskCoreException Thrown if the database write fails
	 */
	void setAcquisitionToolDetails(DataSource datasource, String name, String version, String settings) throws TskCoreException {

		long id = datasource.getId();
		acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = connections.getConnection();) {
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.UPDATE_ACQUISITION_TOOL_SETTINGS);
			statement.clearParameters();
			statement.setString(1, settings);
			statement.setString(2, name);
			statement.setString(3, version);
			statement.setLong(4, id);
			connection.executeUpdate(statement);
		} catch (SQLException ex) {
			throw new TskCoreException("Error setting acquisition details", ex);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Set the acquisition details in the data_source_info table.
	 *
	 * @param dataSourceId The data source ID.
	 * @param details      The acquisition details.
	 * @param trans        The current transaction.
	 *
	 * @throws TskCoreException
	 */
	void setAcquisitionDetails(long dataSourceId, String details, CaseDbTransaction trans) throws TskCoreException {
		try {
			CaseDbConnection connection = trans.getConnection();
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.UPDATE_ACQUISITION_DETAILS);
			statement.clearParameters();
			statement.setString(1, details);
			statement.setLong(2, dataSourceId);
			connection.executeUpdate(statement);
		} catch (SQLException ex) {
			throw new TskCoreException("Error setting acquisition details", ex);
		}
	}

	/**
	 * Get the acquisition details from the data_source_info table
	 *
	 * @param datasource The data source
	 *
	 * @return The acquisition details
	 *
	 * @throws TskCoreException Thrown if the database read fails
	 */
	String getAcquisitionDetails(DataSource datasource) throws TskCoreException {
		long id = datasource.getId();
		CaseDbConnection connection = null;
		ResultSet rs = null;
		String hash = "";
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_ACQUISITION_DETAILS);
			statement.clearParameters();
			statement.setLong(1, id);
			rs = connection.executeQuery(statement);
			if (rs.next()) {
				hash = rs.getString("acquisition_details");
			}
			return hash;
		} catch (SQLException ex) {
			throw new TskCoreException("Error setting acquisition details", ex);
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get String value from the provided column from data_source_info table.
	 *
	 * @param datasource The datasource
	 * @param columnName The column from which the data should be returned
	 *
	 * @return String value from the column
	 *
	 * @throws TskCoreException
	 */
	String getDataSourceInfoString(DataSource datasource, String columnName) throws TskCoreException {
		long id = datasource.getId();
		CaseDbConnection connection = null;
		ResultSet rs = null;
		String returnValue = "";
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_ACQUISITION_TOOL_SETTINGS);
			statement.clearParameters();
			statement.setLong(1, id);
			rs = connection.executeQuery(statement);
			if (rs.next()) {
				returnValue = rs.getString(columnName);
			}
			return returnValue;
		} catch (SQLException ex) {
			throw new TskCoreException("Error setting acquisition details", ex);
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get Long value from the provided column from data_source_info table.
	 *
	 * @param datasource The datasource
	 * @param columnName The column from which the data should be returned
	 *
	 * @return Long value from the column
	 *
	 * @throws TskCoreException
	 */
	Long getDataSourceInfoLong(DataSource datasource, String columnName) throws TskCoreException {
		long id = datasource.getId();
		CaseDbConnection connection = null;
		ResultSet rs = null;
		Long returnValue = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_ACQUISITION_TOOL_SETTINGS);
			statement.clearParameters();
			statement.setLong(1, id);
			rs = connection.executeQuery(statement);
			if (rs.next()) {
				returnValue = rs.getLong(columnName);
			}
			return returnValue;
		} catch (SQLException ex) {
			throw new TskCoreException("Error setting acquisition details", ex);
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Set the review status of the given artifact to newStatus
	 *
	 * @param artifact  The artifact whose review status is being set.
	 * @param newStatus The new review status for the given artifact. Must not
	 *                  be null.
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	public void setReviewStatus(BlackboardArtifact artifact, BlackboardArtifact.ReviewStatus newStatus) throws TskCoreException {
		if (newStatus == null) {
			return;
		}
		acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = connections.getConnection();
				Statement statement = connection.createStatement();) {
			connection.executeUpdate(statement, "UPDATE blackboard_artifacts "
					+ " SET review_status_id=" + newStatus.getID()
					+ " WHERE blackboard_artifacts.artifact_id = " + artifact.getArtifactID());
		} catch (SQLException ex) {
			throw new TskCoreException("Error setting review status", ex);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Return the number of objects in the database of a given file type.
	 *
	 * @param contentType Type of file to count
	 *
	 * @return Number of objects with that type.
	 *
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 *                          core
	 */
	public int countFsContentType(TskData.TSK_FS_META_TYPE_ENUM contentType) throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			Short contentShort = contentType.getValue();
			rs = connection.executeQuery(s, "SELECT COUNT(*) AS count FROM tsk_files WHERE meta_type = '" + contentShort.toString() + "'"); //NON-NLS
			int count = 0;
			if (rs.next()) {
				count = rs.getInt("count");
			}
			return count;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting number of objects.", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Escape the single quotes in the given string so they can be added to the
	 * SQL caseDbConnection
	 *
	 * @param text
	 *
	 * @return text the escaped version
	 */
	public static String escapeSingleQuotes(String text) {
		String escapedText = null;
		if (text != null) {
			escapedText = text.replaceAll("'", "''");
		}
		return escapedText;
	}

	/**
	 * Find all the files with the given MD5 hash.
	 *
	 * @param md5Hash hash value to match files with
	 *
	 * @return List of AbstractFile with the given hash
	 */
	public List<AbstractFile> findFilesByMd5(String md5Hash) {
		if (md5Hash == null) {
			return Collections.<AbstractFile>emptyList();
		}

		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT * FROM tsk_files WHERE " //NON-NLS
					+ " md5 = '" + md5Hash.toLowerCase() + "' " //NON-NLS
					+ "AND size > 0"); //NON-NLS
			return resultSetToAbstractFiles(rs, connection);
		} catch (SQLException | TskCoreException ex) {
			logger.log(Level.WARNING, "Error querying database.", ex); //NON-NLS
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
		return Collections.<AbstractFile>emptyList();
	}

	/**
	 * Query all the files to verify if they have an MD5 hash associated with
	 * them.
	 *
	 * @return true if all files have an MD5 hash
	 */
	public boolean allFilesMd5Hashed() {
		boolean allFilesAreHashed = false;

		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT COUNT(*) AS count FROM tsk_files " //NON-NLS
					+ "WHERE dir_type = '" + TskData.TSK_FS_NAME_TYPE_ENUM.REG.getValue() + "' " //NON-NLS
					+ "AND md5 IS NULL " //NON-NLS
					+ "AND size > '0'"); //NON-NLS
			if (rs.next() && rs.getInt("count") == 0) {
				allFilesAreHashed = true;
			}
		} catch (SQLException | TskCoreException ex) {
			logger.log(Level.WARNING, "Failed to query whether all files have MD5 hashes", ex); //NON-NLS
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
		return allFilesAreHashed;
	}

	/**
	 * Query all the files and counts how many have an MD5 hash.
	 *
	 * @return the number of files with an MD5 hash
	 */
	public int countFilesMd5Hashed() {
		int count = 0;

		acquireSingleUserCaseReadLock();
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT COUNT(*) AS count FROM tsk_files " //NON-NLS
					+ "WHERE md5 IS NOT NULL " //NON-NLS
					+ "AND size > '0'"); //NON-NLS
			if (rs.next()) {
				count = rs.getInt("count");
			}
		} catch (SQLException | TskCoreException ex) {
			logger.log(Level.WARNING, "Failed to query for all the files.", ex); //NON-NLS
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
		return count;

	}

	/**
	 * Selects all of the rows from the tag_names table in the case database.
	 *
	 * @return A list, possibly empty, of TagName data transfer objects (DTOs)
	 *         for the rows.
	 *
	 * @throws TskCoreException
	 */
	public List<TagName> getAllTagNames() throws TskCoreException {
		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// SELECT * FROM tag_names
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_TAG_NAMES);
			resultSet = connection.executeQuery(statement);
			ArrayList<TagName> tagNames = new ArrayList<>();
			while (resultSet.next()) {
				tagNames.add(new TagName(resultSet.getLong("tag_name_id"), resultSet.getString("display_name"),
						resultSet.getString("description"), TagName.HTML_COLOR.getColorByName(resultSet.getString("color")),
						TskData.TagType.valueOf(resultSet.getByte("knownStatus")), resultSet.getLong("tag_set_id"), resultSet.getInt("rank"))); //NON-NLS
			}
			return tagNames;
		} catch (SQLException ex) {
			throw new TskCoreException("Error selecting rows from tag_names table", ex);
		} finally {
			closeResultSet(resultSet);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Selects all of the rows from the tag_names table in the case database for
	 * which there is at least one matching row in the content_tags or
	 * blackboard_artifact_tags tables.
	 *
	 * @return A list, possibly empty, of TagName data transfer objects (DTOs)
	 *         for the rows.
	 *
	 * @throws TskCoreException
	 */
	public List<TagName> getTagNamesInUse() throws TskCoreException {
		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// SELECT * FROM tag_names WHERE tag_name_id IN (SELECT tag_name_id from content_tags UNION SELECT tag_name_id FROM blackboard_artifact_tags)
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_TAG_NAMES_IN_USE);
			resultSet = connection.executeQuery(statement);
			ArrayList<TagName> tagNames = new ArrayList<>();
			while (resultSet.next()) {
				tagNames.add(new TagName(resultSet.getLong("tag_name_id"), resultSet.getString("display_name"),
						resultSet.getString("description"), TagName.HTML_COLOR.getColorByName(resultSet.getString("color")),
						TskData.TagType.valueOf(resultSet.getByte("knownStatus")), resultSet.getLong("tag_set_id"), resultSet.getInt("rank"))); //NON-NLS
			}
			return tagNames;
		} catch (SQLException ex) {
			throw new TskCoreException("Error selecting rows from tag_names table", ex);
		} finally {
			closeResultSet(resultSet);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Selects all of the rows from the tag_names table in the case database for
	 * which there is at least one matching row in the content_tags or
	 * blackboard_artifact_tags tables, for the given data source object id.
	 *
	 * @param dsObjId data source object id
	 *
	 * @return A list, possibly empty, of TagName data transfer objects (DTOs)
	 *         for the rows.
	 *
	 * @throws TskCoreException
	 */
	public List<TagName> getTagNamesInUse(long dsObjId) throws TskCoreException {

		ArrayList<TagName> tagNames = new ArrayList<>();
		//	SELECT * FROM tag_names WHERE tag_name_id IN 
		//	 ( SELECT content_tags.tag_name_id as tag_name_id FROM content_tags as content_tags, tsk_files as tsk_files WHERE content_tags.obj_id = tsk_files.obj_id AND tsk_files.data_source_obj_id =  ? "
		//     UNION 
		//     SELECT artifact_tags.tag_name_id as tag_name_id FROM blackboard_artifact_tags as artifact_tags, blackboard_artifacts AS arts WHERE artifact_tags.artifact_id = arts.artifact_id AND arts.data_source_obj_id = ? )
		//   )
		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_TAG_NAMES_IN_USE_BY_DATASOURCE);
			statement.setLong(1, dsObjId);
			statement.setLong(2, dsObjId);
			resultSet = connection.executeQuery(statement); //NON-NLS
			while (resultSet.next()) {
				tagNames.add(new TagName(resultSet.getLong("tag_name_id"), resultSet.getString("display_name"),
						resultSet.getString("description"), TagName.HTML_COLOR.getColorByName(resultSet.getString("color")),
						TskData.TagType.valueOf(resultSet.getByte("knownStatus")), resultSet.getLong("tag_set_id"), resultSet.getInt("rank"))); //NON-NLS
			}
			return tagNames;
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to get tag names in use for data source objID : " + dsObjId, ex);
		} finally {
			closeResultSet(resultSet);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Inserts row into the tags_names table in the case database.
	 *
	 * @param displayName The display name for the new tag name.
	 * @param description The description for the new tag name.
	 * @param color       The HTML color to associate with the new tag name.
	 *
	 * @return A TagName data transfer object (DTO) for the new row.
	 *
	 * @throws TskCoreException
	 * @deprecated TaggingManager.addOrUpdateTagName should be used instead with
	 * the default knowStatus of TskData.TagType.UNKNOWN
	 */
	@Deprecated
	@SuppressWarnings("deprecation")
	public TagName addTagName(String displayName, String description, TagName.HTML_COLOR color) throws TskCoreException {
		return addOrUpdateTagName(displayName, description, color, TskData.FileKnown.UNKNOWN);
	}

	/**
	 * Inserts row into the tags_names table, or updates the existing row if the
	 * displayName already exists in the tag_names table in the case database.
	 *
	 * @param displayName The display name for the new tag name.
	 * @param description The description for the new tag name.
	 * @param color       The HTML color to associate with the new tag name.
	 * @param knownStatus The TskData.FileKnown value to associate with the new
	 *                    tag name.
	 *
	 * @return A TagName data transfer object (DTO) for the new row.
	 *
	 * @throws TskCoreException
	 * @deprecated This method has been replaced by
	 * TaggingManager.addOrUpdateTagName.
	 */
	@Deprecated
	public TagName addOrUpdateTagName(String displayName, String description, TagName.HTML_COLOR color, TskData.FileKnown knownStatus) throws TskCoreException {
		return getTaggingManager().addOrUpdateTagName(displayName, description, color, knownStatus);
	}

	/**
	 * Inserts a row into the content_tags table in the case database.
	 *
	 * @param content         The content to tag.
	 * @param tagName         The name to use for the tag.
	 * @param comment         A comment to store with the tag.
	 * @param beginByteOffset Designates the beginning of a tagged section.
	 * @param endByteOffset   Designates the end of a tagged section.
	 *
	 * @return A ContentTag data transfer object (DTO) for the new row.
	 *
	 * @throws TskCoreException
	 * @deprecated Use TaggingManager.addContentTag
	 */
	@Deprecated
	public ContentTag addContentTag(Content content, TagName tagName, String comment, long beginByteOffset, long endByteOffset) throws TskCoreException {
		return taggingMgr.addContentTag(content, tagName, comment, beginByteOffset, endByteOffset).getAddedTag();
	}

	/*
	 * Deletes a row from the content_tags table in the case database. @param
	 * tag A ContentTag data transfer object (DTO) for the row to delete.
	 * @throws TskCoreException
	 */
	public void deleteContentTag(ContentTag tag) throws TskCoreException {
		CaseDbTransaction trans = beginTransaction();
		try {
			// DELETE FROM content_tags WHERE tag_id = ?
			PreparedStatement statement = trans.getConnection().getPreparedStatement(PREPARED_STATEMENT.DELETE_CONTENT_TAG);
			statement.clearParameters();
			statement.setLong(1, tag.getId());
			trans.getConnection().executeUpdate(statement);

			// update the aggregate score for the content
			Long contentId = tag.getContent() != null ? tag.getContent().getId() : null;
			Long dataSourceId = tag.getContent() != null && tag.getContent().getDataSource() != null
					? tag.getContent().getDataSource().getId()
					: null;

			this.getScoringManager().updateAggregateScoreAfterDeletion(contentId, dataSourceId, trans);

			trans.commit();
			trans = null;
		} catch (SQLException ex) {
			throw new TskCoreException("Error deleting row from content_tags table (id = " + tag.getId() + ")", ex);
		} finally {
			if (trans != null) {
				trans.rollback();
			}
		}
	}

	/**
	 * Selects all of the rows from the content_tags table in the case database.
	 *
	 * @return A list, possibly empty, of ContentTag data transfer objects
	 *         (DTOs) for the rows.
	 *
	 * @throws TskCoreException
	 */
	public List<ContentTag> getAllContentTags() throws TskCoreException {
		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// SELECT content_tags.tag_id, content_tags.obj_id, content_tags.tag_name_id, content_tags.comment, content_tags.begin_byte_offset, content_tags.end_byte_offset, tag_names.display_name, tag_names.description, tag_names.color, tag_names.knownStatus, tsk_examiners.login_name 
			//	FROM content_tags 
			//	INNER JOIN tag_names ON content_tags.tag_name_id = tag_names.tag_name_id 
			//	LEFT OUTER JOIN tsk_examiners ON content_tags.examiner_id = tsk_examiners.examiner_id
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_CONTENT_TAGS);
			resultSet = connection.executeQuery(statement);
			ArrayList<ContentTag> tags = new ArrayList<ContentTag>();
			while (resultSet.next()) {
				TagName tagName = new TagName(resultSet.getLong("tag_name_id"), resultSet.getString("display_name"),
						resultSet.getString("description"), TagName.HTML_COLOR.getColorByName(resultSet.getString("color")),
						TskData.TagType.valueOf(resultSet.getByte("knownStatus")), resultSet.getLong("tag_set_id"), resultSet.getInt("rank"));  //NON-NLS
				Content content = getContentById(resultSet.getLong("obj_id")); //NON-NLS
				tags.add(new ContentTag(resultSet.getLong("tag_id"), content, tagName, resultSet.getString("comment"),
						resultSet.getLong("begin_byte_offset"), resultSet.getLong("end_byte_offset"), resultSet.getString("login_name")));  //NON-NLS
			}
			return tags;
		} catch (SQLException ex) {
			throw new TskCoreException("Error selecting rows from content_tags table", ex);
		} finally {
			closeResultSet(resultSet);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Gets a count of the rows in the content_tags table in the case database
	 * with a specified foreign key into the tag_names table.
	 *
	 * @param tagName A data transfer object (DTO) for the tag name to match.
	 *
	 * @return The count, possibly zero.
	 *
	 * @throws TskCoreException
	 */
	public long getContentTagsCountByTagName(TagName tagName) throws TskCoreException {
		if (tagName.getId() == Tag.ID_NOT_SET) {
			throw new TskCoreException("TagName object is invalid, id not set");
		}
		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// SELECT COUNT(*) AS count FROM content_tags WHERE tag_name_id = ?
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.COUNT_CONTENT_TAGS_BY_TAG_NAME);
			statement.clearParameters();
			statement.setLong(1, tagName.getId());
			resultSet = connection.executeQuery(statement);
			if (resultSet.next()) {
				return resultSet.getLong("count");
			} else {
				throw new TskCoreException("Error getting content_tags row count for tag name (tag_name_id = " + tagName.getId() + ")");
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting content_tags row count for tag name (tag_name_id = " + tagName.getId() + ")", ex);
		} finally {
			closeResultSet(resultSet);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Gets content tags count by tag name, for the given data source
	 *
	 * @param tagName The representation of the desired tag type in the case
	 *                database, which can be obtained by calling getTagNames
	 *                and/or addTagName.
	 *
	 * @param dsObjId data source object id
	 *
	 * @return A count of the content tags with the specified tag name, and for
	 *         the given data source
	 *
	 * @throws TskCoreException If there is an error getting the tags count from
	 *                          the case database.
	 */
	public long getContentTagsCountByTagName(TagName tagName, long dsObjId) throws TskCoreException {

		if (tagName.getId() == Tag.ID_NOT_SET) {
			throw new TskCoreException("TagName object is invalid, id not set");
		}

		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// "SELECT COUNT(*) AS count FROM content_tags as content_tags, tsk_files as tsk_files WHERE content_tags.obj_id = tsk_files.obj_id"
			//		+ " AND content_tags.tag_name_id = ? "
			//		+ " AND tsk_files.data_source_obj_id = ? "
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.COUNT_CONTENT_TAGS_BY_TAG_NAME_BY_DATASOURCE);
			statement.clearParameters();
			statement.setLong(1, tagName.getId());
			statement.setLong(2, dsObjId);

			resultSet = connection.executeQuery(statement);
			if (resultSet.next()) {
				return resultSet.getLong("count");
			} else {
				throw new TskCoreException("Error getting content_tags row count for tag name (tag_name_id = " + tagName.getId() + ")" + " for dsObjId = " + dsObjId);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to get content_tags row count for  tag_name_id = " + tagName.getId() + "data source objID : " + dsObjId, ex);
		} finally {
			closeResultSet(resultSet);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Selects the rows in the content_tags table in the case database with a
	 * specified tag id.
	 *
	 * @param contentTagID the tag id of the ContentTag to retrieve.
	 *
	 * @return The content tag.
	 *
	 * @throws TskCoreException
	 */
	public ContentTag getContentTagByID(long contentTagID) throws TskCoreException {

		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		ContentTag tag = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// SELECT content_tags.tag_id, content_tags.obj_id, content_tags.tag_name_id, content_tags.comment, content_tags.begin_byte_offset, content_tags.end_byte_offset, tag_names.display_name, tag_names.description, tag_names.color, tag_names.knownStatus, tsk_examiners.login_name 
			//	FROM content_tags 
			//	INNER JOIN tag_names ON content_tags.tag_name_id = tag_names.tag_name_id 
			//	UTER LEFT JOIN tsk_examiners ON content_tags.examiner_id = tsk_examiners.examiner_id 
			//	WHERE tag_id = ?
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_CONTENT_TAG_BY_ID);
			statement.clearParameters();
			statement.setLong(1, contentTagID);
			resultSet = connection.executeQuery(statement);

			while (resultSet.next()) {
				TagName tagName = new TagName(resultSet.getLong("tag_name_id"), resultSet.getString("display_name"),
						resultSet.getString("description"), TagName.HTML_COLOR.getColorByName(resultSet.getString("color")),
						TskData.TagType.valueOf(resultSet.getByte("knownStatus")), resultSet.getLong("tag_set_id"), resultSet.getInt("rank"));
				tag = new ContentTag(resultSet.getLong("tag_id"), getContentById(resultSet.getLong("obj_id")), tagName,
						resultSet.getString("comment"), resultSet.getLong("begin_byte_offset"), resultSet.getLong("end_byte_offset"), resultSet.getString("login_name"));
			}
			resultSet.close();

		} catch (SQLException ex) {
			throw new TskCoreException("Error getting content tag with id = " + contentTagID, ex);
		} finally {
			closeResultSet(resultSet);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
		return tag;
	}

	/**
	 * Selects the rows in the content_tags table in the case database with a
	 * specified foreign key into the tag_names table.
	 *
	 * @param tagName A data transfer object (DTO) for the tag name to match.
	 *
	 * @return A list, possibly empty, of ContentTag data transfer objects
	 *         (DTOs) for the rows.
	 *
	 * @throws TskCoreException
	 */
	public List<ContentTag> getContentTagsByTagName(TagName tagName) throws TskCoreException {
		if (tagName.getId() == Tag.ID_NOT_SET) {
			throw new TskCoreException("TagName object is invalid, id not set");
		}
		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// SELECT content_tags.tag_id, content_tags.obj_id, content_tags.tag_name_id, content_tags.comment, content_tags.begin_byte_offset, content_tags.end_byte_offset, tsk_examiners.login_name 
			//	FROM content_tags 
			//  LEFT OUTER JOIN tsk_examiners ON content_tags.examiner_id = tsk_examiners.examiner_id 
			//	WHERE tag_name_id = ?
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_CONTENT_TAGS_BY_TAG_NAME);
			statement.clearParameters();
			statement.setLong(1, tagName.getId());
			resultSet = connection.executeQuery(statement);
			ArrayList<ContentTag> tags = new ArrayList<ContentTag>();
			while (resultSet.next()) {
				ContentTag tag = new ContentTag(resultSet.getLong("tag_id"), getContentById(resultSet.getLong("obj_id")),
						tagName, resultSet.getString("comment"), resultSet.getLong("begin_byte_offset"), resultSet.getLong("end_byte_offset"), resultSet.getString("login_name"));  //NON-NLS
				tags.add(tag);
			}
			resultSet.close();
			return tags;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting content_tags rows (tag_name_id = " + tagName.getId() + ")", ex);
		} finally {
			closeResultSet(resultSet);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Gets content tags by tag name, for the given data source. This includes
	 * looking up all Content objects that have entries in tsk_files, as well as
	 * all OsAccounts (which do not have entries in tsk_files).
	 *
	 * @param tagName The tag name of interest.
	 * @param dsObjId data source object id
	 *
	 * @return A list, possibly empty, of the content tags with the specified
	 *         tag name, and for the given data source.
	 *
	 * @throws TskCoreException If there is an error getting the tags from the
	 *                          case database.
	 */
	public List<ContentTag> getContentTagsByTagName(TagName tagName, long dsObjId) throws TskCoreException {

		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			
			// NOTE: Getting all content tags by tag name for a given data source includes
			// looking up all Content objects that have entries in tsk_files, as well as
			// all OsAccounts. OsAccounts do not have corresponding entries in tsk_files so we 
			// have to do a separate query to look them up, and then do a UNION of the results.
			
//			"SELECT content_tags.tag_id, content_tags.obj_id, content_tags.tag_name_id, content_tags.comment, content_tags.begin_byte_offset, content_tags.end_byte_offset, tag_names.display_name, tag_names.description, tag_names.color, tag_names.knownStatus, tag_names.tag_set_id, tsk_examiners.login_name "
//			+ "FROM content_tags "
//			+ "JOIN tsk_os_accounts acc ON content_tags.obj_id = acc.os_account_obj_id "
//			+ "JOIN tag_names ON content_tags.tag_name_id = tag_names.tag_name_id "
//			+ "JOIN tsk_examiners ON content_tags.examiner_id = tsk_examiners.examiner_id "
//			+ "WHERE content_tags.tag_name_id = ? "
//			+ "AND acc.os_account_obj_id IN (SELECT os_account_obj_id FROM tsk_os_account_instances WHERE data_source_obj_id = ?) "
//			+ "AND acc.db_status = " + OsAccount.OsAccountDbStatus.ACTIVE.getId()
//			+ " UNION "
//			+ "SELECT content_tags.tag_id, content_tags.obj_id, content_tags.tag_name_id, content_tags.comment, content_tags.begin_byte_offset, content_tags.end_byte_offset, tag_names.display_name, tag_names.description, tag_names.color, tag_names.knownStatus, tag_names.tag_set_id, tsk_examiners.login_name "
//			+ "FROM content_tags as content_tags, tsk_files as tsk_files, tag_names as tag_names, tsk_examiners as tsk_examiners "
//			+ "WHERE content_tags.examiner_id = tsk_examiners.examiner_id "
//			+ "AND content_tags.obj_id = tsk_files.obj_id "
//			+ "AND content_tags.tag_name_id = tag_names.tag_name_id "
//			+ "AND content_tags.tag_name_id = ? "
//			+ "AND tsk_files.data_source_obj_id = ? "
			
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_CONTENT_TAGS_BY_TAG_NAME_BY_DATASOURCE);
			statement.clearParameters();
			statement.setLong(1, tagName.getId());
			statement.setLong(2, dsObjId);
			statement.setLong(3, tagName.getId());
			statement.setLong(4, dsObjId);
			resultSet = connection.executeQuery(statement);
			ArrayList<ContentTag> tags = new ArrayList<ContentTag>();
			while (resultSet.next()) {
				ContentTag tag = new ContentTag(resultSet.getLong("tag_id"), getContentById(resultSet.getLong("obj_id")),
						tagName, resultSet.getString("comment"), resultSet.getLong("begin_byte_offset"), resultSet.getLong("end_byte_offset"), resultSet.getString("login_name"));  //NON-NLS
				tags.add(tag);
			}
			resultSet.close();
			return tags;
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to get content_tags row count for  tag_name_id = " + tagName.getId() + " data source objID : " + dsObjId, ex);
		} finally {
			closeResultSet(resultSet);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Selects the rows in the content_tags table in the case database with a
	 * specified foreign key into the tsk_objects table.
	 *
	 * @param content A data transfer object (DTO) for the content to match.
	 *
	 * @return A list, possibly empty, of ContentTag data transfer objects
	 *         (DTOs) for the rows.
	 *
	 * @throws TskCoreException
	 */
	public List<ContentTag> getContentTagsByContent(Content content) throws TskCoreException {
		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// SELECT content_tags.tag_id, content_tags.obj_id, content_tags.tag_name_id, content_tags.comment, content_tags.begin_byte_offset, content_tags.end_byte_offset, tag_names.display_name, tag_names.description, tag_names.color, tag_names.knownStatus, tsk_examiners.login_name 
			//	FROM content_tags 
			//	INNER JOIN tag_names ON content_tags.tag_name_id = tag_names.tag_name_id 
			//	LEFT OUTER JOIN tsk_examiners ON content_tags.examiner_id = tsk_examiners.examiner_id 
			//	WHERE content_tags.obj_id = ?
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_CONTENT_TAGS_BY_CONTENT);
			statement.clearParameters();
			statement.setLong(1, content.getId());
			resultSet = connection.executeQuery(statement);
			ArrayList<ContentTag> tags = new ArrayList<ContentTag>();
			while (resultSet.next()) {
				TagName tagName = new TagName(resultSet.getLong("tag_name_id"), resultSet.getString("display_name"),
						resultSet.getString("description"), TagName.HTML_COLOR.getColorByName(resultSet.getString("color")),
						TskData.TagType.valueOf(resultSet.getByte("knownStatus")), resultSet.getLong("tag_set_id"), resultSet.getInt("rank"));  //NON-NLS
				ContentTag tag = new ContentTag(resultSet.getLong("tag_id"), content, tagName,
						resultSet.getString("comment"), resultSet.getLong("begin_byte_offset"), resultSet.getLong("end_byte_offset"), resultSet.getString("login_name"));  //NON-NLS
				tags.add(tag);
			}
			return tags;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting content tags data for content (obj_id = " + content.getId() + ")", ex);
		} finally {
			closeResultSet(resultSet);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Inserts a row into the blackboard_artifact_tags table in the case
	 * database.
	 *
	 * @param artifact The blackboard artifact to tag.
	 * @param tagName  The name to use for the tag.
	 * @param comment  A comment to store with the tag.
	 *
	 * @return A BlackboardArtifactTag data transfer object (DTO) for the new
	 *         row.
	 *
	 * @throws TskCoreException
	 * @deprecated User TaggingManager.addArtifactTag instead.
	 */
	@Deprecated
	public BlackboardArtifactTag addBlackboardArtifactTag(BlackboardArtifact artifact, TagName tagName, String comment) throws TskCoreException {
		return taggingMgr.addArtifactTag(artifact, tagName, comment).getAddedTag();
	}

	/*
	 * Deletes a row from the blackboard_artifact_tags table in the case
	 * database. @param tag A BlackboardArtifactTag data transfer object (DTO)
	 * representing the row to delete. @throws TskCoreException
	 */
	public void deleteBlackboardArtifactTag(BlackboardArtifactTag tag) throws TskCoreException {
		CaseDbTransaction trans = beginTransaction();
		try {
			// DELETE FROM blackboard_artifact_tags WHERE tag_id = ?
			PreparedStatement statement = trans.getConnection().getPreparedStatement(PREPARED_STATEMENT.DELETE_ARTIFACT_TAG);
			statement.clearParameters();
			statement.setLong(1, tag.getId());
			trans.getConnection().executeUpdate(statement);

			// update the aggregate score for the artifact
			Long artifactObjId = tag.getArtifact().getId();
			Long dataSourceId = tag.getContent() != null && tag.getContent().getDataSource() != null
					? tag.getContent().getDataSource().getId()
					: null;

			this.getScoringManager().updateAggregateScoreAfterDeletion(artifactObjId, dataSourceId, trans);

			trans.commit();
			trans = null;
		} catch (SQLException ex) {
			throw new TskCoreException("Error deleting row from blackboard_artifact_tags table (id = " + tag.getId() + ")", ex);
		} finally {
			if (trans != null) {
				trans.rollback();
			}
		}
	}

	/**
	 * Selects all of the rows from the blackboard_artifacts_tags table in the
	 * case database.
	 *
	 * @return A list, possibly empty, of BlackboardArtifactTag data transfer
	 *         objects (DTOs) for the rows.
	 *
	 * @throws TskCoreException
	 */
	public List<BlackboardArtifactTag> getAllBlackboardArtifactTags() throws TskCoreException {
		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// SELECT blackboard_artifact_tags.tag_id, blackboard_artifact_tags.artifact_id, blackboard_artifact_tags.tag_name_id, blackboard_artifact_tags.comment, tag_names.display_name, tag_names.description, tag_names.color, tag_names.knownStatus, tsk_examiners.login_name
			//	FROM blackboard_artifact_tags 
			//	INNER JOIN tag_names ON blackboard_artifact_tags.tag_name_id = tag_names.tag_name_id 
			//	LEFT OUTER JOIN tsk_examiners ON blackboard_artifact_tags.examiner_id = tsk_examiners.examiner_id
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_ARTIFACT_TAGS);
			resultSet = connection.executeQuery(statement);
			ArrayList<BlackboardArtifactTag> tags = new ArrayList<>();
			while (resultSet.next()) {
				TagName tagName = new TagName(resultSet.getLong("tag_name_id"), resultSet.getString("display_name"),
						resultSet.getString("description"), TagName.HTML_COLOR.getColorByName(resultSet.getString("color")),
						TskData.TagType.valueOf(resultSet.getByte("knownStatus")), resultSet.getLong("tag_set_id"), resultSet.getInt("rank"));  //NON-NLS
				BlackboardArtifact artifact = getBlackboardArtifact(resultSet.getLong("artifact_id")); //NON-NLS
				Content content = getContentById(artifact.getObjectID());
				BlackboardArtifactTag tag = new BlackboardArtifactTag(resultSet.getLong("tag_id"),
						artifact, content, tagName, resultSet.getString("comment"), resultSet.getString("login_name"));  //NON-NLS
				tags.add(tag);
			}
			return tags;
		} catch (SQLException ex) {
			throw new TskCoreException("Error selecting rows from blackboard_artifact_tags table", ex);
		} finally {
			closeResultSet(resultSet);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Gets a count of the rows in the blackboard_artifact_tags table in the
	 * case database with a specified foreign key into the tag_names table.
	 *
	 * @param tagName A data transfer object (DTO) for the tag name to match.
	 *
	 * @return The count, possibly zero.
	 *
	 * @throws TskCoreException
	 */
	public long getBlackboardArtifactTagsCountByTagName(TagName tagName) throws TskCoreException {
		if (tagName.getId() == Tag.ID_NOT_SET) {
			throw new TskCoreException("TagName object is invalid, id not set");
		}
		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// SELECT COUNT(*) AS count FROM blackboard_artifact_tags WHERE tag_name_id = ?
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.COUNT_ARTIFACTS_BY_TAG_NAME);
			statement.clearParameters();
			statement.setLong(1, tagName.getId());
			resultSet = connection.executeQuery(statement);
			if (resultSet.next()) {
				return resultSet.getLong("count");
			} else {
				throw new TskCoreException("Error getting blackboard_artifact_tags row count for tag name (tag_name_id = " + tagName.getId() + ")");
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifact_content_tags row count for tag name (tag_name_id = " + tagName.getId() + ")", ex);
		} finally {
			closeResultSet(resultSet);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Gets an artifact tags count by tag name, for the given data source.
	 *
	 * @param tagName The representation of the desired tag type in the case
	 *                database, which can be obtained by calling getTagNames
	 *                and/or addTagName.
	 * @param dsObjId data source object id
	 *
	 * @return A count of the artifact tags with the specified tag name, for the
	 *         given data source.
	 *
	 * @throws TskCoreException If there is an error getting the tags count from
	 *                          the case database.
	 */
	public long getBlackboardArtifactTagsCountByTagName(TagName tagName, long dsObjId) throws TskCoreException {

		if (tagName.getId() == Tag.ID_NOT_SET) {
			throw new TskCoreException("TagName object is invalid, id not set");
		}

		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// "SELECT COUNT(*) AS count FROM blackboard_artifact_tags as artifact_tags, blackboard_artifacts AS arts WHERE artifact_tags.artifact_id = arts.artifact_id"
			//    + " AND artifact_tags.tag_name_id = ?"
			//	 + " AND arts.data_source_obj_id =  ? "
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.COUNT_ARTIFACTS_BY_TAG_NAME_BY_DATASOURCE);
			statement.clearParameters();
			statement.setLong(1, tagName.getId());
			statement.setLong(2, dsObjId);
			resultSet = connection.executeQuery(statement);
			if (resultSet.next()) {
				return resultSet.getLong("count");
			} else {
				throw new TskCoreException("Error getting blackboard_artifact_tags row count for tag name (tag_name_id = " + tagName.getId() + ")" + " for dsObjId = " + dsObjId);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to get blackboard_artifact_tags row count for  tag_name_id = " + tagName.getId() + "data source objID : " + dsObjId, ex);
		} finally {
			closeResultSet(resultSet);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Selects the rows in the blackboard_artifacts_tags table in the case
	 * database with a specified foreign key into the tag_names table.
	 *
	 * @param tagName A data transfer object (DTO) for the tag name to match.
	 *
	 * @return A list, possibly empty, of BlackboardArtifactTag data transfer
	 *         objects (DTOs) for the rows.
	 *
	 * @throws TskCoreException
	 */
	public List<BlackboardArtifactTag> getBlackboardArtifactTagsByTagName(TagName tagName) throws TskCoreException {
		if (tagName.getId() == Tag.ID_NOT_SET) {
			throw new TskCoreException("TagName object is invalid, id not set");
		}
		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// SELECT blackboard_artifact_tags.tag_id, blackboard_artifact_tags.artifact_id, blackboard_artifact_tags.tag_name_id, blackboard_artifact_tags.comment, tsk_examiners.login_name 
			//	FROM blackboard_artifact_tags 
			//	LEFT OUTER JOIN tsk_examiners ON blackboard_artifact_tags.examiner_id = tsk_examiners.examiner_id 
			//	WHERE tag_name_id = ?
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_ARTIFACT_TAGS_BY_TAG_NAME);
			statement.clearParameters();
			statement.setLong(1, tagName.getId());
			resultSet = connection.executeQuery(statement);
			ArrayList<BlackboardArtifactTag> tags = new ArrayList<BlackboardArtifactTag>();
			while (resultSet.next()) {
				BlackboardArtifact artifact = getBlackboardArtifact(resultSet.getLong("artifact_id")); //NON-NLS
				Content content = getContentById(artifact.getObjectID());
				BlackboardArtifactTag tag = new BlackboardArtifactTag(resultSet.getLong("tag_id"),
						artifact, content, tagName, resultSet.getString("comment"), resultSet.getString("login_name"));  //NON-NLS
				tags.add(tag);
			}
			return tags;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifact tags data (tag_name_id = " + tagName.getId() + ")", ex);
		} finally {
			closeResultSet(resultSet);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Gets artifact tags by tag name, for specified data source.
	 *
	 * @param tagName The representation of the desired tag type in the case
	 *                database, which can be obtained by calling getTagNames
	 *                and/or addTagName.
	 * @param dsObjId data source object id
	 *
	 * @return A list, possibly empty, of the artifact tags with the specified
	 *         tag name, for the specified data source.
	 *
	 * @throws TskCoreException If there is an error getting the tags from the
	 *                          case database.
	 */
	public List<BlackboardArtifactTag> getBlackboardArtifactTagsByTagName(TagName tagName, long dsObjId) throws TskCoreException {

		if (tagName.getId() == Tag.ID_NOT_SET) {
			throw new TskCoreException("TagName object is invalid, id not set");
		}

		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			//	SELECT artifact_tags.tag_id, artifact_tags.artifact_id, artifact_tags.tag_name_id, artifact_tags.comment, arts.obj_id, arts.artifact_obj_id, arts.data_source_obj_id, arts.artifact_type_id, arts.review_status_id, tsk_examiners.login_name 
			//	 FROM blackboard_artifact_tags as artifact_tags, blackboard_artifacts AS arts 
			//	 LEFT OUTER JOIN tsk_examiners ON artifact_tags.examiner_id = tsk_examiners.examiner_id 
			//	 WHERE artifact_tags.artifact_id = arts.artifact_id
			//	 AND artifact_tags.tag_name_id = ? 
			//	 AND arts.data_source_obj_id =  ?             
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_ARTIFACT_TAGS_BY_TAG_NAME_BY_DATASOURCE);
			statement.clearParameters();
			statement.setLong(1, tagName.getId());
			statement.setLong(2, dsObjId);
			resultSet = connection.executeQuery(statement);
			ArrayList<BlackboardArtifactTag> tags = new ArrayList<BlackboardArtifactTag>();
			while (resultSet.next()) {
				BlackboardArtifact artifact = getBlackboardArtifact(resultSet.getLong("artifact_id")); //NON-NLS
				Content content = getContentById(artifact.getObjectID());
				BlackboardArtifactTag tag = new BlackboardArtifactTag(resultSet.getLong("tag_id"),
						artifact, content, tagName, resultSet.getString("comment"), resultSet.getString("login_name"));  //NON-NLS
				tags.add(tag);
			}
			return tags;
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to get blackboard_artifact_tags row count for  tag_name_id = " + tagName.getId() + "data source objID : " + dsObjId, ex);
		} finally {
			closeResultSet(resultSet);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}

	}

	/**
	 * Selects the row in the blackboard artifact tags table in the case
	 * database with a specified tag id.
	 *
	 * @param artifactTagID the tag id of the BlackboardArtifactTag to retrieve.
	 *
	 * @return the BlackBoardArtifact Tag with the given tag id, or null if no
	 *         such tag could be found
	 *
	 * @throws TskCoreException
	 */
	public BlackboardArtifactTag getBlackboardArtifactTagByID(long artifactTagID) throws TskCoreException {

		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		BlackboardArtifactTag tag = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			//SELECT blackboard_artifact_tags.tag_id, blackboard_artifact_tags.artifact_id, blackboard_artifact_tags.tag_name_id, blackboard_artifact_tags.comment, tag_names.display_name, tag_names.description, tag_names.color, tag_names.knownStatus, tsk_examiners.login_name 
			//	FROM blackboard_artifact_tags 
			//	INNER JOIN tag_names ON blackboard_artifact_tags.tag_name_id = tag_names.tag_name_id  
			//	LEFT OUTER JOIN tsk_examiners ON blackboard_artifact_tags.examiner_id = tsk_examiners.examiner_id 
			//	WHERE blackboard_artifact_tags.tag_id = ?
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_ARTIFACT_TAG_BY_ID);
			statement.clearParameters();
			statement.setLong(1, artifactTagID);
			resultSet = connection.executeQuery(statement);

			while (resultSet.next()) {
				TagName tagName = new TagName(resultSet.getLong("tag_name_id"), resultSet.getString("display_name"),
						resultSet.getString("description"), TagName.HTML_COLOR.getColorByName(resultSet.getString("color")),
						TskData.TagType.valueOf(resultSet.getByte("knownStatus")), resultSet.getLong("tag_set_id"), resultSet.getInt("rank"));
				BlackboardArtifact artifact = getBlackboardArtifact(resultSet.getLong("artifact_id")); //NON-NLS
				Content content = getContentById(artifact.getObjectID());
				tag = new BlackboardArtifactTag(resultSet.getLong("tag_id"),
						artifact, content, tagName, resultSet.getString("comment"), resultSet.getString("login_name"));
			}
			resultSet.close();

		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifact tag with id = " + artifactTagID, ex);
		} finally {
			closeResultSet(resultSet);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
		return tag;
	}

	/**
	 * Selects the rows in the blackboard_artifacts_tags table in the case
	 * database with a specified foreign key into the blackboard_artifacts
	 * table.
	 *
	 * @param artifact A data transfer object (DTO) for the artifact to match.
	 *
	 * @return A list, possibly empty, of BlackboardArtifactTag data transfer
	 *         objects (DTOs) for the rows.
	 *
	 * @throws TskCoreException
	 */
	public List<BlackboardArtifactTag> getBlackboardArtifactTagsByArtifact(BlackboardArtifact artifact) throws TskCoreException {
		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			//  SELECT blackboard_artifact_tags.tag_id, blackboard_artifact_tags.artifact_id, blackboard_artifact_tags.tag_name_id, blackboard_artifact_tags.comment, tag_names.display_name, tag_names.description, tag_names.color, tag_names.knownStatus, tsk_examiners.login_name 
			//	FROM blackboard_artifact_tags 
			//	INNER JOIN tag_names ON blackboard_artifact_tags.tag_name_id = tag_names.tag_name_id 
			//	LEFT OUTER JOIN tsk_examiners ON blackboard_artifact_tags.examiner_id = tsk_examiners.examiner_id 
			//	WHERE blackboard_artifact_tags.artifact_id = ?
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_ARTIFACT_TAGS_BY_ARTIFACT);
			statement.clearParameters();
			statement.setLong(1, artifact.getArtifactID());
			resultSet = connection.executeQuery(statement);
			ArrayList<BlackboardArtifactTag> tags = new ArrayList<>();
			while (resultSet.next()) {
				TagName tagName = new TagName(resultSet.getLong("tag_name_id"), resultSet.getString("display_name"),
						resultSet.getString("description"), TagName.HTML_COLOR.getColorByName(resultSet.getString("color")),
						TskData.TagType.valueOf(resultSet.getByte("knownStatus")), resultSet.getLong("tag_set_id"), resultSet.getInt("rank"));  //NON-NLS
				Content content = getContentById(artifact.getObjectID());
				BlackboardArtifactTag tag = new BlackboardArtifactTag(resultSet.getLong("tag_id"),
						artifact, content, tagName, resultSet.getString("comment"), resultSet.getString("login_name"));  //NON-NLS
				tags.add(tag);
			}
			return tags;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifact tags data (artifact_id = " + artifact.getArtifactID() + ")", ex);
		} finally {
			closeResultSet(resultSet);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Change the path for an image in the database.
	 *
	 * @param newPath  New path to the image
	 * @param objectId Data source ID of the image
	 *
	 * @throws TskCoreException
	 */
	public void updateImagePath(String newPath, long objectId) throws TskCoreException {
		acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = connections.getConnection();) {
			// UPDATE tsk_image_names SET name = ? WHERE obj_id = ?
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.UPDATE_IMAGE_PATH);
			statement.clearParameters();
			statement.setString(1, newPath);
			statement.setLong(2, objectId);
			connection.executeUpdate(statement);
		} catch (SQLException ex) {
			throw new TskCoreException("Error updating image path in database for object " + objectId, ex);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Inserts a row into the reports table in the case database.
	 *
	 * @param localPath        The path of the report file, must be in the
	 *                         database directory (case directory in Autopsy) or
	 *                         one of its subdirectories.
	 * @param sourceModuleName The name of the module that created the report.
	 * @param reportName       The report name.
	 *
	 * @return A Report object for the new row.
	 *
	 * @throws TskCoreException
	 */
	public Report addReport(String localPath, String sourceModuleName, String reportName) throws TskCoreException {
		return addReport(localPath, sourceModuleName, reportName, null);
	}

	/**
	 * Inserts a row into the reports table in the case database.
	 *
	 * @param localPath        The path of the report file, must be in the
	 *                         database directory (case directory in Autopsy) or
	 *                         one of its subdirectories.
	 * @param sourceModuleName The name of the module that created the report.
	 * @param reportName       The report name.
	 * @param parent           The Content from which the report was created, if
	 *                         available.
	 *
	 * @return A Report object for the new row.
	 *
	 * @throws TskCoreException
	 */
	public Report addReport(String localPath, String sourceModuleName, String reportName, Content parent) throws TskCoreException {
		// Make sure the local path of the report is in the database directory
		// or one of its subdirectories.
		String relativePath = ""; //NON-NLS
		long createTime = 0;
		String localPathLower = localPath.toLowerCase();

		if (localPathLower.startsWith("http")) {
			relativePath = localPathLower;
			createTime = System.currentTimeMillis() / 1000;
		} else {
			/*
			 * Note: The following call to .relativize() may be dangerous in
			 * case-sensitive operating systems and should be looked at. For
			 * now, we are simply relativizing the paths as all lower case, then
			 * using the length of the result to pull out the appropriate number
			 * of characters from the localPath String.
			 */
			try {
				String casePathLower = getDbDirPath().toLowerCase();
				int length = new File(casePathLower).toURI().relativize(new File(localPathLower).toURI()).getPath().length();
				relativePath = new File(localPath.substring(localPathLower.length() - length)).getPath();
			} catch (IllegalArgumentException ex) {
				String errorMessage = String.format("Local path %s not in the database directory or one of its subdirectories", localPath);
				throw new TskCoreException(errorMessage, ex);
			}
			try {
				// get its file time
				java.io.File tempFile = new java.io.File(localPath);
				// Convert to UNIX epoch (seconds, not milliseconds).
				createTime = tempFile.lastModified() / 1000;
			} catch (Exception ex) {
				throw new TskCoreException("Could not get create time for report at " + localPath, ex);
			}
		}

		// Write the report data to the database.
		acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = connections.getConnection();) {
			// Insert a row for the report into the tsk_objects table.
			// INSERT INTO tsk_objects (par_obj_id, type) VALUES (?, ?)
			long parentObjId = 0;
			if (parent != null) {
				parentObjId = parent.getId();
			}
			long objectId = addObject(parentObjId, TskData.ObjectType.REPORT.getObjectType(), connection);

			// INSERT INTO reports (obj_id, path, crtime, src_module_name, display_name) VALUES (?, ?, ?, ?, ?)
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_REPORT);
			statement.clearParameters();
			statement.setLong(1, objectId);
			statement.setString(2, relativePath);
			statement.setLong(3, createTime);
			statement.setString(4, sourceModuleName);
			statement.setString(5, reportName);
			connection.executeUpdate(statement);
			return new Report(this, objectId, localPath, createTime, sourceModuleName, reportName, parent);
		} catch (SQLException ex) {
			throw new TskCoreException("Error adding report " + localPath + " to reports table", ex);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Selects all of the rows from the reports table in the case database.
	 *
	 * @return A list, possibly empty, of Report data transfer objects (DTOs)
	 *         for the rows.
	 *
	 * @throws TskCoreException
	 */
	public List<Report> getAllReports() throws TskCoreException {
		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		ResultSet parentResultSet = null;
		PreparedStatement statement = null;
		Statement parentStatement = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// SELECT * FROM reports
			statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_REPORTS);
			parentStatement = connection.createStatement();
			resultSet = connection.executeQuery(statement);
			ArrayList<Report> reports = new ArrayList<Report>();
			while (resultSet.next()) {
				String localpath = resultSet.getString("path");
				if (localpath.toLowerCase().startsWith("http") == false) {
					// make path absolute
					localpath = Paths.get(getDbDirPath(), localpath).normalize().toString(); //NON-NLS
				}

				// get the report parent
				Content parent = null;
				long reportId = resultSet.getLong("obj_id"); // NON-NLS
				String parentQuery = String.format("SELECT * FROM tsk_objects WHERE obj_id = %s;", reportId);
				parentResultSet = parentStatement.executeQuery(parentQuery);
				if (parentResultSet.next()) {
					long parentId = parentResultSet.getLong("par_obj_id");	// NON-NLS
					parent = this.getContentById(parentId);
				}
				parentResultSet.close();

				reports.add(new Report(this,
						reportId,
						localpath,
						resultSet.getLong("crtime"), //NON-NLS
						resultSet.getString("src_module_name"), //NON-NLS
						resultSet.getString("report_name"),
						parent));  //NON-NLS
			}
			return reports;
		} catch (SQLException ex) {
			throw new TskCoreException("Error querying reports table", ex);
		} finally {
			closeResultSet(resultSet);
			closeResultSet(parentResultSet);
			closeStatement(statement);
			closeStatement(parentStatement);

			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get a Report object for the given id.
	 *
	 * @param id
	 *
	 * @return A new Report object for the given id.
	 *
	 * @throws TskCoreException
	 */
	public Report getReportById(long id) throws TskCoreException {
		CaseDbConnection connection = null;
		PreparedStatement statement = null;
		Statement parentStatement = null;
		ResultSet resultSet = null;
		ResultSet parentResultSet = null;
		Report report = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// SELECT * FROM reports WHERE obj_id = ?
			statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_REPORT_BY_ID);
			parentStatement = connection.createStatement();
			statement.clearParameters();
			statement.setLong(1, id);
			resultSet = connection.executeQuery(statement);

			if (resultSet.next()) {
				// get the report parent
				Content parent = null;
				String parentQuery = String.format("SELECT * FROM tsk_objects WHERE obj_id = %s;", id);
				parentResultSet = parentStatement.executeQuery(parentQuery);
				if (parentResultSet.next()) {
					long parentId = parentResultSet.getLong("par_obj_id"); // NON-NLS
					parent = this.getContentById(parentId);
				}

				report = new Report(this, resultSet.getLong("obj_id"), //NON-NLS
						Paths.get(getDbDirPath(), resultSet.getString("path")).normalize().toString(), //NON-NLS
						resultSet.getLong("crtime"), //NON-NLS
						resultSet.getString("src_module_name"), //NON-NLS
						resultSet.getString("report_name"),
						parent);  //NON-NLS
			} else {
				throw new TskCoreException("No report found for id: " + id);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error querying reports table for id: " + id, ex);
		} finally {
			closeResultSet(resultSet);
			closeResultSet(parentResultSet);
			closeStatement(statement);
			closeStatement(parentStatement);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}

		return report;
	}

	/**
	 * Deletes a row from the reports table in the case database.
	 *
	 * @param report A Report data transfer object (DTO) for the row to delete.
	 *
	 * @throws TskCoreException
	 */
	public void deleteReport(Report report) throws TskCoreException {
		acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = connections.getConnection();) {
			// DELETE FROM reports WHERE reports.obj_id = ?
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.DELETE_REPORT);
			statement.setLong(1, report.getId());
			connection.executeUpdate(statement);
			// DELETE FROM tsk_objects WHERE tsk_objects.obj_id = ?
			statement = connection.getPreparedStatement(PREPARED_STATEMENT.DELETE_REPORT_TSK_OBJECT);
			statement.setLong(1, report.getId());
			statement.setLong(2, TskData.ObjectType.REPORT.getObjectType());
			connection.executeUpdate(statement);
		} catch (SQLException ex) {
			throw new TskCoreException("Error querying reports table", ex);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}

	static void closeResultSet(ResultSet resultSet) {
		if (resultSet != null) {
			try {
				resultSet.close();
			} catch (SQLException ex) {
				logger.log(Level.SEVERE, "Error closing ResultSet", ex); //NON-NLS
			}
		}
	}

	static void closeStatement(Statement statement) {
		if (statement != null) {
			try {
				statement.close();
			} catch (SQLException ex) {
				logger.log(Level.SEVERE, "Error closing Statement", ex); //NON-NLS

			}
		}
	}

	static void closeConnection(CaseDbConnection connection) {
		if (connection != null) {
			connection.close();
		}
	}

	private static void rollbackTransaction(CaseDbConnection connection) {
		if (connection != null) {
			connection.rollbackTransaction();
		}
	}

	/**
	 * Sets the end date for the given ingest job
	 *
	 * @param ingestJobId The ingest job to set the end date for
	 * @param endDateTime The end date
	 *
	 * @throws TskCoreException If inserting into the database fails
	 */
	void setIngestJobEndDateTime(long ingestJobId, long endDateTime) throws TskCoreException {
		acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = connections.getConnection();) {
			Statement statement = connection.createStatement();
			statement.executeUpdate("UPDATE ingest_jobs SET end_date_time=" + endDateTime + " WHERE ingest_job_id=" + ingestJobId + ";");
		} catch (SQLException ex) {
			throw new TskCoreException("Error updating the end date (ingest_job_id = " + ingestJobId + ".", ex);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}

	void setIngestJobStatus(long ingestJobId, IngestJobStatusType status) throws TskCoreException {
		acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = connections.getConnection();
				Statement statement = connection.createStatement();) {
			statement.executeUpdate("UPDATE ingest_jobs SET status_id=" + status.ordinal() + " WHERE ingest_job_id=" + ingestJobId + ";");
		} catch (SQLException ex) {
			throw new TskCoreException("Error ingest job status (ingest_job_id = " + ingestJobId + ".", ex);
		} finally {
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 *
	 * @param dataSource    The datasource the ingest job is being run on
	 * @param hostName      The name of the host
	 * @param ingestModules The ingest modules being run during the ingest job.
	 *                      Should be in pipeline order.
	 * @param jobStart      The time the job started
	 * @param jobEnd        The time the job ended
	 * @param status        The ingest job status
	 * @param settingsDir   The directory of the job's settings
	 *
	 * @return An information object representing the ingest job added to the
	 *         database.
	 *
	 * @throws TskCoreException If adding the job to the database fails.
	 */
	public final IngestJobInfo addIngestJob(Content dataSource, String hostName, List<IngestModuleInfo> ingestModules, Date jobStart, Date jobEnd, IngestJobStatusType status, String settingsDir) throws TskCoreException {
		CaseDbConnection connection = null;
		acquireSingleUserCaseWriteLock();
		ResultSet resultSet = null;
		Statement statement;
		try {
			connection = connections.getConnection();
			connection.beginTransaction();
			statement = connection.createStatement();
			PreparedStatement insertStatement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_INGEST_JOB, Statement.RETURN_GENERATED_KEYS);
			insertStatement.setLong(1, dataSource.getId());
			insertStatement.setString(2, hostName);
			insertStatement.setLong(3, jobStart.getTime());
			insertStatement.setLong(4, jobEnd.getTime());
			insertStatement.setInt(5, status.ordinal());
			insertStatement.setString(6, settingsDir);
			connection.executeUpdate(insertStatement);
			resultSet = insertStatement.getGeneratedKeys();
			resultSet.next();
			long id = resultSet.getLong(1); //last_insert_rowid()
			for (int i = 0; i < ingestModules.size(); i++) {
				IngestModuleInfo ingestModule = ingestModules.get(i);
				statement.executeUpdate("INSERT INTO ingest_job_modules (ingest_job_id, ingest_module_id, pipeline_position) "
						+ "VALUES (" + id + ", " + ingestModule.getIngestModuleId() + ", " + i + ");");
			}
			resultSet.close();
			resultSet = null;
			connection.commitTransaction();
			return new IngestJobInfo(id, dataSource.getId(), hostName, jobStart, "", ingestModules, this);
		} catch (SQLException ex) {
			rollbackTransaction(connection);
			throw new TskCoreException("Error adding the ingest job.", ex);
		} finally {
			closeResultSet(resultSet);
			closeConnection(connection);
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Adds the given ingest module to the database.
	 *
	 * @param displayName      The display name of the module
	 * @param factoryClassName The factory class name of the module.
	 * @param type             The type of the module.
	 * @param version          The version of the module.
	 *
	 * @return An ingest module info object representing the module added to the
	 *         db.
	 *
	 * @throws TskCoreException When the ingest module cannot be added.
	 */
	public final IngestModuleInfo addIngestModule(String displayName, String factoryClassName, IngestModuleType type, String version) throws TskCoreException {
		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		String uniqueName = factoryClassName + "-" + displayName + "-" + version;
		acquireSingleUserCaseWriteLock();
		try {
			connection = connections.getConnection();
			statement = connection.createStatement();
			resultSet = statement.executeQuery("SELECT * FROM ingest_modules WHERE unique_name = '" + uniqueName + "'");
			if (!resultSet.next()) {
				resultSet.close();
				resultSet = null;
				PreparedStatement insertStatement = connection.getPreparedStatement(PREPARED_STATEMENT.INSERT_INGEST_MODULE, Statement.RETURN_GENERATED_KEYS);
				insertStatement.setString(1, displayName);
				insertStatement.setString(2, uniqueName);
				insertStatement.setInt(3, type.ordinal());
				insertStatement.setString(4, version);
				connection.executeUpdate(insertStatement);
				resultSet = insertStatement.getGeneratedKeys();
				resultSet.next();
				long id = resultSet.getLong(1); //last_insert_rowid()
				resultSet.close();
				resultSet = null;
				return new IngestModuleInfo(id, displayName, uniqueName, type, version);
			} else {
				return new IngestModuleInfo(resultSet.getInt("ingest_module_id"), resultSet.getString("display_name"),
						resultSet.getString("unique_name"), IngestModuleType.fromID(resultSet.getInt("type_id")), resultSet.getString("version"));
			}
		} catch (SQLException ex) {
			try {
				closeStatement(statement);
				if (connection != null) {
					statement = connection.createStatement();
					resultSet = statement.executeQuery("SELECT * FROM ingest_modules WHERE unique_name = '" + uniqueName + "'");
					if (resultSet.next()) {
						return new IngestModuleInfo(resultSet.getInt("ingest_module_id"), resultSet.getString("display_name"),
								uniqueName, IngestModuleType.fromID(resultSet.getInt("type_id")), resultSet.getString("version"));
					}
				}
				throw new TskCoreException("Couldn't add new module to database.", ex);
			} catch (SQLException ex1) {
				throw new TskCoreException("Couldn't add new module to database.", ex1);
			}
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			closeConnection(connection);
			releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Gets all of the ingest jobs that have been run.
	 *
	 * @return The information about the ingest jobs that have been run
	 *
	 * @throws TskCoreException If there is a problem getting the ingest jobs
	 */
	public final List<IngestJobInfo> getIngestJobs() throws TskCoreException {
		CaseDbConnection connection = null;
		ResultSet resultSet = null;
		Statement statement = null;
		List<IngestJobInfo> ingestJobs = new ArrayList<>();
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			statement = connection.createStatement();
			resultSet = statement.executeQuery("SELECT * FROM ingest_jobs");
			while (resultSet.next()) {
				ingestJobs.add(new IngestJobInfo(resultSet.getInt("ingest_job_id"), resultSet.getLong("obj_id"),
						resultSet.getString("host_name"), new Date(resultSet.getLong("start_date_time")),
						new Date(resultSet.getLong("end_date_time")), IngestJobStatusType.fromID(resultSet.getInt("status_id")),
						resultSet.getString("settings_dir"), this.getIngestModules(resultSet.getInt("ingest_job_id"), connection), this));
			}
			return ingestJobs;
		} catch (SQLException ex) {
			throw new TskCoreException("Couldn't get the ingest jobs.", ex);
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Gets the ingest modules associated with the ingest job
	 *
	 * @param ingestJobId The id of the ingest job to get ingest modules for
	 * @param connection  The database connection
	 *
	 * @return The ingest modules of the job
	 *
	 * @throws SQLException If it fails to get the modules from the db.
	 */
	private List<IngestModuleInfo> getIngestModules(int ingestJobId, CaseDbConnection connection) throws SQLException {
		ResultSet resultSet = null;
		Statement statement = null;
		List<IngestModuleInfo> ingestModules = new ArrayList<>();
		acquireSingleUserCaseReadLock();
		try {
			statement = connection.createStatement();
			resultSet = statement.executeQuery("SELECT ingest_job_modules.ingest_module_id AS ingest_module_id, "
					+ "ingest_job_modules.pipeline_position AS pipeline_position, "
					+ "ingest_modules.display_name AS display_name, ingest_modules.unique_name AS unique_name, "
					+ "ingest_modules.type_id AS type_id, ingest_modules.version AS version "
					+ "FROM ingest_job_modules, ingest_modules "
					+ "WHERE ingest_job_modules.ingest_job_id = " + ingestJobId + " "
					+ "AND ingest_modules.ingest_module_id = ingest_job_modules.ingest_module_id "
					+ "ORDER BY (ingest_job_modules.pipeline_position);");
			while (resultSet.next()) {
				ingestModules.add(new IngestModuleInfo(resultSet.getInt("ingest_module_id"), resultSet.getString("display_name"),
						resultSet.getString("unique_name"), IngestModuleType.fromID(resultSet.getInt("type_id")), resultSet.getString("version")));
			}
			return ingestModules;
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			releaseSingleUserCaseReadLock();

		}
	}

	/**
	 * Builds "INSERT or IGNORE ....", or "INSERT .... ON CONFLICT DO NOTHING"
	 * insert SQL, based on the database type being used, using the given base
	 * SQL.
	 *
	 * @param sql Base insert SQL - "INTO xyz ...."
	 *
	 * @return SQL string.
	 */
	String getInsertOrIgnoreSQL(String sql) {
		switch (getDatabaseType()) {
			case POSTGRESQL:
				return " INSERT " + sql + " ON CONFLICT DO NOTHING "; //NON-NLS
			case SQLITE:
				return " INSERT OR IGNORE " + sql; //NON-NLS
			default:
				throw new UnsupportedOperationException("Unsupported DB type: " + getDatabaseType().name());
		}
	}

	/**
	 * Returns a list of Blackboard artifact whoes values in dbColumn match the
	 * list of values. The method will generate an SQL OR statement that can be
	 * used as part of a where clause to retrieve artifacts for a set of values.
	 *
	 * For example getArtifactsForValues("artifacts.artifact_obj_id",
	 * artifactObjIdList) will return a list of artifacts for the artifactObjID
	 * values in the given list.
	 *
	 * When using this method be sure to use the tables as nicknamed in
	 * DATA_ARTIFACT_QUERY_STRING and ANALYSIS_RESULT_QUERY_STRING;
	 *
	 * @param category The type of artifacts to return.
	 * @param dbColumn The database column.
	 * @param value    List of values.
	 *
	 * @return A list of BlackboardArtifacts
	 *
	 * @throws TskCoreException
	 */
	private List<? extends BlackboardArtifact> getArtifactsForValues(BlackboardArtifact.Category category, String dbColumn, List<? extends Number> values, CaseDbConnection connection) throws TskCoreException {
		String where = "";
		// This look creates the OR statement with the following format:
		// <dbColumn> = <value> OR <dbColumn> = <value2> OR ...  
		for (Number value : values) {
			if (!where.isEmpty()) {
				where += " OR ";
			}
			where += dbColumn + " = " + value;
		}

		// Base on the category pass the OR statement to the approprate method
		// that will retrieve the artifacts.
		if (category == BlackboardArtifact.Category.DATA_ARTIFACT) {
			return blackboard.getDataArtifactsWhere(where, connection);
		} else {
			return blackboard.getAnalysisResultsWhere(where, connection);
		}
	}

	/**
	 * Stores a pair of object ID and its type
	 */
	static class ObjectInfo {

		private long id;
		private TskData.ObjectType type;

		ObjectInfo(long id, ObjectType type) {
			this.id = id;
			this.type = type;
		}

		long getId() {
			return id;
		}

		TskData.ObjectType getType() {
			return type;
		}
	}

	private interface DbCommand {

		void execute() throws SQLException;
	}

	private enum PREPARED_STATEMENT {

		SELECT_ARTIFACTS_BY_TYPE("SELECT artifact_id, obj_id FROM blackboard_artifacts " //NON-NLS
				+ "WHERE artifact_type_id = ?"), //NON-NLS
		COUNT_ARTIFACTS_OF_TYPE("SELECT COUNT(*) AS count FROM blackboard_artifacts WHERE artifact_type_id = ? AND review_status_id != " + BlackboardArtifact.ReviewStatus.REJECTED.getID()), //NON-NLS
		COUNT_ARTIFACTS_OF_TYPE_BY_DATA_SOURCE("SELECT COUNT(*) AS count FROM blackboard_artifacts WHERE data_source_obj_id = ? AND artifact_type_id = ? AND review_status_id != " + BlackboardArtifact.ReviewStatus.REJECTED.getID()), //NON-NLS
		COUNT_ARTIFACTS_FROM_SOURCE("SELECT COUNT(*) AS count FROM blackboard_artifacts WHERE obj_id = ? AND review_status_id != " + BlackboardArtifact.ReviewStatus.REJECTED.getID()), //NON-NLS
		COUNT_ARTIFACTS_BY_SOURCE_AND_TYPE("SELECT COUNT(*) AS count FROM blackboard_artifacts WHERE obj_id = ? AND artifact_type_id = ? AND review_status_id != " + BlackboardArtifact.ReviewStatus.REJECTED.getID()), //NON-NLS
		SELECT_FILES_BY_PARENT("SELECT tsk_files.* " //NON-NLS
				+ "FROM tsk_objects INNER JOIN tsk_files " //NON-NLS
				+ "ON tsk_objects.obj_id=tsk_files.obj_id " //NON-NLS
				+ "WHERE (tsk_objects.par_obj_id = ? ) " //NON-NLS
				+ "ORDER BY tsk_files.meta_type DESC, LOWER(tsk_files.name)"), //NON-NLS
		SELECT_FILES_BY_PARENT_AND_TYPE("SELECT tsk_files.* " //NON-NLS
				+ "FROM tsk_objects INNER JOIN tsk_files " //NON-NLS
				+ "ON tsk_objects.obj_id=tsk_files.obj_id " //NON-NLS
				+ "WHERE (tsk_objects.par_obj_id = ? AND tsk_files.type = ? ) " //NON-NLS
				+ "ORDER BY tsk_files.dir_type, LOWER(tsk_files.name)"), //NON-NLS
		SELECT_FILES_BY_PARENT_AND_NAME("SELECT tsk_files.* " //NON-NLS
				+ "FROM tsk_objects INNER JOIN tsk_files " //NON-NLS
				+ "ON tsk_objects.obj_id=tsk_files.obj_id " //NON-NLS
				+ "WHERE (tsk_objects.par_obj_id = ? AND " //NON-NLS
				+ "LOWER(tsk_files.name) LIKE LOWER(?) AND LOWER(tsk_files.name) NOT LIKE LOWER('%journal%')) "//NON-NLS
				+ "ORDER BY tsk_files.dir_type, LOWER(tsk_files.name)"), //NON-NLS
		SELECT_FILES_BY_EXTENSION_AND_PARENT_AND_NAME("SELECT tsk_files.* " //NON-NLS
				+ "FROM tsk_objects INNER JOIN tsk_files " //NON-NLS
				+ "ON tsk_objects.obj_id=tsk_files.obj_id " //NON-NLS
				+ "WHERE tsk_files.extension = ? AND "
				+ "(tsk_objects.par_obj_id = ? AND " //NON-NLS
				+ "LOWER(tsk_files.name) LIKE LOWER(?) AND LOWER(tsk_files.name) NOT LIKE LOWER('%journal%')) "//NON-NLS
				+ "ORDER BY tsk_files.dir_type, LOWER(tsk_files.name)"), //NON-NLS
		SELECT_FILE_IDS_BY_PARENT("SELECT tsk_files.obj_id AS obj_id " //NON-NLS
				+ "FROM tsk_objects INNER JOIN tsk_files " //NON-NLS
				+ "ON tsk_objects.obj_id=tsk_files.obj_id " //NON-NLS
				+ "WHERE (tsk_objects.par_obj_id = ?)"), //NON-NLS
		SELECT_FILE_IDS_BY_PARENT_AND_TYPE("SELECT tsk_files.obj_id AS obj_id " //NON-NLS
				+ "FROM tsk_objects INNER JOIN tsk_files " //NON-NLS
				+ "ON tsk_objects.obj_id=tsk_files.obj_id " //NON-NLS
				+ "WHERE (tsk_objects.par_obj_id = ? " //NON-NLS
				+ "AND tsk_files.type = ? )"), //NON-NLS
		SELECT_FILE_BY_ID("SELECT * FROM tsk_files WHERE obj_id = ? LIMIT 1"), //NON-NLS
		SELECT_ARTIFACT_BY_ARTIFACT_OBJ_ID("SELECT * FROM blackboard_artifacts WHERE artifact_obj_id = ? LIMIT 1"),
		SELECT_ARTIFACT_TYPE_BY_ARTIFACT_OBJ_ID("SELECT artifact_type_id FROM blackboard_artifacts WHERE artifact_obj_id = ? LIMIT 1"),
		SELECT_ARTIFACT_BY_ARTIFACT_ID("SELECT * FROM blackboard_artifacts WHERE artifact_id = ? LIMIT 1"),
		INSERT_ARTIFACT("INSERT INTO blackboard_artifacts (artifact_id, obj_id, artifact_obj_id, data_source_obj_id, artifact_type_id, review_status_id) " //NON-NLS
				+ "VALUES (?, ?, ?, ?, ?," + BlackboardArtifact.ReviewStatus.UNDECIDED.getID() + ")"), //NON-NLS
		POSTGRESQL_INSERT_ARTIFACT("INSERT INTO blackboard_artifacts (artifact_id, obj_id, artifact_obj_id, data_source_obj_id, artifact_type_id, review_status_id) " //NON-NLS
				+ "VALUES (DEFAULT, ?, ?, ?, ?," + BlackboardArtifact.ReviewStatus.UNDECIDED.getID() + ")"), //NON-NLS
		INSERT_ANALYSIS_RESULT("INSERT INTO tsk_analysis_results (artifact_obj_id, conclusion, significance, priority, configuration, justification) " //NON-NLS
				+ "VALUES (?, ?, ?, ?, ?, ?)"), //NON-NLS
		INSERT_STRING_ATTRIBUTE("INSERT INTO blackboard_attributes (artifact_id, artifact_type_id, source, context, attribute_type_id, value_type, value_text) " //NON-NLS
				+ "VALUES (?,?,?,?,?,?,?)"), //NON-NLS
		INSERT_BYTE_ATTRIBUTE("INSERT INTO blackboard_attributes (artifact_id, artifact_type_id, source, context, attribute_type_id, value_type, value_byte) " //NON-NLS
				+ "VALUES (?,?,?,?,?,?,?)"), //NON-NLS
		INSERT_INT_ATTRIBUTE("INSERT INTO blackboard_attributes (artifact_id, artifact_type_id, source, context, attribute_type_id, value_type, value_int32) " //NON-NLS
				+ "VALUES (?,?,?,?,?,?,?)"), //NON-NLS
		INSERT_LONG_ATTRIBUTE("INSERT INTO blackboard_attributes (artifact_id, artifact_type_id, source, context, attribute_type_id, value_type, value_int64) " //NON-NLS
				+ "VALUES (?,?,?,?,?,?,?)"), //NON-NLS
		INSERT_DOUBLE_ATTRIBUTE("INSERT INTO blackboard_attributes (artifact_id, artifact_type_id, source, context, attribute_type_id, value_type, value_double) " //NON-NLS
				+ "VALUES (?,?,?,?,?,?,?)"), //NON-NLS
		INSERT_FILE_ATTRIBUTE("INSERT INTO tsk_file_attributes (obj_id, attribute_type_id, value_type, value_byte, value_text, value_int32, value_int64, value_double) " //NON-NLS
				+ "VALUES (?,?,?,?,?,?,?,?)"), //NON-NLS
		SELECT_FILES_BY_DATA_SOURCE_AND_NAME("SELECT * FROM tsk_files WHERE LOWER(name) LIKE LOWER(?) AND LOWER(name) NOT LIKE LOWER('%journal%') AND data_source_obj_id = ?"), //NON-NLS
		SELECT_FILES_BY_EXTENSION_AND_DATA_SOURCE_AND_NAME("SELECT * FROM tsk_files WHERE extension = ? AND LOWER(name) LIKE LOWER(?) AND LOWER(name) NOT LIKE LOWER('%journal%') AND data_source_obj_id = ?"), //NON-NLS
		SELECT_FILES_BY_DATA_SOURCE_AND_PARENT_PATH_AND_NAME("SELECT * FROM tsk_files WHERE LOWER(name) LIKE LOWER(?) AND LOWER(name) NOT LIKE LOWER('%journal%') AND LOWER(parent_path) LIKE LOWER(?) AND data_source_obj_id = ?"), //NON-NLS
		SELECT_FILES_BY_EXTENSION_AND_DATA_SOURCE_AND_PARENT_PATH_AND_NAME("SELECT * FROM tsk_files WHERE extension = ? AND LOWER(name) LIKE LOWER(?) AND LOWER(name) NOT LIKE LOWER('%journal%') AND LOWER(parent_path) LIKE LOWER(?) AND data_source_obj_id = ?"), //NON-NLS
		UPDATE_FILE_MD5("UPDATE tsk_files SET md5 = ? WHERE obj_id = ?"), //NON-NLS
		UPDATE_IMAGE_MD5("UPDATE tsk_image_info SET md5 = ? WHERE obj_id = ?"), //NON-NLS
		UPDATE_IMAGE_SHA1("UPDATE tsk_image_info SET sha1 = ? WHERE obj_id = ?"), //NON-NLS
		UPDATE_IMAGE_SHA256("UPDATE tsk_image_info SET sha256 = ? WHERE obj_id = ?"), //NON-NLS
		SELECT_IMAGE_MD5("SELECT md5 FROM tsk_image_info WHERE obj_id = ?"), //NON-NLS
		SELECT_IMAGE_SHA1("SELECT sha1 FROM tsk_image_info WHERE obj_id = ?"), //NON-NLS
		SELECT_IMAGE_SHA256("SELECT sha256 FROM tsk_image_info WHERE obj_id = ?"), //NON-NLS
		UPDATE_ACQUISITION_DETAILS("UPDATE data_source_info SET acquisition_details = ? WHERE obj_id = ?"), //NON-NLS
		UPDATE_ACQUISITION_TOOL_SETTINGS("UPDATE data_source_info SET acquisition_tool_settings = ?, acquisition_tool_name = ?, acquisition_tool_version = ? WHERE obj_id = ?"), //NON-NLS
		SELECT_ACQUISITION_DETAILS("SELECT acquisition_details FROM data_source_info WHERE obj_id = ?"), //NON-NLS
		SELECT_ACQUISITION_TOOL_SETTINGS("SELECT acquisition_tool_settings, acquisition_tool_name, acquisition_tool_version, added_date_time FROM data_source_info WHERE obj_id = ?"), //NON-NLS
		SELECT_LOCAL_PATH_FOR_FILE("SELECT path FROM tsk_files_path WHERE obj_id = ?"), //NON-NLS
		SELECT_ENCODING_FOR_FILE("SELECT encoding_type FROM tsk_files_path WHERE obj_id = ?"), // NON-NLS
		SELECT_LOCAL_PATH_AND_ENCODING_FOR_FILE("SELECT path, encoding_type FROM tsk_files_path WHERE obj_id = ?"), // NON_NLS
		SELECT_PATH_FOR_FILE("SELECT parent_path FROM tsk_files WHERE obj_id = ?"), //NON-NLS
		SELECT_FILE_NAME("SELECT name FROM tsk_files WHERE obj_id = ?"), //NON-NLS
		SELECT_DERIVED_FILE("SELECT derived_id, rederive FROM tsk_files_derived WHERE obj_id = ?"), //NON-NLS
		SELECT_FILE_DERIVATION_METHOD("SELECT tool_name, tool_version, other FROM tsk_files_derived_method WHERE derived_id = ?"), //NON-NLS
		SELECT_MAX_OBJECT_ID("SELECT MAX(obj_id) AS max_obj_id FROM tsk_objects"), //NON-NLS
		INSERT_OBJECT("INSERT INTO tsk_objects (par_obj_id, type) VALUES (?, ?)"), //NON-NLS
		INSERT_FILE("INSERT INTO tsk_files (obj_id, fs_obj_id, name, type, has_path, dir_type, meta_type, dir_flags, meta_flags, size, ctime, crtime, atime, mtime, md5, sha256, sha1, known, mime_type, parent_path, data_source_obj_id, extension, owner_uid, os_account_obj_id, collected) " //NON-NLS
				+ "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"), //NON-NLS
		INSERT_FILE_SYSTEM_FILE("INSERT INTO tsk_files(obj_id, fs_obj_id, data_source_obj_id, attr_type, attr_id, name, meta_addr, meta_seq, type, has_path, dir_type, meta_type, dir_flags, meta_flags, size, ctime, crtime, atime, mtime, md5, sha256, sha1, mime_type, parent_path, extension, owner_uid, os_account_obj_id, collected)"
				+ " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"), // NON-NLS
		UPDATE_DERIVED_FILE("UPDATE tsk_files SET type = ?, dir_type = ?, meta_type = ?, dir_flags = ?,  meta_flags = ?, size= ?, ctime= ?, crtime= ?, atime= ?, mtime= ?, mime_type = ?  "
				+ "WHERE obj_id = ?"), //NON-NLS
		INSERT_LAYOUT_FILE("INSERT INTO tsk_file_layout (obj_id, byte_start, byte_len, sequence) " //NON-NLS
				+ "VALUES (?, ?, ?, ?)"), //NON-NLS
		INSERT_LOCAL_PATH("INSERT INTO tsk_files_path (obj_id, path, encoding_type) VALUES (?, ?, ?)"), //NON-NLS
		UPDATE_LOCAL_PATH("UPDATE tsk_files_path SET path = ?, encoding_type = ? WHERE obj_id = ?"), //NON-NLS
		COUNT_CHILD_OBJECTS_BY_PARENT("SELECT COUNT(obj_id) AS count FROM tsk_objects WHERE par_obj_id = ?"), //NON-NLS
		SELECT_FILE_SYSTEM_BY_OBJECT("SELECT fs_obj_id from tsk_files WHERE obj_id=?"), //NON-NLS
		SELECT_TAG_NAMES("SELECT * FROM tag_names"), //NON-NLS
		SELECT_TAG_NAMES_IN_USE("SELECT * FROM tag_names " //NON-NLS
				+ "WHERE tag_name_id IN " //NON-NLS
				+ "(SELECT tag_name_id from content_tags UNION SELECT tag_name_id FROM blackboard_artifact_tags)"), //NON-NLS
		SELECT_TAG_NAMES_IN_USE_BY_DATASOURCE("SELECT * FROM tag_names "
				+ "WHERE tag_name_id IN "
				+ "( SELECT content_tags.tag_name_id as tag_name_id "
				+ "FROM content_tags as content_tags, tsk_files as tsk_files"
				+ " WHERE content_tags.obj_id = tsk_files.obj_id"
				+ " AND tsk_files.data_source_obj_id =  ?"
				+ " UNION "
				+ "SELECT artifact_tags.tag_name_id as tag_name_id "
				+ " FROM blackboard_artifact_tags as artifact_tags, blackboard_artifacts AS arts "
				+ " WHERE artifact_tags.artifact_id = arts.artifact_id"
				+ " AND arts.data_source_obj_id =  ?"
				+ " )"),
		INSERT_TAG_NAME("INSERT INTO tag_names (display_name, description, color, knownStatus) VALUES (?, ?, ?, ?)"), //NON-NLS
		INSERT_CONTENT_TAG("INSERT INTO content_tags (obj_id, tag_name_id, comment, begin_byte_offset, end_byte_offset, examiner_id) VALUES (?, ?, ?, ?, ?, ?)"), //NON-NLS
		DELETE_CONTENT_TAG("DELETE FROM content_tags WHERE tag_id = ?"), //NON-NLS
		COUNT_CONTENT_TAGS_BY_TAG_NAME("SELECT COUNT(*) AS count FROM content_tags WHERE tag_name_id = ?"), //NON-NLS
		COUNT_CONTENT_TAGS_BY_TAG_NAME_BY_DATASOURCE(
				"SELECT COUNT(*) AS count FROM content_tags as content_tags, tsk_files as tsk_files WHERE content_tags.obj_id = tsk_files.obj_id"
				+ " AND content_tags.tag_name_id = ? "
				+ " AND tsk_files.data_source_obj_id = ? "
		),
		SELECT_CONTENT_TAGS("SELECT content_tags.tag_id, content_tags.obj_id, content_tags.tag_name_id, content_tags.comment, content_tags.begin_byte_offset, content_tags.end_byte_offset, tag_names.display_name, tag_names.description, tag_names.color, tag_names.knownStatus, tsk_examiners.login_name, tag_names.tag_set_id, tag_names.rank "
				+ "FROM content_tags "
				+ "INNER JOIN tag_names ON content_tags.tag_name_id = tag_names.tag_name_id "
				+ "LEFT OUTER JOIN tsk_examiners ON content_tags.examiner_id = tsk_examiners.examiner_id"), //NON-NLS
		SELECT_CONTENT_TAGS_BY_TAG_NAME("SELECT content_tags.tag_id, content_tags.obj_id, content_tags.tag_name_id, content_tags.comment, content_tags.begin_byte_offset, content_tags.end_byte_offset, tsk_examiners.login_name "
				+ "FROM content_tags "
				+ "LEFT OUTER JOIN tsk_examiners ON content_tags.examiner_id = tsk_examiners.examiner_id "
				+ "WHERE tag_name_id = ?"), //NON-NLS		
		SELECT_CONTENT_TAGS_BY_TAG_NAME_BY_DATASOURCE("SELECT content_tags.tag_id, content_tags.obj_id, content_tags.tag_name_id, content_tags.comment, content_tags.begin_byte_offset, content_tags.end_byte_offset, tag_names.display_name, tag_names.description, tag_names.color, tag_names.knownStatus, tag_names.tag_set_id, tsk_examiners.login_name "
			+ "FROM content_tags "
			+ "JOIN tsk_os_accounts acc ON content_tags.obj_id = acc.os_account_obj_id "
			+ "JOIN tag_names ON content_tags.tag_name_id = tag_names.tag_name_id "
			+ "JOIN tsk_examiners ON content_tags.examiner_id = tsk_examiners.examiner_id "
			+ "WHERE content_tags.tag_name_id = ? "
			+ "AND acc.os_account_obj_id IN (SELECT os_account_obj_id FROM tsk_os_account_instances WHERE data_source_obj_id = ?) "
			+ "AND acc.db_status = " + OsAccount.OsAccountDbStatus.ACTIVE.getId()
			+ " UNION "
			+ "SELECT content_tags.tag_id, content_tags.obj_id, content_tags.tag_name_id, content_tags.comment, content_tags.begin_byte_offset, content_tags.end_byte_offset, tag_names.display_name, tag_names.description, tag_names.color, tag_names.knownStatus, tag_names.tag_set_id, tsk_examiners.login_name "
			+ "FROM content_tags as content_tags, tsk_files as tsk_files, tag_names as tag_names, tsk_examiners as tsk_examiners "
			+ "WHERE content_tags.examiner_id = tsk_examiners.examiner_id "
			+ "AND content_tags.obj_id = tsk_files.obj_id "
			+ "AND content_tags.tag_name_id = tag_names.tag_name_id "
			+ "AND content_tags.tag_name_id = ? "
			+ "AND tsk_files.data_source_obj_id = ? "), //NON-NLS	
		SELECT_CONTENT_TAG_BY_ID("SELECT content_tags.tag_id, content_tags.obj_id, content_tags.tag_name_id, content_tags.comment, content_tags.begin_byte_offset, content_tags.end_byte_offset, tag_names.display_name, tag_names.description, tag_names.color, tag_names.knownStatus, tsk_examiners.login_name, tag_names.tag_set_id, tag_names.rank "
				+ "FROM content_tags "
				+ "INNER JOIN tag_names ON content_tags.tag_name_id = tag_names.tag_name_id "
				+ "LEFT OUTER JOIN tsk_examiners ON content_tags.examiner_id = tsk_examiners.examiner_id "
				+ "WHERE tag_id = ?"), //NON-NLS
		SELECT_CONTENT_TAGS_BY_CONTENT("SELECT content_tags.tag_id, content_tags.obj_id, content_tags.tag_name_id, content_tags.comment, content_tags.begin_byte_offset, content_tags.end_byte_offset, tag_names.display_name, tag_names.description, tag_names.color, tag_names.knownStatus, tsk_examiners.login_name, tag_names.tag_set_id, tag_names.rank "
				+ "FROM content_tags "
				+ "INNER JOIN tag_names ON content_tags.tag_name_id = tag_names.tag_name_id "
				+ "LEFT OUTER JOIN tsk_examiners ON content_tags.examiner_id = tsk_examiners.examiner_id "
				+ "WHERE content_tags.obj_id = ?"), //NON-NLS
		INSERT_ARTIFACT_TAG("INSERT INTO blackboard_artifact_tags (artifact_id, tag_name_id, comment, examiner_id) "
				+ "VALUES (?, ?, ?, ?)"), //NON-NLS
		DELETE_ARTIFACT_TAG("DELETE FROM blackboard_artifact_tags WHERE tag_id = ?"), //NON-NLS
		SELECT_ARTIFACT_TAGS("SELECT blackboard_artifact_tags.tag_id, blackboard_artifact_tags.artifact_id, blackboard_artifact_tags.tag_name_id, blackboard_artifact_tags.comment, tag_names.display_name, tag_names.description, tag_names.color, tag_names.knownStatus, tag_names.tag_set_id, tsk_examiners.login_name, tag_names.rank "
				+ "FROM blackboard_artifact_tags "
				+ "INNER JOIN tag_names ON blackboard_artifact_tags.tag_name_id = tag_names.tag_name_id "
				+ "LEFT OUTER JOIN tsk_examiners ON blackboard_artifact_tags.examiner_id = tsk_examiners.examiner_id"), //NON-NLS
		COUNT_ARTIFACTS_BY_TAG_NAME("SELECT COUNT(*) AS count FROM blackboard_artifact_tags WHERE tag_name_id = ?"), //NON-NLS
		COUNT_ARTIFACTS_BY_TAG_NAME_BY_DATASOURCE("SELECT COUNT(*) AS count FROM blackboard_artifact_tags as artifact_tags, blackboard_artifacts AS arts WHERE artifact_tags.artifact_id = arts.artifact_id"
				+ " AND artifact_tags.tag_name_id = ?"
				+ " AND arts.data_source_obj_id =  ? "),
		SELECT_ARTIFACT_TAGS_BY_TAG_NAME("SELECT blackboard_artifact_tags.tag_id, blackboard_artifact_tags.artifact_id, blackboard_artifact_tags.tag_name_id, blackboard_artifact_tags.comment, tsk_examiners.login_name "
				+ "FROM blackboard_artifact_tags "
				+ "LEFT OUTER JOIN tsk_examiners ON blackboard_artifact_tags.examiner_id = tsk_examiners.examiner_id "
				+ "WHERE tag_name_id = ?"), //NON-NLS
		SELECT_ARTIFACT_TAGS_BY_TAG_NAME_BY_DATASOURCE("SELECT artifact_tags.tag_id, artifact_tags.artifact_id, artifact_tags.tag_name_id, artifact_tags.comment, arts.obj_id, arts.artifact_obj_id, arts.data_source_obj_id, arts.artifact_type_id, arts.review_status_id, tsk_examiners.login_name "
				+ "FROM blackboard_artifact_tags as artifact_tags, blackboard_artifacts AS arts, tsk_examiners AS tsk_examiners "
				+ "WHERE artifact_tags.examiner_id = tsk_examiners.examiner_id"
				+ " AND artifact_tags.artifact_id = arts.artifact_id"
				+ " AND artifact_tags.tag_name_id = ? "
				+ " AND arts.data_source_obj_id =  ? "),
		SELECT_ARTIFACT_TAG_BY_ID("SELECT blackboard_artifact_tags.tag_id, blackboard_artifact_tags.artifact_id, blackboard_artifact_tags.tag_name_id, blackboard_artifact_tags.comment, tag_names.display_name, tag_names.description, tag_names.color, tag_names.knownStatus, tsk_examiners.login_name, tag_names.tag_set_id, tag_names.rank "
				+ "FROM blackboard_artifact_tags "
				+ "INNER JOIN tag_names ON blackboard_artifact_tags.tag_name_id = tag_names.tag_name_id  "
				+ "LEFT OUTER JOIN tsk_examiners ON blackboard_artifact_tags.examiner_id = tsk_examiners.examiner_id "
				+ "WHERE blackboard_artifact_tags.tag_id = ?"), //NON-NLS
		SELECT_ARTIFACT_TAGS_BY_ARTIFACT("SELECT blackboard_artifact_tags.tag_id, blackboard_artifact_tags.artifact_id, blackboard_artifact_tags.tag_name_id, blackboard_artifact_tags.comment, tag_names.display_name, tag_names.description, tag_names.color, tag_names.knownStatus, tsk_examiners.login_name, tag_names.tag_set_id, tag_names.rank "
				+ "FROM blackboard_artifact_tags "
				+ "INNER JOIN tag_names ON blackboard_artifact_tags.tag_name_id = tag_names.tag_name_id "
				+ "LEFT OUTER JOIN tsk_examiners ON blackboard_artifact_tags.examiner_id = tsk_examiners.examiner_id "
				+ "WHERE blackboard_artifact_tags.artifact_id = ?"), //NON-NLS
		SELECT_REPORTS("SELECT * FROM reports"), //NON-NLS
		SELECT_REPORT_BY_ID("SELECT * FROM reports WHERE obj_id = ?"), //NON-NLS
		INSERT_REPORT("INSERT INTO reports (obj_id, path, crtime, src_module_name, report_name) VALUES (?, ?, ?, ?, ?)"), //NON-NLS
		DELETE_REPORT("DELETE FROM reports WHERE reports.obj_id = ?"), //NON-NLS
		DELETE_REPORT_TSK_OBJECT("DELETE FROM tsk_objects where tsk_objects.obj_id = ? and tsk_objects.type = ?"),
		INSERT_INGEST_JOB("INSERT INTO ingest_jobs (obj_id, host_name, start_date_time, end_date_time, status_id, settings_dir) VALUES (?, ?, ?, ?, ?, ?)"), //NON-NLS
		INSERT_INGEST_MODULE("INSERT INTO ingest_modules (display_name, unique_name, type_id, version) VALUES(?, ?, ?, ?)"), //NON-NLS
		SELECT_ATTR_BY_VALUE_BYTE("SELECT source FROM blackboard_attributes WHERE artifact_id = ? AND attribute_type_id = ? AND value_type = 4 AND value_byte = ?"), //NON-NLS
		UPDATE_ATTR_BY_VALUE_BYTE("UPDATE blackboard_attributes SET source = ? WHERE artifact_id = ? AND attribute_type_id = ? AND value_type = 4 AND value_byte = ?"), //NON-NLS
		UPDATE_IMAGE_PATH("UPDATE tsk_image_names SET name = ? WHERE obj_id = ?"), // NON-NLS 
		SELECT_ARTIFACT_OBJECTIDS_BY_PARENT("SELECT blackboard_artifacts.artifact_obj_id AS artifact_obj_id " //NON-NLS
				+ "FROM tsk_objects INNER JOIN blackboard_artifacts " //NON-NLS
				+ "ON tsk_objects.obj_id=blackboard_artifacts.obj_id " //NON-NLS
				+ "WHERE (tsk_objects.par_obj_id = ?)"),
		SELECT_EXAMINER_BY_ID("SELECT * FROM tsk_examiners WHERE examiner_id = ?"),
		SELECT_EXAMINER_BY_LOGIN_NAME("SELECT * FROM tsk_examiners WHERE login_name = ?"),
		INSERT_EXAMINER_POSTGRESQL("INSERT INTO tsk_examiners (login_name) VALUES (?) ON CONFLICT DO NOTHING"),
		INSERT_EXAMINER_SQLITE("INSERT OR IGNORE INTO tsk_examiners (login_name) VALUES (?)"),
		UPDATE_FILE_NAME("UPDATE tsk_files SET name = ? WHERE obj_id = ?"),
		UPDATE_IMAGE_NAME("UPDATE tsk_image_info SET display_name = ? WHERE obj_id = ?"),
		UPDATE_IMAGE_SIZES("UPDATE tsk_image_info SET size = ?, ssize = ? WHERE obj_id = ?"),
		DELETE_IMAGE_NAME("DELETE FROM tsk_image_names WHERE obj_id = ?"),
		INSERT_IMAGE_NAME("INSERT INTO tsk_image_names (obj_id, name, sequence) VALUES (?, ?, ?)"),
		INSERT_IMAGE_INFO("INSERT INTO tsk_image_info (obj_id, type, ssize, tzone, size, md5, sha1, sha256, display_name)"
				+ " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"),
		INSERT_DATA_SOURCE_INFO("INSERT INTO data_source_info (obj_id, device_id, time_zone, added_date_time, host_id, acquisition_tool_settings) VALUES (?, ?, ?, ?, ?, ?)"),
		INSERT_VS_INFO("INSERT INTO tsk_vs_info (obj_id, vs_type, img_offset, block_size) VALUES (?, ?, ?, ?)"),
		INSERT_VS_PART_SQLITE("INSERT INTO tsk_vs_parts (obj_id, addr, start, length, desc, flags) VALUES (?, ?, ?, ?, ?, ?)"),
		INSERT_VS_PART_POSTGRESQL("INSERT INTO tsk_vs_parts (obj_id, addr, start, length, descr, flags) VALUES (?, ?, ?, ?, ?, ?)"),
		INSERT_POOL_INFO("INSERT INTO tsk_pool_info (obj_id, pool_type) VALUES (?, ?)"),
		INSERT_FS_INFO("INSERT INTO tsk_fs_info (obj_id, data_source_obj_id, img_offset, fs_type, block_size, block_count, root_inum, first_inum, last_inum, display_name)"
				+ "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
		SELECT_TAG_NAME_BY_ID("SELECT * FROM tag_names where tag_name_id = ?");

		private final String sql;

		private PREPARED_STATEMENT(String sql) {
			this.sql = sql;
		}

		String getSQL() {
			return sql;
		}
	}

	/**
	 * A class for the connection pool. This class will hand out connections of
	 * the appropriate type based on the subclass that is calling
	 * getPooledConnection();
	 */
	abstract private class ConnectionPool {

		private PooledDataSource pooledDataSource;

		public ConnectionPool() {
			pooledDataSource = null;
		}

		CaseDbConnection getConnection() throws TskCoreException {
			if (pooledDataSource == null) {
				throw new TskCoreException("Error getting case database connection - case is closed");
			}
			try {
				return getPooledConnection();
			} catch (SQLException exp) {
				throw new TskCoreException(exp.getMessage());
			}
		}

		void close() throws TskCoreException {
			if (pooledDataSource != null) {
				try {
					pooledDataSource.close();
				} catch (SQLException exp) {
					throw new TskCoreException(exp.getMessage());
				} finally {
					pooledDataSource = null;
				}
			}
		}

		abstract CaseDbConnection getPooledConnection() throws SQLException;

		public PooledDataSource getPooledDataSource() {
			return pooledDataSource;
		}

		public void setPooledDataSource(PooledDataSource pooledDataSource) {
			this.pooledDataSource = pooledDataSource;
		}
	}

	/**
	 * Handles the initial setup of SQLite database connections, as well as
	 * overriding getPooledConnection()
	 */
	private final class SQLiteConnections extends ConnectionPool {

		private final Map<String, String> configurationOverrides = new HashMap<String, String>();

		SQLiteConnections(String dbPath) throws SQLException {
			configurationOverrides.put("acquireIncrement", "2");
			configurationOverrides.put("initialPoolSize", "5");
			configurationOverrides.put("minPoolSize", "5");
			/*
			 * NOTE: max pool size and max statements are related. If you
			 * increase max pool size, then also increase statements.
			 */
			configurationOverrides.put("maxPoolSize", "20");
			configurationOverrides.put("maxStatements", "200");
			configurationOverrides.put("maxStatementsPerConnection", "20");

			SQLiteConfig config = new SQLiteConfig();
			config.setSynchronous(SQLiteConfig.SynchronousMode.OFF); // Reduce I/O operations, we have no OS crash recovery anyway.
			config.setReadUncommitted(true);
			config.enforceForeignKeys(true); // Enforce foreign key constraints.
			SQLiteDataSource unpooled = new SQLiteDataSource(config);
			unpooled.setUrl("jdbc:sqlite:" + dbPath);
			setPooledDataSource((PooledDataSource) DataSources.pooledDataSource(unpooled, configurationOverrides));
		}

		@Override
		public CaseDbConnection getPooledConnection() throws SQLException {
			// If the requesting thread already has an open transaction, the new connection may get SQLITE_BUSY errors. 
			if (CaseDbTransaction.hasOpenTransaction(Thread.currentThread().getId())) {
				// Temporarily filter out Image Gallery threads
				if (!Thread.currentThread().getName().contains("ImageGallery")) {
					logger.log(Level.WARNING, String.format("Thread %s (ID = %d) already has an open transaction.  New connection may encounter SQLITE_BUSY error. ", Thread.currentThread().getName(), Thread.currentThread().getId()), new Throwable());
				}
			}
			return new SQLiteConnection(getPooledDataSource().getConnection());
		}
	}

	/**
	 * Handles the initial setup of PostgreSQL database connections, as well as
	 * overriding getPooledConnection()
	 */
	private final class PostgreSQLConnections extends ConnectionPool {

		PostgreSQLConnections(CaseDbConnectionInfo info, String dbName) throws PropertyVetoException, UnsupportedEncodingException {
			
			ComboPooledDataSource comboPooledDataSource = new ComboPooledDataSource();
			comboPooledDataSource.setDriverClass("org.postgresql.Driver"); //loads the jdbc driver
			
			String connectionURL = "jdbc:postgresql://" + info.getHost() + ":" + Integer.valueOf(info.getPort()) + "/"
					+ URLEncoder.encode(dbName, StandardCharsets.UTF_8.toString());
			if (info.isSslEnabled()) {
				if (info.isSslVerify()) {
					if (info.getCustomSslValidationClassName().isBlank()) {
						connectionURL += CaseDatabaseFactory.SSL_VERIFY_DEFAULT_URL;
					} else {
						// use custom SSL certificate validation class
						connectionURL += CaseDatabaseFactory.getCustomPostrgesSslVerificationUrl(info.getCustomSslValidationClassName());
					}
				} else {
					connectionURL += CaseDatabaseFactory.SSL_NONVERIFY_URL;
				}
			}
			comboPooledDataSource.setJdbcUrl(connectionURL);
			comboPooledDataSource.setUser(info.getUserName());
			comboPooledDataSource.setPassword(info.getPassword());
			comboPooledDataSource.setAcquireIncrement(2);
			comboPooledDataSource.setInitialPoolSize(5);
			comboPooledDataSource.setMinPoolSize(5);
			/*
			 * NOTE: max pool size and max statements are related. If you
			 * increase max pool size, then also increase statements.
			 */
			comboPooledDataSource.setMaxPoolSize(20);
			comboPooledDataSource.setMaxStatements(200);
			comboPooledDataSource.setMaxStatementsPerConnection(20);
			setPooledDataSource(comboPooledDataSource);
		}

		@Override
		public CaseDbConnection getPooledConnection() throws SQLException {
			return new PostgreSQLConnection(getPooledDataSource().getConnection());
		}
	}

	/**
	 * An abstract base class for case database connection objects.
	 */
	abstract class CaseDbConnection implements AutoCloseable {

		static final int SLEEP_LENGTH_IN_MILLISECONDS = 5000;
		static final int MAX_RETRIES = 20; //MAX_RETRIES * SLEEP_LENGTH_IN_MILLESECONDS = max time to hang attempting connection

		private class CreateStatement implements DbCommand {

			private final Connection connection;
			private Statement statement = null;

			CreateStatement(Connection connection) {
				this.connection = connection;
			}

			Statement getStatement() {
				return statement;
			}

			@Override
			public void execute() throws SQLException {
				statement = connection.createStatement();
			}
		}

		private class SetAutoCommit implements DbCommand {

			private final Connection connection;
			private final boolean mode;

			SetAutoCommit(Connection connection, boolean mode) {
				this.connection = connection;
				this.mode = mode;
			}

			@Override
			public void execute() throws SQLException {
				connection.setAutoCommit(mode);
			}
		}

		private class Commit implements DbCommand {

			private final Connection connection;

			Commit(Connection connection) {
				this.connection = connection;
			}

			@Override
			public void execute() throws SQLException {
				connection.commit();
			}
		}

		/**
		 * Obtains a write lock on tsk_aggregate_score table. Only PostgreSQL is
		 * supported.
		 *
		 * NOTE: We run into deadlock risks when we start to lock multiple
		 * tables. If that need arrises, consider changing to opportunistic
		 * locking and single-step transactions.
		 */
		private class AggregateScoreTablePostgreSQLWriteLock implements DbCommand {

			private final Connection connection;

			AggregateScoreTablePostgreSQLWriteLock(Connection connection) {
				this.connection = connection;
			}

			@Override
			public void execute() throws SQLException {
				PreparedStatement preparedStatement = connection.prepareStatement("LOCK TABLE ONLY tsk_aggregate_score in SHARE ROW EXCLUSIVE MODE");
				preparedStatement.execute();

			}
		}

		private class ExecuteQuery implements DbCommand {

			private final Statement statement;
			private final String query;
			private ResultSet resultSet;

			ExecuteQuery(Statement statement, String query) {
				this.statement = statement;
				this.query = query;
			}

			ResultSet getResultSet() {
				return resultSet;
			}

			@Override
			public void execute() throws SQLException {
				resultSet = statement.executeQuery(query);
			}
		}

		private class ExecutePreparedStatementQuery implements DbCommand {

			private final PreparedStatement preparedStatement;
			private ResultSet resultSet;

			ExecutePreparedStatementQuery(PreparedStatement preparedStatement) {
				this.preparedStatement = preparedStatement;
			}

			ResultSet getResultSet() {
				return resultSet;
			}

			@Override
			public void execute() throws SQLException {
				resultSet = preparedStatement.executeQuery();
			}
		}

		private class ExecutePreparedStatementUpdate implements DbCommand {

			private final PreparedStatement preparedStatement;

			ExecutePreparedStatementUpdate(PreparedStatement preparedStatement) {
				this.preparedStatement = preparedStatement;
			}

			@Override
			public void execute() throws SQLException {
				preparedStatement.executeUpdate();
			}
		}

		private class ExecuteStatementUpdate implements DbCommand {

			private final Statement statement;
			private final String updateCommand;

			ExecuteStatementUpdate(Statement statement, String updateCommand) {
				this.statement = statement;
				this.updateCommand = updateCommand;
			}

			@Override
			public void execute() throws SQLException {
				statement.executeUpdate(updateCommand);
			}
		}

		private class ExecuteStatementUpdateGenerateKeys implements DbCommand {

			private final Statement statement;
			private final int generateKeys;
			private final String updateCommand;

			ExecuteStatementUpdateGenerateKeys(Statement statement, String updateCommand, int generateKeys) {
				this.statement = statement;
				this.generateKeys = generateKeys;
				this.updateCommand = updateCommand;
			}

			@Override
			public void execute() throws SQLException {
				statement.executeUpdate(updateCommand, generateKeys);
			}
		}

		private class PrepareStatement implements DbCommand {

			private final Connection connection;
			private final String input;
			private PreparedStatement preparedStatement = null;

			PrepareStatement(Connection connection, String input) {
				this.connection = connection;
				this.input = input;
			}

			PreparedStatement getPreparedStatement() {
				return preparedStatement;
			}

			@Override
			public void execute() throws SQLException {
				preparedStatement = connection.prepareStatement(input);
			}
		}

		private class PrepareStatementGenerateKeys implements DbCommand {

			private final Connection connection;
			private final String input;
			private final int generateKeys;
			private PreparedStatement preparedStatement = null;

			PrepareStatementGenerateKeys(Connection connection, String input, int generateKeysInput) {
				this.connection = connection;
				this.input = input;
				this.generateKeys = generateKeysInput;
			}

			PreparedStatement getPreparedStatement() {
				return preparedStatement;
			}

			@Override
			public void execute() throws SQLException {
				preparedStatement = connection.prepareStatement(input, generateKeys);
			}
		}

		abstract void executeCommand(DbCommand command) throws SQLException;

		private final Connection connection;
		private final Map<PREPARED_STATEMENT, PreparedStatement> preparedStatements;
		private final Map<String, PreparedStatement> adHocPreparedStatements;

		CaseDbConnection(Connection connection) {
			this.connection = connection;
			preparedStatements = new EnumMap<PREPARED_STATEMENT, PreparedStatement>(PREPARED_STATEMENT.class);
			adHocPreparedStatements = new HashMap<>();
		}

		boolean isOpen() {
			return this.connection != null;
		}

		PreparedStatement getPreparedStatement(PREPARED_STATEMENT statementKey) throws SQLException {
			return getPreparedStatement(statementKey, Statement.NO_GENERATED_KEYS);
		}

		PreparedStatement getPreparedStatement(PREPARED_STATEMENT statementKey, int generateKeys) throws SQLException {
			// Lazy statement preparation.
			PreparedStatement statement;
			if (this.preparedStatements.containsKey(statementKey)) {
				statement = this.preparedStatements.get(statementKey);
			} else {
				statement = prepareStatement(statementKey.getSQL(), generateKeys);
				this.preparedStatements.put(statementKey, statement);
			}
			return statement;
		}

		/**
		 * Get a prepared statement for the given input. Will cache the prepared
		 * statement for this connection.
		 *
		 * @param sqlStatement The SQL for the prepared statement.
		 * @param generateKeys The generate keys enum from Statement.
		 *
		 * @return The prepared statement
		 *
		 * @throws SQLException
		 */
		PreparedStatement getPreparedStatement(String sqlStatement, int generateKeys) throws SQLException {
			PreparedStatement statement;
			String statementKey = "SQL:" + sqlStatement + " Key:" + generateKeys;
			if (adHocPreparedStatements.containsKey(statementKey) && !adHocPreparedStatements.get(statementKey).isClosed()) {
				statement = this.adHocPreparedStatements.get(statementKey);
			} else {
				statement = prepareStatement(sqlStatement, generateKeys);
				this.adHocPreparedStatements.put(statementKey, statement);
			}
			return statement;
		}

		PreparedStatement prepareStatement(String sqlStatement, int generateKeys) throws SQLException {
			PrepareStatement prepareStatement = new PrepareStatement(this.getConnection(), sqlStatement);
			executeCommand(prepareStatement);
			return prepareStatement.getPreparedStatement();
		}

		Statement createStatement() throws SQLException {
			CreateStatement createStatement = new CreateStatement(this.connection);
			executeCommand(createStatement);
			return createStatement.getStatement();
		}

		void beginTransaction() throws SQLException {
			SetAutoCommit setAutoCommit = new SetAutoCommit(connection, false);
			executeCommand(setAutoCommit);
		}

		void commitTransaction() throws SQLException {
			Commit commit = new Commit(connection);
			executeCommand(commit);
			// You must turn auto commit back on when done with the transaction.
			SetAutoCommit setAutoCommit = new SetAutoCommit(connection, true);
			executeCommand(setAutoCommit);
		}

		/**
		 * A rollback that logs exceptions and does not throw, intended for
		 * "internal" use in SleuthkitCase methods where the exception that
		 * motivated the rollback is the exception to report to the client.
		 */
		void rollbackTransaction() {
			try {
				connection.rollback();
			} catch (SQLException e) {
				logger.log(Level.SEVERE, "Error rolling back transaction", e);
			}
			try {
				connection.setAutoCommit(true);
			} catch (SQLException e) {
				logger.log(Level.SEVERE, "Error restoring auto-commit", e);
			}
		}

		/**
		 * A rollback that throws, intended for use by the CaseDbTransaction
		 * class where client code is managing the transaction and the client
		 * may wish to know that the rollback failed.
		 *
		 * @throws SQLException
		 */
		void rollbackTransactionWithThrow() throws SQLException {
			try {
				connection.rollback();
			} finally {
				connection.setAutoCommit(true);
			}
		}

		/**
		 * Blocks until a write lock can be obtained on the tsk_aggregate_score
		 * table. Used to ensure only one thread/client is updating the score at
		 * a time. Can be called multiple times on the same transaction.
		 *
		 * @throws SQLException
		 * @throws TskCoreException
		 */
		void getAggregateScoreTableWriteLock() throws SQLException, TskCoreException {
			switch (getDatabaseType()) {
				case POSTGRESQL:
					AggregateScoreTablePostgreSQLWriteLock tableWriteLock = new AggregateScoreTablePostgreSQLWriteLock(connection);
					executeCommand(tableWriteLock);
					break;
				case SQLITE:
					// We do nothing here because we assume the entire SQLite DB is already locked from
					// when the analysis results were added/deleted in the same transaction. 
					break;
				default:
					throw new TskCoreException("Unknown DB Type: " + getDatabaseType().name());
			}
		}

		ResultSet executeQuery(Statement statement, String query) throws SQLException {
			ExecuteQuery queryCommand = new ExecuteQuery(statement, query);
			executeCommand(queryCommand);
			return queryCommand.getResultSet();
		}

		/**
		 *
		 * @param statement The SQL statement to execute
		 *
		 * @return returns the ResultSet from the execution of the query
		 *
		 * @throws SQLException \ref query_database_page \ref
		 *                      insert_and_update_database_page
		 */
		ResultSet executeQuery(PreparedStatement statement) throws SQLException {
			ExecutePreparedStatementQuery executePreparedStatementQuery = new ExecutePreparedStatementQuery(statement);
			executeCommand(executePreparedStatementQuery);
			return executePreparedStatementQuery.getResultSet();
		}

		void executeUpdate(Statement statement, String update) throws SQLException {
			executeUpdate(statement, update, Statement.NO_GENERATED_KEYS);
		}

		void executeUpdate(Statement statement, String update, int generateKeys) throws SQLException {
			ExecuteStatementUpdate executeStatementUpdate = new ExecuteStatementUpdate(statement, update);
			executeCommand(executeStatementUpdate);
		}

		void executeUpdate(PreparedStatement statement) throws SQLException {
			ExecutePreparedStatementUpdate executePreparedStatementUpdate = new ExecutePreparedStatementUpdate(statement);
			executeCommand(executePreparedStatementUpdate);
		}

		/**
		 * Close the connection to the database.
		 */
		@Override
		public void close() {
			try {
				for (PreparedStatement stmt : preparedStatements.values()) {
					closeStatement(stmt);
				}
				for (PreparedStatement stmt : adHocPreparedStatements.values()) {
					closeStatement(stmt);
				}
				connection.close();
			} catch (SQLException ex) {
				logger.log(Level.SEVERE, "Unable to close connection to case database", ex);
			}
		}

		Connection getConnection() {
			return this.connection;
		}
	}

	/**
	 * A connection to an SQLite case database.
	 */
	private final class SQLiteConnection extends CaseDbConnection {

		private static final int DATABASE_LOCKED_ERROR = 0; // This should be 6 according to documentation, but it has been observed to be 0.
		private static final int SQLITE_BUSY_ERROR = 5;

		SQLiteConnection(Connection conn) {
			super(conn);
		}

		@Override
		void executeCommand(DbCommand command) throws SQLException {
			int retryCounter = 0;
			while (true) {
				try {
					command.execute(); // Perform the operation
					break;
				} catch (SQLException ex) {
					if ((ex.getErrorCode() == SQLITE_BUSY_ERROR || ex.getErrorCode() == DATABASE_LOCKED_ERROR) && retryCounter < MAX_RETRIES) {
						try {

							// We do not notify of error here, as this is not an
							// error condition. It is likely a temporary busy or
							// locked issue and we will retry.
							retryCounter++;
							Thread.sleep(SLEEP_LENGTH_IN_MILLISECONDS);
						} catch (InterruptedException exp) {
							Logger.getLogger(SleuthkitCase.class.getName()).log(Level.WARNING, "Unexpectedly unable to wait for database.", exp);
						}
					} else {
						throw ex;
					}
				}
			}
		}
	}

	/**
	 * A connection to a PostgreSQL case database.
	 */
	private final class PostgreSQLConnection extends CaseDbConnection {

		private final String COMMUNICATION_ERROR = PSQLState.COMMUNICATION_ERROR.getState();
		private final String SYSTEM_ERROR = PSQLState.SYSTEM_ERROR.getState();
		private final String UNKNOWN_STATE = PSQLState.UNKNOWN_STATE.getState();
		private static final int MAX_RETRIES = 3;

		PostgreSQLConnection(Connection conn) {
			super(conn);
		}

		@Override
		void executeUpdate(Statement statement, String update, int generateKeys) throws SQLException {
			CaseDbConnection.ExecuteStatementUpdateGenerateKeys executeStatementUpdateGenerateKeys = new CaseDbConnection.ExecuteStatementUpdateGenerateKeys(statement, update, generateKeys);
			executeCommand(executeStatementUpdateGenerateKeys);
		}

		@Override
		PreparedStatement prepareStatement(String sqlStatement, int generateKeys) throws SQLException {
			CaseDbConnection.PrepareStatementGenerateKeys prepareStatementGenerateKeys = new CaseDbConnection.PrepareStatementGenerateKeys(this.getConnection(), sqlStatement, generateKeys);
			executeCommand(prepareStatementGenerateKeys);
			return prepareStatementGenerateKeys.getPreparedStatement();
		}

		@Override
		void executeCommand(DbCommand command) throws SQLException {
			SQLException lastException = null;
			for (int retries = 0; retries < MAX_RETRIES; retries++) {
				try {
					command.execute();
					lastException = null; // reset since we had a successful execution
					break;
				} catch (SQLException ex) {
					lastException = ex;
					String sqlState = ex.getSQLState();
					if (sqlState == null || sqlState.equals(COMMUNICATION_ERROR) || sqlState.equals(SYSTEM_ERROR) || sqlState.equals(UNKNOWN_STATE)) {
						try {
							Thread.sleep(SLEEP_LENGTH_IN_MILLISECONDS);
						} catch (InterruptedException exp) {
							Logger.getLogger(SleuthkitCase.class.getName()).log(Level.WARNING, "Unexpectedly unable to wait for database.", exp);
						}
					} else {
						throw ex;
					}
				}
			}

			// rethrow the exception if we bailed because of too many retries
			if (lastException != null) {
				throw lastException;
			}
		}
	}

	/**
     * Allows callers to execute multiple database operations in a single
     * transaction.  The usual motivations for this are for speed and
     * atomicity. 
     *
     * WARNING: You need to be very careful when using this because it is
     * easy to get the system into a deadlock when using a SQLite database. 
     * For example, if you get this transaction, perform some inserts 
     * (and you therefore have a write lock on the DB), and then need to
     * query the database from the same thread.  If your query does not use
     * this transaction, then it will get a new connection and will be 
     * blocked by the connection that is held by the transaction. 
     *
     * If you are using CaseDbTransaction, you need to use only DB methods
     * that also take in a transaction. We recommend that you preprocess
     * as much as possible before getting the transaction to:
     * - prevent deadlocks
     * - hold on to the transaction for as little time as possible. 
     *
     * 
	 * Note that this class does not implement the
	 * Transaction interface because that sort of flexibility and its associated
	 * complexity is not needed. Also, TskCoreExceptions are thrown to be
	 * consistent with the outer SleuthkitCase class.
	 *
	 * This class will automatically acquire the single user case write lock and
	 * release it when the transaction is closed. Otherwise we risk deadlock
	 * because this transaction can lock up SQLite and make it "busy" and
	 * another thread may get a write lock to the DB, but not be able to do
	 * anything because the DB is busy.
	 */
	public static final class CaseDbTransaction {

		private final CaseDbConnection connection;
		private SleuthkitCase sleuthkitCase;

        /* This class can store information about what was 
         * inserted as part of the transaction so that we can
         * fire events after the data has been persisted. */

		// Score changes are stored as a map keyed by objId to prevent duplicates.
		private Map<Long, ScoreChange> scoreChangeMap = new HashMap<>();
		private List<Host> hostsAdded = new ArrayList<>();
		private List<TimelineEventAddedEvent> timelineEvents = new ArrayList<>();
		private List<OsAccount> accountsChanged = new ArrayList<>();
		private List<OsAccount> accountsAdded = new ArrayList<>();
		private List<TskEvent.MergedAccountsPair> accountsMerged = new ArrayList<>();

		private List<Long> deletedOsAccountObjectIds = new ArrayList<>();
		private List<Long> deletedResultObjectIds = new ArrayList<>();

    // Keep track of which threads have connections to debug deadlocks
    private static Set<Long> threadsWithOpenTransaction = new HashSet<>();
    private static final Object threadsWithOpenTransactionLock = new Object();

		private CaseDbTransaction(SleuthkitCase sleuthkitCase) throws TskCoreException {
			this.sleuthkitCase = sleuthkitCase;

			sleuthkitCase.acquireSingleUserCaseWriteLock();
			this.connection = sleuthkitCase.getConnection();
			try {
				synchronized (threadsWithOpenTransactionLock) {
					this.connection.beginTransaction();
					threadsWithOpenTransaction.add(Thread.currentThread().getId());
				}
			} catch (SQLException ex) {
				sleuthkitCase.releaseSingleUserCaseWriteLock();
				throw new TskCoreException("Failed to create transaction on case database", ex);
			}

		}

		/**
		 * The implementations of the public APIs that take a CaseDbTransaction
		 * object need access to the underlying CaseDbConnection.
		 *
		 * @return The CaseDbConnection instance for this instance of
		 *         CaseDbTransaction.
		 */
		CaseDbConnection getConnection() {
			return this.connection;
		}

		/**
		 * Saves a score change done as part of the transaction.
		 *
		 * @param scoreChange Score change.
		 */
		void registerScoreChange(ScoreChange scoreChange) {
			scoreChangeMap.put(scoreChange.getObjectId(), scoreChange);
		}
		
		/**
		 * Register timeline event to be fired when transaction finishes.
		 * @param timelineEvent The timeline event.
		 */
		void registerTimelineEvent(TimelineEventAddedEvent timelineEvent) {
			if (timelineEvent != null) {
				timelineEvents.add(timelineEvent);
			}
		}

		/**
		 * Saves a host that has been added as a part of this transaction.
		 *
		 * @param host The host.
		 */
		void registerAddedHost(Host host) {
			if (host != null) {
				this.hostsAdded.add(host);
			}
		}

		/**
		 * Saves an account that has been updated as a part of this transaction.
		 *
		 * @param account The account.
		 */
		void registerChangedOsAccount(OsAccount account) {
			if (account != null) {
				accountsChanged.add(account);
			}
		}

		/**
		 * Saves an account that has been deleted as a part of this transaction.
		 *
		 * @param osAccountObjId The account.
		 */
		void registerDeletedOsAccount(long osAccountObjId) {
			deletedOsAccountObjectIds.add(osAccountObjId);
		}

		/**
		 * Saves an account that has been added as a part of this transaction.
		 *
		 * @param account The account.
		 */
		void registerAddedOsAccount(OsAccount account) {
			if (account != null) {
				accountsAdded.add(account);
			}
		}

		/**
		 * Saves an account that has been merged as part of this transaction.
		 *
		 * @param sourceOsAccountObjId
		 * @param destinationOsAccountObjId
		 */
		void registerMergedOsAccount(long sourceOsAccountObjId, long destinationOsAccountObjId) {
			accountsMerged.add(new TskEvent.MergedAccountsPair(sourceOsAccountObjId, destinationOsAccountObjId));
		}

		/**
		 * Saves an analysis result that has been deleted as a part of this
		 * transaction.
		 *
		 * @param result Deleted result.
		 */
		void registerDeletedAnalysisResult(long analysisResultObjId) {
			this.deletedResultObjectIds.add(analysisResultObjId);
		}

		/**
		 * Check if the given thread has an open transaction.
		 *
		 * @param threadId Thread id to check for.
		 *
		 * @return True if the given thread has an open transaction, false
		 *         otherwise.
		 */
		private static boolean hasOpenTransaction(long threadId) {
			synchronized (threadsWithOpenTransactionLock) {
				return threadsWithOpenTransaction.contains(threadId);
			}
		}

		/**
		 * Commits the transaction on the case database that was begun when this
		 * object was constructed.
		 *
		 * @throws TskCoreException
		 */
		public void commit() throws TskCoreException {
			try {
				this.connection.commitTransaction();
			} catch (SQLException ex) {
				throw new TskCoreException("Failed to commit transaction on case database", ex);
			} finally {
				close();

				if (!scoreChangeMap.isEmpty()) {
					Map<Long, List<ScoreChange>> changesByDataSource = scoreChangeMap.values().stream()
							.collect(Collectors.groupingBy(ScoreChange::getDataSourceObjectId));
					for (Map.Entry<Long, List<ScoreChange>> entry : changesByDataSource.entrySet()) {
						sleuthkitCase.fireTSKEvent(new TskEvent.AggregateScoresChangedEvent(entry.getKey(), ImmutableSet.copyOf(entry.getValue())));
					}
				}
				if (!timelineEvents.isEmpty()) {
					for (TimelineEventAddedEvent evt : timelineEvents) {
						sleuthkitCase.fireTSKEvent(evt);
					}
				}
				if (!hostsAdded.isEmpty()) {
					sleuthkitCase.fireTSKEvent(new TskEvent.HostsAddedTskEvent(hostsAdded));
				}
				if (!accountsAdded.isEmpty()) {
					sleuthkitCase.fireTSKEvent(new TskEvent.OsAccountsAddedTskEvent(accountsAdded));
				}
				if (!accountsChanged.isEmpty()) {
					sleuthkitCase.fireTSKEvent(new TskEvent.OsAccountsUpdatedTskEvent(accountsChanged));
				}
				if (!accountsMerged.isEmpty()) {
					sleuthkitCase.fireTSKEvent(new TskEvent.OsAccountsMergedTskEvent(accountsMerged));
				}
				if (!deletedOsAccountObjectIds.isEmpty()) {
					sleuthkitCase.fireTSKEvent(new TskEvent.OsAccountsDeletedTskEvent(deletedOsAccountObjectIds));
				}
				if (!deletedResultObjectIds.isEmpty()) {
					sleuthkitCase.fireTSKEvent(new TskEvent.AnalysisResultsDeletedTskEvent(deletedResultObjectIds));
				}
			}
		}

		/**
		 * Rolls back the transaction on the case database that was begun when
		 * this object was constructed.
		 *
		 * @throws TskCoreException
		 */
		public void rollback() throws TskCoreException {
			try {
				this.connection.rollbackTransactionWithThrow();
			} catch (SQLException ex) {
				throw new TskCoreException("Case database transaction rollback failed", ex);
			} finally {
				close();
			}
		}

		/**
		 * Close the database connection
		 *
		 */
		void close() {
			this.connection.close();
			sleuthkitCase.releaseSingleUserCaseWriteLock();
			synchronized (threadsWithOpenTransactionLock) {
				threadsWithOpenTransaction.remove(Thread.currentThread().getId());
			}
		}
	}

	/**
	 * The CaseDbQuery supports the use case where developers have a need for
	 * data that is not exposed through the SleuthkitCase API. A CaseDbQuery
	 * instance gets created through the SleuthkitCase executeDbQuery() method.
	 * It wraps the ResultSet and takes care of acquiring and releasing the
	 * appropriate database lock. It implements AutoCloseable so that it can be
	 * used in a try-with -resources block freeing developers from having to
	 * remember to close the result set and releasing the lock.
	 */
	public final class CaseDbQuery implements AutoCloseable {

		private ResultSet resultSet;
		private CaseDbConnection connection;

		private CaseDbQuery(String query) throws TskCoreException {
			this(query, false);
		}

		private CaseDbQuery(String query, boolean allowWriteQuery) throws TskCoreException {
			if (!allowWriteQuery) {
				if (!query.regionMatches(true, 0, "SELECT", 0, "SELECT".length())) {
					throw new TskCoreException("Unsupported query: Only SELECT queries are supported.");
				}
			}

			SleuthkitCase.this.acquireSingleUserCaseReadLock();
			try {
				connection = connections.getConnection();
				resultSet = connection.executeQuery(connection.createStatement(), query);
			} catch (SQLException ex) {
				SleuthkitCase.this.releaseSingleUserCaseReadLock();
				throw new TskCoreException("Error executing query: ", ex);
			} catch (TskCoreException ex) {
				SleuthkitCase.this.releaseSingleUserCaseReadLock();
				throw ex;
			}
		}

		/**
		 * Get the result set for this query.
		 *
		 * @return The result set.
		 */
		public ResultSet getResultSet() {
			return resultSet;
		}

		@Override
		public void close() throws TskCoreException {
			try {
				if (resultSet != null) {
					final Statement statement = resultSet.getStatement();
					if (statement != null) {
						statement.close();
					}
					resultSet.close();
				}
				closeConnection(connection);
			} catch (SQLException ex) {
				throw new TskCoreException("Error closing query: ", ex);
			} finally {
				SleuthkitCase.this.releaseSingleUserCaseReadLock();
			}
		}
	}

	/**
	 * Add an observer for SleuthkitCase errors.
	 *
	 * @param observer The observer to add.
	 *
	 * @deprecated Catch exceptions instead.
	 */
	@Deprecated
	public void addErrorObserver(ErrorObserver observer) {
		sleuthkitCaseErrorObservers.add(observer);
	}

	/**
	 * Remove an observer for SleuthkitCase errors.
	 *
	 * @param observer The observer to remove.
	 *
	 * @deprecated Catch exceptions instead.
	 */
	@Deprecated
	public void removeErrorObserver(ErrorObserver observer) {
		int i = sleuthkitCaseErrorObservers.indexOf(observer);
		if (i >= 0) {
			sleuthkitCaseErrorObservers.remove(i);
		}
	}

	/**
	 * Submit an error to all clients that are listening.
	 *
	 * @param context      The context in which the error occurred.
	 * @param errorMessage A description of the error that occurred.
	 *
	 * @deprecated Catch exceptions instead.
	 */
	@Deprecated
	public void submitError(String context, String errorMessage) {
		for (ErrorObserver observer : sleuthkitCaseErrorObservers) {
			if (observer != null) {
				try {
					observer.receiveError(context, errorMessage);
				} catch (Exception ex) {
					logger.log(Level.SEVERE, "Observer client unable to receive message: {0}, {1}", new Object[]{context, errorMessage, ex});

				}
			}
		}
	}

	/**
	 * Notifies observers of errors in the SleuthkitCase.
	 *
	 * @deprecated Catch exceptions instead.
	 */
	@Deprecated
	public interface ErrorObserver {

		/**
		 * List of arguments for the context string parameters. This does not
		 * preclude the use of arbitrary context strings by client code, but it
		 * does provide a place to define standard context strings to allow
		 * filtering of notifications by implementations of ErrorObserver.
		 */
		public enum Context {

			/**
			 * Error occurred while reading image content.
			 */
			IMAGE_READ_ERROR("Image File Read Error"),
			/**
			 * Error occurred while reading database content.
			 */
			DATABASE_READ_ERROR("Database Read Error");

			private final String contextString;

			private Context(String context) {
				this.contextString = context;
			}

			public String getContextString() {
				return contextString;
			}
		};

		void receiveError(String context, String errorMessage);
	}

	/**
	 * Given an object id, works up the tree of ancestors to the data source for
	 * the object and gets the object id of the data source. The trivial case
	 * where the input object id is for a source is handled.
	 *
	 * @param objectId An object id.
	 *
	 * @return A data source object id.
	 *
	 */
	@Deprecated
	long getDataSourceObjectId(long objectId) {
		try {
			CaseDbConnection connection = connections.getConnection();
			try {
				return getDataSourceObjectId(connection, objectId);
			} finally {
				closeConnection(connection);
			}
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error getting data source object id for a file", ex);
			return 0;
		}
	}

	/**
	 * Get last (max) object id of content object in tsk_objects.
	 *
	 * @return currently max id
	 *
	 * @throws TskCoreException exception thrown when database error occurs and
	 *                          last object id could not be queried
	 * @deprecated Do not use, assumes a single-threaded, single-user case.
	 */
	@Deprecated
	public long getLastObjectId() throws TskCoreException {
		CaseDbConnection connection = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();

			// SELECT MAX(obj_id) AS max_obj_id FROM tsk_objects
			PreparedStatement statement = connection.getPreparedStatement(PREPARED_STATEMENT.SELECT_MAX_OBJECT_ID);
			rs = connection.executeQuery(statement);
			long id = -1;
			if (rs.next()) {
				id = rs.getLong("max_obj_id");
			}
			return id;
		} catch (SQLException e) {
			throw new TskCoreException("Error getting last object id", e);
		} finally {
			closeResultSet(rs);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Find and return list of files matching the specific Where clause. Use
	 * findAllFilesWhere instead. It returns a more generic data type
	 *
	 * @param sqlWhereClause a SQL where clause appropriate for the desired
	 *                       files (do not begin the WHERE clause with the word
	 *                       WHERE!)
	 *
	 * @return a list of FsContent each of which satisfy the given WHERE clause
	 *
	 * @throws TskCoreException
	 * @deprecated	use SleuthkitCase.findAllFilesWhere() instead
	 */
	@Deprecated
	public List<FsContent> findFilesWhere(String sqlWhereClause) throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT * FROM tsk_files WHERE " + sqlWhereClause); //NON-NLS
			List<FsContent> results = new ArrayList<FsContent>();
			List<AbstractFile> temp = resultSetToAbstractFiles(rs, connection);
			for (AbstractFile f : temp) {
				final TSK_DB_FILES_TYPE_ENUM type = f.getType();
				if (type.equals(TskData.TSK_DB_FILES_TYPE_ENUM.FS)) {
					results.add((FsContent) f);
				}
			}
			return results;
		} catch (SQLException e) {
			throw new TskCoreException("SQLException thrown when calling 'SleuthkitCase.findFilesWhere().", e);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get the artifact type id associated with an artifact type name.
	 *
	 * @param artifactTypeName An artifact type name.
	 *
	 * @return An artifact id or -1 if the attribute type does not exist.
	 *
	 * @throws TskCoreException If an error occurs accessing the case database.
	 *
	 * @deprecated Use getArtifactType instead
	 */
	@Deprecated
	public int getArtifactTypeID(String artifactTypeName) throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT artifact_type_id FROM blackboard_artifact_types WHERE type_name = '" + artifactTypeName + "'"); //NON-NLS
			int typeId = -1;
			if (rs.next()) {
				typeId = rs.getInt("artifact_type_id");
			}
			return typeId;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting artifact type id", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Gets a list of the standard blackboard artifact type enum objects.
	 *
	 * @return The members of the BlackboardArtifact.ARTIFACT_TYPE enum.
	 *
	 * @throws TskCoreException Specified, but not thrown.
	 * @deprecated For a list of standard blackboard artifacts type enum
	 * objects, use BlackboardArtifact.ARTIFACT_TYPE.values.
	 */
	@Deprecated
	public ArrayList<BlackboardArtifact.ARTIFACT_TYPE> getBlackboardArtifactTypes() throws TskCoreException {
		return new ArrayList<BlackboardArtifact.ARTIFACT_TYPE>(Arrays.asList(BlackboardArtifact.ARTIFACT_TYPE.values()));
	}

	/**
	 * Adds a custom artifact type. The artifact type name must be unique, but
	 * the display name need not be unique.
	 *
	 * @param artifactTypeName The artifact type name.
	 * @param displayName      The artifact type display name.
	 *
	 * @return The artifact type id assigned to the artifact type.
	 *
	 * @throws TskCoreException If there is an error adding the type to the case
	 *                          database.
	 * @deprecated Use SleuthkitCase.addBlackboardArtifactType() instead.
	 */
	@Deprecated
	public int addArtifactType(String artifactTypeName, String displayName) throws TskCoreException {
		try {
			return addBlackboardArtifactType(artifactTypeName, displayName).getTypeID();
		} catch (TskDataException ex) {
			throw new TskCoreException("Failed to add artifact type.", ex);
		}
	}

	/**
	 * Adds a custom attribute type with a string value type. The attribute type
	 * name must be unique, but the display name need not be unique.
	 *
	 * @param attrTypeString The attribute type name.
	 * @param displayName    The attribute type display name.
	 *
	 * @return The attribute type id.
	 *
	 * @throws TskCoreException If there is an error adding the type to the case
	 *                          database.
	 * @deprecated Use SleuthkitCase.addArtifactAttributeType() instead.
	 */
	@Deprecated
	public int addAttrType(String attrTypeString, String displayName) throws TskCoreException {
		try {
			return addArtifactAttributeType(attrTypeString, TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, displayName).getTypeID();
		} catch (TskDataException ex) {
			throw new TskCoreException("Couldn't add new attribute type");
		}
	}

	/**
	 * Gets the attribute type id associated with an attribute type name.
	 *
	 * @param attrTypeName An attribute type name.
	 *
	 * @return An attribute id or -1 if the attribute type does not exist.
	 *
	 * @throws TskCoreException If an error occurs accessing the case database.
	 * @deprecated Use SleuthkitCase.getAttributeType() instead.
	 */
	@Deprecated
	public int getAttrTypeID(String attrTypeName) throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT attribute_type_id FROM blackboard_attribute_types WHERE type_name = '" + attrTypeName + "'"); //NON-NLS
			int typeId = -1;
			if (rs.next()) {
				typeId = rs.getInt("attribute_type_id");
			}
			return typeId;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting attribute type id", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get the string associated with the given id. Will throw an error if that
	 * id does not exist
	 *
	 * @param attrTypeID attribute id
	 *
	 * @return string associated with the given id
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within tsk core
	 * @deprecated Use getAttributeType instead
	 */
	@Deprecated
	public String getAttrTypeString(int attrTypeID) throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT type_name FROM blackboard_attribute_types WHERE attribute_type_id = " + attrTypeID); //NON-NLS
			if (rs.next()) {
				return rs.getString("type_name");
			} else {
				throw new TskCoreException("No type with that id");
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting or creating a attribute type name", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get the display name for the attribute with the given id. Will throw an
	 * error if that id does not exist
	 *
	 * @param attrTypeID attribute id
	 *
	 * @return string associated with the given id
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within tsk core
	 * @deprecated Use getAttributeType instead
	 */
	@Deprecated
	public String getAttrTypeDisplayName(int attrTypeID) throws TskCoreException {
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT display_name FROM blackboard_attribute_types WHERE attribute_type_id = " + attrTypeID); //NON-NLS
			if (rs.next()) {
				return rs.getString("display_name");
			} else {
				throw new TskCoreException("No type with that id");
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting or creating a attribute type name", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Gets a list of the standard blackboard attribute type enum objects.
	 *
	 * @return The members of the BlackboardAttribute.ATTRIBUTE_TYPE enum.
	 *
	 * @throws TskCoreException Specified, but not thrown.
	 * @deprecated For a list of standard blackboard attribute types enum
	 * objects, use BlackboardAttribute.ATTRIBUTE_TYP.values.
	 */
	@Deprecated
	public ArrayList<BlackboardAttribute.ATTRIBUTE_TYPE> getBlackboardAttributeTypes() throws TskCoreException {
		return new ArrayList<BlackboardAttribute.ATTRIBUTE_TYPE>(Arrays.asList(BlackboardAttribute.ATTRIBUTE_TYPE.values()));
	}

	/**
	 * Process a read-only query on the tsk database, any table Can be used to
	 * e.g. to find files of a given criteria. resultSetToFsContents() will
	 * convert the files to useful objects. MUST CALL closeRunQuery() when done
	 *
	 * @param query the given string query to run
	 *
	 * @return	the resultSet from running the query. Caller MUST CALL
	 *         closeRunQuery(resultSet) as soon as possible, when done with
	 *         retrieving data from the resultSet
	 *
	 * @throws SQLException if error occurred during the query
	 * @deprecated Do not use runQuery(), use executeQuery() instead. \ref
	 * query_database_page
	 */
	@Deprecated
	public ResultSet runQuery(String query) throws SQLException {
		CaseDbConnection connection = null;
		acquireSingleUserCaseReadLock();
		try {
			connection = connections.getConnection();
			return connection.executeQuery(connection.createStatement(), query);
		} catch (TskCoreException ex) {
			throw new SQLException("Error getting connection for ad hoc query", ex);
		} finally {
			//TODO unlock should be done in closeRunQuery()
			//but currently not all code calls closeRunQuery - need to fix this
			closeConnection(connection);
			releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Closes ResultSet and its Statement previously retrieved from runQuery()
	 *
	 * @param resultSet with its Statement to close
	 *
	 * @throws SQLException of closing the query files failed
	 * @deprecated Do not use runQuery() and closeRunQuery(), use executeQuery()
	 * instead. \ref query_database_page
	 */
	@Deprecated
	public void closeRunQuery(ResultSet resultSet) throws SQLException {
		final Statement statement = resultSet.getStatement();
		resultSet.close();
		if (statement != null) {
			statement.close();
		}
	}

	/**
	 * Adds a carved file to the VirtualDirectory '$CarvedFiles' in the volume
	 * or image given by systemId. Creates $CarvedFiles virtual directory if it
	 * does not exist already.
	 *
	 * @param carvedFileName the name of the carved file to add
	 * @param carvedFileSize the size of the carved file to add
	 * @param containerId    the ID of the parent volume, file system, or image
	 * @param data           the layout information - a list of offsets that
	 *                       make up this carved file.
	 *
	 * @return A LayoutFile object representing the carved file.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 * @deprecated Use addCarvedFile(CarvingResult) instead
	 */
	@Deprecated
	public LayoutFile addCarvedFile(String carvedFileName, long carvedFileSize, long containerId, List<TskFileRange> data) throws TskCoreException {
		CarvingResult.CarvedFile carvedFile = new CarvingResult.CarvedFile(carvedFileName, carvedFileSize, data);
		List<CarvingResult.CarvedFile> files = new ArrayList<CarvingResult.CarvedFile>();
		files.add(carvedFile);
		CarvingResult carvingResult;
		Content parent = getContentById(containerId);
		if (parent instanceof FileSystem
				|| parent instanceof Volume
				|| parent instanceof Image) {
			carvingResult = new CarvingResult(parent, files);
		} else {
			throw new TskCoreException(String.format("Parent (id =%d) is not an file system, volume or image", containerId));
		}
		return addCarvedFiles(carvingResult).get(0);
	}

	/**
	 * Adds a collection of carved files to the VirtualDirectory '$CarvedFiles'
	 * in the volume or image given by systemId. Creates $CarvedFiles virtual
	 * directory if it does not exist already.
	 *
	 * @param filesToAdd A list of CarvedFileContainer files to add as carved
	 *                   files.
	 *
	 * @return A list of the files added to the database.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 * @deprecated Use addCarvedFile(CarvingResult) instead
	 */
	@Deprecated
	public List<LayoutFile> addCarvedFiles(List<CarvedFileContainer> filesToAdd) throws TskCoreException {
		List<CarvingResult.CarvedFile> carvedFiles = new ArrayList<CarvingResult.CarvedFile>();
		for (CarvedFileContainer container : filesToAdd) {
			CarvingResult.CarvedFile carvedFile = new CarvingResult.CarvedFile(container.getName(), container.getSize(), container.getRanges());
			carvedFiles.add(carvedFile);
		}
		CarvingResult carvingResult;
		Content parent = getContentById(filesToAdd.get(0).getId());
		if (parent instanceof FileSystem
				|| parent instanceof Volume
				|| parent instanceof Image) {
			carvingResult = new CarvingResult(parent, carvedFiles);
		} else {
			throw new TskCoreException(String.format("Parent (id =%d) is not an file system, volume or image", parent.getId()));
		}
		return addCarvedFiles(carvingResult);
	}

	/**
	 * Creates a new derived file object, adds it to database and returns it.
	 *
	 * TODO add support for adding derived method
	 *
	 * @param fileName        file name the derived file
	 * @param localPath       local path of the derived file, including the file
	 *                        name. The path is relative to the database path.
	 * @param size            size of the derived file in bytes
	 * @param ctime           The changed time of the file.
	 * @param crtime          The creation time of the file.
	 * @param atime           The accessed time of the file
	 * @param mtime           The modified time of the file.
	 * @param isFile          whether a file or directory, true if a file
	 * @param parentFile      parent file object (derived or local file)
	 * @param rederiveDetails details needed to re-derive file (will be specific
	 *                        to the derivation method), currently unused
	 * @param toolName        name of derivation method/tool, currently unused
	 * @param toolVersion     version of derivation method/tool, currently
	 *                        unused
	 * @param otherDetails    details of derivation method/tool, currently
	 *                        unused
	 *
	 * @return newly created derived file object
	 *
	 * @throws TskCoreException exception thrown if the object creation failed
	 *                          due to a critical system error
	 * @deprecated Use the newer version with explicit encoding type parameter
	 */
	@Deprecated
	public DerivedFile addDerivedFile(String fileName, String localPath,
			long size, long ctime, long crtime, long atime, long mtime,
			boolean isFile, AbstractFile parentFile,
			String rederiveDetails, String toolName, String toolVersion, String otherDetails) throws TskCoreException {
		return addDerivedFile(fileName, localPath, size, ctime, crtime, atime, mtime,
				isFile, parentFile, rederiveDetails, toolName, toolVersion,
				otherDetails, TskData.EncodingType.NONE);
	}

	/**
	 * Adds a local/logical file to the case database. The database operations
	 * are done within a caller-managed transaction; the caller is responsible
	 * for committing or rolling back the transaction.
	 *
	 * @param fileName     The name of the file.
	 * @param localPath    The absolute path (including the file name) of the
	 *                     local/logical in secondary storage.
	 * @param size         The size of the file in bytes.
	 * @param ctime        The changed time of the file.
	 * @param crtime       The creation time of the file.
	 * @param atime        The accessed time of the file
	 * @param mtime        The modified time of the file.
	 * @param md5          The MD5 hash of the file
	 * @param known        The known status of the file (can be null)
	 * @param mimeType     The MIME type of the file
	 * @param isFile       True, unless the file is a directory.
	 * @param encodingType Type of encoding used on the file
	 * @param parent       The parent of the file (e.g., a virtual directory)
	 * @param transaction  A caller-managed transaction within which the add
	 *                     file operations are performed.
	 *
	 * @return An object representing the local/logical file.
	 *
	 * @throws TskCoreException if there is an error completing a case database
	 *                          operation.
	 *
	 * @deprecated Use the newer version with explicit sha256 parameter
	 */
	@Deprecated
	public LocalFile addLocalFile(String fileName, String localPath,
			long size, long ctime, long crtime, long atime, long mtime,
			String md5, FileKnown known, String mimeType,
			boolean isFile, TskData.EncodingType encodingType,
			Content parent, CaseDbTransaction transaction) throws TskCoreException {

		return addLocalFile(fileName, localPath, size, ctime, crtime, atime, mtime,
				md5, null, known, mimeType, isFile, encodingType,
				parent, transaction);
	}

	/**
	 * Adds a local/logical file to the case database. The database operations
	 * are done within a caller-managed transaction; the caller is responsible
	 * for committing or rolling back the transaction.
	 *
	 * @param fileName    The name of the file.
	 * @param localPath   The absolute path (including the file name) of the
	 *                    local/logical in secondary storage.
	 * @param size        The size of the file in bytes.
	 * @param ctime       The changed time of the file.
	 * @param crtime      The creation time of the file.
	 * @param atime       The accessed time of the file
	 * @param mtime       The modified time of the file.
	 * @param isFile      True, unless the file is a directory.
	 * @param parent      The parent of the file (e.g., a virtual directory)
	 * @param transaction A caller-managed transaction within which the add file
	 *                    operations are performed.
	 *
	 * @return An object representing the local/logical file.
	 *
	 * @throws TskCoreException if there is an error completing a case database
	 *                          operation.
	 * @deprecated Use the newer version with explicit encoding type parameter
	 */
	@Deprecated
	public LocalFile addLocalFile(String fileName, String localPath,
			long size, long ctime, long crtime, long atime, long mtime,
			boolean isFile,
			AbstractFile parent, CaseDbTransaction transaction) throws TskCoreException {
		return addLocalFile(fileName, localPath, size, ctime, crtime, atime, mtime, isFile,
				TskData.EncodingType.NONE, parent, transaction);
	}

	/**
	 * Wraps the version of addLocalFile that takes a Transaction in a
	 * transaction local to this method.
	 *
	 * @param fileName
	 * @param localPath
	 * @param size
	 * @param ctime
	 * @param crtime
	 * @param atime
	 * @param mtime
	 * @param isFile
	 * @param parent
	 *
	 * @return
	 *
	 * @throws TskCoreException
	 * @deprecated Use the newer version with explicit encoding type parameter
	 */
	@Deprecated
	public LocalFile addLocalFile(String fileName, String localPath,
			long size, long ctime, long crtime, long atime, long mtime,
			boolean isFile,
			AbstractFile parent) throws TskCoreException {
		return addLocalFile(fileName, localPath, size, ctime, crtime, atime, mtime,
				isFile, TskData.EncodingType.NONE, parent);
	}

	/**
	 * Start process of adding a image to the case. Adding an image is a
	 * multi-step process and this returns an object that allows it to happen.
	 *
	 * @param timezone        TZ time zone string to use for ingest of image.
	 * @param addUnallocSpace Set to true to create virtual files for
	 *                        unallocated space in the image.
	 * @param noFatFsOrphans  Set to true to skip processing orphan files of FAT
	 *                        file systems.
	 *
	 * @return Object that encapsulates control of adding an image via the
	 *         SleuthKit native code layer
	 *
	 * @deprecated Use the newer version with explicit image writer path
	 * parameter
	 */
	@Deprecated
	public AddImageProcess makeAddImageProcess(String timezone, boolean addUnallocSpace, boolean noFatFsOrphans) {
		return this.caseHandle.initAddImageProcess(timezone, addUnallocSpace, noFatFsOrphans, "", null, this);
	}

	/**
	 * Helper to return FileSystems in an Image
	 *
	 * @param image Image to lookup FileSystem for
	 *
	 * @return Collection of FileSystems in the image
	 *
	 * @deprecated Use getImageFileSystems which throws an exception if an error
	 * occurs.
	 */
	@Deprecated
	public Collection<FileSystem> getFileSystems(Image image) {
		try {
			return getImageFileSystems(image);
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error loading all file systems for image with ID {0}", image.getId());
			return new ArrayList<>();
		}
	}

	/**
	 * Find all files in the data source, by name and parent
	 *
	 * @param dataSource the dataSource (Image, parent-less VirtualDirectory) to
	 *                   search for the given file name
	 * @param fileName   Pattern of the name of the file or directory to match
	 *                   (case insensitive, used in LIKE SQL statement).
	 * @param parentFile Object for parent file/directory to find children in
	 *
	 * @return a list of AbstractFile for files/directories whose name matches
	 *         fileName and that were inside a directory described by
	 *         parentFile.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 *
	 * @deprecated Use findFilesInFolder()
	 */
	@Deprecated
	public List<AbstractFile> findFiles(Content dataSource, String fileName, AbstractFile parentFile) throws TskCoreException {
		return findFilesInFolder(fileName, parentFile);
	}

	/**
	 * Acquires a write lock, but only if this is a single-user case. Always
	 * call this method in a try block with a call to the lock release method in
	 * an associated finally block.
	 *
	 * @deprecated Use acquireSingleUserCaseWriteLock.
	 */
	@Deprecated
	public void acquireExclusiveLock() {
		acquireSingleUserCaseWriteLock();
	}

	/**
	 * Releases a write lock, but only if this is a single-user case. This
	 * method should always be called in the finally block of a try block in
	 * which the lock was acquired.
	 *
	 * @deprecated Use releaseSingleUserCaseWriteLock.
	 */
	@Deprecated
	public void releaseExclusiveLock() {
		releaseSingleUserCaseWriteLock();
	}

	/**
	 * Acquires a read lock, but only if this is a single-user case. Call this
	 * method in a try block with a call to the lock release method in an
	 * associated finally block.
	 *
	 * @deprecated Use acquireSingleUserCaseReadLock.
	 */
	@Deprecated
	public void acquireSharedLock() {
		acquireSingleUserCaseReadLock();
	}

	/**
	 * Releases a read lock, but only if this is a single-user case. This method
	 * should always be called in the finally block of a try block in which the
	 * lock was acquired.
	 *
	 * @deprecated Use releaseSingleUserCaseReadLock.
	 */
	@Deprecated
	public void releaseSharedLock() {
		releaseSingleUserCaseReadLock();
	}
};
