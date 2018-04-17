/*
 * Sleuth Kit Data Model
 *
 * Copyright 2013-18 Basis Technology Corp.
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

import com.google.common.collect.HashMultimap;
import com.google.common.collect.SetMultimap;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.joda.time.DateTimeZone;
import org.joda.time.Interval;
import org.joda.time.Period;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_HASHSET_HIT;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import static org.sleuthkit.datamodel.StringUtils.joinAsStrings;
import org.sleuthkit.datamodel.timeline.BaseTypes;
import org.sleuthkit.datamodel.timeline.CombinedEvent;
import org.sleuthkit.datamodel.timeline.DescriptionLoD;
import org.sleuthkit.datamodel.timeline.EventCluster;
import org.sleuthkit.datamodel.timeline.EventStripe;
import org.sleuthkit.datamodel.timeline.EventType;
import org.sleuthkit.datamodel.timeline.EventTypeZoomLevel;
import org.sleuthkit.datamodel.timeline.RangeDivisionInfo;
import org.sleuthkit.datamodel.timeline.RootEventType;
import org.sleuthkit.datamodel.timeline.SingleEvent;
import org.sleuthkit.datamodel.timeline.TimeUnits;
import org.sleuthkit.datamodel.timeline.ZoomParams;
import org.sleuthkit.datamodel.timeline.filters.AbstractFilter;
import org.sleuthkit.datamodel.timeline.filters.DataSourceFilter;
import org.sleuthkit.datamodel.timeline.filters.DataSourcesFilter;
import org.sleuthkit.datamodel.timeline.filters.DescriptionFilter;
import org.sleuthkit.datamodel.timeline.filters.Filter;
import org.sleuthkit.datamodel.timeline.filters.HashHitsFilter;
import org.sleuthkit.datamodel.timeline.filters.HideKnownFilter;
import org.sleuthkit.datamodel.timeline.filters.IntersectionFilter;
import org.sleuthkit.datamodel.timeline.filters.RootFilter;
import org.sleuthkit.datamodel.timeline.filters.TagsFilter;
import org.sleuthkit.datamodel.timeline.filters.TextFilter;
import org.sleuthkit.datamodel.timeline.filters.TypeFilter;
import org.sleuthkit.datamodel.timeline.filters.UnionFilter;

/**
 * Provides access to the Timeline features of SleuthkitCase
 */
public final class TimelineManager {

	private static final Logger LOGGER = Logger.getLogger(TimelineManager.class.getName());

	private final Set<PreparedStatement> preparedStatements = new HashSet<>();

	private final SleuthkitCase sleuthkitCase;
	private final String primaryKeyType;
	private final String csvFunction;

	TimelineManager(SleuthkitCase tskCase) throws TskCoreException {
		sleuthkitCase = tskCase;
		primaryKeyType = sleuthkitCase.getDatabaseType() == TskData.DbType.POSTGRESQL ? "BIGSERIAL" : "INTEGER";
		csvFunction = sleuthkitCase.getDatabaseType() == TskData.DbType.POSTGRESQL ? "string_agg" : "group_concat";

		initializeDB();
	}

	public Interval getSpanningInterval(Collection<Long> eventIDs) throws TskCoreException {
		if (eventIDs.isEmpty()) {
			return null;
		}
		final String query = "SELECT Min(time) as minTime, Max(time) as maxTime FROM events WHERE event_id IN (" + joinAsStrings(eventIDs, ", ") + ")";
		sleuthkitCase.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement stmt = con.createStatement();
				ResultSet results = stmt.executeQuery(query);) {
			if (results.next()) {
				return new Interval(results.getLong("minTime") * 1000, (results.getLong("maxTime") + 1) * 1000, DateTimeZone.UTC); // NON-NLS
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error executing get spanning interval query: " + query, ex); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseReadLock();
		}
		return null;
	}

	public SleuthkitCase.CaseDbTransaction beginTransaction() throws TskCoreException {
		return sleuthkitCase.beginTransaction();
	}

	public void commitTransaction(SleuthkitCase.CaseDbTransaction transaction) throws TskCoreException {
		transaction.commit();
	}

	/**
	 * @return the total number of events in the database or, -1 if there is an
	 *         error.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public int countAllEvents() throws TskCoreException {
		sleuthkitCase.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement statement = con.createStatement();
				ResultSet results = statement.executeQuery(STATEMENTS.COUNT_ALL_EVENTS.getSQL());) {
			if (results.next()) {
				return results.getInt("count"); // NON-NLS
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error counting all events", ex); //NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseReadLock();
		}
		return -1;
	}

	/**
	 * get the count of all events that fit the given zoom params organized by
	 * the EvenType of the level specified in the ZoomParams
	 *
	 * @param params the params that control what events to count and how to
	 *               organize the returned map
	 *
	 * @return a map from event type( of the requested level) to event counts
	 */
	public Map<EventType, Long> countEventsByType(ZoomParams params) throws TskCoreException {
		if (params.getTimeRange() == null) {
			return Collections.emptyMap();
		} else {
			return countEventsByType(params.getTimeRange().getStartMillis() / 1000,
					params.getTimeRange().getEndMillis() / 1000,
					params.getFilter(), params.getTypeZoomLevel());
		}
	}

	/**
	 * get a count of tagnames applied to the given event ids as a map from
	 * tagname displayname to count of tag applications
	 *
	 * @param eventIDsWithTags the event ids to get the tag counts map for
	 *
	 * @return a map from tagname displayname to count of applications
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public Map<String, Long> getTagCountsByTagName(Set<Long> eventIDsWithTags) throws TskCoreException {
		sleuthkitCase.acquireSingleUserCaseReadLock();
		String query
				= "SELECT tag_names.display_name AS display_name, COUNT(distinct tag_id) AS count FROM "
				+ getAugmentedEventsTablesSQL(true, false)
				+ " JOIN tag_names ON (events.tag_name_id = tag_names.tag_name_id ) "
				+ " WHERE event_id IN (" + StringUtils.buildCSVString(eventIDsWithTags) + ") "
				+ " GROUP BY tag_names.tag_name_id";
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement statement = con.createStatement();
				ResultSet resultSet = statement.executeQuery(query);) {
			HashMap<String, Long> counts = new HashMap<>();
			while (resultSet.next()) {
				counts.put(resultSet.getString("display_name"), resultSet.getLong("count")); //NON-NLS
			}
			return counts;
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to get tag counts by tag name with query: " + query, ex); //NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * drop the tables from this database and recreate them in order to start
	 * over.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public void reInitializeDB() throws TskCoreException {
		sleuthkitCase.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement statement = con.createStatement();) {
			statement.execute(STATEMENTS.DROP_DB_INFO_TABLE.getSQL());
			statement.execute(STATEMENTS.DROP_EVENTS_TABLE.getSQL());

			initializeDB();
		} catch (SQLException ex) {
			throw new TskCoreException("Error dropping old tables", ex); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Get the minimal interval that bounds all the vents that pass the given
	 * filter.
	 *
	 * @param timeRange The timerange that the events must be within.
	 * @param filter    The filter that the events must pass.
	 * @param timeZone  The timeZone to return the interval in.
	 *
	 * @return The minimal interval that bounds the events.
	 *
	 * @throws TskCoreException
	 */
	public Interval getSpanningInterval(Interval timeRange, RootFilter filter, DateTimeZone timeZone) throws TskCoreException {
		long start = timeRange.getStartMillis() / 1000;
		long end = timeRange.getEndMillis() / 1000;
		String sqlWhere = getSQLWhere(filter);
		sleuthkitCase.acquireSingleUserCaseReadLock();
		boolean needsTags = filter.getTagsFilter().isActive();
		boolean needsHashSets = filter.getHashHitsFilter().isActive();
		String augmentedEventsTablesSQL = getAugmentedEventsTablesSQL(needsTags, needsHashSets);
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement stmt = con.createStatement(); //can't use prepared statement because of complex where clause
				ResultSet results = stmt.executeQuery(
						" SELECT (SELECT Max(time) FROM " + augmentedEventsTablesSQL
						+ "			 WHERE time <=" + start + " AND " + sqlWhere + ") AS start,"
						+ "		 (SELECT Min(time)  FROM " + augmentedEventsTablesSQL
						+ "			 WHERE time >= " + end + " AND " + sqlWhere + ") AS end");) {

			if (results.next()) {
				long start2 = results.getLong("start"); // NON-NLS
				long end2 = results.getLong("end"); // NON-NLS

				if (end2 == 0) {
					end2 = getMaxTime();
				}
				return new Interval(start2 * 1000, (end2 + 1) * 1000, timeZone);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to get MIN time.", ex); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseReadLock();
		}
		return null;
	}

	public SingleEvent getEventById(Long eventID) throws TskCoreException {
		sleuthkitCase.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				PreparedStatement stmt = con.prepareStatement(STATEMENTS.GET_EVENT_BY_ID.getSQL(), 0);) {
			stmt.setLong(1, eventID);
			try (ResultSet results = stmt.executeQuery();) {
				if (results.next()) {
					return constructTimeLineEvent(results);
				}
			}
		} catch (SQLException sqlEx) {
			throw new TskCoreException("exception while querying for event with id = " + eventID, sqlEx); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseReadLock();
		}
		return null;
	}

	/**
	 * Get the IDs of all the events within the given time range that pass the
	 * given filter.
	 *
	 * @param timeRange The Interval that all returned events must be within.
	 * @param filter    The Filter that all returned events must pass.
	 *
	 * @return A List of event ids, sorted by timestamp of the corresponding
	 *         event..
	 */
	public List<Long> getEventIDs(Interval timeRange, RootFilter filter) throws TskCoreException {
		Long startTime = timeRange.getStartMillis() / 1000;
		Long endTime = timeRange.getEndMillis() / 1000;

		if (Objects.equals(startTime, endTime)) {
			endTime++; //make sure end is at least 1 millisecond after start
		}

		ArrayList<Long> resultIDs = new ArrayList<>();

		sleuthkitCase.acquireSingleUserCaseReadLock();
		boolean needsTags = filter.getTagsFilter().isActive();
		boolean needsHashSets = filter.getHashHitsFilter().isActive();
		String query = "SELECT events.event_id AS event_id FROM" + getAugmentedEventsTablesSQL(needsTags, needsHashSets)
				+ " WHERE time >=  " + startTime + " AND time <" + endTime + " AND " + getSQLWhere(filter) + " ORDER BY time ASC"; // NON-NLS
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement stmt = con.createStatement();
				ResultSet results = stmt.executeQuery(query);) {
			while (results.next()) {
				resultIDs.add(results.getLong("event_id")); //NON-NLS
			}

		} catch (SQLException sqlEx) {
			throw new TskCoreException("failed to execute query for event ids in range", sqlEx); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseReadLock();
		}

		return resultIDs;
	}

	/**
	 * Get a representation of all the events, within the given time range, that
	 * pass the given filter, grouped by time and description such that file
	 * system events for the same file, with the same timestamp, are combined
	 * together.
	 *
	 * @param timeRange The Interval that all returned events must be within.
	 * @param filter    The Filter that all returned events must pass.
	 *
	 * @return A List of combined events, sorted by timestamp.
	 */
	public List<CombinedEvent> getCombinedEvents(Interval timeRange, RootFilter filter) throws TskCoreException {
		Long startTime = timeRange.getStartMillis() / 1000;
		Long endTime = timeRange.getEndMillis() / 1000;

		if (Objects.equals(startTime, endTime)) {
			endTime++; //make sure end is at least 1 millisecond after start
		}

		ArrayList<CombinedEvent> combinedEvents = new ArrayList<>();
		final boolean needsTags = filter.getTagsFilter().isActive();
		final boolean needsHashSets = filter.getHashHitsFilter().isActive();
		final String query = "SELECT full_description, time, file_id, "
				+ csvAggFunction("CAST(events.event_id AS VARCHAR)") + " AS eventIDs, "
				+ csvAggFunction("CAST(sub_type AS VARCHAR)") + " AS eventTypes"
				+ " FROM " + getAugmentedEventsTablesSQL(needsTags, needsHashSets)
				+ " WHERE time >= " + startTime + " AND time <" + endTime + " AND " + getSQLWhere(filter)
				+ " GROUP BY time, full_description, file_id ORDER BY time ASC, full_description";

		sleuthkitCase.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement stmt = con.createStatement();
				ResultSet resultSet = stmt.executeQuery(query);) {

			while (resultSet.next()) {

				//make a map from event type to event ID
				List<Long> eventIDs = unGroupConcat(resultSet.getString("eventIDs"), Long::valueOf);
				List<EventType> eventTypes = unGroupConcat(resultSet.getString("eventTypes"), (String s) -> RootEventType.allTypes.get(Integer.valueOf(s)));
				Map<EventType, Long> eventMap = new HashMap<>();
				for (int i = 0; i < eventIDs.size(); i++) {
					eventMap.put(eventTypes.get(i), eventIDs.get(i));
				}
				combinedEvents.add(new CombinedEvent(resultSet.getLong("time") * 1000, resultSet.getString("full_description"), resultSet.getLong("file_id"), eventMap));
			}

		} catch (SQLException sqlEx) {
			throw new TskCoreException("Failed to execute query for combined events: \n" + query, sqlEx); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseReadLock();
		}

		return combinedEvents;
	}

	/**
	 * this relies on the fact that no tskObj has ID 0 but 0 is the default
	 * value for the datasource_id column in the events table.
	 *
	 * @return
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public boolean hasNewColumns() throws TskCoreException {
		return hasHashHitColumn() && hasDataSourceIDColumn() && hasTaggedColumn()
				&& (getDataSourceIDs().isEmpty() == false);
	}

	public Set<Long> getDataSourceIDs() throws TskCoreException {
		sleuthkitCase.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement stmt = con.createStatement();
				ResultSet results = stmt.executeQuery(STATEMENTS.GET_DATASOURCE_IDS.getSQL());) {
			HashSet<Long> dataSourceIDs = new HashSet<>();
			while (results.next()) {
				long datasourceID = results.getLong("datasource_id"); //NON-NLS
				dataSourceIDs.add(datasourceID);
			}
			return dataSourceIDs;
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to get MAX time.", ex); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get a the hashset names for hash sets with hits.
	 *
	 * @return A set of hashset names which have hits.
	 *
	 * @throws TskCoreException
	 */
	public Set< String> getHashSetNames() throws TskCoreException {
		Set< String> hashSets = new HashSet<>();
		sleuthkitCase.acquireSingleUserCaseReadLock();

		String query = "SELECT DISTINCT value_text AS hash_set_name FROM blackboard_artifacts "
				+ " JOIN blackboard_attributes ON (blackboard_artifacts.artifact_id = blackboard_attributes.artifact_id) "
				+ " JOIN blackboard_artifact_types ON( blackboard_artifacts.artifact_type_id = blackboard_artifact_types.artifact_type_id) "
				+ " WHERE blackboard_artifact_types.artifact_type_id = " + BlackboardArtifact.ARTIFACT_TYPE.TSK_HASHSET_HIT.getTypeID()
				+ " AND blackboard_attributes.attribute_type_id = " + BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement stms = con.createStatement();
				ResultSet results = stms.executeQuery(query);) {
			while (results.next()) {
				String hashSetName = results.getString("hash_set_name"); //NON-NLS
				hashSets.add(hashSetName);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to get hash sets.", ex); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseReadLock();
		}
		return Collections.unmodifiableSet(hashSets);
	}

	public void analyze() throws TskCoreException {
		sleuthkitCase.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement stmt = con.createStatement();) {

			stmt.execute("ANALYZE;"); //NON-NLS
			if (sleuthkitCase.getDatabaseType() == TskData.DbType.SQLITE) {
				stmt.execute("analyze sqlite_master;"); //NON-NLS
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to analyze events db.", ex); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * @return maximum time in seconds from unix epoch
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public Long getMaxTime() throws TskCoreException {
		sleuthkitCase.acquireSingleUserCaseReadLock();

		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement stms = con.createStatement();
				ResultSet results = stms.executeQuery(STATEMENTS.GET_MAX_TIME.getSQL());) {
			if (results.next()) {
				return results.getLong("max"); // NON-NLS
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to get MAX time.", ex); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseReadLock();
		}
		return -1l;
	}

	/**
	 * @return maximum time in seconds from unix epoch
	 */
	public Long getMinTime() throws TskCoreException {
		sleuthkitCase.acquireSingleUserCaseReadLock();

		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement stms = con.createStatement();
				ResultSet results = stms.executeQuery(STATEMENTS.GET_MIN_TIME.getSQL());) {
			if (results.next()) {
				return results.getLong("min"); // NON-NLS
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to get MIN time.", ex); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseReadLock();
		}
		return -1l;
	}

	/**
	 * create the table and indices if they don't already exist
	 *
	 * @return the number of rows in the table , count > 0 indicating an
	 *         existing table
	 */
	synchronized void initializeDB() throws TskCoreException {
		///TODO: Move to SleuthkitCase?
		sleuthkitCase.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement stmt = con.createStatement();) {

			try {
				stmt.execute("CREATE TABLE if not exists db_info ( key TEXT,  value INTEGER, PRIMARY KEY (key))");// NON-NLS
			} catch (SQLException ex) {
				throw new TskCoreException("problem creating db_info table", ex); // NON-NLS
			}

			try {
				stmt.execute("CREATE TABLE if not exists events " // NON-NLS
						+ " (event_id " + primaryKeyType + " PRIMARY KEY, " // NON-NLS
						+ " datasource_id BIGINT, " // NON-NLS
						+ " file_id BIGINT, " // NON-NLS
						+ " artifact_id BIGINT, " // NON-NLS
						+ " time INTEGER, " // NON-NLS
						+ " sub_type INTEGER, " // NON-NLS
						+ " base_type INTEGER, " // NON-NLS
						+ " full_description TEXT, " // NON-NLS
						+ " med_description TEXT, " // NON-NLS
						+ " short_description TEXT, " // NON-NLS
						+ " known_state INTEGER," //boolean // NON-NLS
						+ " hash_hit INTEGER," //boolean // NON-NLS
						+ " tagged INTEGER)");//boolean // NON-NLS
			} catch (SQLException ex) {
				throw new TskCoreException("problem creating  database table", ex); // NON-NLS
			}

			if (hasDataSourceIDColumn() == false) {
				try {
					stmt.execute("ALTER TABLE events ADD COLUMN datasource_id INTEGER");	// NON-NLS
				} catch (SQLException ex) {
					throw new TskCoreException("problem upgrading events table", ex); // NON-NLS
				}
			}
			if (hasTaggedColumn() == false) {
				try {
					// NON-NLS
					stmt.execute("ALTER TABLE events ADD COLUMN tagged INTEGER");
				} catch (SQLException ex) {
					throw new TskCoreException("problem upgrading events table", ex); // NON-NLS
				}
			}

			if (hasHashHitColumn() == false) {
				try {
					stmt.execute("ALTER TABLE events ADD COLUMN hash_hit INTEGER");	// NON-NLS
				} catch (SQLException ex) {
					throw new TskCoreException("problem upgrading events table", ex); // NON-NLS
				}
			}

			createIndex("events", Arrays.asList("datasource_id")); //NON-NLS
			createIndex("events", Arrays.asList("event_id", "hash_hit")); //NON-NLS
			createIndex("events", Arrays.asList("event_id", "tagged")); //NON-NLS
			createIndex("events", Arrays.asList("file_id")); //NON-NLS
			createIndex("events", Arrays.asList("artifact_id")); //NON-NLS
			createIndex("events", Arrays.asList("sub_type", "short_description", "time")); //NON-NLS
			createIndex("events", Arrays.asList("base_type", "short_description", "time")); //NON-NLS
			createIndex("events", Arrays.asList("time")); //NON-NLS
			createIndex("events", Arrays.asList("known_state")); //NON-NLS
		} catch (SQLException ex) {
			throw new TskCoreException("Error initializing event tables", ex);
		} finally {
			sleuthkitCase.releaseSingleUserCaseWriteLock();
		}
	}

	private enum STATEMENTS {
		INSERT_ROW("INSERT INTO events ("
				+ " datasource_id,"
				+ " file_id ,"
				+ " artifact_id, "
				+ " time, "
				+ " sub_type,"
				+ " base_type,"
				+ " full_description,"
				+ " med_description, "
				+ " short_description, "
				+ " known_state,"
				+ " hash_hit,"
				+ " tagged) " // NON-NLS
				+ " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"), // NON-NLS
		GET_DATASOURCE_IDS("SELECT DISTINCT datasource_id FROM events WHERE datasource_id != 0"),// NON-NLS
		GET_MAX_TIME("SELECT Max(time) AS max FROM events"), // NON-NLS
		GET_MIN_TIME("SELECT Min(time) AS min FROM events"), // NON-NLS
		GET_EVENT_BY_ID("SELECT * FROM events WHERE event_id =  ?"), // NON-NLS

		/*
		 * This SQL query is really just a select count(*), but that has
		 * performance problems on very large tables unless you include a where
		 * clause see http://stackoverflow.com/a/9338276/4004683 for more.
		 */
		COUNT_ALL_EVENTS("SELECT count(event_id) AS count FROM events WHERE event_id IS NOT null"), //NON-NLS
		DROP_EVENTS_TABLE("DROP TABLE IF EXISTS events"), //NON-NLS
		DROP_DB_INFO_TABLE("DROP TABLE IF EXISTS db_ino"), //NON-NLS
		SELECT_NON_ARTIFACT_EVENT_IDS_BY_OBJECT_ID("SELECT event_id FROM events WHERE file_id = ? AND artifact_id IS NULL"), //NON-NLS
		SELECT_EVENT_IDS_BY_OBJECT_ID_AND_ARTIFACT_ID("SELECT event_id FROM events WHERE file_id = ? AND artifact_id = ?"); //NON-NLS

		private final String sql;

		private STATEMENTS(String sql) {
			this.sql = sql;
		}

		String getSQL() {
			return sql;
		}
	}

	/**
	 * Get a List of event IDs for the events that are derived from the given
	 * artifact.
	 *
	 * @param artifact The BlackboardArtifact to get derived event IDs for.
	 *
	 * @return A List of event IDs for the events that are derived from the
	 *         given artifact.
	 */
	public List<Long> getEventIDsForArtifact(BlackboardArtifact artifact) throws TskCoreException {
		ArrayList<Long> eventIDs = new ArrayList<Long>();

		String query = "SELECT event_id FROM events WHERE artifact_id = " + artifact.getArtifactID();
		sleuthkitCase.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement stmt = con.createStatement();
				ResultSet results = stmt.executeQuery(query);) {
			while (results.next()) {
				eventIDs.add(results.getLong("event_id"));
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error executing getEventIDsForArtifact query.", ex); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseReadLock();
		}
		return eventIDs;
	}

	/**
	 * Get a List of event IDs for the events that are derived from the given
	 * file.
	 *
	 * @param file                    The AbstractFile to get derived event IDs
	 *                                for.
	 * @param includeDerivedArtifacts If true, also get event IDs for events
	 *                                derived from artifacts derived form this
	 *                                file. If false, only gets events derived
	 *                                directly from this file (file system
	 *                                timestamps).
	 *
	 * @return A List of event IDs for the events that are derived from the
	 *         given file.
	 */
	public List<Long> getEventIDsForFile(AbstractFile file, boolean includeDerivedArtifacts) throws TskCoreException {
		ArrayList<Long> eventIDs = new ArrayList<>();

		String query = "SELECT event_id FROM events WHERE file_id = " + file.getId()
				+ (includeDerivedArtifacts ? "" : " AND artifact_id IS NULL");
		sleuthkitCase.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement stmt = con.createStatement();
				ResultSet results = stmt.executeQuery(query);) {
			while (results.next()) {
				eventIDs.add(results.getLong("event_id"));
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error executing getEventIDsForFile query.", ex); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseReadLock();
		}
		return eventIDs;
	}

	/**
	 * NOTE: does not lock the db, must be called form inside a
	 * DBLock.lock/unlock pair
	 *
	 * @param tableName  the value of tableName
	 * @param columnList the value of columnList
	 */
	private void createIndex(final String tableName, final List<String> columnList) throws TskCoreException {
		String indexColumns = columnList.stream().collect(Collectors.joining(",", "(", ")"));
		String indexName = tableName + "_" + joinAsStrings(columnList, "_") + "_idx"; //NON-NLS
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement stmt = con.createStatement();) {
			String sql = "CREATE INDEX IF NOT EXISTS " + indexName + " ON " + tableName + indexColumns; // NON-NLS
			stmt.execute(sql);
		} catch (SQLException ex) {
			throw new TskCoreException("problem creating index " + indexName, ex); // NON-NLS
		}
	}

	/**
	 * @param dbColumn the value of dbColumn
	 *
	 * @return the boolean
	 */
	private boolean hasDBColumn(final String dbColumn) throws TskCoreException {

		String query = sleuthkitCase.getDatabaseType() == TskData.DbType.POSTGRESQL
				? "SELECT column_name as name FROM information_schema.columns WHERE table_name = 'events';" //NON-NLS  //Postgres
				: "PRAGMA table_info(events)";	//NON-NLS //SQLite
		sleuthkitCase.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement statement = con.createStatement();) {
			statement.execute(query);
			try (ResultSet results = statement.getResultSet();) {
				while (results.next()) {
					if (dbColumn.equals(results.getString("name"))) {	//NON-NLS
						return true;
					}
				}
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error querying for events table column names", ex); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseReadLock();
		}
		return false;
	}

	private boolean hasDataSourceIDColumn() throws TskCoreException {
		return hasDBColumn("datasource_id"); //NON-NLS
	}

	private boolean hasTaggedColumn() throws TskCoreException {
		return hasDBColumn("tagged"); //NON-NLS
	}

	private boolean hasHashHitColumn() throws TskCoreException {
		return hasDBColumn("hash_hit"); //NON-NLS
	}

	public void insertEvent(long time, EventType type, long datasourceID, long objID,
			Long artifactID, String fullDescription, String medDescription,
			String shortDescription, TskData.FileKnown known, Set<String> hashSetNames, List<? extends Tag> tags) throws TskCoreException {

		int typeNum = RootEventType.allTypes.indexOf(type);
		int superTypeNum = type.getSuperType().ordinal();

		sleuthkitCase.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				PreparedStatement insertRowStmt = con.prepareStatement(STATEMENTS.INSERT_ROW.getSQL(), PreparedStatement.NO_GENERATED_KEYS);) {
			//"INSERT INTO events (datasource_id,file_id ,artifact_id, time, sub_type, base_type, full_description, med_description, short_description, known_state, hashHit, tagged) " 
			insertRowStmt.clearParameters();
			insertRowStmt.setLong(1, datasourceID);
			insertRowStmt.setLong(2, objID);
			if (artifactID == null) {
				insertRowStmt.setNull(3, Types.NULL);
			} else {
				insertRowStmt.setLong(3, artifactID);
			}
			insertRowStmt.setLong(4, time);

			if (typeNum == -1) {
				insertRowStmt.setNull(5, Types.INTEGER);
			} else {
				insertRowStmt.setInt(5, typeNum);
			}

			insertRowStmt.setInt(6, superTypeNum);
			insertRowStmt.setString(7, fullDescription);
			insertRowStmt.setString(8, medDescription);
			insertRowStmt.setString(9, shortDescription);

			insertRowStmt.setByte(10, known == null ? TskData.FileKnown.UNKNOWN.getFileKnownValue() : known.getFileKnownValue());

			insertRowStmt.setInt(11, hashSetNames.isEmpty() ? 0 : 1);
			insertRowStmt.setInt(12, tags.isEmpty() ? 0 : 1);

			insertRowStmt.executeUpdate();
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to insert event.", ex); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseWriteLock();
		}
	}

	private UnsupportedOperationException getUnsupportedDBTypeException() {
		return new UnsupportedOperationException("Unsupported DB type: " + sleuthkitCase.getDatabaseType().name());
	}

	private Set<Long> getEventIDs(long objectID) throws TskCoreException {
		//TODO: inline this
		HashSet<Long> eventIDs = new HashSet<>();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				PreparedStatement selectStmt = con.prepareStatement(STATEMENTS.SELECT_NON_ARTIFACT_EVENT_IDS_BY_OBJECT_ID.getSQL(), 0);) {
			//"SELECT event_id FROM events WHERE file_id = ? AND artifact_id IS NULL"
			selectStmt.setLong(1, objectID);
			try (ResultSet executeQuery = selectStmt.executeQuery();) {
				while (executeQuery.next()) {
					eventIDs.add(executeQuery.getLong("event_id")); //NON-NLS
				}
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting event ids for object id = " + objectID, ex);
		}
		return eventIDs;
	}

	private Set<Long> getEventIDs(long objectID, Long artifactID) throws TskCoreException {
		//TODO: inline this
		HashSet<Long> eventIDs = new HashSet<>();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				PreparedStatement selectStmt = con.prepareStatement(STATEMENTS.SELECT_EVENT_IDS_BY_OBJECT_ID_AND_ARTIFACT_ID.getSQL(), 0);) {
			//"SELECT event_id FROM events WHERE file_id = ? AND artifact_id = ?"
			selectStmt.setLong(1, objectID);
			selectStmt.setLong(2, artifactID);
			try (ResultSet executeQuery = selectStmt.executeQuery();) {

				while (executeQuery.next()) {
					eventIDs.add(executeQuery.getLong("event_id")); //NON-NLS
				}
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting event ids for object id = " + objectID + " and artifact id = " + artifactID, ex);
		}
		return eventIDs;
	}

	/**
	 * mark any events with the given object and artifact ids as tagged.
	 *
	 *
	 * @param objectID   the obj_id that this tag applies to, the id of the
	 *                   content that the artifact is derived from for artifact
	 *                   tags
	 * @param artifactID the artifact_id that this tag applies to, or null if
	 *                   this is a content tag
	 * @param tagged     true to mark the matching events tagged, false to mark
	 *                   them as untagged
	 *
	 * @return the event ids that match the object/artifact pair
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public Set<Long> setEventsTagged(long objectID, Long artifactID, boolean tagged) throws TskCoreException {

		sleuthkitCase.acquireSingleUserCaseWriteLock();
		Set<Long> eventIDs = Collections.emptySet();
		if (Objects.isNull(artifactID)) {
			eventIDs = getEventIDs(objectID);
		} else {
			eventIDs = getEventIDs(objectID, artifactID);
		}

		//update tagged state for all event with selected ids
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement updateStatement = con.createStatement();) {
			updateStatement.executeUpdate("UPDATE events SET tagged = " + (tagged ? 1 : 0) //NON-NLS
					+ " WHERE event_id IN (" + joinAsStrings(eventIDs, ",") + ")"); //NON-NLS
		} catch (SQLException ex) {
			throw new TskCoreException("Error marking events tagged", ex);
		} finally {
			sleuthkitCase.releaseSingleUserCaseWriteLock();
		}
		return eventIDs;
	}

	void rollBackTransaction(SleuthkitCase.CaseDbTransaction trans) throws TskCoreException {
		trans.rollback();
	}

	@Override
	protected void finalize() throws Throwable {
		try {
			closeStatements();
		} finally {
			super.finalize();
		}
	}

	private void closeStatements() throws SQLException {
		for (PreparedStatement pStmt : preparedStatements) {
			pStmt.close();
		}
	}

	private SingleEvent constructTimeLineEvent(ResultSet resultSet) throws SQLException {
		return new SingleEvent(resultSet.getLong("event_id"), //NON-NLS
				resultSet.getLong("datasource_id"), //NON-NLS
				resultSet.getLong("file_id"), //NON-NLS
				resultSet.getLong("artifact_id"), //NON-NLS
				resultSet.getLong("time"), RootEventType.allTypes.get(resultSet.getInt("sub_type")), //NON-NLS
				resultSet.getString("full_description"), //NON-NLS
				resultSet.getString("med_description"), //NON-NLS
				resultSet.getString("short_description"), //NON-NLS
				TskData.FileKnown.valueOf(resultSet.getByte("known_state")), //NON-NLS
				resultSet.getInt("hash_hit") != 0, //NON-NLS
				resultSet.getInt("tagged") != 0); //NON-NLS
	}

	/**
	 * count all the events with the given options and return a map organizing
	 * the counts in a hierarchy from date > eventtype> count
	 *
	 * @param startTime events before this time will be excluded (seconds from
	 *                  unix epoch)
	 * @param endTime   events at or after this time will be excluded (seconds
	 *                  from unix epoch)
	 * @param filter    only events that pass this filter will be counted
	 * @param zoomLevel only events of this type or a subtype will be counted
	 *                  and the counts will be organized into bins for each of
	 *                  the subtypes of the given event type
	 *
	 * @return a map organizing the counts in a hierarchy from date > eventtype>
	 *         count
	 */
	private Map<EventType, Long> countEventsByType(Long startTime, Long endTime, RootFilter filter, EventTypeZoomLevel zoomLevel) throws TskCoreException {
		if (Objects.equals(startTime, endTime)) {
			endTime++;
		}

		Map<EventType, Long> typeMap = new HashMap<>();

		//do we want the root or subtype column of the databse
		final boolean useSubTypes = EventTypeZoomLevel.SUB_TYPE.equals(zoomLevel);
		final boolean needsTags = filter.getTagsFilter().isActive();
		final boolean needsHashSets = filter.getHashHitsFilter().isActive();
		//get some info about the range of dates requested
		final String queryString = "SELECT count(DISTINCT events.event_id) AS count, " + typeColumnHelper(useSubTypes) //NON-NLS
				+ " FROM " + getAugmentedEventsTablesSQL(needsTags, needsHashSets)
				+ " WHERE time >= " + startTime + " AND time < " + endTime + " AND " + getSQLWhere(filter) // NON-NLS
				+ " GROUP BY " + typeColumnHelper(useSubTypes); // NON-NLS

		sleuthkitCase.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement stmt = con.createStatement();
				ResultSet results = stmt.executeQuery(queryString);) {
			while (results.next()) {
				EventType type = useSubTypes
						? RootEventType.allTypes.get(results.getInt("sub_type")) //NON-NLS
						: BaseTypes.values()[results.getInt("base_type")]; //NON-NLS

				typeMap.put(type, results.getLong("count")); // NON-NLS
			}

		} catch (SQLException ex) {
			throw new TskCoreException("Error getting count of events from db: " + queryString, ex); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseReadLock();
		}
		return typeMap;
	}

	/**
	 * Get an SQL expression that returns the union of the events table joined
	 * to the content and blackboard artifacts tags tables, if necessary. Other
	 * wise just return "events"
	 *
	 * Omitting details it is: SELECT <all relevant columns> FROM events JOIN
	 * content_tags UNION ALL events JOIN blackboard_artifact_tags
	 *
	 * @param filter   The root filter. If the tags filter is active, the sql
	 *                 for the joined tables is returned.
	 * @param needTags the value of needTags
	 *
	 * @return the java.lang.String
	 */
	private String getAugmentedEventsTablesSQL(boolean needTags, boolean needHashSets) {
		String coreColumns = "event_id, datasource_id, events.file_id, events.artifact_id,"
				+ "			time, sub_type, base_type, full_description, med_description, "
				+ "			short_description, known_state, hash_hit, tagged ";
		String tagColumns = " , tag_name_id, tag_id ";
		String joinedWithTags = needTags ? "("
				+ " SELECT " + coreColumns + tagColumns
				+ "		from events LEFT OUTER JOIN content_tags ON (content_tags.obj_id = events.file_id) "
				+ "	UNION ALL "
				+ "	SELECT " + coreColumns + tagColumns
				+ "		FROM events LEFT OUTER JOIN blackboard_artifact_tags ON (blackboard_artifact_tags.artifact_id = events.artifact_id)"
				+ " ) AS events" : " events ";
		if (needHashSets) {
			return " ( SELECT " + coreColumns + (needTags ? tagColumns : "") + " , hash_set_name "
					+ " FROM " + joinedWithTags + " LEFT OUTER JOIN ( "
					+ "		SELECT DISTINCT value_text AS hash_set_name, obj_id  "
					+ "		FROM blackboard_artifacts"
					+ "		JOIN blackboard_attributes ON (blackboard_artifacts.artifact_id = blackboard_attributes.artifact_id)"
					+ "		JOIN blackboard_artifact_types ON( blackboard_artifacts.artifact_type_id = blackboard_artifact_types.artifact_type_id)"
					+ "		WHERE  blackboard_artifact_types.artifact_type_id = " + TSK_HASHSET_HIT.getTypeID()
					+ "		AND blackboard_attributes.attribute_type_id = " + TSK_SET_NAME.getTypeID() + ") AS hash_set_hits"
					+ "	ON ( events.file_id = hash_set_hits.obj_id)) AS events";
		} else {
			return joinedWithTags;
		}
	}

	/**
	 * Get a list of EventStripes, clustered according to the given zoom
	 * paramaters.
	 *
	 * @param params   The ZoomParams that determine the zooming, filtering and
	 *                 clustering.
	 * @param timeZone The time zone to use.
	 *
	 * @return a list of aggregate events within the given timerange, that pass
	 *         the supplied filter, aggregated according to the given event type
	 *         and description zoom levels
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException If there is an error
	 *                                                  querying the db.
	 */
	public List<EventStripe> getEventStripes(ZoomParams params, DateTimeZone timeZone) throws TskCoreException {
		//unpack params
		Interval timeRange = params.getTimeRange();
		RootFilter filter = params.getFilter();
		DescriptionLoD descriptionLOD = params.getDescriptionLOD();
		EventTypeZoomLevel typeZoomLevel = params.getTypeZoomLevel();

		long start = timeRange.getStartMillis() / 1000;
		long end = timeRange.getEndMillis() / 1000;

		//ensure length of querried interval is not 0
		end = Math.max(end, start + 1);

		//get some info about the time range requested
		RangeDivisionInfo rangeInfo = RangeDivisionInfo.getRangeDivisionInfo(timeRange, timeZone);

		//build dynamic parts of query
		String descriptionColumn = getDescriptionColumn(descriptionLOD);
		final boolean useSubTypes = typeZoomLevel.equals(EventTypeZoomLevel.SUB_TYPE);
		String typeColumn = typeColumnHelper(useSubTypes);
		final boolean needsTags = filter.getTagsFilter().isActive();
		final boolean needsHashSets = filter.getHashHitsFilter().isActive();
		//compose query string, the new-lines are only for nicer formatting if printing the entire query
		String query = "SELECT " + formatTimeFunction(rangeInfo.getPeriodSize(), timeZone) + " AS interval, " // NON-NLS
				+ csvAggFunction("events.event_id") + " as event_ids, " //NON-NLS
				+ csvAggFunction("CASE WHEN hash_hit = 1 THEN events.event_id ELSE NULL END") + " as hash_hits, " //NON-NLS
				+ csvAggFunction("CASE WHEN tagged = 1 THEN events.event_id ELSE NULL END") + " as taggeds, " //NON-NLS
				+ " min(time) AS minTime, max(time) AS maxTime,  " + typeColumn + ", " + descriptionColumn // NON-NLS
				+ " FROM " + getAugmentedEventsTablesSQL(needsTags, needsHashSets) // NON-NLS
				+ " WHERE time >= " + start + " AND time < " + end + " AND " + getSQLWhere(filter) // NON-NLS
				+ " GROUP BY interval, " + typeColumn + " , " + descriptionColumn // NON-NLS
				+ " ORDER BY min(time)"; // NON-NLS

		// perform query and map results to AggregateEvent objects
		List<EventCluster> events = new ArrayList<>();

		sleuthkitCase.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement createStatement = con.createStatement();
				ResultSet resultSet = createStatement.executeQuery(query)) {
			while (resultSet.next()) {
				events.add(eventClusterHelper(resultSet, useSubTypes, descriptionLOD, timeZone));
			}
		} catch (SQLException ex) {
			LOGGER.log(Level.SEVERE, "Failed to get events with query: " + query, ex); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseReadLock();
		}

		return mergeClustersToStripes(rangeInfo.getPeriodSize().getPeriod(), events);
	}

	String formatTimeFunction(TimeUnits periodSize, DateTimeZone timeZone) {
		switch (sleuthkitCase.getDatabaseType()) {
			case SQLITE:
				String strfTimeFormat = getStrfTimeFormat(periodSize);
				String useLocalTime = timeZone.equals(DateTimeZone.getDefault()) ? ", 'localtime'" : ""; // NON-NLS
				return "strftime('" + strfTimeFormat + "', time , 'unixepoch'" + useLocalTime + ")";
			case POSTGRESQL:
				String formatString = getPostgresTimeFormat(periodSize);
				return "to_char(to_timestamp(time) AT TIME ZONE '" + timeZone.getID() + "', '" + formatString + "')";
			default:
				throw getUnsupportedDBTypeException();
		}
	}

	/**
	 * map a single row in a ResultSet to an EventCluster
	 *
	 * @param resultSet      the result set whose current row should be mapped
	 * @param useSubTypes    use the sub_type column if true, else use the
	 *                       base_type column
	 * @param descriptionLOD the description level of detail for this event
	 * @param filter
	 *
	 * @return an AggregateEvent corresponding to the current row in the given
	 *         result set
	 *
	 * @throws SQLException
	 */
	private EventCluster eventClusterHelper(ResultSet resultSet, boolean useSubTypes, DescriptionLoD descriptionLOD, DateTimeZone timeZone) throws SQLException {
		Interval interval = new Interval(resultSet.getLong("minTime") * 1000, resultSet.getLong("maxTime") * 1000, timeZone);// NON-NLS
		String eventIDsString = resultSet.getString("event_ids");// NON-NLS
		List<Long> eventIDs = unGroupConcat(eventIDsString, Long::valueOf);
		String description = resultSet.getString(getDescriptionColumn(descriptionLOD));
		EventType type = useSubTypes ? RootEventType.allTypes.get(resultSet.getInt("sub_type")) : BaseTypes.values()[resultSet.getInt("base_type")];// NON-NLS

		List<Long> hashHits = unGroupConcat(resultSet.getString("hash_hits"), Long::valueOf); //NON-NLS
		List<Long> tagged = unGroupConcat(resultSet.getString("taggeds"), Long::valueOf); //NON-NLS

		return new EventCluster(interval, type, eventIDs, hashHits, tagged, description, descriptionLOD);
	}

	/**
	 * merge the events in the given list if they are within the same period
	 * General algorithm is as follows:
	 *
	 * 1) sort them into a map from (type, description)-> List<aggevent>
	 * 2) for each key in map, merge the events and accumulate them in a list to
	 * return
	 *
	 * @param timeUnitLength
	 * @param preMergedEvents
	 *
	 * @return
	 */
	static private List<EventStripe> mergeClustersToStripes(Period timeUnitLength, List<EventCluster> preMergedEvents) {

		//effectively map from type to (map from description to events)
		Map<EventType, SetMultimap< String, EventCluster>> typeMap = new HashMap<>();

		for (EventCluster aggregateEvent : preMergedEvents) {
			typeMap.computeIfAbsent(aggregateEvent.getEventType(), eventType -> HashMultimap.create())
					.put(aggregateEvent.getDescription(), aggregateEvent);
		}
		//result list to return
		ArrayList<EventCluster> aggEvents = new ArrayList<>();

		//For each (type, description) key, merge agg events
		for (SetMultimap<String, EventCluster> descrMap : typeMap.values()) {
			//for each description ...
			for (String descr : descrMap.keySet()) {
				//run through the sorted events, merging together adjacent events
				Iterator<EventCluster> iterator = descrMap.get(descr).stream()
						.sorted(Comparator.comparing(event -> event.getSpan().getStartMillis()))
						.iterator();
				EventCluster current = iterator.next();
				while (iterator.hasNext()) {
					EventCluster next = iterator.next();
					Interval gap = current.getSpan().gap(next.getSpan());

					//if they overlap or gap is less one quarter timeUnitLength
					//TODO: 1/4 factor is arbitrary. review! -jm
					if (gap == null || gap.toDuration().getMillis() <= timeUnitLength.toDurationFrom(gap.getStart()).getMillis() / 4) {
						//merge them
						current = EventCluster.merge(current, next);
					} else {
						//done merging into current, set next as new current
						aggEvents.add(current);
						current = next;
					}
				}
				aggEvents.add(current);
			}
		}

		//merge clusters to stripes
		Map<ImmutablePair<EventType, String>, EventStripe> stripeDescMap = new HashMap<>();

		for (EventCluster eventCluster : aggEvents) {
			stripeDescMap.merge(ImmutablePair.of(eventCluster.getEventType(), eventCluster.getDescription()),
					new EventStripe(eventCluster), EventStripe::merge);
		}

		return stripeDescMap.values().stream().sorted(Comparator.comparing(EventStripe::getStartMillis)).collect(Collectors.toList());
	}

	/**
	 * Static helper methods for converting between java "data model" objects
	 * and sqlite queries.
	 */
	private static String typeColumnHelper(final boolean useSubTypes) {
		return useSubTypes ? "sub_type" : "base_type"; //NON-NLS
	}

	/**
	 * take the result of a group_concat SQLite operation and split it into a
	 * set of X using the mapper to to convert from string to X If groupConcat
	 * is empty, null, or all whitespace, returns an empty list.
	 *
	 * @param <X>         the type of elements to return
	 * @param groupConcat a string containing the group_concat result ( a comma
	 *                    separated list)
	 * @param mapper      a function from String to X
	 *
	 * @return a Set of X, each element mapped from one element of the original
	 *         comma delimited string
	 */
	<X> List<X> unGroupConcat(String groupConcat, Function<String, X> mapper) {
		if (org.apache.commons.lang3.StringUtils.isBlank(groupConcat)) {
			return Collections.emptyList();
		}

		List<X> result = new ArrayList<>();
		String[] split = groupConcat.split(",");
		for (String s : split) {
			result.add(mapper.apply(s));
		}
		return result;
	}

	/**
	 * get the SQL where clause corresponding to an intersection filter ie
	 * (sub-clause1 and sub-clause2 and ... and sub-clauseN)
	 *
	 * @param filter the filter get the where clause for
	 *
	 * @return an SQL where clause (without the "where") corresponding to the
	 *         filter
	 */
	private String getSQLWhere(IntersectionFilter<?> filter) {
		String join = String.join(" and ", filter.getSubFilters().stream()
				.filter(Filter::isActive)
				.map(this::getSQLWhere)
				.collect(Collectors.toList()));
		return "(" + org.apache.commons.lang3.StringUtils.defaultIfBlank(join, getTrueLiteral()) + ")";
	}

	/**
	 * get the SQL where clause corresponding to a union filter ie (sub-clause1
	 * or sub-clause2 or ... or sub-clauseN)
	 *
	 * @param filter the filter get the where clause for
	 *
	 * @return an SQL where clause (without the "where") corresponding to the
	 *         filter
	 */
	private String getSQLWhere(UnionFilter<?> filter) {
		String join = String.join(" or ", filter.getSubFilters().stream()
				.filter(Filter::isActive)
				.map(this::getSQLWhere)
				.collect(Collectors.toList()));
		return "(" + org.apache.commons.lang3.StringUtils.defaultIfBlank(join, getTrueLiteral()) + ")";
	}

	public String getSQLWhere(RootFilter filter) {
		return getSQLWhere((Filter) filter);
	}

	/**
	 * Get the SQL where clause corresponding to the given filter
	 *
	 * Uses instanceof to dispatch to the correct method for each filter type.
	 * NOTE: I don't like this if-else instance of chain, but I can't decide
	 * what to do instead -jm We could move the methods into the filter classes
	 * and use dynamic dispatch.
	 *
	 * @param filter A filter to generate the SQL where clause for,
	 *
	 * @return An SQL where clause (without the "where") corresponding to the
	 *         filter.
	 */
	private String getSQLWhere(Filter filter) {
		String result = "";
		if (filter == null) {
			return getTrueLiteral();
		} else if (filter instanceof DescriptionFilter) {
			result = getSQLWhere((DescriptionFilter) filter);
		} else if (filter instanceof TagsFilter) {
			result = getSQLWhere((TagsFilter) filter);
		} else if (filter instanceof HashHitsFilter) {
			result = getSQLWhere((HashHitsFilter) filter);
		} else if (filter instanceof DataSourceFilter) {
			result = getSQLWhere((DataSourceFilter) filter);
		} else if (filter instanceof DataSourcesFilter) {
			result = getSQLWhere((DataSourcesFilter) filter);
		} else if (filter instanceof HideKnownFilter) {
			result = getSQLWhere((HideKnownFilter) filter);
		} else if (filter instanceof TextFilter) {
			result = getSQLWhere((TextFilter) filter);
		} else if (filter instanceof TypeFilter) {
			result = getSQLWhere((TypeFilter) filter);
		} else if (filter instanceof IntersectionFilter) {
			result = getSQLWhere((IntersectionFilter) filter);
		} else if (filter instanceof UnionFilter) {
			result = getSQLWhere((UnionFilter) filter);
		} else {
			throw new IllegalArgumentException("getSQLWhere not defined for " + filter.getClass().getCanonicalName());
		}
		result = org.apache.commons.lang3.StringUtils.deleteWhitespace(result).equals("(1and1and1)") ? getTrueLiteral() : result; //NON-NLS
		result = org.apache.commons.lang3.StringUtils.deleteWhitespace(result).equals("()") ? getTrueLiteral() : result;
		return result;
	}

	private String getSQLWhere(HideKnownFilter filter) {
		if (filter.isActive()) {
			return "(known_state != " + TskData.FileKnown.KNOWN.getFileKnownValue() + ")"; // NON-NLS
		} else {
			return getTrueLiteral();
		}
	}

	private String getSQLWhere(DescriptionFilter filter) {
		if (filter.isActive()) {
			String likeOrNotLike = (filter.getFilterMode() == DescriptionFilter.FilterMode.INCLUDE ? "" : " NOT") + " LIKE '"; //NON-NLS
			return "(" + getDescriptionColumn(filter.getDescriptionLoD()) + likeOrNotLike + filter.getDescription() + "'  )"; // NON-NLS
		} else {
			return getTrueLiteral();
		}
	}

	private String getSQLWhere(TagsFilter filter) {
		if (false == filter.isActive()
				|| filter.getSubFilters().isEmpty()) {
			return getTrueLiteral();
		} else {
			String tagNameIDs = filter.getSubFilters().stream()
					.filter(tagFilter -> tagFilter.isSelected() && !tagFilter.isDisabled())
					.map(tagNameFilter -> String.valueOf(tagNameFilter.getTagName().getId()))
					.collect(Collectors.joining(", ", "(", ")"));
			return "(events.tag_name_id IN " + tagNameIDs + ") "; //NON-NLS
		}
	}

	private String getSQLWhere(HashHitsFilter filter) {
		if (false == filter.isActive()
				|| filter.getSubFilters().isEmpty()) {
			return getTrueLiteral();
		} else {
			String hashSetNAmes = filter.getSubFilters().stream()
					.filter(hashFilter -> hashFilter.isSelected() && !hashFilter.isDisabled())
					.map(hashFilter -> hashFilter.getHashSetName())
					.collect(Collectors.joining("', '", "('", "')"));
			return "(hash_set_name IN " + hashSetNAmes + " )"; //NON-NLS
		}
	}

	private String getSQLWhere(DataSourceFilter filter) {
		if (filter.isActive()) {
			return "(datasource_id = '" + filter.getDataSourceID() + "')"; //NON-NLS
		} else {
			return getTrueLiteral();
		}
	}

	private String getSQLWhere(DataSourcesFilter filter) {
		return filter.isActive() ? "(datasource_id in (" //NON-NLS
				+ filter.getSubFilters().stream()
						.filter(AbstractFilter::isActive)
						.map((dataSourceFilter) -> String.valueOf(dataSourceFilter.getDataSourceID()))
						.collect(Collectors.joining(", ")) + "))" : getTrueLiteral();
	}

	private String getSQLWhere(TextFilter filter) {
		if (filter.isActive()) {
			if (org.apache.commons.lang3.StringUtils.isBlank(filter.getText())) {
				return getTrueLiteral();
			}
			String strippedFilterText = org.apache.commons.lang3.StringUtils.strip(filter.getText());
			return "((med_description like '%" + strippedFilterText + "%')" //NON-NLS
					+ " or (full_description like '%" + strippedFilterText + "%')" //NON-NLS
					+ " or (short_description like '%" + strippedFilterText + "%'))"; //NON-NLS
		} else {
			return getTrueLiteral();
		}
	}

	/**
	 * generate a sql where clause for the given type filter, while trying to be
	 * as simple as possible to improve performance.
	 *
	 * @param typeFilter
	 *
	 * @return
	 */
	private String getSQLWhere(TypeFilter typeFilter) {
		if (typeFilter.isSelected()) {
			if (typeFilter.getEventType() instanceof RootEventType) {
				if (typeFilter.getSubFilters().stream()
						.allMatch(subFilter -> subFilter.isActive() && subFilter.getSubFilters().stream().allMatch(Filter::isActive))) {
					return getTrueLiteral(); //then collapse clause to true
				}
			}
			return "(sub_type IN (" + org.apache.commons.lang3.StringUtils.join(getActiveSubTypes(typeFilter), ",") + "))"; //NON-NLS
		} else {
			return getFalseLiteral();
		}
	}

	private List<Integer> getActiveSubTypes(TypeFilter filter) {
		if (filter.isActive()) {
			if (filter.getSubFilters().isEmpty()) {
				return Collections.singletonList(RootEventType.allTypes.indexOf(filter.getEventType()));
			} else {
				return filter.getSubFilters().stream().flatMap((Filter t) -> getActiveSubTypes((TypeFilter) t).stream()).collect(Collectors.toList());
			}
		} else {
			return Collections.emptyList();
		}
	}

	/**
	 * get a sqlite strftime format string that will allow us to group by the
	 * requested period size. That is, with all info more granular than that
	 * requested dropped (replaced with zeros).
	 *
	 * @param timeUnit the {@link TimeUnits} instance describing what
	 *                 granularity to build a strftime string for
	 *
	 * @return a String formatted according to the sqlite strftime spec
	 *
	 * @see https://www.sqlite.org/lang_datefunc.html
	 */
	String getStrfTimeFormat(TimeUnits timeUnit) {
		switch (timeUnit) {
			case YEARS:
				return "%Y-01-01T00:00:00"; // NON-NLS
			case MONTHS:
				return "%Y-%m-01T00:00:00"; // NON-NLS
			case DAYS:
				return "%Y-%m-%dT00:00:00"; // NON-NLS
			case HOURS:
				return "%Y-%m-%dT%H:00:00"; // NON-NLS
			case MINUTES:
				return "%Y-%m-%dT%H:%M:00"; // NON-NLS
			case SECONDS:
			default:    //seconds - should never happen
				return "%Y-%m-%dT%H:%M:%S"; // NON-NLS  
			}
	}

	String getPostgresTimeFormat(TimeUnits timeUnit) {
		switch (timeUnit) {
			case YEARS:
				return "YYYY-01-01T00:00:00"; // NON-NLS
			case MONTHS:
				return "YYYY-MM-01T00:00:00"; // NON-NLS
			case DAYS:
				return "YYYY-MM-DDT00:00:00"; // NON-NLS
			case HOURS:
				return "YYYY-MM-DDTHH24:00:00"; // NON-NLS
			case MINUTES:
				return "YYYY-MM-DDTHH24:MI:00"; // NON-NLS
			case SECONDS:
			default:    //seconds - should never happen
				return "YYYY-MM-DDTHH24:MI:SS"; // NON-NLS  
			}
	}

	String getDescriptionColumn(DescriptionLoD lod) {
		switch (lod) {
			case FULL:
				return "full_description"; //NON-NLS
			case MEDIUM:
				return "med_description"; //NON-NLS
			case SHORT:
			default:
				return "short_description"; //NON-NLS
			}
	}

	private String getFalseLiteral() {
		switch (sleuthkitCase.getDatabaseType()) {
			case POSTGRESQL:
				return "FALSE";
			case SQLITE:
				return "0";
			default:
				throw getUnsupportedDBTypeException();
		}
	}

	public String getTrueLiteral() {
		switch (sleuthkitCase.getDatabaseType()) {
			case POSTGRESQL:
				return "TRUE";
			case SQLITE:
				return "1";
			default:
				throw getUnsupportedDBTypeException();
		}
	}

	String csvAggFunction(String args) {
		return csvAggFunction(args, ",");
	}

	String csvAggFunction(String args, String seperator) {
		return csvFunction + "(Cast (" + args + " AS VARCHAR) , '" + seperator + "')";
	}
}
