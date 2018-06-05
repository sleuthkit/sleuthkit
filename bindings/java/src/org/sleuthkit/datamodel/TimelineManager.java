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

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;
import com.google.common.collect.ImmutableList;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import org.apache.commons.lang3.ObjectUtils;
import static org.apache.commons.lang3.StringUtils.defaultString;
import static org.apache.commons.lang3.StringUtils.substringAfter;
import static org.apache.commons.lang3.StringUtils.substringBefore;
import org.joda.time.DateTimeZone;
import org.joda.time.Interval;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_HASHSET_HIT;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_TL_EVENT;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TL_EVENT_TYPE;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import static org.sleuthkit.datamodel.StringUtils.joinAsStrings;
import org.sleuthkit.datamodel.timeline.ArtifactEventType;
import org.sleuthkit.datamodel.timeline.EventType;
import org.sleuthkit.datamodel.timeline.EventTypeZoomLevel;
import org.sleuthkit.datamodel.timeline.TimeUnits;
import org.sleuthkit.datamodel.timeline.TimelineEvent;
import org.sleuthkit.datamodel.timeline.filters.HashHitsFilter;
import org.sleuthkit.datamodel.timeline.filters.RootFilter;
import org.sleuthkit.datamodel.timeline.filters.TagsFilter;

/**
 * Provides access to the Timeline features of SleuthkitCase
 */
public final class TimelineManager {

	private static final Logger logger = Logger.getLogger(TimelineManager.class.getName());

	private final SleuthkitCase sleuthkitCase;
	private final String csvFunction;

	final private BiMap<Long, EventType> eventTypeIDMap = HashBiMap.create();

	TimelineManager(SleuthkitCase tskCase) throws TskCoreException {
		sleuthkitCase = tskCase;
		csvFunction = sleuthkitCase.getDatabaseType() == TskData.DbType.POSTGRESQL ? "string_agg" : "group_concat";
		initializeEventTypes();
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
		boolean needsTags = filter.getTagsFilter().hasSubFilters();
		boolean needsHashSets = filter.getHashHitsFilter().hasSubFilters();
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

	public TimelineEvent getEventById(long eventID) throws TskCoreException {
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
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public List<Long> getEventIDs(Interval timeRange, RootFilter filter) throws TskCoreException {
		Long startTime = timeRange.getStartMillis() / 1000;
		Long endTime = timeRange.getEndMillis() / 1000;

		if (Objects.equals(startTime, endTime)) {
			endTime++; //make sure end is at least 1 millisecond after start
		}

		ArrayList<Long> resultIDs = new ArrayList<>();

		sleuthkitCase.acquireSingleUserCaseReadLock();
		boolean needsTags = filter.getTagsFilter().hasSubFilters();
		boolean needsHashSets = filter.getHashHitsFilter().hasSubFilters();
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
	 * this relies on the fact that no tskObj has ID 0 but 0 is the default
	 * value for the datasource_id column in the events table.
	 *
	 * @return
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public boolean hasNewColumns() throws TskCoreException {
		return hasHashHitColumn() && hasDataSourceIDColumn() && hasTaggedColumn()
				&& getDataSourceIDs().isEmpty() == false;
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
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
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

	private void initializeEventTypes() throws TskCoreException {
		//initialize root and base event types, these are added to the DB in c++ land
		eventTypeIDMap.put(EventType.ROOT_EVEN_TYPE.getTypeID(), EventType.ROOT_EVEN_TYPE);
		eventTypeIDMap.put(EventType.WEB_ACTIVITY.getTypeID(), EventType.WEB_ACTIVITY);
		eventTypeIDMap.put(EventType.MISC_TYPES.getTypeID(), EventType.MISC_TYPES);
		eventTypeIDMap.put(EventType.FILE_SYSTEM.getTypeID(), EventType.FILE_SYSTEM);
		eventTypeIDMap.put(EventType.FILE_ACCESSED.getTypeID(), EventType.FILE_ACCESSED);
		eventTypeIDMap.put(EventType.FILE_CHANGED.getTypeID(), EventType.FILE_CHANGED);
		eventTypeIDMap.put(EventType.FILE_CREATED.getTypeID(), EventType.FILE_CREATED);
		eventTypeIDMap.put(EventType.FILE_MODIFIED.getTypeID(), EventType.FILE_MODIFIED);

		//initialize the other event types that aren't added in c++
		sleuthkitCase.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement statement = con.createStatement();) {

			List<EventType> typesToInitialize = new ArrayList<>();
			typesToInitialize.add(EventType.CUSTOM_TYPES);//Initialize the custom base type
			typesToInitialize.addAll(EventType.getWebActivityTypes());//Initialize the web events
			typesToInitialize.addAll(EventType.getMiscTypes());	//initialize the misc events
			typesToInitialize.add(EventType.OTHER);	//initialize the Other custom type.

			for (EventType type : typesToInitialize) {
				statement.executeUpdate(
						insertOrIgnore(" INTO event_types(event_type_id, display_name, super_type_id) "
								+ "VALUES( "
								+ type.getTypeID() + ", '"
								+ type.getDisplayName() + "',"
								+ type.getBaseType().getTypeID()
								+ ")"));
				eventTypeIDMap.put(type.getTypeID(), type);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to initialize event types.", ex); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Get an EventType object given it's id
	 */
	public Optional<EventType> getEventType(long eventTypeID) {
		return Optional.ofNullable(eventTypeIDMap.get(eventTypeID));
	}

	public ImmutableList<EventType> getEventTypes() {
		return ImmutableList.copyOf(eventTypeIDMap.values());
	}

	private Set<ArtifactEventType> getEventTypesForArtifactType(int artfTypeID) {
		return eventTypeIDMap.values().stream()
				.filter(ArtifactEventType.class::isInstance)
				.map(ArtifactEventType.class::cast)
				.filter(eventType -> eventType.getArtifactTypeID() == artfTypeID)
				.collect(Collectors.toSet());
	}

	private String insertOrIgnore(String query) {
		switch (sleuthkitCase.getDatabaseType()) {
			case POSTGRESQL:
				return " INSERT " + query + " ON CONFLICT DO NOTHING "; //NON-NLS
			case SQLITE:
				return " INSERT OR IGNORE " + query;
			default:
				throw newUnsupportedDBTypeException();
		}
	}

	/**
	 * Enum constants for sql statements. TODO: Inline these away.
	 */
	private enum STATEMENTS {

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
		ArrayList<Long> eventIDs = new ArrayList<>();

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

	void addFileSystemEvents(AbstractFile file) throws TskCoreException {
		//gather time stamps into map
		HashMap<EventType, Long> timeMap = new HashMap<>();
		timeMap.put(EventType.FILE_CREATED, file.getCrtime());
		timeMap.put(EventType.FILE_ACCESSED, file.getAtime());
		timeMap.put(EventType.FILE_CHANGED, file.getCtime());
		timeMap.put(EventType.FILE_MODIFIED, file.getMtime());

		/*
		 * if there are no legitimate ( greater than zero ) time stamps ( eg,
		 * logical/local files) skip the rest of the event generation: this
		 * should result in dropping logical files, since they do not have
		 * legitimate time stamps.
		 */
		if (Collections.max(timeMap.values()) > 0) {
			final String parentPath = file.getParentPath();

			String rootFolder = substringBefore(substringAfter(parentPath, "/"), "/");
			String shortDesc = defaultString(rootFolder);
			shortDesc = shortDesc.endsWith("/") ? shortDesc : shortDesc + "/";
			String medDesc = parentPath;
			String fullDescription = medDesc + file.getName();

			for (Map.Entry<EventType, Long> timeEntry : timeMap.entrySet()) {
				if (timeEntry.getValue() > 0) {
					// if the time is legitimate ( greater than zero ) insert it
					addEvent(timeEntry.getValue(),
							timeEntry.getKey(),
							file.getDataSource().getId(),
							file.getId(),
							null,
							fullDescription,
							medDesc,
							shortDesc,
							file.getKnown(),
							file.getHashSetNames().isEmpty() == false,
							false);
				}
			}
		}
	}

	/**
	 * Add any events that can be created from the given Artifact. If the
	 * artifact is a TSK_EVENT then the TSK_DATETIME, TSK_EVENT_TYPE and
	 * TSK_DESCRIPTION are used to make the event, otherwise each event type is
	 * checked to see if it can automatically create an event from the given
	 * artifact.
	 *
	 * @param artifact The artifact to add events for
	 *
	 * @return A set of added events.
	 *
	 * @throws TskCoreException
	 */
	Set<TimelineEvent> addEventsFromArtifact(BlackboardArtifact artifact) throws TskCoreException {
		Set<TimelineEvent> newEvents = new HashSet<>();

		/*
		 * If the artifact is a TSK_TL_EVENT, use the TSK_TL_EVENT_TYPE
		 * attribute to determine its event type, but give it a generic
		 * description.
		 */
		if (artifact.getArtifactTypeID() == TSK_TL_EVENT.getTypeID()) {
			EventType eventType;//the type of the event to add.
			BlackboardAttribute attribute = artifact.getAttribute(new BlackboardAttribute.Type(TSK_TL_EVENT_TYPE));
			if (attribute == null) {
				eventType = EventType.OTHER;
			} else {
				long eventTypeID = attribute.getValueLong();
				eventType = eventTypeIDMap.get(eventTypeID);
				eventType = ObjectUtils.defaultIfNull(eventType, EventType.OTHER);
			}

			Optional<TimelineEvent> newEvent = addArtifactEvent(EventType.OTHER::buildEventPayload, eventType, artifact);
			newEvent.ifPresent(newEvents::add);

		} else {
			/*
			 * If there are any event types configured to make descriptions
			 * automatically, use those.
			 */
			Set<ArtifactEventType> eventTypesForArtifact = getEventTypesForArtifactType(artifact.getArtifactTypeID());
			for (ArtifactEventType eventType : eventTypesForArtifact) {
				Optional<TimelineEvent> newEvent = addArtifactEvent(eventType, artifact);
				newEvent.ifPresent(newEvents::add);
			}
		}

		return newEvents;
	}

	/**
	 * Add an event of the given type from the given artifact. If the event type
	 * and artifact are not compatible, no event is created.
	 *
	 * @param eventType The event type to create.
	 * @param artifact  The artifact to create the event from.
	 *
	 * @return The created event, wrapped in an Optional, or an empty Optional
	 *         if no event was created, because e.g. the timestamp is 0.
	 *
	 * @throws TskCoreException
	 */
	private Optional<TimelineEvent> addArtifactEvent(ArtifactEventType eventType, BlackboardArtifact artifact) throws TskCoreException {
		return addArtifactEvent(eventType::buildEventPayload, eventType, artifact);
	}

	/**
	 * Add an event of the given type from the given artifact. This version of
	 * addArtifactEvent allows a non standard description for the given event
	 * type.
	 *
	 * @param payloadExtractor A Function that will create the decsription based
	 *                         on the artifact. This allows the description to
	 *                         be built based on an event type (usually OTHER)
	 *                         different to the event type of the event.
	 * @param eventType        The event type to create.
	 * @param artifact         The artifact to create the event from.
	 *
	 * @return The created event, wrapped in an Optional, or an empty Optional
	 *         if no event was created.
	 *
	 * @throws TskCoreException
	 */
	private Optional<TimelineEvent> addArtifactEvent(CheckedFunction<BlackboardArtifact, ArtifactEventType.EventPayload> payloadExtractor,
			EventType eventType, BlackboardArtifact artifact) throws TskCoreException {
		ArtifactEventType.EventPayload eventDescription = payloadExtractor.apply(artifact);

		// if the time is legitimate ( greater than zero ) insert it into the db
		if (eventDescription != null && eventDescription.getTime() > 0) {
			long objectID = artifact.getObjectID();
			AbstractFile file = sleuthkitCase.getAbstractFileById(objectID);
			return Optional.of(addEvent(eventDescription.getTime(),
					eventType,
					file.getDataSource().getId(),
					objectID,
					artifact.getArtifactID(),
					eventDescription.getFullDescription(),
					eventDescription.getMedDescription(),
					eventDescription.getShortDescription(),
					file.getKnown(),
					file.getHashSetNames().isEmpty() == false,
					sleuthkitCase.getBlackboardArtifactTagsByArtifact(artifact).isEmpty() == false));
		}
		return Optional.empty();
	}

	private TimelineEvent addEvent(long time, EventType type, long datasourceID, long objID,
			Long artifactID, String fullDescription, String medDescription,
			String shortDescription, TskData.FileKnown known, boolean hashHit, boolean tagged) throws TskCoreException {

		String sql = "INSERT INTO events ("
				+ " datasource_id, "
				+ " file_id, "
				+ " artifact_id, "
				+ " time, "
				+ " sub_type, "
				+ " base_type, "
				+ " full_description, "
				+ " med_description, "
				+ " short_description, "
				+ " known_state, "
				+ " hash_hit, "
				+ " tagged) "
				+ " VALUES ("
				+ datasourceID + ","
				+ objID + ","
				+ ((artifactID == null) ? "NULL" : artifactID) + ","
				+ time + ","
				+ ((type.getTypeID() == -1) ? "NULL" : type.getTypeID()) + ","
				+ type.getBaseType().getTypeID() + ",'"
				+ SleuthkitCase.escapeSingleQuotes(fullDescription) + "','"
				+ SleuthkitCase.escapeSingleQuotes(medDescription) + "','"
				+ SleuthkitCase.escapeSingleQuotes(shortDescription) + "','"
				+ known.getFileKnownValue() + "',"
				+ (hashHit ? 1 : 0) + ","
				+ (tagged ? 1 : 0) + "  )";// NON-NLS  
		sleuthkitCase.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement insertRowStmt = con.createStatement();) {
			con.executeUpdate(insertRowStmt, sql, PreparedStatement.RETURN_GENERATED_KEYS);
			try (ResultSet generatedKeys = insertRowStmt.getGeneratedKeys();) {
				generatedKeys.next();
				long eventID = generatedKeys.getLong(1);
				TimelineEvent singleEvent = new TimelineEvent(eventID, datasourceID,
						objID, artifactID, time, type, fullDescription, medDescription,
						shortDescription, known, hashHit, tagged);
				sleuthkitCase.postTSKEvent(new EventAddedEvent(singleEvent));
				return singleEvent;
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to insert event.", ex); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseWriteLock();
		}
	}

	private Set<Long> getEventIDs(long objectID, boolean includeArtifacts) throws TskCoreException {
		HashSet<Long> eventIDs = new HashSet<>();
		String sql = "SELECT event_id FROM events WHERE file_id = ? "
				+ (includeArtifacts ? "" : " AND artifact_id IS NULL");
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				PreparedStatement selectStmt = con.prepareStatement(sql, PreparedStatement.NO_GENERATED_KEYS);) {
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
	 * Set any events with the given object and artifact ids as tagged.
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
		Set<Long> eventIDs;
		if (Objects.isNull(artifactID)) {
			eventIDs = getEventIDs(objectID, false);
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

	/**
	 * Set the known_state and hash_hit of the events associated with the given
	 * file, including artifact based events.
	 *
	 * @param file The file.
	 *
	 * @throws TskCoreException if there is a error.
	 */
	public Set<Long> setFileStatus(AbstractFile file) throws TskCoreException {
		Set<Long> eventIDs = getEventIDs(file.getId(), true);
		//update known state for all event with given ids
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement updateStatement = con.createStatement();) {
			updateStatement.executeUpdate(
					"UPDATE events SET known_state = '" + file.getKnown().getFileKnownValue() + "', " //NON-NLS
					+ "                hash_hit = " + (file.getHashSetNames().isEmpty() ? 0 : 1) //NON-NLS
					+ " WHERE event_id IN (" + joinAsStrings(eventIDs, ",") + ")"); //NON-NLS
		} catch (SQLException ex) {
			throw new TskCoreException("Error setting known_state or hash_hit of events.", ex);
		} finally {
			sleuthkitCase.releaseSingleUserCaseWriteLock();
		}
		return eventIDs;
	}

	void rollBackTransaction(SleuthkitCase.CaseDbTransaction trans) throws TskCoreException {
		trans.rollback();
	}

	private TimelineEvent constructTimeLineEvent(ResultSet resultSet) throws SQLException, TskCoreException {
		int typeID = resultSet.getInt("sub_type"); //NON-NLS
		return new TimelineEvent(resultSet.getLong("event_id"), //NON-NLS
				resultSet.getLong("datasource_id"), //NON-NLS
				resultSet.getLong("file_id"), //NON-NLS
				resultSet.getLong("artifact_id"), //NON-NLS
				resultSet.getLong("time"), //NON-NLS
				getEventType(typeID).orElseThrow(() -> newEventTypeMappingException(typeID)), //NON-NLS
				resultSet.getString("full_description"), //NON-NLS
				resultSet.getString("med_description"), //NON-NLS
				resultSet.getString("short_description"), //NON-NLS
				TskData.FileKnown.valueOf(resultSet.getByte("known_state")), //NON-NLS
				resultSet.getInt("hash_hit") != 0, //NON-NLS
				resultSet.getInt("tagged") != 0); //NON-NLS
	}

	private static TskCoreException newEventTypeMappingException(int typeID) {
		return new TskCoreException("Error mapping event type id " + typeID);
	}

	private UnsupportedOperationException newUnsupportedDBTypeException() {
		return new UnsupportedOperationException("Unsupported DB type: " + sleuthkitCase.getDatabaseType().name());
	}

	/**
	 * Count all the events with the given options and return a map organizing
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
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public Map<EventType, Long> countEventsByType(Long startTime, final Long endTime, RootFilter filter, EventTypeZoomLevel zoomLevel) throws TskCoreException {
		long adjustedEndTime = Objects.equals(startTime, endTime) ? endTime + 1 : endTime;
		boolean useSubTypes = EventTypeZoomLevel.SUB_TYPE.equals(zoomLevel);	//do we want the root or subtype column of the databse
		TagsFilter tagsFilter = filter.getTagsFilter();
		boolean needsTags = tagsFilter != null && tagsFilter.hasSubFilters();
		HashHitsFilter hashHitsFilter = filter.getHashHitsFilter();
		boolean needsHashSets = hashHitsFilter != null && hashHitsFilter.hasSubFilters();
		//get some info about the range of dates requested
		String queryString = "SELECT count(DISTINCT events.event_id) AS count, " + typeColumnHelper(useSubTypes) //NON-NLS
				+ " FROM " + getAugmentedEventsTablesSQL(needsTags, needsHashSets)
				+ " WHERE time >= " + startTime + " AND time < " + adjustedEndTime + " AND " + getSQLWhere(filter) // NON-NLS
				+ " GROUP BY " + typeColumnHelper(useSubTypes); // NON-NLS

		sleuthkitCase.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement stmt = con.createStatement();
				ResultSet results = stmt.executeQuery(queryString);) {
			Map<EventType, Long> typeMap = new HashMap<>();
			while (results.next()) {
				int eventTypeID = useSubTypes
						? results.getInt("sub_type") //NON-NLS
						: results.getInt("base_type"); //NON-NLS
				EventType eventType = getEventType(eventTypeID).orElseThrow(()
						-> new TskCoreException("Error mapping event type id " + eventTypeID + " to EventType."));//NON-NLS

				typeMap.put(eventType, results.getLong("count")); // NON-NLS
			}
			return typeMap;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting count of events from db: " + queryString, ex); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get an SQL expression that produces an events table augmented with the
	 * columsn required by the filters. The union of the events table joined to
	 * the content and blackboard artifacts tags tables, if necessary, then
	 * joined to a query that selects hash set hits, if necessary. Other wise
	 * just return "events".
	 *
	 * Omitting details it is: SELECT <all relevant columns> FROM events LEFT
	 * JOIN (events JOIN content_tags UNION ALL events JOIN
	 * blackboard_artifact_tags) left join SELECT <HASH_SET_HITS> from
	 * <Blackboard artifacts and attributes>
	 *
	 * @param needTags     True if the filters require joining to the tags
	 *                     tables.
	 * @param needHashSets True if the filters require joining to the hash set
	 *                     sub query.
	 *
	 * @return An SQL expresion that produces an events table augmented with the
	 *         columns required by the filters.
	 */
	static public String getAugmentedEventsTablesSQL(boolean needTags, boolean needHashSets) {
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
	 * get a format string that will allow us to group by the requested period
	 * size. That is, with all info more granular than that requested dropped
	 * (replaced with zeros).
	 *
	 * @param periodSize tHE TimeUnits instance describing what granularity to
	 *                   build a strftime string for
	 * @param timeZone
	 *
	 * @return a String formatted according to the sqlite strftime spec
	 *
	 * @see https://www.sqlite.org/lang_datefunc.html
	 */
	public String formatTimeFunction(TimeUnits periodSize, DateTimeZone timeZone) {
		switch (sleuthkitCase.getDatabaseType()) {
			case SQLITE:
				String strfTimeFormat = getStrfTimeFormat(periodSize);
				String useLocalTime = timeZone.equals(DateTimeZone.getDefault()) ? ", 'localtime'" : ""; // NON-NLS
				return "strftime('" + strfTimeFormat + "', time , 'unixepoch'" + useLocalTime + ")";
			case POSTGRESQL:
				String formatString = getPostgresTimeFormat(periodSize);
				return "to_char(to_timestamp(time) AT TIME ZONE '" + timeZone.getID() + "', '" + formatString + "')";
			default:
				throw newUnsupportedDBTypeException();
		}
	}

	/**
	 * Get the column name to use depending on if we want base types or subtypes
	 *
	 * @param useSubTypes True to use sub types, false to use base types.
	 *
	 * @return column name to use depending on if we want base types or subtypes
	 */
	public static String typeColumnHelper(final boolean useSubTypes) {
		return useSubTypes ? "sub_type" : "base_type"; //NON-NLS
	}

	/**
	 * Get the SQL where clause corresponding to the given filter
	 *
	 * @param filter A filter to generate the SQL where clause for,
	 *
	 * @return An SQL where clause (without the "where") corresponding to the
	 *         filter.
	 */
	public String getSQLWhere(RootFilter filter) {

		String result;
		if (filter == null) {
			return getTrueLiteral();
		} else {
			result = filter.getSQLWhere(this);
		}

		return result;
	}

	private static String getStrfTimeFormat(TimeUnits timeUnit) {
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

	private static String getPostgresTimeFormat(TimeUnits timeUnit) {
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

	public String getDescriptionColumn(DescriptionLoD lod) {
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

	public String getFalseLiteral() {
		switch (sleuthkitCase.getDatabaseType()) {
			case POSTGRESQL:
				return "FALSE";
			case SQLITE:
				return "0";
			default:
				throw newUnsupportedDBTypeException();
		}
	}

	public String getTrueLiteral() {
		switch (sleuthkitCase.getDatabaseType()) {
			case POSTGRESQL:
				return "TRUE";
			case SQLITE:
				return "1";
			default:
				throw newUnsupportedDBTypeException();
		}
	}

	public String csvAggFunction(String args) {
		return csvAggFunction(args, ",");
	}

	public String csvAggFunction(String args, String seperator) {
		return csvFunction + "(Cast (" + args + " AS VARCHAR) , '" + seperator + "')";

	}

	/**
	 * Event fired by SleuthkitCase to indicate that a event has been added to
	 * the events table.
	 */
	final public class EventAddedEvent {

		private final TimelineEvent singleEvent;

		public TimelineEvent getEvent() {
			return singleEvent;
		}

		EventAddedEvent(TimelineEvent singleEvent) {
			this.singleEvent = singleEvent;
		}
	}

	/**
	 * Functinal interface for a function from I to O that throws
	 * TskCoreException.
	 *
	 * @param <I> Input type.
	 * @param <O> Output type.
	 */
	@FunctionalInterface
	interface CheckedFunction<I, O> {

		O apply(I input) throws TskCoreException;
	}
}
