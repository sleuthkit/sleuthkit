/*
 * Sleuth Kit Data Model
 *
 * Copyright 2013-2019 Basis Technology Corp.
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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
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
import static java.util.Objects.isNull;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import org.joda.time.DateTimeZone;
import org.joda.time.Interval;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_HASHSET_HIT;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_TL_EVENT;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TL_EVENT_TYPE;
import static org.sleuthkit.datamodel.CollectionUtils.isNotEmpty;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import static org.sleuthkit.datamodel.SleuthkitCase.escapeSingleQuotes;
import static org.sleuthkit.datamodel.StringUtils.buildCSVString;
import org.sleuthkit.datamodel.timeline.ArtifactEventType;
import org.sleuthkit.datamodel.timeline.EventType;
import org.sleuthkit.datamodel.timeline.EventTypeZoomLevel;
import org.sleuthkit.datamodel.timeline.TimelineEvent;
import org.sleuthkit.datamodel.timeline.TimelineFilter;

/**
 * Provides access to the Timeline features of SleuthkitCase
 */
public final class TimelineManager {

	private static final Logger logger = Logger.getLogger(TimelineManager.class.getName());

	/**
	 * These event types are added to the DB in c++ land, but still need to be
	 * put in the eventTypeIDMap
	 */
	private static final ImmutableList<EventType> ROOT_BASE_AND_FILESYSTEM_TYPES
			= ImmutableList.of(
					EventType.ROOT_EVENT_TYPE,
					EventType.WEB_ACTIVITY,
					EventType.MISC_TYPES,
					EventType.FILE_SYSTEM,
					EventType.FILE_ACCESSED,
					EventType.FILE_CHANGED,
					EventType.FILE_CREATED,
					EventType.FILE_MODIFIED);

	/**
	 * These event types are predefined but not added to the DB by the C++ code.
	 * They are added by the TimelineManager constructor.
	 */
	private static final ImmutableList<EventType> PREDEFINED_EVENT_TYPES
			= new ImmutableList.Builder<EventType>()
					.add(EventType.CUSTOM_TYPES)
					.addAll(EventType.getWebActivityTypes())
					.addAll(EventType.getMiscTypes())
					.add(EventType.OTHER).build();

	private final SleuthkitCase sleuthkitCase;

	/**
	 * map from event type id to EventType object.
	 */
	private final Map<Long, EventType> eventTypeIDMap = new HashMap<>();

	TimelineManager(SleuthkitCase tskCase) throws TskCoreException {
		sleuthkitCase = tskCase;

		//initialize root and base event types, these are added to the DB in c++ land
		ROOT_BASE_AND_FILESYSTEM_TYPES.forEach(eventType -> eventTypeIDMap.put(eventType.getTypeID(), eventType));

		//initialize the other event types that aren't added in c++
		sleuthkitCase.acquireSingleUserCaseWriteLock();
		try (final CaseDbConnection con = sleuthkitCase.getConnection();
				final Statement statement = con.createStatement()) {
			for (EventType type : PREDEFINED_EVENT_TYPES) {
				con.executeUpdate(statement,
						insertOrIgnore(" INTO tsk_event_types(event_type_id, display_name, super_type_id) "
								+ "VALUES( " + type.getTypeID() + ", '"
								+ escapeSingleQuotes(type.getDisplayName()) + "',"
								+ type.getSuperType().getTypeID()
								+ ")"));
				eventTypeIDMap.put(type.getTypeID(), type);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to initialize event types.", ex); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseWriteLock();
		}
	}

	public SleuthkitCase getSleuthkitCase() {
		return sleuthkitCase;
	}

	public Interval getSpanningInterval(Collection<Long> eventIDs) throws TskCoreException {
		if (eventIDs.isEmpty()) {
			return null;
		}
		final String query = "SELECT Min(time) as minTime, Max(time) as maxTime FROM tsk_events WHERE event_id IN (" + buildCSVString(eventIDs) + ")";
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
	 * @return The total number of events in the database or, -1 if there is an
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
	 * Get a count of tagnames applied to the given event ids as a map from
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
				+ getAugmentedEventsTablesSQL(true, false, false)
				+ " JOIN tag_names ON (tsk_events.tag_name_id = tag_names.tag_name_id ) "
				+ " WHERE event_id IN (" + buildCSVString(eventIDsWithTags) + ") "
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
	public Interval getSpanningInterval(Interval timeRange, TimelineFilter.RootFilter filter, DateTimeZone timeZone) throws TskCoreException {
		long start = timeRange.getStartMillis() / 1000;
		long end = timeRange.getEndMillis() / 1000;
		String sqlWhere = getSQLWhere(filter);
		String augmentedEventsTablesSQL = getAugmentedEventsTablesSQL(filter);
		sleuthkitCase.acquireSingleUserCaseReadLock();
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
		String sql = "SELECT * FROM  " + getAugmentedEventsTablesSQL(false, false, false) + " WHERE event_id = " + eventID;

		sleuthkitCase.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement stmt = con.createStatement();) {
			try (ResultSet results = stmt.executeQuery(sql);) {
				if (results.next()) {
					int typeID = results.getInt("event_type_id");
					EventType type = getEventType(typeID).orElseThrow(() -> newEventTypeMappingException(typeID)); //NON-NLS
					return new TimelineEvent(eventID,
							results.getLong("data_source_obj_id"),
							results.getLong("file_obj_id"),
							results.getLong("artifact_id"),
							results.getLong("time"),
							type, results.getString("full_description"),
							results.getString("med_description"),
							results.getString("short_description"),
							intToBoolean(results.getInt("hash_hit")),
							intToBoolean(results.getInt("tagged")));
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
	public List<Long> getEventIDs(Interval timeRange, TimelineFilter.RootFilter filter) throws TskCoreException {
		Long startTime = timeRange.getStartMillis() / 1000;
		Long endTime = timeRange.getEndMillis() / 1000;

		if (Objects.equals(startTime, endTime)) {
			endTime++; //make sure end is at least 1 millisecond after start
		}

		ArrayList<Long> resultIDs = new ArrayList<>();

		String query = "SELECT tsk_events.event_id AS event_id FROM " + getAugmentedEventsTablesSQL(filter)
				+ " WHERE time >=  " + startTime + " AND time <" + endTime + " AND " + getSQLWhere(filter) + " ORDER BY time ASC"; // NON-NLS
		sleuthkitCase.acquireSingleUserCaseReadLock();
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

	public Set<Long> getDataSourceIDs() throws TskCoreException {
		sleuthkitCase.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement stmt = con.createStatement();
				ResultSet results = stmt.executeQuery(STATEMENTS.GET_DATASOURCE_IDS.getSQL());) {
			HashSet<Long> dataSourceIDs = new HashSet<>();
			while (results.next()) {
				long datasourceID = results.getLong("data_source_obj_id"); //NON-NLS
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

	/**
	 * Get an EventType object given it's ID.
	 *
	 * @param eventTypeID The ID of the event type to get.
	 *
	 * @return An Optional containing the EventType, or an empty Optional if no
	 *         EventType with the given ID was found.
	 */
	public Optional<EventType> getEventType(long eventTypeID) {
		return Optional.ofNullable(eventTypeIDMap.get(eventTypeID));
	}

	/**
	 * Get a list of all the EventTypes.
	 *
	 * @return A list of all the eventTypes.
	 */
	public ImmutableList<EventType> getEventTypes() {
		return ImmutableList.copyOf(eventTypeIDMap.values());
	}

	private String insertOrIgnore(String query) {
		switch (sleuthkitCase.getDatabaseType()) {
			case POSTGRESQL:
				return " INSERT " + query + " ON CONFLICT DO NOTHING "; //NON-NLS
			case SQLITE:
				return " INSERT OR IGNORE " + query;
			default:
				throw new UnsupportedOperationException("Unsupported DB type: " + sleuthkitCase.getDatabaseType().name());
		}
	}

	/**
	 * Enum constants for sql statements. TODO: Inline these away?
	 */
	private enum STATEMENTS {

		GET_DATASOURCE_IDS("SELECT DISTINCT data_source_obj_id FROM tsk_event_descriptions WHERE data_source_obj_id != 0"),// NON-NLS
		GET_MAX_TIME("SELECT Max(time) AS max FROM tsk_events"), // NON-NLS
		GET_MIN_TIME("SELECT Min(time) AS min FROM tsk_events"), // NON-NLS

		/*
		 * This SQL query is really just a select count(*), but that has
		 * performance problems on very large tables unless you include a where
		 * clause see http://stackoverflow.com/a/9338276/4004683 for more.
		 */
		COUNT_ALL_EVENTS("SELECT count(event_id) AS count FROM tsk_events WHERE event_id IS NOT null"); //NON-NLS

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
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public List<Long> getEventIDsForArtifact(BlackboardArtifact artifact) throws TskCoreException {
		ArrayList<Long> eventIDs = new ArrayList<>();

		String query
				= "SELECT event_id FROM tsk_events "
				+ " LEFT JOIN tsk_event_descriptions on ( tsk_events.event_description_id = tsk_event_descriptions.event_description_id ) "
				+ " WHERE artifact_id = " + artifact.getArtifactID();
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
	 * Get a Set of event IDs for the events that are derived from the given
	 * file.
	 *
	 * @param file                    The File / data source to get derived
	 *                                event IDs for.
	 * @param includeDerivedArtifacts If true, also get event IDs for events
	 *                                derived from artifacts derived form this
	 *                                file. If false, only gets events derived
	 *                                directly from this file (file system
	 *                                timestamps).
	 *
	 * @return A Set of event IDs for the events that are derived from the given
	 *         file.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public Set<Long> getEventIDsForFile(Content file, boolean includeDerivedArtifacts) throws TskCoreException {
		return getEventAndDescriptionIDs(file.getId(), includeDerivedArtifacts).keySet();
	}

	/**
	 * Add a row to the tsk_events_description table.
	 *
	 * @param dataSourceObjId
	 * @param fileObjId
	 * @param artifactID
	 * @param fullDescription
	 * @param medDescription
	 * @param shortDescription
	 * @param hasHashHits
	 * @param tagged
	 * @param connection
	 *
	 * @return the event_decription_id of the inserted row.
	 *
	 * @throws TskCoreException
	 */
	private long addEventDescription(long dataSourceObjId, long fileObjId, Long artifactID,
			String fullDescription, String medDescription, String shortDescription,
			boolean hasHashHits, boolean tagged, CaseDbConnection connection) throws TskCoreException {
		String insertDescriptionSql
				= "INSERT INTO tsk_event_descriptions ( "
				+ "data_source_obj_id, file_obj_id, artifact_id,  "
				+ " full_description, med_description, short_description, "
				+ " hash_hit, tagged "
				+ " ) VALUES ("
				+ dataSourceObjId + ","
				+ fileObjId + ","
				+ Objects.toString(artifactID, "NULL") + ","
				+ quotePreservingNull(fullDescription) + ","
				+ quotePreservingNull(medDescription) + ","
				+ quotePreservingNull(shortDescription) + ", "
				+ booleanToInt(hasHashHits) + ","
				+ booleanToInt(tagged)
				+ " )";

		sleuthkitCase.acquireSingleUserCaseWriteLock();
		try (Statement insertDescriptionStmt = connection.createStatement()) {
			connection.executeUpdate(insertDescriptionStmt, insertDescriptionSql, PreparedStatement.RETURN_GENERATED_KEYS);
			try (ResultSet generatedKeys = insertDescriptionStmt.getGeneratedKeys()) {
				generatedKeys.next();
				return generatedKeys.getLong(1);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to insert event description.", ex); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseWriteLock();
		}
	}

	Collection<TimelineEvent> addAbstractFileEvents(AbstractFile file, CaseDbConnection connection) throws TskCoreException {
		//gather time stamps into map
		Map<EventType, Long> timeMap = ImmutableMap.of(
				EventType.FILE_CREATED, file.getCrtime(),
				EventType.FILE_ACCESSED, file.getAtime(),
				EventType.FILE_CHANGED, file.getCtime(),
				EventType.FILE_MODIFIED, file.getMtime());

		/*
		 * If there are no legitimate ( greater than zero ) time stamps ( eg,
		 * logical/local files) skip the rest of the event generation: this
		 * should result in dropping logical files, since they do not have
		 * legitimate time stamps.
		 */
		if (Collections.max(timeMap.values()) <= 0) {
			return Collections.emptySet();
		}

		boolean hashHashHits = CollectionUtils.isNotEmpty(file.getHashSetNames());
		boolean hasTags = CollectionUtils.isNotEmpty(sleuthkitCase.getContentTagsByContent(file));
		String description = file.getParentPath() + file.getName();
		long fileObjId = file.getId();
		Set<TimelineEvent> events = new HashSet<>();
		sleuthkitCase.acquireSingleUserCaseWriteLock();
		try {
			long descriptionID = addEventDescription(file.getDataSourceObjectId(), fileObjId, null,
					description, null, null, false, false, connection);

			for (Map.Entry<EventType, Long> timeEntry : timeMap.entrySet()) {
				Long time = timeEntry.getValue();
				if (time > 0) {// if the time is legitimate ( greater than zero ) insert it
					EventType type = timeEntry.getKey();
					long eventID = addEventWithExistingDescription(time, type, descriptionID, connection);

					events.add(new TimelineEvent(eventID, descriptionID, fileObjId, null, time, type,
							description, null, null, hashHashHits, hasTags));
				}
			}

		} finally {
			sleuthkitCase.releaseSingleUserCaseWriteLock();
		}
		events.stream()
				.map(TimelineEventAddedEvent::new)
				.forEach(sleuthkitCase::fireTSKEvent);

		return events;
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
	Set<TimelineEvent> addArtifactEvents(BlackboardArtifact artifact) throws TskCoreException {
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
				eventType = eventTypeIDMap.getOrDefault(eventTypeID, EventType.OTHER);
			}

			addArtifactEvent(EventType.OTHER::buildEventPayload, eventType, artifact)
					.ifPresent(newEvents::add);

		} else {
			/*
			 * If there are any event types configured to make descriptions
			 * automatically, use those.
			 */
			Set<ArtifactEventType> eventTypesForArtifact = eventTypeIDMap.values().stream()
					.filter(ArtifactEventType.class::isInstance)
					.map(ArtifactEventType.class::cast)
					.filter(eventType -> eventType.getArtifactTypeID() == artifact.getArtifactTypeID())
					.collect(Collectors.toSet());

			for (ArtifactEventType eventType : eventTypesForArtifact) {
				addArtifactEvent(eventType::buildEventPayload, eventType, artifact)
						.ifPresent(newEvents::add);
			}
		}
		newEvents.stream()
				.map(TimelineEventAddedEvent::new)
				.forEach(sleuthkitCase::fireTSKEvent);
		return newEvents;
	}

	/**
	 * Add an event of the given type from the given artifact. By passing the
	 * payloadExtractor, thismethod allows a non standard description for the
	 * given event type.
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
	private Optional<TimelineEvent> addArtifactEvent(TSKCoreCheckedFunction<BlackboardArtifact, ArtifactEventType.EventDescriptionWithTime> payloadExtractor,
			EventType eventType, BlackboardArtifact artifact) throws TskCoreException {
		ArtifactEventType.EventDescriptionWithTime eventPayload = payloadExtractor.apply(artifact);
		if (eventPayload == null) {
			return Optional.empty();
		}
		long time = eventPayload.getTime();
		// if the time is legitimate ( greater than zero ) insert it into the db
		if (time <= 0) {
			return Optional.empty();
		}
		String fullDescription = eventPayload.getFullDescription();
		String medDescription = eventPayload.getMediumDescription();
		String shortDescription = eventPayload.getShortDescription();
		long artifactID = artifact.getArtifactID();
		long fileObjId = artifact.getObjectID();
		long dataSourceObjectID = artifact.getDataSourceObjectID();

		AbstractFile file = sleuthkitCase.getAbstractFileById(fileObjId);
		boolean hasHashHits = false;
		// file will be null if source was data source or some non-file
		if (file != null) {
			hasHashHits = isNotEmpty(file.getHashSetNames());
		}
		boolean tagged = isNotEmpty(sleuthkitCase.getBlackboardArtifactTagsByArtifact(artifact));

		TimelineEvent event;
		sleuthkitCase.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = getSleuthkitCase().getConnection();) {

			long descriptionID = addEventDescription(dataSourceObjectID, fileObjId, artifactID,
					fullDescription, medDescription, shortDescription,
					hasHashHits, tagged, connection);

			long eventID = addEventWithExistingDescription(time, eventType, descriptionID, connection);

			event = new TimelineEvent(eventID, dataSourceObjectID, fileObjId, artifactID,
					time, eventType, fullDescription, medDescription, shortDescription,
					hasHashHits, tagged);

		} finally {
			sleuthkitCase.releaseSingleUserCaseWriteLock();
		}
		return Optional.of(event);
	}

	private long addEventWithExistingDescription(Long time, EventType type, long descriptionID, CaseDbConnection connection) throws TskCoreException {
		String insertEventSql
				= "INSERT INTO tsk_events ( event_type_id, event_description_id , time) "
				+ " VALUES (" + type.getTypeID() + ", " + descriptionID + ", " + time + ")";

		sleuthkitCase.acquireSingleUserCaseWriteLock();
		try (Statement insertRowStmt = connection.createStatement();) {
			connection.executeUpdate(insertRowStmt, insertEventSql, PreparedStatement.RETURN_GENERATED_KEYS);

			try (ResultSet generatedKeys = insertRowStmt.getGeneratedKeys();) {
				generatedKeys.next();
				return generatedKeys.getLong(1);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to insert event for existing description.", ex); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseWriteLock();
		}
	}

	static private String quotePreservingNull(String value) {
		return isNull(value) ? " NULL " : "'" + escapeSingleQuotes(value) + "'";
	}

	/**
	 * Get events that are associated with the file
	 *
	 * @param fileObjID
	 * @param includeArtifacts true if results should also include events from
	 *                         artifacts associated with the file.
	 *
	 * @return A map from event_id to event_decsription_id.
	 *
	 * @throws TskCoreException
	 */
	private Map<Long, Long> getEventAndDescriptionIDs(long fileObjID, boolean includeArtifacts) throws TskCoreException {
		return getEventAndDescriptionIDsHelper(fileObjID, (includeArtifacts ? "" : " AND artifact_id IS NULL"));
	}

	/**
	 * Get events that match both the file and artifact IDs
	 *
	 * @param fileObjID
	 * @param artifactID
	 *
	 * @return A map from event_id to event_decsription_id.
	 *
	 * @throws TskCoreException
	 */
	private Map<Long, Long> getEventAndDescriptionIDs(long fileObjID, Long artifactID) throws TskCoreException {
		return getEventAndDescriptionIDsHelper(fileObjID, " AND artifact_id = " + artifactID);
	}

	/**
	 * Get a map containging event_id and their corresponding
	 * event_description_ids.
	 *
	 * @param fileObjID      get event Ids for events that are derived from the
	 *                       file with this id.
	 * @param artifactClause SQL clause that clients can pass in to filter the
	 *                       returned ids.
	 *
	 * @return A map from event_id to event_decsription_id.
	 *
	 * @throws TskCoreException
	 */
	private Map<Long, Long> getEventAndDescriptionIDsHelper(long fileObjID, String artifactClause) throws TskCoreException {
		//map from event_id to the event_description_id for that event.
		Map<Long, Long> eventIDToDescriptionIDs = new HashMap<>();
		String sql = "SELECT event_id, tsk_events.event_description_id"
				+ " FROM tsk_events "
				+ " LEFT JOIN tsk_event_descriptions ON ( tsk_events.event_description_id = tsk_event_descriptions.event_description_id )"
				+ " WHERE file_obj_id = " + fileObjID
				+ artifactClause;

		sleuthkitCase.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement selectStmt = con.createStatement();
				ResultSet executeQuery = selectStmt.executeQuery(sql);) {
			while (executeQuery.next()) {
				eventIDToDescriptionIDs.put(executeQuery.getLong("event_id"), executeQuery.getLong("event_description_id")); //NON-NLS
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting event description ids for object id = " + fileObjID, ex);
		} finally {
			sleuthkitCase.releaseSingleUserCaseReadLock();
		}
		return eventIDToDescriptionIDs;
	}

	/**
	 * Set any events with the given object and artifact ids as tagged.
	 *
	 * @param fileObjId  the obj_id that this tag applies to, the id of the
	 *                   content that the artifact is derived from for artifact
	 *                   tags
	 * @param artifactID the artifact_id that this tag applies to, or null if
	 *                   this is a content tag
	 * @param tagged     true to mark the matching events tagged, false to mark
	 *                   them as untagged
	 *
	 * @return the event ids that match the object/artifact pair.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public Set<Long> setEventsTagged(long fileObjId, Long artifactID, boolean tagged) throws TskCoreException {
		sleuthkitCase.acquireSingleUserCaseWriteLock();
		Map<Long, Long> eventIDs;  // map from event_ids to event_description_ids
		if (Objects.isNull(artifactID)) {
			eventIDs = getEventAndDescriptionIDs(fileObjId, false);
		} else {
			eventIDs = getEventAndDescriptionIDs(fileObjId, artifactID);
		}

		//update tagged state for all event with selected ids
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement updateStatement = con.createStatement();) {
			updateStatement.executeUpdate("UPDATE tsk_event_descriptions SET tagged = " + booleanToInt(tagged)
					+ " WHERE event_description_id IN (" + buildCSVString(eventIDs.values()) + ")"); //NON-NLS
		} catch (SQLException ex) {
			throw new TskCoreException("Error marking events tagged", ex);
		} finally {
			sleuthkitCase.releaseSingleUserCaseWriteLock();
		}
		return eventIDs.keySet();
	}

	public Set<Long> setEventsHashed(long fileObjdId, boolean hashHits) throws TskCoreException {
		sleuthkitCase.acquireSingleUserCaseWriteLock();
		Map<Long, Long> eventIDs = getEventAndDescriptionIDs(fileObjdId, true);

		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement updateStatement = con.createStatement();) {
			updateStatement.executeUpdate("UPDATE tsk_event_descriptions SET hash_hit = " + booleanToInt(hashHits) //NON-NLS
					+ " WHERE event_description_id IN (" + buildCSVString(eventIDs.values()) + ")"); //NON-NLS
		} catch (SQLException ex) {
			throw new TskCoreException("Error setting hash_hit of events.", ex);
		} finally {
			sleuthkitCase.releaseSingleUserCaseWriteLock();
		}
		return eventIDs.keySet();
	}

	void rollBackTransaction(SleuthkitCase.CaseDbTransaction trans) throws TskCoreException {
		trans.rollback();
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
	public Map<EventType, Long> countEventsByType(Long startTime, final Long endTime, TimelineFilter.RootFilter filter, EventTypeZoomLevel zoomLevel) throws TskCoreException {
		long adjustedEndTime = Objects.equals(startTime, endTime) ? endTime + 1 : endTime;
		//do we want the base or subtype column of the databse
		String typeColumn = typeColumnHelper(EventTypeZoomLevel.SUB_TYPE.equals(zoomLevel));

		String queryString = "SELECT count(DISTINCT tsk_events.event_id) AS count, " + typeColumn
				+ " FROM " + getAugmentedEventsTablesSQL(filter)
				+ " WHERE time >= " + startTime + " AND time < " + adjustedEndTime + " AND " + getSQLWhere(filter) // NON-NLS
				+ " GROUP BY " + typeColumn; // NON-NLS

		sleuthkitCase.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = sleuthkitCase.getConnection();
				Statement stmt = con.createStatement();
				ResultSet results = stmt.executeQuery(queryString);) {
			Map<EventType, Long> typeMap = new HashMap<>();
			while (results.next()) {
				int eventTypeID = results.getInt(typeColumn);
				EventType eventType = getEventType(eventTypeID)
						.orElseThrow(() -> newEventTypeMappingException(eventTypeID));//NON-NLS

				typeMap.put(eventType, results.getLong("count")); // NON-NLS
			}
			return typeMap;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting count of events from db: " + queryString, ex); // NON-NLS
		} finally {
			sleuthkitCase.releaseSingleUserCaseReadLock();
		}
	}

	private static TskCoreException newEventTypeMappingException(int eventTypeID) {
		return new TskCoreException("Error mapping event type id " + eventTypeID + " to EventType.");
	}

	/**
	 * Get an SQL expression that produces an events table augmented with the
	 * columns required by the given filter: The union of the events table
	 * joined to the content and blackboard artifacts tags tables, if necessary,
	 * then joined to a query that selects hash set hits, if necessary. Then
	 * joined to the tsk_files table for mime_types if necessary.
	 *
	 * @param filter The filter that is inspected to determine what
	 *               joins/columns are needed..
	 *
	 * @return An SQL expresion that produces an events table augmented with the
	 *         columns required by the filters.
	 */
	static public String getAugmentedEventsTablesSQL(TimelineFilter.RootFilter filter) {
		TimelineFilter.TagsFilter tagsFilter = filter.getTagsFilter();
		boolean needsTags = tagsFilter != null && tagsFilter.hasSubFilters();

		TimelineFilter.HashHitsFilter hashHitsFilter = filter.getHashHitsFilter();
		boolean needsHashSets = hashHitsFilter != null && hashHitsFilter.hasSubFilters();

		TimelineFilter.FileTypesFilter fileTypesFitler = filter.getFileTypesFilter();
		boolean needsMimeTypes = fileTypesFitler != null && fileTypesFitler.hasSubFilters();

		return getAugmentedEventsTablesSQL(needsTags, needsHashSets, needsMimeTypes);
	}

	/**
	 * Get an SQL expression that produces an events table augmented with the
	 * columns required by the filters: The union of the events table joined to
	 * the content and blackboard artifacts tags tables, if necessary; then
	 * joined to a query that selects hash set hits, if necessary; then joined
	 * to the tsk_files table for mime_types if necessary. If all flags are
	 * false, just return "events".
	 *
	 * @param needTags      True if the Sfilters require joining to the tags
	 *                      tables.
	 * @param needHashSets  True if the filters require joining to the hash set
	 *                      sub query.
	 * @param needMimeTypes True if the filters require joining to the tsk_files
	 *                      table for the mime_type.
	 *
	 * @return An SQL expresion that produces an events table augmented with the
	 *         columns required by the filters.
	 */
	static private String getAugmentedEventsTablesSQL(boolean needTags, boolean needHashSets, boolean needMimeTypes) {
		return "( select event_id, time, tsk_event_descriptions.data_source_obj_id, file_obj_id, artifact_id, "
				+ " full_description, med_description, short_description, tsk_events.event_type_id, super_type_id,"
				+ " hash_hit, tagged "
				+ (needTags ? ", tag_name_id, tag_id" : "")
				+ (needHashSets ? ", hash_set_name" : "")
				+ (needMimeTypes ? ", mime_type" : "")
				+ " FROM tsk_events "
				+ " JOIN tsk_event_descriptions ON ( tsk_event_descriptions.event_description_id = tsk_events.event_description_id)"
				+ " JOIN tsk_event_types ON (tsk_events.event_type_id = tsk_event_types.event_type_id )  "
				+ (needTags
						? ("LEFT OUTER JOIN ("
						+ "		SELECT  event_description_id, tag_name_id, tag_id "
						+ "			FROM tsk_event_descriptions LEFT OUTER JOIN content_tags ON (content_tags.obj_id = tsk_event_descriptions.file_obj_id) "
						+ "	UNION ALL "
						+ "		SELECT  event_description_id,  tag_name_id, tag_id "
						+ "			FROM tsk_event_descriptions LEFT OUTER JOIN blackboard_artifact_tags ON (blackboard_artifact_tags.artifact_id = tsk_event_descriptions.artifact_id)"
						+ " ) AS tsk_event_tags ON (tsk_event_tags.event_description_id = tsk_events.event_description_id)")
						: "")
				+ (needHashSets ? " LEFT OUTER JOIN ( "
						+ "		SELECT DISTINCT value_text AS hash_set_name, obj_id  "
						+ "		FROM blackboard_artifacts"
						+ "		JOIN blackboard_attributes ON (blackboard_artifacts.artifact_id = blackboard_attributes.artifact_id)"
						+ "		JOIN blackboard_artifact_types ON( blackboard_artifacts.artifact_type_id = blackboard_artifact_types.artifact_type_id)"
						+ "		WHERE  blackboard_artifact_types.artifact_type_id = " + TSK_HASHSET_HIT.getTypeID()
						+ "		AND blackboard_attributes.attribute_type_id = " + TSK_SET_NAME.getTypeID() + ") AS hash_set_hits"
						+ "	ON ( tsk_event_descriptions.file_obj_id = hash_set_hits.obj_id)"
						: "")
				+ (needMimeTypes ? " LEFT OUTER JOIN tsk_files "
						+ "	ON (tsk_event_descriptions.file_obj_id = tsk_files.obj_id)"
						: "")
				+ ")  AS tsk_events";
	}

	/**
	 * Convert a boolean to int with the mappings true => 1, false =>0
	 *
	 * @param value the bollean value to convert to an int.
	 *
	 * @return 1 if value is true, 0 if value is false.
	 */
	private static int booleanToInt(boolean value) {
		return value ? 1 : 0;
	}

	private static boolean intToBoolean(int value) {
		return value != 0;
	}

	/**
	 * Get the column name to use depending on if we want base types or subtypes
	 *
	 * @param useSubTypes True to use sub types, false to use base types.
	 *
	 * @return column name to use depending on if we want base types or subtypes
	 */
	public static String typeColumnHelper(final boolean useSubTypes) {
		return useSubTypes ? "event_type_id" : "super_type_id"; //NON-NLS
	}

	/**
	 * Get the SQL where clause corresponding to the given filter
	 *
	 * @param filter A filter to generate the SQL where clause for,
	 *
	 * @return An SQL where clause (without the "where") corresponding to the
	 *         filter.
	 */
	public String getSQLWhere(TimelineFilter.RootFilter filter) {

		String result;
		if (filter == null) {
			return getTrueLiteral();
		} else {
			result = filter.getSQLWhere(this);
		}

		return result;
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

	String getTrueLiteral() {
		switch (sleuthkitCase.getDatabaseType()) {
			case POSTGRESQL:
				return "TRUE";
			case SQLITE:
				return "1";
			default:
				throw new UnsupportedOperationException("Unsupported DB type: " + sleuthkitCase.getDatabaseType().name());

		}
	}

	/**
	 * Event fired by SleuthkitCase to indicate that a event has been added to
	 * the tsk_events table.
	 */
	final static public class TimelineEventAddedEvent {

		private final TimelineEvent addedEvent;

		public TimelineEvent getAddedEvent() {
			return addedEvent;
		}

		TimelineEventAddedEvent(TimelineEvent event) {
			this.addedEvent = event;
		}
	}

	/**
	 * Functional interface for a function from I to O that throws
	 * TskCoreException.
	 *
	 * @param <I> Input type.
	 * @param <O> Output type.
	 */
	@FunctionalInterface
	interface TSKCoreCheckedFunction<I, O> {

		O apply(I input) throws TskCoreException;
	}
}
