/*
 * Sleuth Kit Data Model
 *
 * Copyright 2018-2020 Basis Technology Corp.
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

import com.google.common.annotations.Beta;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.time.Instant;
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
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.joda.time.DateTimeZone;
import org.joda.time.Interval;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_TL_EVENT;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TL_EVENT_TYPE;
import static org.sleuthkit.datamodel.CollectionUtils.isNotEmpty;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import static org.sleuthkit.datamodel.SleuthkitCase.escapeSingleQuotes;
import static org.sleuthkit.datamodel.StringUtils.buildCSVString;

/**
 * Provides access to the timeline data in a case database.
 */
public final class TimelineManager {

	private static final Logger logger = Logger.getLogger(TimelineManager.class.getName());

	/**
	 * Timeline event types added to the case database when it is created.
	 */
	private static final ImmutableList<TimelineEventType> ROOT_CATEGORY_AND_FILESYSTEM_TYPES
			= ImmutableList.of(
					TimelineEventType.ROOT_EVENT_TYPE,
					TimelineEventType.WEB_ACTIVITY,
					TimelineEventType.MISC_TYPES,
					TimelineEventType.FILE_SYSTEM,
					TimelineEventType.FILE_ACCESSED,
					TimelineEventType.FILE_CHANGED,
					TimelineEventType.FILE_CREATED,
					TimelineEventType.FILE_MODIFIED);

	/**
	 * Timeline event types added to the case database by the TimelineManager
	 * constructor. Adding these types at runtime permits new child types of the
	 * category types to be defined without modifying the table creation and
	 * population code in the Sleuth Kit.
	 */
	private static final ImmutableList<TimelineEventType> PREDEFINED_EVENT_TYPES
			= new ImmutableList.Builder<TimelineEventType>()
					.add(TimelineEventType.CUSTOM_TYPES)
					.addAll(TimelineEventType.WEB_ACTIVITY.getChildren())
					.addAll(TimelineEventType.MISC_TYPES.getChildren())
					.addAll(TimelineEventType.CUSTOM_TYPES.getChildren())
					.build();

	// all known artifact type ids (used for determining if an artifact is standard or custom event)
	private static final Set<Integer> ARTIFACT_TYPE_IDS = Stream.of(BlackboardArtifact.ARTIFACT_TYPE.values())
			.map(artType -> artType.getTypeID())
			.collect(Collectors.toSet());

	private final SleuthkitCase caseDB;

	/**
	 * Maximum timestamp to look to in future. Twelve (12) years from current
	 * date.
	 */
	private static final Long MAX_TIMESTAMP_TO_ADD = Instant.now().getEpochSecond() + 394200000;

	/**
	 * Mapping of timeline event type IDs to TimelineEventType objects.
	 */
	private final Map<Long, TimelineEventType> eventTypeIDMap = new HashMap<>();

	/**
	 * Constructs a timeline manager that provides access to the timeline data
	 * in a case database.
	 *
	 * @param caseDB The case database.
	 *
	 * @throws TskCoreException If there is an error constructing the timeline
	 *                          manager.
	 */
	TimelineManager(SleuthkitCase caseDB) throws TskCoreException {
		this.caseDB = caseDB;

		//initialize root and base event types, these are added to the DB in c++ land
		ROOT_CATEGORY_AND_FILESYSTEM_TYPES.forEach(eventType -> eventTypeIDMap.put(eventType.getTypeID(), eventType));

		//initialize the other event types that aren't added in c++
		caseDB.acquireSingleUserCaseWriteLock();
		try (final CaseDbConnection con = caseDB.getConnection();
				final Statement statement = con.createStatement()) {
			for (TimelineEventType type : PREDEFINED_EVENT_TYPES) {
				con.executeUpdate(statement,
						insertOrIgnore(" INTO tsk_event_types(event_type_id, display_name, super_type_id) "
								+ "VALUES( " + type.getTypeID() + ", '"
								+ escapeSingleQuotes(type.getDisplayName()) + "',"
								+ type.getParent().getTypeID()
								+ ")")); //NON-NLS
				eventTypeIDMap.put(type.getTypeID(), type);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to initialize timeline event types", ex); // NON-NLS
		} finally {
			caseDB.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Gets the smallest possible time interval that spans a collection of
	 * timeline events.
	 *
	 * @param eventIDs The event IDs of the events for which to obtain the
	 *                 spanning interval.
	 *
	 * @return The minimal spanning interval, may be null.
	 *
	 * @throws TskCoreException If there is an error querying the case database.
	 */
	public Interval getSpanningInterval(Collection<Long> eventIDs) throws TskCoreException {
		if (eventIDs.isEmpty()) {
			return null;
		}
		final String query = "SELECT Min(time) as minTime, Max(time) as maxTime FROM tsk_events WHERE event_id IN (" + buildCSVString(eventIDs) + ")"; //NON-NLS
		caseDB.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = caseDB.getConnection();
				Statement stmt = con.createStatement();
				ResultSet results = stmt.executeQuery(query);) {
			if (results.next()) {
				return new Interval(results.getLong("minTime") * 1000, (results.getLong("maxTime") + 1) * 1000, DateTimeZone.UTC); // NON-NLS
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error executing get spanning interval query: " + query, ex); // NON-NLS
		} finally {
			caseDB.releaseSingleUserCaseReadLock();
		}
		return null;
	}

	/**
	 * Gets the smallest possible time interval that spans a collection of
	 * timeline events.
	 *
	 * @param timeRange A time range that the events must be within.
	 * @param filter    A timeline events filter that the events must pass.
	 * @param timeZone  The time zone for the returned time interval.
	 *
	 * @return The minimal spanning interval, may be null.
	 *
	 * @throws TskCoreException If there is an error querying the case database.
	 */
	public Interval getSpanningInterval(Interval timeRange, TimelineFilter.RootFilter filter, DateTimeZone timeZone) throws TskCoreException {
		long start = timeRange.getStartMillis() / 1000;
		long end = timeRange.getEndMillis() / 1000;
		String sqlWhere = getSQLWhere(filter);
		String augmentedEventsTablesSQL = getAugmentedEventsTablesSQL(filter);
		String queryString = " SELECT (SELECT Max(time) FROM " + augmentedEventsTablesSQL
				+ "			 WHERE time <=" + start + " AND " + sqlWhere + ") AS start,"
				+ "		 (SELECT Min(time)  FROM " + augmentedEventsTablesSQL
				+ "			 WHERE time >= " + end + " AND " + sqlWhere + ") AS end";//NON-NLS
		caseDB.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = caseDB.getConnection();
				Statement stmt = con.createStatement(); //can't use prepared statement because of complex where clause
				ResultSet results = stmt.executeQuery(queryString);) {

			if (results.next()) {
				long start2 = results.getLong("start"); // NON-NLS
				long end2 = results.getLong("end"); // NON-NLS

				if (end2 == 0) {
					end2 = getMaxEventTime();
				}
				return new Interval(start2 * 1000, (end2 + 1) * 1000, timeZone);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to get MIN time.", ex); // NON-NLS
		} finally {
			caseDB.releaseSingleUserCaseReadLock();
		}
		return null;
	}

	/**
	 * Gets the timeline event with a given event ID.
	 *
	 * @param eventID An event ID.
	 *
	 * @return The timeline event, may be null.
	 *
	 * @throws TskCoreException If there is an error querying the case database.
	 */
	public TimelineEvent getEventById(long eventID) throws TskCoreException {
		String sql = "SELECT * FROM  " + getAugmentedEventsTablesSQL(false) + " WHERE event_id = " + eventID;
		caseDB.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = caseDB.getConnection();
				Statement stmt = con.createStatement();) {
			try (ResultSet results = stmt.executeQuery(sql);) {
				if (results.next()) {
					int typeID = results.getInt("event_type_id");
					TimelineEventType type = getEventType(typeID).orElseThrow(() -> newEventTypeMappingException(typeID)); //NON-NLS
					return new TimelineEvent(eventID,
							results.getLong("data_source_obj_id"),
							results.getLong("content_obj_id"),
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
			throw new TskCoreException("Error while executing query " + sql, sqlEx); // NON-NLS
		} finally {
			caseDB.releaseSingleUserCaseReadLock();
		}
		return null;
	}

	/**
	 * Gets the event IDs of the timeline events within a given time range that
	 * pass a given timeline events filter.
	 *
	 * @param timeRange The time range that the events must be within.
	 * @param filter    The timeline events filter that the events must pass.
	 *
	 * @return A list of event IDs ordered by event time.
	 *
	 * @throws TskCoreException If there is an error querying the case database.
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
		caseDB.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = caseDB.getConnection();
				Statement stmt = con.createStatement();
				ResultSet results = stmt.executeQuery(query);) {
			while (results.next()) {
				resultIDs.add(results.getLong("event_id")); //NON-NLS
			}

		} catch (SQLException sqlEx) {
			throw new TskCoreException("Error while executing query " + query, sqlEx); // NON-NLS
		} finally {
			caseDB.releaseSingleUserCaseReadLock();
		}

		return resultIDs;
	}

	/**
	 * Gets the maximum timeline event time in the case database.
	 *
	 * @return The maximum timeline event time in seconds since the UNIX epoch,
	 *         or -1 if there are no timeline events in the case database.
	 *
	 * @throws TskCoreException If there is an error querying the case database.
	 */
	public Long getMaxEventTime() throws TskCoreException {
		caseDB.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = caseDB.getConnection();
				Statement stms = con.createStatement();
				ResultSet results = stms.executeQuery(STATEMENTS.GET_MAX_TIME.getSQL());) {
			if (results.next()) {
				return results.getLong("max"); // NON-NLS
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error while executing query " + STATEMENTS.GET_MAX_TIME.getSQL(), ex); // NON-NLS
		} finally {
			caseDB.releaseSingleUserCaseReadLock();
		}
		return -1l;
	}

	/**
	 * Gets the minimum timeline event time in the case database.
	 *
	 * @return The minimum timeline event time in seconds since the UNIX epoch,
	 *         or -1 if there are no timeline events in the case database.
	 *
	 * @throws TskCoreException If there is an error querying the case database.
	 */
	public Long getMinEventTime() throws TskCoreException {
		caseDB.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = caseDB.getConnection();
				Statement stms = con.createStatement();
				ResultSet results = stms.executeQuery(STATEMENTS.GET_MIN_TIME.getSQL());) {
			if (results.next()) {
				return results.getLong("min"); // NON-NLS
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error while executing query " + STATEMENTS.GET_MAX_TIME.getSQL(), ex); // NON-NLS
		} finally {
			caseDB.releaseSingleUserCaseReadLock();
		}
		return -1l;
	}

	/**
	 * Gets the timeline event type with a given event type ID.
	 *
	 * @param eventTypeID An event type ID.
	 *
	 * @return The timeline event type in an Optional object, may be empty if
	 *         the event type is not found.
	 */
	public Optional<TimelineEventType> getEventType(long eventTypeID) {
		return Optional.ofNullable(eventTypeIDMap.get(eventTypeID));
	}

	/**
	 * Gets all of the timeline event types in the case database.
	 *
	 * @return A list of timeline event types.
	 */
	public ImmutableList<TimelineEventType> getEventTypes() {
		return ImmutableList.copyOf(eventTypeIDMap.values());
	}

	private String insertOrIgnore(String query) {
		switch (caseDB.getDatabaseType()) {
			case POSTGRESQL:
				return " INSERT " + query + " ON CONFLICT DO NOTHING "; //NON-NLS
			case SQLITE:
				return " INSERT OR IGNORE " + query; //NON-NLS
			default:
				throw new UnsupportedOperationException("Unsupported DB type: " + caseDB.getDatabaseType().name());
		}
	}

	/**
	 * Enum constants for sql statements. TODO: Inline these away?
	 */
	private enum STATEMENTS {

		GET_MAX_TIME("SELECT Max(time) AS max FROM tsk_events"), // NON-NLS
		GET_MIN_TIME("SELECT Min(time) AS min FROM tsk_events"); // NON-NLS

		private final String sql;

		private STATEMENTS(String sql) {
			this.sql = sql;
		}

		String getSQL() {
			return sql;
		}
	}

	/**
	 * Gets a list of event IDs for the timeline events that have a given
	 * artifact as the event source.
	 *
	 * @param artifact An artifact.
	 *
	 * @return The list of event IDs.
	 *
	 * @throws TskCoreException If there is an error querying the case database.
	 */
	public List<Long> getEventIDsForArtifact(BlackboardArtifact artifact) throws TskCoreException {
		ArrayList<Long> eventIDs = new ArrayList<>();

		String query
				= "SELECT event_id FROM tsk_events "
				+ " LEFT JOIN tsk_event_descriptions on ( tsk_events.event_description_id = tsk_event_descriptions.event_description_id ) "
				+ " WHERE artifact_id = " + artifact.getArtifactID();
		caseDB.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = caseDB.getConnection();
				Statement stmt = con.createStatement();
				ResultSet results = stmt.executeQuery(query);) {
			while (results.next()) {
				eventIDs.add(results.getLong("event_id"));//NON-NLS
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error executing getEventIDsForArtifact query.", ex); // NON-NLS
		} finally {
			caseDB.releaseSingleUserCaseReadLock();
		}
		return eventIDs;
	}

	/**
	 * Gets a list of event IDs for the timeline events that have a given
	 * content as the event source.
	 *
	 * @param content                 The content.
	 * @param includeDerivedArtifacts If true, also get event IDs for events
	 *                                where the event source is an artifact that
	 *                                has the given content as its source.
	 *
	 * @return The list of event IDs.
	 *
	 * @throws TskCoreException If there is an error querying the case database.
	 */
	public Set<Long> getEventIDsForContent(Content content, boolean includeDerivedArtifacts) throws TskCoreException {
		caseDB.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection conn = caseDB.getConnection()) {
			return getEventAndDescriptionIDs(conn, content.getId(), includeDerivedArtifacts).keySet();
		} finally {
			caseDB.releaseSingleUserCaseWriteLock();
		}
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
	 * @throws DuplicateException
	 */
	private long addEventDescription(long dataSourceObjId, long fileObjId, Long artifactID,
			String fullDescription, String medDescription, String shortDescription,
			boolean hasHashHits, boolean tagged, CaseDbConnection connection) throws TskCoreException, DuplicateException {
		String tableValuesClause
				= "tsk_event_descriptions ( "
				+ "data_source_obj_id, content_obj_id, artifact_id,  "
				+ " full_description, med_description, short_description, "
				+ " hash_hit, tagged "
				+ " ) VALUES "
				+ "(?, ?, ?, ?, ?, ?, ?, ?)";

		String insertDescriptionSql = getSqlIgnoreConflict(tableValuesClause);

		caseDB.acquireSingleUserCaseWriteLock();
		try (PreparedStatement insertDescriptionStmt = connection.prepareStatement(insertDescriptionSql, PreparedStatement.RETURN_GENERATED_KEYS)) {
			insertDescriptionStmt.clearParameters();
			insertDescriptionStmt.setLong(1, dataSourceObjId);
			insertDescriptionStmt.setLong(2, fileObjId);

			if (artifactID == null) {
				insertDescriptionStmt.setNull(3, Types.INTEGER);
			} else {
				insertDescriptionStmt.setLong(3, artifactID);
			}

			insertDescriptionStmt.setString(4, fullDescription);
			insertDescriptionStmt.setString(5, medDescription);
			insertDescriptionStmt.setString(6, shortDescription);
			insertDescriptionStmt.setInt(7, booleanToInt(hasHashHits));
			insertDescriptionStmt.setInt(8, booleanToInt(tagged));
			int row = insertDescriptionStmt.executeUpdate();
			// if no inserted rows, there is a conflict due to a duplicate event 
			// description.  If that happens, return null as no id was inserted.
			if (row < 1) {
				throw new DuplicateException(String.format(
						"An event description already exists for [fullDescription: %s, contentId: %d, artifactId: %s]",
						fullDescription == null ? "<null>" : fullDescription,
						fileObjId,
						artifactID == null ? "<null>" : Long.toString(artifactID)));
			}

			try (ResultSet generatedKeys = insertDescriptionStmt.getGeneratedKeys()) {
				if (generatedKeys.next()) {
					return generatedKeys.getLong(1);
				} else {
					throw new DuplicateException(String.format(
							"An event description already exists for [fullDescription: %s, contentId: %d, artifactId: %s]",
							fullDescription == null ? "<null>" : fullDescription,
							fileObjId,
							artifactID == null ? "<null>" : Long.toString(artifactID)));
				}
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to insert event description.", ex); // NON-NLS
		} finally {
			caseDB.releaseSingleUserCaseWriteLock();
		}
	}

	Collection<TimelineEvent> addEventsForNewFile(AbstractFile file, CaseDbConnection connection) throws TskCoreException {
		Set<TimelineEvent> events = addEventsForNewFileQuiet(file, connection);
		events.stream()
				.map(TimelineEventAddedEvent::new)
				.forEach(caseDB::fireTSKEvent);

		return events;
	}

	/**
	 * Adds timeline events for the new file to the database. Does not fire
	 * TSKEvents for each addition. This method should only be used if an update
	 * event will be sent later. For example, a data source processor may send
	 * out a single event that a data source has been added rather than an event
	 * for each timeline event.
	 *
	 * @param file       The new file
	 * @param connection Database connection to use
	 *
	 * @return Set of new events
	 *
	 * @throws TskCoreException
	 */
	Set<TimelineEvent> addEventsForNewFileQuiet(AbstractFile file, CaseDbConnection connection) throws TskCoreException {
		//gather time stamps into map
		Map<TimelineEventType, Long> timeMap = ImmutableMap.of(TimelineEventType.FILE_CREATED, file.getCrtime(),
				TimelineEventType.FILE_ACCESSED, file.getAtime(),
				TimelineEventType.FILE_CHANGED, file.getCtime(),
				TimelineEventType.FILE_MODIFIED, file.getMtime());

		/*
		 * If there are no legitimate ( greater than zero ) time stamps skip the
		 * rest of the event generation.
		 */
		if (Collections.max(timeMap.values()) <= 0) {
			return Collections.emptySet();
		}

		String description = file.getParentPath() + file.getName();
		long fileObjId = file.getId();
		Set<TimelineEvent> events = new HashSet<>();
		caseDB.acquireSingleUserCaseWriteLock();
		try {
			long descriptionID = addEventDescription(file.getDataSourceObjectId(), fileObjId, null,
					description, null, null, false, false, connection);

			for (Map.Entry<TimelineEventType, Long> timeEntry : timeMap.entrySet()) {
				Long time = timeEntry.getValue();
				if (time > 0 && time < MAX_TIMESTAMP_TO_ADD) {// if the time is legitimate ( greater than zero and less then 12 years from current date) insert it
					TimelineEventType type = timeEntry.getKey();
					long eventID = addEventWithExistingDescription(time, type, descriptionID, connection);

					/*
					 * Last two flags indicating hasTags and hasHashHits are
					 * both set to false with the assumption that this is not
					 * possible for a new file. See JIRA-5407
					 */
					events.add(new TimelineEvent(eventID, descriptionID, fileObjId, null, time, type,
							description, null, null, false, false));
				} else {
					if (time >= MAX_TIMESTAMP_TO_ADD) {
						logger.log(Level.WARNING, String.format("Date/Time discarded from Timeline for %s for file %s with Id %d", timeEntry.getKey().getDisplayName(), file.getParentPath() + file.getName(), file.getId()));
					}
				}
			}
		} catch (DuplicateException dupEx) {
			logger.log(Level.SEVERE, "Attempt to make file event duplicate.", dupEx);
		} finally {
			caseDB.releaseSingleUserCaseWriteLock();
		}

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
			TimelineEventType eventType;//the type of the event to add.
			BlackboardAttribute attribute = artifact.getAttribute(new BlackboardAttribute.Type(TSK_TL_EVENT_TYPE));
			if (attribute == null) {
				eventType = TimelineEventType.OTHER;
			} else {
				long eventTypeID = attribute.getValueLong();
				eventType = eventTypeIDMap.getOrDefault(eventTypeID, TimelineEventType.OTHER);
			}

			try {
				// @@@ This casting is risky if we change class hierarchy, but was expedient.  Should move parsing to another class
				addArtifactEvent(((TimelineEventArtifactTypeImpl) TimelineEventType.OTHER).makeEventDescription(artifact), eventType, artifact)
						.ifPresent(newEvents::add);
			} catch (DuplicateException ex) {
				logger.log(Level.SEVERE, getDuplicateExceptionMessage(artifact, "Attempt to make a timeline event artifact duplicate"), ex);
			}
		} else {
			/*
			 * If there are any event types configured to make descriptions
			 * automatically, use those.
			 */
			Set<TimelineEventArtifactTypeImpl> eventTypesForArtifact = eventTypeIDMap.values().stream()
					.filter(TimelineEventArtifactTypeImpl.class::isInstance)
					.map(TimelineEventArtifactTypeImpl.class::cast)
					.filter(eventType -> eventType.getArtifactTypeID() == artifact.getArtifactTypeID())
					.collect(Collectors.toSet());

			boolean duplicateExists = false;
			for (TimelineEventArtifactTypeImpl eventType : eventTypesForArtifact) {
				try {
					addArtifactEvent(eventType.makeEventDescription(artifact), eventType, artifact)
							.ifPresent(newEvents::add);
				} catch (DuplicateException ex) {
					duplicateExists = true;
					logger.log(Level.SEVERE, getDuplicateExceptionMessage(artifact, "Attempt to make artifact event duplicate"), ex);
				}
			}

			// if no other timeline events were created directly, then create new 'other' ones.
			if (!duplicateExists && newEvents.isEmpty()) {
				try {
					addOtherEventDesc(artifact).ifPresent(newEvents::add);
				} catch (DuplicateException ex) {
					logger.log(Level.SEVERE, getDuplicateExceptionMessage(artifact, "Attempt to make 'other' artifact event duplicate"), ex);
				}
			}
		}
		newEvents.stream()
				.map(TimelineEventAddedEvent::new)
				.forEach(caseDB::fireTSKEvent);
		return newEvents;
	}

	/**
	 * Formats a message to be displayed in response to a duplicate exception.
	 *
	 * @param artifact The artifact that caused the exception.
	 * @param error    The error message to be displayed in the core of the
	 *                 message.
	 *
	 * @return A formatted message (i.e.
	 *         "[org.sleuthkit.datamodel.TimelineManager]: Attempt to make
	 *         'other' artifact event duplicate (artifactID=12345, Source=Recent
	 *         Activity).")
	 */
	private String getDuplicateExceptionMessage(BlackboardArtifact artifact, String error) {
		String artifactIDStr = null;
		String sourceStr = null;

		if (artifact != null) {
			artifactIDStr = Long.toString(artifact.getId());

			try {
				sourceStr = artifact.getAttributes().stream()
					.filter(attr -> attr != null && attr.getSources() != null && !attr.getSources().isEmpty())
					.map(attr -> String.join(",", attr.getSources()))
					.findFirst()
					.orElse(null);
			} catch (TskCoreException ex) {
				logger.log(Level.WARNING, String.format("Could not fetch artifacts for artifact id: %d.", artifact.getId()), ex);
			}
		}

		artifactIDStr = (artifactIDStr == null) ? "<null>" : artifactIDStr;
		sourceStr = (sourceStr == null) ? "<null>" : sourceStr;

		return String.format("%s (artifactID=%s, Source=%s).", error, artifactIDStr, sourceStr);
	}

	/**
	 * Adds 'other' type events for artifacts that have no corresponding
	 * TimelineEventType.
	 *
	 * @param artifact The artifact for which to add a new timeline event.
	 *
	 * @return An optional of a new timeline event or empty if no time attribute
	 *         can be determined or the artifact is null.
	 *
	 * @throws TskCoreException
	 */
	private Optional<TimelineEvent> addOtherEventDesc(BlackboardArtifact artifact) throws TskCoreException, DuplicateException {
		if (artifact == null) {
			return Optional.empty();
		}

		Long timeVal = artifact.getAttributes().stream()
				.filter((attr) -> attr.getAttributeType().getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME)
				.map(attr -> attr.getValueLong())
				.findFirst()
				.orElse(null);

		if (timeVal == null) {
			return Optional.empty();
		}

		String description = String.format("%s: %d", artifact.getDisplayName(), artifact.getId());

		TimelineEventDescriptionWithTime evtWDesc = new TimelineEventDescriptionWithTime(timeVal, description, description, description);

		TimelineEventType evtType = (ARTIFACT_TYPE_IDS.contains(artifact.getArtifactTypeID()))
				? TimelineEventType.OTHER
				: TimelineEventType.USER_CREATED;

		return addArtifactEvent(evtWDesc, evtType, artifact);
	}

	/**
	 * Add an event of the given type from the given artifact to the database.
	 *
	 * @param eventPayload A description for this artifact including the time.
	 * @param eventType    The event type to create.
	 * @param artifact     The artifact to create the event from.
	 *
	 * @return The created event, wrapped in an Optional, or an empty Optional
	 *         if no event was created.
	 *
	 * @throws TskCoreException
	 * @throws DuplicateException
	 */
	private Optional<TimelineEvent> addArtifactEvent(TimelineEventDescriptionWithTime eventPayload,
			TimelineEventType eventType, BlackboardArtifact artifact) throws TskCoreException, DuplicateException {

		if (eventPayload == null) {
			return Optional.empty();
		}
		long time = eventPayload.getTime();
		// if the time is legitimate ( greater than or equal to zero or less than or equal to 12 years from present time) insert it into the db
		if (time <= 0 || time >= MAX_TIMESTAMP_TO_ADD) {
			if (time >= MAX_TIMESTAMP_TO_ADD) {
				logger.log(Level.WARNING, String.format("Date/Time discarded from Timeline for %s for artifact %s with id %d", artifact.getDisplayName(), eventPayload.getDescription(TimelineLevelOfDetail.HIGH), artifact.getId()));
			}
			return Optional.empty();
		}
		String fullDescription = eventPayload.getDescription(TimelineLevelOfDetail.HIGH);
		String medDescription = eventPayload.getDescription(TimelineLevelOfDetail.MEDIUM);
		String shortDescription = eventPayload.getDescription(TimelineLevelOfDetail.LOW);
		long artifactID = artifact.getArtifactID();
		long fileObjId = artifact.getObjectID();
		long dataSourceObjectID = artifact.getDataSourceObjectID();

		AbstractFile file = caseDB.getAbstractFileById(fileObjId);
		boolean hasHashHits = false;
		// file will be null if source was data source or some non-file
		if (file != null) {
			hasHashHits = isNotEmpty(file.getHashSetNames());
		}
		boolean tagged = isNotEmpty(caseDB.getBlackboardArtifactTagsByArtifact(artifact));

		TimelineEvent event;
		caseDB.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = caseDB.getConnection();) {

			long descriptionID = addEventDescription(dataSourceObjectID, fileObjId, artifactID,
					fullDescription, medDescription, shortDescription,
					hasHashHits, tagged, connection);

			long eventID = addEventWithExistingDescription(time, eventType, descriptionID, connection);

			event = new TimelineEvent(eventID, dataSourceObjectID, fileObjId, artifactID,
					time, eventType, fullDescription, medDescription, shortDescription,
					hasHashHits, tagged);

		} finally {
			caseDB.releaseSingleUserCaseWriteLock();
		}
		return Optional.of(event);
	}

	private long addEventWithExistingDescription(Long time, TimelineEventType type, long descriptionID, CaseDbConnection connection) throws TskCoreException, DuplicateException {
		String tableValuesClause
				= "tsk_events ( event_type_id, event_description_id , time) VALUES (?, ?, ?)";

		String insertEventSql = getSqlIgnoreConflict(tableValuesClause);

		caseDB.acquireSingleUserCaseWriteLock();
		try (PreparedStatement insertRowStmt = connection.prepareStatement(insertEventSql, Statement.RETURN_GENERATED_KEYS);) {
			insertRowStmt.clearParameters();
			insertRowStmt.setLong(1, type.getTypeID());
			insertRowStmt.setLong(2, descriptionID);
			insertRowStmt.setLong(3, time);
			int row = insertRowStmt.executeUpdate();
			// if no inserted rows, return null.
			if (row < 1) {
				throw new DuplicateException(String.format("An event already exists in the event table for this item [time: %s, type: %s, description: %d].",
						time == null ? "<null>" : Long.toString(time),
						type == null ? "<null>" : type.toString(),
						descriptionID));
			}

			try (ResultSet generatedKeys = insertRowStmt.getGeneratedKeys();) {
				if (generatedKeys.next()) {
					return generatedKeys.getLong(1);
				} else {
					throw new DuplicateException(String.format("An event already exists in the event table for this item [time: %s, type: %s, description: %d].",
							time == null ? "<null>" : Long.toString(time),
							type == null ? "<null>" : type.toString(),
							descriptionID));
				}
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to insert event for existing description.", ex); // NON-NLS
		} finally {
			caseDB.releaseSingleUserCaseWriteLock();
		}
	}

	private Map<Long, Long> getEventAndDescriptionIDs(CaseDbConnection conn, long contentObjID, boolean includeArtifacts) throws TskCoreException {
		return getEventAndDescriptionIDsHelper(conn, contentObjID, (includeArtifacts ? "" : " AND artifact_id IS NULL"));
	}

	private Map<Long, Long> getEventAndDescriptionIDs(CaseDbConnection conn, long contentObjID, Long artifactID) throws TskCoreException {
		return getEventAndDescriptionIDsHelper(conn, contentObjID, " AND artifact_id = " + artifactID);
	}

	private Map<Long, Long> getEventAndDescriptionIDsHelper(CaseDbConnection con, long fileObjID, String artifactClause) throws TskCoreException {
		//map from event_id to the event_description_id for that event.
		Map<Long, Long> eventIDToDescriptionIDs = new HashMap<>();
		String sql = "SELECT event_id, tsk_events.event_description_id"
				+ " FROM tsk_events "
				+ " LEFT JOIN tsk_event_descriptions ON ( tsk_events.event_description_id = tsk_event_descriptions.event_description_id )"
				+ " WHERE content_obj_id = " + fileObjID
				+ artifactClause;
		try (Statement selectStmt = con.createStatement(); ResultSet executeQuery = selectStmt.executeQuery(sql);) {
			while (executeQuery.next()) {
				eventIDToDescriptionIDs.put(executeQuery.getLong("event_id"), executeQuery.getLong("event_description_id")); //NON-NLS
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting event description ids for object id = " + fileObjID, ex);
		}
		return eventIDToDescriptionIDs;
	}

	/**
	 * Finds all of the timeline events directly associated with a given content
	 * and marks them as having an event source that is tagged. This does not
	 * include timeline events where the event source is an artifact, even if
	 * the artifact source is the tagged content.
	 *
	 * @param content The content.
	 *
	 * @return The event IDs of the events that were marked as having a tagged
	 *         event source.
	 *
	 * @throws TskCoreException If there is an error updating the case database.
	 *
	 * WARNING: THIS IS A BETA VERSION OF THIS METHOD, SUBJECT TO CHANGE AT ANY
	 * TIME.
	 */
	@Beta
	public Set<Long> updateEventsForContentTagAdded(Content content) throws TskCoreException {
		caseDB.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection conn = caseDB.getConnection()) {
			Map<Long, Long> eventIDs = getEventAndDescriptionIDs(conn, content.getId(), false);
			updateEventSourceTaggedFlag(conn, eventIDs.values(), 1);
			return eventIDs.keySet();
		} finally {
			caseDB.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Finds all of the timeline events directly associated with a given content
	 * and marks them as not having an event source that is tagged, if and only
	 * if there are no other tags on the content. The inspection of events does
	 * not include events where the event source is an artifact, even if the
	 * artifact source is the content from which trhe tag was removed.
	 *
	 * @param content The content.
	 *
	 * @return The event IDs of the events that were marked as not having a
	 *         tagged event source.
	 *
	 * @throws TskCoreException If there is an error updating the case database.
	 *
	 * WARNING: THIS IS A BETA VERSION OF THIS METHOD, SUBJECT TO CHANGE AT ANY
	 * TIME.
	 */
	@Beta
	public Set<Long> updateEventsForContentTagDeleted(Content content) throws TskCoreException {
		caseDB.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection conn = caseDB.getConnection()) {
			if (caseDB.getContentTagsByContent(content).isEmpty()) {
				Map<Long, Long> eventIDs = getEventAndDescriptionIDs(conn, content.getId(), false);
				updateEventSourceTaggedFlag(conn, eventIDs.values(), 0);
				return eventIDs.keySet();
			} else {
				return Collections.emptySet();
			}
		} finally {
			caseDB.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Finds all of the timeline events directly associated with a given
	 * artifact and marks them as having an event source that is tagged.
	 *
	 * @param artifact The artifact.
	 *
	 * @return The event IDs of the events that were marked as having a tagged
	 *         event source.
	 *
	 * @throws TskCoreException If there is an error updating the case database.
	 */
	public Set<Long> updateEventsForArtifactTagAdded(BlackboardArtifact artifact) throws TskCoreException {
		caseDB.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection conn = caseDB.getConnection()) {
			Map<Long, Long> eventIDs = getEventAndDescriptionIDs(conn, artifact.getObjectID(), artifact.getArtifactID());
			updateEventSourceTaggedFlag(conn, eventIDs.values(), 1);
			return eventIDs.keySet();
		} finally {
			caseDB.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Finds all of the timeline events directly associated with a given
	 * artifact and marks them as not having an event source that is tagged, if
	 * and only if there are no other tags on the artifact.
	 *
	 * @param artifact The artifact.
	 *
	 * @return The event IDs of the events that were marked as not having a
	 *         tagged event source.
	 *
	 * @throws TskCoreException If there is an error updating the case database.
	 */
	public Set<Long> updateEventsForArtifactTagDeleted(BlackboardArtifact artifact) throws TskCoreException {
		caseDB.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection conn = caseDB.getConnection()) {
			if (caseDB.getBlackboardArtifactTagsByArtifact(artifact).isEmpty()) {
				Map<Long, Long> eventIDs = getEventAndDescriptionIDs(conn, artifact.getObjectID(), artifact.getArtifactID());
				updateEventSourceTaggedFlag(conn, eventIDs.values(), 0);
				return eventIDs.keySet();
			} else {
				return Collections.emptySet();
			}
		} finally {
			caseDB.releaseSingleUserCaseWriteLock();
		}
	}

	private void updateEventSourceTaggedFlag(CaseDbConnection conn, Collection<Long> eventDescriptionIDs, int flagValue) throws TskCoreException {
		if (eventDescriptionIDs.isEmpty()) {
			return;
		}

		String sql = "UPDATE tsk_event_descriptions SET tagged = " + flagValue + " WHERE event_description_id IN (" + buildCSVString(eventDescriptionIDs) + ")"; //NON-NLS
		try (Statement updateStatement = conn.createStatement()) {
			updateStatement.executeUpdate(sql);
		} catch (SQLException ex) {
			throw new TskCoreException("Error marking content events tagged: " + sql, ex);//NON-NLS
		}
	}

	/**
	 * Finds all of the timeline events associated directly or indirectly with a
	 * given content and marks them as having an event source that has a hash
	 * set hit. This includes both the events that have the content as their
	 * event source and the events for which the content is the source content
	 * for the source artifact of the event.
	 *
	 * @param content The content.
	 *
	 * @return The event IDs of the events that were marked as having an event
	 *         source with a hash set hit.
	 *
	 * @throws TskCoreException If there is an error updating the case database.
	 */
	public Set<Long> updateEventsForHashSetHit(Content content) throws TskCoreException {
		caseDB.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection con = caseDB.getConnection(); Statement updateStatement = con.createStatement();) {
			Map<Long, Long> eventIDs = getEventAndDescriptionIDs(con, content.getId(), true);
			if (!eventIDs.isEmpty()) {
				String sql = "UPDATE tsk_event_descriptions SET hash_hit = 1" + " WHERE event_description_id IN (" + buildCSVString(eventIDs.values()) + ")"; //NON-NLS
				try {
					updateStatement.executeUpdate(sql); //NON-NLS
					return eventIDs.keySet();
				} catch (SQLException ex) {
					throw new TskCoreException("Error setting hash_hit of events.", ex);//NON-NLS
				}
			} else {
				return eventIDs.keySet();
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error setting hash_hit of events.", ex);//NON-NLS
		} finally {
			caseDB.releaseSingleUserCaseWriteLock();
		}
	}

	void rollBackTransaction(SleuthkitCase.CaseDbTransaction trans) throws TskCoreException {
		trans.rollback();
	}

	/**
	 * Counts the timeline events events that satisfy the given conditions.
	 *
	 * @param startTime         Events that occurred before this time are not
	 *                          counted (units: seconds from UNIX epoch)
	 * @param endTime           Events that occurred at or after this time are
	 *                          not counted (seconds from unix epoch)
	 * @param filter            Events that fall within the specified time range
	 *                          are only ocunted if they pass this filter.
	 * @param typeHierachyLevel Events that fall within the specified time range
	 *                          and pass the specified filter asre only counted
	 *                          if their types are at the specified level of the
	 *                          event type hierarchy.
	 *
	 * @return The event counts for each event type at the specified level in
	 *         the event types hierarchy.
	 *
	 * @throws TskCoreException If there is an error querying the case database.
	 */
	public Map<TimelineEventType, Long> countEventsByType(Long startTime, Long endTime, TimelineFilter.RootFilter filter, TimelineEventType.HierarchyLevel typeHierachyLevel) throws TskCoreException {
		long adjustedEndTime = Objects.equals(startTime, endTime) ? endTime + 1 : endTime;
		//do we want the base or subtype column of the databse
		String typeColumn = typeColumnHelper(TimelineEventType.HierarchyLevel.EVENT.equals(typeHierachyLevel));

		String queryString = "SELECT count(DISTINCT tsk_events.event_id) AS count, " + typeColumn//NON-NLS
				+ " FROM " + getAugmentedEventsTablesSQL(filter)//NON-NLS
				+ " WHERE time >= " + startTime + " AND time < " + adjustedEndTime + " AND " + getSQLWhere(filter) // NON-NLS
				+ " GROUP BY " + typeColumn; // NON-NLS

		caseDB.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = caseDB.getConnection();
				Statement stmt = con.createStatement();
				ResultSet results = stmt.executeQuery(queryString);) {
			Map<TimelineEventType, Long> typeMap = new HashMap<>();
			while (results.next()) {
				int eventTypeID = results.getInt(typeColumn);
				TimelineEventType eventType = getEventType(eventTypeID)
						.orElseThrow(() -> newEventTypeMappingException(eventTypeID));//NON-NLS

				typeMap.put(eventType, results.getLong("count")); // NON-NLS
			}
			return typeMap;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting count of events from db: " + queryString, ex); // NON-NLS
		} finally {
			caseDB.releaseSingleUserCaseReadLock();
		}
	}

	private static TskCoreException newEventTypeMappingException(int eventTypeID) {
		return new TskCoreException("Error mapping event type id " + eventTypeID + " to EventType.");//NON-NLS
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
	static private String getAugmentedEventsTablesSQL(TimelineFilter.RootFilter filter) {
		TimelineFilter.FileTypesFilter fileTypesFitler = filter.getFileTypesFilter();
		boolean needsMimeTypes = fileTypesFitler != null && fileTypesFitler.hasSubFilters();

		return getAugmentedEventsTablesSQL(needsMimeTypes);
	}

	/**
	 * Get an SQL expression that produces an events table augmented with the
	 * columns required by the filters: The union of the events table joined to
	 * the content and blackboard artifacts tags tables, if necessary; then
	 * joined to a query that selects hash set hits, if necessary; then joined
	 * to the tsk_files table for mime_types if necessary. If all flags are
	 * false, just return "events".
	 *
	 * @param needMimeTypes True if the filters require joining to the tsk_files
	 *                      table for the mime_type.
	 *
	 * @return An SQL expression that produces an events table augmented with
	 *         the columns required by the filters.
	 */
	static private String getAugmentedEventsTablesSQL(boolean needMimeTypes) {
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
		return "( SELECT event_id, time, tsk_event_descriptions.data_source_obj_id, content_obj_id, artifact_id, "
				+ " full_description, med_description, short_description, tsk_events.event_type_id, super_type_id,"
				+ " hash_hit, tagged "
				+ (needMimeTypes ? ", mime_type" : "")
				+ " FROM tsk_events "
				+ " JOIN tsk_event_descriptions ON ( tsk_event_descriptions.event_description_id = tsk_events.event_description_id)"
				+ " JOIN tsk_event_types ON (tsk_events.event_type_id = tsk_event_types.event_type_id )  "
				+ (needMimeTypes ? " LEFT OUTER JOIN tsk_files "
						+ "	ON (tsk_event_descriptions.content_obj_id = tsk_files.obj_id)"
						: "")
				+ ")  AS tsk_events";
	}

	/**
	 * Convert a boolean to int with the mappings true => 1, false =>0
	 *
	 * @param value the boolean value to convert to an int.
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
	 * Gets the timeline events that fall within a given time interval and
	 * satisfy a given event filter.
	 *
	 * @param timeRange The time level.
	 * @param filter    The event filter.
	 *
	 * @return	The list of events that fall within the specified interval and
	 *         poass the specified filter.
	 *
	 * @throws TskCoreException If there is an error querying the case database.
	 */
	public List<TimelineEvent> getEvents(Interval timeRange, TimelineFilter.RootFilter filter) throws TskCoreException {
		List<TimelineEvent> events = new ArrayList<>();

		Long startTime = timeRange.getStartMillis() / 1000;
		Long endTime = timeRange.getEndMillis() / 1000;

		if (Objects.equals(startTime, endTime)) {
			endTime++; //make sure end is at least 1 millisecond after start
		}

		if (filter == null) {
			return events;
		}

		if (endTime < startTime) {
			return events;
		}

		//build dynamic parts of query
		String querySql = "SELECT time, content_obj_id, data_source_obj_id, artifact_id, " // NON-NLS
				+ "  event_id, " //NON-NLS
				+ " hash_hit, " //NON-NLS
				+ " tagged, " //NON-NLS
				+ " event_type_id, super_type_id, "
				+ " full_description, med_description, short_description " // NON-NLS
				+ " FROM " + getAugmentedEventsTablesSQL(filter) // NON-NLS
				+ " WHERE time >= " + startTime + " AND time < " + endTime + " AND " + getSQLWhere(filter) // NON-NLS
				+ " ORDER BY time"; // NON-NLS

		caseDB.acquireSingleUserCaseReadLock();
		try (CaseDbConnection con = caseDB.getConnection();
				Statement stmt = con.createStatement();
				ResultSet resultSet = stmt.executeQuery(querySql);) {

			while (resultSet.next()) {
				int eventTypeID = resultSet.getInt("event_type_id");
				TimelineEventType eventType = getEventType(eventTypeID).orElseThrow(()
						-> new TskCoreException("Error mapping event type id " + eventTypeID + "to EventType."));//NON-NLS

				TimelineEvent event = new TimelineEvent(
						resultSet.getLong("event_id"), // NON-NLS
						resultSet.getLong("data_source_obj_id"), // NON-NLS
						resultSet.getLong("content_obj_id"), // NON-NLS
						resultSet.getLong("artifact_id"), // NON-NLS
						resultSet.getLong("time"), // NON-NLS
						eventType,
						resultSet.getString("full_description"), // NON-NLS
						resultSet.getString("med_description"), // NON-NLS
						resultSet.getString("short_description"), // NON-NLS
						resultSet.getInt("hash_hit") != 0, //NON-NLS
						resultSet.getInt("tagged") != 0);

				events.add(event);
			}

		} catch (SQLException ex) {
			throw new TskCoreException("Error getting events from db: " + querySql, ex); // NON-NLS
		} finally {
			caseDB.releaseSingleUserCaseReadLock();
		}

		return events;
	}

	/**
	 * Get the column name to use depending on if we want base types or subtypes
	 *
	 * @param useSubTypes True to use sub types, false to use base types.
	 *
	 * @return column name to use depending on if we want base types or subtypes
	 */
	private static String typeColumnHelper(final boolean useSubTypes) {
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
	String getSQLWhere(TimelineFilter.RootFilter filter) {

		String result;
		if (filter == null) {
			return getTrueLiteral();
		} else {
			result = filter.getSQLWhere(this);
		}

		return result;
	}

	/**
	 * Creates a sql statement that will do nothing due to unique constraint.
	 *
	 * @param insertTableValues the table, columns, and values portion of the
	 *                          insert statement (i.e. 'table_name(col1, col2)
	 *                          VALUES (rowVal1, rowVal2)').
	 *
	 * @return The sql statement.
	 *
	 * @throws TskCoreException
	 */
	private String getSqlIgnoreConflict(String insertTableValues) throws TskCoreException {
		switch (caseDB.getDatabaseType()) {
			case POSTGRESQL:
				return "INSERT INTO " + insertTableValues + " ON CONFLICT DO NOTHING";
			case SQLITE:
				return "INSERT OR IGNORE INTO " + insertTableValues;
			default:
				throw new TskCoreException("Unknown DB Type: " + caseDB.getDatabaseType().name());
		}
	}

	private String getTrueLiteral() {
		switch (caseDB.getDatabaseType()) {
			case POSTGRESQL:
				return "TRUE";//NON-NLS
			case SQLITE:
				return "1";//NON-NLS
			default:
				throw new UnsupportedOperationException("Unsupported DB type: " + caseDB.getDatabaseType().name());//NON-NLS

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
	 * Exception thrown in the event of a duplicate.
	 */
	private static class DuplicateException extends Exception {

		private static final long serialVersionUID = 1L;

		/**
		 * Main constructor.
		 *
		 * @param message Message for duplicate exception.
		 */
		DuplicateException(String message) {
			super(message);
		}
	}
}
