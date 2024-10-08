/*
 * Sleuth Kit Data Model
 *
 * Copyright 2021 Basis Technology Corp.
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

import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;

/**
 *
 * Tests to make sure timeline event types handle all artifacts with time-valued
 * attributes.
 *
 */
public class TimelineEventTypesTest {

	private static final Logger LOGGER = Logger.getLogger(TimelineEventTypesTest.class.getName());

	public TimelineEventTypesTest() {

	}

	@BeforeClass
	public static void setUpClass() {
	}

	@AfterClass
	public static void tearDownClass() {
	}

	@Before
	public void setUp() {
	}

	@After
	public void tearDown() {
	}

	/**
	 * Ensure all event display names exist.
	 */
	@Test
	public void testEventIdentifiersUnique() {
		Set<String> identifiers = new HashSet<>();
		Set<String> repeats = new HashSet<>();
		Set<TimelineEventArtifactTypeImpl> nullDisplayNames = new HashSet<>();

		getArtifactEvents().forEach((artEv) -> {
			if (artEv.getDisplayName() == null) {
				nullDisplayNames.add(artEv);
			} else if (!identifiers.add(artEv.getDisplayName())) {
				repeats.add(artEv.getDisplayName());
			}
		});

		assertEquals("Expected no null display names", 0, nullDisplayNames.size());
		assertEquals("Expected no repeats but received: " + repeats.stream().collect(Collectors.joining(", ")), 0, repeats.size());
	}

	/**
	 * Ensure all artifacts with time-valued attributes are represented without
	 * duplicates.
	 */
	@Test
	public void testArtifactAttributeEvents() {
		// this was generated based off of the artifact_catalog.dox
		Map<ARTIFACT_TYPE, Set<ATTRIBUTE_TYPE>> mapping = new HashMap<>();
		mapping.put(ARTIFACT_TYPE.TSK_PROG_NOTIFICATIONS, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME));
		mapping.put(ARTIFACT_TYPE.TSK_WEB_SEARCH_QUERY, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED));
		mapping.put(ARTIFACT_TYPE.TSK_RECENT_OBJECT, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED));
		mapping.put(ARTIFACT_TYPE.TSK_SCREEN_SHOTS, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME));
		mapping.put(ARTIFACT_TYPE.TSK_BLUETOOTH_ADAPTER, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME));
		mapping.put(ARTIFACT_TYPE.TSK_CALENDAR_ENTRY, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME_END, ATTRIBUTE_TYPE.TSK_DATETIME_START));
		mapping.put(ARTIFACT_TYPE.TSK_DEVICE_ATTACHED, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME));
		mapping.put(ARTIFACT_TYPE.TSK_SERVICE_ACCOUNT, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME_CREATED));
		mapping.put(ARTIFACT_TYPE.TSK_DELETED_PROG, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME));
		mapping.put(ARTIFACT_TYPE.TSK_GPS_LAST_KNOWN_LOCATION, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME));
		mapping.put(ARTIFACT_TYPE.TSK_USER_DEVICE_EVENT, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME_END, ATTRIBUTE_TYPE.TSK_DATETIME_START));
		mapping.put(ARTIFACT_TYPE.TSK_WEB_HISTORY, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED, ATTRIBUTE_TYPE.TSK_DATETIME_CREATED));
		mapping.put(ARTIFACT_TYPE.TSK_OS_INFO, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME));
		mapping.put(ARTIFACT_TYPE.TSK_GPS_ROUTE, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME));
		mapping.put(ARTIFACT_TYPE.TSK_MESSAGE, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME));
		mapping.put(ARTIFACT_TYPE.TSK_GPS_BOOKMARK, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME));
		mapping.put(ARTIFACT_TYPE.TSK_GPS_SEARCH, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME));
		mapping.put(ARTIFACT_TYPE.TSK_WEB_FORM_AUTOFILL, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED, ATTRIBUTE_TYPE.TSK_DATETIME_CREATED));
		mapping.put(ARTIFACT_TYPE.TSK_WEB_CACHE, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME_CREATED));
		mapping.put(ARTIFACT_TYPE.TSK_WIFI_NETWORK, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME));
		mapping.put(ARTIFACT_TYPE.TSK_WEB_FORM_ADDRESS, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED, ATTRIBUTE_TYPE.TSK_DATETIME_MODIFIED));
		mapping.put(ARTIFACT_TYPE.TSK_METADATA_EXIF, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME_CREATED));
		mapping.put(ARTIFACT_TYPE.TSK_WEB_COOKIE, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED, ATTRIBUTE_TYPE.TSK_DATETIME_CREATED));
		mapping.put(ARTIFACT_TYPE.TSK_WEB_DOWNLOAD, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED));
		mapping.put(ARTIFACT_TYPE.TSK_TL_EVENT, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME));
		mapping.put(ARTIFACT_TYPE.TSK_METADATA, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME_CREATED, ATTRIBUTE_TYPE.TSK_DATETIME_MODIFIED, ATTRIBUTE_TYPE.TSK_LAST_PRINTED_DATETIME));
		mapping.put(ARTIFACT_TYPE.TSK_WEB_BOOKMARK, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME_CREATED));
		mapping.put(ARTIFACT_TYPE.TSK_BLUETOOTH_PAIRING, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME, ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED));
		mapping.put(ARTIFACT_TYPE.TSK_INSTALLED_PROG, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME));
		mapping.put(ARTIFACT_TYPE.TSK_BACKUP_EVENT, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME_END, ATTRIBUTE_TYPE.TSK_DATETIME_START));
		mapping.put(ARTIFACT_TYPE.TSK_CALLLOG, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME_END, ATTRIBUTE_TYPE.TSK_DATETIME_START));
		mapping.put(ARTIFACT_TYPE.TSK_PROG_RUN, EnumSet.of(ATTRIBUTE_TYPE.TSK_DATETIME));

		Map<Integer, ARTIFACT_TYPE> artTypeIds = Stream.of(ARTIFACT_TYPE.values())
				.collect(Collectors.toMap((art) -> art.getTypeID(), (art) -> art));

		Map<Integer, ATTRIBUTE_TYPE> attrTypeIds = Stream.of(ATTRIBUTE_TYPE.values())
				.collect(Collectors.toMap((attr) -> attr.getTypeID(), (attr) -> attr));

		Map<ARTIFACT_TYPE, Set<ATTRIBUTE_TYPE>> duplicates = new HashMap<>();
		Map<ARTIFACT_TYPE, Set<ATTRIBUTE_TYPE>> timelineEventArtifacts = new HashMap<>();

		getArtifactEvents().forEach((artEv) -> {
			ARTIFACT_TYPE currArtType = artTypeIds.get(artEv.getArtifactTypeID());
			ATTRIBUTE_TYPE curAttrType = attrTypeIds.get(artEv.getDateTimeAttributeType().getTypeID());
			if (currArtType != null && curAttrType != null) {
				// if adding for this artifact's set of attributes results in duplicate
				if (!timelineEventArtifacts.computeIfAbsent(currArtType, (artType) -> new HashSet<>()).add(curAttrType)
						&& !currArtType.equals(ARTIFACT_TYPE.TSK_TL_EVENT)) {
					duplicates.computeIfAbsent(currArtType, (artType) -> new HashSet<>()).add(curAttrType);
				}
			}
		});

		Map<ARTIFACT_TYPE, Set<ATTRIBUTE_TYPE>> notRepresentedInTimeline = new HashMap<>();
		for (Entry<ARTIFACT_TYPE, Set<ATTRIBUTE_TYPE>> e : mapping.entrySet()) {
			Set<ATTRIBUTE_TYPE> bbAttrs = new HashSet<>(e.getValue());
			Set<ATTRIBUTE_TYPE> timelineEvtAttrs = timelineEventArtifacts.get(e.getKey());
			timelineEvtAttrs = timelineEvtAttrs == null ? Collections.emptySet() : timelineEvtAttrs;

			bbAttrs.removeAll(timelineEvtAttrs);
			if (bbAttrs.size() > 0) {
				notRepresentedInTimeline.put(e.getKey(), bbAttrs);
			}
		}

		assertEquals("Expected all time valued attributes represented, but the following are not: "
				+ notRepresentedInTimeline.toString(), 0, notRepresentedInTimeline.size());

		assertEquals("Expected no repeats but received: " + duplicates.toString(), 0, duplicates.size());
	}

	/**
	 * Recursively gathers all timeline event types for artifacts.
	 *
	 * @return Timeline event types for artifacts.
	 */
	private Stream<TimelineEventArtifactTypeImpl> getArtifactEvents() {
		return getArtifactEvents(TimelineEventType.ROOT_EVENT_TYPE);
	}

	/**
	 * Recursively gathers all timeline event types for artifacts.
	 *
	 * @param type The parent type that will be checked and whose children will
	 *             be checked.
	 *
	 * @return Timeline event types for artifacts.
	 */
	private Stream<TimelineEventArtifactTypeImpl> getArtifactEvents(TimelineEventType type) {
		Stream<TimelineEventArtifactTypeImpl> thisItem = type instanceof TimelineEventArtifactTypeImpl
				? Stream.of((TimelineEventArtifactTypeImpl) type)
				: Stream.empty();

		Stream<TimelineEventArtifactTypeImpl> children = type.getChildren() == null
				? Stream.empty()
				: type.getChildren().stream()
						.flatMap(t -> getArtifactEvents(t));

		return Stream.concat(thisItem, children);
	}
}
