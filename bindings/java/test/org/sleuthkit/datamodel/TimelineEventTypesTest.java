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

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
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

/**
 *
 * Tests OsAccount apis.
 *
 */
public class TimelineEventTypesTest {
	
	private static final Logger LOGGER = Logger.getLogger(TimelineEventTypesTest.class.getName());

	public TimelineEventTypesTest (){

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

	@Test
	public void testAnEventTypeForEveryArtifact() {
		// artifact types with no time-value attributes
		Set<ARTIFACT_TYPE> artifactsWithNoTime = new HashSet<>(Arrays.asList(
			ARTIFACT_TYPE.TSK_OBJECT_DETECTED,
			ARTIFACT_TYPE.TSK_REMOTE_DRIVE,
			ARTIFACT_TYPE.TSK_ACCOUNT,
			ARTIFACT_TYPE.TSK_SIM_ATTACHED,
			ARTIFACT_TYPE.TSK_DEVICE_INFO,
			ARTIFACT_TYPE.TSK_HASHSET_HIT,
			ARTIFACT_TYPE.TSK_DOWNLOAD_SOURCE,
			ARTIFACT_TYPE.TSK_USER_CONTENT_SUSPECTED,
			ARTIFACT_TYPE.TSK_TAG_ARTIFACT,
			ARTIFACT_TYPE.TSK_WIFI_NETWORK_ADAPTER,
			ARTIFACT_TYPE.TSK_CLIPBOARD_CONTENT,
			ARTIFACT_TYPE.TSK_YARA_HIT,
			ARTIFACT_TYPE.TSK_DATA_SOURCE_USAGE,
			ARTIFACT_TYPE.TSK_KEYWORD_HIT,
			ARTIFACT_TYPE.TSK_SPEED_DIAL_ENTRY,
			ARTIFACT_TYPE.TSK_ASSOCIATED_OBJECT,
			ARTIFACT_TYPE.TSK_CONTACT,
			ARTIFACT_TYPE.TSK_EXTRACTED_TEXT,
			ARTIFACT_TYPE.TSK_WEB_CATEGORIZATION,
			ARTIFACT_TYPE.TSK_TAG_FILE,
			ARTIFACT_TYPE.TSK_VERIFICATION_FAILED,
			ARTIFACT_TYPE.TSK_GPS_AREA,
			ARTIFACT_TYPE.TSK_EXT_MISMATCH_DETECTED,
			ARTIFACT_TYPE.TSK_TOOL_OUTPUT,
			ARTIFACT_TYPE.TSK_ENCRYPTION_DETECTED,
			ARTIFACT_TYPE.TSK_GEN_INFO,
			ARTIFACT_TYPE.TSK_FACE_DETECTED,
			ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT,
			ARTIFACT_TYPE.TSK_WEB_ACCOUNT_TYPE,
			ARTIFACT_TYPE.TSK_INTERESTING_ARTIFACT_HIT,
			ARTIFACT_TYPE.TSK_ENCRYPTION_SUSPECTED
		));
				
		Set<Integer> eventArtifactTypeIds = getArtifactEvents()
				.map((artEv) -> artEv.getArtifactTypeID())
				.collect(Collectors.toSet());
		
		Set<BlackboardArtifact.ARTIFACT_TYPE> missingTypes = getArtifactTypes()
				.filter((artType) -> !artifactsWithNoTime.contains(artType))
				.filter((artType) -> !eventArtifactTypeIds.contains(artType.getTypeID()))
				.collect(Collectors.toSet());
		
		String missingItems = missingTypes.stream().map((artType) -> artType.name()).collect(Collectors.joining(", "));
		assertEquals("Expected no missing event types but received: " + missingItems, missingTypes.size(), 0);
	}
	
	@Test
	public void timelineTypesCoverAllArtifacts() {
		// are we covering every artifact?
		// are identifiers / artifacts unique?
		// are we covering all time valued attributes for artifact?
		// what happens to artifacts that fall through?
		// are all filters visible and fiterable in ui?


//		TimelineEventArtifactTypeImpl impl = null;
//		impl.getA
	}
	
	private Stream<BlackboardArtifact.ARTIFACT_TYPE> getArtifactTypes() {
		return Stream.of(BlackboardArtifact.ARTIFACT_TYPE.values());
	}
	
	private Stream<TimelineEventArtifactTypeImpl> getArtifactEvents() {
		return getArtifactEvents(TimelineEventType.ROOT_EVENT_TYPE);
	}
	
	private Stream<TimelineEventArtifactTypeImpl> getArtifactEvents(TimelineEventType type) {
		Stream<TimelineEventArtifactTypeImpl> thisItem = type instanceof TimelineEventArtifactTypeImpl ? 
				Stream.of((TimelineEventArtifactTypeImpl) type) : 
				Stream.empty();
		
		Stream<TimelineEventArtifactTypeImpl> children = type.getChildren() == null ? 
				Stream.empty() : 
				type.getChildren().stream()
						.flatMap(t -> getArtifactEvents(t));
		
		return Stream.concat(thisItem, children);
	}
}
