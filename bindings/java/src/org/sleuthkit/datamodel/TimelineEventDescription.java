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
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

/**
 * A container for a timeline event description with potentially varying levels
 * of detail.
 */
class TimelineEventDescription {

	private final String shortDesc;
	private final String mediumDesc;
	private final String fullDesc;

	/**
	 * Constructs a container for a timeline event description that varies with
	 * each of three levels of detail.
	 *
	 * @param fullDescription  The full length description of an event for use
	 *                         at a high level of detail.
	 * @param medDescription   The medium length description of an event for use
	 *                         at a medium level of detail.
	 * @param shortDescription The short length description of an event for use
	 *                         at a low level of detail.
	 */
	TimelineEventDescription(String fullDescription, String medDescription, String shortDescription) {
		this.shortDesc = shortDescription;
		this.mediumDesc = medDescription;
		this.fullDesc = fullDescription;
	}

	/**
	 * Constructs a container for a timeline event description for the high
	 * level of detail. The descriptions for the low and medium levels of detail
	 * will be the empty string.
	 *
	 * @param fullDescription The full length description of an event for use at
	 *                        a high level of detail.
	 */
	TimelineEventDescription(String fullDescription) {
		this.shortDesc = "";
		this.mediumDesc = "";
		this.fullDesc = fullDescription;
	}

	/**
	 * Gets the description of this event at the given level of detail.
	 *
	 * @param levelOfDetail The level of detail.
	 *
	 * @return The event description at the given level of detail.
	 */
	String getDescription(TimelineLevelOfDetail levelOfDetail) {
		switch (levelOfDetail) {
			case HIGH:
			default:
				return this.fullDesc;
			case MEDIUM:
				return this.mediumDesc;
			case LOW:
				return this.shortDesc;
		}
	}
	
}
