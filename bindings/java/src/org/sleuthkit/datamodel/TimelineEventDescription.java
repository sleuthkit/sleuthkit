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
 * Encapsulates the potential multiple levels of description for an event in to
 * one object. Currently used for interim storage.
 */
class TimelineEventDescription {

	String shortDesc;
	String mediumDesc;
	String fullDesc;

	TimelineEventDescription(String fullDescription, String medDescription, String shortDescription) {
		this.shortDesc = shortDescription;
		this.mediumDesc = medDescription;
		this.fullDesc = fullDescription;
	}

	TimelineEventDescription(String fullDescription) {
		this.shortDesc = "";
		this.mediumDesc = "";
		this.fullDesc = fullDescription;
	}

	/**
	 * Get the full description of this event.
	 *
	 * @return the full description
	 */
	String getFullDescription() {
		return fullDesc;
	}

	/**
	 * Get the medium description of this event.
	 *
	 * @return the medium description
	 */
	String getMediumDescription() {
		return mediumDesc;
	}

	/**
	 * Get the short description of this event.
	 *
	 * @return the short description
	 */
	String getShortDescription() {
		return shortDesc;
	}

	/**
	 * Get the description of this event at the give level of detail(LoD).
	 *
	 * @param lod The level of detail to get.
	 *
	 * @return The description of this event at the given level of detail.
	 */
	String getDescription(TimelineEvent.DescriptionLevel lod) {
		switch (lod) {
			case FULL:
			default:
				return getFullDescription();
			case MEDIUM:
				return getMediumDescription();
			case SHORT:
				return getShortDescription();
		}
	}
}
