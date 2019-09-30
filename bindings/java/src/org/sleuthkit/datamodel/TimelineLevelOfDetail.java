/*
 * Sleuth Kit Data Model
 *
 * Copyright 2019 Basis Technology Corp.
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

import java.util.ResourceBundle;

/**
 * An enumeration of the levels of detail of various aspects of timeline data.
 */
public enum TimelineLevelOfDetail {

	LOW(ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle").getString("TimelineLOD.low")),
	MEDIUM(ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle").getString("TimelineLOD.medium")),
	HIGH(ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle").getString("TimelineLOD.high"));

	private final String displayName;

	/**
	 * Gets the display name of this level of detail.
	 *
	 * @return The display name.
	 */
	public String getDisplayName() {
		return displayName;
	}

	/**
	 * Constructs an element of the enumeration of the levels of detail of
	 * various aspects of timeline data such as event descriptions and timeline
	 * zoom levels.
	 *
	 * @param displayName The display name of the level of detail.
	 */
	private TimelineLevelOfDetail(String displayName) {
		this.displayName = displayName;
	}

	/**
	 * Gets the next higher level of detail relative to this level of detail.
	 *
	 * @return The next higher level of detail, may be null.
	 */
	public TimelineLevelOfDetail moreDetailed() {
		try {
			return values()[ordinal() + 1];
		} catch (ArrayIndexOutOfBoundsException e) {
			return null;
		}
	}

	/**
	 * Gets the next lower level of detail relative to this level of detail.
	 *
	 * @return The next lower level of detail, may be null.
	 */
	public TimelineLevelOfDetail lessDetailed() {
		try {
			return values()[ordinal() - 1];
		} catch (ArrayIndexOutOfBoundsException e) {
			return null;
		}
	}

}
