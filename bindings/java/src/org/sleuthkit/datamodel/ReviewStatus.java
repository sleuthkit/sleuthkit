/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011-2016 Basis Technology Corp.
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

import java.util.ResourceBundle;

/**
 * Enum to represent the review status of a artifact.
 *
 */
public enum ReviewStatus {

	APPROVED(1, "APPROVED", "ReviewStatus.Approved"), //approved by human user
	REJECTED(2, "REJECTED", "ReviewStatus.Rejected"), //rejected by humna user
	UNDECIDED(3, "UNDECIDED", "ReviewStatus.Undecided"); // not yet reviewed by human user

	private final Integer id;
	private final String name;
	private final String displayName;

	private ReviewStatus(Integer id, String name, String displayNameKey) {
		this.id = id;
		this.name = name;
		this.displayName = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle").getString(displayNameKey);
	}

	/**
	 * Get the ID of this review status.
	 *
	 * @return the ID of this review status.
	 */
	public Integer getID() {
		return id;
	}

	/**
	 * Get the name of this review status.
	 *
	 * @return the name of this review status.
	 */
	String getName() {
		return name;
	}

	/**
	 * Get the displayName The display name of this review status.
	 *
	 * @return the displayName The display name of this review status.
	 */
	public String getDisplayName() {
		return displayName;
	}
}
