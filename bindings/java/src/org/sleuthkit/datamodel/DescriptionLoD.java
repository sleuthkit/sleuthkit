/*
 * Sleuth Kit Data Model
 *
 * Copyright 2018 Basis Technology Corp.
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
 * Enumeration of description levels of detail (LoD).
 */
public enum DescriptionLoD {
	SHORT(ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle").getString("DescriptionLOD.short")),
	MEDIUM(ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle").getString("DescriptionLOD.medium")),
	FULL(ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle").getString("DescriptionLOD.full"));

	private final String displayName;

	public String getDisplayName() {
		return displayName;
	}

	private DescriptionLoD(String displayName) {
		this.displayName = displayName;
	}

	public DescriptionLoD moreDetailed() {
		try {
			return values()[ordinal() + 1];
		} catch (ArrayIndexOutOfBoundsException e) {
			return null;
		}
	}

	public DescriptionLoD lessDetailed() {
		try {
			return values()[ordinal() - 1];
		} catch (ArrayIndexOutOfBoundsException e) {
			return null;
		}
	}

}
