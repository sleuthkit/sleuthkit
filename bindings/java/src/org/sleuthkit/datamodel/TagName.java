/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011-2017 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Objects;

/**
 * Instances of this class are data transfer objects (DTOs) that represent the
 * names (and related properties) a user can select from to apply a tag to
 * content or a blackboard artifact.
 */
public class TagName implements Comparable<TagName>, Serializable {

	private static final long serialVersionUID = 1L;

	public enum HTML_COLOR {

		NONE("None"), //NON-NLS
		WHITE("White"), //NON-NLS
		SILVER("Silver"), //NON-NLS
		GRAY("Gray"), //NON-NLS
		BLACK("Black"), //NON-NLS
		RED("Red"), //NON-NLS
		MAROON("Maron"), //NON-NLS
		YELLOW("Yellow"), //NON-NLS
		OLIVE("Olive"), //NON-NLS
		LIME("Lime"), //NON-NLS
		GREEN("Green"), //NON-NLS
		AQUA("Aqua"), //NON-NLS
		TEAL("Teal"), //NON-NLS
		BLUE("Blue"), //NON-NLS
		NAVY("Navy"), //NON-NLS
		FUCHSIA("Fuchsia"), //NON-NLS
		PURPLE("Purple"); //NON-NLS
		private final static HashMap<String, HTML_COLOR> colorMap = new HashMap<String, HTML_COLOR>();
		private final String name;

		static {
			for (HTML_COLOR color : HTML_COLOR.values()) {
				colorMap.put(color.name(), color);
			}
		}

		private HTML_COLOR(String name) {
			this.name = name;
		}

		String getName() {
			return name;
		}

		public static HTML_COLOR getColorByName(String colorName) {
			if (colorMap.containsKey(colorName)) {
				return colorMap.get(colorName);
			} else {
				return NONE;
			}
		}
	}
	private final long id;
	private final String displayName;
	private final String description;
	private final HTML_COLOR color;
	private final TskData.FileKnown knownStatus;

	// Clients of the org.sleuthkit.datamodel package should not directly create these objects.		
	TagName(long id, String displayName, String description, HTML_COLOR color, TskData.FileKnown knownStatus) {
		this.id = id;
		this.displayName = displayName;
		this.description = description;
		this.color = color;
		this.knownStatus = knownStatus;
	}

	public long getId() {
		return id;
	}

	public String getDisplayName() {
		return displayName;
	}

	public String getDescription() {
		return description;
	}

	public HTML_COLOR getColor() {
		return color;
	}

	public TskData.FileKnown getKnownStatus() {
		return knownStatus;
	}

	/**
	 * Compares two TagName objects by comparing their display names.
	 *
	 * @param other The other TagName to compare this TagName to
	 *
	 * @return the result of calling compareTo on the displayNames
	 */
	@Override
	public int compareTo(TagName other) {
		return this.getDisplayName().compareTo(other.getDisplayName());
	}

	@Override
	public int hashCode() {
		int hash = 5;
		hash = 89 * hash + (int) (this.id ^ (this.id >>> 32));
		hash = 89 * hash + (this.displayName != null ? this.displayName.hashCode() : 0);
		hash = 89 * hash + (this.description != null ? this.description.hashCode() : 0);
		hash = 89 * hash + (this.color != null ? this.color.hashCode() : 0);
		hash = 89 * hash + (this.knownStatus != null ? this.knownStatus.hashCode() : 0);
		return hash;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		final TagName other = (TagName) obj;
		return (this.id == other.id
				&& Objects.equals(this.displayName, other.displayName)
				&& Objects.equals(this.description, other.description)
				&& Objects.equals(this.color, other.color)
				&& Objects.equals(this.knownStatus, other.knownStatus));
	}
}
