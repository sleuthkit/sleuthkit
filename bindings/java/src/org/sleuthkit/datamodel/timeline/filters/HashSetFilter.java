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
package org.sleuthkit.datamodel.timeline.filters;

import java.util.Objects;

/**
 * Filter for an individual hash set
 */
final public class HashSetFilter extends AbstractFilter {

	private final String hashSetName;

	public String getHashSetName() {
		return hashSetName;
	}

	public HashSetFilter(String hashSetName) {
		this.hashSetName = hashSetName;
	}

	@Override
	synchronized public HashSetFilter copyOf() {
		HashSetFilter filterCopy = new HashSetFilter(getHashSetName());
		filterCopy.setSelected(isSelected());
		filterCopy.setDisabled(isDisabled());
		return filterCopy;
	}

	@Override
	public String getDisplayName() {
		return hashSetName;
	}

	@Override
	public int hashCode() {
		int hash = 7;
		hash = 79 * hash + Objects.hashCode(this.hashSetName);
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
		final HashSetFilter other = (HashSetFilter) obj;
		if (!Objects.equals(this.hashSetName, other.hashSetName)) {
			return false;
		}

		return isSelected() == other.isSelected();
	}
}
