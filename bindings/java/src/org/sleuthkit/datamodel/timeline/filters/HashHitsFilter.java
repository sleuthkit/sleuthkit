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

/**
 *
 */
final public class HashHitsFilter extends AbstractUnionFilter<HashSetFilter> {

	@Override
	public String getDisplayName() {
		return BundleUtils.getBundle().getString("hashHitsFilter.displayName.text");
	}

	@Override
	public HashHitsFilter copyOf() {
		HashHitsFilter filterCopy = new HashHitsFilter();
		//add a copy of each subfilter
		this.getSubFilters().forEach(hashSetFilter -> filterCopy.addSubFilter(hashSetFilter.copyOf()));

		return filterCopy;
	}

	 
	 
}
