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

import java.util.Comparator;
import org.sleuthkit.datamodel.TagName;

/**
 * Filter to show only events tag with the tagNames of the selected subfilters.
 */
public final class TagsFilter extends AbstractUnionFilter<TagNameFilter> {

	@Override
	public String getDisplayName() {
		return BundleUtils.getBundle().getString("tagsFilter.displayName.text");
	}

	@Override
	public TagsFilter copyOf() {
		TagsFilter filterCopy = new TagsFilter();
		//add a copy of each subfilter
		getSubFilters().forEach(tagNameFilter -> filterCopy.addSubFilter(tagNameFilter.copyOf()));

		return filterCopy;
	}

	public void removeFilterForTag(TagName tagName) {
		getSubFilters().removeIf(subfilter -> subfilter.getTagName().equals(tagName));
		getSubFilters().sort(Comparator.comparing(TagNameFilter::getDisplayName));
	}
}
