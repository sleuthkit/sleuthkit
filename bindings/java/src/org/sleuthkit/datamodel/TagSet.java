/*
 * Sleuth Kit Data Model
 *
 * Copyright 2020 Basis Technology Corp.
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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/**
 * A TagSet is a named group of TagNames.
 */
public class TagSet {

	private final String setName;
	private final long id;
	private final List<TagName> tagNameList;

	/**
	 * Construct a TagSet.
	 *
	 * @param id		    Tag set id value.
	 * @param setName	Name of tag set.
	 */
	TagSet(long id, String setName, List<TagName> tagNameList) {
		if (setName == null || setName.isEmpty()) {
			throw new IllegalArgumentException("TagSet name must be a non-empty string");
		}
		this.tagNameList = new ArrayList<>(tagNameList);
		this.tagNameList.sort(new TagNameComparator());
		this.id = id;
		this.setName = setName;
	}

	/**
	 * Returns the name of the tag set.
	 *
	 * @return Tag set name.
	 */
	public String getName() {
		return setName;
	}

	/**
	 * Returns a list of the TagName objects that belong to the tag set.
	 *
	 * @return An unmodifiable list of TagName objects.
	 */
	public List<TagName> getTagNames() {
		return Collections.unmodifiableList(tagNameList);
	}

	/**
	 * Return the TagSet id.
	 *
	 * @return TagSet id value.
	 */
	long getId() {
		return id;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}

		if (getClass() != obj.getClass()) {
			return false;
		}

		final TagSet other = (TagSet) obj;

		return (this.id == other.getId()
				&& setName.equals(other.getName())
				&& tagNameList.equals(other.tagNameList));
	}

	@Override
	public int hashCode() {
		int hash = 5;
		hash = 89 * hash + (int) (this.id ^ (this.id >>> 32));
		hash = 89 * hash + Objects.hashCode(this.setName);
		hash = 89 * hash + Objects.hashCode(this.tagNameList);

		return hash;
	}
	
	/**
	 * Comparator for TagNames. TagNames will sort by rank, then TagName.getName().
	 */
	private class TagNameComparator implements Comparator<TagName> {
		@Override
		public int compare(TagName tagName1, TagName tagName2) {
			int result = ((Integer)tagName1.getRank()).compareTo(tagName2.getRank());
			if(result == 0) {
				result =  tagName1.getName().compareTo(tagName2.getName());
			} 
			return result;
		}
	}
}
