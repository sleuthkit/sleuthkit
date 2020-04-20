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
import java.util.List;
import java.util.Objects;

/**
 * A TagSet is a name group of TagNames.
 */
public class TagSet {
	private final String setName;
	private final int id;
	private final List<TagName> tagNameList = new ArrayList<>();

	/**
	 * Construct a TagSet.
	 * 
	 * @param id		Tag set id value.
	 * @param setName	Name of tag set.
	 */
	TagSet(int id, String setName) {
		this.id = id;
		this.setName = setName;
	}
	
	public String getName() {
		return setName;
	}
	
	public List<TagName> getTagNames() {
		return Collections.unmodifiableList(tagNameList);
	}

	void addTagName(TagName tagName) {
		tagNameList.add(tagName);
	}
	
	void addTagNames(List<TagName> tagNameList) {
		tagNameList.addAll(tagNameList);
	}
	
	int getId() {
		return id;
	}
	
	@Override
	public boolean equals(Object obj) {
		if(obj == null) {
			return false;
		}
		
		if(getClass() != obj.getClass()) {
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
		hash = 89 * hash + Objects.hashCode(this.setName);
		hash = 89 * hash + Objects.hashCode(this.tagNameList);
		hash = 89 * hash + this.id;
		return hash;
	}
	
}
