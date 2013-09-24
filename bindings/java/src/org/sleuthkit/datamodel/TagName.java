/*
 * Sleuth Kit Data Model
 * 
 * Copyright 2013 Basis Technology Corp.
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

/**
 * Instances of this class represent the names of tags associated with content 
 * or artifacts.
 */
public class TagName {
	public enum TAG_COLOR {
		NONE("None"),
		WHITE("White"),
		SILVER("Silver"),	
		GRAY("Gray"),	
		BLACK("Black"),	
		RED("Red"),	
		MAROON("Maron"),	
		YELLOW("Yellow"),	
		OLIVE("Olive"),	
		LIME("Lime"),	
		GREEN("Green"),	
		AQUA("Aqua"),	
		TEAL("Teal"),	
		BLUE("Blue"),	
		NAVY("Navy"),	
		FUCHSIA("Fuchsia"),	
		PURPLE("Purple");
		
		private String name;
		
		private TAG_COLOR(String name) {
			this.name = name;
		}
		
		String getName() {
			return name;
		}
	}
		
	static long ID_NOT_SET = 0;
	private long id = ID_NOT_SET;
	private final String displayName;
	private String description = "";
	private TAG_COLOR color = TAG_COLOR.NONE;
		
	public TagName(String displayName) {
		this.displayName = displayName;
	}

	public TagName(String displayName, String description) {
		this(displayName);
		this.description = description;
	}

	public TagName(String displayName, String description, TAG_COLOR color) {
		this(displayName, description);
		this.color = color;
	}

	public String getDisplayName() {
		return displayName;
	}
	
	public String getDescription() {
		return description;
	}
	
	public void setDescription (String description) {
		this.description = description;
	}
	
	public TAG_COLOR getColor() {
		return color;
	}
	
	public void setColor(TAG_COLOR color) {
		this.color = color;
	}
		
	long getId() {
		return id;
	}	

	void setId(long id) {
		this.id = id;
	}		
}
