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
 * Instances of this class are data transfer objects (DTOs) that represent the 
 * types of tags a user can apply to Content and BlackboardArtifact objects.
 */
public class TagType {
	// With the exception of NONE, the elements of this enum correspond to the
	// HTML colors.
	public enum COLOR {
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
		
		private COLOR(String name) {
			this.name = name;
		}
		
		String getName() {
			return name;
		}
	}
		
	static long ID_NOT_SET = -1;
	private long id = ID_NOT_SET;
	private final String displayName;
	private String description = "";
	private COLOR color = COLOR.NONE;
		
	public TagType(String displayName) throws IllegalArgumentException {
		if (null == displayName || displayName.isEmpty() == true) {
			throw new IllegalArgumentException("displayName is null or empty");
		}
		this.displayName = displayName;
	}

	public TagType(String displayName, String description) throws IllegalArgumentException {
		this(displayName);
		if (null == description || description.isEmpty() == true) {
			throw new IllegalArgumentException("description is null or empty");
		}
		this.description = description;
	}

	public TagType(String displayName, String description, COLOR color) throws IllegalArgumentException {
		this(displayName, description);
		if (null == color) {
			throw new IllegalArgumentException("color is null");
		}
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
	
	public COLOR getColor() {
		return color;
	}
	
	public void setColor(COLOR color) {
		this.color = color;
	}		
	
	long getId() {
		return id;
	}	

	void setId(long id) {
		this.id = id;
	}			
}
