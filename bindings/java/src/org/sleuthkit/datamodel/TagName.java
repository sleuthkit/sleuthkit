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

import java.util.HashMap;

/**
 * Instances of this class are data transfer objects (DTOs) that represent the 
 * names (and related properties) a user can select from to apply a tag to a 
 * Content or BlackboardArtifact object.
 */
public class TagName {
	public enum HTML_COLOR {
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
		
		private final static HashMap<String, HTML_COLOR> colorMap = new HashMap<String, HTML_COLOR>();
		private String name;
		
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
			}
			else {
				return NONE;
			}
		}
	}
		
	static long ID_NOT_SET = -1;
	private long id = ID_NOT_SET;
	private final String displayName;
	private String description;
	private HTML_COLOR color;
		
	public TagName(String displayName, String description, HTML_COLOR color) throws IllegalArgumentException {
		if (null == displayName || displayName.isEmpty() == true) {
			throw new IllegalArgumentException("displayName is null or empty");
		}
		this.displayName = displayName;

		if (null == description) {
			throw new IllegalArgumentException("description is null or empty");
		}
		this.description = description;
				
		if (null == color) {
			throw new IllegalArgumentException("color is null");
		}
		this.color = color;
	}

	TagName(long id, String displayName, String description, HTML_COLOR color) throws IllegalArgumentException {
		this(displayName, description, color);
		this.id = id;
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
	
	long getId() {
		return id;
	}	

	void setId(long id) {
		this.id = id;
	}			
}
