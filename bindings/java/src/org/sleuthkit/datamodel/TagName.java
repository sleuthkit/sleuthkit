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
 * Instances of this class represent the names of tags associated with content.
 */
public class TagName {
	static long ID_NOT_SET = 0;
	private long id = ID_NOT_SET;
	private final String displayName;
	
	public TagName(String displayName) {
		this.displayName = displayName;
	}

	public String getDisplayName() {
		return displayName;
	}
		
	// This method is package-private because its only intended client is the
	// SleuthkitCase (i.e., database access) class. 	
	TagName(long id, String displayName) {
		this(displayName);
		this.id = id;
	}

	// This method is package-private because its only intended client is the
	// SleuthkitCase (i.e., database access) class. 	
	void setId(long id) {
		this.id = id;
	}
			
	// This method is package-private because its only intended client is the
	// SleuthkitCase (i.e., database access) class. 	
	long getId() {
		return id;
	}	
}
