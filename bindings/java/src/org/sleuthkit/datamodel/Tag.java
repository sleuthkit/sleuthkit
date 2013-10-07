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
 * This class is a base class for data transfer object (DTO) classes that model 
 * tags applied to Content and BlackboardArtifact objects by users.
 */
public abstract class Tag {	
	static long ID_NOT_SET = 0;
	private long id = ID_NOT_SET;
	private final TagType type;
	private final String comment;
			
	public Tag(TagType type, String comment) throws IllegalArgumentException {
		if (null == type) {
			throw new IllegalArgumentException("type is null");
		}
		this.type = type;
				
		if (null == comment) {
			throw new IllegalArgumentException("comment is null");
		}
		this.comment = comment;
	}
						
	public TagType getType() {
		return type;
	}
		
	public String getComment() {
		return comment;
	}
	
	long getId() {
		return id;
	}	
		
	void setId(long id) {
		this.id = id;
	}
}
