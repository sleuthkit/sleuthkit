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
 * This class is a base class for classes that model tags applied to objects by 
 * users.
 */
public abstract class Tag {	
	static long ID_NOT_SET = 0;
	private long id = ID_NOT_SET;
	private final TagName name;
	private String comment = "";
	private long beginByteOffset = 0;
	private long endByteOffset = 0;

	public Tag(TagName name) {
		this.name = name;
	}
			
	public Tag(TagName name, String comment) {
		this(name);
		this.comment = comment;
	}
			
	public Tag(TagName name, String comment, long beginByteOffset, long endByteOffset) {
		this(name, comment);
		this.beginByteOffset = beginByteOffset;
		this.endByteOffset = endByteOffset;
	}
			
	public TagName getName() {
		return name;
	}
	
	public String getComment() {
		return comment;
	}
	
	public long getBeginByteOffset() {
		return beginByteOffset;
	}

	public long getEndByteOffset() {
		return endByteOffset;
	}
	
	void setId(long id) {
		this.id = id;
	}

	long getId() {
		return id;
	}	
}
