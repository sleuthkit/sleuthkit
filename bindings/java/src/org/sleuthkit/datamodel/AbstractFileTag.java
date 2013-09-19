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
 * Instances of this class represent tags a user applies to a file or a portion 
 * of a file.
 */
public class AbstractFileTag {	
	static long ID_NOT_SET = 0;
	private long id = ID_NOT_SET;
	private final AbstractFile file;
	private final TagName name;
	private String comment = "";
	private long beginByteOffset = 0;
	private long endByteOffset = 0;

	public AbstractFileTag(AbstractFile file, TagName name) {
		this.file = file;
		this.name = name;
	}
			
	public AbstractFileTag(AbstractFile file, TagName name, String comment) {
		this(file, name);
		this.comment = comment;
	}
			
	public AbstractFileTag(AbstractFile file, TagName name, String comment, long beginByteOffset, long endByteOffset) {
		this(file, name, comment);
		this.beginByteOffset = beginByteOffset;
		this.endByteOffset = endByteOffset;
	}
			
	public AbstractFile getFile() {
		return file;
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
	
	// This method is package-private because its only intended client is the
	// SleuthkitCase (i.e., database access) class. 
	AbstractFileTag(long id, AbstractFile file, TagName name, String comment, long beginByteOffset, long endByteOffset) {
		this(file, name, comment, beginByteOffset, endByteOffset);
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
