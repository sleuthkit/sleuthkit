/* SPDX-License-Identifier: Apache-2.0 */
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
 * tags applied to content and blackboard artifacts by users.
 */
public abstract class Tag {

	static long ID_NOT_SET = -1;
	private long tagID = ID_NOT_SET;
	private final TagName name;
	private final String comment;
	private final String userName;

	Tag(long tagID, TagName name, String comment, String userName) {
		this.tagID = tagID;
		this.name = name;
		this.comment = comment;
		this.userName = userName;
	}

	/**
	 * Get Tag ID (unique amongst tags)
	 * 
	 * @return 
	 */
	public long getId() {
		return tagID;
	}

	public TagName getName() {
		return name;
	}

	public String getComment() {
		return comment;
	}
	
	public String getUserName() {
		return userName == null ? "" : userName;
	}
}
