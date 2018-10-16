/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Sleuth Kit Data Model
 * 
 * Copyright 2013-2018 Basis Technology Corp.
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
 * Instances of this class are data transfer objects (DTOs) that represent tags
 * a user can apply to content.
 */
public class ContentTag extends Tag {

	private final Content content;
	private final long beginByteOffset;
	private final long endByteOffset;

	// Clients of the org.sleuthkit.datamodel package should not directly create these objects.
	ContentTag(long tagID, Content content, TagName name, String comment, long beginByteOffset, long endByteOffset, String userName) {
		super(tagID, name, comment, userName);
		this.content = content;
		this.beginByteOffset = beginByteOffset;
		this.endByteOffset = endByteOffset;
	}

	/**
	 * Return the tagged content
	 * 
	 * @return tagged content
	 */
	public Content getContent() {
		return content;
	}
	
	/**
	 * Returns whether the tag has a byte range
	 * 
	 * @return true if the tag has a byte range, false otherwise
	 */
	public boolean hasByteExtent() {
		return (beginByteOffset > 0) && (endByteOffset > 0) && (endByteOffset > beginByteOffset);
	}

	/**
	 * Returns starting offset of the byte range
	 * 
	 * @return start offset 
	 */
	public long getBeginByteOffset() {
		return beginByteOffset;
	}

	/**
	 * Returns end offset of the byte range
	 * 
	 * @return end offset 
	 */
	public long getEndByteOffset() {
		return endByteOffset;
	}
}
