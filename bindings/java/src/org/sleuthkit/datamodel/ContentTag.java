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

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Instances of this class are data transfer objects (DTOs) that represent tags 
 * a user can apply to Content objects.
 */
public class ContentTag extends Tag {
	private final Content content;
	private final long beginByteOffset;
	private final long endByteOffset;
					
	public ContentTag(Content content, TagType type, String comment, long beginByteOffset, long endByteOffset) throws IllegalArgumentException {
		super(type, comment);

			if (null == content) {
				throw new IllegalArgumentException("content is null");
			}
			this.content = content;

			if ((beginByteOffset < 0) || (beginByteOffset > (content.getSize() - 1))) {				
				StringBuilder message = new StringBuilder("beginByteOffset (= ").append(beginByteOffset).append(") is out of range 0 - ").append(content.getSize() - 1);
				addContentPath(content, message);
				throw new IllegalArgumentException(message.toString());			
			}

			if (endByteOffset < 0 || endByteOffset > content.getSize() - 1) {
				StringBuilder message = new StringBuilder("endByteOffset (= ").append(beginByteOffset).append(") is out of range 0 - ").append(content.getSize() - 1);
				addContentPath(content, message);
				throw new IllegalArgumentException(message.toString());			
			}

			if (endByteOffset < beginByteOffset) {
				StringBuilder message = new StringBuilder("endByteOffset (= ").append(endByteOffset).append(" is less than beginByteOffset (= ").append(beginByteOffset).append(")");
				throw new IllegalArgumentException(message.toString());			
			}
			this.beginByteOffset = beginByteOffset;
			this.endByteOffset = endByteOffset;				
	}
	
	private void addContentPath(Content content, StringBuilder errorMessage) {
		try {
			String path = content.getUniquePath();
			if (!path.isEmpty()) {
				errorMessage.append(" for ").append(path);
			}
		}
		catch (TskCoreException ex) {
			Logger.getLogger(ContentTag.class.getName()).log(Level.SEVERE, "failed to get unique path for Content object", ex);
		}		
	}
	
	public Content getContent() {
		return content;
	}	
	
	public long getBeginByteOffset() {
		return beginByteOffset;
	}

	public long getEndByteOffset() {
		return endByteOffset;
	}		
}
