/*
 * Sleuth Kit Data Model
 *
 * Copyright 2019 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel.blackboardutils;

import java.util.Collection;
import java.util.Collections;

/**
 * Class to represent attachments to a message.
 *
 * Attachments can be URL attachments or file attachments.
 *
 */
public final class MessageAttachments {

	private final Collection<FileAttachment> fileAttachments;
	private final Collection<URLAttachment> urlAttachments;

	/**
	 * Builds Message attachments from the given file attachments and URL
	 * attachments.
	 *
	 * @param fileAttachments Collection of file attachments.
	 * @param urlAttachments  Collection of URL attachments.
	 */
	public MessageAttachments(Collection<FileAttachment> fileAttachments, Collection<URLAttachment> urlAttachments) {
		this.fileAttachments = fileAttachments;
		this.urlAttachments = urlAttachments;
	}

	/**
	 * Returns collection of file attachments.
	 *
	 * @return Collection of File attachments.
	 */
	public Collection<FileAttachment> getFileAttachments() {
		return Collections.unmodifiableCollection(fileAttachments);
	}

	/**
	 * Returns collection of URL attachments.
	 *
	 * @return Collection of URL attachments.
	 */
	public Collection<URLAttachment> getUrlAttachments() {
		return Collections.unmodifiableCollection(urlAttachments);
	}

	/**
	 * Returns total count of attachments.
	 * 
	 * @return Count of attachments.
	 */
	public int getAttachmentsCount() {
		return (fileAttachments.size() + urlAttachments.size());
	}
}
