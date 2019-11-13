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

/**
 *
 * An interface implemented by message attachments.
 */
public interface Attachment {

	/**
	 * Returns location of an attachment - a path or a URL.
	 *
	 * @return String representing location of attachment.
	 */
	String getLocation();

	/*
	 * Returns object id of the attachment file.
	 *
	 * @return Object id of attachment, may be null if not available or
	 * not applicable.
	 */
	Long getObjId();

}
