/*
 * Sleuth Kit Data Model
 *
 * Copyright 2014 Basis Technology Corp.
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
package org.sleuthkit.datamodel;

/**
 * Used to pass info about a hash so that it can be added into the TSK-db from
 * Autopsy. HashHitInfo is for the reverse direction.
 */
public class HashEntry {

	private String fileName;
	private String md5Hash;
	private String sha1Hash;
	private String sha256Hash;
	private String comment;

	public HashEntry(String fileName, String md5Hash, String sha1Hash, String sha256Hash, String comment) {
		this.fileName = fileName;
		this.md5Hash = md5Hash;
		this.sha1Hash = sha1Hash;
		this.sha256Hash = sha256Hash;
		this.comment = comment;
	}

	public String getFileName() {
		return fileName;
	}

	public String getMd5Hash() {
		return md5Hash;
	}

	public String getSha1Hash() {
		return sha1Hash;
	}

	public String getSha256Hash() {
		return sha256Hash;
	}

	public String getComment() {
		return comment;
	}
}
