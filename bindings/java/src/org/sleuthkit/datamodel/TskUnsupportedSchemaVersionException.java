/*
 * SleuthKit Java Bindings
 *
 * Copyright 2011-2017 Basis Technology Corp.
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
 * Subtype of TskCoreException that is thrown when attempting to open a database
 * with an unsupported schema version.
 */
public class TskUnsupportedSchemaVersionException extends TskCoreException {

	private static final long serialVersionUID = 1L;
	private final SchemaVersionNumber unsupportedVersion;
	private final SchemaVersionNumber currentVersion;

	/**
	 * Constructor.
	 *
	 * @param unsupportedVer The schema version of the db that couldn't be
	 *                       opened.
	 * @param currentVer     The current schema version in the code.
	 * @param msg            A message with details.
	 */
	TskUnsupportedSchemaVersionException(SchemaVersionNumber unsupportedVer, SchemaVersionNumber currentVer, String msg) {
		super(msg);
		this.unsupportedVersion = unsupportedVer;
		this.currentVersion = currentVer;
	}

	/**
	 * Get the version of the schema used by the db that we attempted to open.
	 *
	 * @return The version of the schema used by the db that we attempted to
	 *         open.
	 */
	public SchemaVersionNumber getUnsupportedVersion() {
		return unsupportedVersion;
	}

	/**
	 * The current version of the schema that the code uses.
	 *
	 * @return The current version of the schema that the code uses.
	 */
	public SchemaVersionNumber getCurrentVersion() {
		return currentVersion;
	}
}
