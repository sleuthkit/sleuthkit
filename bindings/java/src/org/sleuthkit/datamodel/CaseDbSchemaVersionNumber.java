/*
 * Sleuth Kit Data Model
 *
 * Copyright 2017 Basis Technology Corp.
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
 * As of SleuthKit 4.5.0 database schema versions are two part: Major.Minor. 
 * This versioning schema is based on semantic versioning, but without using the
 * patch number (in practice it is always the default value of zero for case database versions).
 *
 * The major part is incremented for incompatible changes, i.e., the case 
 * database will not be usable by an older version. For example, the major 
 * number should be incremented if tables and/or columns are removed, the 
 * meanings of values changes, or new records are added to lookup tables 
 * that will not be convertible to older versions of the corresponding Java 
 * enums.
 *
 * The minor version is incremented for compatible changes that are usable by
 * older versions of the SleuthKit, although the new schema may not be fully taken
 * advantage of. For example, adding an index should be backwards compatible: 
 * an older version of the software will still be able to open and use the case database, but
 * query performance may or may not be affected. Also, adding a column to a
 * table should be backwards compatible as older versions of the software should
 * simply ignore it.
 */
public final class CaseDbSchemaVersionNumber extends VersionNumber {

	/**
	 * Constructor for CaseDBSchemaVersionNumber. The patch version is unused
	 * and immutably 0.
	 *
	 * @param majorVersion The major version part.
	 * @param minorVersion The minor version part.
	 */
	public CaseDbSchemaVersionNumber(int majorVersion, int minorVersion) {
		super(majorVersion, minorVersion, 0);
	}

	/**
	 * Is a database with the given schema version openable by this version
	 * number?
	 *
	 * @param dbSchemaVersion The schema version of the db want to check for
	 *                        compatibility.
	 *
	 * @return true if the db schema version is compatible with this version.
	 */
	public boolean isCompatible(CaseDbSchemaVersionNumber dbSchemaVersion) {
		/*
		 * Since we provide upgrade paths for schema versions greater than 1, this
	         * amounts to checking if the major version part is greater than 1 and less
	         * than this version's major number.
	         */
		final int dbMajor = dbSchemaVersion.getMajor();
		return 1 < dbMajor && dbMajor <= getMajor();
	}

	@Override
	public String toString() {
		return getMajor() + "." + getMinor();
	}
}
