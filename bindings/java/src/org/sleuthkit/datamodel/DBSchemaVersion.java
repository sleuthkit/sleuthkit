/*
 * Sleuth Kit Data Model
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

import java.util.Comparator;

/**
 * As of TSK 4.5.0 database schema versions are two part: Major.minor. This
 * versioning schema is based on semantic versioning, but without using the
 * patch number.
 *
 * The major part is incremented for incompatible changes, ie, it will not be
 * usable by older version of TSK. For example, the major number should be
 * incremented if tables and/or columns are removed,the meanings of values
 * changes, or new records are added to lookup tables that will not be
 * convertible to Java Enums.
 *
 * The minor version is incremented for compatible changes that are use-able by
 * older versions of TSK, although the new schema may not be fully taken
 * advantage. For example, adding an index should be backwards compatible: the
 * old version will still be able to open and use the db, but query performance
 * may or may not be affected. Also, adding a column to a table should be
 * backwards compatible as old versions should simply ignore it.
 */
public class DBSchemaVersion implements Comparable<DBSchemaVersion> {

	/**
	 * Comparator that compares DBSchemaVersions, first by major number, and
	 * then by minor number in case of equal major numbers.
	 */
	private static final Comparator<DBSchemaVersion> VERSION_COMPARATOR = new Comparator<DBSchemaVersion>() {

		@Override
		public int compare(DBSchemaVersion o1, DBSchemaVersion o2) {
			int majorComp = Integer.compare(o1.getMajor(), o2.getMajor());
			if (majorComp != 0) {
				return majorComp;
			} else {
				return Integer.compare(o1.getMinor(), o2.getMinor());
			}
		}
	};

	private final int major;
	private final int minor;

	public DBSchemaVersion(int majorVersion, int minorVersion) {
		major = majorVersion;
		minor = minorVersion;
	}

	public int getMajor() {
		return major;
	}

	public int getMinor() {
		return minor;
	}

	@Override
	public String toString() {
		return major + "." + minor;
	}

	@Override
	public int compareTo(DBSchemaVersion vs) {
		return VERSION_COMPARATOR.compare(this, vs);
	}

	@Override
	public int hashCode() {
		int hash = 5;
		hash = 53 * hash + this.major;
		hash = 53 * hash + this.minor;
		return hash;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		final DBSchemaVersion other = (DBSchemaVersion) obj;
		return this.compareTo(other) == 0;
	}
}
