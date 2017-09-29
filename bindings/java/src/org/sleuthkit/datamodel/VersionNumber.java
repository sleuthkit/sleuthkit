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

/**
 * A version number consisting of three parts: Major.Minor.Patch. The compareTo
 * method implements numerical ordering with decreasing precedence from left to 
 * right, e.g., 1.0.0 < 2.0.0 < 2.1.0 < 2.1.1.
 */
public class VersionNumber implements Comparable<VersionNumber> {

	private final int major;
	private final int minor;
	private final int patch;

	public VersionNumber(int majorVersion, int minorVersion, int patchVersion) {
		major = majorVersion;
		minor = minorVersion;
		patch = patchVersion;
	}

	public int getMajor() {
		return major;
	}

	public int getMinor() {
		return minor;
	}

	public int getPatch() {
		return patch;
	}

	@Override
	public String toString() {
		return major + "." + minor + "." + patch;
	}

	@Override
	public int compareTo(VersionNumber vs) {
		int majorComp = Integer.compare(this.getMajor(), vs.getMajor());
		if (majorComp != 0) {
			return majorComp;
		} else {
			final int minorCompare = Integer.compare(this.getMinor(), vs.getMinor());
			if (minorCompare != 0) {
				return minorCompare;
			} else {
				return Integer.compare(this.getPatch(), vs.getPatch());
			}
		}
	}

	@Override
	public int hashCode() {
		int hash = 3;
		hash = 97 * hash + this.major;
		hash = 97 * hash + this.minor;
		hash = 97 * hash + this.patch;
		return hash;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		final VersionNumber other = (VersionNumber) obj;
		return this.major == other.getMajor()
				&& this.minor == other.getMinor()
				&& this.patch == other.getPatch();
	}
}
