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
 *
 */
public class TskUnsupportedSchemaVersionException extends TskCoreException {

	private static final long serialVersionUID = 1L;
	private final int majorVersion;

	private final int minorVersion;
	private final int currentMajorVer;
	private final int currentMinorVer;

	TskUnsupportedSchemaVersionException(int unsupportedMajorVer, int unsupportedMinorVer, int currentMajorVer, int currentMinorVer, String msg) {
		super(msg);
		this.majorVersion = unsupportedMajorVer;
		this.minorVersion = unsupportedMinorVer;
		this.currentMajorVer = currentMajorVer;
		this.currentMinorVer = currentMinorVer;
	}

	public int getUnsupportedMajorVersion() {
		return majorVersion;
	}

	public int getUnsupportedMinorVersion() {
		return minorVersion;
	}

	public int getCurrentMajorVer() {
		return currentMajorVer;
	}

	public int getCurrentMinorVer() {
		return currentMinorVer;
	}
}
