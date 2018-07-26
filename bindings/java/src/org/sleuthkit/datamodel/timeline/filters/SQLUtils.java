/*
 * Sleuth Kit Data Model
 *
 * Copyright 2018 Basis Technology Corp.
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
package org.sleuthkit.datamodel.timeline.filters;

import org.sleuthkit.datamodel.SleuthkitCase;

/**
 *
 */
final class SQLUtils {

	private SQLUtils() {
	}

	static public String getFalseLiteral(SleuthkitCase sleuthkitCase) {
		switch (sleuthkitCase.getDatabaseType()) {
			case POSTGRESQL:
				return "FALSE";
			case SQLITE:
				return "0";
			default:
				throw new UnsupportedOperationException("Unsupported DB type: " + sleuthkitCase.getDatabaseType().name());
		}
	}

	static public String getTrueLiteral(SleuthkitCase sleuthkitCase) {
		switch (sleuthkitCase.getDatabaseType()) {
			case POSTGRESQL:
				return "TRUE";
			case SQLITE:
				return "1";
			default:
				throw new UnsupportedOperationException("Unsupported DB type: " + sleuthkitCase.getDatabaseType().name());
		}
	}

}
