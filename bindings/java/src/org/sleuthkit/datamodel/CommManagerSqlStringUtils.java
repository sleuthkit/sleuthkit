/*
 * Sleuth Kit Data Model
 *
 * Copyright 2017-18 Basis Technology Corp.
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

import java.util.Collection;

/**
 * Collection of string utility methods for use by CVT, CommunicationsManager
 * and Timeline.
 */
final class CommManagerSqlStringUtils {

	private CommManagerSqlStringUtils() {
	}

	/**
	 * Builds a comma-separated string of Long values safe for use in a SQL
	 * IN-clause. Each value is serialized as its numeric decimal representation.
	 * Null elements are skipped.
	 *
	 * @param values Collection of Long values.
	 *
	 * @return A comma-separated numeric string, or empty string if no values.
	 */
	static String buildLongCSVString(Collection<Long> values) {
		if (values == null || values.isEmpty()) {
			return "";
		}
		StringBuilder sb = new StringBuilder();
		for (Long val : values) {
			if (val == null) {
				continue;
			}
			if (sb.length() > 0) {
				sb.append(",");
			}
			sb.append(val.longValue());
		}
		return sb.toString();
	}

	/**
	 * Builds a comma-separated string of Integer values safe for use in a SQL
	 * IN-clause. Each value is serialized as its numeric decimal representation.
	 * Null elements are skipped.
	 *
	 * @param values Collection of Integer values.
	 *
	 * @return A comma-separated numeric string, or empty string if no values.
	 */
	static String buildIntCSVString(Collection<Integer> values) {
		if (values == null || values.isEmpty()) {
			return "";
		}
		StringBuilder sb = new StringBuilder();
		for (Integer val : values) {
			if (val == null) {
				continue;
			}
			if (sb.length() > 0) {
				sb.append(",");
			}
			sb.append(val.intValue());
		}
		return sb.toString();
	}
}
