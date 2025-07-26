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
import java.util.Collections;

/**
 * Collection of string utility methods for use by CVT, CommunicationsManager
 * and Timeline.
 */
final class CommManagerSqlStringUtils {

	private CommManagerSqlStringUtils() {
	}

	/**
	 * Utility method to convert a list to an CSV string.
	 * 
	 * Null entries in the values collection will be removed before
	 * the string is created.
	 *
	 * @param values - collection of objects .
	 *
	 * @return a CSV string.
	 */
	static <T> String buildCSVString(Collection<T> values) {
		return joinAsStrings(values, ",");
	}

	/**
	 * Utility method to join a collection into a string using a supplied
	 * separator. Null entries in the values collection will be removed before
	 * the string is created.
	 *
	 * @param <T>       The type of the values in the collection to be joined
	 * @param values    The collection to be joined
	 * @param separator The separator to insert between each value in the result
	 *                  string
	 *
	 * @return a string with the elements of values separated by separator
	 */
	static <T> String joinAsStrings(Collection<T> values, String separator) {
		if (values == null || values.isEmpty()) {
			return "";
		}
		
		values.removeAll(Collections.singleton(null));
		
		return org.apache.commons.lang3.StringUtils.join(values, separator);
	}
}
