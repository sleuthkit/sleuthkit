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
 * Collection of string utility methods.
 * 
 */
class StringUtils {
	
	/**
	 * Utility method to convert a list to an CSV string.
	 * 
	 * @param values - collection of objects .
	 * 
	 * @return a CSV string.
	 */
	static <T> String buildCSVString(Collection<T> values) {
		if (values == null || values.isEmpty()) {
			return "";
		}

		StringBuilder result = new StringBuilder();
		for (T val : values) {
			result.append(val);
			result.append(",");
		}

		return result.substring(0, result.length() - 1);
	}
}
