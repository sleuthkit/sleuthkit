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

/**
 * Unit level filter.
 */
public interface SubFilter {

	/**
	 * Returns a string description of the filter.
	 *
	 * @return	A string description of the filter.
	 */
	public String getDescription();

	/**
	 * Get the SQL string for the filter.
	 *
	 * @param commsManager Communications manager.
	 *
	 * @return SQL String for the filter.
	 */
	public String getSQL(CommunicationsManager commsManager);
}
