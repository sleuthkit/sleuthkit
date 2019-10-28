/*
 * Sleuth Kit Data Model
 *
 * Copyright 2019 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

/**
 * Utility methods for administering a case database.
 */
public class SleuthkitCaseAdmin {

	/**
	 * Deletes a data source from a case database.
	 *
	 * @param caseDB          The case database.
	 * @param dataSourceObjID The object ID of the data source to be deleted.
	 *
	 * @throws TskCoreException If there is an error deleting the data source.
	 */
	public static void deleteDataSource(SleuthkitCase caseDB, long dataSourceObjID) throws TskCoreException {
		caseDB.deleteDataSource(dataSourceObjID);
	}

	/**
	 * Prevent instantiation of this utility class.
	 */
	private SleuthkitCaseAdmin() {
	}

}
