/*
 * SleuthKit Java Bindings
 *
 * Copyright 2020 Basis Technology Corp.
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

import java.util.List;

/**
 * Interface for sending information directly from a data source processors 
 * to the ingest pipeline.
 */
public interface AddDataSourceCallbacks {
	/**
	 * Call when the data source has been completely added to the case database.
	 * 
	 * @param dataSourceObjectId The object ID of the new data source
	 * 
	 * @throws AddDataSourceCallbacksException 
	 */
	void onDataSourceAdded(long dataSourceObjectId) throws AddDataSourceCallbacksException;
	
	/**
	 * Call to add a set of file object IDs that are ready for ingest.
	 * 
	 * @param fileObjectIds List of file object IDs.
	 * 
	 * @throws AddDataSourceCallbacksException 
	 */
	void onFilesAdded(List<Long> fileObjectIds) throws AddDataSourceCallbacksException;
}
