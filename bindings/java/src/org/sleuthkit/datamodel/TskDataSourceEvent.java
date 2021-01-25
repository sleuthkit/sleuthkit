/*
 * Sleuth Kit Data Model
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

/**
 *
 * Defines an interface implemented by data source specific events published by
 * Sleuthkit. These events are applicable to single data source.
 */
public interface TskDataSourceEvent {

	/**
	 * Returns the object id of the data source that the event pertains to.
	 *
	 * All data in an event should pertain to a single data source.
	 *
	 * @return Data source object id.
	 */
	public long getDataSourceId();
}
