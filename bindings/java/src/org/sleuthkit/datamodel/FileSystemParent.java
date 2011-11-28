/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011 Basis Technology Corp.
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
 * Interface for all objects that could be a parent to a FileSystem
 * object. 
 */

public abstract class FileSystemParent extends AbstractContent{
	
	FileSystemParent(SleuthkitCase db, long obj_id) {
		super(db, obj_id);
	}
	
	
	
	/**
	 * get the handle to the sleuthkit image info object
	 * @return the object pointer
	 */
	abstract long getImageHandle() throws TskException;
}
