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
package org.sleuthkit.datamodel.filerepository;

import java.util.Collections;
import java.util.Map;
import org.sleuthkit.datamodel.AbstractFile;

/**
 * Container for bulk existence results.
 */
public class BulkExistenceResult {
	
	private Map<String, BulkExistenceEnum> files;
	
	/**
	 * Checks the status of a file in this container. It is assumed that the
	 * file is contained within response, otherwise a null value is returned.
	 * 
	 * @param file File to test
	 * @return 
	 */
	public BulkExistenceEnum getResult(AbstractFile file) {
		if (file.getSha256Hash() == null || file.getSha256Hash().isEmpty()) {
			return BulkExistenceEnum.INVALID;
		}
		
		return files.get(file.getSha256Hash());
	}
	
	void setFiles(Map<String, BulkExistenceEnum> files) {
		this.files = Collections.unmodifiableMap(files);
	}
}
