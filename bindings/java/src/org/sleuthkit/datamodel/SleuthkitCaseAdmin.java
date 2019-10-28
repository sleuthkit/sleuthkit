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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * 
 * Class to perform sleuthkit case admin functions
 */
public class SleuthkitCaseAdmin {
	
	private String dbPath = null;
	private String caseName = null;
	private CaseDbConnectionInfo info = null;
	private String caseDirPath = null;
	private final SleuthkitCase sleuthkitCase;
	
	public SleuthkitCaseAdmin(String dbPath) throws TskCoreException {
	    this.dbPath = dbPath;
		this.sleuthkitCase = SleuthkitCase.openCase(this.dbPath);
		
	}
	
	public SleuthkitCaseAdmin(String caseName, CaseDbConnectionInfo info, String caseDirPath) throws TskCoreException {
		this.caseName = caseName;
		this.info = info;
		this.caseDirPath = caseDirPath;
		this.sleuthkitCase = SleuthkitCase.openCase(this.caseName, this.info, this.caseDirPath);
	}
	
	public void deleteDataSource(Long dataSourceObjId) throws TskCoreException {
	
		try {
            Method m=sleuthkitCase.getClass().getDeclaredMethod("deleteDataSource", long.class);	
		    m.setAccessible(true);
		    m.invoke(sleuthkitCase, dataSourceObjId);
		} catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException ex) {
			throw new TskCoreException("Error deleting data source.", ex);	
		}
	}
}
