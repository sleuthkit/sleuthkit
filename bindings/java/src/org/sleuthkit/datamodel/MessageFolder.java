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
 * This class is used to abstract a message folder in an email container, 
 * like an mbox or pst file
 */
class MessageFolder {
	
	private final long srcObjID;
	private final String pathName;
	private boolean hasSubfolders;
	
	
	public MessageFolder(String pathName, long objID) {
		this(pathName, objID, false);
	}
	
	public MessageFolder(String pathName, long objID, boolean hasSubfolders) {
		this.pathName = pathName;
		this.srcObjID = objID;
		this.hasSubfolders = hasSubfolders;
	}
	
	public String getName() {
		return this.pathName;
	}
	
	public long getSrcOBjID() {
		return this.srcObjID;
	}
	
	public synchronized boolean hasSubfolders() {
		return this.hasSubfolders;
	}
	
	public synchronized void setHasSubfolders(boolean hasSubFolders) {
		this.hasSubfolders = hasSubFolders;
	}
}
