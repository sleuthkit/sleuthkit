/*
 * Sleuth Kit Data Model
 *
 * Copyright 2013 Basis Technology Corp.
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

import java.util.ArrayList;

/**
 * Used to transmit hashDb information about a particular file from TSK to Autopsy 
 */
public class HashInfo {
	private String hashMd5;
	private String hashSha1;
	private String hashSha2_256;
    private ArrayList<String> names = new ArrayList<String>();
	private ArrayList<String> comments = new ArrayList<String>();

	/**
	 * Default constructor when error message is not available
	 */
	public HashInfo(String hashMd5, String hashSha1, String hashSha2_256) {
		this.hashMd5 = hashMd5;
		this.hashSha1 = hashSha1;
		this.hashSha2_256 = hashSha2_256;
	}
	
    public void addName(String name) {
        names.add(name);
    }
    
    public void addComment(String comment) {
        comments.add(comment);
    }	
	
	public String getHashMd5() {
		return hashMd5;
	}
	
	public String getHashSha1() {
		return hashSha1;
	}
	
	public String getHashSha2() {
		return hashSha2_256;
	}	
	
	public ArrayList<String> getNames() {
		return names;
	}
	
	public ArrayList<String> getComments() {
		return comments;
	}
}
