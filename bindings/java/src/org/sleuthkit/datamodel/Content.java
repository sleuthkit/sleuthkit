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
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import java.util.ArrayList;
import java.util.List;

/**
 * Interface for all datatypes that can be found in the database.
 */
public interface Content extends SleuthkitVisitableItem{
	
	/**
	 * read data from the content in the sleuthkit
	 * @param buf a character array of data (in bytes)
	 * @param offset offset to start reading from
	 * @param len amount of data to read (in bytes)
	 * @return num of bytes read, or -1 on error
	 * @throws TskException  
	 */
	public int read(byte[] buf, long offset, long len) throws TskException;

	/**
	 * get the size of the content
	 * @return size of the content
	 */
	public long getSize();

	/**
	 * visitor pattern support
	 * @param <T> visitor return type
	 * @param v visitor
	 * @return visitor return value
	 */
	public <T> T accept(ContentVisitor<T> v);
	
    /**
     * Does this parent always have exactly one child?
     * @return True if the getChildren function is one-to-one
     */
    public boolean isOnto();
	
	/**
	 * Gets the content object id.
	 * @return object id
	 */
	public long getId();
	
	/**
	 * Gets the child contents.
	 * @return List of children
	 * @throws TskException
	 */
	public List<Content> getChildren() throws TskException;
	/**
	 * Add an artifact associated with this content to the blackboard
	 * @param artifactTypeID id of the artifact type (if the id doesn't already exist
	 * an error will be thrown)
	 * @return the blackboard artifact (the artifact type id can be looked up from this)
	 * @throws TskException
	 */
	public BlackboardArtifact newArtifact(int artifactTypeID) throws TskException;
	
	/**
	 * Add an artifact associated with this content to the blackboard
	 * @param type artifact type enum 
	 * @return the blackboard artifact 
	 * @throws TskException
	 */
	public BlackboardArtifact newArtifact(BlackboardArtifact.ARTIFACT_TYPE type) throws TskException;
	
	/**
	 * Get all artifacts associated with this content that have the given type name
	 * @param artifactTypeName name of the type to look up
	 * @return a list of blackboard artifacts
	 * @throws TskException
	 */
	public ArrayList<BlackboardArtifact> getArtifacts(String artifactTypeName) throws TskException;
	
	/**
	 * Get all artifacts associated with this content that have the given type id
	 * @param artifactTypeID type id to look up
	 * @return a list of blackboard artifacts
	 * @throws TskException
	 */
	public ArrayList<BlackboardArtifact> getArtifacts(int artifactTypeID) throws TskException;
	
	/**
	 * Get all artifacts associated with this content that have the given type
	 * @param type type to look up
	 * @return a list of blackboard artifacts
	 * @throws TskException
	 */
	public ArrayList<BlackboardArtifact> getArtifacts(BlackboardArtifact.ARTIFACT_TYPE type) throws TskException;
	
	/**
	 * Get all artifacts associated with this content
	 * @return a list of blackboard artifacts
	 * @throws TskException
	 */
	public ArrayList<BlackboardArtifact> getAllArtifacts() throws TskException;
}
