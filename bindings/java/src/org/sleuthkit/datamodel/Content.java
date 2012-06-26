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

import java.util.ArrayList;
import java.util.List;

/**
 * Interface for all datatypes that can be found in the database.
 */
public interface Content extends SleuthkitVisitableItem{
    
    /**
     * Read data from the content object 
     * @param buf a character array of data (in bytes) to copy read data to 
     * @param offset offset in the content to start reading from
     * @param len amount of data to read (in bytes)
     * @return num of bytes read, or -1 on error
     * @throws TskCoreException if critical error occurred during read in the tsk core
     */
    public int read(byte[] buf, long offset, long len) throws TskCoreException;
    
    /**
     * Get the size of the content
     * @return size of the content
     */
    public long getSize();
    
    /**
     * Visitor pattern support
     * @param v visitor supplying an algorithm to run on the content object
     * @return visitor return value resulting from running the algorithm
     */
    public <T> T accept(ContentVisitor<T> v);
    
    /**
     * Get the name of this content object
     * @return the name
     */
    public String getName();
    
    /**
     * Gets the content object id.
     * @return object id
     */
    public long getId();
	
	/**
	 * Get the root image
	 * @return image
	 * @throws TskCoreException if critical error occurred within tsk core
	 */
	public Image getImage() throws TskCoreException;
    
    /**
     * Gets the child content objects of this content.
	 * 
     * @return List of children
     * @throws TskCoreException if critical error occurred within tsk core
     */
    public List<Content> getChildren() throws TskCoreException;
    
    /**
     * Create and add an artifact associated with this content to the blackboard
	 * 
     * @param artifactTypeID id of the artifact type (if the id doesn't already exist
     * an exception will be thrown)
     * @return the blackboard artifact created (the artifact type id can be looked up from this)
     * @throws TskCoreException if critical error occurred within tsk core
     */
    public BlackboardArtifact newArtifact(int artifactTypeID) throws TskCoreException;
    
    /**
     * Create and add an artifact associated with this content to the blackboard
	 * 
     * @param type artifact enum tyoe
     * @return the blackboard artifact created (the artifact type id can be looked up from this)
     * @throws TskCoreException if critical error occurred within tsk core
     */
    public BlackboardArtifact newArtifact(BlackboardArtifact.ARTIFACT_TYPE type) throws TskCoreException;
    
    /**
     * Get all artifacts associated with this content that have the given type name
	 * 
     * @param artifactTypeName name of the type to look up
     * @return a list of blackboard artifacts matching the type
     * @throws TskCoreException if critical error occurred within tsk core
     */
    public ArrayList<BlackboardArtifact> getArtifacts(String artifactTypeName) throws TskCoreException;
    
    /**
     * Get all artifacts associated with this content that have the given type id
	 * 
     * @param artifactTypeID type id to look up
     * @return a list of blackboard artifacts matching the type
     * @throws TskCoreException if critical error occurred within tsk core
     */
    public ArrayList<BlackboardArtifact> getArtifacts(int artifactTypeID) throws TskCoreException;
    
    /**
     * Get all artifacts associated with this content that have the given type
	 * 
     * @param type type to look up
     * @return a list of blackboard artifacts matching the type
     * @throws TskCoreException if critical error occurred within tsk core
     */
    public ArrayList<BlackboardArtifact> getArtifacts(BlackboardArtifact.ARTIFACT_TYPE type) throws TskCoreException;
    
    /**
     * Get all artifacts associated with this content
	 * 
     * @return a list of blackboard artifacts
     * @throws TskCoreException if critical error occurred within tsk core
     */
    public ArrayList<BlackboardArtifact> getAllArtifacts() throws TskCoreException;
}
