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
 * Content objects make up a tree and each object can have a parent
 * and children.  For example, the child of an Image object is a 
 * Volume or File System.  This interface defines the basic methods for
 * reading the content associated with this object, the parent and children,
 * and adding artifacts. 
 */
public interface Content extends SleuthkitVisitableItem {

	/**
	 * Reads data that this content object is associated with (file contents, 
	 * volume contents, etc.).
	 *
	 * @param buf a character array of data (in bytes) to copy read data to
	 * @param offset byte offset in the content to start reading from
	 * @param len number of bytes to read into buf. 
	 * @return num of bytes read, or -1 on error
	 * @throws TskCoreException if critical error occurred during read in the
	 * tsk core
	 */
	public int read(byte[] buf, long offset, long len) throws TskCoreException;
	
	/**
	 * Free native resources after read is done on the Content object.  
	 * After closing, read can be called again on the same Content object,
	 * which should result in re-opening of new native resources.
	 */
	public void close();

	/**
	 * Get the (reported) size of the content object and, in theory, how
	 * much you should be able to read from it.  In some cases, data corruption
	 * may mean that you cannot read this much data.
	 *
	 * @return size of the content
	 */
	public long getSize();

	/**
	 * Visitor pattern support
	 *
	 * @param v visitor supplying an algorithm to run on the content object
	 * @return visitor return value resulting from running the algorithm
	 */
	public <T> T accept(ContentVisitor<T> v);

	/**
	 * Get the name of this content object (does not include parent path)
	 *
	 * @return the name
	 */
	public String getName();
	
	/**
	 * @return returns the full path to this Content object starting with a "/"
	 * followed by the Image name and similarly for all other segments in the
	 * hierarchy.
	 */
	public String getUniquePath() throws TskCoreException;

	/**
	 * Returns the unique object ID that was assigned to it in the database.
	 * This is a Sleuth Kit database-assigned number.
	 *
	 * @return object id
	 */
	public long getId();

	/**
	 * Get the root image of this content, of null if there is no image associated with this content
	 * (such as for LocalFile)
	 *
	 * @return image associated with this Content or null if there isn't any
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
	 * Returns true if the content object has children objects.
	 * Note, this should be more efficient than getting children and checking it empty.
	 * 
	 * @return true if has children, false otherwise.
	 * @throws TskCoreException if critical error occurred within tsk core
	 */
	public boolean hasChildren() throws TskCoreException;
	
	/**
	 * Returns count of children objects.
	 * Note, this should be more efficient than getting children and counting them.
	 * 
	 * @return children count
	 * @throws TskCoreException if critical error occurred within tsk core
	 */
	public int getChildrenCount() throws TskCoreException;
	
	/**
	 * @return returns the parent of this Content object or null if there isn't
	 * one as is the case for Image.
	 * @throws TskCoreException 
	 */
	public Content getParent() throws TskCoreException;

	/**
	 * Gets the child content ids of this content.
	 *
	 * @return List of children ids
	 * @throws TskCoreException if critical error occurred within tsk core
	 */
	public List<Long> getChildrenIds() throws TskCoreException;

	/**
	 * Create and add an artifact associated with this content to the blackboard
	 *
	 * @param artifactTypeID id of the artifact type (if the id doesn't already
	 * exist an exception will be thrown)
	 * @return the blackboard artifact created (the artifact type id can be
	 * looked up from this)
	 * @throws TskCoreException if critical error occurred within tsk core
	 */
	public BlackboardArtifact newArtifact(int artifactTypeID) throws TskCoreException;

	/**
	 * Create and add an artifact associated with this content to the blackboard
	 *
	 * @param type artifact enum tyoe
	 * @return the blackboard artifact created (the artifact type id can be
	 * looked up from this)
	 * @throws TskCoreException if critical error occurred within tsk core
	 */
	public BlackboardArtifact newArtifact(BlackboardArtifact.ARTIFACT_TYPE type) throws TskCoreException;

	/**
	 * Get all artifacts associated with this content that have the given type
	 * name
	 *
	 * @param artifactTypeName name of the type to look up
	 * @return a list of blackboard artifacts matching the type
	 * @throws TskCoreException if critical error occurred within tsk core
	 */
	public ArrayList<BlackboardArtifact> getArtifacts(String artifactTypeName) throws TskCoreException;

	
	/**
	 * Return the TSK_GEN_INFO artifact for the file so that individual attributes 
	 * can be added to it.
	 * 
	 * @returna Instance of the TSK_GEN_INFO artifact
	 * @throws TskCoreException 
	 */
	public BlackboardArtifact getGenInfoArtifact() throws TskCoreException;
	
	/**
	 * Get all artifacts associated with this content that have the given type
	 * id
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
	
	
	
	/**
	 * Get count of all artifacts associated with this content that have the given type
	 * name
	 *
	 * @param artifactTypeName name of the type to look up
	 * @return count of blackboard artifacts matching the type
	 * @throws TskCoreException if critical error occurred within tsk core
	 */
	public long getArtifactsCount(String artifactTypeName) throws TskCoreException;

	/**
	 * Get count of all artifacts associated with this content that have the given type
	 * id
	 *
	 * @param artifactTypeID type id to look up
	 * @return count of blackboard artifacts matching the type
	 * @throws TskCoreException if critical error occurred within tsk core
	 */
	public long getArtifactsCount(int artifactTypeID) throws TskCoreException;

	/**
	 * Get count of all artifacts associated with this content that have the given type
	 *
	 * @param type type to look up
	 * @return count of blackboard artifacts matching the type
	 * @throws TskCoreException if critical error occurred within tsk core
	 */
	public long getArtifactsCount(BlackboardArtifact.ARTIFACT_TYPE type) throws TskCoreException;

	/**
	 * Get count of all artifacts associated with this content
	 *
	 * @return count of all blackboard artifacts for this content
	 * @throws TskCoreException if critical error occurred within tsk core
	 */
	public long getAllArtifactsCount() throws TskCoreException;
}
