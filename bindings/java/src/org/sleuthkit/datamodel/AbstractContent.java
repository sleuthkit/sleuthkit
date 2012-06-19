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
 *  http://www.apache.org/licenses/LICENSE-2.0
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
 * Implements some general methods from the Content interface 
 * common across many content sub types
 */
public abstract class AbstractContent implements Content {

    private SleuthkitCase db;
    private long obj_id;
    private String name;
    
    protected AbstractContent(SleuthkitCase db, long obj_id, String name) {
        this.db = db;
        this.obj_id = obj_id;
        this.name = name;
    }
    
	/**
	 * Gets name associated with the content object
	 * @return the content name 
	 */
    @Override
    public String getName() {
        return this.name;
    }
    
	/**
	 * Gets unique id associated with the content object
	 * @return the content id
	 */
    @Override
    public long getId() {
        return this.obj_id;
    }
    
	/**
	 * Gets handle of SleuthkitCase to which this content belongs
	 * @return the case handle
	 */
    public SleuthkitCase getSleuthkitCase() {
        return db;
    }
    
    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final AbstractContent other = (AbstractContent) obj;
        if (this.obj_id != other.obj_id) {
            return false;
        }
        return true;
    }
    
    @Override
    public int hashCode() {
        int hash = 7;
        hash = 41 * hash + (int) (this.obj_id ^ (this.obj_id >>> 32));
        return hash;
    }
    
	/**
	 * Creates new blackboard artifact for this content
	 * @param artifactTypeID type id of the artifact to create (refer to BlackboardArtifact.ARTIFACT_TYPE)
	 * @return the artifact created
	 */
	@Override
	public BlackboardArtifact newArtifact(int artifactTypeID) throws TskCoreException{
		return db.newBlackboardArtifact(artifactTypeID, obj_id);
	}
	
	
	/**
	 * Creates new blackboard artifact for this content
	 * @param type type of the artifact to create
	 * @return the artifact created
	 */
	@Override
	public BlackboardArtifact newArtifact(BlackboardArtifact.ARTIFACT_TYPE type) throws TskCoreException{
		return db.newBlackboardArtifact(type, obj_id);
	}
	
	/**
	 * Gets all blackboard artifacts (of a given type), associated with this content object
	 * @param artifactTypeName type name of the artifacts to get
	 * @return list of artifacts for this content, matching the type
	 * @throws TskCoreException exception thrown if a critical error occurs in tsk core
	 */
	@Override
	public ArrayList<BlackboardArtifact> getArtifacts(String artifactTypeName) throws TskCoreException{
		return db.getBlackboardArtifacts(artifactTypeName, obj_id);
	}
	
	/**
	 * Gets all blackboard artifacts (of a given type), associated with this content object
	 * 
	 * @param artifactTypeID type of the artifacts to get, refer to BlackboardArtifact.ARTIFACT_TYPE
	 * @return list of artifacts for this content, matching the type
	 * @throws TskCoreException exception thrown if a critical error occurs in tsk core
	 */
	@Override
	public ArrayList<BlackboardArtifact> getArtifacts(int artifactTypeID) throws TskCoreException{
		return db.getBlackboardArtifacts(artifactTypeID, obj_id);
	}
	
	/**
	 * Gets all blackboard artifacts (of a given type), associated with this content object
	 * @param type type of the artifacts to get
	 * @return list of artifacts for this content, matching the type
	 * @throws TskCoreException exception thrown if a critical error occurs in tsk core
	 */
	@Override
	public ArrayList<BlackboardArtifact> getArtifacts(BlackboardArtifact.ARTIFACT_TYPE type) throws TskCoreException{
		return db.getBlackboardArtifacts(type, obj_id);
	}
	
	/**
	 * Gets all blackboard artifacts associated with this content object
	 * @return list of artifacts for this content, matching the type
	 * @throws TskCoreException exception thrown if a critical error occurs in tsk core
	 */
	@Override
	public ArrayList<BlackboardArtifact> getAllArtifacts() throws TskCoreException{
		return db.getMatchingArtifacts("WHERE obj_id = " + obj_id);
	}
}
