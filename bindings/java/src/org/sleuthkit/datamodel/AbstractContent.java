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
import org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE;

/**
 * Implements some general methods from the Content interface 
 * common across many content sub types
 */
public abstract class AbstractContent implements Content {

    private SleuthkitCase db;
    private long objId;
    private String name;
    
    protected AbstractContent(SleuthkitCase db, long obj_id, String name) {
        this.db = db;
        this.objId = obj_id;
        this.name = name;
    }
    

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public long getId() {
        return this.objId;
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
        if (this.objId != other.objId) {
            return false;
        }
        return true;
    }
    
    @Override
    public int hashCode() {
        int hash = 7;
        hash = 41 * hash + (int) (this.objId ^ (this.objId >>> 32));
        return hash;
    }
    

	@Override
	public BlackboardArtifact newArtifact(int artifactTypeID) throws TskCoreException{
		return db.newBlackboardArtifact(artifactTypeID, objId);
	}
	
	

	@Override
	public BlackboardArtifact newArtifact(BlackboardArtifact.ARTIFACT_TYPE type) throws TskCoreException{
		return db.newBlackboardArtifact(type, objId);
	}
	

	@Override
	public ArrayList<BlackboardArtifact> getArtifacts(String artifactTypeName) throws TskCoreException{
		return db.getBlackboardArtifacts(artifactTypeName, objId);
	}
	

	@Override
	public ArrayList<BlackboardArtifact> getArtifacts(int artifactTypeID) throws TskCoreException{
		return db.getBlackboardArtifacts(artifactTypeID, objId);
	}
	

	@Override
	public ArrayList<BlackboardArtifact> getArtifacts(BlackboardArtifact.ARTIFACT_TYPE type) throws TskCoreException{
		return db.getBlackboardArtifacts(type, objId);
	}
	

	@Override
	public ArrayList<BlackboardArtifact> getAllArtifacts() throws TskCoreException{
		return db.getMatchingArtifacts("WHERE obj_id = " + objId);
	}

	@Override
	public long getArtifactsCount(String artifactTypeName) throws TskCoreException {
		return db.getBlackboardArtifactsCount(artifactTypeName, objId);
	}

	@Override
	public long getArtifactsCount(int artifactTypeID) throws TskCoreException {
		return db.getBlackboardArtifactsCount(artifactTypeID, objId);
	}

	@Override
	public long getArtifactsCount(ARTIFACT_TYPE type) throws TskCoreException {
		return db.getBlackboardArtifactsCount(type, objId);
	}

	@Override
	public long getAllArtifactsCount() throws TskCoreException {
		return db.getBlackboardArtifactsCount(objId);
	}
	
	
}
