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
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE;
import org.sleuthkit.datamodel.SleuthkitCase.ObjectInfo;

/**
 * Implements some general methods from the Content interface common across many
 * content sub types
 */
public abstract class AbstractContent implements Content {

	public final static long UNKNOWN_ID = -1;
	private final SleuthkitCase db;
	private long objId;
	private String name;
	private Content parent;
	private String uniquePath;
	protected long parentId;
	private volatile boolean hasChildren;
	private volatile boolean checkedHasChildren;
	private volatile int childrenCount;
	

	protected AbstractContent(SleuthkitCase db, long obj_id, String name) {
		this.db = db;
		this.objId = obj_id;
		this.name = name;
		this.parentId = UNKNOWN_ID;
		
		checkedHasChildren = false;
		hasChildren = false;
		childrenCount = -1;
	}

	@Override
	public String getName() {
		return this.name;
	}

	/*
	 * This base implementation simply walks the hierarchy appending its own
	 * name to the result of calling its parent's getUniquePath() method (with
	 * interleaving forward slashes).
	 */
	@Override
	public synchronized String getUniquePath() throws TskCoreException {
		if (uniquePath == null) {
			uniquePath = "";
			if (!name.isEmpty()) {
				uniquePath = "/" + getName();
			}

			Content myParent = getParent();
			if (myParent != null) {
				uniquePath = myParent.getUniquePath() + uniquePath;
			}
		}
		return uniquePath;
	}
	
	@Override
	public boolean hasChildren() throws TskCoreException {
		if (checkedHasChildren == true) {
			return hasChildren;
		}
		
		hasChildren = this.getSleuthkitCase().getContentHasChildren(this);
		checkedHasChildren = true;
		
		if (!hasChildren) {
			childrenCount = 0;
		}
		
		return hasChildren;
	}
	
	@Override
	public int getChildrenCount() throws TskCoreException {
		if (childrenCount != -1) {
			return childrenCount;
		}
		
		childrenCount = this.getSleuthkitCase().getContentChildrenCount(this);	
		
		hasChildren = childrenCount > 0;
		checkedHasChildren = true;
		
		return childrenCount;
	}

	@Override
	public synchronized Content getParent() throws TskCoreException {
		if (parent == null) {
			ObjectInfo parentInfo = null;
			try {
				parentInfo = db.getParentInfo(this);
			} catch (TskCoreException ex) {
				// there is not parent; not an error if we've got an Image
				return null;
			}
			parent = db.getContentById(parentInfo.id);
		}
		return parent;
	}

	void setParent(Content parent) {
		this.parent = parent;
	}

	/**
	 * Set the ID of the this AbstractContent's parent
	 *
	 * @param parentId the ID of the parent. Note: use
	 * AbstractContent.UNKNOWN_ID if the parent's ID is not known.
	 */
	void setParentId(long parentId) {
		this.parentId = parentId;
	}

	@Override
	public long getId() {
		return this.objId;
	}

	@Override
	public Image getImage() throws TskCoreException {
		Image image = null;
		Content myParent = getParent();
		if (myParent != null) {
			image = myParent.getImage();
		}
		return image;
	}

	/**
	 * Gets handle of SleuthkitCase to which this content belongs
	 *
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
	public BlackboardArtifact newArtifact(int artifactTypeID) throws TskCoreException {
		return db.newBlackboardArtifact(artifactTypeID, objId);
	}

	@Override
	public BlackboardArtifact newArtifact(BlackboardArtifact.ARTIFACT_TYPE type) throws TskCoreException {
		return db.newBlackboardArtifact(type, objId);
	}

	@Override
	public ArrayList<BlackboardArtifact> getArtifacts(String artifactTypeName) throws TskCoreException {
		return db.getBlackboardArtifacts(artifactTypeName, objId);
	}

	@Override
	public ArrayList<BlackboardArtifact> getArtifacts(int artifactTypeID) throws TskCoreException {
		return db.getBlackboardArtifacts(artifactTypeID, objId);
	}

	@Override
	public ArrayList<BlackboardArtifact> getArtifacts(BlackboardArtifact.ARTIFACT_TYPE type) throws TskCoreException {
		return db.getBlackboardArtifacts(type, objId);
	}
	
	@Override
	public BlackboardArtifact getGenInfoArtifact() throws TskCoreException {
		ArrayList<BlackboardArtifact> arts = getArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_GEN_INFO);
		if (arts.isEmpty()) {
			BlackboardArtifact art = newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_GEN_INFO);
			return art;
		}
		else {
			return arts.get(0);
		}
	}

	@Override
	public ArrayList<BlackboardArtifact> getAllArtifacts() throws TskCoreException {
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

	@Override
	public String toString() {
		return toString(true);
	}

	public String toString(boolean preserveState){
		if (preserveState) {
			return "AbstractContent [\t" + "objId " + String.format("%010d", objId) + "\t" 
					+ "name " + name + "\t" + "parentId " + parentId + "\t" 
					+ "\t" + "checkedHasChildren " + checkedHasChildren 
					+ "\t" + "hasChildren " + hasChildren 
					+ "\t" + "childrenCount " + childrenCount 
					+ "uniquePath " + uniquePath + "]\t";
		} else {
			try {
				if (getParent() != null) {
					return "AbstractContent [\t" + "objId " + String.format("%010d", objId) 
							+ "\t" + "name " + name 
								+ "\t" + "checkedHasChildren " + checkedHasChildren 
								+ "\t" + "hasChildren " + hasChildren 
								+ "\t" + "childrenCount " + childrenCount 
							+ "\t" + "getUniquePath " + getUniquePath() 
							+ "\t" + "getParent " + getParent().getId() + "]\t";
				} else {
					return "AbstractContent [\t" + "objId " 
							+ String.format("%010d", objId) + "\t" + "name " + name 
								+ "\t" + "checkedHasChildren " + checkedHasChildren 
								+ "\t" + "hasChildren " + hasChildren 
								+ "\t" + "childrenCount " + childrenCount 
							+ "\t" + "uniquePath " + getUniquePath() 
							+ "\t" + "parentId " + parentId + "]\t";
				}
			} catch (TskCoreException ex) {
				Logger.getLogger(AbstractContent.class.getName()).log(Level.SEVERE, "Could not find Parent", ex);
				return "AbstractContent [\t" + "objId " + String.format("%010d", objId) + "\t" 
					+ "name " + name + "\t" + "parentId " + parentId + "\t" 
					+ "\t" + "checkedHasChildren " + checkedHasChildren 
					+ "\t" + "hasChildren " + hasChildren 
					+ "\t" + "childrenCount " + childrenCount 
					+ "uniquePath " + uniquePath + "]\t";
			}
		}
	}
}
