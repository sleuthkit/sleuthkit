/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011-2016 Basis Technology Corp.
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
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;
import org.sleuthkit.datamodel.SleuthkitCase.ObjectInfo;

/**
 * Implements some general methods from the Content interface common across many
 * content sub types
 */
public abstract class AbstractContent implements Content {

	public final static long UNKNOWN_ID = -1;
	private final SleuthkitCase db;
	private final long objId;
	private final String name;
	private Content parent;
	private String uniquePath;
	protected long parentId;
	private volatile boolean hasChildren;
	private volatile boolean checkedHasChildren;
	private volatile int childrenCount;
	private BlackboardArtifact genInfoArtifact = null;

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

		childrenCount = this.getSleuthkitCase().getContentChildrenCount(this);

		hasChildren = childrenCount > 0;
		checkedHasChildren = true;

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
			ObjectInfo parentInfo;
			try {
				parentInfo = db.getParentInfo(this);
			} catch (TskCoreException ex) {
				// there is not parent; not an error if we've got a data source
				return null;
			}
			parent = db.getContentById(parentInfo.getId());
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
	 *                 AbstractContent.UNKNOWN_ID if the parent's ID is not
	 *                 known.
	 */
	void setParentId(long parentId) {
		this.parentId = parentId;
	}

	@Override
	public long getId() {
		return this.objId;
	}

	/**
	 * Gets all children of this abstract content, if any.
	 *
	 * @return A list of the children.
	 *
	 * @throws TskCoreException if there was an error querying the case
	 *                          database.
	 */
	@Override
	public List<Content> getChildren() throws TskCoreException {
		List<Content> children = new ArrayList<Content>();

		children.addAll(getSleuthkitCase().getAbstractFileChildren(this));
		children.addAll(getSleuthkitCase().getBlackboardArtifactChildren(this));

		return children;

	}

	/**
	 * Gets the object ids of objects, if any, that are children of this
	 * abstract content.
	 *
	 * @return A list of the object ids.
	 *
	 * @throws TskCoreException if there was an error querying the case
	 *                          database.
	 */
	@Override
	public List<Long> getChildrenIds() throws TskCoreException {

		List<Long> childrenIDs = new ArrayList<Long>();

		childrenIDs.addAll(getSleuthkitCase().getAbstractFileChildrenIds(this));
		childrenIDs.addAll(getSleuthkitCase().getBlackboardArtifactChildrenIds(this));

		return childrenIDs;
	}

	// classes should override this if they can be a data source 
	@Override
	public Content getDataSource() throws TskCoreException {
		Content myParent = getParent();
		if (myParent == null) {
			return null;
		}

		return myParent.getDataSource();
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

		try {
			// New children may have been added to an existing content
			// object in which case they are not equal.
			if (this.getChildrenCount() != other.getChildrenCount()) {
				return false;
			}
		} catch (TskCoreException ex) {
			Logger.getLogger(AbstractContent.class.getName()).log(Level.SEVERE, null, ex);
		}

		return true;
	}

	@Override
	public int hashCode() {
		int hash = 7 + (int) (this.objId ^ (this.objId >>> 32));
		try {
			hash = 41 * hash + this.getChildrenCount();
		} catch (TskCoreException ex) {
			Logger.getLogger(AbstractContent.class.getName()).log(Level.SEVERE, null, ex);
		}
		return hash;
	}

	@Override
	public BlackboardArtifact newArtifact(int artifactTypeID) throws TskCoreException {
		// don't let them make more than 1 GEN_INFO
		if (artifactTypeID == ARTIFACT_TYPE.TSK_GEN_INFO.getTypeID()) {
			return getGenInfoArtifact(true);
		}
		return db.newBlackboardArtifact(artifactTypeID, objId);
	}

	@Override
	public BlackboardArtifact newArtifact(BlackboardArtifact.ARTIFACT_TYPE type) throws TskCoreException {
		return newArtifact(type.getTypeID());
	}

	@Override
	public ArrayList<BlackboardArtifact> getArtifacts(String artifactTypeName) throws TskCoreException {
		return getArtifacts(db.getArtifactType(artifactTypeName).getTypeID());
	}

	@Override
	public ArrayList<BlackboardArtifact> getArtifacts(int artifactTypeID) throws TskCoreException {
		if (artifactTypeID == ARTIFACT_TYPE.TSK_GEN_INFO.getTypeID()) {
			if (genInfoArtifact == null) // don't make one if it doesn't already exist
			{
				getGenInfoArtifact(false);
			}

			ArrayList<BlackboardArtifact> list = new ArrayList<BlackboardArtifact>();
			// genInfoArtifact coudl still be null if there isn't an artifact
			if (genInfoArtifact != null) {
				list.add(genInfoArtifact);
			}
			return list;
		}
		return db.getBlackboardArtifacts(artifactTypeID, objId);
	}

	@Override
	public ArrayList<BlackboardArtifact> getArtifacts(BlackboardArtifact.ARTIFACT_TYPE type) throws TskCoreException {
		return getArtifacts(type.getTypeID());
	}

	@Override
	public BlackboardArtifact getGenInfoArtifact() throws TskCoreException {
		return getGenInfoArtifact(true);
	}

	@Override
	public BlackboardArtifact getGenInfoArtifact(boolean create) throws TskCoreException {
		if (genInfoArtifact != null) {
			return genInfoArtifact;
		}

		// go to db directly to avoid infinite loop
		ArrayList<BlackboardArtifact> arts = db.getBlackboardArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_GEN_INFO, objId);
		BlackboardArtifact retArt;
		if (arts.isEmpty()) {
			if (create) {
				retArt = db.newBlackboardArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_GEN_INFO, objId);
			} else {
				return null;
			}
		} else {
			retArt = arts.get(0);
		}
		genInfoArtifact = retArt;
		return retArt;
	}

	@Override
	public ArrayList<BlackboardAttribute> getGenInfoAttributes(ATTRIBUTE_TYPE attr_type) throws TskCoreException {
		ArrayList<BlackboardAttribute> returnList = new ArrayList<BlackboardAttribute>();

		if (genInfoArtifact == null) {
			getGenInfoArtifact(false);
			if (genInfoArtifact == null) {
				return returnList;
			}
		}

		for (BlackboardAttribute attribute : genInfoArtifact.getAttributes()) {
			if (attribute.getAttributeType().getTypeID() == attr_type.getTypeID()) {
				returnList.add(attribute);
			}
		}

		return returnList;
	}

	@Override
	public ArrayList<BlackboardArtifact> getAllArtifacts() throws TskCoreException {
		return db.getMatchingArtifacts("WHERE obj_id = " + objId); //NON-NLS
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
	public Set<String> getHashSetNames() throws TskCoreException {
		Set<String> hashNames = new HashSet<String>();
		ArrayList<BlackboardArtifact> artifacts = getArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_HASHSET_HIT);

		for (BlackboardArtifact a : artifacts) {
			BlackboardAttribute attribute = a.getAttribute(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_SET_NAME));
			if (attribute != null) {
				hashNames.add(attribute.getValueString());
			}
		}
		return Collections.unmodifiableSet(hashNames);
	}

	@Override
	public String toString() {
		return toString(true);
	}

	public String toString(boolean preserveState) {
		if (preserveState) {
			return "AbstractContent [\t" + "objId " + String.format("%010d", objId) + "\t" //NON-NLS
					+ "name " + name + "\t" + "parentId " + parentId + "\t" //NON-NLS
					+ "\t" + "checkedHasChildren " + checkedHasChildren //NON-NLS
					+ "\t" + "hasChildren " + hasChildren //NON-NLS
					+ "\t" + "childrenCount " + childrenCount //NON-NLS
					+ "uniquePath " + uniquePath + "]\t"; //NON-NLS
		} else {
			try {
				if (getParent() != null) {
					return "AbstractContent [\t" + "objId " + String.format("%010d", objId) //NON-NLS
							+ "\t" + "name " + name //NON-NLS
							+ "\t" + "checkedHasChildren " + checkedHasChildren //NON-NLS
							+ "\t" + "hasChildren " + hasChildren //NON-NLS
							+ "\t" + "childrenCount " + childrenCount //NON-NLS
							+ "\t" + "getUniquePath " + getUniquePath() //NON-NLS
							+ "\t" + "getParent " + getParent().getId() + "]\t"; //NON-NLS
				} else {
					return "AbstractContent [\t" + "objId " //NON-NLS
							+ String.format("%010d", objId) + "\t" + "name " + name //NON-NLS
							+ "\t" + "checkedHasChildren " + checkedHasChildren //NON-NLS
							+ "\t" + "hasChildren " + hasChildren //NON-NLS
							+ "\t" + "childrenCount " + childrenCount //NON-NLS
							+ "\t" + "uniquePath " + getUniquePath() //NON-NLS
							+ "\t" + "parentId " + parentId + "]\t"; //NON-NLS
				}
			} catch (TskCoreException ex) {
				Logger.getLogger(AbstractContent.class.getName()).log(Level.SEVERE, "Could not find Parent", ex); //NON-NLS
				return "AbstractContent [\t" + "objId " + String.format("%010d", objId) + "\t" //NON-NLS
						+ "name " + name + "\t" + "parentId " + parentId + "\t" //NON-NLS
						+ "\t" + "checkedHasChildren " + checkedHasChildren //NON-NLS
						+ "\t" + "hasChildren " + hasChildren //NON-NLS
						+ "\t" + "childrenCount " + childrenCount //NON-NLS
						+ "uniquePath " + uniquePath + "]\t";  //NON-NLS
			}
		}
	}
}
