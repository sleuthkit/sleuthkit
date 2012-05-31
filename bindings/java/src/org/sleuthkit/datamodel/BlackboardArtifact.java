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

import java.lang.String;
import java.util.ArrayList;
import java.util.Collection;

/**
 * Blackboard Artifact class used to store a set of name-value pairs
 * @author alawrence
 */
public class BlackboardArtifact implements SleuthkitVisitableItem {

	/**
	 * Enum for artifact types. 
	 * Refer to http://wiki.sleuthkit.org/index.php?title=Artifact_Examples
	 * for details on which attributes should be used for each artifact.
	 * The enum typeIDs will be populated at database creation
	 * time, so they will always match the ids stored in the database.
	 */
	/* It is very important that this list be kept up to
	 * date and in sync with the C++ code.  Do not add
	 * anything here unless you also add it there.
	 * See framework/Services/TskBlackboard.* */
	public enum ARTIFACT_TYPE implements SleuthkitVisitableItem {

		TSK_GEN_INFO(1, "TSK_GEN_INFO", "General Info"), ///< Default type
		TSK_WEB_BOOKMARK(2, "TSK_WEB_BOOKMARK", "Bookmarks"),
		TSK_WEB_COOKIE(3, "TSK_WEB_COOKIE", "Cookies"),
		TSK_WEB_HISTORY(4, "TSK_WEB_HISTORY", "Web History"),
		TSK_WEB_DOWNLOAD(5, "TSK_WEB_DOWNLOAD", "Downloads"),
		TSK_RECENT_OBJECT(6, "TSK_RECENT_OBJ", "Recent Documents"),
		TSK_TRACKPOINT(7, "TSK_TRACKPOINT", "Trackpoints"),
		TSK_INSTALLED_PROG(8, "TSK_INSTALLED_PROG", "Installed Programs"),
		TSK_KEYWORD_HIT(9, "TSK_KEYWORD_HIT", "Keyword Hits"),
		TSK_HASHSET_HIT(10, "TSK_HASHSET_HIT", "Hashset Hits"),
		TSK_DEVICE_ATTACHED(11, "TSK_DEVICE_ATTACHED", "Device Attached"),
		TSK_INTERESTING_FILE_HIT(12, "TSK_INTERESTING_FILE_HIT", "Interesting File");
		/* SEE ABOVE -- KEEP C++ CODE IN SYNC */
		private String label;
		private int typeID;
		private String displayName;

		private ARTIFACT_TYPE(int typeID, String label, String displayName) {
			this.typeID = typeID;
			this.label = label;
			this.displayName = displayName;
		}

		/**
		 * get the label string for the enum
		 * @return label string
		 */
		public String getLabel() {
			return this.label;
		}

		/**
		 * get the type id for the enum
		 * @return type id
		 */
		public int getTypeID() {
			return this.typeID;
		}

		/**
		 * get the enum value that corresponds to the given label
		 * @param label label string
		 * @return the corresponding enum
		 */
		static public ARTIFACT_TYPE fromLabel(String label) {
			for (ARTIFACT_TYPE v : ARTIFACT_TYPE.values()) {
				if (v.label.equals(label)) {
					return v;
				}
			}
			throw new IllegalArgumentException("No ARTIFACT_TYPE matching type: " + label);
		}

		/**
		 * get the enum value that corresponds to the given id
		 * @param ID the id
		 * @return the corresponding enum
		 */
		static public ARTIFACT_TYPE fromID(int ID) {
			for (ARTIFACT_TYPE v : ARTIFACT_TYPE.values()) {
				if (v.typeID == ID) {
					return v;
				}
			}
			throw new IllegalArgumentException("No ARTIFACT_TYPE matching type: " + ID);
		}

		public String getDisplayName() {
			return this.displayName;
		}

		@Override
		public <T> T accept(SleuthkitItemVisitor<T> v) {
			return v.visit(this);
		}
	}
	private long artifactID;
	private long objID;
	private int artifactTypeID;
	private String artifactTypeName;
	private String displayName;
	private SleuthkitCase Case;

	/**
	 * constuctor for an artifact. should only be used by SleuthkitCase
	 * @param Case the case that can be used to access the database this artifact is part of
	 * @param artifactID the id for this artifact
	 * @param objID the object this artifact is associated with
	 * @param artifactTypeID the type id of this artifact
	 * @param artifactTypeName the type name of this artifact
	 */
	protected BlackboardArtifact(SleuthkitCase Case, long artifactID, long objID, int artifactTypeID, String artifactTypeName, String displayName) {
		this.Case = Case;
		this.artifactID = artifactID;
		this.objID = objID;
		this.artifactTypeID = artifactTypeID;
		this.artifactTypeName = artifactTypeName;
		this.displayName = displayName;
	}

	/**
	 * get the id for this artifact
	 * @return id
	 */
	public long getArtifactID() {
		return this.artifactID;
	}

	/**
	 * get the object id this artifact is associated with
	 * @return object id
	 */
	public long getObjectID() {
		return this.objID;
	}

	/**
	 * get the artifact type id for this artifact
	 * @return artifact type id
	 */
	public int getArtifactTypeID() {
		return this.artifactTypeID;
	}

	/**
	 * get the artifact type name for this artifact
	 * @return artifact type name
	 */
	public String getArtifactTypeName() {
		return this.artifactTypeName;
	}

	/**
	 * get the artifact display name for this artifact
	 * @return artifact display name
	 */
	public String getDisplayName() {
		return this.displayName;
	}

	/**
	 * add an attribute to this artifact
	 * @param attr the attribute to add
	 * @throws TskException
	 */
	public void addAttribute(BlackboardAttribute attr) throws TskException {
		attr.setArtifactID(artifactID);
		attr.setCase(Case);
		Case.addBlackboardAttribute(attr);
	}

	/**
	 * add a collection of attributes to this artifact in a single transaction
	 * @param attributes List of attributes to add
	 * @throws TskException
	 */
	public void addAttributes(Collection<BlackboardAttribute> attributes) throws TskException {
		if (attributes.isEmpty()) {
			return;
		}

		for (BlackboardAttribute attr : attributes) {
			attr.setArtifactID(artifactID);
			attr.setCase(Case);
		}
		Case.addBlackboardAttributes(attributes);
	}

	/**
	 * get all attributes associated with this artifact
	 * @return a list of attributes
	 * @throws TskException
	 */
	public ArrayList<BlackboardAttribute> getAttributes() throws TskException {
		return Case.getMatchingAttributes("WHERE artifact_id = " + artifactID);
	}

	@Override
	public <T> T accept(SleuthkitItemVisitor<T> v) {
		return v.visit(this);
	}

	public SleuthkitCase getSleuthkitCase() {
		return Case;
	}

    /**
     * Compare this artifact with the given object
	 * Ensure that the artifacts have the same ID
     * @param obj
     * @return Whether this object is equal to the given one
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final BlackboardArtifact other = (BlackboardArtifact) obj;
        if (this.artifactID != other.artifactID) {
            return false;
        }
        return true;
    }
}
