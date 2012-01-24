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

/**
 * Blackboard Artifact class used to store a set of name-value pairs
 * @author alawrence
 */
public class BlackboardArtifact {
	
	/**
	 * Enum for artifact types. The enum typeIDs will be populated at database creation
	 * time, so they will always match the ids stored in the database.
	 */
	public enum TSK_BLACKBOARD_ARTIFACT_TYPE {
		DEFAULT(1, "default_artifact_type"),	 ///< Default type
		TSK_WEB_BOOKMARK (2, "tsk_web_bookmark"),
		TSK_WEB_COOKIE (3, "tsk_web_cookie"),
		TSK_WEB_HISTORY (4, "tsk_web_history"),
		TSK_WEB_DOWNLOAD (5, "tsk_web_download"),
		TSK_RECENT_OBJECT (6, "tsk_recent_object"),
		TSK_TRACKPOINT (7, "tsk_trackpoint"),
		TSK_INSTALLED_PROG (8, "tsk_installed_prog"),
		TSK_KEYWORD_HIT (9, "tsk_keyword_hit");
		
		private String label;
		private int typeID;

		private TSK_BLACKBOARD_ARTIFACT_TYPE(int typeID, String label){
			this.typeID = typeID;
			this.label = label;
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
		public int getTypeID(){
			return this.typeID;
		}
		
		/**
		 * get the enum value that corresponds to the given label
		 * @param label label string
		 * @return the corresponding enum
		 */
		static public TSK_BLACKBOARD_ARTIFACT_TYPE fromLabel(String label) {
			for (TSK_BLACKBOARD_ARTIFACT_TYPE v : TSK_BLACKBOARD_ARTIFACT_TYPE.values()) {
				if (v.label.equals(label)) {
					return v;
				}
			}
			throw new IllegalArgumentException("No TSK_BLACKBOARD_ARTIFACT_TYPE matching type: " + label);
		}
		/**
		 * get the enum value that corresponds to the given id
		 * @param ID the id
		 * @return the corresponding enum
		 */
		static public TSK_BLACKBOARD_ARTIFACT_TYPE fromID(int ID) {
			for (TSK_BLACKBOARD_ARTIFACT_TYPE v : TSK_BLACKBOARD_ARTIFACT_TYPE.values()) {
				if (v.typeID == ID) {
					return v;
				}
			}
			throw new IllegalArgumentException("No TSK_BLACKBOARD_ARTIFACT_TYPE matching type: " + ID);
		}
	}
	
	
	
	private long artifactID;
	private long objID;
	private int artifactTypeID;
	private String artifactTypeName;
	private SleuthkitCase Case;
	
	/**
	 * constuctor for an artifact. should only be used by SleuthkitCase
	 * @param Case the case that can be used to access the database this artifact is part of
	 * @param artifactID the id for this artifact
	 * @param objID the object this artifact is associated with
	 * @param artifactTypeID the type id of this artifact
	 * @param artifactTypeName the type name of this artifact
	 */
	protected BlackboardArtifact(SleuthkitCase Case, long artifactID, long objID, int artifactTypeID, String artifactTypeName){
		this.Case = Case;
		this.artifactID = artifactID;
		this.objID = objID;
		this.artifactTypeID = artifactTypeID;
		this.artifactTypeName = artifactTypeName;
	}
	
	/**
	 * get the id for this artifact
	 * @return id
	 */
	public long getArtifactID(){
		return this.artifactID;
	}
	
	/**
	 * get the object id this artifact is associated with
	 * @return object id
	 */
	public long getObjectID(){
		return this.objID;
	}
	/**
	 * get the artifact type id for this artifact
	 * @return artifact type id
	 */
	public int getArtifactTypeID(){
		return this.artifactTypeID;
	}
	/**
	 * get the artifact type name for this artifact
	 * @return artifact type name
	 */
	public String getArtifactTypeName(){
		return this.artifactTypeName;
	}
	
	//add int
	/**
	 * add an attribute to this artifact
	 * @param attrType the attribute type enum
	 * @param value the value int
	 * @param moduleName the module that created this attribute
	 * @param context addition information about the attribute
	 * @throws TskException
	 */
	public void addAttribute(BlackboardAttribute attr) throws TskException{
		attr.setArtifactID(artifactID);
		attr.setCase(Case);
		Case.addBlackboardAttribute(attr);
	}
	
	/**
	 * get all attributes associated with this artifact
	 * @return a list of attributes
	 * @throws TskException
	 */
	public ArrayList<BlackboardAttribute> getAttributes() throws TskException{
		return Case.getMatchingAttributes("WHERE artifact_id = " + artifactID);
	}
}

