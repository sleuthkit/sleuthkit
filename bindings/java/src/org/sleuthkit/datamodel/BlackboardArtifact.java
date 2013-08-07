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

import java.util.Collection;
import java.util.List;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;

/**
 * Represents an artifact as stored in the Blackboard. Artifacts are a collection
 * of name value pairs and have a type that represents the type of data they are
 * storing.  This class is used to create artifacts on the blackboard and is used
 * to represent artifacts queried from the blackboard.
 */
public class BlackboardArtifact implements SleuthkitVisitableItem {

	/**
	 * Enum for artifact types.  The C++ code has the full description of 
	 * how to use these. 
	 * Refer to http://wiki.sleuthkit.org/index.php?title=Artifact_Examples
	 * for details on which attributes should be used for each artifact.
	 */
	/* It is very important that this list be kept up to
	 * date and in sync with the C++ code.  Do not add
	 * anything here unless you also add it there.
	 * See framework/Services/TskBlackboard.* */
	public enum ARTIFACT_TYPE implements SleuthkitVisitableItem {

		TSK_GEN_INFO(1, "TSK_GEN_INFO", "General Info"), ///< Default type
		TSK_WEB_BOOKMARK(2, "TSK_WEB_BOOKMARK", "Web Bookmarks"), ///< web bookmarks
		TSK_WEB_COOKIE(3, "TSK_WEB_COOKIE", "Web Cookies"), ///< web cookies
		TSK_WEB_HISTORY(4, "TSK_WEB_HISTORY", "Web History"), ///< web history
		TSK_WEB_DOWNLOAD(5, "TSK_WEB_DOWNLOAD", "Web Downloads"), ///< web downloads
		TSK_RECENT_OBJECT(6, "TSK_RECENT_OBJ", "Recent Documents"), ///< recent objects 
		TSK_GPS_TRACKPOINT(7, "TSK_GPS_TRACKPOINT", "GPS Trackpoints"), ///< trackpoint (geo location data)
		TSK_INSTALLED_PROG(8, "TSK_INSTALLED_PROG", "Installed Programs"), ///< installed programs
		TSK_KEYWORD_HIT(9, "TSK_KEYWORD_HIT", "Keyword Hits"), ///< keyword search hits
		TSK_HASHSET_HIT(10, "TSK_HASHSET_HIT", "Hashset Hits"), ///< hashset hits
		TSK_DEVICE_ATTACHED(11, "TSK_DEVICE_ATTACHED", "Devices Attached"), ///< attached devices
		TSK_INTERESTING_FILE_HIT(12, "TSK_INTERESTING_FILE_HIT", "Interesting Files"), ///< an interesting/notable file hit
		TSK_EMAIL_MSG(13, "TSK_EMAIL_MSG", "E-Mail Messages"), ///< email message
		TSK_EXTRACTED_TEXT(14, "TSK_EXTRACTED_TEXT", "Extracted Text"), ///< text extracted from file
		TSK_WEB_SEARCH_QUERY(15, "TSK_WEB_SEARCH_QUERY", "Web Search"), ///< web search engine query extracted from web history
		TSK_METADATA_EXIF(16, "TSK_METADATA_EXIF", "EXIF Metadata"), ///< EXIF Metadata
		TSK_TAG_FILE(17, "TSK_TAG_FILE", "File Tags"), ///< tagged files
		TSK_TAG_ARTIFACT(18, "TSK_TAG_ARTIFACT", "Result Tags"), ///< tagged results/artifacts
		TSK_OS_INFO(19, "TSK_OS_INFO", "Operating System Information"), ///< Information pertaining to an operating system.
		TSK_OS_ACCOUNT(20, "TSK_OS_ACCOUNT", "Operating System User Account"), ///< An operating system user account.
		TSK_SERVICE_ACCOUNT(21, "TSK_SERVICE_ACCOUNT", "Accounts"), ///< An application/service/web user account.
        TSK_TOOL_OUTPUT(22, "TSK_TOOL_OUTPUT", "Raw Tool Output"), ///< Output from an external tool or module that (raw text)
		TSK_CONTACT(23, "TSK_CONTACT", "Contacts"), ///< A Contact extracted from a phone, or from an Addressbook/Email/Messaging Application
		TSK_MESSAGE(24, "TSK_MESSAGE", "Messages"), ///< An SMS/MMS message extracted from phone, or from another messaging application, like IM
		TSK_CALLLOG(25, "TSK_CALLLOG", "Call Logs"), ///< A Phone call log extracted from a phones or softphone application
		TSK_CALENDAR_ENTRY(26, "TSK_CALENDAR_ENTRY", "Calendar Entries"), ///< A Calendar entry from a phone, PIM or a Calendar application.
		TSK_SPEED_DIAL_ENTRY(27, "TSK_SPEED_DIAL_ENTRY", "Speed Dial Entries"), ///< A speed dial entry from a phone 
		TSK_BLUETOOTH_PAIRING(28, "TSK_BLUETOOTH_PAIRING", "BlueTooth Pairings"), ///< A bluetooth pairing entry
		TSK_GPS_BOOKMARK(29, "TSK_GPS_BOOKMARK", "GPS Bookmarks"),	// GPS Bookmarks
		TSK_GPS_LAST_KNOWN_LOCATION(30, "TSK_GPS_LAST_KNOWN_LOCATION", "GPS Last Known Location"),	// GPS Last known location
		TSK_GPS_SEARCH(31, "TSK_GPS_SEARCH", "GPS Searches"),	// GPS Searches
		 
		
		; 
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
		 * Gets the label string for the artifact type enum
		 * @return label string
		 */
		public String getLabel() {
			return this.label;
		}

		/**
		 * Gets the type id for the artifact type enum
		 * @return type id
		 */
		public int getTypeID() {
			return this.typeID;
		}

		/**
		 * Gets the artifact type enum value that corresponds to the given label
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
		 * Gets the artifact type enum value that corresponds to the given id
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

		/**
		 * Gets display name of the artifact
		 * @return display name string
		 */
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
	 * Constructor for an artifact. Should only be used by SleuthkitCase
	 * @param Case the case that can be used to access the database this artifact is part of
	 * @param artifactID the id for this artifact
	 * @param objID the object this artifact is associated with
	 * @param artifactTypeID the type id of this artifact
	 * @param artifactTypeName the type name of this artifact
	 * @param displayName the display name of this artifact
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
	 * Get the id for this artifact
	 * @return id
	 */
	public long getArtifactID() {
		return this.artifactID;
	}

	/**
	 * Get the object id of the object this artifact is associated with
	 * @return object id
	 */
	public long getObjectID() {
		return this.objID;
	}

	/**
	 * Get the artifact type id for this artifact
	 * @return artifact type id
	 */
	public int getArtifactTypeID() {
		return this.artifactTypeID;
	}

	/**
	 * Get the artifact type name for this artifact
	 * @return artifact type name
	 */
	public String getArtifactTypeName() {
		return this.artifactTypeName;
	}

	/**
	 * Get the artifact display name for this artifact
	 * @return artifact display name
	 */
	public String getDisplayName() {
		return this.displayName;
	}

	/**
	 * Add an attribute to this artifact
	 * @param attr the attribute to add
	 * @throws TskException exception thrown if a critical error occurs within tsk core and attribute was not added
	 */
	public void addAttribute(BlackboardAttribute attr) throws TskCoreException {
		attr.setArtifactID(artifactID);
		attr.setCase(Case);
		Case.addBlackboardAttribute(attr);
	}

	/**
	 * Add a collection of attributes to this artifact in a single transaction (faster than individually)
	 * @param attributes List of attributes to add
	 * @throws TskException exception thrown if a critical error occurs within tsk core and attributes were not added
	 */
	public void addAttributes(Collection<BlackboardAttribute> attributes) throws TskCoreException {
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
	 * Gets all attributes associated with this artifact
	 * @return a list of attributes
	 * @throws TskException exception thrown if a critical error occurs within tsk core and attributes were not queried
	 */
	public List<BlackboardAttribute> getAttributes() throws TskCoreException {
		//return Case.getMatchingAttributes("WHERE artifact_id = " + artifactID);
		return Case.getBlackboardAttributes(this);
	}
	

	/**
	 * A method to accept a visitor SleuthkitItemVisitor, and execute an algorithm on this object
	 * @param v the visitor to accept
	 * @return object of generic type T to return
	 */
	@Override
	public <T> T accept(SleuthkitItemVisitor<T> v) {
		return v.visit(this);
	}

	/**
	 * Gets the SleuthkitCase handle associated with this object
	 * @return the case handle
	 */
	public SleuthkitCase getSleuthkitCase() {
		return Case;
	}


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

	@Override
	public int hashCode() {
		int hash = 7;
		hash = 41 * hash + (int) (this.artifactID ^ (this.artifactID >>> 32));
		return hash;
	}

	@Override
	public String toString() {
		return "BlackboardArtifact{" + "artifactID=" + artifactID + ", objID=" + objID + ", artifactTypeID=" + artifactTypeID + ", artifactTypeName=" + artifactTypeName + ", displayName=" + displayName + ", Case=" + Case + '}';
	}
	
	
}
