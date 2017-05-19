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
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.ResourceBundle;

/**
 * Represents an artifact as stored in the Blackboard. Artifacts are a
 * collection of name value pairs and have a type that represents the type of
 * data they are storing. This class is used to create artifacts on the
 * blackboard and is used to represent artifacts queried from the blackboard.
 */
public class BlackboardArtifact implements SleuthkitVisitableItem {

	private static final ResourceBundle bundle = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle");

	/**
	 * Represents the type of an BlackboardArtifact
	 */
	public static final class Type implements Serializable {

		private static final long serialVersionUID = 1L;
		private final String typeName;
		private final int typeID;
		private final String displayName;

		/**
		 * Constructs a type for a blackboard artifact
		 *
		 * @param typeName    The typeName of the type
		 * @param typeID      the ID of the type
		 * @param displayName The display name of this type
		 */
		public Type(int typeID, String typeName, String displayName) {
			this.typeID = typeID;
			this.typeName = typeName;
			this.displayName = displayName;
		}

		/**
		 * Constructs a type for a blackboard artifact
		 *
		 * @param type the artifact type enum from which this type will be based
		 */
		public Type(ARTIFACT_TYPE type) {
			this.typeID = type.getTypeID();
			this.typeName = type.getLabel();
			this.displayName = type.getDisplayName();
		}

		/**
		 * Gets the typeName string for the artifact type enum
		 *
		 * @return typeName string
		 */
		public String getTypeName() {
			return this.typeName;
		}

		/**
		 * Gets the type id for the artifact type enum
		 *
		 * @return type id
		 */
		public int getTypeID() {
			return this.typeID;
		}

		/**
		 * Gets display name of the artifact type
		 *
		 * @return display name string
		 */
		public String getDisplayName() {
			return this.displayName;
		}

		@Override
		public boolean equals(Object that) {
			if (this == that) {
				return true;
			} else if (!(that instanceof Type)) {
				return false;
			} else {
				return ((Type) that).sameType(this);
			}
		}

		/**
		 * Compares two Types to see if they are the same
		 *
		 * @param that the other type
		 *
		 * @return true if it is the same type
		 */
		private boolean sameType(Type that) {
			return this.typeName.equals(that.getTypeName())
					&& this.displayName.equals(that.getDisplayName())
					&& this.typeID == that.getTypeID();
		}

		@Override
		public int hashCode() {
			int hash = 11;
			hash = 83 * hash + Objects.hashCode(this.typeID);
			hash = 83 * hash + Objects.hashCode(this.displayName);
			hash = 83 * hash + Objects.hashCode(this.typeName);
			return hash;
		}
	}

	/**
	 * Enum for artifact types. Refer to
	 * http://wiki.sleuthkit.org/index.php?title=Artifact_Examples for details
	 * on which attributes should be used for each artifact.
	 */
	public enum ARTIFACT_TYPE implements SleuthkitVisitableItem {

		TSK_GEN_INFO(1, "TSK_GEN_INFO", //NON-NLS
				bundle.getString("BlackboardArtifact.tskGenInfo.text")), ///< Default type
		TSK_WEB_BOOKMARK(2, "TSK_WEB_BOOKMARK", //NON-NLS
				bundle.getString("BlackboardArtifact.tskWebBookmark.text")), ///< web bookmarks
		TSK_WEB_COOKIE(3, "TSK_WEB_COOKIE", //NON-NLS
				bundle.getString("BlackboardArtifact.tskWebCookie.text")), ///< web cookies
		TSK_WEB_HISTORY(4, "TSK_WEB_HISTORY", //NON-NLS
				bundle.getString("BlackboardArtifact.tskWebHistory.text")), ///< web history
		TSK_WEB_DOWNLOAD(5, "TSK_WEB_DOWNLOAD", //NON-NLS
				bundle.getString("BlackboardArtifact.tskWebDownload.text")), ///< web downloads
		TSK_RECENT_OBJECT(6, "TSK_RECENT_OBJ", //NON-NLS
				bundle.getString("BlackboardArtifact.tsk.recentObject.text")), ///< recent objects
		TSK_GPS_TRACKPOINT(7, "TSK_GPS_TRACKPOINT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskGpsTrackpoint.text")), ///< trackpoint (geo location data)
		TSK_INSTALLED_PROG(8, "TSK_INSTALLED_PROG", //NON-NLS
				bundle.getString("BlackboardArtifact.tskInstalledProg.text")), ///< installed programs
		TSK_KEYWORD_HIT(9, "TSK_KEYWORD_HIT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskKeywordHits.text")), ///< keyword search hits
		TSK_HASHSET_HIT(10, "TSK_HASHSET_HIT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskHashsetHit.text")), ///< hashset hits
		TSK_DEVICE_ATTACHED(11, "TSK_DEVICE_ATTACHED", //NON-NLS
				bundle.getString("BlackboardArtifact.tskDeviceAttached.text")), ///< attached devices
		TSK_INTERESTING_FILE_HIT(12, "TSK_INTERESTING_FILE_HIT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskInterestingFileHit.text")), ///< an interesting/notable file hit
		TSK_EMAIL_MSG(13, "TSK_EMAIL_MSG", //NON-NLS
				bundle.getString("BlackboardArtifact.tskEmailMsg.text")), ///< email message
		TSK_EXTRACTED_TEXT(14, "TSK_EXTRACTED_TEXT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskExtractedText.text")), ///< text extracted from file
		TSK_WEB_SEARCH_QUERY(15, "TSK_WEB_SEARCH_QUERY", //NON-NLS
				bundle.getString("BlackboardArtifact.tskWebSearchQuery.text")), ///< web search engine query extracted from web history
		TSK_METADATA_EXIF(16, "TSK_METADATA_EXIF", //NON-NLS
				bundle.getString("BlackboardArtifact.tskMetadataExif.text")), ///< EXIF Metadata
		@Deprecated
		// tags are now added via a special table, not blackboard
		TSK_TAG_FILE(17, "TSK_TAG_FILE", //NON-NLS
				bundle.getString("BlackboardArtifact.tagFile.text")), ///< tagged files
		@Deprecated
		// tags are now added via a special table, not blackboard
		TSK_TAG_ARTIFACT(18, "TSK_TAG_ARTIFACT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskTagArtifact.text")), ///< tagged results/artifacts
		TSK_OS_INFO(19, "TSK_OS_INFO", //NON-NLS
				bundle.getString("BlackboardArtifact.tskOsInfo.text")), ///< Information pertaining to an operating system.
		TSK_OS_ACCOUNT(20, "TSK_OS_ACCOUNT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskOsAccount.text")), ///< An operating system user account.
		TSK_SERVICE_ACCOUNT(21, "TSK_SERVICE_ACCOUNT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskServiceAccount.text")), ///< An application/service/web user account.
		@Deprecated
		// use Case.addReport in Autopsy
		TSK_TOOL_OUTPUT(22, "TSK_TOOL_OUTPUT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskToolOutput.text")), ///< Output from an external tool or module that (raw text)
		TSK_CONTACT(23, "TSK_CONTACT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskContact.text")), ///< A Contact extracted from a phone, or from an Addressbook/Email/Messaging Application
		TSK_MESSAGE(24, "TSK_MESSAGE", //NON-NLS
				bundle.getString("BlackboardArtifact.tskMessage.text")), ///< An SMS/MMS message extracted from phone, or from another messaging application, like IM
		TSK_CALLLOG(25, "TSK_CALLLOG", //NON-NLS
				bundle.getString("BlackboardArtifact.tskCalllog.text")), ///< A Phone call log extracted from a phones or softphone application
		TSK_CALENDAR_ENTRY(26, "TSK_CALENDAR_ENTRY", //NON-NLS
				bundle.getString("BlackboardArtifact.tskCalendarEntry.text")), ///< A Calendar entry from a phone, PIM or a Calendar application.
		TSK_SPEED_DIAL_ENTRY(27, "TSK_SPEED_DIAL_ENTRY", //NON-NLS
				bundle.getString("BlackboardArtifact.tskSpeedDialEntry.text")), ///< A speed dial entry from a phone
		TSK_BLUETOOTH_PAIRING(28, "TSK_BLUETOOTH_PAIRING", //NON-NLS
				bundle.getString("BlackboardArtifact.tskBluetoothPairing.text")), ///< A bluetooth pairing entry
		TSK_GPS_BOOKMARK(29, "TSK_GPS_BOOKMARK", //NON-NLS
				bundle.getString("BlackboardArtifact.tskGpsBookmark.text")), // GPS Bookmarks
		TSK_GPS_LAST_KNOWN_LOCATION(30, "TSK_GPS_LAST_KNOWN_LOCATION", //NON-NLS
				bundle.getString("BlackboardArtifact.tskGpsLastKnownLocation.text")), // GPS Last known location
		TSK_GPS_SEARCH(31, "TSK_GPS_SEARCH", //NON-NLS
				bundle.getString("BlackboardArtifact.tskGpsSearch.text")), // GPS Searches
		TSK_PROG_RUN(32, "TSK_PROG_RUN", //NON-NLS
				bundle.getString("BlackboardArtifact.tskProgRun.text")), ///< Application run information
		TSK_ENCRYPTION_DETECTED(33, "TSK_ENCRYPTION_DETECTED", //NON-NLS
				bundle.getString("BlackboardArtifact.tskEncryptionDetected.text")), ///< Encrypted File
		TSK_EXT_MISMATCH_DETECTED(34, "TSK_EXT_MISMATCH_DETECTED", //NON-NLS
				bundle.getString("BlackboardArtifact.tskExtMismatchDetected.text")), ///< Extension Mismatch
		TSK_INTERESTING_ARTIFACT_HIT(35, "TSK_INTERESTING_ARTIFACT_HIT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskInterestingArtifactHit.text")), // Any artifact that should be called out
		TSK_GPS_ROUTE(36, "TSK_GPS_ROUTE", //NON-NLS
				bundle.getString("BlackboardArtifact.tskGpsRoute.text")), // Route based on GPS coordinates
		TSK_REMOTE_DRIVE(37, "TSK_REMOTE_DRIVE", //NON-NLS
				bundle.getString("BlackboardArtifact.tskRemoteDrive.text")),
		TSK_FACE_DETECTED(38, "TSK_FACE_DETECTED", //NON-NLS
				bundle.getString("BlackboardArtifact.tskFaceDetected.text")),
		TSK_ACCOUNT(39, "TSK_ACCOUNT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskAccount.text"));

		/*
		 * SEE ABOVE -- KEEP C++ CODE IN SYNC
		 */
		private final String label;
		private final int typeID;
		private final String displayName;

		private ARTIFACT_TYPE(int typeID, String label, String displayName) {
			this.typeID = typeID;
			this.label = label;
			this.displayName = displayName;
		}

		/**
		 * Gets the typeName string for the artifact type enum
		 *
		 * @return typeName string
		 */
		public String getLabel() {
			return this.label;
		}

		/**
		 * Gets the type id for the artifact type enum
		 *
		 * @return type id
		 */
		public int getTypeID() {
			return this.typeID;
		}

		/**
		 * Gets the artifact type enum value that corresponds to the given
		 * typeName
		 *
		 * @param label typeName string
		 *
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
		 *
		 * @param ID the id
		 *
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
		 *
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
	private final long artifactID;
	private final long objID;
	private final int artifactTypeID;
	private final String artifactTypeName;
	private final String displayName;
	private final ReviewStatus reviewStatus;
	private final SleuthkitCase sleuthkitCase;
	private final List<BlackboardAttribute> attrsCache = new ArrayList<BlackboardAttribute>();
	private boolean loadedCacheFromDb = false; // true once we've gone to the DB to fill in the attrsCache.  Until it is set, it may not be complete.

	/**
	 * Constructor for an artifact. Should only be used by SleuthkitCase
	 *
	 * @param sleuthkitCase    the case that can be used to access the database
	 *                         this artifact is part of
	 * @param artifactID       the id for this artifact
	 * @param objID            the object this artifact is associated with
	 * @param artifactTypeID   the type id of this artifact
	 * @param artifactTypeName the type name of this artifact
	 * @param displayName      the display name of this artifact
	 * @param reviewStatus     the review status of this artifact
	 */
	BlackboardArtifact(SleuthkitCase sleuthkitCase, long artifactID, long objID, int artifactTypeID, String artifactTypeName, String displayName, ReviewStatus reviewStatus) {
		this.sleuthkitCase = sleuthkitCase;
		this.artifactID = artifactID;
		this.objID = objID;
		this.artifactTypeID = artifactTypeID;
		this.artifactTypeName = artifactTypeName;
		this.displayName = displayName;
		this.reviewStatus = reviewStatus;
	}

	/**
	 * Constructor for an artifact. Should only be used by SleuthkitCase
	 *
	 * @param Case             the case that can be used to access the database
	 *                         this artifact is part of
	 * @param artifactID       the id for this artifact
	 * @param objID            the object this artifact is associated with
	 * @param artifactTypeID   the type id of this artifact
	 * @param artifactTypeName the type name of this artifact
	 * @param displayName      the display name of this artifact
	 * @param reviewStatus     the review status of this artifact
	 * @param isNew            true if we are currently creating the artifact
	 */
	BlackboardArtifact(SleuthkitCase sleuthkitCase, long artifactID, long objID, int artifactTypeID, String artifactTypeName, String displayName, ReviewStatus reviewStatus, boolean isNew) {
		this(sleuthkitCase, artifactID, objID, artifactTypeID, artifactTypeName, displayName, reviewStatus);
		// If the artifact is new, we don't need to waste a database call later to load the attributes
		if (isNew) {
			this.loadedCacheFromDb = true;
		}
	}

	public ReviewStatus getReviewStatus() {
		return reviewStatus;
	}

	/**
	 * Get the id for this artifact
	 *
	 * @return id
	 */
	public long getArtifactID() {
		return this.artifactID;
	}

	/**
	 * Get the object id of the object this artifact is associated with
	 *
	 * @return object id
	 */
	public long getObjectID() {
		return this.objID;
	}

	/**
	 * Get the artifact type id for this artifact
	 *
	 * @return artifact type id
	 */
	public int getArtifactTypeID() {
		return this.artifactTypeID;
	}

	/**
	 * Get the artifact type name for this artifact
	 *
	 * @return artifact type name
	 */
	public String getArtifactTypeName() {
		return this.artifactTypeName;
	}

	/**
	 * Get the artifact display name for this artifact
	 *
	 * @return artifact display name
	 */
	public String getDisplayName() {
		return this.displayName;
	}

	/**
	 * Add an attribute to this artifact
	 *
	 * @param attr the attribute to add
	 *
	 * @throws TskCoreException if a critical error occurs and the attribute was
	 *                          not added
	 */
	public void addAttribute(BlackboardAttribute attr) throws TskCoreException {
		attr.setArtifactId(artifactID);
		attr.setCaseDatabase(sleuthkitCase);
		sleuthkitCase.addBlackboardAttribute(attr, this.artifactTypeID);
		attrsCache.add(attr);
	}

	/**
	 * Add a collection of attributes to this artifact in a single transaction
	 * (faster than individually)
	 *
	 * @param attributes List of attributes to add
	 *
	 * @throws TskCoreException if a critical error occurs and the attribute was
	 *                          not added
	 */
	public void addAttributes(Collection<BlackboardAttribute> attributes) throws TskCoreException {
		if (attributes.isEmpty()) {
			return;
		}

		for (BlackboardAttribute attr : attributes) {
			attr.setArtifactId(artifactID);
			attr.setCaseDatabase(sleuthkitCase);
		}
		sleuthkitCase.addBlackboardAttributes(attributes, this.artifactTypeID);
		attrsCache.addAll(attributes);
	}

	/**
	 * Gets all attributes associated with this artifact
	 *
	 * @return a list of attributes
	 *
	 * @throws TskCoreException if a critical error occurs and the attributes
	 *                          are not fetched
	 */
	public List<BlackboardAttribute> getAttributes() throws TskCoreException {
		if (loadedCacheFromDb == false) {
			List<BlackboardAttribute> attrs = sleuthkitCase.getBlackboardAttributes(this);
			attrsCache.clear();
			attrsCache.addAll(attrs);
			loadedCacheFromDb = true;
		}
		return attrsCache;
	}

	/**
	 * Gets all attributes associated with this artifact that are of the given
	 * attribute type.
	 *
	 * @param attributeType the type of attributes to get
	 *
	 * @return a list of attributes of the given type
	 *
	 * @throws TskCoreException if a critical error occurs and the attributes
	 *                          are not fetched
	 * @deprecated There should not be multiple attributes of a type on an
	 * artifact. Use getAttribute(BlackboardAttribute.Type) instead.
	 */
	@Deprecated
	public List<BlackboardAttribute> getAttributes(final BlackboardAttribute.ATTRIBUTE_TYPE attributeType) throws TskCoreException {
		if (loadedCacheFromDb == false) {
			List<BlackboardAttribute> attrs = sleuthkitCase.getBlackboardAttributes(this);
			attrsCache.clear();
			attrsCache.addAll(attrs);
			loadedCacheFromDb = true;
		}
		ArrayList<BlackboardAttribute> filteredAttributes = new ArrayList<BlackboardAttribute>();
		for (BlackboardAttribute attr : attrsCache) {
			if (attr.getAttributeType().getTypeID() == attributeType.getTypeID()) {
				filteredAttributes.add(attr);
			}
		}
		return filteredAttributes;
	}

	/**
	 * Gets the attribute of this artifact of given type.
	 *
	 * @param attributeType The type of attribute to get
	 *
	 * @return The attribute of that type, returns null if there is no attribute
	 *         of that type.
	 *
	 * @throws TskCoreException if a critical error occurs and the attributes
	 *                          are not fetched
	 */
	public BlackboardAttribute getAttribute(BlackboardAttribute.Type attributeType) throws TskCoreException {
		List<BlackboardAttribute> attributes = this.getAttributes();
		for (BlackboardAttribute attribute : attributes) {
			if (attribute.getAttributeType().equals(attributeType)) {
				return attribute;
			}
		}
		return null;
	}

	/**
	 * A method to accept a visitor SleuthkitItemVisitor, and execute an
	 * algorithm on this object
	 *
	 * @param <T> the object type to be returned from visit()
	 * @param v   the visitor to accept
	 *
	 * @return object of generic type T to return
	 */
	@Override
	public <T> T accept(SleuthkitItemVisitor<T> v) {
		return v.visit(this);
	}

	/**
	 * Gets the SleuthkitCase handle associated with this object
	 *
	 * @return the case handle
	 */
	public SleuthkitCase getSleuthkitCase() {
		return sleuthkitCase;
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
		return "BlackboardArtifact{" + "artifactID=" + artifactID + ", objID=" + objID + ", artifactTypeID=" + artifactTypeID + ", artifactTypeName=" + artifactTypeName + ", displayName=" + displayName + ", Case=" + sleuthkitCase + '}'; //NON-NLS
	}

	/**
	 * Enum to represent the review status of an artifact.
	 */
	public enum ReviewStatus {

		APPROVED(1, "APPROVED", "ReviewStatus.Approved"), //approved by human user
		REJECTED(2, "REJECTED", "ReviewStatus.Rejected"), //rejected by humna user
		UNDECIDED(3, "UNDECIDED", "ReviewStatus.Undecided"); // not yet reviewed by human user

		private final Integer id;
		private final String name;
		private final String displayName;

		private final static Map<Integer, ReviewStatus> idToStatus = new HashMap<Integer, ReviewStatus>();

		static {
			for (ReviewStatus status : values()) {
				idToStatus.put(status.getID(), status);
			};
		}

		private ReviewStatus(Integer id, String name, String displayNameKey) {
			this.id = id;
			this.name = name;
			this.displayName = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle").getString(displayNameKey);
		}

		/**
		 * Get the Review Status with the given id, if one exists.
		 *
		 * @param id The review status id to instantiate.
		 *
		 * @return The review status with the given id, or null if none exists.
		 */
		public static ReviewStatus withID(int id) {
			return idToStatus.get(id);
		}

		/**
		 * Get the ID of this review status.
		 *
		 * @return the ID of this review status.
		 */
		public Integer getID() {
			return id;
		}

		/**
		 * Get the name of this review status.
		 *
		 * @return the name of this review status.
		 */
		String getName() {
			return name;
		}

		/**
		 * Get the display name of this review status.
		 *
		 * @return the displayName The display name of this review status.
		 */
		public String getDisplayName() {
			return displayName;
		}
	}

	/**
	 * Constructor for an artifact. Should only be used by SleuthkitCase. Sets
	 * the initial review status as "undecided"
	 *
	 * @param sleuthkitCase    the case that can be used to access the database
	 *                         this artifact is part of
	 * @param artifactID       the id for this artifact
	 * @param objID            the object this artifact is associated with
	 * @param artifactTypeID   the type id of this artifact
	 * @param artifactTypeName the type name of this artifact
	 * @param displayName      the display name of this artifact
	 *
	 * @deprecated use new BlackboardArtifact(SleuthkitCase, long, long, int,
	 * String, String, ReviewStatus) instead
	 */
	@Deprecated
	protected BlackboardArtifact(SleuthkitCase sleuthkitCase, long artifactID, long objID, int artifactTypeID, String artifactTypeName, String displayName) {
		this(sleuthkitCase, artifactID, objID, artifactTypeID, artifactTypeName, displayName, ReviewStatus.UNDECIDED);
	}
}
