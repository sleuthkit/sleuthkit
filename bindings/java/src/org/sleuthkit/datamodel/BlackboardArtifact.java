/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011-2017 Basis Technology Corp.
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
import java.io.UnsupportedEncodingException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.ResourceBundle;
import java.util.Set;
import org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;
import org.sleuthkit.datamodel.SleuthkitCase.ObjectInfo;

/**
 * An artifact that has been posted to the blackboard. An artifact is a typed
 * collection of name value pairs (attributes) that is associated with its
 * source content (either a data source, or file within a data source). Both
 * standard artifact types and custom artifact types are supported.
 *
 * IMPORTANT NOTE: No more than one attribute of a given type should be added to
 * an artifact.
 */
public class BlackboardArtifact implements Content {

	private static final ResourceBundle bundle = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle");
	private final long artifactId;
	private final long sourceObjId;				// refers to objID of parent/source object
	private final long artifactObjId;			// objId of the artifact in tsk_objects. TBD: replace artifactID with this
	private final long dataSourceObjId;			// objId of the data source in tsk_objects.
	private final int artifactTypeId;
	private final String artifactTypeName;
	private final String displayName;
	private ReviewStatus reviewStatus;
	private final SleuthkitCase sleuthkitCase;
	private final List<BlackboardAttribute> attrsCache = new ArrayList<BlackboardAttribute>();
	private boolean loadedCacheFromDb = false;
	private Content parent;
	private String uniquePath;

	private byte[] contentBytes = null;

	private volatile boolean checkedHasChildren;
	private volatile boolean hasChildren;
	private volatile int childrenCount;

	/**
	 * Constructs an artifact that has been posted to the blackboard. An
	 * artifact is a typed collection of name value pairs (attributes) that is
	 * associated with its source content (either a data source, or file within
	 * a data source). Both standard artifact types and custom artifact types
	 * are supported.
	 *
	 * @param sleuthkitCase    The SleuthKit case (case database) that contains
	 *                         the artifact data.
	 * @param artifactID       The unique id for this artifact
	 * @param sourceObjId      The unique id of the content with which this
	 *                         artifact is associated.
	 * @param artifactObjId    The unique id this artifact, in tsk_objects
	 * @param dataSourceObjId  Object ID of the datasource where the artifact
	 *                         was found.
	 * @param artifactTypeID   The type id of this artifact.
	 * @param artifactTypeName The type name of this artifact.
	 * @param displayName      The display name of this artifact.
	 * @param reviewStatus     The review status of this artifact.
	 */
	BlackboardArtifact(SleuthkitCase sleuthkitCase, long artifactID, long sourceObjId, long artifactObjId, long dataSourceObjId, int artifactTypeID, String artifactTypeName, String displayName, ReviewStatus reviewStatus) {

		this.sleuthkitCase = sleuthkitCase;
		this.artifactId = artifactID;
		this.sourceObjId = sourceObjId;
		this.artifactObjId = artifactObjId;
		this.artifactTypeId = artifactTypeID;
		this.dataSourceObjId = dataSourceObjId;
		this.artifactTypeName = artifactTypeName;
		this.displayName = displayName;
		this.reviewStatus = reviewStatus;

		this.checkedHasChildren = false;
		this.hasChildren = false;
		this.childrenCount = -1;

	}

	/**
	 * Constructs an artifact that has been posted to the blackboard. An
	 * artifact is a typed collection of name value pairs (attributes) that is
	 * associated with its source content (either a data source, or file within
	 * a data source). Both standard artifact types and custom artifact types
	 * are supported.
	 *
	 * @param sleuthkitCase    The SleuthKit case (case database) that contains
	 *                         the artifact data.
	 * @param artifactID       The unique id for this artifact.
	 * @param sourceObjId      The unique id of the content with which this
	 *                         artifact is associated.
	 * @param artifactObjID    The unique id this artifact. in tsk_objects
	 * @param dataSourceObjID  Unique id of the data source.
	 * @param artifactTypeID   The type id of this artifact.
	 * @param artifactTypeName The type name of this artifact.
	 * @param displayName      The display name of this artifact.
	 * @param reviewStatus     The review status of this artifact.
	 */
	BlackboardArtifact(SleuthkitCase sleuthkitCase, long artifactID, long sourceObjId, long artifactObjID, long dataSourceObjID, int artifactTypeID, String artifactTypeName, String displayName, ReviewStatus reviewStatus, boolean isNew) {
		this(sleuthkitCase, artifactID, sourceObjId, artifactObjID, dataSourceObjID, artifactTypeID, artifactTypeName, displayName, reviewStatus);
		if (isNew) {
			/*
			 * If this object represents a newly created artifact, then its
			 * collection of attributes has already been populated and there is
			 * no need to fetch them form the case database.
			 */
			this.loadedCacheFromDb = true;
		}
	}

	/**
	 * Gets the SleuthKit case (case database) that contains the data for this
	 * artifact.
	 *
	 * @return The SleuthKit case (case database) object.
	 */
	public SleuthkitCase getSleuthkitCase() {
		return sleuthkitCase;
	}

	/**
	 * Gets the unique id for this artifact.
	 *
	 * @return The artifact id.
	 */
	public long getArtifactID() {
		return this.artifactId;
	}

	/**
	 * Gets the object id of the source content (data source or file within a
	 * data source) of this artifact
	 *
	 * @return The object id.
	 */
	public long getObjectID() {
		return this.sourceObjId;
	}

	/**
	 * Gets the object id of the data source for this artifact.
	 *
	 * @return The data source object id.
	 */
	long getDataSourceObjectID() {
		return this.dataSourceObjId;
	}

	/**
	 * Gets the artifact type id for this artifact.
	 *
	 * @return The artifact type id.
	 */
	public int getArtifactTypeID() {
		return this.artifactTypeId;
	}

	/**
	 * Gets the artifact type name for this artifact.
	 *
	 * @return The artifact type name.
	 */
	public String getArtifactTypeName() {
		return this.artifactTypeName;
	}

	/**
	 * Gets the artifact type display name for this artifact.
	 *
	 * @return The artifact type display name.
	 */
	public String getDisplayName() {
		return this.displayName;
	}

	/**
	 * Gets a short description for this artifact.
	 *
	 * @return The description, may be the empty string.
	 *
	 * @throws TskCoreException if there is a problem creating the description.
	 */
	public String getShortDescription() throws TskCoreException {
		BlackboardAttribute attr = null;
		StringBuilder shortDescription = new StringBuilder("");
		switch (ARTIFACT_TYPE.fromID(artifactTypeId)) {
			case TSK_WEB_BOOKMARK:  //web_bookmark, web_cookie, web_download, and web_history are the same attribute for now
			case TSK_WEB_COOKIE:
			case TSK_WEB_DOWNLOAD:
			case TSK_WEB_HISTORY:
				attr = getAttribute(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DOMAIN));
				break;
			case TSK_KEYWORD_HIT:
				attr = getAttribute(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_KEYWORD_PREVIEW));
				break;
			case TSK_DEVICE_ATTACHED:
				attr = getAttribute(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DEVICE_ID));
				break;
			case TSK_CONTACT: //contact, message, and calllog are the same attributes for now
			case TSK_MESSAGE:
			case TSK_CALLLOG:
				//get the first of these attributes which exists and is non null
				final ATTRIBUTE_TYPE[] typesThatCanHaveName = {ATTRIBUTE_TYPE.TSK_NAME,
					ATTRIBUTE_TYPE.TSK_PHONE_NUMBER,
					ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_FROM,
					ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_TO,
					ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_HOME,
					ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_MOBILE,
					ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_OFFICE,
					ATTRIBUTE_TYPE.TSK_EMAIL,
					ATTRIBUTE_TYPE.TSK_EMAIL_FROM,
					ATTRIBUTE_TYPE.TSK_EMAIL_TO,
					ATTRIBUTE_TYPE.TSK_EMAIL_HOME,
					ATTRIBUTE_TYPE.TSK_EMAIL_OFFICE}; //in the order we want to use them 
				for (ATTRIBUTE_TYPE t : typesThatCanHaveName) {
					attr = getAttribute(new BlackboardAttribute.Type(t));
					if (attr != null && !attr.getDisplayString().isEmpty()) {
						break;
					}
				}
				break;
			default:
				break;
		}
		if (attr != null) {
			shortDescription.append(attr.getAttributeType().getDisplayName()).append(": ").append(attr.getDisplayString());
		} else {
			shortDescription.append(getDisplayName());
		}
		//get the first of these date attributes which exists and is non null
		final ATTRIBUTE_TYPE[] typesThatCanHaveDate = {ATTRIBUTE_TYPE.TSK_DATETIME,
			ATTRIBUTE_TYPE.TSK_DATETIME_SENT,
			ATTRIBUTE_TYPE.TSK_DATETIME_RCVD,
			ATTRIBUTE_TYPE.TSK_DATETIME_CREATED,
			ATTRIBUTE_TYPE.TSK_DATETIME_MODIFIED,
			ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED,
			ATTRIBUTE_TYPE.TSK_DATETIME_START,
			ATTRIBUTE_TYPE.TSK_DATETIME_END};  //in the order we want to use them 
		BlackboardAttribute date;
		for (ATTRIBUTE_TYPE t : typesThatCanHaveDate) {
			date = getAttribute(new BlackboardAttribute.Type(t));
			if (date != null && !date.getDisplayString().isEmpty()) {
				shortDescription.append(" ");
				shortDescription.append(MessageFormat.format(bundle.getString("BlackboardArtifact.shortDescriptionDate.text"), date.getDisplayString()));  //NON-NLS
				break;
			}
		}
		return shortDescription.toString();
	}

	/**
	 * Gets the review status of this artifact, i.e., whether it has been
	 * approved, rejected, or is still waiting for a decision from the user.
	 *
	 * @return The review status.
	 */
	public ReviewStatus getReviewStatus() {
		return reviewStatus;
	}

	/**
	 * Sets the review status of this artifact, i.e., whether it has been
	 * approved, rejected, or is still waiting for a decision from the user.
	 *
	 * @param newStatus new status of the artifact
	 *
	 * @throws TskCoreException If an error occurs
	 */
	public void setReviewStatus(ReviewStatus newStatus) throws TskCoreException {
		getSleuthkitCase().setReviewStatus(this, newStatus);
		reviewStatus = newStatus;
	}
	
	/**
	 * Adds an attribute to this artifact.
	 *
	 * IMPORTANT NOTE: No more than one attribute of a given type should be
	 * added to an artifact.
	 *
	 * @param attribute The attribute to add
	 *
	 * @throws TskCoreException If an error occurs and the attribute was not
	 *                          added to the artifact.
	 */
	public void addAttribute(BlackboardAttribute attribute) throws TskCoreException {
		attribute.setArtifactId(artifactId);
		attribute.setCaseDatabase(getSleuthkitCase());
		getSleuthkitCase().addBlackboardAttribute(attribute, this.artifactTypeId);
		attrsCache.add(attribute);
	}

	/**
	 * Gets the attributes of this artifact.
	 *
	 * @return The attributes.
	 *
	 * @throws TskCoreException If an error occurs and the attributes cannot be
	 *                          fetched.
	 */
	public List<BlackboardAttribute> getAttributes() throws TskCoreException {
		ArrayList<BlackboardAttribute> attributes;
		if (false == loadedCacheFromDb) {
			attributes = getSleuthkitCase().getBlackboardAttributes(this);
			attrsCache.clear();
			attrsCache.addAll(attributes);
			loadedCacheFromDb = true;
		} else {
			attributes = new ArrayList<BlackboardAttribute>(attrsCache);
		}
		return attributes;
	}

	/**
	 * Gets the attribute of this artifact that matches a given type.
	 *
	 * IMPORTANT NOTE: No more than one attribute of a given type should be
	 * added to an artifact.
	 *
	 * @param attributeType The attribute type.
	 *
	 * @return The first attribute of the given type, or null if there are no
	 *         attributes of that type.
	 *
	 * @throws TskCoreException If an error occurs and the attribute is not
	 *                          fetched.
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
	 * Adds a collection of attributes to this artifact in a single operation
	 * (faster than adding each attribute individually).
	 *
	 * @param attributes The collection of attributes.
	 *
	 * @throws TskCoreException If an error occurs and the attributes were not
	 *                          added to the artifact.
	 */
	public void addAttributes(Collection<BlackboardAttribute> attributes) throws TskCoreException {
		if (attributes.isEmpty()) {
			return;
		}
		for (BlackboardAttribute attribute : attributes) {
			attribute.setArtifactId(artifactId);
			attribute.setCaseDatabase(getSleuthkitCase());
		}
		getSleuthkitCase().addBlackboardAttributes(attributes, artifactTypeId);
		attrsCache.addAll(attributes);
	}

	/**
	 * This overiding implementation returns the unique path of the parent. It
	 * does not include the Artifact name in the unique path.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	@Override
	public synchronized String getUniquePath() throws TskCoreException {

		// Return the path of the parrent file
		if (uniquePath == null) {
			uniquePath = "";
			Content myParent = getParent();
			if (myParent != null) {
				uniquePath = myParent.getUniquePath();
			}
		}
		return uniquePath;
	}

	@Override
	public synchronized Content getParent() throws TskCoreException {
		if (parent == null) {
			ObjectInfo parentInfo;
			try {
				parentInfo = getSleuthkitCase().getParentInfo(this);
			} catch (TskCoreException ex) {
				// there is not parent; not an error if we've got a data source
				return null;
			}
			parent = getSleuthkitCase().getContentById(parentInfo.getId());
		}
		return parent;
	}

	/**
	 * Get all artifacts associated with this content
	 *
	 * @return a list of blackboard artifacts
	 *
	 * @throws TskCoreException if critical error occurred within tsk core
	 */
	@Override
	public ArrayList<BlackboardArtifact> getAllArtifacts() throws TskCoreException {
		// Currently we don't have any artifacts derived from an artifact.
		return new ArrayList<BlackboardArtifact>();
	}

	/**
	 * Get all artifacts associated with this content that have the given type
	 * name
	 *
	 * @param artifactTypeName name of the type to look up
	 *
	 * @return a list of blackboard artifacts matching the type
	 *
	 * @throws TskCoreException if critical error occurred within tsk core
	 */
	@Override
	public ArrayList<BlackboardArtifact> getArtifacts(String artifactTypeName) throws TskCoreException {
		// Currently we don't have any artifacts derived from an artifact.
		return new ArrayList<BlackboardArtifact>();
	}

	/**
	 * Get all artifacts associated with this content that have the given type
	 * id
	 *
	 * @param artifactTypeID type id to look up
	 *
	 * @return a list of blackboard artifacts matching the type
	 *
	 * @throws TskCoreException if critical error occurred within tsk core
	 */
	@Override
	public ArrayList<BlackboardArtifact> getArtifacts(int artifactTypeID) throws TskCoreException {
		// Currently we don't have any artifacts derived from an artifact.
		return new ArrayList<BlackboardArtifact>();
	}

	/**
	 * Get all artifacts associated with this content that have the given type
	 *
	 * @param type type to look up
	 *
	 * @return a list of blackboard artifacts matching the type
	 *
	 * @throws TskCoreException if critical error occurred within tsk core
	 */
	@Override
	public ArrayList<BlackboardArtifact> getArtifacts(BlackboardArtifact.ARTIFACT_TYPE type) throws TskCoreException {
		// Currently we don't have any artifacts derived from an artifact.
		return new ArrayList<BlackboardArtifact>();
	}

	/**
	 * Get count of all artifacts associated with this content
	 *
	 * @return count of all blackboard artifacts for this content
	 *
	 * @throws TskCoreException if critical error occurred within tsk core
	 */
	@Override
	public long getAllArtifactsCount() throws TskCoreException {
		// Currently we don't have any artifacts derived from an artifact.
		return 0;
	}

	/**
	 * Get count of all artifacts associated with this content that have the
	 * given type name
	 *
	 * @param artifactTypeName name of the type to look up
	 *
	 * @return count of blackboard artifacts matching the type
	 *
	 * @throws TskCoreException if critical error occurred within tsk core
	 */
	@Override
	public long getArtifactsCount(String artifactTypeName) throws TskCoreException {
		// Currently we don't have any artifacts derived from an artifact.
		return 0;
	}

	/**
	 * Get count of all artifacts associated with this content that have the
	 * given type id
	 *
	 * @param artifactTypeID type id to look up
	 *
	 * @return count of blackboard artifacts matching the type
	 *
	 * @throws TskCoreException if critical error occurred within tsk core
	 */
	@Override
	public long getArtifactsCount(int artifactTypeID) throws TskCoreException {
		// Currently we don't have any artifacts derived from an artifact.
		return 0;
	}

	/**
	 * Get count of all artifacts associated with this content that have the
	 * given type
	 *
	 * @param type type to look up
	 *
	 * @return count of blackboard artifacts matching the type
	 *
	 * @throws TskCoreException if critical error occurred within tsk core
	 */
	@Override
	public long getArtifactsCount(BlackboardArtifact.ARTIFACT_TYPE type) throws TskCoreException {
		// Currently we don't have any artifacts derived from an artifact.
		return 0;
	}

	/**
	 * Return the TSK_GEN_INFO artifact for the file so that individual
	 * attributes can be added to it. Creates one if it does not already exist.
	 *
	 * @return Instance of the TSK_GEN_INFO artifact
	 *
	 * @throws TskCoreException
	 */
	@Override
	public BlackboardArtifact getGenInfoArtifact() throws TskCoreException {
		// Currently we don't have any artifacts derived from an artifact.
		return null;
	}

	/**
	 * Return the TSK_GEN_INFO artifact for the file so that individual
	 * attributes can be added to it. If one does not create, behavior depends
	 * on the create argument.
	 *
	 * @param create If true, an artifact will be created if it does not already
	 *               exist.
	 *
	 * @return Instance of the TSK_GEN_INFO artifact or null if artifact does
	 *         not already exist and create was set to false
	 *
	 * @throws TskCoreException
	 */
	@Override
	public BlackboardArtifact getGenInfoArtifact(boolean create) throws TskCoreException {
		// Currently we don't have any artifacts derived from an artifact.
		if (create) {
			throw new TskCoreException("Artifacts of artifacts are not supported.");
		}

		return null;
	}

	/**
	 * Return attributes of a given type from TSK_GEN_INFO.
	 *
	 * @param attr_type Attribute type to find inside of the TSK_GEN_INFO
	 *                  artifact.
	 *
	 * @return Attributes
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	@Override
	public ArrayList<BlackboardAttribute> getGenInfoAttributes(BlackboardAttribute.ATTRIBUTE_TYPE attr_type) throws TskCoreException {
		// Currently we don't have any artifacts derived from an artifact.
		return new ArrayList<BlackboardAttribute>();
	}

	/**
	 * Get the names of all the hashsets that this content is in.
	 *
	 * @return the names of the hashsets that this content is in
	 *
	 * @throws TskCoreException if critical error occurred within tsk core
	 */
	@Override
	public Set<String> getHashSetNames() throws TskCoreException {
		// Currently we don't have any artifacts derived from an artifact.
		return new HashSet<String>();
	}

	/**
	 * Create and add an artifact associated with this content to the blackboard
	 *
	 * @param artifactTypeID id of the artifact type (if the id doesn't already
	 *                       exist an exception will be thrown)
	 *
	 * @return the blackboard artifact created (the artifact type id can be
	 *         looked up from this)
	 *
	 * @throws TskCoreException if critical error occurred within tsk core
	 */
	@Override
	public BlackboardArtifact newArtifact(int artifactTypeID) throws TskCoreException {
		throw new TskCoreException("Cannot create artifact of an artifact. Not supported.");
	}

	/**
	 * Create and add an artifact associated with this content to the blackboard
	 *
	 * @param type artifact enum type
	 *
	 * @return the blackboard artifact created (the artifact type id can be
	 *         looked up from this)
	 *
	 * @throws TskCoreException if critical error occurred within tsk core
	 */
	@Override
	public BlackboardArtifact newArtifact(BlackboardArtifact.ARTIFACT_TYPE type) throws TskCoreException {
		throw new TskCoreException("Cannot create artifact of an artifact. Not supported.");
	}

	/**
	 * Accepts a Sleuthkit item visitor (Visitor design pattern).
	 *
	 * @param visitor A SleuthkitItemVisitor supplying an algorithm to run using
	 *                this derived file as input.
	 *
	 * @return The output of the algorithm.
	 */
	@Override
	public <T> T accept(ContentVisitor<T> v) {
		return v.visit(this);
	}

	/**
	 * Tests this artifact for equality with another object.
	 *
	 * @param object The other object.
	 *
	 * @return True or false.
	 */
	@Override
	public boolean equals(Object object) {
		if (object == null) {
			return false;
		}
		if (getClass() != object.getClass()) {
			return false;
		}
		final BlackboardArtifact other = (BlackboardArtifact) object;
		return artifactId == other.getArtifactID();
	}

	/**
	 * Gets the hash code for this artifact.
	 *
	 * @return The hash code.
	 */
	@Override
	public int hashCode() {
		int hash = 7;
		hash = 41 * hash + (int) (this.artifactId ^ (this.artifactId >>> 32));
		return hash;
	}

	/**
	 * Gets a string representation of this artifact.
	 *
	 * @return The string.
	 */
	@Override
	public String toString() {
		return "BlackboardArtifact{" + "artifactID=" + artifactId + ", objID=" + getObjectID() + ", artifactObjID=" + artifactObjId + ", artifactTypeID=" + artifactTypeId + ", artifactTypeName=" + artifactTypeName + ", displayName=" + displayName + ", Case=" + getSleuthkitCase() + '}'; //NON-NLS
	}

	/**
	 * Accepts a visitor SleuthkitItemVisitor that will perform an operation on
	 * this artifact type and return some object as the result of the operation.
	 *
	 * @param visitor The visitor, where the type parameter of the visitor is
	 *                the type of the object that will be returned as the result
	 *                of the visit operation.
	 *
	 * @return An object of type T.
	 */
	@Override
	public <T> T accept(SleuthkitItemVisitor<T> visitor) {
		return visitor.visit(this);
	}

	/**
	 * Get the (reported) size of the content object. Artifact content is a
	 * string dump of all its attributes.
	 *
	 * @return size of the content in bytes
	 */
	@Override
	public long getSize() {

		if (contentBytes == null) {
			try {
				loadArtifactContent();
			} catch (TskCoreException ex) {
				return 0;
			}
		}

		return contentBytes.length;
	}

	/**
	 * Close the Content object.
	 */
	@Override
	public void close() {
		contentBytes = null;
	}

	/**
	 * Reads content data for this artifact Artifact content is a string dump of
	 * all its attributes.
	 *
	 * @param buf    a character array of data (in bytes) to copy read data to
	 * @param offset byte offset in the content to start reading from
	 * @param len    number of bytes to read into buf.
	 *
	 * @return num of bytes read, or -1 on error
	 *
	 * @throws TskCoreException if critical error occurred during read in the
	 *                          tsk core
	 */
	@Override
	public final int read(byte[] buf, long offset, long len) throws TskCoreException {

		if (contentBytes == null) {
			loadArtifactContent();
		}

		if (0 == contentBytes.length) {
			return 0;
		}

		// Copy bytes
		long readLen = Math.min(contentBytes.length - offset, len);
		System.arraycopy(contentBytes, 0, buf, 0, (int) readLen);

		return (int) readLen;
	}

	@Override
	public String getName() {
		return this.displayName + getArtifactID();
	}

	@Override
	public Content getDataSource() throws TskCoreException {
		Content myParent = getParent();
		if (myParent == null) {
			return null;
		}

		return myParent.getDataSource();
	}

	/**
	 * Load and save the content for the artifact. Artifact content is a string
	 * dump of all its attributes.
	 *
	 * @throws TskCoreException if critical error occurred during read
	 */
	private void loadArtifactContent() throws TskCoreException {
		StringBuilder artifactContents = new StringBuilder();

		Content dataSource = null;
		try {
			dataSource = getDataSource();
		} catch (TskCoreException ex) {
			throw new TskCoreException("Unable to get datasource for artifact: " + this.toString(), ex);
		}
		if (dataSource == null) {
			throw new TskCoreException("Datasource was null for artifact: " + this.toString());
		}

		try {
			for (BlackboardAttribute attribute : getAttributes()) {
				artifactContents.append(attribute.getAttributeType().getDisplayName());
				artifactContents.append(" : ");
				artifactContents.append(attribute.getDisplayString());
				artifactContents.append(System.lineSeparator());
			}
		} catch (TskCoreException ex) {
			throw new TskCoreException("Unable to get attributes for artifact: " + this.toString(), ex);
		}

		try {
			contentBytes = artifactContents.toString().getBytes("UTF-8");
		} catch (UnsupportedEncodingException ex) {
			throw new TskCoreException("Failed to convert artifact string to bytes for artifact: " + this.toString(), ex);
		}

	}

	/**
	 * An artifact type.
	 */
	public static final class Type implements Serializable {

		private static final long serialVersionUID = 1L;
		private final String typeName;
		private final int typeID;
		private final String displayName;

		/**
		 * Constructs a custom artifact type.
		 *
		 * @param typeName    The name of the type.
		 * @param typeID      The id of the type.
		 * @param displayName The display name of the type.
		 */
		public Type(int typeID, String typeName, String displayName) {
			this.typeID = typeID;
			this.typeName = typeName;
			this.displayName = displayName;
		}

		/**
		 * Constructs a standard artifact type.
		 *
		 * @param type An element of the ARTIFACT_TYPE enum.
		 */
		public Type(ARTIFACT_TYPE type) {
			this(type.getTypeID(), type.getLabel(), type.getDisplayName());
		}

		/**
		 * Gets the type for this artifact type.
		 *
		 * @return The type name.
		 */
		public String getTypeName() {
			return this.typeName;
		}

		/**
		 * Gets the type id for this artifact type.
		 *
		 * @return The type id.
		 */
		public int getTypeID() {
			return this.typeID;
		}

		/**
		 * Gets display name of this artifact type.
		 *
		 * @return The display name.
		 */
		public String getDisplayName() {
			return this.displayName;
		}

		/**
		 * Tests this artifact type for equality with another object.
		 *
		 * @param that The other object.
		 *
		 * @return True or false.
		 */
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
		 * Compares two artifact types to see if they are the same type.
		 *
		 * @param that The other type.
		 *
		 * @return True or false.
		 */
		private boolean sameType(Type that) {
			return this.typeName.equals(that.getTypeName())
					&& this.displayName.equals(that.getDisplayName())
					&& this.typeID == that.getTypeID();
		}

		/**
		 * Gets the hash code for this artifact type.
		 *
		 * @return The hash code.
		 */
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
	 * Enum for the standard artifact types. Refer to
	 * http://wiki.sleuthkit.org/index.php?title=Artifact_Examples for details
	 * on the standard attributes for each standard artifact type.
	 */
	public enum ARTIFACT_TYPE implements SleuthkitVisitableItem {

		/**
		 * A generic information artifact, the default type.
		 */
		TSK_GEN_INFO(1, "TSK_GEN_INFO", //NON-NLS
				bundle.getString("BlackboardArtifact.tskGenInfo.text")),
		/**
		 * A Web bookmark.
		 */
		TSK_WEB_BOOKMARK(2, "TSK_WEB_BOOKMARK", //NON-NLS
				bundle.getString("BlackboardArtifact.tskWebBookmark.text")),
		/**
		 * A Web cookie
		 */
		TSK_WEB_COOKIE(3, "TSK_WEB_COOKIE",
				bundle.getString("BlackboardArtifact.tskWebCookie.text")), //NON-NLS				
		/**
		 * A Web history.
		 */
		TSK_WEB_HISTORY(4, "TSK_WEB_HISTORY", //NON-NLS
				bundle.getString("BlackboardArtifact.tskWebHistory.text")),
		/**
		 * A Web download.
		 */
		TSK_WEB_DOWNLOAD(5, "TSK_WEB_DOWNLOAD", //NON-NLS
				bundle.getString("BlackboardArtifact.tskWebDownload.text")),
		/**
		 * A recent object.
		 */
		TSK_RECENT_OBJECT(6, "TSK_RECENT_OBJ", //NON-NLS
				bundle.getString("BlackboardArtifact.tsk.recentObject.text")),
		/**
		 * A GPS track point (geolocation data).
		 */
		TSK_GPS_TRACKPOINT(7, "TSK_GPS_TRACKPOINT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskGpsTrackpoint.text")),
		/**
		 * An installed program.
		 */
		TSK_INSTALLED_PROG(8, "TSK_INSTALLED_PROG", //NON-NLS
				bundle.getString("BlackboardArtifact.tskInstalledProg.text")),
		/**
		 * A search hit for a keyword.
		 */
		TSK_KEYWORD_HIT(9, "TSK_KEYWORD_HIT",
				bundle.getString("BlackboardArtifact.tskKeywordHits.text")),
		/**
		 * A hit for a hash set (hash database).
		 */
		TSK_HASHSET_HIT(10, "TSK_HASHSET_HIT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskHashsetHit.text")),
		/**
		 * An attached device.
		 */
		TSK_DEVICE_ATTACHED(11, "TSK_DEVICE_ATTACHED", //NON-NLS
				bundle.getString("BlackboardArtifact.tskDeviceAttached.text")),
		/**
		 * An meta-artifact to call attention to a file deemed to be
		 * interesting.
		 */
		TSK_INTERESTING_FILE_HIT(12, "TSK_INTERESTING_FILE_HIT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskInterestingFileHit.text")), ///< an interesting/notable file hit
		/**
		 * An email message.
		 */
		TSK_EMAIL_MSG(13, "TSK_EMAIL_MSG", //NON-NLS
				bundle.getString("BlackboardArtifact.tskEmailMsg.text")),
		/**
		 * Text extracted from the source content.
		 */
		TSK_EXTRACTED_TEXT(14, "TSK_EXTRACTED_TEXT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskExtractedText.text")),
		/**
		 * A Web search engine query extracted from Web history.
		 */
		TSK_WEB_SEARCH_QUERY(15, "TSK_WEB_SEARCH_QUERY", //NON-NLS
				bundle.getString("BlackboardArtifact.tskWebSearchQuery.text")),
		/**
		 * EXIF metadata.
		 */
		TSK_METADATA_EXIF(16, "TSK_METADATA_EXIF", //NON-NLS
				bundle.getString("BlackboardArtifact.tskMetadataExif.text")),
		/**
		 * A tag applied to a file.
		 *
		 * @deprecated Tags are no longer treated as artifacts.
		 */
		@Deprecated
		TSK_TAG_FILE(17, "TSK_TAG_FILE", //NON-NLS
				bundle.getString("BlackboardArtifact.tagFile.text")),
		/**
		 * A tag applied to an artifact.
		 *
		 * @deprecated Tags are no longer treated as artifacts.
		 */
		@Deprecated
		TSK_TAG_ARTIFACT(18, "TSK_TAG_ARTIFACT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskTagArtifact.text")),
		/**
		 * Information pertaining to an operating system.
		 */
		TSK_OS_INFO(19, "TSK_OS_INFO", //NON-NLS
				bundle.getString("BlackboardArtifact.tskOsInfo.text")),
		/**
		 * An operating system user account.
		 */
		TSK_OS_ACCOUNT(20, "TSK_OS_ACCOUNT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskOsAccount.text")),
		/**
		 * An application or Web service account.
		 */
		TSK_SERVICE_ACCOUNT(21, "TSK_SERVICE_ACCOUNT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskServiceAccount.text")),
		/**
		 * Output from an external tool or module (raw text).
		 *
		 * @deprecated Tool output should be saved as a report.
		 */
		@Deprecated
		TSK_TOOL_OUTPUT(22, "TSK_TOOL_OUTPUT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskToolOutput.text")),
		/**
		 * A contact extracted from a phone, or from an address
		 * book/email/messaging application.
		 */
		TSK_CONTACT(23, "TSK_CONTACT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskContact.text")),
		/**
		 * An SMS/MMS message extracted from phone, or from another messaging
		 * application, like IM.
		 */
		TSK_MESSAGE(24, "TSK_MESSAGE", //NON-NLS
				bundle.getString("BlackboardArtifact.tskMessage.text")),
		/**
		 * A phone call log extracted from a phone or softphone application.
		 */
		TSK_CALLLOG(25, "TSK_CALLLOG", //NON-NLS
				bundle.getString("BlackboardArtifact.tskCalllog.text")),
		/**
		 * A calendar entry from a phone, PIM, or a calendar application.
		 */
		TSK_CALENDAR_ENTRY(26, "TSK_CALENDAR_ENTRY", //NON-NLS
				bundle.getString("BlackboardArtifact.tskCalendarEntry.text")),
		/**
		 * A speed dial entry from a phone.
		 */
		TSK_SPEED_DIAL_ENTRY(27, "TSK_SPEED_DIAL_ENTRY", //NON-NLS
				bundle.getString("BlackboardArtifact.tskSpeedDialEntry.text")),
		/**
		 * A bluetooth pairing entry.
		 */
		TSK_BLUETOOTH_PAIRING(28, "TSK_BLUETOOTH_PAIRING", //NON-NLS
				bundle.getString("BlackboardArtifact.tskBluetoothPairing.text")),
		/**
		 * A GPS bookmark.
		 */
		TSK_GPS_BOOKMARK(29, "TSK_GPS_BOOKMARK", //NON-NLS
				bundle.getString("BlackboardArtifact.tskGpsBookmark.text")),
		/**
		 * A GPS last known location record.
		 */
		TSK_GPS_LAST_KNOWN_LOCATION(30, "TSK_GPS_LAST_KNOWN_LOCATION", //NON-NLS
				bundle.getString("BlackboardArtifact.tskGpsLastKnownLocation.text")),
		/**
		 * A GPS search record.
		 */
		TSK_GPS_SEARCH(31, "TSK_GPS_SEARCH", //NON-NLS
				bundle.getString("BlackboardArtifact.tskGpsSearch.text")),
		/**
		 * Application run information.
		 */
		TSK_PROG_RUN(32, "TSK_PROG_RUN", //NON-NLS
				bundle.getString("BlackboardArtifact.tskProgRun.text")),
		/**
		 * An encrypted file.
		 */
		TSK_ENCRYPTION_DETECTED(33, "TSK_ENCRYPTION_DETECTED", //NON-NLS
				bundle.getString("BlackboardArtifact.tskEncryptionDetected.text")),
		/**
		 * A file with an extension that does not match its MIME type.
		 */
		TSK_EXT_MISMATCH_DETECTED(34, "TSK_EXT_MISMATCH_DETECTED", //NON-NLS
				bundle.getString("BlackboardArtifact.tskExtMismatchDetected.text")),
		/**
		 * An meta-artifact to call attention to an artifact deemed to be
		 * interesting.
		 */
		TSK_INTERESTING_ARTIFACT_HIT(35, "TSK_INTERESTING_ARTIFACT_HIT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskInterestingArtifactHit.text")),
		/**
		 * A route based on GPS coordinates.
		 */
		TSK_GPS_ROUTE(36, "TSK_GPS_ROUTE", //NON-NLS
				bundle.getString("BlackboardArtifact.tskGpsRoute.text")),
		/**
		 * A remote drive.
		 */
		TSK_REMOTE_DRIVE(37, "TSK_REMOTE_DRIVE", //NON-NLS
				bundle.getString("BlackboardArtifact.tskRemoteDrive.text")),
		/**
		 * A human face was detected in a media file.
		 */
		TSK_FACE_DETECTED(38, "TSK_FACE_DETECTED", //NON-NLS
				bundle.getString("BlackboardArtifact.tskFaceDetected.text")),
		/**
		 * An account.
		 */
		TSK_ACCOUNT(39, "TSK_ACCOUNT", //NON-NLS
				bundle.getString("BlackboardArtifact.tskAccount.text")),
		/**
		 * An encrypted file.
		 */
		TSK_ENCRYPTION_SUSPECTED(40, "TSK_ENCRYPTION_SUSPECTED", //NON-NLS
				bundle.getString("BlackboardArtifact.tskEncryptionSuspected.text"));

		private final String label;
		private final int typeId;
		private final String displayName;

		/**
		 * Constructs a value for the standard artifact types enum.
		 *
		 * @param typeId      The type id.
		 * @param label       The type name.
		 * @param displayName The type display name.
		 */
		private ARTIFACT_TYPE(int typeId, String label, String displayName) {
			this.typeId = typeId;
			this.label = label;
			this.displayName = displayName;
		}

		/**
		 * Gets the type id for this standard artifact type.
		 *
		 * @return type id
		 */
		public int getTypeID() {
			return this.typeId;
		}

		/**
		 * Gets the type name (label) for this standard artifact type.
		 *
		 * @return The type name.
		 */
		public String getLabel() {
			return this.label;
		}

		/**
		 * Gets the standard artifact type enum value that corresponds to a
		 * given type name (label).
		 *
		 * @param label The type name
		 *
		 * @return The enum element.
		 */
		static public ARTIFACT_TYPE fromLabel(String label) {
			for (ARTIFACT_TYPE value : ARTIFACT_TYPE.values()) {
				if (value.getLabel().equals(label)) {
					return value;
				}
			}
			throw new IllegalArgumentException("No ARTIFACT_TYPE matching type: " + label);
		}

		/**
		 * Gets the artifact type enum value that corresponds to a given type
		 * id.
		 *
		 * @param id The type id.
		 *
		 * @return the corresponding enum
		 */
		static public ARTIFACT_TYPE fromID(int id) {
			for (ARTIFACT_TYPE value : ARTIFACT_TYPE.values()) {
				if (value.getTypeID() == id) {
					return value;
				}
			}
			throw new IllegalArgumentException("No ARTIFACT_TYPE matching type: " + id);
		}

		/**
		 * Gets the display name of this standard artifact type.
		 *
		 * @return The display name.
		 */
		public String getDisplayName() {
			return displayName;
		}

		/**
		 * Accepts a visitor SleuthkitItemVisitor that will perform an operation
		 * on this artifact type and return some object as the result of the
		 * operation.
		 *
		 * @param visitor The visitor, where the type parameter of the visitor
		 *                is the type of the object that will be returned as the
		 *                result of the visit operation.
		 *
		 * @return An object of type T.
		 */
		@Override
		public <T> T accept(SleuthkitItemVisitor<T> visitor) {
			return visitor.visit(this);
		}

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
			}
		}

		/**
		 * Constructs a value for the review status enum.
		 *
		 * @param id             The status id.
		 * @param name           The status name
		 * @param displayNameKey The bundle.properties key for the status
		 *                       display name.
		 */
		private ReviewStatus(Integer id, String name, String displayNameKey) {
			this.id = id;
			this.name = name;
			this.displayName = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle").getString(displayNameKey);
		}

		/**
		 * Gets the review status value with the given id, if one exists.
		 *
		 * @param id A review status id.
		 *
		 * @return The review status with the given id, or null if none exists.
		 */
		public static ReviewStatus withID(int id) {
			return idToStatus.get(id);
		}

		/**
		 * Gets the id of this review status.
		 *
		 * @return The id of this review status.
		 */
		public Integer getID() {
			return id;
		}

		/**
		 * Gets the name of this review status.
		 *
		 * @return The name of this review status.
		 */
		String getName() {
			return name;
		}

		/**
		 * Gets the display name of this review status.
		 *
		 * @return The display name of this review status.
		 */
		public String getDisplayName() {
			return displayName;
		}
	}

	/**
	 * Constructs an artifact that has been posted to the blackboard. An
	 * artifact is a typed collection of name value pairs (attributes) that is
	 * associated with its source content (either a data source, or file within
	 * a data source). Both standard artifact types and custom artifact types
	 * are supported.
	 *
	 * @param sleuthkitCase    The SleuthKit case (case database) that contains
	 *                         the artifact data.
	 * @param artifactID       The unique id for this artifact.
	 * @param objID            The unique id of the content with which this
	 *                         artifact is associated.
	 * @param artifactObjID	   The unique id of the artifact, in tsk_objects
	 * @param dataSourceObjId  The id of the data source
	 * @param artifactTypeID   The type id of this artifact.
	 * @param artifactTypeName The type name of this artifact.
	 * @param displayName      The display name of this artifact.
	 *
	 * @deprecated Use new BlackboardArtifact(SleuthkitCase, long, long, int,
	 * String, String, ReviewStatus) instead.
	 */
	@Deprecated
	protected BlackboardArtifact(SleuthkitCase sleuthkitCase, long artifactID, long objID, long artifactObjID, long dataSourceObjId, int artifactTypeID, String artifactTypeName, String displayName) {
		this(sleuthkitCase, artifactID, objID, artifactObjID, dataSourceObjId, artifactTypeID, artifactTypeName, displayName, ReviewStatus.UNDECIDED);
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
	 *
	 * @deprecated An artifact should not have multiple attributes of the same
	 * type. Use getAttribute(BlackboardAttribute.Type) instead.
	 */
	@Deprecated
	public List<BlackboardAttribute> getAttributes(final BlackboardAttribute.ATTRIBUTE_TYPE attributeType) throws TskCoreException {
		if (loadedCacheFromDb == false) {
			List<BlackboardAttribute> attrs = getSleuthkitCase().getBlackboardAttributes(this);
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

	@Override
	public long getId() {
		return this.artifactObjId;
	}

	/**
	 * Gets the object ids of children of this artifact, if any
	 *
	 * @return A list of the object ids of children.
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
	public boolean hasChildren() throws TskCoreException {
		if (checkedHasChildren == true) {
			return hasChildren;
		}

		childrenCount = this.getSleuthkitCase().getContentChildrenCount(this);

		hasChildren = childrenCount > 0;
		checkedHasChildren = true;

		return hasChildren;
	}

	/**
	 * Get all children of this artifact, if any.
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
}
