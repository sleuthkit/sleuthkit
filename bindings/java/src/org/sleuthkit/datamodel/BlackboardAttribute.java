/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011-2021 Basis Technology Corp.
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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.ResourceBundle;
import java.util.TimeZone;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Represents an attribute of an artifact posted to the blackboard. Instances
 * should be constructed and then added to an instance of the BlackboardArtifact
 * class.
 *
 * Attributes are a name-value pairs. The name is the type of the attribute, as
 * represented by the BlackboardAttribute.Type class. Standard attribute types
 * are specified by the ATTRIBUTE_TYPE enumeration. Custom attribute types may
 * be created by constructing a BlackboardAttribute.Type object and calling the
 * SleuthkitCase.addArtifactAttributeType method. The BlackboardAttribute.Type
 * object that is returned can then be used to create instances of the custom
 * attribute by calling the appropriate BlackboardAttribute constructor. It can
 * also be used to do blackboard queries involving the custom type.
 */
public class BlackboardAttribute extends AbstractAttribute {

	private static final Logger LOGGER = Logger.getLogger(BlackboardAttribute.class.getName());

	private static final ResourceBundle bundle = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle");

	private String context;
	private String sources;

	private long artifactID;

	// Cached parent artifact. This field is populated lazily upon the first
	// call to getParentArtifact().
	private BlackboardArtifact parentArtifact;

	// The parent data source is defined as being
	// the data source of the parent artifact.
	private Long parentDataSourceID;

	/**
	 * Constructs a standard attribute with an integer value. The attribute
	 * should be added to an appropriate artifact.
	 *
	 * @param attributeType The standard attribute type.
	 * @param source        The source of this attribute.
	 * @param valueInt      The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  standard attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER.
	 */
	public BlackboardAttribute(ATTRIBUTE_TYPE attributeType, String source, int valueInt) throws IllegalArgumentException {
		super(new BlackboardAttribute.Type(attributeType), valueInt);
		this.sources = replaceNulls(source);
		this.context = "";
	}

	/**
	 * Constructs an attribute with an integer value. The attribute should be
	 * added to an appropriate artifact.
	 *
	 * @param attributeType The attribute type.
	 * @param source        The source of this attribute.
	 * @param valueInt      The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER.
	 */
	public BlackboardAttribute(Type attributeType, String source, int valueInt) throws IllegalArgumentException {
		super(attributeType, valueInt);
		this.sources = replaceNulls(source);
		this.context = "";
	}

	/**
	 * Constructs a standard attribute with a long/datetime value. If the value
	 * is a datetime, it should be seconds from January 1, 1970. The attribute
	 * should be added to an appropriate artifact.
	 *
	 * @param attributeType The standard attribute type.
	 * @param source        The source of this attribute.
	 * @param valueLong     The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  standard attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG
	 *                                  or
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME.
	 */
	public BlackboardAttribute(ATTRIBUTE_TYPE attributeType, String source, long valueLong) throws IllegalArgumentException {
		super(new BlackboardAttribute.Type(attributeType), valueLong);
		this.sources = replaceNulls(source);
		this.context = "";
	}

	/**
	 * Constructs an attribute with a long/datetime value. The attribute should
	 * be added to an appropriate artifact.
	 *
	 * @param attributeType The attribute type.
	 * @param source        The source of this attribute.
	 * @param valueLong     The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  standard attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG
	 *                                  or
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME.
	 */
	public BlackboardAttribute(Type attributeType, String source, long valueLong) throws IllegalArgumentException {
		super(attributeType, valueLong);
		this.sources = replaceNulls(source);
		this.context = "";
	}

	/**
	 * Constructs a standard attribute with a double value. The attribute should
	 * be added to an appropriate artifact.
	 *
	 * @param attributeType The standard attribute type.
	 * @param source        The source of this attribute.
	 * @param valueDouble   The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  standard attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE.
	 */
	public BlackboardAttribute(ATTRIBUTE_TYPE attributeType, String source, double valueDouble) throws IllegalArgumentException {
		super(new BlackboardAttribute.Type(attributeType), valueDouble);
		this.sources = replaceNulls(source);
		this.context = "";
	}

	/**
	 * Constructs an attribute with a double value. The attribute should be
	 * added to an appropriate artifact.
	 *
	 * @param attributeType The attribute type.
	 * @param source        The source of this attribute.
	 * @param valueDouble   The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE.
	 */
	public BlackboardAttribute(Type attributeType, String source, double valueDouble) throws IllegalArgumentException {
		super(attributeType, valueDouble);
		this.sources = replaceNulls(source);
		this.context = "";
	}

	/**
	 * Constructs a standard attribute with an string value. The attribute
	 * should be added to an appropriate artifact.
	 *
	 * @param attributeType The standard attribute type.
	 * @param source        The source of this attribute.
	 * @param valueString   The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  standard attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING
	 *                                  or
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.JSON
	 */
	public BlackboardAttribute(ATTRIBUTE_TYPE attributeType, String source, String valueString) throws IllegalArgumentException {
		super(new BlackboardAttribute.Type(attributeType), valueString);
		this.sources = replaceNulls(source);
		this.context = "";
	}

	/**
	 * Constructs an attribute with a string value. The attribute should be
	 * added to an appropriate artifact.
	 *
	 * @param attributeType The attribute type.
	 * @param source        The source of this attribute.
	 * @param valueString   The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING.
	 */
	public BlackboardAttribute(Type attributeType, String source, String valueString) throws IllegalArgumentException {
		super(attributeType, valueString);
		this.sources = replaceNulls(source);
		this.context = "";
	}

	/**
	 * Constructs a standard attribute with a byte array value. The attribute
	 * should be added to an appropriate artifact.
	 *
	 * @param attributeType The standard attribute type.
	 * @param source        The source of this attribute.
	 * @param valueBytes    The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  standard attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE.
	 */
	public BlackboardAttribute(ATTRIBUTE_TYPE attributeType, String source, byte[] valueBytes) throws IllegalArgumentException {
		super(new BlackboardAttribute.Type(attributeType), valueBytes);
		this.sources = replaceNulls(source);
		this.context = "";
	}

	/**
	 * Constructs an attribute with a byte array value. The attribute should be
	 * added to an appropriate artifact.
	 *
	 * @param attributeType The attribute type.
	 * @param source        The source of this attribute.
	 * @param valueBytes    The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE.
	 */
	public BlackboardAttribute(Type attributeType, String source, byte[] valueBytes) throws IllegalArgumentException {
		super(attributeType, valueBytes);
		this.sources = replaceNulls(source);
		this.context = "";
	}

	/**
	 * Gets the id of the artifact associated with this attribute, if the
	 * attribute was added to an artifact. Attributes should always be added to
	 * artifacts after they are constructed.
	 *
	 * @return The artifact id or zero if the artifact id has not been set.
	 */
	public long getArtifactID() {
		return artifactID;
	}

	/**
	 * Sets the artifact id.
	 *
	 * @param artifactID The artifact id.
	 */
	void setArtifactId(long artifactID) {
		this.artifactID = artifactID;
	}

	/**
	 * Gets the sources of this attribute.
	 *
	 * @return A list of sources, may be empty.
	 */
	public List<String> getSources() {
		if (null != sources && !this.sources.isEmpty()) {
			List<String> modules = Arrays.asList(sources.split(","));
			return modules;
		} else {
			return Collections.emptyList();
		}
	}

	/**
	 * Adds a source to the sources of this attribute.
	 *
	 * @param source The source name.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public void addSource(String source) throws TskCoreException {
		this.sources = getCaseDatabase().addSourceToArtifactAttribute(this, source);
	}

	/**
	 * Gets the artifact associated with this attribute. The artifact can be
	 * used to get the source content for the artifact as well as any other
	 * attributes associated with the artifact.
	 *
	 * @return The artifact.
	 *
	 * @throws TskCoreException If there is no artifact associated with this
	 *                          attribute or there is an error reading from the
	 *                          case database.
	 */
	public BlackboardArtifact getParentArtifact() throws TskCoreException {
		if (parentArtifact == null) {
			parentArtifact = getCaseDatabase().getBlackboardArtifact(getArtifactID());
		}
		return parentArtifact;
	}

	@Override
	public int hashCode() {
		return Objects.hash(
				this.getAttributeType(), this.getValueInt(), this.getValueLong(), this.getValueDouble(),
				this.getValueString(), this.getValueBytes(), this.getSources(), getContext());
	}

	@Override
	public boolean equals(Object that) {
		if (this == that) {
			return true;
		} else if (that instanceof BlackboardAttribute) {
			BlackboardAttribute other = (BlackboardAttribute) that;
			Object[] thisObject = new Object[]{this.getSources(), this.getContext()};
			Object[] otherObject = new Object[]{other.getSources(), other.getContext()};
			return areValuesEqual(that) && Objects.deepEquals(thisObject, otherObject);
		} else {
			return false;
		}
	}

	@Override
	public String toString() {
		return "BlackboardAttribute{" + "artifactID=" + getArtifactID() + ", attributeType=" + getAttributeType().toString() + ", moduleName=" + getSources() + ", context=" + context + ", valueInt=" + getValueInt() + ", valueLong=" + getValueLong() + ", valueDouble=" + getValueDouble() + ", valueString=" + getValueString() + ", valueBytes=" + Arrays.toString(getValueBytes()) + ", Case=" + getCaseDatabase() + '}'; //NON-NLS
	}

	/**
	 * Gets the attribute value as a string, formatted as required.
	 *
	 * @return The value as a string.
	 */
	@Override
	public String getDisplayString() {
		switch (getAttributeType().getValueType()) {
			case DATETIME: {
				try {
					if (parentDataSourceID == null) {
						BlackboardArtifact parent = getParentArtifact();
						parentDataSourceID = parent.getDataSourceObjectID();
					}
					final Content dataSource = parentDataSourceID != null ? getCaseDatabase().getContentById(parentDataSourceID) : null;
					if ((dataSource != null) && (dataSource instanceof Image)) {
						// return the date/time string in the timezone associated with the datasource,
						Image image = (Image) dataSource;
						TimeZone tzone = TimeZone.getTimeZone(image.getTimeZone());
						return TimeUtilities.epochToTime(getValueLong(), tzone);
					}
				} catch (TskException ex) {
					LOGGER.log(Level.WARNING, "Could not get timezone for image", ex); //NON-NLS
				}
				// return time string in default timezone
				return TimeUtilities.epochToTime(getValueLong());
			}
			default: {
				return super.getDisplayString();
			}
		}
	}

	/**
	 * Constructs an artifact attribute. To be used when creating an attribute
	 * based on a query of the blackboard _attributes table in the case
	 * database.
	 *
	 * @param artifactID      The artifact id for this attribute
	 * @param attributeTypeID The attribute type id.
	 * @param source          The source of this attribute.
	 * @param context         Contextual information about this attribute.
	 * @param valueType       The attribute value type.
	 * @param valueInt        The value from the the value_int32 column.
	 * @param valueLong       The value from the the value_int64 column.
	 * @param valueDouble     The value from the the value_double column.
	 * @param valueString     The value from the the value_text column.
	 * @param valueBytes      The value from the the value_byte column.
	 * @param sleuthkitCase   A reference to the SleuthkitCase object
	 *                        representing the case database.
	 */
	BlackboardAttribute(long artifactID, BlackboardAttribute.Type attributeType, String source, String context,
			int valueInt, long valueLong, double valueDouble, String valueString, byte[] valueBytes,
			SleuthkitCase sleuthkitCase) {

		super(attributeType, valueInt, valueLong, valueDouble, valueString, valueBytes, sleuthkitCase);
		this.artifactID = artifactID;
		this.sources = replaceNulls(source);
		this.context = replaceNulls(context);
	}

	/**
	 * Sets the parent data source id. The parent data source is defined as
	 * being the data source of the parent artifact.
	 *
	 * @param parentDataSourceID The parent data source id.
	 */
	void setParentDataSourceID(Long parentDataSourceID) {
		this.parentDataSourceID = parentDataSourceID;
	}

	/**
	 * Gets the sources of this attribute.
	 *
	 * @return A comma-separated-values list of sources, may be empty. The CSV
	 *         is due to a deliberate denormalization of the source field in the
	 *         case database and this method is a helper method for the
	 *         SleuthkitCase class.
	 */
	String getSourcesCSV() {
		return sources;
	}

	/**
	 * Represents the type of an attribute.
	 */
	public static final class Type implements Serializable {

		public static final Type TSK_URL = new Type(1, "TSK_URL", bundle.getString("BlackboardAttribute.tskUrl.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_DATETIME = new Type(2, "TSK_DATETIME", bundle.getString("BlackboardAttribute.tskDatetime.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME);
		public static final Type TSK_NAME = new Type(3, "TSK_NAME", bundle.getString("BlackboardAttribute.tskName.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_PROG_NAME = new Type(4, "TSK_PROG_NAME", bundle.getString("BlackboardAttribute.tskProgName.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_VALUE = new Type(6, "TSK_VALUE", bundle.getString("BlackboardAttribute.tskValue.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_FLAG = new Type(7, "TSK_FLAG", bundle.getString("BlackboardAttribute.tskFlag.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_PATH = new Type(8, "TSK_PATH", bundle.getString("BlackboardAttribute.tskPath.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_KEYWORD = new Type(10, "TSK_KEYWORD", bundle.getString("BlackboardAttribute.tskKeyword.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_KEYWORD_REGEXP = new Type(11, "TSK_KEYWORD_REGEXP", bundle.getString("BlackboardAttribute.tskKeywordRegexp.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_KEYWORD_PREVIEW = new Type(12, "TSK_KEYWORD_PREVIEW", bundle.getString("BlackboardAttribute.tskKeywordPreview.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);

		// TSK_KEYWORD_SET (id: 13) has been deprecated.  Please use TSK_SET_NAME instead.
		public static final Type TSK_USER_NAME = new Type(14, "TSK_USER_NAME", bundle.getString("BlackboardAttribute.tskUserName.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_DOMAIN = new Type(15, "TSK_DOMAIN", bundle.getString("BlackboardAttribute.tskDomain.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_PASSWORD = new Type(16, "TSK_PASSWORD", bundle.getString("BlackboardAttribute.tskPassword.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_NAME_PERSON = new Type(17, "TSK_NAME_PERSON", bundle.getString("BlackboardAttribute.tskNamePerson.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_DEVICE_MODEL = new Type(18, "TSK_DEVICE_MODEL", bundle.getString("BlackboardAttribute.tskDeviceModel.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_DEVICE_MAKE = new Type(19, "TSK_DEVICE_MAKE", bundle.getString("BlackboardAttribute.tskDeviceMake.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_DEVICE_ID = new Type(20, "TSK_DEVICE_ID", bundle.getString("BlackboardAttribute.tskDeviceId.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_EMAIL = new Type(21, "TSK_EMAIL", bundle.getString("BlackboardAttribute.tskEmail.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_HASH_MD5 = new Type(22, "TSK_HASH_MD5", bundle.getString("BlackboardAttribute.tskHashMd5.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_HASH_SHA1 = new Type(23, "TSK_HASH_SHA1", bundle.getString("BlackboardAttribute.tskHashSha1.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_HASH_SHA2_256 = new Type(24, "TSK_HASH_SHA2_256", bundle.getString("BlackboardAttribute.tskHashSha225.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_HASH_SHA2_512 = new Type(25, "TSK_HASH_SHA2_512", bundle.getString("BlackboardAttribute.tskHashSha2512.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_TEXT = new Type(26, "TSK_TEXT", bundle.getString("BlackboardAttribute.tskText.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_TEXT_FILE = new Type(27, "TSK_TEXT_FILE", bundle.getString("BlackboardAttribute.tskTextFile.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_TEXT_LANGUAGE = new Type(28, "TSK_TEXT_LANGUAGE", bundle.getString("BlackboardAttribute.tskTextLanguage.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_ENTROPY = new Type(29, "TSK_ENTROPY", bundle.getString("BlackboardAttribute.tskEntropy.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE);

		// TSK_HASHSET_NAME (id: 30) has been deprecated.  Please use TSK_SET_NAME instead.
		// TSK_INTERESTING_FILE (id: 31) has been deprecated.  Please use TSK_INTERESTING_ITEM analysis result instead.
		public static final Type TSK_REFERRER = new Type(32, "TSK_REFERRER", bundle.getString("BlackboardAttribute.tskReferrer.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_DATETIME_ACCESSED = new Type(33, "TSK_DATETIME_ACCESSED", bundle.getString("BlackboardAttribute.tskDateTimeAccessed.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME);
		public static final Type TSK_IP_ADDRESS = new Type(34, "TSK_IP_ADDRESS", bundle.getString("BlackboardAttribute.tskIpAddress.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_PHONE_NUMBER = new Type(35, "TSK_PHONE_NUMBER", bundle.getString("BlackboardAttribute.tskPhoneNumber.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_PATH_ID = new Type(36, "TSK_PATH_ID", bundle.getString("BlackboardAttribute.tskPathId.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG);
		public static final Type TSK_SET_NAME = new Type(37, "TSK_SET_NAME", bundle.getString("BlackboardAttribute.tskSetName.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);

		// TSK_ENCRYPTION_DETECTED (id: 38) has been deprecated.  Please use TSK_ENCRYPTION_DETECTED as an artifact.
		public static final Type TSK_MALWARE_DETECTED = new Type(39, "TSK_MALWARE_DETECTED", bundle.getString("BlackboardAttribute.tskMalwareDetected.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER);
		public static final Type TSK_STEG_DETECTED = new Type(40, "TSK_STEG_DETECTED", bundle.getString("BlackboardAttribute.tskStegDetected.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER);
		public static final Type TSK_EMAIL_TO = new Type(41, "TSK_EMAIL_TO", bundle.getString("BlackboardAttribute.tskEmailTo.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_EMAIL_CC = new Type(42, "TSK_EMAIL_CC", bundle.getString("BlackboardAttribute.tskEmailCc.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_EMAIL_BCC = new Type(43, "TSK_EMAIL_BCC", bundle.getString("BlackboardAttribute.tskEmailBcc.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_EMAIL_FROM = new Type(44, "TSK_EMAIL_FROM", bundle.getString("BlackboardAttribute.tskEmailFrom.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_EMAIL_CONTENT_PLAIN = new Type(45, "TSK_EMAIL_CONTENT_PLAIN", bundle.getString("BlackboardAttribute.tskEmailContentPlain.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_EMAIL_CONTENT_HTML = new Type(46, "TSK_EMAIL_CONTENT_HTML", bundle.getString("BlackboardAttribute.tskEmailContentHtml.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_EMAIL_CONTENT_RTF = new Type(47, "TSK_EMAIL_CONTENT_RTF", bundle.getString("BlackboardAttribute.tskEmailContentRtf.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_MSG_ID = new Type(48, "TSK_MSG_ID", bundle.getString("BlackboardAttribute.tskMsgId.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_MSG_REPLY_ID = new Type(49, "TSK_MSG_REPLY_ID", bundle.getString("BlackboardAttribute.tskMsgReplyId.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_DATETIME_RCVD = new Type(50, "TSK_DATETIME_RCVD", bundle.getString("BlackboardAttribute.tskDateTimeRcvd.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME);
		public static final Type TSK_DATETIME_SENT = new Type(51, "TSK_DATETIME_SENT", bundle.getString("BlackboardAttribute.tskDateTimeSent.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME);
		public static final Type TSK_SUBJECT = new Type(52, "TSK_SUBJECT", bundle.getString("BlackboardAttribute.tskSubject.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_TITLE = new Type(53, "TSK_TITLE", bundle.getString("BlackboardAttribute.tskTitle.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_GEO_LATITUDE = new Type(54, "TSK_GEO_LATITUDE", bundle.getString("BlackboardAttribute.tskGeoLatitude.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE);
		public static final Type TSK_GEO_LONGITUDE = new Type(55, "TSK_GEO_LONGITUDE", bundle.getString("BlackboardAttribute.tskGeoLongitude.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE);
		public static final Type TSK_GEO_VELOCITY = new Type(56, "TSK_GEO_VELOCITY", bundle.getString("BlackboardAttribute.tskGeoVelocity.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE);
		public static final Type TSK_GEO_ALTITUDE = new Type(57, "TSK_GEO_ALTITUDE", bundle.getString("BlackboardAttribute.tskGeoAltitude.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE);
		public static final Type TSK_GEO_BEARING = new Type(58, "TSK_GEO_BEARING", bundle.getString("BlackboardAttribute.tskGeoBearing.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_GEO_HPRECISION = new Type(59, "TSK_GEO_HPRECISION", bundle.getString("BlackboardAttribute.tskGeoHPrecision.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE);
		public static final Type TSK_GEO_VPRECISION = new Type(60, "TSK_GEO_VPRECISION", bundle.getString("BlackboardAttribute.tskGeoVPrecision.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE);
		public static final Type TSK_GEO_MAPDATUM = new Type(61, "TSK_GEO_MAPDATUM", bundle.getString("BlackboardAttribute.tskGeoMapDatum.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);

		// TSK_FILE_TYPE_SIG (id: 62) has been deprecated.  Please use the mime type field of the AbstractFile object instead.
		public static final Type TSK_FILE_TYPE_EXT = new Type(63, "TSK_FILE_TYPE_EXT", bundle.getString("BlackboardAttribute.tskFileTypeExt.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);

		// TSK_TAGGED_ARTIFACT (id: 64) has been deprected.  Please create a tag as an artifact.
		// TSK_TAG_NAME (id: 65) has been deprecated.  Please create a tag as an artifact.
		public static final Type TSK_COMMENT = new Type(66, "TSK_COMMENT", bundle.getString("BlackboardAttribute.tskComment.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_URL_DECODED = new Type(67, "TSK_URL_DECODED", bundle.getString("BlackboardAttribute.tskUrlDecoded.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_DATETIME_CREATED = new Type(68, "TSK_DATETIME_CREATED", bundle.getString("BlackboardAttribute.tskDateTimeCreated.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME);
		public static final Type TSK_DATETIME_MODIFIED = new Type(69, "TSK_DATETIME_MODIFIED", bundle.getString("BlackboardAttribute.tskDateTimeModified.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME);
		public static final Type TSK_PROCESSOR_ARCHITECTURE = new Type(70, "TSK_PROCESSOR_ARCHITECTURE", bundle.getString("BlackboardAttribute.tskProcessorArchitecture.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_VERSION = new Type(71, "TSK_VERSION", bundle.getString("BlackboardAttribute.tskVersion.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_USER_ID = new Type(72, "TSK_USER_ID", bundle.getString("BlackboardAttribute.tskUserId.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_DESCRIPTION = new Type(73, "TSK_DESCRIPTION", bundle.getString("BlackboardAttribute.tskDescription.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_MESSAGE_TYPE = new Type(74, "TSK_MESSAGE_TYPE", bundle.getString("BlackboardAttribute.tskMessageType.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING); // SMS or MMS or IM ...
		public static final Type TSK_PHONE_NUMBER_HOME = new Type(75, "TSK_PHONE_NUMBER_HOME", bundle.getString("BlackboardAttribute.tskPhoneNumberHome.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_PHONE_NUMBER_OFFICE = new Type(76, "TSK_PHONE_NUMBER_OFFICE", bundle.getString("BlackboardAttribute.tskPhoneNumberOffice.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_PHONE_NUMBER_MOBILE = new Type(77, "TSK_PHONE_NUMBER_MOBILE", bundle.getString("BlackboardAttribute.tskPhoneNumberMobile.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_PHONE_NUMBER_FROM = new Type(78, "TSK_PHONE_NUMBER_FROM", bundle.getString("BlackboardAttribute.tskPhoneNumberFrom.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_PHONE_NUMBER_TO = new Type(79, "TSK_PHONE_NUMBER_TO", bundle.getString("BlackboardAttribute.tskPhoneNumberTo.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_DIRECTION = new Type(80, "TSK_DIRECTION", bundle.getString("BlackboardAttribute.tskDirection.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING); // Msg/Call direction: incoming, outgoing
		public static final Type TSK_EMAIL_HOME = new Type(81, "TSK_EMAIL_HOME", bundle.getString("BlackboardAttribute.tskEmailHome.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_EMAIL_OFFICE = new Type(82, "TSK_EMAIL_OFFICE", bundle.getString("BlackboardAttribute.tskEmailOffice.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_DATETIME_START = new Type(83, "TSK_DATETIME_START", bundle.getString("BlackboardAttribute.tskDateTimeStart.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME); // start time of an event - call log, Calendar entry
		public static final Type TSK_DATETIME_END = new Type(84, "TSK_DATETIME_END", bundle.getString("BlackboardAttribute.tskDateTimeEnd.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME); // end time of an event - call log, Calendar entry
		public static final Type TSK_CALENDAR_ENTRY_TYPE = new Type(85, "TSK_CALENDAR_ENTRY_TYPE", bundle.getString("BlackboardAttribute.tskCalendarEntryType.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING); // meeting, task,
		public static final Type TSK_LOCATION = new Type(86, "TSK_LOCATION", bundle.getString("BlackboardAttribute.tskLocation.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING); // Location string associated with an event - Conf Room Name, Address ....
		public static final Type TSK_SHORTCUT = new Type(87, "TSK_SHORTCUT", bundle.getString("BlackboardAttribute.tskShortcut.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING); // Short Cut string - short code or dial string for Speed dial, a URL short cut - e.g. bitly string, Windows Desktop Short cut name etc.
		public static final Type TSK_DEVICE_NAME = new Type(88, "TSK_DEVICE_NAME", bundle.getString("BlackboardAttribute.tskDeviceName.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING); // device name - a user assigned (usually) device name - such as "Joe's computer", "bob_win8", "BT Headset"
		public static final Type TSK_CATEGORY = new Type(89, "TSK_CATEGORY", bundle.getString("BlackboardAttribute.tskCategory.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING); // category/type, possible value set varies by the artifact
		public static final Type TSK_EMAIL_REPLYTO = new Type(90, "TSK_EMAIL_REPLYTO", bundle.getString("BlackboardAttribute.tskEmailReplyTo.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING); // ReplyTo address
		public static final Type TSK_SERVER_NAME = new Type(91, "TSK_SERVER_NAME", bundle.getString("BlackboardAttribute.tskServerName.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING); // server name, e.g. a mail server name - "smtp.google.com", a DNS server name...
		public static final Type TSK_COUNT = new Type(92, "TSK_COUNT", bundle.getString("BlackboardAttribute.tskCount.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER); // Count related to the artifact
		public static final Type TSK_MIN_COUNT = new Type(93, "TSK_MIN_COUNT", bundle.getString("BlackboardAttribute.tskMinCount.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER); // Minimum number/count
		public static final Type TSK_PATH_SOURCE = new Type(94, "TSK_PATH_SOURCE", bundle.getString("BlackboardAttribute.tskPathSource.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING); // Path to a source file related to the artifact
		public static final Type TSK_PERMISSIONS = new Type(95, "TSK_PERMISSIONS", bundle.getString("BlackboardAttribute.tskPermissions.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING); // Permissions
		public static final Type TSK_ASSOCIATED_ARTIFACT = new Type(96, "TSK_ASSOCIATED_ARTIFACT", bundle.getString("BlackboardAttribute.tskAssociatedArtifact.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG); // Artifact ID of a related artifact
		public static final Type TSK_ISDELETED = new Type(97, "TSK_ISDELETED", bundle.getString("BlackboardAttribute.tskIsDeleted.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING); // boolean to indicate that the artifact is recovered fom deleted content
		public static final Type TSK_GEO_LATITUDE_START = new Type(98, "TSK_GEO_LATITUDE_START", bundle.getString("BlackboardAttribute.tskGeoLatitudeStart.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE); // Starting location lattitude
		public static final Type TSK_GEO_LATITUDE_END = new Type(99, "TSK_GEO_LATITUDE_END", bundle.getString("BlackboardAttribute.tskGeoLatitudeEnd.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE); // Ending location lattitude
		public static final Type TSK_GEO_LONGITUDE_START = new Type(100, "TSK_GEO_LONGITUDE_START", bundle.getString("BlackboardAttribute.tskGeoLongitudeStart.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE); // Starting location longitude
		public static final Type TSK_GEO_LONGITUDE_END = new Type(101, "TSK_GEO_LONGITUDE_END", bundle.getString("BlackboardAttribute.tskGeoLongitudeEnd.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE); //Ending Location longitude
		public static final Type TSK_READ_STATUS = new Type(102, "TSK_READ_STATUS", bundle.getString("BlackboardAttribute.tskReadStatus.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER); // Message read status: 1 if read, 0 if unread
		public static final Type TSK_LOCAL_PATH = new Type(103, "TSK_LOCAL_PATH", bundle.getString("BlackboardAttribute.tskLocalPath.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING); // Local path to a network drive
		public static final Type TSK_REMOTE_PATH = new Type(104, "TSK_REMOTE_PATH", bundle.getString("BlackboardAttribute.tskRemotePath.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING); // Remote path of a network drive
		public static final Type TSK_TEMP_DIR = new Type(105, "TSK_TEMP_DIR", bundle.getString("BlackboardAttribute.tskTempDir.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING); // Default temporary files directory
		public static final Type TSK_PRODUCT_ID = new Type(106, "TSK_PRODUCT_ID", bundle.getString("BlackboardAttribute.tskProductId.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING); // Product ID
		public static final Type TSK_OWNER = new Type(107, "TSK_OWNER", bundle.getString("BlackboardAttribute.tskOwner.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING); // Registered owner of a piece of software
		public static final Type TSK_ORGANIZATION = new Type(108, "TSK_ORGANIZATION", bundle.getString("BlackboardAttribute.tskOrganization.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING); // Registered Organization for a piece of software
		public static final Type TSK_CARD_NUMBER = new Type(109, "TSK_CARD_NUMBER", bundle.getString("BlackboardAttribute.tskCardNumber.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_CARD_EXPIRATION = new Type(110, "TSK_CARD_EXPIRATION", bundle.getString("BlackboardAttribute.tskCardExpiration.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_CARD_SERVICE_CODE = new Type(111, "TSK_CARD_SERVICE_CODE", bundle.getString("BlackboardAttribute.tskCardServiceCode.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_CARD_DISCRETIONARY = new Type(112, "TSK_CARD_DISCRETIONARY", bundle.getString("BlackboardAttribute.tskCardDiscretionary.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_CARD_LRC = new Type(113, "TSK_CARD_LRC", bundle.getString("BlackboardAttribute.tskCardLRC.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_KEYWORD_SEARCH_DOCUMENT_ID = new Type(114, "TSK_KEYWORD_SEARCH_DOCUMENT_ID", bundle.getString("BlackboardAttribute.tskKeywordSearchDocumentID.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_CARD_SCHEME = new Type(115, "TSK_CARD_SCHEME", bundle.getString("BlackboardAttribute.tskCardScheme.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_CARD_TYPE = new Type(116, "TSK_CARD_TYPE", bundle.getString("BlackboardAttribute.tskCardType.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_BRAND_NAME = new Type(117, "TSK_BRAND_NAME", bundle.getString("BlackboardAttribute.tskBrandName.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_BANK_NAME = new Type(118, "TSK_BANK_NAME", bundle.getString("BlackboardAttribute.tskBankName.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_COUNTRY = new Type(119, "TSK_COUNTRY", bundle.getString("BlackboardAttribute.tskCountry.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_CITY = new Type(120, "TSK_CITY", bundle.getString("BlackboardAttribute.tskCity.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_ACCOUNT_TYPE = new Type(121, "TSK_ACCOUNT_TYPE", bundle.getString("BlackboardAttribute.tskAccountType.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);

		/**
		 * Keyword search type: exact match, sub-string, or regex.
		 */
		public static final Type TSK_KEYWORD_SEARCH_TYPE = new Type(122, "TSK_KEYWORD_SEARCH_TYPE", bundle.getString("BlackboardAttribute.tskKeywordSearchType.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER);
		public static final Type TSK_HEADERS = new Type(123, "TSK_HEADERS", bundle.getString("BlackboardAttribute.tskHeaders.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_ID = new Type(124, "TSK_ID", bundle.getString("BlackboardAttribute.tskId.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_SSID = new Type(125, "TSK_SSID", bundle.getString("BlackboardAttribute.tskSsid.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_BSSID = new Type(126, "TSK_BSSID", bundle.getString("BlackboardAttribute.tskBssid.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_MAC_ADDRESS = new Type(127, "TSK_MAC_ADDRESS", bundle.getString("BlackboardAttribute.tskMacAddress.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_IMEI = new Type(128, "TSK_IMEI", bundle.getString("BlackboardAttribute.tskImei.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_IMSI = new Type(129, "TSK_IMSI", bundle.getString("BlackboardAttribute.tskImsi.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_ICCID = new Type(130, "TSK_ICCID", bundle.getString("BlackboardAttribute.tskIccid.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_THREAD_ID = new Type(131, "TSK_THREAD_ID", bundle.getString("BlackboardAttribute.tskthreadid.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		/**
		 * The event type of a TSK_TL_EVENT artifact. The value should be the id
		 * of the EventType in the tsk_event_types table.
		 */
		public static final Type TSK_TL_EVENT_TYPE = new Type(132, "TSK_TL_EVENT_TYPE", bundle.getString("BlackboardAttribute.tskTLEventType.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG);
		public static final Type TSK_DATETIME_DELETED = new Type(133, "TSK_DATETIME_DELETED", bundle.getString("BlackboardAttribute.tskdatetimedeleted.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME);
		public static final Type TSK_DATETIME_PASSWORD_RESET = new Type(134, "TSK_DATETIME_PASSWORD_RESET", bundle.getString("BlackboardAttribute.tskdatetimepwdreset.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME);
		public static final Type TSK_DATETIME_PASSWORD_FAIL = new Type(135, "TSK_DATETIME_PWD_FAIL", bundle.getString("BlackboardAttribute.tskdatetimepwdfail.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME);
		public static final Type TSK_DISPLAY_NAME = new Type(136, "TSK_DISPLAY_NAME", bundle.getString("BlackboardAttribute.tskdisplayname.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_PASSWORD_SETTINGS = new Type(137, "TSK_PASSWORD_SETTINGS", bundle.getString("BlackboardAttribute.tskpasswordsettings.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_ACCOUNT_SETTINGS = new Type(138, "TSK_ACCOUNT_SETTINGS", bundle.getString("BlackboardAttribute.tskaccountsettings.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_PASSWORD_HINT = new Type(139, "TSK_PASSWORD_HINT", bundle.getString("BlackboardAttribute.tskpasswordhint.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_GROUPS = new Type(140, "TSK_GROUPS", bundle.getString("BlackboardAttribute.tskgroups.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		/*
		 * Use
		 * org.sleuthkit.datamodel.blackboardutils.attributes.MessageAttachments
		 * to create and process TSK_ATTACHMENTS attributes.
		 */
		public static final Type TSK_ATTACHMENTS = new Type(141, "TSK_ATTACHMENTS", bundle.getString("BlackboardAttribute.tskattachments.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.JSON);
		/*
		 * Use org.sleuthkit.datamodel.blackboardutils.attributes.GeoTrackPoints
		 * to create and process TSK_GEO_TRACKPOINTS attributes.
		 */
		public static final Type TSK_GEO_TRACKPOINTS = new Type(142, "TSK_GEO_TRACKPOINTS", bundle.getString("BlackboardAttribute.tskgeopath.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.JSON);
		/*
		 * Use org.sleuthkit.datamodel.blackboardutils.attributes.GeoWaypoints
		 * to create and process TSK_GEO_WAYPOINTS attributes.
		 */
		public static final Type TSK_GEO_WAYPOINTS = new Type(143, "TSK_GEO_WAYPOINTS", bundle.getString("BlackboardAttribute.tskgeowaypoints.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.JSON);
		public static final Type TSK_DISTANCE_TRAVELED = new Type(144, "TSK_DISTANCE_TRAVELED", bundle.getString("BlackboardAttribute.tskdistancetraveled.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE);
		public static final Type TSK_DISTANCE_FROM_HOMEPOINT = new Type(145, "TSK_DISTANCE_FROM_HOMEPOINT", bundle.getString("BlackboardAttribute.tskdistancefromhome.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE);
		public static final Type TSK_HASH_PHOTODNA = new Type(146, "TSK_HASH_PHOTODNA", bundle.getString("BlackboardAttribute.tskhashphotodna.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_BYTES_SENT = new Type(147, "TSK_BYTES_SENT", bundle.getString("BlackboardAttribute.tskbytessent.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG);
		public static final Type TSK_BYTES_RECEIVED = new Type(148, "TSK_BYTES_RECEIVED", bundle.getString("BlackboardAttribute.tskbytesreceived.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG);
		public static final Type TSK_LAST_PRINTED_DATETIME = new Type(149, "TSK_LAST_PRINTED_DATETIME", bundle.getString("BlackboardAttribute.tsklastprinteddatetime.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME);
		public static final Type TSK_RULE = new Type(150, "TSK_RULE", bundle.getString("BlackboardAttribute.tskrule.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_ACTIVITY_TYPE = new Type(151, "TSK_ACTIVITY_TYPE", bundle.getString("BlackboardAttribute.tskActivityType.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		/*
		 * Use org.sleuthkit.datamodel.blackboardutils.attributes.GeoAreaPoints
		 * to create and process TSK_GEO_AREAPOINTS attributes.
		 */
		public static final Type TSK_GEO_AREAPOINTS = new Type(152, "TSK_GEO_AREAPOINTS", bundle.getString("BlackboardAttribute.tskgeoareapoints.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.JSON);
		public static final Type TSK_REALM = new Type(153, "TSK_REALM", bundle.getString("BlackboardAttribute.tskRealm.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_HOST = new Type(154, "TSK_HOST", bundle.getString("BlackboardAttribute.tskHost.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_HOME_DIR = new Type(155, "TSK_HOME_DIR", bundle.getString("BlackboardAttribute.tskHomeDir.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_IS_ADMIN = new Type(156, "TSK_IS_ADMIN", bundle.getString("BlackboardAttribute.tskIsAdmin.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER);
		public static final Type TSK_CORRELATION_TYPE = new Type(157, "TSK_CORRELATION_TYPE", bundle.getString("BlackboardAttribute.tskCorrelationType.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_CORRELATION_VALUE = new Type(158, "TSK_CORRELATION_VALUE", bundle.getString("BlackboardAttribute.tskCorrelationValue.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);
		public static final Type TSK_OTHER_CASES = new Type(159, "TSK_OTHER_CASES", bundle.getString("BlackboardAttribute.tskOtherCases.text"), TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING);

		// NOTE: When adding a new standard BlackboardAttribute.Type, add the instance and then add to the STANDARD_TYPES list.
		/**
		 * A list of all the standard attribute types.
		 */
		static final List<Type> STANDARD_TYPES = Collections.unmodifiableList(Arrays.asList(
				TSK_URL,
				TSK_DATETIME,
				TSK_NAME,
				TSK_PROG_NAME,
				TSK_VALUE,
				TSK_FLAG,
				TSK_PATH,
				TSK_KEYWORD,
				TSK_KEYWORD_REGEXP,
				TSK_KEYWORD_PREVIEW,
				TSK_USER_NAME,
				TSK_DOMAIN,
				TSK_PASSWORD,
				TSK_NAME_PERSON,
				TSK_DEVICE_MODEL,
				TSK_DEVICE_MAKE,
				TSK_DEVICE_ID,
				TSK_EMAIL,
				TSK_HASH_MD5,
				TSK_HASH_SHA1,
				TSK_HASH_SHA2_256,
				TSK_HASH_SHA2_512,
				TSK_TEXT,
				TSK_TEXT_FILE,
				TSK_TEXT_LANGUAGE,
				TSK_ENTROPY,
				TSK_REFERRER,
				TSK_DATETIME_ACCESSED,
				TSK_IP_ADDRESS,
				TSK_PHONE_NUMBER,
				TSK_PATH_ID,
				TSK_SET_NAME,
				TSK_MALWARE_DETECTED,
				TSK_STEG_DETECTED,
				TSK_EMAIL_TO,
				TSK_EMAIL_CC,
				TSK_EMAIL_BCC,
				TSK_EMAIL_FROM,
				TSK_EMAIL_CONTENT_PLAIN,
				TSK_EMAIL_CONTENT_HTML,
				TSK_EMAIL_CONTENT_RTF,
				TSK_MSG_ID,
				TSK_MSG_REPLY_ID,
				TSK_DATETIME_RCVD,
				TSK_DATETIME_SENT,
				TSK_SUBJECT,
				TSK_TITLE,
				TSK_GEO_LATITUDE,
				TSK_GEO_LONGITUDE,
				TSK_GEO_VELOCITY,
				TSK_GEO_ALTITUDE,
				TSK_GEO_BEARING,
				TSK_GEO_HPRECISION,
				TSK_GEO_VPRECISION,
				TSK_GEO_MAPDATUM,
				TSK_FILE_TYPE_EXT,
				TSK_COMMENT,
				TSK_URL_DECODED,
				TSK_DATETIME_CREATED,
				TSK_DATETIME_MODIFIED,
				TSK_PROCESSOR_ARCHITECTURE,
				TSK_VERSION,
				TSK_USER_ID,
				TSK_DESCRIPTION,
				TSK_MESSAGE_TYPE,
				TSK_PHONE_NUMBER_HOME,
				TSK_PHONE_NUMBER_OFFICE,
				TSK_PHONE_NUMBER_MOBILE,
				TSK_PHONE_NUMBER_FROM,
				TSK_PHONE_NUMBER_TO,
				TSK_DIRECTION,
				TSK_EMAIL_HOME,
				TSK_EMAIL_OFFICE,
				TSK_DATETIME_START,
				TSK_DATETIME_END,
				TSK_CALENDAR_ENTRY_TYPE,
				TSK_LOCATION,
				TSK_SHORTCUT,
				TSK_DEVICE_NAME,
				TSK_CATEGORY,
				TSK_EMAIL_REPLYTO,
				TSK_SERVER_NAME,
				TSK_COUNT,
				TSK_MIN_COUNT,
				TSK_PATH_SOURCE,
				TSK_PERMISSIONS,
				TSK_ASSOCIATED_ARTIFACT,
				TSK_ISDELETED,
				TSK_GEO_LATITUDE_START,
				TSK_GEO_LATITUDE_END,
				TSK_GEO_LONGITUDE_START,
				TSK_GEO_LONGITUDE_END,
				TSK_READ_STATUS,
				TSK_LOCAL_PATH,
				TSK_REMOTE_PATH,
				TSK_TEMP_DIR,
				TSK_PRODUCT_ID,
				TSK_OWNER,
				TSK_ORGANIZATION,
				TSK_CARD_NUMBER,
				TSK_CARD_EXPIRATION,
				TSK_CARD_SERVICE_CODE,
				TSK_CARD_DISCRETIONARY,
				TSK_CARD_LRC,
				TSK_KEYWORD_SEARCH_DOCUMENT_ID,
				TSK_CARD_SCHEME,
				TSK_CARD_TYPE,
				TSK_BRAND_NAME,
				TSK_BANK_NAME,
				TSK_COUNTRY,
				TSK_CITY,
				TSK_ACCOUNT_TYPE,
				TSK_KEYWORD_SEARCH_TYPE,
				TSK_HEADERS,
				TSK_ID,
				TSK_SSID,
				TSK_BSSID,
				TSK_MAC_ADDRESS,
				TSK_IMEI,
				TSK_IMSI,
				TSK_ICCID,
				TSK_THREAD_ID,
				TSK_TL_EVENT_TYPE,
				TSK_DATETIME_DELETED,
				TSK_DATETIME_PASSWORD_RESET,
				TSK_DATETIME_PASSWORD_FAIL,
				TSK_DISPLAY_NAME,
				TSK_PASSWORD_SETTINGS,
				TSK_ACCOUNT_SETTINGS,
				TSK_PASSWORD_HINT,
				TSK_GROUPS,
				TSK_ATTACHMENTS,
				TSK_GEO_TRACKPOINTS,
				TSK_GEO_WAYPOINTS,
				TSK_DISTANCE_TRAVELED,
				TSK_DISTANCE_FROM_HOMEPOINT,
				TSK_HASH_PHOTODNA,
				TSK_BYTES_SENT,
				TSK_BYTES_RECEIVED,
				TSK_LAST_PRINTED_DATETIME,
				TSK_RULE,
				TSK_ACTIVITY_TYPE,
				TSK_GEO_AREAPOINTS,
				TSK_REALM,
				TSK_HOST,
				TSK_HOME_DIR,
				TSK_IS_ADMIN,
				TSK_CORRELATION_TYPE,
				TSK_CORRELATION_VALUE,
				TSK_OTHER_CASES
		));

		private static final long serialVersionUID = 1L;
		private final String typeName;
		private final int typeID;
		private final String displayName;
		private final TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE valueType;

		/**
		 * Constructs an attribute type.
		 *
		 * @param typeID      The type id.
		 * @param typeName    The type name.
		 * @param displayName The display name for the type.
		 * @param valueType   The type of the value.
		 */
		public Type(int typeID, String typeName, String displayName, TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE valueType) {
			this.typeID = typeID;
			this.typeName = typeName;
			this.displayName = displayName;
			this.valueType = valueType;
		}

		/**
		 * Constructs a standard attribute type.
		 *
		 * @param type The specification of the type provided by the
		 *             TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE enumeration.
		 */
		public Type(BlackboardAttribute.ATTRIBUTE_TYPE type) {
			this.typeID = type.getTypeID();
			this.typeName = type.getLabel();
			this.displayName = type.getDisplayName();
			this.valueType = type.getValueType();
		}

		/**
		 * Gets the value type of this attribute type.
		 *
		 * @return The value type.
		 */
		public TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE getValueType() {
			return this.valueType;
		}

		/**
		 * Gets the type name of this attribute type.
		 *
		 * @return The type name.
		 */
		public String getTypeName() {
			return this.typeName;
		}

		/**
		 * Gets the type id of this attribute type.
		 *
		 * @return The type id.
		 */
		public int getTypeID() {
			return this.typeID;
		}

		/**
		 * Gets the display name of this attribute type.
		 *
		 * @return The display name.
		 */
		public String getDisplayName() {
			return this.displayName;
		}

		@Override
		public boolean equals(Object that) {
			if (this == that) {
				return true;
			} else if (!(that instanceof BlackboardAttribute.Type)) {
				return false;
			} else {
				return ((BlackboardAttribute.Type) that).sameType(this);
			}
		}

		/**
		 * Determines if this attribute type object is equivalent to another
		 * attribute type object.
		 *
		 * @param that the other type
		 *
		 * @return true if it is the same type
		 */
		private boolean sameType(BlackboardAttribute.Type that) {
			return this.typeName.equals(that.getTypeName())
					&& this.displayName.equals(that.getDisplayName())
					&& this.typeID == that.getTypeID()
					&& this.valueType == that.getValueType();
		}

		@Override
		public int hashCode() {
			int hash = 7;
			hash = 63 * hash + Objects.hashCode(this.typeID);
			hash = 63 * hash + Objects.hashCode(this.displayName);
			hash = 63 * hash + Objects.hashCode(this.typeName);
			hash = 63 * hash + Objects.hashCode(this.valueType);
			return hash;
		}

		@Override
		public String toString() {
			return "(typeID= " + this.typeID
					+ ", displayName=" + this.displayName
					+ ", typeName=" + this.typeName
					+ ", valueType=" + this.valueType + ")";
		}
	}

	/**
	 * Specifies the type ids and display names of the supported attribute value
	 * types.
	 */
	public enum TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE {

		/**
		 * The value type of the attribute is a string.
		 */
		STRING(0, "String"), //NON-NLS
		/**
		 * The value type of the attribute is an int.
		 */
		INTEGER(1, "Integer"), //NON-NLS
		/**
		 * The value type of the attribute is a long.
		 */
		LONG(2, "Long"), //NON-NLS
		/**
		 * The value type of the attribute is a double.
		 */
		DOUBLE(3, "Double"), //NON-NLS
		/**
		 * The value type of the attribute is a byte array.
		 */
		BYTE(4, "Byte"), //NON-NLS
		/**
		 * The value type of the attribute is a long representing seconds from
		 * January 1, 1970.
		 */
		DATETIME(5, "DateTime"),
		/**
		 * The value type of the attribute is a JSON string.
		 */
		JSON(6, "Json");

		private final long typeId;
		private final String typeName;

		/*
		 * TODO (AUT-2070): Add a localized displayName field and a
		 * getDisplayName method for API consistency.
		 */
		/**
		 * Constructs an attribute value type object.
		 *
		 * @param type     The type id of the value type.
		 * @param typeName The type name of the value type.
		 */
		private TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE(long type, String typeName) {
			this.typeId = type;
			this.typeName = typeName;
		}

		/**
		 * Gets the type id for this attribute value type.
		 *
		 * TODO (AUT-2070): Deprecate and provide a getTypeId method instead for
		 * API consistency.
		 *
		 * @return attribute value type id
		 */
		public long getType() {
			return typeId;
		}

		/**
		 * Gets the type name for this attribute value type.
		 *
		 * TODO (AUT-2070): Deprecate and provide a getTypeName method instead
		 * for API consistency.
		 *
		 * @return attribute value type name
		 */
		public String getLabel() {
			return this.typeName;
		}

		/**
		 * Gets the attribute value type for a given value type id.
		 *
		 * @param typeId A value type id.
		 *
		 * @return A BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE
		 *         object.
		 *
		 * @throws IllegalArgumentException If the given type id does not map to
		 *                                  a supported value type.
		 *
		 * TODO (AUT-2070): Deprecate and provide a fromTypeId method instead
		 * for API consistency.
		 */
		static public TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE fromType(long typeId) {
			for (TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE valueType : TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.values()) {
				if (valueType.getType() == typeId) {
					return valueType;
				}
			}
			throw new IllegalArgumentException("No TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE matching type: " + typeId);
		}

		/**
		 * Gets the attribute value type for a given value type name.
		 *
		 * @param typeName A type name.
		 *
		 * @return A BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE
		 *         object.
		 *
		 * @throws IllegalArgumentException If the given type name does not map
		 *                                  to a supported value type.
		 *
		 * TODO (AUT-2070): Deprecate and provide a fromTypeName method instead
		 * for API consistency.
		 */
		static public TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE fromLabel(String typeName) {
			for (TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE valueType : TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.values()) {
				if (valueType.getLabel().equals(typeName)) {
					return valueType;
				}
			}
			throw new IllegalArgumentException("No TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE matching type: " + typeName);
		}

	}

	/**
	 * Specifies the type ids, type names, display names, and value types of the
	 * standard attribute types. See
	 * http://wiki.sleuthkit.org/index.php?title=Artifact_Examples for more
	 * information.
	 */
	public enum ATTRIBUTE_TYPE {

		TSK_URL(1, "TSK_URL", //NON-NLS
				bundle.getString("BlackboardAttribute.tskUrl.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_DATETIME(2, "TSK_DATETIME", //NON-NLS
				bundle.getString("BlackboardAttribute.tskDatetime.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME),
		TSK_NAME(3, "TSK_NAME", //NON-NLS
				bundle.getString("BlackboardAttribute.tskName.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_PROG_NAME(4, "TSK_PROG_NAME", //NON-NLS
				bundle.getString("BlackboardAttribute.tskProgName.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_VALUE(6, "TSK_VALUE", //NON-NLS
				bundle.getString("BlackboardAttribute.tskValue.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_FLAG(7, "TSK_FLAG", //NON-NLS
				bundle.getString("BlackboardAttribute.tskFlag.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_PATH(8, "TSK_PATH", //NON-NLS
				bundle.getString("BlackboardAttribute.tskPath.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_KEYWORD(10, "TSK_KEYWORD", //NON-NLS
				bundle.getString("BlackboardAttribute.tskKeyword.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_KEYWORD_REGEXP(11, "TSK_KEYWORD_REGEXP", //NON-NLS
				bundle.getString("BlackboardAttribute.tskKeywordRegexp.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_KEYWORD_PREVIEW(12, "TSK_KEYWORD_PREVIEW", //NON-NLS
				bundle.getString("BlackboardAttribute.tskKeywordPreview.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		/**
		 * @deprecated Use a TSK_SET_NAME attribute instead.
		 */
		@Deprecated
		TSK_KEYWORD_SET(13, "TSK_KEYWORD_SET", //NON-NLS
				bundle.getString("BlackboardAttribute.tskKeywordSet.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_USER_NAME(14, "TSK_USER_NAME", //NON-NLS
				bundle.getString("BlackboardAttribute.tskUserName.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_DOMAIN(15, "TSK_DOMAIN", //NON-NLS
				bundle.getString("BlackboardAttribute.tskDomain.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_PASSWORD(16, "TSK_PASSWORD", //NON-NLS
				bundle.getString("BlackboardAttribute.tskPassword.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_NAME_PERSON(17, "TSK_NAME_PERSON", //NON-NLS
				bundle.getString("BlackboardAttribute.tskNamePerson.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_DEVICE_MODEL(18, "TSK_DEVICE_MODEL", //NON-NLS
				bundle.getString("BlackboardAttribute.tskDeviceModel.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_DEVICE_MAKE(19, "TSK_DEVICE_MAKE", //NON-NLS
				bundle.getString("BlackboardAttribute.tskDeviceMake.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_DEVICE_ID(20, "TSK_DEVICE_ID", //NON-NLS
				bundle.getString("BlackboardAttribute.tskDeviceId.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_EMAIL(21, "TSK_EMAIL", //NON-NLS
				bundle.getString("BlackboardAttribute.tskEmail.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_HASH_MD5(22, "TSK_HASH_MD5", //NON-NLS
				bundle.getString("BlackboardAttribute.tskHashMd5.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_HASH_SHA1(23, "TSK_HASH_SHA1", //NON-NLS
				bundle.getString("BlackboardAttribute.tskHashSha1.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_HASH_SHA2_256(24, "TSK_HASH_SHA2_256", //NON-NLS
				bundle.getString("BlackboardAttribute.tskHashSha225.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_HASH_SHA2_512(25, "TSK_HASH_SHA2_512", //NON-NLS
				bundle.getString("BlackboardAttribute.tskHashSha2512.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_TEXT(26, "TSK_TEXT", //NON-NLS
				bundle.getString("BlackboardAttribute.tskText.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_TEXT_FILE(27, "TSK_TEXT_FILE", //NON-NLS
				bundle.getString("BlackboardAttribute.tskTextFile.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_TEXT_LANGUAGE(28, "TSK_TEXT_LANGUAGE", //NON-NLS
				bundle.getString("BlackboardAttribute.tskTextLanguage.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_ENTROPY(29, "TSK_ENTROPY", //NON-NLS
				bundle.getString("BlackboardAttribute.tskEntropy.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE),
		/**
		 * @deprecated Use a TSK_SET_NAME attribute instead.
		 */
		@Deprecated
		TSK_HASHSET_NAME(30, "TSK_HASHSET_NAME", //NON-NLS
				bundle.getString("BlackboardAttribute.tskHashsetName.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		/**
		 * @deprecated Use a TSK_INTERESTING_ITEM artifact instead.
		 */
		@Deprecated
		TSK_INTERESTING_FILE(31, "TSK_INTERESTING_FILE", //NON-NLS
				bundle.getString("BlackboardAttribute.tskInterestingFile.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG),
		TSK_REFERRER(32, "TSK_REFERRER", //NON-NLS
				bundle.getString("BlackboardAttribute.tskReferrer.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_DATETIME_ACCESSED(33, "TSK_DATETIME_ACCESSED", //NON-NLS
				bundle.getString("BlackboardAttribute.tskDateTimeAccessed.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME),
		TSK_IP_ADDRESS(34, "TSK_IP_ADDRESS", //NON-NLS
				bundle.getString("BlackboardAttribute.tskIpAddress.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_PHONE_NUMBER(35, "TSK_PHONE_NUMBER", //NON-NLS
				bundle.getString("BlackboardAttribute.tskPhoneNumber.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_PATH_ID(36, "TSK_PATH_ID", //NON-NLS
				bundle.getString("BlackboardAttribute.tskPathId.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG),
		TSK_SET_NAME(37, "TSK_SET_NAME", //NON-NLS
				bundle.getString("BlackboardAttribute.tskSetName.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		/**
		 * @deprecated Use a TSK_ENCRYPTION_DETECTED artifact instead.
		 */
		@Deprecated
		TSK_ENCRYPTION_DETECTED(38, "TSK_ENCRYPTION_DETECTED", //NON-NLS
				bundle.getString("BlackboardAttribute.tskEncryptionDetected.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER),
		TSK_MALWARE_DETECTED(39, "TSK_MALWARE_DETECTED", //NON-NLS
				bundle.getString("BlackboardAttribute.tskMalwareDetected.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER),
		TSK_STEG_DETECTED(40, "TSK_STEG_DETECTED", //NON-NLS
				bundle.getString("BlackboardAttribute.tskStegDetected.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER),
		TSK_EMAIL_TO(41, "TSK_EMAIL_TO", //NON-NLS
				bundle.getString("BlackboardAttribute.tskEmailTo.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_EMAIL_CC(42, "TSK_EMAIL_CC", //NON-NLS
				bundle.getString("BlackboardAttribute.tskEmailCc.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_EMAIL_BCC(43, "TSK_EMAIL_BCC", //NON-NLS
				bundle.getString("BlackboardAttribute.tskEmailBcc.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_EMAIL_FROM(44, "TSK_EMAIL_FROM", //NON-NLS
				bundle.getString("BlackboardAttribute.tskEmailFrom.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_EMAIL_CONTENT_PLAIN(45, "TSK_EMAIL_CONTENT_PLAIN", //NON-NLS
				bundle.getString("BlackboardAttribute.tskEmailContentPlain.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_EMAIL_CONTENT_HTML(46, "TSK_EMAIL_CONTENT_HTML", //NON-NLS
				bundle.getString("BlackboardAttribute.tskEmailContentHtml.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_EMAIL_CONTENT_RTF(47, "TSK_EMAIL_CONTENT_RTF", //NON-NLS
				bundle.getString("BlackboardAttribute.tskEmailContentRtf.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_MSG_ID(48, "TSK_MSG_ID", //NON-NLS
				bundle.getString("BlackboardAttribute.tskMsgId.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_MSG_REPLY_ID(49, "TSK_MSG_REPLY_ID", //NON-NLS
				bundle.getString("BlackboardAttribute.tskMsgReplyId.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_DATETIME_RCVD(50, "TSK_DATETIME_RCVD", //NON-NLS
				bundle.getString("BlackboardAttribute.tskDateTimeRcvd.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME),
		TSK_DATETIME_SENT(51, "TSK_DATETIME_SENT", //NON-NLS
				bundle.getString("BlackboardAttribute.tskDateTimeSent.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME),
		TSK_SUBJECT(52, "TSK_SUBJECT", //NON-NLS
				bundle.getString("BlackboardAttribute.tskSubject.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_TITLE(53, "TSK_TITLE", //NON-NLS
				bundle.getString("BlackboardAttribute.tskTitle.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_GEO_LATITUDE(54, "TSK_GEO_LATITUDE", //NON-NLS
				bundle.getString("BlackboardAttribute.tskGeoLatitude.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE),
		TSK_GEO_LONGITUDE(55, "TSK_GEO_LONGITUDE", //NON-NLS
				bundle.getString("BlackboardAttribute.tskGeoLongitude.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE),
		TSK_GEO_VELOCITY(56, "TSK_GEO_VELOCITY", //NON-NLS
				bundle.getString("BlackboardAttribute.tskGeoVelocity.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE),
		TSK_GEO_ALTITUDE(57, "TSK_GEO_ALTITUDE", //NON-NLS
				bundle.getString("BlackboardAttribute.tskGeoAltitude.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE),
		TSK_GEO_BEARING(58, "TSK_GEO_BEARING", //NON-NLS
				bundle.getString("BlackboardAttribute.tskGeoBearing.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_GEO_HPRECISION(59, "TSK_GEO_HPRECISION", //NON-NLS
				bundle.getString("BlackboardAttribute.tskGeoHPrecision.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE),
		TSK_GEO_VPRECISION(60, "TSK_GEO_VPRECISION", //NON-NLS
				bundle.getString("BlackboardAttribute.tskGeoVPrecision.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE),
		TSK_GEO_MAPDATUM(61, "TSK_GEO_MAPDATUM", //NON-NLS
				bundle.getString("BlackboardAttribute.tskGeoMapDatum.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		/**
		 * @deprecated Use the mime type field of the AbstractFile object
		 * instead.
		 */
		@Deprecated
		TSK_FILE_TYPE_SIG(62, "TSK_FILE_TYPE_SIG", //NON-NLS
				bundle.getString("BlackboardAttribute.tskFileTypeSig.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_FILE_TYPE_EXT(63, "TSK_FILE_TYPE_EXT", //NON-NLS
				bundle.getString("BlackboardAttribute.tskFileTypeExt.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		/**
		 * @deprecated Do not use. Tags are no longer implemented as artifact
		 * attributes.
		 */
		@Deprecated
		TSK_TAGGED_ARTIFACT(64, "TSK_TAGGED_ARTIFACT", //NON-NLS
				bundle.getString("BlackboardAttribute.tskTaggedArtifact.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG),
		/**
		 * @deprecated Do not use. Tags are no longer implemented as artifact
		 * attributes.
		 */
		@Deprecated
		TSK_TAG_NAME(65, "TSK_TAG_NAME", //NON-NLS
				bundle.getString("BlackboardAttribute.tskTagName.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_COMMENT(66, "TSK_COMMENT", //NON-NLS
				bundle.getString("BlackboardAttribute.tskComment.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_URL_DECODED(67, "TSK_URL_DECODED", //NON-NLS
				bundle.getString("BlackboardAttribute.tskUrlDecoded.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_DATETIME_CREATED(68, "TSK_DATETIME_CREATED", //NON-NLS
				bundle.getString("BlackboardAttribute.tskDateTimeCreated.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME),
		TSK_DATETIME_MODIFIED(69, "TSK_DATETIME_MODIFIED", //NON-NLS
				bundle.getString("BlackboardAttribute.tskDateTimeModified.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME),
		TSK_PROCESSOR_ARCHITECTURE(70, "TSK_PROCESSOR_ARCHITECTURE", //NON-NLS
				bundle.getString("BlackboardAttribute.tskProcessorArchitecture.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_VERSION(71, "TSK_VERSION", //NON-NLS
				bundle.getString("BlackboardAttribute.tskVersion.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_USER_ID(72, "TSK_USER_ID", //NON-NLS
				bundle.getString("BlackboardAttribute.tskUserId.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_DESCRIPTION(73, "TSK_DESCRIPTION", //NON-NLS
				bundle.getString("BlackboardAttribute.tskDescription.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_MESSAGE_TYPE(74, "TSK_MESSAGE_TYPE", //NON-NLS
				bundle.getString("BlackboardAttribute.tskMessageType.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING), // SMS or MMS or IM ...
		TSK_PHONE_NUMBER_HOME(75, "TSK_PHONE_NUMBER_HOME", //NON-NLS
				bundle.getString("BlackboardAttribute.tskPhoneNumberHome.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_PHONE_NUMBER_OFFICE(76, "TSK_PHONE_NUMBER_OFFICE", //NON-NLS
				bundle.getString("BlackboardAttribute.tskPhoneNumberOffice.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_PHONE_NUMBER_MOBILE(77, "TSK_PHONE_NUMBER_MOBILE", //NON-NLS
				bundle.getString("BlackboardAttribute.tskPhoneNumberMobile.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_PHONE_NUMBER_FROM(78, "TSK_PHONE_NUMBER_FROM", //NON-NLS
				bundle.getString("BlackboardAttribute.tskPhoneNumberFrom.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_PHONE_NUMBER_TO(79, "TSK_PHONE_NUMBER_TO", //NON-NLS
				bundle.getString("BlackboardAttribute.tskPhoneNumberTo.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_DIRECTION(80, "TSK_DIRECTION", //NON-NLS
				bundle.getString("BlackboardAttribute.tskDirection.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING), // Msg/Call direction: incoming, outgoing
		TSK_EMAIL_HOME(81, "TSK_EMAIL_HOME", //NON-NLS
				bundle.getString("BlackboardAttribute.tskEmailHome.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_EMAIL_OFFICE(82, "TSK_EMAIL_OFFICE", //NON-NLS
				bundle.getString("BlackboardAttribute.tskEmailOffice.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_DATETIME_START(83, "TSK_DATETIME_START", //NON-NLS
				bundle.getString("BlackboardAttribute.tskDateTimeStart.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME), // start time of an event - call log, Calendar entry
		TSK_DATETIME_END(84, "TSK_DATETIME_END", //NON-NLS
				bundle.getString("BlackboardAttribute.tskDateTimeEnd.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME), // end time of an event - call log, Calendar entry
		TSK_CALENDAR_ENTRY_TYPE(85, "TSK_CALENDAR_ENTRY_TYPE", //NON-NLS
				bundle.getString("BlackboardAttribute.tskCalendarEntryType.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING), // meeting, task,
		TSK_LOCATION(86, "TSK_LOCATION", //NON-NLS
				bundle.getString("BlackboardAttribute.tskLocation.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING), // Location string associated with an event - Conf Room Name, Address ....
		TSK_SHORTCUT(87, "TSK_SHORTCUT", //NON-NLS
				bundle.getString("BlackboardAttribute.tskShortcut.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING), // Short Cut string - short code or dial string for Speed dial, a URL short cut - e.g. bitly string, Windows Desktop Short cut name etc.
		TSK_DEVICE_NAME(88, "TSK_DEVICE_NAME", //NON-NLS
				bundle.getString("BlackboardAttribute.tskDeviceName.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING), // device name - a user assigned (usually) device name - such as "Joe's computer", "bob_win8", "BT Headset"
		TSK_CATEGORY(89, "TSK_CATEGORY", //NON-NLS
				bundle.getString("BlackboardAttribute.tskCategory.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING), // category/type, possible value set varies by the artifact
		TSK_EMAIL_REPLYTO(90, "TSK_EMAIL_REPLYTO", //NON-NLS
				bundle.getString("BlackboardAttribute.tskEmailReplyTo.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING), // ReplyTo address
		TSK_SERVER_NAME(91, "TSK_SERVER_NAME", //NON-NLS
				bundle.getString("BlackboardAttribute.tskServerName.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING), // server name, e.g. a mail server name - "smtp.google.com", a DNS server name...
		TSK_COUNT(92, "TSK_COUNT", //NON-NLS
				bundle.getString("BlackboardAttribute.tskCount.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER), // Count related to the artifact
		TSK_MIN_COUNT(93, "TSK_MIN_COUNT", //NON-NLS
				bundle.getString("BlackboardAttribute.tskMinCount.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER), // Minimum number/count
		TSK_PATH_SOURCE(94, "TSK_PATH_SOURCE", //NON-NLS
				bundle.getString("BlackboardAttribute.tskPathSource.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING), // Path to a source file related to the artifact
		TSK_PERMISSIONS(95, "TSK_PERMISSIONS", //NON-NLS
				bundle.getString("BlackboardAttribute.tskPermissions.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING), // Permissions
		TSK_ASSOCIATED_ARTIFACT(96, "TSK_ASSOCIATED_ARTIFACT", //NON-NLS
				bundle.getString("BlackboardAttribute.tskAssociatedArtifact.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG), // Artifact ID of a related artifact
		TSK_ISDELETED(97, "TSK_ISDELETED", //NON-NLS
				bundle.getString("BlackboardAttribute.tskIsDeleted.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING), // boolean to indicate that the artifact is recovered fom deleted content
		TSK_GEO_LATITUDE_START(98, "TSK_GEO_LATITUDE_START", //NON-NLS
				bundle.getString("BlackboardAttribute.tskGeoLatitudeStart.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE), // Starting location lattitude
		TSK_GEO_LATITUDE_END(99, "TSK_GEO_LATITUDE_END", //NON-NLS
				bundle.getString("BlackboardAttribute.tskGeoLatitudeEnd.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE), // Ending location lattitude
		TSK_GEO_LONGITUDE_START(100, "TSK_GEO_LONGITUDE_START", //NON-NLS
				bundle.getString("BlackboardAttribute.tskGeoLongitudeStart.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE), // Starting location longitude
		TSK_GEO_LONGITUDE_END(101, "TSK_GEO_LONGITUDE_END", //NON-NLS
				bundle.getString("BlackboardAttribute.tskGeoLongitudeEnd.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE), //Ending Location longitude
		TSK_READ_STATUS(102, "TSK_READ_STATUS", //NON-NLS
				bundle.getString("BlackboardAttribute.tskReadStatus.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER), // Message read status: 1 if read, 0 if unread
		TSK_LOCAL_PATH(103, "TSK_LOCAL_PATH", //NON-NLS
				bundle.getString("BlackboardAttribute.tskLocalPath.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING), // Local path to a network drive
		TSK_REMOTE_PATH(104, "TSK_REMOTE_PATH", //NON-NLS
				bundle.getString("BlackboardAttribute.tskRemotePath.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING), // Remote path of a network drive
		TSK_TEMP_DIR(105, "TSK_TEMP_DIR", //NON-NLS
				bundle.getString("BlackboardAttribute.tskTempDir.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING), // Default temporary files directory
		TSK_PRODUCT_ID(106, "TSK_PRODUCT_ID", //NON-NLS
				bundle.getString("BlackboardAttribute.tskProductId.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING), // Product ID
		TSK_OWNER(107, "TSK_OWNER", //NON-NLS
				bundle.getString("BlackboardAttribute.tskOwner.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING), // Registered owner of a piece of software
		TSK_ORGANIZATION(108, "TSK_ORGANIZATION", //NON-NLS
				bundle.getString("BlackboardAttribute.tskOrganization.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING), // Registered Organization for a piece of software
		TSK_CARD_NUMBER(109, "TSK_CARD_NUMBER", //NON-NLS
				bundle.getString("BlackboardAttribute.tskCardNumber.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_CARD_EXPIRATION(110, "TSK_CARD_EXPIRATION", //for card as 4 digits MMYY //NON-NLS
				bundle.getString("BlackboardAttribute.tskCardExpiration.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_CARD_SERVICE_CODE(111, "TSK_CARD_SERVICE_CODE", // 3 digits //NON-NLS
				bundle.getString("BlackboardAttribute.tskCardServiceCode.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_CARD_DISCRETIONARY(112, "TSK_CARD_DISCRETIONARY", //data used at the discretion of the issuer //NON-NLS
				bundle.getString("BlackboardAttribute.tskCardDiscretionary.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_CARD_LRC(113, "TSK_CARD_LRC", //NON-NLS  //Longitudunal Redundancy Check character //NON-NLS
				bundle.getString("BlackboardAttribute.tskCardLRC.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_KEYWORD_SEARCH_DOCUMENT_ID(114, "TSK_KEYWORD_SEARCH_DOCUMENT_ID", //NON-NLS
				bundle.getString("BlackboardAttribute.tskKeywordSearchDocumentID.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_CARD_SCHEME(115, "TSK_CARD_SCHEME", //amex, visa, mastercard, discover, etc //NON-NLS
				bundle.getString("BlackboardAttribute.tskCardScheme.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_CARD_TYPE(116, "TSK_CARD_TYPE", // debit vs credit //NON-NLS
				bundle.getString("BlackboardAttribute.tskCardType.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_BRAND_NAME(117, "TSK_BRAND_NAME",
				bundle.getString("BlackboardAttribute.tskBrandName.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_BANK_NAME(118, "TSK_BANK_NAME",
				bundle.getString("BlackboardAttribute.tskBankName.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_COUNTRY(119, "TSK_COUNTRY",
				bundle.getString("BlackboardAttribute.tskCountry.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_CITY(120, "TSK_CITY",
				bundle.getString("BlackboardAttribute.tskCity.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_ACCOUNT_TYPE(121, "TSK_ACCOUNT_TYPE",
				bundle.getString("BlackboardAttribute.tskAccountType.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		/**
		 * Keyword search type: exact match, sub-string, or regex.
		 */
		TSK_KEYWORD_SEARCH_TYPE(122, "TSK_KEYWORD_SEARCH_TYPE", //NON-NLS
				bundle.getString("BlackboardAttribute.tskKeywordSearchType.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER),
		TSK_HEADERS(123, "TSK_HEADERS", //NON-NLS
				bundle.getString("BlackboardAttribute.tskHeaders.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_ID(124, "TSK_ID", //NON-NLS
				bundle.getString("BlackboardAttribute.tskId.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_SSID(125, "TSK_SSID", //NON-NLS
				bundle.getString("BlackboardAttribute.tskSsid.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_BSSID(126, "TSK_BSSID", //NON-NLS
				bundle.getString("BlackboardAttribute.tskBssid.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_MAC_ADDRESS(127, "TSK_MAC_ADDRESS", //NON-NLS
				bundle.getString("BlackboardAttribute.tskMacAddress.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_IMEI(128, "TSK_IMEI", //NON-NLS
				bundle.getString("BlackboardAttribute.tskImei.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_IMSI(129, "TSK_IMSI", //NON-NLS
				bundle.getString("BlackboardAttribute.tskImsi.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_ICCID(130, "TSK_ICCID", //NON-NLS
				bundle.getString("BlackboardAttribute.tskIccid.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_THREAD_ID(131, "TSK_THREAD_ID",
				bundle.getString("BlackboardAttribute.tskthreadid.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		/**
		 * The event type of a TSK_TL_EVENT artifact. The value should be the id
		 * of the EventType in the tsk_event_types table.
		 */
		TSK_TL_EVENT_TYPE(132, "TSK_TL_EVENT_TYPE", //NON-NLS
				bundle.getString("BlackboardAttribute.tskTLEventType.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG),
		TSK_DATETIME_DELETED(133, "TSK_DATETIME_DELETED", //NON-NLS
				bundle.getString("BlackboardAttribute.tskdatetimedeleted.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME),
		TSK_DATETIME_PASSWORD_RESET(134, "TSK_DATETIME_PASSWORD_RESET",
				bundle.getString("BlackboardAttribute.tskdatetimepwdreset.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME),
		TSK_DATETIME_PASSWORD_FAIL(135, "TSK_DATETIME_PWD_FAIL",
				bundle.getString("BlackboardAttribute.tskdatetimepwdfail.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME),
		TSK_DISPLAY_NAME(136, "TSK_DISPLAY_NAME",
				bundle.getString("BlackboardAttribute.tskdisplayname.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_PASSWORD_SETTINGS(137, "TSK_PASSWORD_SETTINGS",
				bundle.getString("BlackboardAttribute.tskpasswordsettings.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_ACCOUNT_SETTINGS(138, "TSK_ACCOUNT_SETTINGS",
				bundle.getString("BlackboardAttribute.tskaccountsettings.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_PASSWORD_HINT(139, "TSK_PASSWORD_HINT",
				bundle.getString("BlackboardAttribute.tskpasswordhint.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_GROUPS(140, "TSK_GROUPS",
				bundle.getString("BlackboardAttribute.tskgroups.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		/*
		 * Use
		 * org.sleuthkit.datamodel.blackboardutils.attributes.MessageAttachments
		 * to create and process TSK_ATTACHMENTS attributes.
		 */
		TSK_ATTACHMENTS(141, "TSK_ATTACHMENTS",
				bundle.getString("BlackboardAttribute.tskattachments.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.JSON),
		/*
		 * Use org.sleuthkit.datamodel.blackboardutils.attributes.GeoTrackPoints
		 * to create and process TSK_GEO_TRACKPOINTS attributes.
		 */
		TSK_GEO_TRACKPOINTS(142, "TSK_GEO_TRACKPOINTS",
				bundle.getString("BlackboardAttribute.tskgeopath.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.JSON),
		/*
		 * Use org.sleuthkit.datamodel.blackboardutils.attributes.GeoWaypoints
		 * to create and process TSK_GEO_WAYPOINTS attributes.
		 */
		TSK_GEO_WAYPOINTS(143, "TSK_GEO_WAYPOINTS",
				bundle.getString("BlackboardAttribute.tskgeowaypoints.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.JSON),
		TSK_DISTANCE_TRAVELED(144, "TSK_DISTANCE_TRAVELED",
				bundle.getString("BlackboardAttribute.tskdistancetraveled.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE),
		TSK_DISTANCE_FROM_HOMEPOINT(145, "TSK_DISTANCE_FROM_HOMEPOINT",
				bundle.getString("BlackboardAttribute.tskdistancefromhome.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE),
		TSK_HASH_PHOTODNA(146, "TSK_HASH_PHOTODNA",
				bundle.getString("BlackboardAttribute.tskhashphotodna.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_BYTES_SENT(147, "TSK_BYTES_SENT",
				bundle.getString("BlackboardAttribute.tskbytessent.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG),
		TSK_BYTES_RECEIVED(148, "TSK_BYTES_RECEIVED",
				bundle.getString("BlackboardAttribute.tskbytesreceived.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG),
		TSK_LAST_PRINTED_DATETIME(149, "TSK_LAST_PRINTED_DATETIME",
				bundle.getString("BlackboardAttribute.tsklastprinteddatetime.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME),
		TSK_RULE(150, "TSK_RULE",
				bundle.getString("BlackboardAttribute.tskrule.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_ACTIVITY_TYPE(151, "TSK_ACTIVITY_TYPE",
				bundle.getString("BlackboardAttribute.tskActivityType.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		/*
		 * Use org.sleuthkit.datamodel.blackboardutils.attributes.GeoAreaPoints
		 * to create and process TSK_GEO_AREAPOINTS attributes.
		 */
		TSK_GEO_AREAPOINTS(152, "TSK_GEO_AREAPOINTS",
				bundle.getString("BlackboardAttribute.tskgeoareapoints.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.JSON),
		TSK_REALM(153, "TSK_REALM",
				bundle.getString("BlackboardAttribute.tskRealm.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_HOST(154, "TSK_HOST",
				bundle.getString("BlackboardAttribute.tskHost.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_HOME_DIR(155, "TSK_HOME_DIR",
				bundle.getString("BlackboardAttribute.tskHomeDir.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_IS_ADMIN(156, "TSK_IS_ADMIN",
				bundle.getString("BlackboardAttribute.tskIsAdmin.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER),
		TSK_CORRELATION_TYPE(157, "TSK_CORRELATION_TYPE",
				bundle.getString("BlackboardAttribute.tskCorrelationType.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_CORRELATION_VALUE(158, "TSK_CORRELATION_VALUE",
				bundle.getString("BlackboardAttribute.tskCorrelationValue.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),
		TSK_OTHER_CASES(159, "TSK_OTHER_CASES",
				bundle.getString("BlackboardAttribute.tskOtherCases.text"),
				TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING),;

		private final int typeID;
		private final String typeName;
		private final String displayName;
		private final TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE valueType;

		/**
		 * Constructs a standard attribute type.
		 *
		 * @param typeID      The id of the type.
		 * @param typeName    The name of the type.
		 * @param displayName The display name of the type
		 * @param valueType   The value type of the type.
		 */
		private ATTRIBUTE_TYPE(int typeID, String typeName, String displayName, TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE valueType) {
			this.typeID = typeID;
			this.typeName = typeName;
			this.displayName = displayName;
			this.valueType = valueType;
		}

		/**
		 * Gets the type id of this standard attribute type.
		 *
		 * @return The type id.
		 */
		public int getTypeID() {
			return this.typeID;
		}

		/**
		 * Gets the type name of this standard attribute type.
		 *
		 * @return The type name.
		 *
		 * TODO (AUT-2070): Deprecate and provide a getTypeName method instead
		 * for API consistency.
		 */
		public String getLabel() {
			return this.typeName;
		}

		/**
		 * Gets the display name of this standard attribute type.
		 *
		 * @return The display name.
		 */
		public String getDisplayName() {
			return this.displayName;
		}

		/**
		 * Gets the value type of this standard attribute type.
		 *
		 * @return the value type
		 */
		public TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE getValueType() {
			return this.valueType;
		}

		/**
		 * Gets the standard attribute type for a given type id.
		 *
		 * @param typeID A standard attribute type id.
		 *
		 * @return A BlackboardAttribute.ATTRIBUTE_TYPE object.
		 *
		 * @throws IllegalArgumentException If the given type id does not map to
		 *                                  a standard attribute type.
		 *
		 * TODO (AUT-2070): Deprecate and provide a fromTypeId method instead
		 * for API consistency.
		 */
		static public ATTRIBUTE_TYPE fromID(int typeID) {
			for (ATTRIBUTE_TYPE attrType : ATTRIBUTE_TYPE.values()) {
				if (attrType.getTypeID() == typeID) {
					return attrType;
				}
			}
			throw new IllegalArgumentException("No ATTRIBUTE_TYPE matching type: " + typeID);
		}

		/**
		 * Gets the standard attribute type for a given type name.
		 *
		 * @param typeName A standard attribute type name.
		 *
		 * @return A BlackboardAttribute.ATTRIBUTE_TYPE object.
		 *
		 * @throws IllegalArgumentException If the given type name does not map
		 *                                  to a standard attribute type.
		 *
		 * TODO (AUT-2070): Deprecate and provide a fromTypeName method instead
		 * for API consistency.
		 */
		static public ATTRIBUTE_TYPE fromLabel(String typeName) {
			for (ATTRIBUTE_TYPE attrType : ATTRIBUTE_TYPE.values()) {
				if (attrType.getLabel().equals(typeName)) {
					return attrType;
				}
			}
			throw new IllegalArgumentException("No ATTRIBUTE_TYPE matching type: " + typeName);
		}

	}

	/**
	 * Creates a standard attribute with an integer value. The attribute should
	 * be added to an appropriate artifact.
	 *
	 * @param attributeTypeID The standard attribute type id.
	 * @param moduleName      The display name of the module creating this
	 *                        attribute.
	 * @param valueInt        The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  standard attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER
	 *                                  or the type id is not for a standard
	 *                                  type.
	 * @deprecated
	 */
	@Deprecated
	public BlackboardAttribute(int attributeTypeID, String moduleName, int valueInt) throws IllegalArgumentException {
		this(ATTRIBUTE_TYPE.fromID(attributeTypeID), moduleName, valueInt);
	}

	/**
	 * Creates a standard attribute with an integer value. The attribute should
	 * be added to an appropriate artifact.
	 *
	 * @param attributeTypeID The standard attribute type id.
	 * @param moduleName      The display name of the module creating this
	 *                        attribute.
	 * @param context         Extra information about the attribute.
	 * @param valueInt        The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  standard attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER
	 *                                  or the type id is not for a standard
	 *                                  type.
	 * @deprecated
	 */
	@Deprecated
	public BlackboardAttribute(int attributeTypeID, String moduleName, String context,
			int valueInt) {
		this(attributeTypeID, moduleName, valueInt);
		this.context = replaceNulls(context);
	}

	/**
	 * Creates a standard attribute with a long/datetime value. The attribute
	 * should be added to an appropriate artifact.
	 *
	 * @param attributeTypeID The standard attribute type id.
	 * @param moduleName      The display name of the module that creating this
	 *                        attribute.
	 * @param valueLong       The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  standard attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG
	 *                                  or
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME
	 *                                  or the type id is not for a standard
	 *                                  type.
	 * @deprecated
	 */
	@Deprecated
	public BlackboardAttribute(int attributeTypeID, String moduleName,
			long valueLong) throws IllegalArgumentException {
		this(ATTRIBUTE_TYPE.fromID(attributeTypeID), moduleName, valueLong);
	}

	/**
	 * Creates a standard attribute with a long/datetime value. The attribute
	 * should be added to an appropriate artifact.
	 *
	 * @param attributeTypeID The standard attribute type id.
	 * @param moduleName      The display name of the module that creating this
	 *                        attribute.
	 * @param context         Extra information about the attribute.
	 * @param valueLong       The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  standard attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG
	 *                                  or
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME
	 *                                  or the type id is not for a standard
	 *                                  type.
	 * @deprecated
	 */
	@Deprecated
	public BlackboardAttribute(int attributeTypeID, String moduleName, String context,
			long valueLong) {
		this(attributeTypeID, moduleName, valueLong);
		this.context = replaceNulls(context);
	}

	/**
	 * Creates a standard attribute with a double value. The attribute should be
	 * added to an appropriate artifact.
	 *
	 * @param attributeTypeID The standard attribute type id.
	 * @param moduleName      The display name of the module creating this
	 *                        attribute.
	 * @param valueDouble     The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  standard attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE
	 *                                  or the type id is not for a standard
	 *                                  type.
	 * @deprecated
	 */
	@Deprecated
	public BlackboardAttribute(int attributeTypeID, String moduleName,
			double valueDouble) throws IllegalArgumentException {
		this(ATTRIBUTE_TYPE.fromID(attributeTypeID), moduleName, valueDouble);
	}

	/**
	 * Creates a standard attribute with a double value. The attribute should be
	 * added to an appropriate artifact.
	 *
	 * @param attributeTypeID The standard attribute type id.
	 * @param moduleName      The display name of the module creating this
	 *                        attribute.
	 * @param context         Extra information about the attribute.
	 * @param valueDouble     The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  standard attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE
	 *                                  or the type id is not for a standard
	 *                                  type.
	 * @deprecated
	 */
	@Deprecated
	public BlackboardAttribute(int attributeTypeID, String moduleName, String context,
			double valueDouble) {
		this(attributeTypeID, moduleName, valueDouble);
		this.context = replaceNulls(context);
	}

	/**
	 * Creates a standard attribute with a string value. The attribute should be
	 * added to an appropriate artifact.
	 *
	 * @param attributeTypeID The standard attribute type id.
	 * @param moduleName      The display name of the module creating this
	 *                        attribute.
	 * @param valueString     The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  standard attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING
	 *                                  or the type id is not for a standard
	 *                                  type.
	 * @deprecated
	 */
	@Deprecated
	public BlackboardAttribute(int attributeTypeID, String moduleName, String valueString) throws IllegalArgumentException {
		this(ATTRIBUTE_TYPE.fromID(attributeTypeID), moduleName, valueString);
	}

	/**
	 * Creates a standard attribute with a string value. The attribute should be
	 * added to an appropriate artifact.
	 *
	 * @param attributeTypeID The standard attribute type id.
	 * @param moduleName      The display name of the module creating this
	 *                        attribute.
	 * @param context         Extra information about the attribute.
	 * @param valueString     The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  standard attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING
	 *                                  or the type id is not for a standard
	 *                                  type.
	 * @deprecated
	 */
	@Deprecated
	public BlackboardAttribute(int attributeTypeID, String moduleName, String context,
			String valueString) {
		this(attributeTypeID, moduleName, valueString);
		this.context = replaceNulls(context);
	}

	/**
	 * Creates a standard attribute with a byte array value. The attribute
	 * should be added to an appropriate artifact.
	 *
	 * @param attributeTypeID The standard attribute type id.
	 * @param moduleName      The display name of the module creating this
	 *                        attribute.
	 * @param valueBytes      The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  standard attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE
	 *                                  or the type id is not for a standard
	 *                                  type.
	 * @deprecated
	 */
	@Deprecated
	public BlackboardAttribute(int attributeTypeID, String moduleName, byte[] valueBytes) throws IllegalArgumentException {
		this(ATTRIBUTE_TYPE.fromID(attributeTypeID), moduleName, valueBytes);
	}

	/**
	 * Creates a standard attribute with a byte array value. The attribute
	 * should be added to an appropriate artifact.
	 *
	 * @param attributeTypeID The standard attribute type id.
	 * @param moduleName      The display name of the module creating this
	 *                        attribute.
	 * @param context         Extra information about the attribute.
	 * @param valueBytes      The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  standard attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE
	 *                                  or the type id is not for a standard
	 *                                  type.
	 * @deprecated
	 */
	@Deprecated
	public BlackboardAttribute(int attributeTypeID, String moduleName, String context,
			byte[] valueBytes) {
		this(attributeTypeID, moduleName, valueBytes);
		this.context = replaceNulls(context);
	}

	/**
	 * Sets the artifact id.
	 *
	 * @param artifactID The artifact id.
	 *
	 * @deprecated The preferred method for doing this is to add the attribute
	 * to a BlackboardArtifact object by calling BlackboardArtifact.addAttribute
	 * or BlackboardArtifact.addAttributes, both of which post the attributes to
	 * the blackboard.
	 */
	@Deprecated
	protected void setArtifactID(long artifactID) {
		setArtifactId(artifactID);
	}

	/**
	 * Sets the reference to the SleuthkitCase object that represents the case
	 * database.
	 *
	 * @param sleuthkitCase A reference to a SleuthkitCase object.
	 *
	 * @deprecated The preferred method for doing this is to add the attribute
	 * to a BlackboardArtifact object by calling BlackboardArtifact.addAttribute
	 * or BlackboardArtifact.addAttributes, both of which post the attributes to
	 * the blackboard.
	 */
	@Deprecated
	protected void setCase(SleuthkitCase sleuthkitCase) {
		setCaseDatabase(sleuthkitCase);
	}

	/**
	 * Gets the context of this attribute.
	 *
	 * @return The context, may be the empty string.
	 *
	 * @deprecated Setting context for an attribute is deprecated.
	 */
	@Deprecated
	public String getContext() {
		return context;
	}

	/**
	 * Gets the context of this attribute.
	 *
	 * @return The context, may be the empty string.
	 *
	 * @deprecated Setting context for an attribute is deprecated.
	 */
	@Deprecated
	String getContextString() {
		return context;
	}

	/**
	 * Gets the attribute type id.
	 *
	 * @return The type id.
	 *
	 * @deprecated Use BlackboardAttribute.getAttributeType.getTypeID instead.
	 */
	@Deprecated
	public int getAttributeTypeID() {
		return getAttributeType().getTypeID();
	}

	/**
	 * Gets the attribute type name.
	 *
	 * @return The type name.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 *
	 * @deprecated Use BlackboardAttribute.getAttributeType.getTypeName instead.
	 */
	@Deprecated
	public String getAttributeTypeName() throws TskCoreException {
		return getAttributeType().getTypeName();
	}

	/**
	 * Gets the attribute type display name.
	 *
	 * @return type The display name.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 *
	 * @deprecated Use BlackboardAttribute.getAttributeType.getDisplayName
	 * instead.
	 */
	@Deprecated
	public String getAttributeTypeDisplayName() throws TskCoreException {
		return getAttributeType().getDisplayName();
	}

	/**
	 * Gets the name of the first module identified as a sources of this
	 * attribute.
	 *
	 * @return A comma-separated-values list of module names, may be empty.
	 *
	 * @deprecated Use getSources instead.
	 */
	@Deprecated
	public String getModuleName() {
		return getSourcesCSV();
	}

}
