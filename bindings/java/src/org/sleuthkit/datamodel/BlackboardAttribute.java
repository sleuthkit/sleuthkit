/*
 * Sleuth Kit Data Model
 *
 * Copyright 2012-2014 Basis Technology Corp.
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

import java.util.ResourceBundle;

/**
 * Represents an attribute as stored in the Blackboard. Attributes are a name
 * value pair. The name represents the type of data being stored. Attributes are
 * grouped together into an Artifact as represented by a BlackboardArtifact
 * object. This class is used to create attribute on the blackboard and is used
 * to represent attribute queried from the blackboard.
 */
public class BlackboardAttribute {

	private long artifactID;
	private int attributeTypeID;
	private String moduleName;
	private String context;
	private TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE valueType;
	private int valueInt;
	private long valueLong;
	private double valueDouble;
	private String valueString;
	private byte[] valueBytes;
	private SleuthkitCase sleuthkitCase;
    private static ResourceBundle bundle = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle");

	/**
	 * Enum for the data type (int, double, etc.) of this attribute's value.
	 */
	public enum TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE {

		STRING(0, "String"), ///< string NON-NLS
		INTEGER(1, "Integer"), ///< int NON-NLS
		LONG(2, "Long"), ///< long NON-NLS
		DOUBLE(3, "Double"), ///< double NON-NLS
		BYTE(4, "Byte");      ///< byte NON-NLS
		private long type;
		private String label;

		private TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE(long type, String label) {
			this.type = type;
			this.label = label;
		}

		/**
		 * Get the type id for this attribute type enum
		 */
		public long getType() {
			return type;
		}

		/**
		 * Get the label string for this attribute type enum
		 */
		public String getLabel() {
			return this.label;
		}

		/**
		 * Get the enum type for the given type id
		 *
		 * @param type type id
		 * @return enum type
		 */
		static public TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE fromType(long type) {
			for (TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE v : TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.values()) {
				if (v.type == type) {
					return v;
				}
			}
			throw new IllegalArgumentException("No TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE matching type: " + type);
		}
	}

	/**
	 * Standard attribute types. Refer to the C++ code for the full description
	 * of their intended use. See
	 * http://wiki.sleuthkit.org/index.php?title=Artifact_Examples for more
	 * information.
	 */
	public enum ATTRIBUTE_TYPE {
		/* It is very important that this list be kept up to
		 * date and in sync with the C++ code.  Do not add
		 * anything here unless you also add it there.
		 * See framework/Services/TskBlackboard.* */

		TSK_URL(1, "TSK_URL",  //NON-NLS
                    bundle.getString("BlackboardAttribute.tskUrl.text")),
		TSK_DATETIME(2, "TSK_DATETIME", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskDatetime.text")),
		TSK_NAME(3, "TSK_NAME",  //NON-NLS
                    bundle.getString("BlackboardAttribute.tskName.text")),
		TSK_PROG_NAME(4, "TSK_PROG_NAME", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskProgName.text")),
		TSK_VALUE(6, "TSK_VALUE",  //NON-NLS
                    bundle.getString("BlackboardAttribute.tskValue.text")),
		TSK_FLAG(7, "TSK_FLAG",  //NON-NLS
                    bundle.getString("BlackboardAttribute.tskFlag.text")),
		TSK_PATH(8, "TSK_PATH",  //NON-NLS
                    bundle.getString("BlackboardAttribute.tskPath.text")),
		TSK_KEYWORD(10, "TSK_KEYWORD", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskKeyword.text")),
		TSK_KEYWORD_REGEXP(11, "TSK_KEYWORD_REGEXP",  //NON-NLS
                    bundle.getString("BlackboardAttribute.tskKeywordRegexp.text")),
		TSK_KEYWORD_PREVIEW(12, "TSK_KEYWORD_PREVIEW", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskKeywordPreview.text")),
        @Deprecated
        // use TSK_SET_NAME instead
		TSK_KEYWORD_SET(13, "TSK_KEYWORD_SET", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskKeywordSet.text")),
		TSK_USER_NAME(14, "TSK_USER_NAME", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskUserName.text")),
		TSK_DOMAIN(15, "TSK_DOMAIN",  //NON-NLS
                    bundle.getString("BlackboardAttribute.tskDomain.text")),
		TSK_PASSWORD(16, "TSK_PASSWORD", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskPassword.text")),
		TSK_NAME_PERSON(17, "TSK_NAME_PERSON", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskNamePerson.text")),
		TSK_DEVICE_MODEL(18, "TSK_DEVICE_MODEL", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskDeviceModel.text")),
		TSK_DEVICE_MAKE(19, "TSK_DEVICE_MAKE", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskDeviceMake.text")),
		TSK_DEVICE_ID(20, "TSK_DEVICE_ID", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskDeviceId.text")),
		TSK_EMAIL(21, "TSK_EMAIL",  //NON-NLS
                    bundle.getString("BlackboardAttribute.tskEmail.text")),
		TSK_HASH_MD5(22, "TSK_HASH_MD5", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskHashMd5.text")),
		TSK_HASH_SHA1(23, "TSK_HASH_SHA1", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskHashSha1.text")),
		TSK_HASH_SHA2_256(24, "TSK_HASH_SHA2_256", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskHashSha225.text")),
		TSK_HASH_SHA2_512(25, "TSK_HASH_SHA2_512", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskHashSha2512.text")),
		TSK_TEXT(26, "TSK_TEXT",  //NON-NLS
                    bundle.getString("BlackboardAttribute.tskText.text")),
		TSK_TEXT_FILE(27, "TSK_TEXT_FILE", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskTextFile.text")),
		TSK_TEXT_LANGUAGE(28, "TSK_TEXT_LANGUAGE", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskTextLanguage.text")),
		TSK_ENTROPY(29, "TSK_ENTROPY", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskEntropy.text")),
        @Deprecated
        // use TSK_SET_NAME instead
		TSK_HASHSET_NAME(30, "TSK_HASHSET_NAME", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskHashsetName.text")),
		@Deprecated
        // use TSK_INTERSTING_FILE_HIT instead
		TSK_INTERESTING_FILE(31, "TSK_INTERESTING_FILE", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskInterestingFile.text")),
		TSK_REFERRER(32, "TSK_REFERRER", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskReferrer.text")),
		TSK_DATETIME_ACCESSED(33, "TSK_DATETIME_ACCESSED", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskDateTimeAccessed.text")),
		TSK_IP_ADDRESS(34, "TSK_IP_ADDRESS", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskIpAddress.text")),
		TSK_PHONE_NUMBER(35, "TSK_PHONE_NUMBER", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskPhoneNumber.text")),
		TSK_PATH_ID(36, "TSK_PATH_ID",  //NON-NLS
                    bundle.getString("BlackboardAttribute.tskPathId.text")),
		TSK_SET_NAME(37, "TSK_SET_NAME", //NON-NLS
                     bundle.getString("BlackboardAttribute.tskSetName.text")),
		@Deprecated
        // use artifact instead
		TSK_ENCRYPTION_DETECTED(38, "TSK_ENCRYPTION_DETECTED", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskEncryptionDetected.text")),
		TSK_MALWARE_DETECTED(39, "TSK_MALWARE_DETECTED", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskMalwareDetected.text")),
		TSK_STEG_DETECTED(40, "TSK_STEG_DETECTED", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskStegDetected.text")),
		TSK_EMAIL_TO(41, "TSK_EMAIL_TO", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskEmailTo.text")),
		TSK_EMAIL_CC(42, "TSK_EMAIL_CC", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskEmailCc.text")),
		TSK_EMAIL_BCC(43, "TSK_EMAIL_BCC", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskEmailBcc.text")),
		TSK_EMAIL_FROM(44, "TSK_EMAIL_FROM", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskEmailFrom.text")),
		TSK_EMAIL_CONTENT_PLAIN(45, "TSK_EMAIL_CONTENT_PLAIN",  //NON-NLS
                    bundle.getString("BlackboardAttribute.tskEmailContentPlain.text")),
		TSK_EMAIL_CONTENT_HTML(46, "TSK_EMAIL_CONTENT_HTML", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskEmailContentHtml.text")),
		TSK_EMAIL_CONTENT_RTF(47, "TSK_EMAIL_CONTENT_RTF", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskEmailContentRtf.text")),
		TSK_MSG_ID(48, "TSK_MSG_ID",  //NON-NLS
                    bundle.getString("BlackboardAttribute.tskMsgId.text")),
		TSK_MSG_REPLY_ID(49, "TSK_MSG_REPLY_ID", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskMsgReplyId.text")),
		TSK_DATETIME_RCVD(50, "TSK_DATETIME_RCVD", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskDateTimeRcvd.text")),
		TSK_DATETIME_SENT(51, "TSK_DATETIME_SENT", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskDateTimeSent.text")),
		TSK_SUBJECT(52, "TSK_SUBJECT", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskSubject.text")),
		TSK_TITLE(53, "TSK_TITLE", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskTitle.text")),
		TSK_GEO_LATITUDE(54, "TSK_GEO_LATITUDE", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskGeoLatitude.text")),
		TSK_GEO_LONGITUDE(55, "TSK_GEO_LONGITUDE", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskGeoLongitude.text")),
		TSK_GEO_VELOCITY(56, "TSK_GEO_VELOCITY", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskGeoVelocity.text")),
		TSK_GEO_ALTITUDE(57, "TSK_GEO_ALTITUDE", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskGeoAltitude.text")),
		TSK_GEO_BEARING(58, "TSK_GEO_BEARING", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskGeoBearing.text")),
		TSK_GEO_HPRECISION(59, "TSK_GEO_HPRECISION", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskGeoHPrecision.text")),
		TSK_GEO_VPRECISION(60, "TSK_GEO_VPRECISION", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskGeoVPrecision.text")),
		TSK_GEO_MAPDATUM(61, "TSK_GEO_MAPDATUM", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskGeoMapDatum.text")),
		TSK_FILE_TYPE_SIG(62, "TSK_FILE_TYPE_SIG", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskFileTypeSig.text")),
		TSK_FILE_TYPE_EXT(63, "TSK_FILE_TYPE_EXT", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskFileTypeExt.text")),
        @Deprecated
        // tag tables exist not, do not tag with blackboard
		TSK_TAGGED_ARTIFACT(64, "TSK_TAGGED_ARTIFACT", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskTaggedArtifact.text")),
        @Deprecated
        // tag tables exist not, do not tag with blackboard
		TSK_TAG_NAME(65, "TSK_TAG_NAME", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskTagName.text")),
		TSK_COMMENT(66, "TSK_COMMENT", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskComment.text")),
		TSK_URL_DECODED(67, "TSK_URL_DECODED", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskUrlDecoded.text")),
		TSK_DATETIME_CREATED(68, "TSK_DATETIME_CREATED", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskDateTimeCreated.text")),
		TSK_DATETIME_MODIFIED(69, "TSK_DATETIME_MODIFIED", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskDateTimeModified.text")),
		TSK_PROCESSOR_ARCHITECTURE(70, "TSK_PROCESSOR_ARCHITECTURE", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskProcessorArchitecture.text")),
		TSK_VERSION(71, "TSK_VERSION", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskVersion.text")),
		TSK_USER_ID(72, "TSK_USER_ID", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskUserId.text")),
		TSK_DESCRIPTION(73, "TSK_DESCRIPTION", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskDescription.text")),
		TSK_MESSAGE_TYPE(74, "TSK_MESSAGE_TYPE", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskMessageType.text")), // SMS or MMS or IM ...
		TSK_PHONE_NUMBER_HOME(75, "TSK_PHONE_NUMBER_HOME", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskPhoneNumberHome.text")),
		TSK_PHONE_NUMBER_OFFICE(76, "TSK_PHONE_NUMBER_OFFICE", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskPhoneNumberOffice.text")),
		TSK_PHONE_NUMBER_MOBILE(77, "TSK_PHONE_NUMBER_MOBILE", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskPhoneNumberMobile.text")),
		TSK_PHONE_NUMBER_FROM(78, "TSK_PHONE_NUMBER_FROM", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskPhoneNumberFrom.text")),
		TSK_PHONE_NUMBER_TO(79, "TSK_PHONE_NUMBER_TO", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskPhoneNumberTo.text")),
		TSK_DIRECTION(80, "TSK_DIRECTION", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskDirection.text")), // Msg/Call direction: incoming, outgoing
		TSK_EMAIL_HOME(81, "TSK_EMAIL_HOME", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskEmailHome.text")),
		TSK_EMAIL_OFFICE(82, "TSK_EMAIL_OFFICE", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskEmailOffice.text")),
		TSK_DATETIME_START(83, "TSK_DATETIME_START", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskDateTimeStart.text")), // start time of an event - call log, Calendar entry
		TSK_DATETIME_END(84, "TSK_DATETIME_END", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskDateTimeEnd.text")), // end time of an event - call log, Calendar entry
		TSK_CALENDAR_ENTRY_TYPE(85, "TSK_CALENDAR_ENTRY_TYPE", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskCalendarEntryType.text")),	// meeting, task,
		TSK_LOCATION(86, "TSK_LOCATION", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskLocation.text")), // Location string associated with an event - Conf Room Name, Address ....
		TSK_SHORTCUT(87, "TSK_SHORTCUT", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskShortcut.text")), // Short Cut string - short code or dial string for Speed dial, a URL short cut - e.g. bitly string, Windows Desktop Short cut name etc.
		TSK_DEVICE_NAME(88, "TSK_DEVICE_NAME", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskDeviceName.text")), // device name - a user assigned (usually) device name - such as "Joe's computer", "bob_win8", "BT Headset"
		TSK_CATEGORY(89, "TSK_CATEGORY", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskCategory.text")), // category/type, possible value set varies by the artifact
		TSK_EMAIL_REPLYTO(90, "TSK_EMAIL_REPLYTO", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskEmailReplyTo.text")), // ReplyTo address
		TSK_SERVER_NAME(91, "TSK_SERVER_NAME", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskServerName.text")), // server name, e.g. a mail server name - "smtp.google.com", a DNS server name...
		TSK_COUNT(92, "TSK_COUNT", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskCount.text")), // Count related to the artifact
		TSK_MIN_COUNT(93, "TSK_MIN_COUNT", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskMinCount.text")), // Minimum number/count
		TSK_PATH_SOURCE(94, "TSK_PATH_SOURCE", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskPathSource.text")), // Path to a source file related to the artifact
		TSK_PERMISSIONS(95, "TSK_PERMISSIONS", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskPermissions.text")), // Permissions
		TSK_ASSOCIATED_ARTIFACT(96, "TSK_ASSOCIATED_ARTIFACT", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskAssociatedArtifact.text")), // Artifact ID of a related artifact
		TSK_ISDELETED(97, "TSK_ISDELETED", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskIsDeleted.text")), // boolean to indicate that the artifact is recovered fom deleted content
		TSK_GEO_LATITUDE_START(98, "TSK_GEO_LATITUDE_START", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskGeoLatitudeStart.text")), // Starting location lattitude
		TSK_GEO_LATITUDE_END(99, "TSK_GEO_LATITUDE_END", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskGeoLatitudeEnd.text")), // Ending location lattitude
		TSK_GEO_LONGITUDE_START(100, "TSK_GEO_LONGITUDE_START", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskGeoLongitudeStart.text")), // Starting location longitude
		TSK_GEO_LONGITUDE_END(101, "TSK_GEO_LONGITUDE_END", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskGeoLongitudeEnd.text")), //Ending Location longitude
		TSK_READ_STATUS(102, "TSK_READ_STATUS", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskReadStatus.text")), // Message read status: 1 if read, 0 if unread
        TSK_LOCAL_PATH(103, "TSK_LOCAL_PATH", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskLocalPath.text")), // Local path to a network drive
        TSK_REMOTE_PATH(104, "TSK_REMOTE_PATH", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskRemotePath.text")), // Remote path of a network drive
        TSK_TEMP_DIR(105, "TSK_TEMP_DIR", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskTempDir.text")), // Default temporary files directory
        TSK_PRODUCT_ID(106, "TSK_PRODUCT_ID", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskProductId.text")), // Product ID
        TSK_OWNER(107, "TSK_OWNER", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskOwner.text")), // Registered owner of a piece of software
        TSK_ORGANIZATION(108, "TSK_ORGANIZATION", //NON-NLS
                    bundle.getString("BlackboardAttribute.tskOrganization.text")), // Registered Organization for a piece of software
		
		;
		/* SEE ABOVE -- ALSO ADD TO C++ CODE */
		private String label;
		private int typeID;
		private String displayName;

        private ATTRIBUTE_TYPE(int typeID, String label, String displayName) {
			this.typeID = typeID;
			this.label = label;
			this.displayName = displayName;
		}

		/**
		 * Get label string of this attribute
		 *
		 * @return label string
		 */
		public String getLabel() {
			return this.label;
		}

		/**
		 * Get type id of this attribute
		 *
		 * @return type id
		 */
		public int getTypeID() {
			return this.typeID;
		}

		/**
		 * Get the attribute enum for the given label
		 *
		 * @param label label string
		 * @return the enum value
		 */
		static public ATTRIBUTE_TYPE fromLabel(String label) {
			for (ATTRIBUTE_TYPE v : ATTRIBUTE_TYPE.values()) {
				if (v.label.equals(label)) {
					return v;
				}
			}
			throw new IllegalArgumentException("No ATTRIBUTE_TYPE matching type: " + label);
		}

		public String getDisplayName() {
			return this.displayName;
		}
	}

	/**
	 * Constructor for a blackboard attribute.
	 *
	 * Should only be used by SleuthkitCase
	 *
	 * @param artifactID artifact id for this attribute
	 * @param attributeTypeID type id
	 * @param moduleName module that created this attribute
	 * @param context extra information about this name value pair
	 * @param valueType type of value to be stored
	 * @param valueInt value if it is an int
	 * @param valueLong value if it is a long
	 * @param valueDouble value if it is a double
	 * @param valueString value if it is a string
	 * @param valueBytes value if it is a byte array
	 * @param sleuthkitCase the case that can be used to make calls into the blackboard
	 * db
	 */
	BlackboardAttribute(long artifactID, int attributeTypeID, String moduleName, String context,
			TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE valueType, int valueInt, long valueLong, double valueDouble,
			String valueString, byte[] valueBytes, SleuthkitCase sleuthkitCase) {

		this.artifactID = artifactID;
		this.attributeTypeID = attributeTypeID;
		this.moduleName = moduleName;
		this.context = context;
		this.valueType = valueType;
		this.valueInt = valueInt;
		this.valueLong = valueLong;
		this.valueDouble = valueDouble;
		if (valueString == null) {
			this.valueString = "";
		} else {
			this.valueString = valueString;
		}
		if (valueBytes == null) {
			this.valueBytes = new byte[0];
		} else {
			this.valueBytes = valueBytes;
		}
		this.sleuthkitCase = sleuthkitCase;
	}

	/**
	 * Create a blackboard attribute that stores an int (creates an attribute
	 * that can be added to an artifact)
	 *
	 * @param attributeTypeID type of the attribute
	 * @param moduleName name of the module that is creating the attribute
	 * @param valueInt the value
	 */
	public BlackboardAttribute(int attributeTypeID, String moduleName, int valueInt) {
		this.artifactID = 0;
		this.attributeTypeID = attributeTypeID;
		this.moduleName = moduleName;
		this.valueType = TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER;
		this.valueInt = valueInt;
		this.valueLong = 0;
		this.valueDouble = 0;
		this.valueString = "";
		this.valueBytes = new byte[0];
		this.context = "";
	}

	/**
	 * Create a blackboard attribute that stores an int (creates an attribute
	 * that can be added to an artifact)
	 *
	 * @param attributeTypeID type of the attribute
	 * @param moduleName name of the module that is creating the attribute
	 * @param context extra information about the attribute
	 * @param valueInt the value
	 * @deprecated context parameter will be deprecated - in lieu of specific
	 * blackboard attributes use the alternative constructor without context
	 */
	@Deprecated
	public BlackboardAttribute(int attributeTypeID, String moduleName, String context,
			int valueInt) {
		this(attributeTypeID, moduleName, valueInt);
		this.context = context;
	}

	/**
	 * Create a blackboard attribute that stores a long (creates an attribute
	 * that can be added to an artifact)
	 *
	 * @param attributeTypeID type of the attribute
	 * @param moduleName name of the module that is creating the attribute
	 * @param valueLong the value
	 */
	public BlackboardAttribute(int attributeTypeID, String moduleName,
			long valueLong) {
		this.artifactID = 0;
		this.attributeTypeID = attributeTypeID;
		this.moduleName = moduleName;
		this.valueType = TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG;
		this.valueInt = 0;
		this.valueLong = valueLong;
		this.valueDouble = 0;
		this.valueString = "";
		this.valueBytes = new byte[0];
		this.context = "";

	}

	/**
	 * Create a blackboard attribute that stores a long (creates an attribute
	 * that can be added to an artifact)
	 *
	 * @param attributeTypeID type of the attribute
	 * @param moduleName name of the module that is creating the attribute
	 * @param context extra information about the attribute
	 * @param valueLong the value
	 * @deprecated context parameter will be deprecated - in lieu of specific
	 * blackboard attributes use the alternative constructor without context
	 */
	@Deprecated
	public BlackboardAttribute(int attributeTypeID, String moduleName, String context,
			long valueLong) {
		this(attributeTypeID, moduleName, valueLong);
		this.context = context;
	}

	/**
	 * Create a blackboard attribute that stores a double (creates an attribute
	 * that can be added to an artifact)
	 *
	 * @param attributeTypeID type of the attribute
	 * @param moduleName name of the module that is creating the attribute
	 * @param valueDouble the value
	 */
	public BlackboardAttribute(int attributeTypeID, String moduleName,
			double valueDouble) {
		this.artifactID = 0;
		this.attributeTypeID = attributeTypeID;
		this.moduleName = moduleName;
		this.valueType = TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE;
		this.valueInt = 0;
		this.valueLong = 0;
		this.valueDouble = valueDouble;
		this.valueString = "";
		this.valueBytes = new byte[0];
		this.context = "";
	}

	/**
	 * Create a blackboard attribute that stores a double (creates an attribute
	 * that can be added to an artifact)
	 *
	 * @param attributeTypeID type of the attribute
	 * @param moduleName name of the module that is creating the attribute
	 * @param context extra information about the attribute
	 * @param valueDouble the value
	 * @deprecated context parameter will be deprecated - in lieu of specific
	 * blackboard attributes use the alternative constructor without context
	 */
	@Deprecated
	public BlackboardAttribute(int attributeTypeID, String moduleName, String context,
			double valueDouble) {
		this(attributeTypeID, moduleName, valueDouble);
		this.context = context;
	}

	/**
	 * Create a blackboard attribute that stores a string (creates an attribute
	 * that can be added to an artifact)
	 *
	 * @param attributeTypeID type of the attribute
	 * @param moduleName name of the module that is creating the attribute
	 * @param valueString the value
	 */
	public BlackboardAttribute(int attributeTypeID, String moduleName, String valueString) {
		this.artifactID = 0;
		this.attributeTypeID = attributeTypeID;
		this.moduleName = moduleName;
		this.valueType = TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING;
		this.valueInt = 0;
		this.valueLong = 0;
		this.valueDouble = 0;
		if (valueString == null) {
			this.valueString = "";
		} else {
			this.valueString = valueString;
		}
		this.valueBytes = new byte[0];
		this.context = "";
	}

	/**
	 * Create a blackboard attribute that stores a string (creates an attribute
	 * that can be added to an artifact)
	 *
	 * @param attributeTypeID type of the attribute
	 * @param moduleName name of the module that is creating the attribute
	 * @param context extra information about the attribute
	 * @param valueString the value
	 * @deprecated context parameter will be deprecated - in lieu of specific
	 * blackboard attributes use the alternative constructor without context
	 */
	@Deprecated
	public BlackboardAttribute(int attributeTypeID, String moduleName, String context,
			String valueString) {
		this(attributeTypeID, moduleName, valueString);
		this.context = context;
	}

	/**
	 * Create a blackboard attribute that stores a byte array (creates an
	 * attribute that can be added to an artifact)
	 *
	 * @param attributeTypeID type of the attribute
	 * @param moduleName name of the module that is creating the attribute
	 * @param valueBytes the value
	 */
	public BlackboardAttribute(int attributeTypeID, String moduleName, byte[] valueBytes) {
		this.artifactID = 0;
		this.attributeTypeID = attributeTypeID;
		this.moduleName = moduleName;
		this.context = "";
		this.valueType = TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE;
		this.valueInt = 0;
		this.valueLong = 0;
		this.valueDouble = 0;
		this.valueString = "";
		if (valueBytes == null) {
			this.valueBytes = new byte[0];
		} else {
			this.valueBytes = valueBytes;
		}
	}

	/**
	 * Create a blackboard attribute that stores a byte array (creates an
	 * attribute that can be added to an artifact)
	 *
	 * @param attributeTypeID type of the attribute
	 * @param moduleName name of the module that is creating the attribute
	 * @param context extra information about the attribute
	 * @param valueBytes the value
	 */
	@Deprecated
	public BlackboardAttribute(int attributeTypeID, String moduleName, String context,
			byte[] valueBytes) {
		this(attributeTypeID, moduleName, valueBytes);
		this.context = context;
	}

	@Override
	public int hashCode() {
		int hash = 5;
		hash = 97 * hash + (int) (this.artifactID ^ (this.artifactID >>> 32));
		return hash;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		final BlackboardAttribute other = (BlackboardAttribute) obj;
		if (this.artifactID != other.artifactID) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "BlackboardAttribute{" + "artifactID=" + artifactID + ", attributeTypeID=" + attributeTypeID + ", moduleName=" + moduleName + ", context=" + context + ", valueType=" + valueType + ", valueInt=" + valueInt + ", valueLong=" + valueLong + ", valueDouble=" + valueDouble + ", valueString=" + valueString + ", valueBytes=" + valueBytes + ", Case=" + sleuthkitCase + '}'; //NON-NLS
	}

	/**
	 * Get the artifact id
	 *
	 * @return artifact id
	 */
	public long getArtifactID() {
		return artifactID;
	}

	/**
	 * Get the attribute type id
	 *
	 * @return type id
	 */
	public int getAttributeTypeID() {
		return attributeTypeID;
	}

	/**
	 * Get the attribute type name string
	 *
	 * @return type name string
	 */
	public String getAttributeTypeName() throws TskCoreException {
		return sleuthkitCase.getAttrTypeString(attributeTypeID);
	}

	/**
	 * Get the attribute type display name
	 *
	 * @return type display name
	 */
	public String getAttributeTypeDisplayName() throws TskCoreException {
		return sleuthkitCase.getAttrTypeDisplayName(attributeTypeID);
	}

	/**
	 * Get the value type.
	 *
	 * This should be used to identify the type of value and
	 * call the right value get method.
	 *
	 * @return value type
	 */
	public TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE getValueType() {
		return valueType;
	}

	/**
	 * Get the value if it is an int
	 *
	 * @return value
	 */
	public int getValueInt() {
		return valueInt;
	}

	/**
	 * Get value if it is a long
	 *
	 * @return value
	 */
	public long getValueLong() {
		return valueLong;
	}

	/**
	 * Get value if it is a double
	 *
	 * @return value
	 */
	public double getValueDouble() {
		return valueDouble;
	}

	/**
	 * Get value if it is a string
	 *
	 * @return value
	 */
	public String getValueString() {
		return valueString;
	}

	/**
	 * Get value if it is a byte array
	 *
	 * @return value
	 */
	public byte[] getValueBytes() {
		return valueBytes;
	}

	/**
	 * Get module name of the module that created the attribute
	 *
	 * @return name
	 */
	public String getModuleName() {
		return moduleName;
	}

	/**
	 * Get context of the data stored in the attribute, if set
	 *
	 * @return context
	 */
	public String getContext() {
		return context;
	}

	/**
	 * Get the artifact that this attribute is associated with.
	 *
	 * The artifact can
	 * be used to find the associated file and other attributes associated with
	 * this artifact.
	 *
	 * @return artifact
	 * @throws TskException exception thrown when critical error occurred within
	 * tsk core
	 */
	public BlackboardArtifact getParentArtifact() throws TskCoreException {
		return sleuthkitCase.getBlackboardArtifact(artifactID);
	}

	/**
	 * Set the artifactID, this should only be used by sleuthkitCase
	 *
	 * @param artifactID artifactID to set on a newly created attribute
	 */
	protected void setArtifactID(long artifactID) {
		this.artifactID = artifactID;
	}

	/**
	 * Set the SleuthkitCase handle, this should only be used by SleuthkitCase
	 * on a newly created attribute
	 *
	 * @param sleuthkitCase case handle to associated with this attribute
	 */
	protected void setCase(SleuthkitCase sleuthkitCase) {
		this.sleuthkitCase = sleuthkitCase;
	}
	
	// from http://stackoverflow.com/questions/9655181/convert-from-byte-array-to-hex-string-in-java
	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	private static String bytesToHexString(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for ( int j = 0; j < bytes.length; j++ ) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

	
	/**
	 * 
	 * NOTE: Dates are not yet formatted. 
	 * 
	 * @return return a string form of the stored value.  Formatted if needed.
	 */
	public String getDisplayString() {
		switch (valueType) {
			case STRING:
				return getValueString();
			case INTEGER:
				if (attributeTypeID == ATTRIBUTE_TYPE.TSK_READ_STATUS.getTypeID()) {
					if (getValueInt() == 0) {
						return "Unread";
					} else {
						return "Read";
					}
				} 
				return Integer.toString(getValueInt());
			case LONG:
				// SHOULD at some point figure out how to convert times in here based on preferred formats
				// and such.  Perhaps pass in a time formatter. 
				return Long.toString(getValueLong());
			case DOUBLE:
				return Double.toString(getValueDouble());
			case BYTE:
				return bytesToHexString(getValueBytes());
		}
		return "";
	}
}
