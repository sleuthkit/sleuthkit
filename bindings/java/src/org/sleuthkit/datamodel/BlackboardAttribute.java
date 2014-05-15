/*
 * Sleuth Kit Data Model
 *
 * Copyright 2012 Basis Technology Corp.
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

import org.openide.util.NbBundle;

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
	private SleuthkitCase Case;

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
                NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskUrl.text")),
		TSK_DATETIME(2, "TSK_DATETIME", //NON-NLS
                     NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskDatetime.text")),
		TSK_NAME(3, "TSK_NAME",  //NON-NLS
                 NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskName.text")),
		TSK_PROG_NAME(4, "TSK_PROG_NAME", //NON-NLS
                      NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskProgName.text")),
		TSK_VALUE(6, "TSK_VALUE",  //NON-NLS
                  NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskValue.text")),
		TSK_FLAG(7, "TSK_FLAG",  //NON-NLS
                 NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskFlag.text")),
		TSK_PATH(8, "TSK_PATH",  //NON-NLS
                 NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskPath.text")),
		TSK_KEYWORD(10, "TSK_KEYWORD", //NON-NLS
                    NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskKeyword.text")),
		TSK_KEYWORD_REGEXP(11, "TSK_KEYWORD_REGEXP",  //NON-NLS
                           NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskKeywordRegexp.text")),
		TSK_KEYWORD_PREVIEW(12, "TSK_KEYWORD_PREVIEW", //NON-NLS
                            NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskKeywordPreview.text")),
		TSK_KEYWORD_SET(13, "TSK_KEYWORD_SET", //NON-NLS
                        NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskKeywordSet.text")), // @@@ Deprecated
		TSK_USER_NAME(14, "TSK_USER_NAME", //NON-NLS
                      NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskUserName.text")),
		TSK_DOMAIN(15, "TSK_DOMAIN",  //NON-NLS
                   NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskDomain.text")),
		TSK_PASSWORD(16, "TSK_PASSWORD", //NON-NLS
                     NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskPassword.text")),
		TSK_NAME_PERSON(17, "TSK_NAME_PERSON", //NON-NLS
                        NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskNamePerson.text")),
		TSK_DEVICE_MODEL(18, "TSK_DEVICE_MODEL", //NON-NLS
                         NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskDeviceModel.text")),
		TSK_DEVICE_MAKE(19, "TSK_DEVICE_MAKE", //NON-NLS
                        NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskDeviceMake.text")),
		TSK_DEVICE_ID(20, "TSK_DEVICE_ID", //NON-NLS
                      NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskDeviceId.text")),
		TSK_EMAIL(21, "TSK_EMAIL",  //NON-NLS
                  NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskEmail.text")),
		TSK_HASH_MD5(22, "TSK_HASH_MD5", //NON-NLS
                     NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskHashMd5.text")),
		TSK_HASH_SHA1(23, "TSK_HASH_SHA1", //NON-NLS
                      NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskHashSha1.text")),
		TSK_HASH_SHA2_256(24, "TSK_HASH_SHA2_256", //NON-NLS
                          NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskHashSha225.text")),
		TSK_HASH_SHA2_512(25, "TSK_HASH_SHA2_512", //NON-NLS
                          NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskHashSha2512.text")),
		TSK_TEXT(26, "TSK_TEXT",  //NON-NLS
                 NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskText.text")),
		TSK_TEXT_FILE(27, "TSK_TEXT_FILE", //NON-NLS
                      NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskTextFile.text")),
		TSK_TEXT_LANGUAGE(28, "TSK_TEXT_LANGUAGE", //NON-NLS
                          NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskTextLanguage.text")),
		TSK_ENTROPY(29, "TSK_ENTROPY", //NON-NLS
                    NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskEntropy.text")),
		TSK_HASHSET_NAME(30, "TSK_HASHSET_NAME", //NON-NLS
                         NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskHashsetName.text")), // @@@ Deprecated
		/*
		 * @deprecated Use TSK_INTERSTING_FILE_HIT artifact instead.
		 */
		@Deprecated
		TSK_INTERESTING_FILE(31, "TSK_INTERESTING_FILE", //NON-NLS
                             NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskInterestingFile.text")), // @@@ Deprecated
		TSK_REFERRER(32, "TSK_REFERRER", //NON-NLS
                     NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskReferrer.text")),
		TSK_DATETIME_ACCESSED(33, "TSK_DATETIME_ACCESSED", //NON-NLS
                              NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskDateTimeAccessed.text")),
		TSK_IP_ADDRESS(34, "TSK_IP_ADDRESS", //NON-NLS
                       NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskIpAddress.text")),
		TSK_PHONE_NUMBER(35, "TSK_PHONE_NUMBER", //NON-NLS
                         NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskPhoneNumber.text")),
		TSK_PATH_ID(36, "TSK_PATH_ID",  //NON-NLS
                    NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskPathId.text")),
		TSK_SET_NAME(37, "TSK_SET_NAME", //NON-NLS
                     NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskSetName.text")),
		@Deprecated
		TSK_ENCRYPTION_DETECTED(38, "TSK_ENCRYPTION_DETECTED", //NON-NLS
                                NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskEncryptionDetected.text")),
		TSK_MALWARE_DETECTED(39, "TSK_MALWARE_DETECTED", //NON-NLS
                             NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskMalwareDetected.text")),
		TSK_STEG_DETECTED(40, "TSK_STEG_DETECTED", //NON-NLS
                          NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskStegDetected.text")),
		TSK_EMAIL_TO(41, "TSK_EMAIL_TO", //NON-NLS
                     NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskEmailTo.text")),
		TSK_EMAIL_CC(42, "TSK_EMAIL_CC", //NON-NLS
                     NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskEmailCc.text")),
		TSK_EMAIL_BCC(43, "TSK_EMAIL_BCC", //NON-NLS
                      NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskEmailBcc.text")),
		TSK_EMAIL_FROM(44, "TSK_EMAIL_FROM", //NON-NLS
                       NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskEmailFrom.text")),
		TSK_EMAIL_CONTENT_PLAIN(45, "TSK_EMAIL_CONTENT_PLAIN",  //NON-NLS
                                NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskEmailContentPlain.text")),
		TSK_EMAIL_CONTENT_HTML(46, "TSK_EMAIL_CONTENT_HTML", //NON-NLS
                               NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskEmailContentHtml.text")),
		TSK_EMAIL_CONTENT_RTF(47, "TSK_EMAIL_CONTENT_RTF", //NON-NLS
                              NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskEmailContentRtf.text")),
		TSK_MSG_ID(48, "TSK_MSG_ID",  //NON-NLS
                   NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskMsgId.text")),
		TSK_MSG_REPLY_ID(49, "TSK_MSG_REPLY_ID", //NON-NLS
                         NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskMsgReplyId.text")),
		TSK_DATETIME_RCVD(50, "TSK_DATETIME_RCVD", //NON-NLS
                          NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskDateTimeRcvd.text")),
		TSK_DATETIME_SENT(51, "TSK_DATETIME_SENT", //NON-NLS
                          NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskDateTimeSent.text")),
		TSK_SUBJECT(52, "TSK_SUBJECT", //NON-NLS
                    NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskSubject.text")),
		TSK_TITLE(53, "TSK_TITLE", //NON-NLS
                  NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskTitle.text")),
		TSK_GEO_LATITUDE(54, "TSK_GEO_LATITUDE", //NON-NLS
                         NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskGeoLatitude.text")),
		TSK_GEO_LONGITUDE(55, "TSK_GEO_LONGITUDE", //NON-NLS
                          NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskGeoLongitude.text")),
		TSK_GEO_VELOCITY(56, "TSK_GEO_VELOCITY", //NON-NLS
                         NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskGeoVelocity.text")),
		TSK_GEO_ALTITUDE(57, "TSK_GEO_ALTITUDE", //NON-NLS
                         NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskGeoAltitude.text")),
		TSK_GEO_BEARING(58, "TSK_GEO_BEARING", //NON-NLS
                        NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskGeoBearing.text")),
		TSK_GEO_HPRECISION(59, "TSK_GEO_HPRECISION", //NON-NLS
                           NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskGeoHPrecision.text")),
		TSK_GEO_VPRECISION(60, "TSK_GEO_VPRECISION", //NON-NLS
                           NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskGeoVPrecision.text")),
		TSK_GEO_MAPDATUM(61, "TSK_GEO_MAPDATUM", //NON-NLS
                         NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskGeoMapDatum.text")),
		TSK_FILE_TYPE_SIG(62, "TSK_FILE_TYPE_SIG", //NON-NLS
                          NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskFileTypeSig.text")),
		TSK_FILE_TYPE_EXT(63, "TSK_FILE_TYPE_EXT", //NON-NLS
                          NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskFileTypeExt.text")),
		TSK_TAGGED_ARTIFACT(64, "TSK_TAGGED_ARTIFACT", //NON-NLS
                            NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskTaggedArtifact.text")),
		TSK_TAG_NAME(65, "TSK_TAG_NAME", //NON-NLS
                     NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskTagName.text")),
		TSK_COMMENT(66, "TSK_COMMENT", //NON-NLS
                    NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskComment.text")),
		TSK_URL_DECODED(67, "TSK_URL_DECODED", //NON-NLS
                        NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskUrlDecoded.text")),
		TSK_DATETIME_CREATED(68, "TSK_DATETIME_CREATED", //NON-NLS
                             NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskDateTimeCreated.text")),
		TSK_DATETIME_MODIFIED(69, "TSK_DATETIME_MODIFIED", //NON-NLS
                              NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskDateTimeModified.text")),
		TSK_PROCESSOR_ARCHITECTURE(70, "TSK_PROCESSOR_ARCHITECTURE", //NON-NLS
                                   NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskProcessorArchitecture.text")),
		TSK_VERSION(71, "TSK_VERSION", //NON-NLS
                    NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskVersion.text")),
		TSK_USER_ID(72, "TSK_USER_ID", //NON-NLS
                    NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskUserId.text")),
		TSK_DESCRIPTION(73, "TSK_DESCRIPTION", //NON-NLS
                        NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskDescription.text")),
		TSK_MESSAGE_TYPE(74, "TSK_MESSAGE_TYPE", //NON-NLS
                         NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskMessageType.text")),	// SMS or MMS or IM ...
		TSK_PHONE_NUMBER_HOME(75, "TSK_PHONE_NUMBER_HOME", //NON-NLS
                              NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskPhoneNumberHome.text")),
		TSK_PHONE_NUMBER_OFFICE(76, "TSK_PHONE_NUMBER_OFFICE", //NON-NLS
                                NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskPhoneNumberOffice.text")),
		TSK_PHONE_NUMBER_MOBILE(77, "TSK_PHONE_NUMBER_MOBILE", //NON-NLS
                                NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskPhoneNumberMobile.text")),
		TSK_PHONE_NUMBER_FROM(78, "TSK_PHONE_NUMBER_FROM", //NON-NLS
                              NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskPhoneNumberFrom.text")),
		TSK_PHONE_NUMBER_TO(79, "TSK_PHONE_NUMBER_TO", //NON-NLS
                            NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskPhoneNumberTo.text")),
		TSK_DIRECTION(80, "TSK_DIRECTION", //NON-NLS
                      NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskDirection.text")), // Msg/Call direction: incoming, outgoing
		TSK_EMAIL_HOME(81, "TSK_EMAIL_HOME", //NON-NLS
                       NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskEmailHome.text")),
		TSK_EMAIL_OFFICE(82, "TSK_EMAIL_OFFICE", //NON-NLS
                         NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskEmailOffice.text")),
		TSK_DATETIME_START(83, "TSK_DATETIME_START", //NON-NLS
                           NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskDateTimeStart.text")),	// start time of an event - call log, Calendar entry
		TSK_DATETIME_END(84, "TSK_DATETIME_END", //NON-NLS
                         NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskDateTimeEnd.text")),	// end time of an event - call log, Calendar entry
		TSK_CALENDAR_ENTRY_TYPE(85, "TSK_CALENDAR_ENTRY_TYPE", //NON-NLS
                                NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskCalendarEntryType.text")),	// meeting, task,
		TSK_LOCATION(86, "TSK_LOCATION", //NON-NLS
                     NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskLocation.text")),	// Location string associated with an event - Conf Room Name, Address ....
		TSK_SHORTCUT(87, "TSK_SHORTCUT", //NON-NLS
                     NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskShortcut.text")),	// Short Cut string - short code or dial string for Speed dial, a URL short cut - e.g. bitly string, Windows Desktop Short cut name etc.
		TSK_DEVICE_NAME(88, "TSK_DEVICE_NAME", //NON-NLS
                        NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskDeviceName.text")),	// device name - a user assigned (usually) device name - such as "Joe's computer", "bob_win8", "BT Headset"
		TSK_CATEGORY(89, "TSK_CATEGORY", //NON-NLS
                     NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskCategory.text")),	// category/type, possible value set varies by the artifact
		TSK_EMAIL_REPLYTO(90, "TSK_EMAIL_REPLYTO", //NON-NLS
                          NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskEmailReplyTo.text")),	// ReplyTo address
		TSK_SERVER_NAME(91, "TSK_SERVER_NAME", //NON-NLS
                        NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskServerName.text")),	// server name, e.g. a mail server name - "smtp.google.com", a DNS server name...
		TSK_COUNT(92, "TSK_COUNT", //NON-NLS
                  NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskCount.text")), // Count related to the artifact
		TSK_MIN_COUNT(93, "TSK_MIN_COUNT", //NON-NLS
                      NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskMinCount.text")), // Minimum number/count
		TSK_PATH_SOURCE(94, "TSK_PATH_SOURCE", //NON-NLS
                        NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskPathSource.text")), // Path to a source file related to the artifact
		TSK_PERMISSIONS(95, "TSK_PERMISSIONS", //NON-NLS
                        NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskPermissions.text")), // Permissions
		TSK_ASSOCIATED_ARTIFACT(96, "TSK_ASSOCIATED_ARTIFACT",  //NON-NLS
                                NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskAssociatedArtifact.text")), // Artifact ID of a related artifact
		TSK_ISDELETED(97, "TSK_ISDELETED", //NON-NLS
                      NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskIsDeleted.text")), // boolean to indicate that the artifact is recovered fom deleted content
        TSK_GEO_LATITUDE_START(98, "TSK_GEO_LATITUDE_START", //NON-NLS
                               NbBundle.getMessage(BlackboardArtifact.class, "BlackboardAttribute.tskGeoLatitudeStart.text")), // Starting location lattitude
        TSK_GEO_LATITUDE_END(99, "TSK_GEO_LATITUDE_END", //NON-NLS
                             NbBundle.getMessage(BlackboardAttribute.class, "BlackboardAttribute.tskGeoLatitudeEnd.text")), // Ending location lattitude
        TSK_GEO_LONGITUDE_START(100, "TSK_GEO_LONGITUDE_START", //NON-NLS
                                NbBundle.getMessage(BlackboardAttribute.class, "BlackboardAttribute.tskGeoLongitudeStart.text")), // Starting location longitude
        TSK_GEO_LONGITUDE_END(101, "TSK_GEO_LONGITUDE_END", //NON-NLS
                              NbBundle.getMessage(BlackboardAttribute.class, "BlackboardAttribute.tskGeoLongitudeEnd.text")), //Ending Location longitude

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
	 * @param Case the case that can be used to make calls into the blackboard
	 * db
	 */
	protected BlackboardAttribute(long artifactID, int attributeTypeID, String moduleName, String context,
			TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE valueType, int valueInt, long valueLong, double valueDouble,
			String valueString, byte[] valueBytes, SleuthkitCase Case) {

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
		this.Case = Case;
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
	 * @param context extra information about the attribute
	 * @param valueBytes the value
	 */
	public BlackboardAttribute(int attributeTypeID, String moduleName, String context,
			byte[] valueBytes) {
		this.artifactID = 0;
		this.attributeTypeID = attributeTypeID;
		this.moduleName = moduleName;
		this.context = context;
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
		return "BlackboardAttribute{" + "artifactID=" + artifactID + ", attributeTypeID=" + attributeTypeID + ", moduleName=" + moduleName + ", context=" + context + ", valueType=" + valueType + ", valueInt=" + valueInt + ", valueLong=" + valueLong + ", valueDouble=" + valueDouble + ", valueString=" + valueString + ", valueBytes=" + valueBytes + ", Case=" + Case + '}'; //NON-NLS
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
		return Case.getAttrTypeString(attributeTypeID);
	}

	/**
	 * Get the attribute type display name
	 *
	 * @return type display name
	 */
	public String getAttributeTypeDisplayName() throws TskCoreException {
		return Case.getAttrTypeDisplayName(attributeTypeID);
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
		return Case.getBlackboardArtifact(artifactID);
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
	 * @param Case case handle to associated with this attribute
	 */
	protected void setCase(SleuthkitCase Case) {
		this.Case = Case;
	}
}
