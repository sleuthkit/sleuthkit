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

		STRING(0, "String"), ///< string
		INTEGER(1, "Integer"), ///< int
		LONG(2, "Long"), ///< long
		DOUBLE(3, "Double"), ///< double
		BYTE(4, "Byte");	  ///< byte
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

		TSK_URL(1, "TSK_URL", "URL"),
		TSK_DATETIME(2, "TSK_DATETIME", "Date/Time"),
		TSK_NAME(3, "TSK_NAME", "Name"),
		TSK_PROG_NAME(4, "TSK_PROG_NAME", "Program Name"),
		TSK_VALUE(6, "TSK_VALUE", "Value"),
		TSK_FLAG(7, "TSK_FLAG", "Flag"),
		TSK_PATH(8, "TSK_PATH", "Path"),
		TSK_KEYWORD(10, "TSK_KEYWORD", "Keyword"),
		TSK_KEYWORD_REGEXP(11, "TSK_KEYWORD_REGEXP", "Keyword Regular Expression"),
		TSK_KEYWORD_PREVIEW(12, "TSK_KEYWORD_PREVIEW", "Keyword Preview"),
		TSK_KEYWORD_SET(13, "TSK_KEYWORD_SET", "Keyword Set"), // @@@ Deprecated
		TSK_USER_NAME(14, "TSK_USER_NAME", "Username"),
		TSK_DOMAIN(15, "TSK_DOMAIN", "Domain"),
		TSK_PASSWORD(16, "TSK_PASSWORD", "Password"),
		TSK_NAME_PERSON(17, "TSK_NAME_PERSON", "Person Name"),
		TSK_DEVICE_MODEL(18, "TSK_DEVICE_MODEL", "Device Model"),
		TSK_DEVICE_MAKE(19, "TSK_DEVICE_MAKE", "Device Make"),
		TSK_DEVICE_ID(20, "TSK_DEVICE_ID", "Device ID"),
		TSK_EMAIL(21, "TSK_EMAIL", "Email"),
		TSK_HASH_MD5(22, "TSK_HASH_MD5", "MD5 Hash"),
		TSK_HASH_SHA1(23, "TSK_HASH_SHA1", "SHA1 Hash"),
		TSK_HASH_SHA2_256(24, "TSK_HASH_SHA2_256", "SHA2-256 Hash"),
		TSK_HASH_SHA2_512(25, "TSK_HASH_SHA2_512", "SHA2-512 Hash"),
		TSK_TEXT(26, "TSK_TEXT", "Text"),
		TSK_TEXT_FILE(27, "TSK_TEXT_FILE", "Text File"),
		TSK_TEXT_LANGUAGE(28, "TSK_TEXT_LANGUAGE", "Text Language"),
		TSK_ENTROPY(29, "TSK_ENTROPY", "Entropy"),
		TSK_HASHSET_NAME(30, "TSK_HASHSET_NAME", "Hashset Name"), // @@@ Deprecated
		TSK_INTERESTING_FILE(31, "TSK_INTERESTING_FILE", "Interesting File"),
		TSK_REFERRER(32, "TSK_REFERRER", "Referrer URL"),
		TSK_DATETIME_ACCESSED(33, "TSK_DATETIME_ACCESSED", "Date Accessed"),
		TSK_IP_ADDRESS(34, "TSK_IP_ADDRESS", "IP Address"),
		TSK_PHONE_NUMBER(35, "TSK_PHONE_NUMBER", "Phone Number"),
		TSK_PATH_ID(36, "TSK_PATH_ID", "Path ID"),
		TSK_SET_NAME(37, "TSK_SET_NAME", "Set Name"),
		TSK_ENCRYPTION_DETECTED(38, "TSK_ENCRYPTION_DETECTED", "Encryption Detected"),
		TSK_MALWARE_DETECTED(39, "TSK_MALWARE_DETECTED", "Malware Detected"),
		TSK_STEG_DETECTED(40, "TSK_STEG_DETECTED", "Steganography Detected"),
		TSK_EMAIL_TO(41, "TSK_EMAIL_TO", "E-Mail To"),
		TSK_EMAIL_CC(42, "TSK_EMAIL_CC", "E-Mail CC"),
		TSK_EMAIL_BCC(43, "TSK_EMAIL_BCC", "E-Mail BCC"),
		TSK_EMAIL_FROM(44, "TSK_EMAIL_FROM", "E-Mail From"),
		TSK_EMAIL_CONTENT_PLAIN(45, "TSK_EMAIL_CONTENT_PLAIN", "Message (Plaintext)"),
		TSK_EMAIL_CONTENT_HTML(46, "TSK_EMAIL_CONTENT_HTML", "Message (HTML)"),
		TSK_EMAIL_CONTENT_RTF(47, "TSK_EMAIL_CONTENT_RTF", "Message (RTF)"),
		TSK_MSG_ID(48, "TSK_MSG_ID", "Message ID"),
		TSK_MSG_REPLY_ID(49, "TSK_MSG_REPLY_ID", "Message Reply ID"),
		TSK_DATETIME_RCVD(50, "TSK_DATETIME_RCVD", "Date Received"),
		TSK_DATETIME_SENT(51, "TSK_DATETIME_SENT", "Date Sent"),
		TSK_SUBJECT(52, "TSK_SUBJECT", "Subject"),
		TSK_TITLE(53, "TSK_TITLE", "Title"),
		TSK_GEO_LATITUDE(54, "TSK_GEO_LATITUDE", "Latitude"),
		TSK_GEO_LONGITUDE(55, "TSK_GEO_LONGITUDE", "Longitude"),
		TSK_GEO_VELOCITY(56, "TSK_GEO_VELOCITY", "Velocity"),
		TSK_GEO_ALTITUDE(57, "TSK_GEO_ALTITUDE", "Altitude"),
		TSK_GEO_BEARING(58, "TSK_GEO_BEARING", "Bearing"),
		TSK_GEO_HPRECISION(59, "TSK_GEO_HPRECISION", "Horizontal Precision"),
		TSK_GEO_VPRECISION(60, "TSK_GEO_VPRECISION", "Vertical Precision"),
		TSK_GEO_MAPDATUM(61, "TSK_GEO_MAPDATUM", "Map Datum"),
		TSK_FILE_TYPE_SIG(62, "TSK_FILE_TYPE_SIG", "File Type (signature)"),
		TSK_FILE_TYPE_EXT(63, "TSK_FILE_TYPE_EXT", "File Type (extension)"),
		TSK_TAGGED_ARTIFACT(64, "TSK_TAGGED_ARTIFACT", "Tagged Result"),
		TSK_TAG_NAME(65, "TSK_TAG_NAME", "Tag Name"),
		TSK_COMMENT(66, "TSK_COMMENT", "Comment"),
		TSK_URL_DECODED(67, "TSK_URL_DECODED", "Decoded URL"),
		TSK_DATETIME_CREATED(68, "TSK_DATETIME_CREATED", "Date Created"),
		TSK_DATETIME_MODIFIED(69, "TSK_DATETIME_MODIFIED", "Date Modified"),
		TSK_PROCESSOR_ARCHITECTURE(70, "TSK_PROCESSOR_ARCHITECTURE", "Processor Architecture"),
		TSK_VERSION(71, "TSK_VERSION", "Version"),
		TSK_USER_ID(72, "TSK_USER_ID", "User ID"),
		TSK_DESCRIPTION(73, "TSK_DESCRIPTION", "Description"),
		TSK_MESSAGE_TYPE(74, "TSK_MESSAGE_TYPE", "Message Type"),	// SMS or MMS or IM ...
		TSK_PHONE_NUMBER_HOME(75, "TSK_PHONE_NUMBER_HOME", "Phone Number (Home)"),
		TSK_PHONE_NUMBER_OFFICE(76, "TSK_PHONE_NUMBER_OFFICE", "Phone Number (Office)"),
		TSK_PHONE_NUMBER_MOBILE(77, "TSK_PHONE_NUMBER_MOBILE", "Phone Number (Mobile)"),
		TSK_PHONE_NUMBER_FROM(78, "TSK_PHONE_NUMBER_FROM", "From Phone Number"),
		TSK_PHONE_NUMBER_TO(79, "TSK_PHONE_NUMBER_TO", "To Phone Number"),
		TSK_DIRECTION(80, "TSK_DIRECTION", "Direction"), // Msg/Call direction: incoming, outgoing
		TSK_EMAIL_HOME(81, "TSK_EMAIL_HOME", "Email (Home)"),
		TSK_EMAIL_OFFICE(82, "TSK_EMAIL_OFFICE", "Email (Office)"),
		TSK_DATETIME_START(83, "TSK_DATETIME_START", "Start Date/Time"),	// start time of an event - call log, Calendar entry
		TSK_DATETIME_END(84, "TSK_DATETIME_END", "End Date/Time"),	// end time of an event - call log, Calendar entry
		TSK_CALENDAR_ENTRY_TYPE(85, "TSK_CALENDAR_ENTRY_TYPE", "Calendar Entry Type"),	// meeting, task, 
		TSK_LOCATION(86, "TSK_LOCATION", "Location"),	// Location string associated with an event - Conf Room Name, Address ....
		TSK_SHORTCUT(87, "TSK_SHORTCUT", "Short Cut"),	// Short Cut string - short code or dial string for Speed dial, a URL short cut - e.g. bitly string, Windows Desktop Short cut name etc.
		TSK_DEVICE_NAME(88, "TSK_DEVICE_NAME", "Device Name"),	// device name - a user assigned (usually) device name - such as "Joe's computer", "bob_win8", "BT Headset"
		TSK_CATEGORY(89, "TSK_CATEGORY", "Category"),	// category/type, possible value set varies by the artifact
		TSK_EMAIL_REPLYTO(90, "TSK_EMAIL_REPLYTO", "ReplyTo Address"),	// ReplyTo address
		TSK_SERVER_NAME(91, "TSK_SERVER_NAME", "Server Name"),	// server name, e.g. a mail server name - "smtp.google.com", a DNS server name...
		
		
		
		
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
		return "BlackboardAttribute{" + "artifactID=" + artifactID + ", attributeTypeID=" + attributeTypeID + ", moduleName=" + moduleName + ", context=" + context + ", valueType=" + valueType + ", valueInt=" + valueInt + ", valueLong=" + valueLong + ", valueDouble=" + valueDouble + ", valueString=" + valueString + ", valueBytes=" + valueBytes + ", Case=" + Case + '}';
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
