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
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

/**
 *
 * @author alawrence
 */
public class BlackboardAttribute {
	private long artifactID;
	private String attributeTypeName;
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
	 * Attribute value type (indicates what value type is stored in an attribute)
	 */
	public enum TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE {
		STRING(0, "String"),	   ///< string
		INTEGER(1, "Integer"),   ///< int
		LONG(2, "Long"),            ///< long
		DOUBLE(3, "Double"),      ///< double
		BYTE(4, "Byte");      ///< byte

		private long type;
		private String label;

		private TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE(long type, String label){
			this.type = type;
			this.label = label;
		}

		/**
		 * get the type id for this enum
		 */
		public long getType(){
			return type;
		}
		
		/**
		 * get the label string for this enum
		 */
		public String getLabel() {
			return this.label;
		}
		
		/**
		 * get the enum for the given type id
		 * @param type type id
		 * @return enum
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
	 * Built in attribute types
	 */
	public enum ATTRIBUTE_TYPE {
		TSK_URL ("TSK_URL"),
		TSK_DATETIME ("TSK_DATETIME"),
		TSK_NAME ("TSK_NAME"),
		TSK_PROG_NAME ("TSK_PROG_NAME"),
		TSK_WEB_BOOKMARK ("TSK_WEB_BOOKMARK"),
		TSK_VALUE ("TSK_VALUE"),
		TSK_FLAG ("TSK_FLAG"),
		TSK_PATH ("TSK_PATH"),
		TSK_GEO ("TSK_GEO"),
		TSK_KEYWORD ("TSK_KEYWORD"),
		TSK_KEYWORD_REGEXP ("TSK_KEYWORD_REGEXP"),
		TSK_KEYWORD_PREVIEW  ("TSK_KEYWORD_PREVIEW"),
		TSK_KEYWORD_SET  ("TSK_KEYWORD_SET"),
		TSK_USERNAME  ("TSK_USERNAME"),
        TSK_DOMAIN ("TSK_DOMAIN"),
        TSK_PASSWORD ("TSK_PASSWORD"),
        TSK_NAME_PERSON ("TSK_NAME_PERSON"),
        TSK_DEVICE_MODEL ("TSK_DEVICE_MODEL"),
        TSK_DEVICE_MAKE ("TSK_DEVICE_MAKE"),
        TSK_DEVICE_ID ("TSK_DEVICE_ID"),
        TSK_EMAIL ("TSK_EMAIL"),
        TSK_HASH_HD5 ("TSK_HASH_MD5"),
        TSK_HASH_SHA1 ("TSK_HASH_SHA1"),
        TSK_HASH_SHA2_256 ("TSK_HASH_SHA2_256"),
        TSK_HASH_SHA2_512 ("TSK_HASH_SHA2_512"),
        TSK_TEXT ("TSK_TEXT"),
        TSK_TEXT_FILE ("TSK_TEXT_FILE"),
        TSK_TEXT_LANGUAGE ("TSK_TEXT_LANGUAGE"),
        TSK_ENTROPY ("TSK_ENTROPY"),
        TSK_HASHSET_NAME ("TSK_HASHSET_NAME");


		private String label;
		private int typeID;

		private ATTRIBUTE_TYPE(String label){
			this.label = label;
		}
		
		/**
		 * get label string
		 * @return label string
		 */
		public String getLabel() {
			return this.label;
		}
		
		/**
		 * get type id
		 * @return type id
		 */
		public int getTypeID(){
			return this.typeID;
		}
		
		/**
		 * set the type id (this should only be used by sleuthkitCase)
		 * @param typeID type id
		 */
		protected void setTypeID(int typeID){
			this.typeID = typeID;
		}
		
		/**
		 * get the attribute enum for the given label
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
	}
	
	/**
	 * constructor for a blackboard attribute. should only be used by sleuthkitCase
	 * @param artifactID artifact id for this attribute
	 * @param attributeTypeName type name
	 * @param attributeTypeID type id
	 * @param moduleName module that created this attribute
	 * @param context extra information about this name value pair
	 * @param valueType type of value to be stored
	 * @param valueInt value if it is an int
	 * @param valueLong value if it is a long
	 * @param valueDouble value if it is a double
	 * @param valueString value if it is a string
	 * @param valueBytes value if it is a byte array
	 * @param Case the case that can be used to make calls into the blackboard db
	 */
	protected BlackboardAttribute(long artifactID, String attributeTypeName, int attributeTypeID, String moduleName, String context,
		TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE valueType, int valueInt, long valueLong, double valueDouble, 
		String valueString, byte[] valueBytes, SleuthkitCase Case){
		
		this.artifactID = artifactID;
		this.attributeTypeName = attributeTypeName;
		this.attributeTypeID = attributeTypeID;
		this.moduleName = moduleName;
		this.context = context;
		this.valueType = valueType;
		this.valueInt = valueInt;
		this.valueLong = valueLong;
		this.valueDouble = valueDouble;
		this.valueString = valueString;
		this.valueBytes = valueBytes;
		this.Case = Case;
	}
	
	/**
	 * get the artifact id 
	 * @return artifact id
	 */
	public long getArtifactID(){
		return artifactID;
	}
	/**
	 * get the type name string
	 * @return type name string
	 */
	public String getAttributeTypeName(){
		return attributeTypeName;
	}
	/**
	 * get the attribute type id
	 * @return type id
	 */
	public int getAttributeTypeID(){
		return attributeTypeID;
	}
	/**
	 * get the value type (this should be used to identify the type of value and call
	 * the right value get method)
	 * @return calue type
	 */
	public TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE getValueType(){
		return valueType;
	}
	/**
	 * get the value if it is an int
	 * @return value
	 */
	public int getValueInt(){
		return valueInt;
	}
	/**
	 * get value if it is a long
	 * @return value
	 */
	public long getValueLong(){
		return valueLong;
	}
	/**
	 * get value if it is a double
	 * @return value
	 */
	public double getValueDouble(){
		return valueDouble;
	}
	/**
	 * get value if it is a string
	 * @return value
	 */
	public String getValueString(){
		return valueString;
	}
	/**
	 * get value if it is a byte array
	 * @return value
	 */
	public byte[] getValueBytes(){
		return valueBytes;
	}
	/**
	 * get module name
	 * @return name
	 */
	public String getModuleName(){
		return moduleName;
	}
	/**
	 * get context
	 * @return context
	 */
	public String getContext(){
		return context;
	}
	/**
	 * get the artifact that this is associated (which can be used to find the associated
	 * file
	 * @return artifact
	 * @throws TskException
	 */
	public BlackboardArtifact getParentArtifact() throws TskException{
		return Case.getBlackboardArtifact(artifactID);
	}
}
