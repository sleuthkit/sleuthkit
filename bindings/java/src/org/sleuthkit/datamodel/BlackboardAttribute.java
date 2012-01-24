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

/**
 *
 * @author alawrence
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
	 * Attribute value type (indicates what value type is stored in an attribute)
	 */
	public enum TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE {
		STRING(0, "String"),	   ///< string
		INTEGER(1, "Integer"),   ///< int
		LONG(2, "Long"),			///< long
		DOUBLE(3, "Double"),	  ///< double
		BYTE(4, "Byte");	  ///< byte

		private long type;
		private String label;

		private TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE(long type, String label){
			this.type = type;
			this.label = label;
		}

		/**
		 * get the type id for this enum
		 * @return
		 */
		public long getType(){
			return type;
		}
		
		/**
		 * get the label string for this enum
		 * @return
		 */
		public String getLabel() {
			return this.label;
		}
		
		/**
		 * get the enum for the given type string
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
	public enum TSK_BLACKBOARD_ATTRIBUTE_TYPE {
		TSK_URL (1,"tsk_url"),
		TSK_DATETIME (2, "tsk_datetime"),
		TSK_NAME (3, "tsk_name"),
		TSK_PROG_NAME (4, "tsk_prog_name"),
		TSK_WEB_BOOKMARK (5, "tsk_web_bookmark"),
		TSK_VALUE (6, "tsk_value"),
		TSK_FLAG (7, "tsk_flag"),
		TSK_PATH (8, "tsk_path"),
		TSK_GEO (9, "tsk_geo"),
		TSK_KEYWORD (10, "tsk_keyword"),
		TSK_REGEXP (11, "tsk_regexp"),
		TSK_PREVIEW  (12, "tsk_preview"),
		TSK_KEYWORD_SET  (13, "tsk_set");

		private String label;
		private int typeID;

		private TSK_BLACKBOARD_ATTRIBUTE_TYPE(int typeID, String label){
			this.typeID = typeID;
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
		 * get the attribute enum for the given label
		 * @param label label string
		 * @return the enum value
		 */
		static public TSK_BLACKBOARD_ATTRIBUTE_TYPE fromLabel(String label) {
			for (TSK_BLACKBOARD_ATTRIBUTE_TYPE v : TSK_BLACKBOARD_ATTRIBUTE_TYPE.values()) {
				if (v.label.equals(label)) {
					return v;
				}
			}
			throw new IllegalArgumentException("No TSK_BLACKBOARD_ATTRIBUTE_TYPE matching type: " + label);
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
	protected BlackboardAttribute(long artifactID, int attributeTypeID, String moduleName, String context,
		TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE valueType, int valueInt, long valueLong, double valueDouble, 
		String valueString, byte[] valueBytes, SleuthkitCase Case){
		
		this.artifactID = artifactID;
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
	 * create a blackboard attribute that stores an int (creates an attribute that can be
	 * added to an artifact)
	 * @param attributeTypeID type of the attribute
	 * @param moduleName name of the module that is creating the attribute
	 * @param context extra information about the attribute
	 * @param valueInt the value
	 */
	public BlackboardAttribute(int attributeTypeID, String moduleName, String context,
		int valueInt){
		this.artifactID = 0;
		this.attributeTypeID = attributeTypeID;
		this.moduleName = moduleName;
		this.context = context;
		this.valueType = TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER;
		this.valueInt = valueInt;
		this.valueLong = 0;
		this.valueDouble = 0;
		this.valueString = "";
		this.valueBytes = new byte[0];
	}
	
	/**
	 * create a blackboard attribute that stores a long (creates an attribute that can be
	 * added to an artifact)
	 * @param attributeTypeID type of the attribute
	 * @param moduleName name of the module that is creating the attribute
	 * @param context extra information about the attribute
	 * @param valueLong the value
	 */
	public BlackboardAttribute(int attributeTypeID, String moduleName, String context,
		long valueLong){
		this.artifactID = 0;
		this.attributeTypeID = attributeTypeID;
		this.moduleName = moduleName;
		this.context = context;
		this.valueType = TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG;
		this.valueInt = 0;
		this.valueLong = valueLong;
		this.valueDouble = 0;
		this.valueString = "";
		this.valueBytes = new byte[0];
		
	}
	
	/**
	 * create a blackboard attribute that stores a double (creates an attribute that can be
	 * added to an artifact)
	 * @param attributeTypeID type of the attribute
	 * @param moduleName name of the module that is creating the attribute
	 * @param context extra information about the attribute
	 * @param valueDouble the value
	 */
	public BlackboardAttribute(int attributeTypeID, String moduleName, String context,
		double valueDouble){
		this.artifactID = 0;
		this.attributeTypeID = attributeTypeID;
		this.moduleName = moduleName;
		this.context = context;
		this.valueType = TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER;
		this.valueInt = 0;
		this.valueLong = 0;
		this.valueDouble = valueDouble;
		this.valueString = "";
		this.valueBytes = new byte[0];
		
	}
	
	/**
	 * create a blackboard attribute that stores a string (creates an attribute that can be
	 * added to an artifact)
	 * @param attributeTypeID type of the attribute
	 * @param moduleName name of the module that is creating the attribute
	 * @param context extra information about the attribute
	 * @param valueString the value
	 */
	public BlackboardAttribute(int attributeTypeID, String moduleName, String context,
		String valueString){
		this.artifactID = 0;
		this.attributeTypeID = attributeTypeID;
		this.moduleName = moduleName;
		this.context = context;
		this.valueType = TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER;
		this.valueInt = 0;
		this.valueLong = 0;
		this.valueDouble = 0;
		this.valueString = valueString;
		this.valueBytes = new byte[0];
		
	}
	
	/**
	 * create a blackboard attribute that stores a byte array (creates an attribute that can be
	 * added to an artifact)
	 * @param attributeTypeID type of the attribute
	 * @param moduleName name of the module that is creating the attribute
	 * @param context extra information about the attribute
	 * @param valueBytes the value
	 */
	public BlackboardAttribute(int attributeTypeID, String moduleName, String context,
		byte[] valueBytes){
		this.artifactID = 0;
		this.attributeTypeID = attributeTypeID;
		this.moduleName = moduleName;
		this.context = context;
		this.valueType = TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER;
		this.valueInt = 0;
		this.valueLong = 0;
		this.valueDouble = 0;
		this.valueString = "";
		this.valueBytes = valueBytes;
		
	}
	
	/**
	 * get the artifact id 
	 * @return artifact id
	 */
	public long getArtifactID(){
		return artifactID;
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
	 * @return value type
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
	
	/**
	 * set the artifactID, this should only be used by sleuthkitCase
	 * @param artifactID artifactID
	 */
	protected void setArtifactID(long artifactID){
		this.artifactID = artifactID;
	}
	
	/**
	 * set the sleuthkitCase, this should only be used by sleuthkitCase
	 * @param Case case
	 */
	
	protected void setCase(SleuthkitCase Case){
		this.Case = Case;
	}
}
