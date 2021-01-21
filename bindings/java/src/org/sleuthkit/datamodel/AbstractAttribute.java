/*
 * Sleuth Kit Data Model
 *
 * Copyright 2021 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import java.util.Arrays;
import java.util.Objects;

/**
 * Attributes are a name-value pairs. Abstract Attribute provides the base
 * functionality for a name value pair with type safety (analogous to a C union)
 *
 */
abstract class AbstractAttribute {

	private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray(); 

	private BlackboardAttribute.Type attributeType;

	private final int valueInt;
	private final long valueLong;
	private final double valueDouble;
	private final String valueString;
	private final byte[] valueBytes;

	private SleuthkitCase sleuthkitCase;

	private long attributeOwnerId;

	
	/**
	 * Constructs an attribute with an integer value. The attribute should be
	 * added to an appropriate artifact.
	 *
	 * @param attributeType The attribute type.
	 * @param valueInt      The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER.
	 */
	public AbstractAttribute(BlackboardAttribute.Type attributeType, int valueInt) {
		if (attributeType.getValueType() != BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER) {
			throw new IllegalArgumentException("Type mismatched with value type");
		}
		this.attributeOwnerId = 0;
		this.attributeType = attributeType;
		this.valueInt = valueInt;
		this.valueLong = 0;
		this.valueDouble = 0;
		this.valueString = "";
		this.valueBytes = new byte[0];
	}


	/**
	 * Constructs an attribute with a long/datetime value. The attribute should
	 * be added to an appropriate artifact.
	 *
	 * @param attributeType The attribute type.
	 * @param valueLong     The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  standard attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG
	 *                                  or
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME.
	 */
	public AbstractAttribute(BlackboardAttribute.Type attributeType, long valueLong) {
		if (attributeType.getValueType() != BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG
				&& attributeType.getValueType() != BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME) {
			throw new IllegalArgumentException("Type mismatched with value type");
		}
		this.attributeOwnerId = 0;
		this.attributeType = attributeType;
		this.valueInt = 0;
		this.valueLong = valueLong;
		this.valueDouble = 0;
		this.valueString = "";
		this.valueBytes = new byte[0];
	}


	/**
	 * Constructs an attribute with a double value. The attribute should be
	 * added to an appropriate artifact.
	 *
	 * @param attributeType The attribute type.
	 * @param valueDouble   The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE.
	 */
	public AbstractAttribute(BlackboardAttribute.Type attributeType, double valueDouble) {
		if (attributeType.getValueType() != BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE) {
			throw new IllegalArgumentException("Type mismatched with value type");
		}
		this.attributeOwnerId = 0;
		this.attributeType = attributeType;
		this.valueInt = 0;
		this.valueLong = 0;
		this.valueDouble = valueDouble;
		this.valueString = "";
		this.valueBytes = new byte[0];
	}


	/**
	 * Constructs an attribute with a string value. The attribute should be
	 * added to an appropriate artifact.
	 *
	 * @param attributeType The attribute type.
	 * @param valueString   The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING.
	 */
	public AbstractAttribute(BlackboardAttribute.Type attributeType, String valueString) {
		if (attributeType.getValueType() != BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING
				&& attributeType.getValueType() != BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.JSON) {
			throw new IllegalArgumentException("Type mismatched with value type");
		}
		this.attributeOwnerId = 0;
		this.attributeType = attributeType;
		this.valueInt = 0;
		this.valueLong = 0;
		this.valueDouble = 0;
		if (valueString == null) {
			this.valueString = "";
		} else {
			this.valueString = replaceNulls(valueString).trim();
		}
		this.valueBytes = new byte[0];
	}


	/**
	 * Constructs an attribute with a byte array value. The attribute should be
	 * added to an appropriate artifact.
	 *
	 * @param attributeType The attribute type.
	 * @param valueBytes    The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE.
	 */
	public AbstractAttribute(BlackboardAttribute.Type attributeType, byte[] valueBytes) {
		if (attributeType.getValueType() != BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE) {
			throw new IllegalArgumentException("Type mismatched with value type");
		}
		this.attributeOwnerId = 0;
		this.attributeType = attributeType;
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
	 * Constructs an artifact attribute. To be used when creating an attribute
	 * based on a query of the blackboard _attributes table in the case
	 * database.
	 *
	 * @param attributeOwnerId The owner id for this attribute.
	 * @param attributeTypeID  The attribute type id. 
	 * @param valueType        The attribute value type.
	 * @param valueInt         The value from the the value_int32 column.
	 * @param valueLong        The value from the the value_int64 column.
	 * @param valueDouble      The value from the the value_double column.
	 * @param valueString      The value from the the value_text column.
	 * @param valueBytes       The value from the the value_byte column.
	 * @param sleuthkitCase    A reference to the SleuthkitCase object
	 *                         representing the case database.
	 */
	AbstractAttribute(long attributeOwnerId, BlackboardAttribute.Type attributeType,
			int valueInt, long valueLong, double valueDouble, String valueString, byte[] valueBytes,
			SleuthkitCase sleuthkitCase) {

		this.attributeOwnerId = attributeOwnerId;
		this.attributeType = attributeType;
		this.valueInt = valueInt;
		this.valueLong = valueLong;
		this.valueDouble = valueDouble;
		if (valueString == null) {
			this.valueString = "";
		} else {
			this.valueString = replaceNulls(valueString).trim();
		}
		if (valueBytes == null) {
			this.valueBytes = new byte[0];
		} else {
			this.valueBytes = valueBytes;
		}
		this.sleuthkitCase = sleuthkitCase;
	}

	/**
	 * Gets the attribute value as a string, formatted as required.
	 *
	 * @return The value as a string.
	 */
	public String getDisplayString() {
		switch (attributeType.getValueType()) {
			case STRING:
				return getValueString();
			case INTEGER:
				if (attributeType.getTypeID() == BlackboardAttribute.ATTRIBUTE_TYPE.TSK_READ_STATUS.getTypeID()) {
					if (getValueInt() == 0) {
						return "Unread";
					} else {
						return "Read";
					}
				}
				return Integer.toString(getValueInt());
			case LONG: 
				return Long.toString(getValueLong());
			case DOUBLE:
				return Double.toString(getValueDouble());
			case BYTE:
				return bytesToHexString(getValueBytes());
			case DATETIME: 
				// once we have TSK timezone, that should be used here.
				return TimeUtilities.epochToTime(getValueLong());
			case JSON: {
				return getValueString();
			}
		}
		return "";
	}

	/**
	 * Gets the type of this attribute.
	 *
	 * @return The attribute type.
	 */
	public BlackboardAttribute.Type getAttributeType() {
		return this.attributeType;
	}

	/**
	 * Gets the value type.
	 *
	 * @return The value type
	 */
	public BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE getValueType() {
		return attributeType.getValueType();
	}

	/**
	 * Gets the value of this attribute. The value is only valid if the
	 * attribute value type is TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER.
	 *
	 * @return The attribute value.
	 */
	public int getValueInt() {
		return valueInt;
	}

	/**
	 * Gets the value of this attribute. The value is only valid if the
	 * attribute value type is TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG.
	 *
	 * @return The attribute value.
	 */
	public long getValueLong() {
		return valueLong;
	}

	/**
	 * Gets the value of this attribute. The value is only valid if the
	 * attribute value type is TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE.
	 *
	 * @return The attribute value.
	 */
	public double getValueDouble() {
		return valueDouble;
	}

	/**
	 * Gets the value of this attribute. The value is only valid if the
	 * attribute value type is TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING or
	 * TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.JSON.
	 *
	 * @return The attribute value.
	 */
	public String getValueString() {
		return valueString;
	}

	/**
	 * Gets the value of this attribute. The value is only valid if the
	 * attribute value type is TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE.
	 *
	 * @return The attribute value.
	 */
	public byte[] getValueBytes() {
		return Arrays.copyOf(valueBytes, valueBytes.length);
	}

	/**
	 * Gets the owner Id of this attribute. An owner is defined as the Object
	 * to which this attribute is associated with.
	 * Eg: For a file Attribute, the owner id would be the file object id.
	 *
	 * Each implementation is expected to give a more specific name. 
	 *
	 * @return
	 */
	long getAttributeOwnerId() {
		return this.attributeOwnerId;
	}

	SleuthkitCase getCaseDatabase() {
		return this.sleuthkitCase;
	}

	/**
	 * Sets the reference to the SleuthkitCase object that represents the case
	 * database.
	 *
	 * @param sleuthkitCase A reference to a SleuthkitCase object.
	 */
	void setCaseDatabase(SleuthkitCase sleuthkitCase) {
		this.sleuthkitCase = sleuthkitCase;
	}

	/**
	 * Sets the owner id for this attribute.
	 *
	 * @param attributeOwnerId The attribute owner id.
	 */
	void setAttributeOwnerId(long attributeOwnerId) {
		this.attributeOwnerId = attributeOwnerId;
	}

 
	/**
	 * Converts a byte array to a string.
	 *
	 * @param bytes The byte array.
	 *
	 * @return The string.
	 */
	static String bytesToHexString(byte[] bytes) {
		// from http://stackoverflow.com/questions/9655181/convert-from-byte-array-to-hex-string-in-java
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = HEX_ARRAY[v >>> 4];
			hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
		}
		return new String(hexChars);
	}
	
	/**
	 * Replace all NUL characters in the string with the SUB character
	 *
	 * @param text The input string.
	 *
	 * @return The output string.
	 */
	final String replaceNulls(String text) {
		return text.replace((char) 0x00, (char) 0x1A);
	}


	boolean isAttributeEquals(Object that) {
		if (that instanceof AbstractAttribute) {
			AbstractAttribute other = (AbstractAttribute) that;
			Object[] thisObject = new Object[]{this.getAttributeType(), this.getValueInt(), this.getValueLong(), this.getValueDouble(),
				this.getValueString(), this.getValueBytes()};
			Object[] otherObject = new Object[]{other.getAttributeType(), other.getValueInt(), other.getValueLong(), other.getValueDouble(),
				other.getValueString(), other.getValueBytes()};

			return Objects.deepEquals(thisObject, otherObject);
		} else {
			return false;
		}
	}
}
