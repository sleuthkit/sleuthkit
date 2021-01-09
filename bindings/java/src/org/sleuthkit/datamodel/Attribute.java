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
  
import com.google.common.base.MoreObjects;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.TimeZone;
import java.util.logging.Level;
import java.util.logging.Logger;
import static org.sleuthkit.datamodel.BlackboardAttribute.bytesToHexString;

/**
 *  
 * Attributes are a name-value pairs. The name is the type of the attribute, as
 * represented by the BlackboardAttribute.Type class. Standard attribute types
 * are specified by the ATTRIBUTE_TYPE enumeration. Custom attribute types may
 * be created by constructing a BlackboardAttribute.Type object and calling the
 * SleuthkitCase.addArtifactAttributeType method. 
 */
public class Attribute {
		
	private static final Logger LOGGER = Logger.getLogger(Attribute.class.getName());

	private BlackboardAttribute.Type attributeType;
	
	private final int valueInt;
	private final long valueLong;
	private final double valueDouble;
	private final String valueString;
	private final byte[] valueBytes;
	
	private SleuthkitCase sleuthkitCase;
	private String sources;

	// The parent data source is defined as being 
	// the data source of the parent artifact.
	private Long parentDataSourceID;
	
	private long attributeOwnerId;

 
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
	public Attribute(BlackboardAttribute.Type attributeType, String source, int valueInt) throws IllegalArgumentException {
		if (attributeType.getValueType() != BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER) {
			throw new IllegalArgumentException("Type mismatched with value type");
		}
		this.attributeOwnerId = 0;
		this.attributeType = attributeType;
		this.sources = replaceNulls(source);
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
	 * @param source        The source of this attribute.
	 * @param valueLong     The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  standard attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG
	 *                                  or
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME.
	 */
	public Attribute(BlackboardAttribute.Type attributeType, String source, long valueLong) throws IllegalArgumentException {
		if (attributeType.getValueType() != BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG
				&& attributeType.getValueType() != BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME) {
			throw new IllegalArgumentException("Type mismatched with value type");
		}
		this.attributeOwnerId = 0;
		this.attributeType = attributeType;
		this.sources = replaceNulls(source);
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
	 * @param source        The source of this attribute.
	 * @param valueDouble   The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE.
	 */
	public Attribute(BlackboardAttribute.Type attributeType, String source, double valueDouble) throws IllegalArgumentException {
		if (attributeType.getValueType() != BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE) {
			throw new IllegalArgumentException("Type mismatched with value type");
		}
		this.attributeOwnerId = 0;
		this.attributeType = attributeType;
		this.sources = replaceNulls(source);
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
	 * @param source        The source of this attribute.
	 * @param valueString   The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING.
	 */
	public Attribute(BlackboardAttribute.Type attributeType, String source, String valueString) throws IllegalArgumentException {
		if (attributeType.getValueType() != BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING
				&& attributeType.getValueType() != BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.JSON) {
			throw new IllegalArgumentException("Type mismatched with value type");
		}
		this.attributeOwnerId = 0;
		this.attributeType = attributeType;
		this.sources = replaceNulls(source);
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
	 * @param source        The source of this attribute.
	 * @param valueBytes    The attribute value.
	 *
	 * @throws IllegalArgumentException If the value type of the specified
	 *                                  attribute type is not
	 *                                  TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE.
	 */
	public Attribute(BlackboardAttribute.Type attributeType, String source, byte[] valueBytes) throws IllegalArgumentException {
		if (attributeType.getValueType() != BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE) {
			throw new IllegalArgumentException("Type mismatched with value type");
		}
		this.attributeOwnerId = 0;
		this.attributeType = attributeType;
		this.sources = replaceNulls(source);
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
	 * @param source           The source of this attribute. 
	 * @param valueType        The attribute value type.
	 * @param valueInt         The value from the the value_int32 column.
	 * @param valueLong        The value from the the value_int64 column.
	 * @param valueDouble      The value from the the value_double column.
	 * @param valueString      The value from the the value_text column.
	 * @param valueBytes       The value from the the value_byte column.
	 * @param sleuthkitCase    A reference to the SleuthkitCase object
	 *                         representing the case database.
	 */
	Attribute(long attributeOwnerId, BlackboardAttribute.Type attributeType, String source,  
			int valueInt, long valueLong, double valueDouble, String valueString, byte[] valueBytes,
			SleuthkitCase sleuthkitCase) {

		this.attributeOwnerId = attributeOwnerId;
		this.attributeType = attributeType;
		this.sources = replaceNulls(source);
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
				// SHOULD at some point figure out how to convert times in here 
				// based on preferred formats and such.  Perhaps provide another 
				// method that takes a formatter argument. 
				return Long.toString(getValueLong());
			case DOUBLE:
				return Double.toString(getValueDouble());
			case BYTE:
				return bytesToHexString(getValueBytes());

			case DATETIME: {
				if (parentDataSourceID == null) {
					// return time string in default timezone
					LOGGER.log(Level.WARNING, "Could not get timezone for image. Parent datasource id is null"); //NON-NLS
					return TimeUtilities.epochToTime(getValueLong());
				} else {
					try {
						final Content dataSource = sleuthkitCase.getContentById(parentDataSourceID);
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
			}
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
	
	Long getParentDataSourceID() {
		return this.parentDataSourceID;
	}
	
	public long getAttributeOwnerId() {
		return this.attributeOwnerId;
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
	 * Sets the parent data source id. The parent data source is defined
	 * as being the data source of the parent artifact.
	 * 
	 * @param parentDataSourceID The parent data source id.
	 */
	void setParentDataSourceID(long parentDataSourceID) {
		this.parentDataSourceID = parentDataSourceID;
	}

	/**
	 * Sets a source to the sources of this attribute.
	 *
	 * @param source The source name.
	 *
	 */
	public void setSource(String source) {
		this.sources = source;
	}
	
	/**
	 * Replace all NUL characters in the string with the SUB character
	 *
	 * @param text The input string.
	 *
	 * @return The output string.
	 */
	private String replaceNulls(String text) {
		return text.replace((char) 0x00, (char) 0x1A);
	}

	
	@Override
	public int hashCode() {
		return Objects.hash(
				this.attributeType, this.valueInt, this.valueLong, this.valueDouble,
				this.valueString, this.valueBytes, this.sources);
	}

	@Override
	public boolean equals(Object that) {
		if (this == that) {
			return true;
		} else if (that instanceof Attribute) {
			Attribute other = (Attribute) that;
			Object[] thisObject = new Object[]{this.attributeType, this.valueInt, this.valueLong, this.valueDouble,
				this.valueString, this.valueBytes, this.sources};
			Object[] otherObject = new Object[]{other.attributeType, other.valueInt, other.valueLong, other.valueDouble,
				other.valueString, other.valueBytes, other.sources};

			return Objects.deepEquals(thisObject, otherObject);
		} else {
			return false;
		}
	}

	@Override
	public String toString() {
		return MoreObjects.toStringHelper(this)
				.add("attributeType", attributeType.toString())
				.add("moduleName", sources) 
				.add("valueInt", valueInt)
				.add("valueLong", valueLong)
				.add("valueDouble", valueDouble)
				.add("valueString", valueString)
				.add("valueBytes", Arrays.toString(valueBytes) )
				.add("Case", sleuthkitCase)
				.toString();
	}
}