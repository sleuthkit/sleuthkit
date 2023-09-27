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
import java.util.Objects;

/**
 * This is a concrete implementation of a simple Attribute Type.
 */
public class Attribute extends AbstractAttribute{
 
	/**
	 * The `parent` object of this Attribute.
	 */
	private long attributeParentId;
	
	/**
	 * Primary key in the respective attribute table.
	 */
	private long id;

	
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
	public Attribute(BlackboardAttribute.Type attributeType, int valueInt) throws IllegalArgumentException {
		super(attributeType, valueInt);
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
	public Attribute(BlackboardAttribute.Type attributeType, long valueLong) throws IllegalArgumentException {
		super(attributeType, valueLong);
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
	public Attribute(BlackboardAttribute.Type attributeType, double valueDouble) throws IllegalArgumentException {
		super(attributeType, valueDouble);
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
	public Attribute(BlackboardAttribute.Type attributeType, String valueString) throws IllegalArgumentException {
		super(attributeType, valueString);
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
	public Attribute(BlackboardAttribute.Type attributeType, byte[] valueBytes) throws IllegalArgumentException {
		super(attributeType, valueBytes);
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
	Attribute(long id, long attributeOwnerId, BlackboardAttribute.Type attributeType,  
			int valueInt, long valueLong, double valueDouble, String valueString, byte[] valueBytes,
			SleuthkitCase sleuthkitCase) {
		super(attributeType, valueInt, valueLong, valueDouble, valueString, valueBytes, sleuthkitCase);
		this.id = id;
	}

	/**
	 * Gets the parent Id of this attribute. A parent is defined as the Object
	 * to which this attribute is associated with. Eg: For a file Attribute the
	 * attribute parent id would be the file object id.
	 *
	 * @return
	 */
	final public long getAttributeParentId() {
		return this.attributeParentId;
	}

	/**
	 * Set the parent id for this attribute. Parent is defined as the Object 
	 * to which this attribute is associated with. 
	 * @param attributeParentId 
	 */
	final void setAttributeParentId(long attributeParentId) {
		this.attributeParentId = attributeParentId;
	}

	
	/**
	 * Returns the Id of the Attribute. 
	 * @return 
	 */
	public long getId() {
		return id;
	}
	
	
	/**
	 * Set the id of the attribute
	 * @param id 
	 */
	void setId(long id) {
		this.id = id;
	}
	
	@Override
	public int hashCode() {
		return Objects.hash(
				this.getAttributeType(), this.getValueInt(), this.getValueLong(), this.getValueDouble(),
				this.getValueString(), this.getValueBytes());
	}

	@Override
	public boolean equals(Object that) {
		if (this == that) {
			return true;
		} else if (that instanceof Attribute) {
 			return areValuesEqual(that);
		} else {
			return false;
		}
	}

	@Override
	public String toString() {
		return MoreObjects.toStringHelper(this)
				.add("attributeType", getAttributeType().toString())
				.add("valueInt", getValueInt())
				.add("valueLong", getValueLong())
				.add("valueDouble", getValueDouble())
				.add("valueString", getValueString())
				.add("valueBytes", Arrays.toString(getValueBytes()) )
				.add("Case", getCaseDatabase())
				.toString();
	}
}