/*
 * Sleuth Kit Data Model
 *
 * Copyright 2020 Basis Technology Corp.
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
package org.sleuthkit.datamodel.blackboardutils.attributes;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import org.sleuthkit.datamodel.BlackboardAttribute;

/**
 * A utility for converting between JSON and artifact attributes of value type
 * TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.JSON.
 */
public final class BlackboardJsonAttrUtil {

	/**
	 * Creates an attribute of a given type with the string value set to an
	 * object of type T serialized to JSON.
	 *
	 * @param <T>        The type of the attribute value object to be
	 *                   serialized.
	 * @param attrType   The type of attribute to create.
	 * @param moduleName The name of the module creating the attribute.
	 * @param attrValue  The attribute value object.
	 *
	 * @return The BlackboardAttribute object.
	 */
	public static <T> BlackboardAttribute toAttribute(BlackboardAttribute.Type attrType, String moduleName, T attrValue) {
		if (attrType.getValueType() != BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.JSON) {
			throw new IllegalArgumentException(String.format("Attribute type %s does not have value type BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.JSON", attrType.getTypeName()));
		}
		return new BlackboardAttribute(attrType, moduleName, (new Gson()).toJson(attrValue));
	}

	/**
	 * Creates an object of type T from the JSON in the string value of a
	 * BlackboardAttribute with a value type of
	 * TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.JSON.
	 *
	 * @param <T>   The type of the object to be created from the JSON.
	 * @param attr  The attribute.
	 * @param clazz The class object for class T.
	 *
	 * @return The T object from the attribute.
	 *
	 * @throws InvalidJsonException Thrown the JSON in an artifact attribute
	 *                              cannot be deserialized to an object of the
	 *                              specified type.
	 */
	public static <T> T fromAttribute(BlackboardAttribute attr, Class<T> clazz) throws InvalidJsonException {
		BlackboardAttribute.Type attrType = attr.getAttributeType();
		if (attrType.getValueType() != BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.JSON) {
			throw new IllegalArgumentException(String.format("Attribute type %s does not have value type BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.JSON", attrType.getTypeName()));
		}
		String json = attr.getValueString();
		if (json == null || json.isEmpty()) {
			throw new InvalidJsonException("The string value (JSON) of the attribute is null or empty");
		}
		try {
			return (new Gson()).fromJson(json, clazz);
		} catch (JsonSyntaxException ex) {
			throw new InvalidJsonException(String.format("The string value (JSON) could not be deserialized as a %s", clazz.getName()), ex);
		}
	}

	/**
	 * Constructs an exception to be thrown when the JSON in an artifact
	 * attribute cannot be deserialized to an object of the specified type.
	 */
	public static class InvalidJsonException extends Exception {

		private static final long serialVersionUID = 1L;

		/**
		 * Constructs an exception thrown when JSON in an artifact attribute
		 * cannot be deserialized to an object of the specified type.
		 *
		 * @param message An error message.
		 */
		public InvalidJsonException(String message) {
			super(message);
		}

		/**
		 * Constructs an exception thrown when JSON in an artifact attribute
		 * cannot be deserialized to an object of the specified type.
		 *
		 * @param message An error message.
		 * @param cause   An excception that caused this exception to be thrown.
		 */
		public InvalidJsonException(String message, Throwable cause) {
			super(message, cause);
		}
	}

	/**
	 * Prevents instantiation of this utility class.
	 */
	private BlackboardJsonAttrUtil() {
	}

}
