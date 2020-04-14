/*
 * Sleuth Kit Data Model
 *
 * Copyright 2019-2020 Basis Technology Corp.
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
package org.sleuthkit.datamodel.blackboardutils;

import java.util.Collection;
import org.apache.commons.lang3.StringUtils;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.SleuthkitCase;

/**
 * A base class for classes that help ingest modules create artifacts.
 *
 */
class ArtifactHelperBase {

	private final SleuthkitCase caseDb;
	private final Content srcContent;		// artifact source
	private final String moduleName;		// module creating the artifacts

	/**
	 * Creates an artifact helper.
	 *
	 * @param caseDb     Sleuthkit case db
	 * @param moduleName name module using the helper
	 * @param srcContent source content
	 */
	ArtifactHelperBase(SleuthkitCase caseDb, String moduleName, Content srcContent) {
		this.moduleName = moduleName;
		this.srcContent = srcContent;
		this.caseDb = caseDb;
	}

	/**
	 * Returns the source content.
	 *
	 * @return Source content.
	 */
	Content getContent() {
		return this.srcContent;
	}

	/**
	 * Returns the sleuthkit case.
	 *
	 * @return Sleuthkit case database.
	 */
	SleuthkitCase getSleuthkitCase() {
		return this.caseDb;
	}

	/**
	 * Returns module name.
	 *
	 * @return Module name.
	 */
	String getModuleName() {
		return this.moduleName;
	}

	/**
	 * Creates and adds a string attribute of specified type to the given list, if the
	 * attribute value is not empty or null.
	 *
	 * @param attributeType Attribute type.
	 * @param attrValue     String attribute value.
	 * @param attributes    List of attributes to add to.
	 *
	 */
	void addAttributeIfNotNull(BlackboardAttribute.ATTRIBUTE_TYPE attributeType, String attrValue, Collection<BlackboardAttribute> attributes) {
		if (!StringUtils.isEmpty(attrValue)) {
			attributes.add(new BlackboardAttribute(attributeType, getModuleName(), attrValue));
		}
	}

	/**
	 * Creates and adds a long attribute of specified type to the given list, if the
	 * attribute value is not 0.
	 *
	 * @param attributeType Attribute type.
	 * @param attrValue     Long attribute value.
	 * @param attributes    List of attributes to add to.
	 */
	void addAttributeIfNotZero(BlackboardAttribute.ATTRIBUTE_TYPE attributeType, long attrValue, Collection<BlackboardAttribute> attributes) {
		if (attrValue > 0) {
			attributes.add(new BlackboardAttribute(attributeType, getModuleName(), attrValue));
		}
	}
	
	/**
	 * Creates and adds an integer attribute of specified type to the given list, if the
	 * attribute value is not 0.
	 *
	 * @param attributeType Attribute type.
	 * @param attrValue     Integer attribute value.
	 * @param attributes    List of attributes to add to.
	 */
	void addAttributeIfNotZero(BlackboardAttribute.ATTRIBUTE_TYPE attributeType, int attrValue, Collection<BlackboardAttribute> attributes) {
		if (attrValue > 0) {
			attributes.add(new BlackboardAttribute(attributeType, getModuleName(), attrValue));
		}
	}
}
