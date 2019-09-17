/*
 * Autopsy Forensic Browser
 *
 * Copyright 2019 Basis Technology Corp.
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
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.SleuthkitCase;

/**
 * An abstract base class for classes that helps ingest modules create
 * artifacts.
 *
 */
class ArtifactHelper {

	private final SleuthkitCase caseDb;
	private final AbstractFile srcAbstractFile;	// artifact source
	private final String moduleName;			// module creating the artifacts

	/**
	 * Creates an artifact helper.
	 *
	 * @param caseDb     Sleuthkit case db
	 * @param moduleName name module using the helper
	 * @param srcFile    source file
	 */
	protected ArtifactHelper(SleuthkitCase caseDb, String moduleName, AbstractFile srcFile) {
		this.moduleName = moduleName;
		this.srcAbstractFile = srcFile;
		this.caseDb = caseDb;
	}

	/**
	 * Returns the source abstract file.
	 *
	 * @return source abstract file
	 */
	AbstractFile getAbstractFile() {
		return this.srcAbstractFile;
	}

	/**
	 * Returns the sleuthkit case.
	 *
	 * @return sleuthkit case
	 */
	SleuthkitCase getSleuthkitCase() {
		return this.caseDb;
	}

	/**
	 * Returns module name.
	 *
	 * @return module name
	 */
	String getModuleName() {
		return this.moduleName;
	}

	/**
	 * Creates and adds an attribute to the list, if the attribute value is not empty or null.
	 *
	 * @param attrValue attribute value 
	 * @param attributeType attribute type
	 * @param attributes list of attributes to add to.
	 * 
	 */
	protected void addAttributeIfNotNull(String attrValue, BlackboardAttribute.ATTRIBUTE_TYPE attributeType, Collection<BlackboardAttribute> attributes) {
		if (!StringUtils.isEmpty(attrValue)) {
			attributes.add(new BlackboardAttribute(attributeType, getModuleName(), attrValue));
		}
	}

	/**
	 * Creates and adds an attribute to the list, if the attribute value is not 0.
	 *
	 * @param attrValue attribute value 
	 * @param attributeType attribute type
	 * @param attributes list of attributes to add to.
	 */
	protected void addAttributeIfNotZero(long attrValue, BlackboardAttribute.ATTRIBUTE_TYPE attributeType, Collection<BlackboardAttribute> attributes) {
		if (attrValue > 0) {
			attributes.add(new BlackboardAttribute(attributeType, getModuleName(), attrValue));
		}
	}
}
