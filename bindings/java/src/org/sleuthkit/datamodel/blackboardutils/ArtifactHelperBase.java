/*
 * Sleuth Kit Data Model
 *
 * Copyright 2019-2021 Basis Technology Corp.
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
import java.util.Optional;
import org.apache.commons.lang3.StringUtils;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.SleuthkitCase;

/**
 * A super class for classes that help modules create artifacts.
 */
class ArtifactHelperBase {

	private final SleuthkitCase caseDb;
	private final Content srcContent;
	private final String moduleName;
	private final Long ingestJobId;

	/**
	 * Constructs the super class part of an artifact helper.
	 *
	 * @param caseDb      The case database.
	 * @param moduleName  The name of the module creating the artifacts.
	 * @param srcContent  The source/parent content of the artifacts.
	 * @param ingestJobId The numeric identifier of the ingest job within which
	 *                    the artifacts are being created, may be null.
	 */
	ArtifactHelperBase(SleuthkitCase caseDb, String moduleName, Content srcContent, Long ingestJobId) {
		this.moduleName = moduleName;
		this.srcContent = srcContent;
		this.caseDb = caseDb;
		this.ingestJobId = ingestJobId;
	}

	/**
	 * Get the source/parent content of the artifacts.
	 *
	 * @return The content.
	 */
	Content getContent() {
		return srcContent;
	}

	/**
	 * Gets the case database.
	 *
	 * @return The case database.
	 */
	SleuthkitCase getSleuthkitCase() {
		return caseDb;
	}

	/**
	 * Gets the name of the module creating the artifacts.
	 *
	 * @return The module name.
	 */
	String getModuleName() {
		return moduleName;
	}

	/**
	 * Gets the numeric identifier of the ingest job within which the artifacts
	 * are being created.
	 *
	 * @return The ingest job ID, may be null
	 */
	Optional<Long> getIngestJobId() {
		return Optional.ofNullable(ingestJobId);
	}

	/**
	 * Creates an attribute of a specified type with a string value and adds it
	 * to a given list of attributes.
	 *
	 * @param attributeType The attribute type.
	 * @param attrValue     The attribute value, may not be the empty string or
	 *                      null.
	 * @param attributes    The list of attributes.
	 */
	void addAttributeIfNotNull(BlackboardAttribute.ATTRIBUTE_TYPE attributeType, String attrValue, Collection<BlackboardAttribute> attributes) {
		if (!StringUtils.isEmpty(attrValue)) {
			attributes.add(new BlackboardAttribute(attributeType, getModuleName(), attrValue));
		}
	}

	/**
	 * Creates an attribute of a specified type with a long value and adds it to
	 * a given list of attributes.
	 *
	 * @param attributeType The attribute type.
	 * @param attrValue     The attribute value, must be greater than zero.
	 * @param attributes    The list of attributes.
	 */
	void addAttributeIfNotZero(BlackboardAttribute.ATTRIBUTE_TYPE attributeType, long attrValue, Collection<BlackboardAttribute> attributes) {
		if (attrValue > 0) {
			attributes.add(new BlackboardAttribute(attributeType, getModuleName(), attrValue));
		}
	}

	/**
	 * Creates an attribute of a specified type with an integer value and adds
	 * it to a given list of attributes.
	 *
	 * @param attributeType The attribute type.
	 * @param attrValue     The attribute value, must be greater than zero.
	 * @param attributes    The list of attributes to which the new attribute
	 *                      will be added.
	 */
	void addAttributeIfNotZero(BlackboardAttribute.ATTRIBUTE_TYPE attributeType, int attrValue, Collection<BlackboardAttribute> attributes) {
		if (attrValue > 0) {
			attributes.add(new BlackboardAttribute(attributeType, getModuleName(), attrValue));
		}
	}

}
