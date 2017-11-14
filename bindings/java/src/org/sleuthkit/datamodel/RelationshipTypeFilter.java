/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011-2017 Basis Technology Corp.
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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Filters communications by relationship type.
 *
 */
public class RelationshipTypeFilter implements SubFilter {

	private final Set<BlackboardArtifact.ARTIFACT_TYPE> relationshipTypes;

	/**
	 * Constructs a RelationshipTypeFilter.
	 *
	 * @param relationshipTypes set of  artifacts types
	 */
	public RelationshipTypeFilter(Set<BlackboardArtifact.ARTIFACT_TYPE> relationshipTypes) {
		this.relationshipTypes = relationshipTypes;
	}

	/**
	 * Get the list of relationship types.
	 *
	 * @return list of relationship types.
	 */
	Set<BlackboardArtifact.ARTIFACT_TYPE> getRelationshipTypes() {
		return new HashSet<BlackboardArtifact.ARTIFACT_TYPE>(relationshipTypes);
	}

	/**
	 * Returns a string description of the filter.
	 *
	 * @return	A string description of the filter.
	 */
	@Override
	public String getDescription() {
		return "Filters relationships by relationship type.";
	}

	/**
	 * Get the SQL string for the filter.
	 *
	 * @param commsManager Communications manager.
	 *
	 * @return SQL String for the filter.
	 */
	@Override
	public String getSQL(CommunicationsManager commsManager) {
		if (relationshipTypes.isEmpty()) {
			return "";
		}

		String sql = "";
		List<Integer> type_ids = new ArrayList<Integer>();
		for (BlackboardArtifact.ARTIFACT_TYPE artType : relationshipTypes) {
			type_ids.add(artType.getTypeID());
		}

		String artifact_type_ids_list = StringUtils.buildCSVString(type_ids);
		if (!artifact_type_ids_list.isEmpty()) {
			sql = " artifacts.artifact_type_id IN ( " + artifact_type_ids_list + " )";
		}

		return sql;
	}

}
