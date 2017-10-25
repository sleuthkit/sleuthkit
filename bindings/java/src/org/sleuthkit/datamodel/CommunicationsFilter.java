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
import java.util.List;

/**
 * Defines an aggregate of filters to apply to a CommunicationsManager query
 * 
 */
public class CommunicationsFilter {
	
	private final List<SubFilter> andFilters;
	// RAMAN TBD: figure our OR filters, I don't think we need any
	//private final List<SubFilter> orFilters;
	
	/*
	 * Returns the AND list of filters
	 */
	public List<SubFilter> getAndFilters() {
		return andFilters;
	}
	
	/*
	 * Adds a filter to AND list
	 */
	public void addAndFilter(SubFilter subFilter) {
		andFilters.add(subFilter);
	}
	
	CommunicationsFilter()
	{
		this.andFilters = new ArrayList<SubFilter>();
		//this.orFilters = new ArrayList<SubFilter>;
	
	}

}
