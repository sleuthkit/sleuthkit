/*
 * Sleuth Kit Data Model
 *
 * Copyright 2018-2019 Basis Technology Corp.
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
package org.sleuthkit.datamodel;

import com.google.common.collect.ImmutableMap;
import static org.apache.commons.lang3.StringUtils.defaultString;

/**
 * Stores all levels of the event descriptions in a single class
 */
class ThreeLevelEventDescription implements TimelineEvent.EventDescription {

	/**
	 * The three descriptions (full, med, short) stored in a map, keyed by
 DescriptionLOD (DescriptionLevel of Detail)
	 */
	private final ImmutableMap<TimelineEvent.DescriptionLevel, String> descriptions;

	ThreeLevelEventDescription(String fullDescr, String mediumDescr, String shortDescr) {
		descriptions = ImmutableMap.of(TimelineEvent.DescriptionLevel.FULL, defaultString(fullDescr),
				TimelineEvent.DescriptionLevel.MEDIUM, defaultString(mediumDescr),
				TimelineEvent.DescriptionLevel.SHORT, defaultString(shortDescr)
		);
	}

	/**
	 * Get the description of this event at the give level of detail(LoD).
	 *
	 * @param lod The level of detail to get.
	 *
	 * @return The description of this event at the given level of detail.
	 */
	@Override
	public String getDescription(TimelineEvent.DescriptionLevel lod) {
		return descriptions.get(lod);
	}
}
