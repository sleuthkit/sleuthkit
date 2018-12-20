/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel.timeline;

import com.google.common.collect.ImmutableMap;
import static org.apache.commons.lang3.StringUtils.defaultString;
import org.sleuthkit.datamodel.DescriptionLoD;

class ThreeLevellEventDescription implements TimelineEvent.EventDescription {

	/**
	 * The three descriptions (full, med, short) stored in a map, keyed by
	 * DescriptionLOD (Level of Detail)
	 */
	private final ImmutableMap<DescriptionLoD, String> descriptions;

	ThreeLevellEventDescription(String fullDescr, String mediumDescr, String shortDescr) {
		descriptions = ImmutableMap.of(
				DescriptionLoD.FULL, defaultString(fullDescr),
				DescriptionLoD.MEDIUM, defaultString(mediumDescr),
				DescriptionLoD.SHORT, defaultString(shortDescr)
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
	public String getDescription(DescriptionLoD lod) {
		return descriptions.get(lod);
	}
}
