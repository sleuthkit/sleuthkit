/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel.timeline;

import org.sleuthkit.datamodel.DescriptionLoD;

 class SingeLevelEventDiscription implements TimelineEvent.EventDescription {

	private final String fullDescr;

	 SingeLevelEventDiscription(String fullDescr) {
		this.fullDescr = fullDescr;

	}

	@Override
	public String getDescription(DescriptionLoD lod) {
		return fullDescr;
	}
}
