/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel;

enum IngestJobStatusType {

	STARTED(0),
	CANCELLED(1),
	COMPLETED(2);
	private int typeId;

	IngestJobStatusType(int statusId) {
		this.typeId = statusId;
	}

	/**
	 * @return the typeId
	 */
	public int getTypeId() {
		return typeId;
	}
	
	public static IngestJobStatusType fromID(int typeId) {
		for (IngestJobStatusType statusType : IngestJobStatusType.values()) {
			if(statusType.getTypeId() == typeId) {
				return statusType;
			}
		}
		return null;
	}
}
