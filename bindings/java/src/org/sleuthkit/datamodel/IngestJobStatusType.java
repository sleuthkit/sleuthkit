/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel;

enum IngestJobStatusType {

	STARTED(0, "Started"),
	CANCELLED(1, "Cancelled"),
	COMPLETED(2, "Completed");
	private int typeId;
	private String typeName;

	IngestJobStatusType(int statusId, String statusName) {
		this.typeId = statusId;
		this.typeName = statusName;
	}

	/**
	 * @return the typeId
	 */
	public int getTypeId() {
		return typeId;
	}

	/**
	 * @return the typeName
	 */
	public String getTypeName() {
		return typeName;
	}

	public static IngestJobStatusType fromID(int typeId) {
		for (IngestJobStatusType statusType : IngestJobStatusType.values()) {
			if (statusType.getTypeId() == typeId) {
				return statusType;
			}
		}
		return null;
	}
}
