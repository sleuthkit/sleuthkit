/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel;

/**
 *
 */
public enum ReviewStatus {

	APPROVED(1, "APPROVED", "approved"), REJECTED(2, "REJECTED", "rejected"), UNDECIDED(3, "UNDECIDED", "undecided");

	private final Integer id;
	private final String name;
	private final String displayName;

	private ReviewStatus(Integer id, String name, String displayName) {
		this.id = id;
		this.name = name;
		this.displayName = displayName;
	}

	/**
	 * @return the id
	 */
	Integer getId() {
		return id;
	}

	/**
	 * @return the name
	 */
	String getName() {
		return name;
	}

	/**
	 * @return the displayName
	 */
	String getDisplayName() {
		return displayName;
	}
}
