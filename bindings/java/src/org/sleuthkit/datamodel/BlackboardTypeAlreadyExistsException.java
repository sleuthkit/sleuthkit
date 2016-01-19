/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel;

/**
 * Exception thrown when it is attempted to add a blackboard type that already
 * exists
 */
public class BlackboardTypeAlreadyExistsException extends TskException {

	private static final long serialVersionUID = 1L;

	/**
	 * Default constructor for this exception
	 */
	public BlackboardTypeAlreadyExistsException() {
		super("No message available");
	}

	/**
	 * Constructor for this exception where there is a message
	 *
	 * @param msg -- The message to display
	 */
	public BlackboardTypeAlreadyExistsException(String msg) {
		super(msg);
	}

}
