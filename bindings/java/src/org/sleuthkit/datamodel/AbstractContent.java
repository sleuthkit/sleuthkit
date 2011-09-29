/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel;

/**
 *
 * @author pmartel
 */
public abstract class AbstractContent implements Content {
	
	final protected SleuthkitCase db;
	final private long obj_id;

	AbstractContent(SleuthkitCase db, long obj_id) {
		this.db = db;
		this.obj_id = obj_id;
	}
	
	@Override
	public long getId() {
		return this.obj_id;
	}
	
}