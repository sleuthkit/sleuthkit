/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel;

/**
 * 
 *
 * @author pmartel
 */
public interface FileSystemParent extends Content {
	/**
	 * get the handle to the sleuthkit image info object
	 * @return the object pointer
	 */
	public long getImageHandle();
}
