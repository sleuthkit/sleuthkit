/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel.blackboardutils;

import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.SleuthkitCase;

/**
 * An abstract base class for classes that helps ingest modules create artifacts.
 * 
 */
public abstract class AbstractArtifactHelper {
	
	private final SleuthkitCase caseDb;
	private final AbstractFile srcAbstractFile;	// artifact source
    private final String moduleName;			// module creating the artifacts
	
	/**
	 * Creates an artifact helper.
	 * 
	 * @param caseDb Sleuthkit case db
     * @param moduleName name module using the helper
     * @param srcFile source file
	 */
	public AbstractArtifactHelper(SleuthkitCase caseDb, String moduleName, AbstractFile srcFile) {
        this.moduleName = moduleName;
        this.srcAbstractFile = srcFile;
        this.caseDb = caseDb;
	}
	
	/**
	 * Returns the source abstract file.
	 * 
	 * @return source abstract file
	 */
	AbstractFile getAbstractFile() {
		return this.srcAbstractFile;
	}
	
	/**
	 * Returns the sleuthkit case.
	 * 
	 * @return sleuthkit case
	 */
	SleuthkitCase getSleuthkitCase() {
		return this.caseDb;
	}
	
	/**
	 * Returns module name.
	 * 
	 * @return module name 
	 */
	String getModuleName() {
		return this.moduleName;
	}
	
}
