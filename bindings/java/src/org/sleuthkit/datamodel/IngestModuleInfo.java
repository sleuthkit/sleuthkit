/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel;

/**
 * Class representing information about an ingest module, used in ingest job
 * info to show which ingest modules were run.
 */
public final class IngestModuleInfo {

	private final int ingestModuleId;
	private final String displayName;
	private final String uniqueName;
	private final int typeID;
	private final String version;

	IngestModuleInfo(int ingestModuleId, String displayName, String uniqueName, int typeID, String version) {
		this.ingestModuleId = ingestModuleId;
		this.displayName = displayName;
		this.uniqueName = uniqueName;
		this.typeID = typeID;
		this.version = version;
	}

	/**
	 * @return the ingestModuleId
	 */
	public int getIngestModuleId() {
		return ingestModuleId;
	}

	/**
	 * @return the displayName
	 */
	public String getDisplayName() {
		return displayName;
	}

	/**
	 * @return the uniqueName
	 */
	public String getUniqueName() {
		return uniqueName;
	}

	/**
	 * @return the typeID
	 */
	public int getTypeID() {
		return typeID;
	}

	/**
	 * @return the version
	 */
	public String getVersion() {
		return version;
	}
    
}
