/*
 * Sleuth Kit Data Model
 * 
 * Copyright 2013 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;

import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.List;

/**
 * Utility class to hold information from OS Info artifacts
 */
public class OSInfo {

	private final List<BlackboardArtifact> artifacts;
	private final Map<Integer, String> attributeMap;
	private final boolean isBackup;
	private final boolean haveFsContent;
	private final long fileSystemId;
	private final boolean haveParentId;
	private final long parentObjId;

	public OSInfo() {
		artifacts = new ArrayList<BlackboardArtifact>();
		attributeMap = new HashMap<Integer, String>();
		isBackup = false;
		fileSystemId = 0;
		haveFsContent = false;
		parentObjId = 0;
		haveParentId = false;
	}

	/**
	 * Initialize an OSInfo object
	 *
	 * @param a_art          - OSInfo artifact associated with one registry hive
	 * @param a_isBackup     - True if the registry hive was found in a
	 *                       "RegBack" directory
	 * @param a_fileSystemId - File system ID for FS containing the registry
	 *                       hive
	 * @param a_parent       - Parent directory containing the registry hive.
	 *                       Can be null
	 *
	 * @throws TskCoreException
	 */
	public OSInfo(BlackboardArtifact a_art, boolean a_isBackup, long a_fileSystemId, Content a_parent) throws TskCoreException {
		artifacts = new ArrayList<BlackboardArtifact>();
		artifacts.add(a_art);
		isBackup = a_isBackup;
		fileSystemId = a_fileSystemId;
		haveFsContent = true;
		attributeMap = new HashMap<Integer, String>();
		for (BlackboardAttribute attr : a_art.getAttributes()) {
			attributeMap.put(attr.getAttributeType().getTypeID(), attr.getValueString());
		}

		if (a_parent != null) {
			parentObjId = a_parent.getId();
			haveParentId = true;
		} else {
			parentObjId = 0;
			haveParentId = false;
		}
	}

	/**
	 * Initialize an OSInfo object (without file system information)
	 *
	 * @param a_art      - OSInfo artifact associated with one registry hive
	 * @param a_isBackup - True if the registry hive was found in a "RegBack"
	 *                   directory
	 * @param a_parent   - Parent directory containing the registry hive. Can be
	 *                   null
	 *
	 * @throws TskCoreException
	 */
	public OSInfo(BlackboardArtifact a_art, boolean a_isBackup, Content a_parent) throws TskCoreException {
		artifacts = new ArrayList<BlackboardArtifact>();
		artifacts.add(a_art);
		isBackup = a_isBackup;
		fileSystemId = 0;
		haveFsContent = false;
		if (a_parent != null) {
			parentObjId = a_parent.getId();
			haveParentId = true;
		} else {
			parentObjId = 0;
			haveParentId = false;
		}
		attributeMap = new HashMap<Integer, String>();
		for (BlackboardAttribute attr : a_art.getAttributes()) {
			attributeMap.put(attr.getAttributeType().getTypeID(), attr.getValueString());
		}
	}

	/**
	 * Determine whether two OSInfo objects should be combined.
	 *
	 * @param a_osInfo - the OSInfo object to compare against
	 *
	 * @return
	 */
	public boolean matches(OSInfo a_osInfo) {

		// Check if the two are in the same directory.
		// OSInfo is only dependant on SYSTEM and SOFTWARE, which should always be in the same directory
		// on the file system.
		if (haveParentId && a_osInfo.haveParentId) {

			return (parentObjId == a_osInfo.parentObjId);
		}

		// If we don't have a parent directory, just see if they're on the same file system,
		// and both have the same backup status.
		if (haveFsContent && a_osInfo.haveFsContent) {
			return ((a_osInfo.isBackup == isBackup) && (a_osInfo.fileSystemId == fileSystemId));
		}

		return false;
	}

	/**
	 * Combine the attribute map for two OSInfo objects.
	 *
	 * @param a_osInfo - The OSInfo object to combine with
	 */
	public void combine(OSInfo a_osInfo) {
		artifacts.addAll(a_osInfo.artifacts);
		attributeMap.putAll(a_osInfo.attributeMap);
	}

	public List<BlackboardArtifact> getArtifacts() {
		return artifacts;
	}

	public boolean haveFileSystem() {
		return haveFsContent;
	}

	public long getFileSystemId() {
		return fileSystemId;
	}

	public boolean getIsBackup() {
		return isBackup;
	}

	/**
	 * Generic method to get an OSInfo attribute value by ATTRIBUTE_TYPE.
	 *
	 * @param attrType - the attribute to get
	 *
	 * @return
	 */
	public String getAttributeValue(ATTRIBUTE_TYPE attrType) {
		if (attributeMap.containsKey(attrType.getTypeID())) {
			return attributeMap.get(attrType.getTypeID());
		}
		return "";
	}

	/*
	 * Dedicated getters for the most common attributes.
	 */
	public String getCompName() {
		return getAttributeValue(ATTRIBUTE_TYPE.TSK_NAME);
	}

	public String getProcessorArchitecture() {
		return getAttributeValue(ATTRIBUTE_TYPE.TSK_PROCESSOR_ARCHITECTURE);
	}

	public String getDomain() {
		return getAttributeValue(ATTRIBUTE_TYPE.TSK_DOMAIN);
	}

	public String getOSName() {
		return getAttributeValue(ATTRIBUTE_TYPE.TSK_PROG_NAME);
	}

}
