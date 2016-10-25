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

import java.util.List;
import java.util.ArrayList;

import org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE;

/**
 * Utility class to combine information from various OS info artifacts into
 * fewer objects.
 */
public class OSUtility {

	private OSUtility() {
	}

	/**
	 * Get all non-backup OSInfo data
	 *
	 * @param skCase - Have to pass this in because we don't have access to the
	 *               normal method
	 *
	 * @return List of OSInfo objects
	 *
	 * @throws TskCoreException
	 */
	public static List<OSInfo> getOSInfo(SleuthkitCase skCase) throws TskCoreException {
		return getOSInfoInternal(skCase, false, false, 0);
	}

	/**
	 * Get OSInfo from the same file system as the given object. Will not
	 * include backups.
	 *
	 * @param skCase - Have to pass this in because we don't have access to the
	 *               normal method
	 * @param fsc    - FsContent from the same file system we want the OS
	 *               information from
	 *
	 * @return - List of OSInfo objects
	 *
	 * @throws TskCoreException
	 */
	public static List<OSInfo> getOSInfo(SleuthkitCase skCase, FsContent fsc) throws TskCoreException {
		return getOSInfoInternal(skCase, false, true, fsc.getFileSystemId());
	}

	/**
	 * Creates a list of all OS Info data on any file system, including the
	 * backups
	 *
	 * @param skCase - Have to pass this in because we don't have access to the
	 *               normal method
	 *
	 * @return - List of OSInfo objects
	 *
	 * @throws TskCoreException
	 */
	public static List<OSInfo> getAllOSInfo(SleuthkitCase skCase) throws TskCoreException {
		return getOSInfoInternal(skCase, true, false, 0);
	}

	/**
	 * Internal method to find and combine the requested OS Info data.
	 *
	 * @param skCase         - Have to pass this in because we don't have access
	 *                       to the normal method
	 * @param includeBackups - true if we should include registry data found in
	 *                       "RegBack"
	 * @param restrictFs     - true if an file system id is being provided to
	 *                       match against
	 * @param fsId           - the file system ID that the registry hives must
	 *                       be on (if restrictFs is set)
	 *
	 * @return - List of OSInfo objects
	 *
	 * @throws TskCoreException
	 */
	private static List<OSInfo> getOSInfoInternal(SleuthkitCase skCase, boolean includeBackups,
			boolean restrictFs, long fsId) throws TskCoreException {

		List<OSInfo> infoList = new ArrayList<OSInfo>();

		// Get all OS_INFO artifacts for this case
		ArrayList<BlackboardArtifact> results = skCase.getBlackboardArtifacts(ARTIFACT_TYPE.TSK_OS_INFO);

		for (BlackboardArtifact art : results) {

			AbstractFile file = skCase.getAbstractFileById(art.getObjectID());
			if (file == null) {
				continue;
			}

			// Check if we're in a backup directory. If so and we're not including backups,
			// skip this artifact.
			boolean isBackup = file.getParentPath().contains("RegBack");
			if (isBackup && (!includeBackups)) {
				continue;
			}

			// FsContent allows us to get the file system ID.
			if (file instanceof FsContent) {
				FsContent fsc = (FsContent) file;

				// If we're restricting the file system, skip any that don't match
				if (restrictFs && (fsId != fsc.getFileSystemId())) {
					continue;
				}

				// Make a new OSInfo object
				OSInfo newInfo = new OSInfo(art, isBackup, fsc.getFileSystemId(), file.getParent());

				// Attempt to merge it with an existing object
				boolean mergedInfo = false;
				for (OSInfo info : infoList) {
					if (info.matches(newInfo)) {
						info.combine(newInfo);
						mergedInfo = true;
						break;
					}
				}

				// If nothing matched, add the new object to the list
				if (!mergedInfo) {
					infoList.add(newInfo);
				}
			} else if (!restrictFs) {
				// Make a new OSInfo object (no file system ID in this case)
				OSInfo newInfo = new OSInfo(art, isBackup, file.getParent());

				// Attempt to merge it with an existing object
				boolean mergedInfo = false;
				for (OSInfo info : infoList) {
					if (info.matches(newInfo)) {
						info.combine(newInfo);
						mergedInfo = true;
						break;
					}
				}

				// If nothing matched, add the new object to the list
				if (!mergedInfo) {
					infoList.add(newInfo);
				}
			} else {
				// If we're limiting the search to one FS, don't include any
				// data we can't find the FS for
			}
		}

		return infoList;
	}

}
