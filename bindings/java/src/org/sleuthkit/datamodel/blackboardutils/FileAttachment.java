/*
 * Sleuth Kit Data Model
 *
 * Copyright 2019 Basis Technology Corp.
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
package org.sleuthkit.datamodel.blackboardutils;

import com.google.common.collect.ImmutableList;
import java.util.List;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.TskData;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.DerivedFile;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;

/**
 * File attachment to a message.
 *
 * The file may or may not have been downloaded, and hence may or may not be
 * part of the data source.
 *
 * A file attachment may also be created for a blob that is added as a derived
 * file.
 *
 */
public final class FileAttachment implements Attachment {

	private final String filePathName;
	private final long objId;

	// Mobile phones often create mount points to refer to SD Cards or other 
	// fixed/removable storage media.
	//
	// Applications use these mount points when referring files. But they may
	// not exist physically in the data source.
	//
	// Common, wellknown mount points are stripped from the file paths to
	// accurately search for the file in the image.
	transient private static final List<String> KNOWN_MOUNTPOINTS
			= ImmutableList.of(
					"/data/", // NON-NLS
					"/storage/emulated/"); //NON-NLS

	/**
	 * Creates a file attachment from a file path.
	 *
	 * Searches the specified data source for the give file name and path, and
	 * if found, saves the object Id of the file. If no match is found, then
	 * just the pathName is remembered.
	 *
	 * @param caseDb     Case database.
	 * @param dataSource Data source to search in.
	 * @param pathName   Full path name of the attachment file.
	 *
	 * @throws TskCoreException If there is an error in finding the attached
	 *                          file.
	 */
	public FileAttachment(SleuthkitCase caseDb, Content dataSource, String pathName) throws TskCoreException {

		//normalize the slashes.
		this.filePathName = normalizePath(pathName);

		String fileName = filePathName.substring(filePathName.lastIndexOf('/') + 1);
		String parentPathSubString = filePathName.substring(0, filePathName.lastIndexOf('/'));

		long matchedFileObjId = -1;
		List<AbstractFile> matchedFiles = caseDb.findFiles(dataSource, fileName, parentPathSubString);
		for (AbstractFile file : matchedFiles) {
			if (file.isMetaFlagSet(TskData.TSK_FS_META_FLAG_ENUM.ALLOC)) {
				matchedFileObjId = file.getId();
				break;
			}
		}
		objId = matchedFileObjId;

	}

	/**
	 * Creates a file attachment from a derived file.
	 *
	 * Occasionally the contents of an attachment may be stored as a blob in an
	 * application database. In that case, the ingest module must write out the contents 
	 * to a local file in the case, and create a corresponding DerivedFile object.
	 *
	 * @param derivedFile Derived file for the attachment.
	 */
	public FileAttachment(DerivedFile derivedFile) {
		objId = derivedFile.getId();
		filePathName = derivedFile.getLocalAbsPath() + "/" + derivedFile.getName();
	}

	/**
	 * Creates a file attachment from a file.
	 *
	 * @param abstractFile Abstract file for attachment..
	 */
	public FileAttachment(AbstractFile abstractFile) {
		objId = abstractFile.getId();
		filePathName = abstractFile.getParentPath() + "/" + abstractFile.getName();
	}

	/**
	 * Returns the full path name of the file.
	 *
	 * @return full path name.
	 */
	public String getPathName() {
		return filePathName;
	}

	/**
	 * Returns the objId of the attachment file, if the file was found in the
	 * data source.
	 *
	 * @return object id of the file. -1 if no matching file is found.
	 */
	public long getObjectId() {
		return objId;
	}

	/**
	 * Normalizes the input path - convert all slashes to TSK convention, 
	 * and checks for any well know mount point prefixes that need stripped.
	 * 
	 * @param path path to normalize
	 * 
	 * @return normalized path.
	 */
	private String normalizePath(String path) {
		//normalize the slashes.
		String adjustedPath = path.replace("\\", "/");

		// Strip common known mountpoints.
		for (String mountPoint : KNOWN_MOUNTPOINTS) {
			if (adjustedPath.toLowerCase().startsWith(mountPoint)) {
				adjustedPath = ("/").concat(adjustedPath.substring(mountPoint.length()));
				break;
			}
		}

		return adjustedPath;
	}

	@Override
	public String getLocation() {
		return this.filePathName;
	}

	@Override
	public Long getObjId() {
		return this.objId;
	}
}
