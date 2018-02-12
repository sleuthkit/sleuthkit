/*
 * Sleuth Kit Data Model
 *
 * Copyright 2014-2018 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import static java.nio.file.StandardOpenOption.READ;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This is a class that models reports.
 */
public class Report implements Content {

	static long ID_NOT_SET = -1;
	private long objectId = ID_NOT_SET;
	private final Path path;
	private final long createdTime;
	private final String sourceModuleName;
	private final String reportName;

	private Content parent; // The object from which the report was generated. 

	private final SleuthkitCase db; // A reference to the database instance.
	private FileChannel fileChannel; // Used to read report content.

	private static final Logger LOGGER = Logger.getLogger(Report.class.getName());

	/**
	 * Create a Report instance.
	 *
	 * @param id          Primary key from associated row in the case database.
	 * @param path        Absolute path to report.
	 * @param createdTime Created time of report (in UNIX epoch time).
	 * @param reportName  May be empty
	 * @param parent	  The parent/source of the Report.
	 */
	Report(SleuthkitCase db, long id, String path, long createdTime, String sourceModuleName, String reportName, Content parent) {
		this.db = db;
		this.objectId = id;
		this.path = Paths.get(path);
		this.createdTime = createdTime;
		this.sourceModuleName = sourceModuleName;
		this.reportName = reportName;
		this.parent = parent;
	}

	@Override
	public long getId() {
		return objectId;
	}

	/**
	 * Get the absolute local path to the report.
	 *
	 * @return
	 */
	public String getPath() {
		return path.toString();
	}

	/**
	 * Get the creation date of the report.
	 *
	 * @return Number of seconds since Jan 1, 1970.
	 */
	public long getCreatedTime() {
		return createdTime;
	}

	/**
	 * Get the name of the module (e.g., ingest module, reporting module) that
	 * generated the report.
	 *
	 * @return The module name.
	 */
	public String getSourceModuleName() {
		return this.sourceModuleName;
	}

	/**
	 * Get the report name, if any.
	 *
	 * @return The name of the report, possibly empty.
	 */
	public String getReportName() {
		return reportName;
	}

	@Override
	public int read(byte[] buf, long offset, long len) throws TskCoreException {
		if (Files.isDirectory(path)) {
			return 0;
		}

		int totalBytesRead = 0;
		ByteBuffer data = ByteBuffer.wrap(buf);
		try {
			fileChannel = FileChannel.open(path, READ);
			fileChannel.position(offset);
			int bytesRead = 0;
			do {
				bytesRead = fileChannel.read(data);
				if (bytesRead != -1) {
					totalBytesRead += bytesRead;
				}
			} while (bytesRead != -1 && data.hasRemaining());
		} catch (IOException ex) {
			LOGGER.log(Level.SEVERE, "Failed to read report file.", ex);
		}

		return totalBytesRead;
	}

	@Override
	public void close() {
		try {
			fileChannel.close();
		} catch (IOException ex) {
			LOGGER.log(Level.WARNING, "Failed to close report file.", ex);
		}
	}

	@Override
	public long getSize() {
		try {
			return Files.size(path);
		} catch (IOException ex) {
			LOGGER.log(Level.SEVERE, "Failed to get size of report.", ex);
			// If we cannot determine the size of the report, return zero
			// to prevent attempts to read content.
			return 0;
		}
	}

	@Override
	public <T> T accept(ContentVisitor<T> v) {
		return v.visit(this);
	}

	@Override
	public String getName() {
		return reportName;
	}

	@Override
	public String getUniquePath() throws TskCoreException {
		return path.toString();
	}

	@Override
	public Content getDataSource() throws TskCoreException {
		if (null == parent) {
			return null;
		} else {
			return parent.getDataSource();
		}
	}

	@Override
	public List<Content> getChildren() throws TskCoreException {
		return Collections.<Content>emptyList();
	}

	@Override
	public boolean hasChildren() throws TskCoreException {
		return false;
	}

	@Override
	public int getChildrenCount() throws TskCoreException {
		return 0;
	}

	@Override
	public Content getParent() throws TskCoreException {
		if (parent == null) {
			SleuthkitCase.ObjectInfo parentInfo;
			try {
				parentInfo = db.getParentInfo(this);
			} catch (TskCoreException ex) {
				return null;
			}
			parent = db.getContentById(parentInfo.getId());
		}
		return parent;
	}

	@Override
	public List<Long> getChildrenIds() throws TskCoreException {
		return Collections.<Long>emptyList();
	}

	@Override
	public BlackboardArtifact newArtifact(int artifactTypeID) throws TskCoreException {
		if (artifactTypeID != BlackboardArtifact.ARTIFACT_TYPE.TSK_KEYWORD_HIT.getTypeID()) {
			throw new TskCoreException("Reports can only have keyword hit artifacts.");
		}
		return db.newBlackboardArtifact(artifactTypeID, objectId);
	}

	@Override
	public BlackboardArtifact newArtifact(BlackboardArtifact.ARTIFACT_TYPE type) throws TskCoreException {
		return newArtifact(type.getTypeID());
	}

	@Override
	public ArrayList<BlackboardArtifact> getArtifacts(String artifactTypeName) throws TskCoreException {
		return getArtifacts(db.getArtifactType(artifactTypeName).getTypeID());
	}

	@Override
	public BlackboardArtifact getGenInfoArtifact() throws TskCoreException {
		// TSK_GEN_INFO artifact is obsolete.
		return null;
	}

	@Override
	public BlackboardArtifact getGenInfoArtifact(boolean create) throws TskCoreException {
		// TSK_GEN_INFO artifact is obsolete.
		return null;
	}

	@Override
	public ArrayList<BlackboardAttribute> getGenInfoAttributes(BlackboardAttribute.ATTRIBUTE_TYPE attr_type) throws TskCoreException {
		// TSK_GEN_INFO artifact is obsolete.
		return null;
	}

	@Override
	public ArrayList<BlackboardArtifact> getArtifacts(int artifactTypeID) throws TskCoreException {
		if (artifactTypeID != BlackboardArtifact.ARTIFACT_TYPE.TSK_KEYWORD_HIT.getTypeID()) {
			throw new TskCoreException("Reports can only have keyword hit artifacts.");
		}
		return db.getBlackboardArtifacts(artifactTypeID, objectId);
	}

	@Override
	public ArrayList<BlackboardArtifact> getArtifacts(BlackboardArtifact.ARTIFACT_TYPE type) throws TskCoreException {
		return getArtifacts(type.getTypeID());
	}

	@Override
	public ArrayList<BlackboardArtifact> getAllArtifacts() throws TskCoreException {
		return db.getMatchingArtifacts("WHERE obj_id = " + objectId); //NON-NLS
	}

	@Override
	public Set<String> getHashSetNames() throws TskCoreException {
		return Collections.<String>emptySet();
	}

	@Override
	public long getArtifactsCount(String artifactTypeName) throws TskCoreException {
		return getArtifactsCount(db.getArtifactType(artifactTypeName).getTypeID());
	}

	@Override
	public long getArtifactsCount(int artifactTypeID) throws TskCoreException {
		if (artifactTypeID != BlackboardArtifact.ARTIFACT_TYPE.TSK_KEYWORD_HIT.getTypeID()) {
			throw new TskCoreException("Reports can only have keyword hit artifacts.");
		}
		return db.getBlackboardArtifactsCount(artifactTypeID, objectId);
	}

	@Override
	public long getArtifactsCount(BlackboardArtifact.ARTIFACT_TYPE type) throws TskCoreException {
		return getArtifactsCount(type.getTypeID());
	}

	@Override
	public long getAllArtifactsCount() throws TskCoreException {
		return db.getBlackboardArtifactsCount(objectId);
	}

	@Override
	public <T> T accept(SleuthkitItemVisitor<T> v) {
		return v.visit(this);
	}
}
