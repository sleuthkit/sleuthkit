/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011-2016 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import java.util.List;

/**
 * Represents information for an ingest job.
 */
public final class IngestJobInfo {

	private final int ingestJobId;
	private final long dataSourceId;
	private final String hostName;
	private final long startDate;
	private long endDate = 0;
	private final String settingsDir;
	private final List<IngestModuleInfo> ingestModuleInfo;
	private final SleuthkitCase skCase;
	private IngestStatusType status;

	/**
	 * Constructs an IngestJobInfo that has not ended
	 * @param ingestJobId
	 * @param dataSourceId
	 * @param hostName
	 * @param startDate
	 * @param settingsDir
	 * @param ingestModuleInfo
	 * @param skCase 
	 */
	IngestJobInfo(int ingestJobId, long dataSourceId, String hostName, long startDate, String settingsDir, List<IngestModuleInfo> ingestModuleInfo, SleuthkitCase skCase) {
		this.ingestJobId = ingestJobId;
		this.dataSourceId = dataSourceId;
		this.hostName = hostName;
		this.startDate = startDate;
		this.settingsDir = settingsDir;
		this.skCase = skCase;
		this.ingestModuleInfo = ingestModuleInfo;
		this.status = IngestStatusType.STARTED;
	}
	
	/**
	 * Constructs an IngestJobInfo that has already ended
	 * @param ingestJobId
	 * @param dataSourceId
	 * @param hostName
	 * @param startDate
	 * @param endDate
	 * @param settingsDir
	 * @param ingestModuleInfo
	 * @param skCase 
	 */
	IngestJobInfo(int ingestJobId, long dataSourceId, String hostName, long startDate, long endDate, String settingsDir, List<IngestModuleInfo> ingestModuleInfo, SleuthkitCase skCase) {
		this.ingestJobId = ingestJobId;
		this.dataSourceId = dataSourceId;
		this.hostName = hostName;
		this.startDate = startDate;
		this.endDate = endDate;
		this.settingsDir = settingsDir;
		this.skCase = skCase;
		this.ingestModuleInfo = ingestModuleInfo;
	}

	/**
	 * @return the endDate
	 */
	public long getEndDate() {
		return endDate;
	}

	/**
	 * Sets the end date for the ingest job info, and updates the database.
	 * Cannot be done multiple times
	 *
	 * @param endDate the endDate to set
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException If the update fails.
	 * @throws org.sleuthkit.datamodel.TskDataException If the job has already
	 *                                                  been given an end date
	 *                                                  or is not in the
	 *                                                  database.
	 */
	public void setEndDate(long endDate) throws TskCoreException, TskDataException {
		this.endDate = endDate;
		try {
			skCase.setIngestJobEndDate(ingestJobId, endDate);
		} catch (TskCoreException ex) {
			this.endDate = 0;
			throw ex;
		} catch (TskDataException ex) {
			this.endDate = 0;
			throw ex;
		}
	}
<<<<<<< HEAD
=======

	/**
	 * Sets the ingest status for the ingest job info, and updates the database.
	 *
	 * @param status The new status
	 *
	 * @throws TskCoreException If the update fails
	 * @throws TskDataException If the job is not in the db.
	 */
	public void setIngestStatus(IngestStatusType status) throws TskCoreException, TskDataException {
		IngestStatusType oldStatus = this.status;
		this.status = status;
		try {
			skCase.setIngestStatus(ingestJobId, status);
		} catch (TskCoreException ex) {
			this.status = oldStatus;
			throw ex;
		} catch (TskDataException ex) {
			this.status = oldStatus;
			throw ex;
		}
	}
>>>>>>> 2146
}
