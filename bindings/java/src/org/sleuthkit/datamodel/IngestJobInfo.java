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

import java.util.Date;
import java.util.List;

/**
 * Represents information for an ingest job.
 */
public final class IngestJobInfo {

	private final int ingestJobId;
	private final int dataSourceId;
	private final String hostName;
	private final Date startDateTime;
	private Date endDateTime = new Date(0);
	private final String settingsDir;
	private final List<IngestModuleInfo> ingestModuleInfo;
	private final SleuthkitCase skCase;
	private IngestJobStatusType status;

	IngestJobInfo(int ingestJobId, int dataSourceId, String hostName, Date startDateTime, String settingsDir, List<IngestModuleInfo> ingestModuleInfo, SleuthkitCase skCase) {
		this.ingestJobId = ingestJobId;
		this.dataSourceId = dataSourceId;
		this.hostName = hostName;
		this.startDateTime = startDateTime;
		this.settingsDir = settingsDir;
		this.skCase = skCase;
		this.ingestModuleInfo = ingestModuleInfo;
		this.status = IngestJobStatusType.STARTED;
	}

	/**
	 * @return the end date time of the job (equal to the epoch if it has not
	 *         been set yet).
	 */
	public Date getEndDateTime() {
		return endDateTime;
	}

	/**
	 * Sets the end date for the ingest job info, and updates the database.
	 * Cannot be done multiple times
	 *
	 * @param endDate the endDateTime to set
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException If the update fails.
	 * @throws org.sleuthkit.datamodel.TskDataException If the job has already
	 *                                                  been given an end date
	 *                                                  or is not in the
	 *                                                  database.
	 */
	public void setEndDateTime(Date endDateTime) throws TskCoreException, TskDataException {
		this.endDateTime = endDateTime;
		try {
			skCase.setIngestJobEndDateTime(ingestJobId, endDateTime.getTime());
		} catch (TskCoreException ex) {
			this.endDateTime = new Date(0);
			throw ex;
		} catch (TskDataException ex) {
			this.endDateTime = new Date(0);
			throw ex;
		}
	}

	/**
	 * Sets the ingest status for the ingest job info, and updates the database.
	 *
	 * @param status The new status
	 *
	 * @throws TskCoreException If the update fails
	 * @throws TskDataException If the job is not in the db.
	 */
	public void setIngestStatus(IngestJobStatusType status) throws TskCoreException, TskDataException {
		IngestJobStatusType oldStatus = this.status;
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
}
