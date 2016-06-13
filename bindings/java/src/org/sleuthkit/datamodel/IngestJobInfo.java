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
import java.util.ResourceBundle;

/**
 * Represents information for an ingest job.
 */
public final class IngestJobInfo {

	private static final ResourceBundle bundle = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle");

	public enum IngestJobStatusType {

		//DO NOT CHANGE ORDER
		STARTED(bundle.getString("IngestJobInfo.IngestJobStatusType.Started.displayName")),
		CANCELLED(bundle.getString("IngestJobInfo.IngestJobStatusType.Cancelled.displayName")),
		COMPLETED(bundle.getString("IngestJobInfo.IngestJobStatusType.Completed.displayName"));

		private String displayName;

		private IngestJobStatusType(String displayName) {
			this.displayName = displayName;
		}

		public static IngestJobStatusType fromID(int typeId) {
			for (IngestJobStatusType statusType : IngestJobStatusType.values()) {
				if (statusType.ordinal() == typeId) {
					return statusType;
				}
			}
			return null;
		}

		/**
		 * @return the displayName
		 */
		public String getDisplayName() {
			return displayName;
		}
	}

	private final long ingestJobId;
	private final long objectId;
	private final String hostName;
	private final Date startDateTime;
	private Date endDateTime = new Date(0);
	private final String settingsDir;
	private final List<IngestModuleInfo> ingestModuleInfo;
	private final SleuthkitCase skCase;
	private IngestJobStatusType status;

	/**
	 * Constructs an IngestJobInfo that has not ended
	 *
	 * @param ingestJobId      The id of the ingest job
	 * @param objectId     The data source the job is being run on
	 * @param hostName         The host on which the job was executed
	 * @param startDateTime    The date time the job was started
	 * @param settingsDir      The directory of the job settings
	 * @param ingestModuleInfo The ingest modules being run for this job
	 * @param skCase           A reference to sleuthkit case
	 */
	IngestJobInfo(long ingestJobId, long objectId, String hostName, Date startDateTime, String settingsDir, List<IngestModuleInfo> ingestModuleInfo, SleuthkitCase skCase) {
		this.ingestJobId = ingestJobId;
		this.objectId = objectId;
		this.hostName = hostName;
		this.startDateTime = startDateTime;
		this.settingsDir = settingsDir;
		this.skCase = skCase;
		this.ingestModuleInfo = ingestModuleInfo;
		this.status = IngestJobStatusType.STARTED;
	}

	/**
	 * Constructs an IngestJobInfo that has already ended
	 *
	 * @param ingestJobId      The id of the ingest job
	 * @param dataSourceId     The data source the job is being run on
	 * @param hostName         The host on which the job was executed
	 * @param startDateTime    The date time the job was started
	 * @param endDateTime      The date time the job was ended (if it ended)
	 * @param status           The status of the job
	 * @param settingsDir      The directory of the job settings
	 * @param ingestModuleInfo The ingest modules being run for this job
	 * @param skCase           A reference to sleuthkit case
	 */
	IngestJobInfo(long ingestJobId, long dataSourceId, String hostName, Date startDateTime, Date endDateTime, IngestJobStatusType status, String settingsDir, List<IngestModuleInfo> ingestModuleInfo, SleuthkitCase skCase) {
		this.ingestJobId = ingestJobId;
		this.objectId = dataSourceId;
		this.hostName = hostName;
		this.startDateTime = startDateTime;
		this.endDateTime = endDateTime;
		this.settingsDir = settingsDir;
		this.skCase = skCase;
		this.ingestModuleInfo = ingestModuleInfo;
		this.status = status;
	}
}
