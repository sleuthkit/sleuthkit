/*
 * Sleuth Kit Data Model
 * 
 * Copyright 2014 Basis Technology Corp.
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

/**
 * This is a data transfer object (DTO) class that models reports.
 */
public class Report {

	static long ID_NOT_SET = -1;
	private long id = ID_NOT_SET;
	private final String path;
	private final long createdTime;
	private final String sourceModuleName;
	private final String reportName;

	/**
	 * Construct a data transfer object for a row in the reports table.
	 *
	 * @param id Primary key from associated row in the case database.
	 * @param path Absolute path to report.
	 * @param createdTime Created time of report (in UNIX epoch time).
	 * @param reportName May be empty
	 */
	Report(long id, String path, long createdTime, String sourceModuleName, String reportName) {
		this.id = id;
		this.path = path;
		this.createdTime = createdTime;
		this.sourceModuleName = sourceModuleName;
		this.reportName = reportName;
	}

	/**
	 * Get the primary key of the associated row in the case database. Only
	 * needed by code updating the reports table.
	 *
	 * @return The primary key value.
	 */
	long getId() {
		return id;
	}

	/**
	 * Get the absolute local path to the report.
	 */
	public String getPath() {
		return path;
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
}
