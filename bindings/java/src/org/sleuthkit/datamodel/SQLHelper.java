/*
 * Sleuth Kit Data Model
 *
 * Copyright 2020 Basis Technology Corp.
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

/**
 * Interface for classes to help create queries for SQLite or PostgreSQL
 */
interface SQLHelper {
	
	// Get the type for the primary key
	String getPrimaryKey();
	
	// Get the type for big int-type data
	String getBigIntType();
	
	// Get the type for blob-type data
	String getBlobType();
	
	// Get the description column name for the tsk_vs_parts table.
	// This varies between SQLite and PostgreSQL.
	String getVSDescColName();


	/**
	 * PostgreSQL-specific implementation
	 */
	class PostgreSQLHelper implements SQLHelper {

		@Override
		public String getPrimaryKey() {
			return "BIGSERIAL";
		}

		@Override
		public String getBigIntType() {
			return "BIGINT";
		}

		@Override
		public String getBlobType() {
			return "BYTEA";
		}

		@Override
		public String getVSDescColName() {
			return "descr";
		}
	}
	
	/**
	 * SQLite-specific implementation
	 */
	class SQLiteHelper implements SQLHelper {

		@Override
		public String getPrimaryKey() {
			return "INTEGER";
		}

		@Override
		public String getBigIntType() {
			return "INTEGER";
		}

		@Override
		public String getBlobType() {
			return "BLOB";
		}

		@Override
		public String getVSDescColName() {
			return "desc";
		}
	}
}