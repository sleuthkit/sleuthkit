/*
 * SleuthKit Java Bindings
 *
 * Copyright 2021 Basis Technology Corp.
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

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Objects;

/**
 * Utility class for file-based database queries.
 */
public class FileManager {

	private final SleuthkitCase skCase;

	/**
	 * Constructs a FileManager.
	 *
	 * @param casedb The case database.
	 */
	FileManager(SleuthkitCase skCase) {
		this.skCase = Objects.requireNonNull(skCase, "Cannot create Blackboard for null SleuthkitCase");
	}
	
	/**
     * Find all files with the exact given name and parentId.
     * 
     * @param parentId Id of the parent folder to search.
     * @param name Exact file name to match.
     * 
     * @return A list of matching files.
     * 
     * @throws TskCoreException 
     */
    public List<AbstractFile> findFilesExactName(long parentId, String name) throws TskCoreException {
		String query = "SELECT tsk_files.* FROM tsk_files JOIN tsk_objects ON tsk_objects.obj_id = tsk_files.obj_id WHERE par_obj_id = ? AND name = ?";
		skCase.acquireSingleUserCaseReadLock();
		try (SleuthkitCase.CaseDbConnection connection = skCase.getConnection()) {
			PreparedStatement statement = connection.getPreparedStatement(query, Statement.RETURN_GENERATED_KEYS);
			statement.clearParameters();
			statement.setLong(1, parentId);
			statement.setString(2, name);
			try (ResultSet rs = connection.executeQuery(statement)) {
				return skCase.resultSetToAbstractFiles(rs, connection);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("SQLException thrown when calling query: " + query + " for parentID = " + parentId + " and name " + name, ex);
		} finally {
			skCase.releaseSingleUserCaseReadLock();
		}
    }
	
	/**
     * Find all files with the exact given name and exact parent path.
     * 
	 * @param dataSource The data source to search within.
     * @param name Exact file name to match.
	 * @param path Exact parent path.
     * 
     * @return A list of matching files.
     * 
     * @throws TskCoreException 
     */
	public List<AbstractFile> findFilesExactNameExactPath(Content dataSource, String name, String path) throws TskCoreException {
		
		// Database paths will always start and end with a forward slash, so add those if not present
		String normalizedPath = path;
		if (!normalizedPath.startsWith("/")) {
			normalizedPath = "/" + normalizedPath;
		}
		if (!normalizedPath.endsWith("/")) {
			normalizedPath = normalizedPath + "/";
		}
		
		String query = "SELECT tsk_files.* FROM tsk_files JOIN tsk_objects ON tsk_objects.obj_id = tsk_files.obj_id WHERE parent_path = ? AND name = ? AND data_source_obj_id = ?";
		skCase.acquireSingleUserCaseReadLock();
		try (SleuthkitCase.CaseDbConnection connection = skCase.getConnection()) {
			PreparedStatement statement = connection.getPreparedStatement(query, Statement.RETURN_GENERATED_KEYS);
			statement.clearParameters();
			statement.setString(1, normalizedPath);
			statement.setString(2, name);
			statement.setLong(3, dataSource.getId());
			try (ResultSet rs = connection.executeQuery(statement)) {
				return skCase.resultSetToAbstractFiles(rs, connection);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("SQLException thrown when calling query: " + query + " for parent path = " + path + " and name " + name, ex);
		} finally {
			skCase.releaseSingleUserCaseReadLock();
		}
	}
}
