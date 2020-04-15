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
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;

/**
 *
 */
public class TaggingManager {
	private static final Logger LOGGER = Logger.getLogger(TaggingManager.class.getName());
	
	private static final String INSERT_TAG_SET = "INSERT INTO tag_sets (name) VALUES('%s')";
	private static final String SELECT_TAG_SET_BY_NAME = "SELECT * FROM tag_sets WHERE name = '%s'";
	private static final String DELETE_TAG_SET = "DELETE FROM tag_sets WHERE name = '%s'";
	private static final String SELECT_ALL_TAG_SET = "SELECT * FROM tag_sets";
	
	private final SleuthkitCase skCase;
		
	TaggingManager(SleuthkitCase skCase) {
		this.skCase = skCase;
	}
	
	/**
	 * Inserts a row into the reports table in the case database.
	 * 
	 * @param name The tag set name.
	 * 
	 * @return A TagSet object for the new row.
	 * 
	 * @throws TskCoreException 
	 */
	public TagSet addTagSet(String name) throws TskCoreException {
		TagSet tagSet = null;
		
		CaseDbConnection connection = skCase.getConnection();
		skCase.acquireSingleUserCaseWriteLock();
		try (Statement stmt = connection.createStatement()){
			connection.beginTransaction();
			// INSERT INTO tag_sets (name) VALUES('%s')
			stmt.execute(String.format(INSERT_TAG_SET, name));
			
			// Read back the id
			// SELECT * FROM tag_sets WHERE name = '%s'
			try(ResultSet resultSet = stmt.executeQuery(String.format(SELECT_TAG_SET_BY_NAME, name))){
			
				resultSet.next();
				int setID = resultSet.getInt("tag_set_id");
			
				tagSet = new TagSet(setID, name);
			}
			
		} catch( SQLException ex) { 
			connection.rollbackTransaction();
			throw new TskCoreException(String.format("Error adding report %s", name), ex);
		}
		finally {
			connection.close();
			skCase.releaseSingleUserCaseWriteLock();
		} 
		
		return tagSet;
	}
	
	/**
	 * Remove a row from the tag set table, this will also remove the tags that
	 * belong to set set from the tag_name table.
	 * 
	 * @param name
	 * 
	 * @throws TskCoreException 
	 */
	public void deletedTagSet(String name)  throws TskCoreException {
		CaseDbConnection connection = skCase.getConnection();
		skCase.acquireSingleUserCaseWriteLock();
		
		try(Statement stmt = connection.createStatement()){
			connection.beginTransaction();
			// DELETE FROM tag_sets WHERE name = '%s'
			stmt.execute(String.format(DELETE_TAG_SET, name));
			connection.commitTransaction();
		} catch( SQLException ex) { 
			connection.rollbackTransaction();
			throw new TskCoreException(String.format("Error deleting tag set %s.", name), ex);
		} finally {
			connection.close();
			skCase.releaseSingleUserCaseWriteLock();
		} 
	}

	public List<TagSet> getTagSets() {
		return null;
	}

}
