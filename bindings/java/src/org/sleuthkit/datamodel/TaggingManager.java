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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;

/**
 * Provides an API to manage Tags.
 */
public class TaggingManager {
	private final SleuthkitCase skCase;

	/**
	 * Construct a TaggingManager for the given SleuthkitCase.
	 *
	 * @param skCase The SleuthkitCase.
	 */
	TaggingManager(SleuthkitCase skCase) {
		this.skCase = skCase;
	}

	/**
	 * Returns a list of all the TagSet that exist in the case.
	 *
	 * @return A List of TagSet objects or an empty list if none were found.
	 *
	 * @throws TskCoreException
	 */
	public List<TagSet> getTagSets() throws TskCoreException {
		List<TagSet> tagSetList = new ArrayList<>();
		CaseDbConnection connection = skCase.getConnection();
		skCase.acquireSingleUserCaseWriteLock();
		String getAllTagSetsQuery = "SELECT * FROM tag_sets";
		try (Statement stmt = connection.createStatement(); ResultSet resultSet = stmt.executeQuery(getAllTagSetsQuery);) {
			while (resultSet.next()) {
				int setID = resultSet.getInt("tag_set_id");
				String setName = resultSet.getString("name");
				TagSet set = new TagSet(setID, setName);
				set.addTagNames(getTagNamesByTagSetID(setID));
				tagSetList.add(set);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error occurred getting TagSet list.", ex);
		} finally {
			connection.close();
			skCase.releaseSingleUserCaseWriteLock();
		}
		return tagSetList;
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
		if (name == null || name.isEmpty()) {
			throw new IllegalArgumentException("Error adding TagSet, TagSet name must be non-empty string.");
		}

		TagSet tagSet = null;

		CaseDbConnection connection = skCase.getConnection();
		skCase.acquireSingleUserCaseWriteLock();
		try (Statement stmt = connection.createStatement()) {
			connection.beginTransaction();
			// INSERT INTO tag_sets (name) VALUES('%s')
			stmt.execute(String.format("INSERT INTO tag_sets (name) VALUES('%s')", name));

			try (ResultSet resultSet = stmt.getGeneratedKeys()) {

				resultSet.next();
				int setID = resultSet.getInt(1);

				tagSet = new TagSet(setID, name);
			}
			connection.commitTransaction();
		} catch (SQLException ex) {
			connection.rollbackTransaction();
			throw new TskCoreException(String.format("Error adding report %s", name), ex);
		} finally {
			connection.close();
			skCase.releaseSingleUserCaseWriteLock();
		}

		return tagSet;
	}

	/**
	 * Remove a row from the tag set table. All tags belonging to the given tag
	 * set will also be removed.
	 *
	 * @param name	Name of tag set to be deleted.
	 *
	 * @throws TskCoreException
	 */
	public void deletedTagSet(String name) throws TskCoreException {
		if (name == null || name.isEmpty()) {
			throw new IllegalArgumentException("Error adding deleting TagSet, TagSet name must be non-empty string.");
		}

		CaseDbConnection connection = skCase.getConnection();
		skCase.acquireSingleUserCaseWriteLock();

		try (Statement stmt = connection.createStatement()) {
			connection.beginTransaction();
			String queryTemplate = "DELETE FROM tag_sets WHERE name = '%s'";
			stmt.execute(String.format(queryTemplate, name));
			connection.commitTransaction();
		} catch (SQLException ex) {
			connection.rollbackTransaction();
			throw new TskCoreException(String.format("Error deleting tag set %s.", name), ex);
		} finally {
			connection.close();
			skCase.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Add the given TagName to the TagSet.
	 *
	 * @param tagSet	 The tag set being added to.
	 * @param tagName	The tag name to add to the set.
	 *
	 * @throws TskCoreException
	 */
	public void addTagNameToTagSet(TagSet tagSet, TagName tagName) throws TskCoreException {
		if (tagSet == null || tagName == null) {
			throw new IllegalArgumentException("NULL value passed to addTagToTagSet");
		}

		CaseDbConnection connection = skCase.getConnection();
		skCase.acquireSingleUserCaseWriteLock();

		try (Statement stmt = connection.createStatement()) {
			connection.beginTransaction();

			String queryTemplate = "UPDATE tag_names SET tag_set_id = %d where tag_name_id = %d";
			stmt.executeUpdate(String.format(queryTemplate, tagSet.getId(), tagName.getId()));

			connection.commitTransaction();
		} catch (SQLException ex) {
			connection.rollbackTransaction();
			throw new TskCoreException(String.format("Error adding TagName (id=%d) to TagSet (id=%s)", tagName.getId(), tagSet.getId()), ex);
		} finally {
			connection.close();
			skCase.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Inserts a row into the blackboard_artifact_tags table in the case
	 * database.
	 *
	 * @param artifact The blackboard artifact to tag.
	 * @param tagName  The name to use for the tag.
	 * @param comment  A comment to store with the tag.
	 *
	 * @return A BlackboardArtifactTag data transfer object (DTO) for the new
	 *         row.
	 *
	 * @throws TskCoreException
	 */
	public BlackboardArtifactTagChange addArtifactTag(BlackboardArtifact artifact, TagName tagName, String comment) throws TskCoreException {
		if (artifact == null || tagName == null) {
			throw new IllegalArgumentException("NULL argument passed to addArtifactTag");
		}

		CaseDbConnection connection = skCase.getConnection();
		skCase.acquireSingleUserCaseWriteLock();
		List<BlackboardArtifactTag> removedTags = new ArrayList<>();
		try {
			connection.beginTransaction();
			// If a TagName is part of a TagSet remove any existing tags from the
			// set that are currenctly on the artifact
			int tagSetId = tagName.getTagSetId();
			if (tagSetId > 0) {
				// Get the list of all of the blackboardArtifactTags that use
				// TagName for the given artifact.
				String selectQuery = String.format("SELECT * from blackboard_artifact_tags JOIN tag_names ON tag_names.tag_name_id = blackboard_artifact_tags.tag_name_id JOIN tsk_examiners on tsk_examiners.examiner_id = blackboard_artifact_tags.examiner_id WHERE artifact_id = %d AND tag_names.tag_set_id = %d", artifact.getId(), tagSetId);

				try (Statement stmt = connection.createStatement(); ResultSet resultSet = stmt.executeQuery(selectQuery)) {
					while (resultSet.next()) {
						BlackboardArtifactTag bat
								= new BlackboardArtifactTag(resultSet.getLong("tag_id"),
										artifact,
										skCase.getContentById(artifact.getObjectID()),
										tagName,
										resultSet.getString("comment"),
										resultSet.getString("login_name"));

						removedTags.add(bat);
					}
				}

				if (!removedTags.isEmpty()) {
					// Remove the tags.
					String removeQuery = String.format("DELETE FROM blackboard_artifact_tags WHERE tag_id IN (SELECT tag_id FROM blackboard_artifact_tags JOIN tag_names ON tag_names.tag_name_id = blackboard_artifact_tags.tag_name_id WHERE artifact_id = %d AND tag_names.tag_set_id = %d)", artifact.getId(), tagSetId);
					try (Statement stmt = connection.createStatement()) {
						stmt.executeUpdate(removeQuery);
					}
				}
			}

			// Add the new Tag.
			BlackboardArtifactTag artifactTag = null;
			try (Statement stmt = connection.createStatement()) {
				Examiner currentExaminer = skCase.getCurrentExaminer();
				String queryTemplate = "INSERT INTO blackboard_artifact_tags (artifact_id, tag_name_id, comment, examiner_id) VALUES (%d, %d, '%s', %d)";

				stmt.executeUpdate(String.format(queryTemplate,
						artifact.getArtifactID(),
						tagName.getId(),
						comment,
						currentExaminer.getId()));

				try (ResultSet resultSet = stmt.getGeneratedKeys()) {
					resultSet.next();
					artifactTag = new BlackboardArtifactTag(resultSet.getLong(1), //last_insert_rowid()
							artifact, skCase.getContentById(artifact.getObjectID()), tagName, comment, currentExaminer.getLoginName());
				}
			}

			connection.commitTransaction();

			return new BlackboardArtifactTagChange(artifactTag, removedTags);
		} catch (SQLException ex) {
			connection.rollbackTransaction();
			throw new TskCoreException("Error adding row to blackboard_artifact_tags table (obj_id = " + artifact.getArtifactID() + ", tag_name_id = " + tagName.getId() + ")", ex);
		} finally {

			connection.close();
			skCase.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Inserts a row into the content_tags table in the case database.
	 *
	 * @param content         The content to tag.
	 * @param tagName         The name to use for the tag.
	 * @param comment         A comment to store with the tag.
	 * @param beginByteOffset Designates the beginning of a tagged section.
	 * @param endByteOffset   Designates the end of a tagged section.
	 *
	 * @return A ContentTag data transfer object (DTO) for the new row.
	 *
	 * @throws TskCoreException
	 */
	public ContentTagChange addContentTag(Content content, TagName tagName, String comment, long beginByteOffset, long endByteOffset) throws TskCoreException {
		CaseDbConnection connection = skCase.getConnection();
		List<ContentTag> removedTags = new ArrayList<>();
		skCase.acquireSingleUserCaseWriteLock();
		try {
			connection.beginTransaction();
			int tagSetId = tagName.getTagSetId();

			if (tagSetId > 0) {
				String selectQuery = String.format("SELECT * from content_tags JOIN tag_names ON tag_names.tag_name_id = content_tags.tag_name_id JOIN tsk_examiners on tsk_examiners.examiner_id = content_tags.examiner_id WHERE obj_id = %d AND tag_names.tag_set_id = %d", content.getId(), tagSetId);

				try (Statement stmt = connection.createStatement(); ResultSet resultSet = stmt.executeQuery(selectQuery)) {
					while (resultSet.next()) {
						ContentTag bat
								= new ContentTag(resultSet.getLong("tag_id"),
										content,
										tagName,
										resultSet.getString("comment"),
										resultSet.getLong("begin_byte_offset"),
										resultSet.getLong("end_byte_offset"),
										resultSet.getString("login_name"));

						removedTags.add(bat);
					}
				}

				if (!removedTags.isEmpty()) {
					String removeQuery = String.format("DELETE FROM content_tags WHERE tag_id IN (SELECT tag_id FROM content_tags JOIN tag_names ON tag_names.tag_name_id = content_tags.tag_name_id WHERE obj_id = %d AND tag_names.tag_set_id = %d)", content.getId(), tagSetId);
					try (Statement stmt = connection.createStatement()) {
						stmt.executeUpdate(removeQuery);
					}
				}
			}

			String queryTemplate = "INSERT INTO content_tags (obj_id, tag_name_id, comment, begin_byte_offset, end_byte_offset, examiner_id) VALUES (%d, %d, '%s', %d, %d, %d)";
			ContentTag contentTag = null;
			try (Statement stmt = connection.createStatement()) {
				Examiner currentExaminer = skCase.getCurrentExaminer();
				String query = String.format(queryTemplate,
						content.getId(),
						tagName.getId(),
						comment,
						beginByteOffset,
						endByteOffset,
						currentExaminer.getId());

				stmt.executeUpdate(query);

				try (ResultSet resultSet = stmt.getGeneratedKeys()) {
					resultSet.next();
					contentTag = new ContentTag(resultSet.getLong(1), //last_insert_rowid()
							content, tagName, comment, beginByteOffset, endByteOffset, currentExaminer.getLoginName());
				}
			}

			connection.commitTransaction();
			return new ContentTagChange(contentTag, removedTags);
		} catch (SQLException ex) {
			connection.rollbackTransaction();
			throw new TskCoreException("Error adding row to content_tags table (obj_id = " + content.getId() + ", tag_name_id = " + tagName.getId() + ")", ex);
		} finally {
			connection.close();
			skCase.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Returns a list of all of the TagNames that are apart of the given TagSet.
	 *
	 * @param tagSetId ID of a TagSet.
	 *
	 * @return List of TagNames for the TagSet or empty list if none were found.
	 *
	 * @throws TskCoreException
	 */
	List<TagName> getTagNamesByTagSetID(int tagSetId) throws TskCoreException {

		if (tagSetId <= 0) {
			throw new IllegalArgumentException("Invalid tagSetID passed to getTagNameByTagSetID");
		}

		List<TagName> tagNameList = new ArrayList<>();

		CaseDbConnection connection = skCase.getConnection();

		skCase.acquireSingleUserCaseReadLock();
		String query = String.format("SELECT * FROM tag_names WHERE tag_set_id = %d", tagSetId);
		try (Statement stmt = connection.createStatement(); ResultSet resultSet = stmt.executeQuery(query)) {
			while (resultSet.next()) {
				long tagId = resultSet.getLong("tag)name_id");
				String tagName = resultSet.getString("display_name");
				String description = resultSet.getString("description");
				String color = resultSet.getString("Color");
				byte knownStatus = resultSet.getByte("knowStatus");

				tagNameList.add(new TagName(tagId, tagName, description, TagName.HTML_COLOR.getColorByName(color), TskData.FileKnown.valueOf(knownStatus), tagSetId));
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting tag names for tag set (%d)", tagSetId), ex);
		} finally {
			connection.close();
			skCase.releaseSingleUserCaseReadLock();
		}

		return tagNameList;
	}

	/**
	 * Object to store the tag change from a call to addArtifactTag.
	 */
	public static class BlackboardArtifactTagChange {

		private final BlackboardArtifactTag addedTag;
		private final List<BlackboardArtifactTag> removedTagList;

		/**
		 * Construct a new artifact tag change object.
		 *
		 * @param added		 Newly created artifact tag.
		 * @param removed	List of removed tags.
		 */
		BlackboardArtifactTagChange(BlackboardArtifactTag added, List<BlackboardArtifactTag> removed) {
			this.addedTag = added;
			this.removedTagList = removed;
		}

		/**
		 * Returns the newly created tag.
		 *
		 * @return Add artifact tag.
		 */
		public BlackboardArtifactTag getAddedTag() {
			return addedTag;
		}

		/**
		 * Returns a list of the artifacts tags that were removed.
		 *
		 * @return
		 */
		public List<BlackboardArtifactTag> getRemovedTags() {
			return Collections.unmodifiableList(removedTagList);
		}
	}

	/**
	 * Object to store the tag change from a call to addContentTag.
	 */
	public static class ContentTagChange {

		private final ContentTag addedTag;
		private final List<ContentTag> removedTagList;

		/**
		 * Construct a new content tag change object.
		 *
		 * @param added		 Newly created artifact tag.
		 * @param removed	List of removed tags.
		 */
		ContentTagChange(ContentTag added, List<ContentTag> removed) {
			this.addedTag = added;
			this.removedTagList = removed;
		}

		/**
		 * Returns the newly created tag.
		 *
		 * @return Add artifact tag.
		 */
		public ContentTag getAddedTag() {
			return addedTag;
		}

		/**
		 * Returns a list of the artifacts tags that were removed.
		 *
		 * @return
		 */
		public List<ContentTag> getRemovedTags() {
			return Collections.unmodifiableList(removedTagList);
		}
	}
}
