/*
 * Sleuth Kit Data Model
 *
 * Copyright 2020-2021 Basis Technology Corp.
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

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;
import static org.sleuthkit.datamodel.TskData.DbType.POSTGRESQL;
import org.sleuthkit.datamodel.TskEvent.TagNamesAddedTskEvent;
import org.sleuthkit.datamodel.TskEvent.TagNamesDeletedTskEvent;
import org.sleuthkit.datamodel.TskEvent.TagNamesUpdatedTskEvent;
import org.sleuthkit.datamodel.TskEvent.TagSetsAddedTskEvent;
import org.sleuthkit.datamodel.TskEvent.TagSetsDeletedTskEvent;

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
	 * Returns a list of all the TagSets that exist in the case.
	 *
	 * @return A List of TagSet objects or an empty list if none were found.
	 *
	 * @throws TskCoreException
	 */
	public List<TagSet> getTagSets() throws TskCoreException {
		List<TagSet> tagSetList = new ArrayList<>();

		skCase.acquireSingleUserCaseReadLock();
		String getAllTagSetsQuery = "SELECT * FROM tsk_tag_sets";
		try (CaseDbConnection connection = skCase.getConnection(); Statement stmt = connection.createStatement(); ResultSet resultSet = stmt.executeQuery(getAllTagSetsQuery);) {
			while (resultSet.next()) {
				int setID = resultSet.getInt("tag_set_id");
				String setName = resultSet.getString("name");
				TagSet set = new TagSet(setID, setName, getTagNamesByTagSetID(setID));
				tagSetList.add(set);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error occurred getting TagSet list.", ex);
		} finally {
			skCase.releaseSingleUserCaseReadLock();
		}
		return tagSetList;
	}

	/**
	 * Inserts a row into the tag_sets table in the case database.
	 *
	 * @param name     The tag set name.
	 * @param tagNames
	 *
	 * @return A TagSet object for the new row.
	 *
	 * @throws TskCoreException
	 */
	public TagSet addTagSet(String name, List<TagName> tagNames) throws TskCoreException {
		if (name == null || name.isEmpty()) {
			throw new IllegalArgumentException("Error adding TagSet, TagSet name must be non-empty string.");
		}

		TagSet tagSet = null;

		CaseDbTransaction trans = skCase.beginTransaction();
		try (Statement stmt = trans.getConnection().createStatement()) {
			String query = String.format("INSERT INTO tsk_tag_sets (name) VALUES('%s')", name);

			if (skCase.getDatabaseType() == POSTGRESQL) {
				stmt.execute(query, Statement.RETURN_GENERATED_KEYS);
			} else {
				stmt.execute(query);
			}

			try (ResultSet resultSet = stmt.getGeneratedKeys()) {

				resultSet.next();
				int setID = resultSet.getInt(1);

				List<TagName> updatedTags = new ArrayList<>();
				if (tagNames != null) {
					// Get all of the TagName ids they can be updated in one
					// SQL call.
					for (int index = 0; index < tagNames.size(); index++) {
						TagName tagName = tagNames.get(index);
						stmt.executeUpdate(String.format("UPDATE tag_names SET tag_set_id = %d, rank = %d WHERE tag_name_id = %d", setID, index, tagName.getId()));
						updatedTags.add(new TagName(tagName.getId(),
								tagName.getDisplayName(),
								tagName.getDescription(),
								tagName.getColor(),
								tagName.getTagType(),
								setID,
								index));
					}
				}
				tagSet = new TagSet(setID, name, updatedTags);
				skCase.fireTSKEvent(new TagSetsAddedTskEvent(Collections.singletonList(tagSet)));
				skCase.fireTSKEvent(new TagNamesUpdatedTskEvent(updatedTags));
			}
			trans.commit();
		} catch (SQLException ex) {
			trans.rollback();
			throw new TskCoreException(String.format("Error adding tag set %s", name), ex);
		}

		return tagSet;
	}

	/**
	 * Remove a row from the tag set table. If the given TagSet has a valid list
	 * of TagNames the TagNames will be removed from the tag_name table if there
	 * are not references to the TagNames in the content_tag or
	 * blackboard_artifact_tag table.
	 *
	 * @param tagSet TagSet to be deleted.
	 *
	 * @throws TskCoreException
	 */
	public void deleteTagSet(TagSet tagSet) throws TskCoreException {
		if (tagSet == null) {
			throw new IllegalArgumentException("Error adding deleting TagSet, TagSet object was null");
		}

		if (isTagSetInUse(tagSet)) {
			throw new TskCoreException("Unable to delete TagSet (%d). TagSet TagName list contains TagNames that are currently in use.");
		}

		CaseDbTransaction trans = skCase.beginTransaction();
		try (Statement stmt = trans.getConnection().createStatement()) {
			String queryTemplate = "DELETE FROM tag_names WHERE tag_name_id IN (SELECT tag_name_id FROM tag_names WHERE tag_set_id = %d)";
			stmt.execute(String.format(queryTemplate, tagSet.getId()));

			queryTemplate = "DELETE FROM tsk_tag_sets WHERE tag_set_id = '%d'";
			stmt.execute(String.format(queryTemplate, tagSet.getId()));
			trans.commit();

			List<Long> tagNameIds = new ArrayList<>();
			for (TagName tagName : tagSet.getTagNames()) {
				tagNameIds.add(tagName.getId());
			}

			skCase.fireTSKEvent(new TagSetsDeletedTskEvent(Collections.singletonList(tagSet.getId())));
			skCase.fireTSKEvent(new TagNamesDeletedTskEvent(tagNameIds));
		} catch (SQLException ex) {
			trans.rollback();
			throw new TskCoreException(String.format("Error deleting tag set where id = %d.", tagSet.getId()), ex);
		}
	}

	/**
	 * Gets the tag set a tag name (tag definition) belongs to, if any.
	 *
	 * @param tagName The tag name.
	 *
	 * @return A TagSet object or null.
	 *
	 * @throws TskCoreException If there is an error querying the case database.
	 */
	public TagSet getTagSet(TagName tagName) throws TskCoreException {
		if (tagName == null) {
			throw new IllegalArgumentException("Null tagName argument");
		}

		if (tagName.getTagSetId() <= 0) {
			return null;
		}

		skCase.acquireSingleUserCaseReadLock();
		TagSet tagSet = null;
		String sqlQuery = String.format("SELECT * FROM tsk_tag_sets WHERE tag_set_id = %d", tagName.getTagSetId());
		try (CaseDbConnection connection = skCase.getConnection(); Statement stmt = connection.createStatement(); ResultSet resultSet = stmt.executeQuery(sqlQuery);) {
			if (resultSet.next()) {
				int setID = resultSet.getInt("tag_set_id");
				String setName = resultSet.getString("name");
				tagSet = new TagSet(setID, setName, getTagNamesByTagSetID(setID));
			}
			return tagSet;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error occurred getting TagSet for TagName '%s' (ID=%d)", tagName.getDisplayName(), tagName.getId()), ex);
		} finally {
			skCase.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Return a TagSet object for the given id.
	 *
	 * @param id TagSet id.
	 *
	 * @return The TagSet represented by the given it, or null if one was not
	 *         found.
	 *
	 * @throws TskCoreException
	 */
	public TagSet getTagSet(long id) throws TskCoreException {
		TagSet tagSet = null;
		String preparedQuery = "Select * FROM tsk_tag_sets WHERE tag_set_id = ?";
		skCase.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = skCase.getConnection(); PreparedStatement statement = connection.getPreparedStatement(preparedQuery, Statement.NO_GENERATED_KEYS)) {
			statement.setLong(1, id);
			try (ResultSet resultSet = statement.executeQuery()) {
				if (resultSet.next()) {
					int setID = resultSet.getInt("tag_set_id");
					String setName = resultSet.getString("name");
					tagSet = new TagSet(setID, setName, getTagNamesByTagSetID(setID));
				}
			}

		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error occurred getting TagSet (ID=%d)", id), ex);
		} finally {
			skCase.releaseSingleUserCaseReadLock();
		}

		return tagSet;
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

		List<BlackboardArtifactTag> removedTags = new ArrayList<>();
		List<String> removedTagIds = new ArrayList<>();
		CaseDbTransaction trans = null;
		try {
			// If a TagName is part of a TagSet remove any existing tags from the
			// set that are currenctly on the artifact
			long tagSetId = tagName.getTagSetId();
			if (tagSetId > 0) {
				// Get the list of all of the blackboardArtifactTags that use
				// TagName for the given artifact.
				String selectQuery = String.format("SELECT * from blackboard_artifact_tags JOIN tag_names ON tag_names.tag_name_id = blackboard_artifact_tags.tag_name_id JOIN tsk_examiners on tsk_examiners.examiner_id = blackboard_artifact_tags.examiner_id WHERE artifact_id = %d AND tag_names.tag_set_id = %d", artifact.getArtifactID(), tagSetId);
				TagName removedTag;
				try (Statement stmt = skCase.getConnection().createStatement(); ResultSet resultSet = stmt.executeQuery(selectQuery)) {
					while (resultSet.next()) {
						removedTag = new TagName(
								resultSet.getLong("tag_name_id"),
								resultSet.getString("display_name"),
								resultSet.getString("description"),
								TagName.HTML_COLOR.getColorByName(resultSet.getString("color")),
								TskData.TagType.valueOf(resultSet.getByte("knownStatus")),
								tagSetId,
								resultSet.getInt("rank")
						);

						BlackboardArtifactTag bat
								= new BlackboardArtifactTag(resultSet.getLong("tag_id"),
										artifact,
										skCase.getContentById(artifact.getObjectID()),
										removedTag,
										resultSet.getString("comment"),
										resultSet.getString("login_name"));

						removedTags.add(bat);
						removedTagIds.add(Long.toString(bat.getId()));
					}
				}

			}

			Content content = skCase.getContentById(artifact.getObjectID());
			Examiner currentExaminer = skCase.getCurrentExaminer();

			trans = skCase.beginTransaction();
			CaseDbConnection connection = trans.getConnection();

			if (!removedTags.isEmpty()) {
				// Remove the tags.
				String removeQuery = String.format("DELETE FROM blackboard_artifact_tags WHERE tag_id IN (%s)", String.join(",", removedTagIds));
				try (Statement stmt = connection.createStatement()) {
					stmt.executeUpdate(removeQuery);
				}
			}

			// Add the new Tag.
			BlackboardArtifactTag artifactTag;
			try (Statement stmt = connection.createStatement()) {

				String query = String.format(
						"INSERT INTO blackboard_artifact_tags (artifact_id, tag_name_id, comment, examiner_id) VALUES (%d, %d, '%s', %d)",
						artifact.getArtifactID(),
						tagName.getId(),
						comment,
						currentExaminer.getId());

				if (skCase.getDatabaseType() == POSTGRESQL) {
					stmt.execute(query, Statement.RETURN_GENERATED_KEYS);
				} else {
					stmt.execute(query);
				}

				try (ResultSet resultSet = stmt.getGeneratedKeys()) {
					resultSet.next();
					artifactTag = new BlackboardArtifactTag(resultSet.getLong(1), //last_insert_rowid()
							artifact, content, tagName, comment, currentExaminer.getLoginName());
				}
			}

			skCase.getScoringManager().updateAggregateScoreAfterAddition(
					artifact.getId(), artifact.getDataSourceObjectID(), getTagScore(tagName.getTagType()), trans);

			trans.commit();

			return new BlackboardArtifactTagChange(artifactTag, removedTags);
		} catch (SQLException ex) {
			if (trans != null) {
				trans.rollback();
			}
			throw new TskCoreException("Error adding row to blackboard_artifact_tags table (obj_id = " + artifact.getArtifactID() + ", tag_name_id = " + tagName.getId() + ")", ex);
		}
	}

	/**
	 * Translates the tag type into an item score. This supports scoring of
	 * tagged items.
	 *
	 * @param tagType The tag type of a tag definition.
	 *
	 * @return The corresponding item score.
	 */
	static Score getTagScore(TskData.TagType tagType) {
		switch (tagType) {
			case BAD:
				/*
				 * The "bad" tag type is used to define tags that are
				 * "notable." An item tagged with a "notable" tag is scored as
				 * notable.
				 */
				return Score.SCORE_NOTABLE;
			case SUSPICIOUS:
				return Score.SCORE_LIKELY_NOTABLE;
			case UNKNOWN:
			case KNOWN:
			default: // N/A
				/*
				 * All other tag type values have no special significance in
				 * a tag definition. 
				 */
				return Score.SCORE_UNKNOWN;
		}
	}

	/**
	 * Retrieves the maximum TagType status of any tag associated with the
	 * object id.
	 *
	 * @param objectId    The object id of the item.
	 * @param transaction The case db transaction to perform this query.
	 *
	 * @return The maximum TagType status for this object or empty.
	 *
	 * @throws TskCoreException
	 */
	Optional<TskData.TagType> getMaxTagType(long objectId, CaseDbTransaction transaction) throws TskCoreException {
		// query content tags and blackboard artifact tags for highest 
		// tag type associated with a tag associated with this object id
		String queryString = "SELECT tag_names.knownStatus AS knownStatus\n"
				+ "	FROM (\n"
				+ "		SELECT ctags.tag_name_id AS tag_name_id FROM content_tags ctags WHERE ctags.obj_id = " + objectId + "\n"
				+ "	    UNION\n"
				+ "	    SELECT btags.tag_name_id AS tag_name_id FROM blackboard_artifact_tags btags \n"
				+ "	    INNER JOIN blackboard_artifacts ba ON btags.artifact_id = ba.artifact_id\n"
				+ "	    WHERE ba.artifact_obj_id = " + objectId + "\n"
				+ "	) tag_name_ids\n"
				+ "	INNER JOIN tag_names ON tag_name_ids.tag_name_id = tag_names.tag_name_id\n"
				+ "	ORDER BY tag_names.knownStatus DESC\n"
				+ "	LIMIT 1";

		try (Statement statement = transaction.getConnection().createStatement();
				ResultSet resultSet = transaction.getConnection().executeQuery(statement, queryString);) {

			if (resultSet.next()) {
				return Optional.ofNullable(TskData.TagType.valueOf(resultSet.getByte("knownStatus")));
			} else {
				return Optional.empty();
			}

		} catch (SQLException ex) {
			throw new TskCoreException("Error getting content tag TagType for content with id: " + objectId);
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
		List<ContentTag> removedTags = new ArrayList<>();
		List<String> removedTagIds = new ArrayList<>();
		Examiner currentExaminer = skCase.getCurrentExaminer();
		CaseDbTransaction trans = skCase.beginTransaction();
		CaseDbConnection connection = trans.getConnection();

		try {
			long tagSetId = tagName.getTagSetId();

			if (tagSetId > 0) {
				String selectQuery = String.format("SELECT * from content_tags JOIN tag_names ON tag_names.tag_name_id = content_tags.tag_name_id JOIN tsk_examiners on tsk_examiners.examiner_id = content_tags.examiner_id WHERE obj_id = %d AND tag_names.tag_set_id = %d", content.getId(), tagSetId);

				try (Statement stmt = connection.createStatement(); ResultSet resultSet = stmt.executeQuery(selectQuery)) {
					while (resultSet.next()) {
						TagName removedTag = new TagName(
								resultSet.getLong("tag_name_id"),
								resultSet.getString("display_name"),
								resultSet.getString("description"),
								TagName.HTML_COLOR.getColorByName(resultSet.getString("color")),
								TskData.TagType.valueOf(resultSet.getByte("knownStatus")),
								tagSetId,
								resultSet.getInt("rank")
						);

						ContentTag bat
								= new ContentTag(resultSet.getLong("tag_id"),
										content,
										removedTag,
										resultSet.getString("comment"),
										resultSet.getLong("begin_byte_offset"),
										resultSet.getLong("end_byte_offset"),
										resultSet.getString("login_name"));

						removedTagIds.add(Long.toString(bat.getId()));
						removedTags.add(bat);
					}
				}

				if (!removedTags.isEmpty()) {
					String removeQuery = String.format("DELETE FROM content_tags WHERE tag_id IN (%s)", String.join(",", removedTagIds));
					try (Statement stmt = connection.createStatement()) {
						stmt.executeUpdate(removeQuery);
					}
				}
			}

			String queryTemplate = "INSERT INTO content_tags (obj_id, tag_name_id, comment, begin_byte_offset, end_byte_offset, examiner_id) VALUES (%d, %d, '%s', %d, %d, %d)";
			ContentTag contentTag = null;
			try (Statement stmt = connection.createStatement()) {

				String query = String.format(queryTemplate,
						content.getId(),
						tagName.getId(),
						comment,
						beginByteOffset,
						endByteOffset,
						currentExaminer.getId());

				if (skCase.getDatabaseType() == POSTGRESQL) {
					stmt.executeUpdate(query, Statement.RETURN_GENERATED_KEYS);
				} else {
					stmt.executeUpdate(query);
				}

				try (ResultSet resultSet = stmt.getGeneratedKeys()) {
					resultSet.next();
					contentTag = new ContentTag(resultSet.getLong(1), //last_insert_rowid()
							content, tagName, comment, beginByteOffset, endByteOffset, currentExaminer.getLoginName());
				}
			}

			Long dataSourceId = content.getDataSource() != null ? content.getDataSource().getId() : null;
			skCase.getScoringManager().updateAggregateScoreAfterAddition(
					content.getId(), dataSourceId, getTagScore(tagName.getTagType()), trans);

			trans.commit();
			return new ContentTagChange(contentTag, removedTags);
		} catch (SQLException ex) {
			trans.rollback();
			throw new TskCoreException("Error adding row to content_tags table (obj_id = " + content.getId() + ", tag_name_id = " + tagName.getId() + ")", ex);
		}
	}
	
	/**
	 * @return 
	 * @deprecated TaggingManager.addOrUpdateTagName(String displayName, String description, TagName.HTML_COLOR color, TskData.TagType tagType) should be used instead.
	 */
	@Deprecated
	public TagName addOrUpdateTagName(String displayName, String description, TagName.HTML_COLOR color, TskData.FileKnown knownStatus) throws TskCoreException {
		return addOrUpdateTagName(displayName, description, color, TskData.TagType.convertFileKnownToTagType(knownStatus));
	}

	/**
	 * Inserts row into the tags_names table, or updates the existing row if the
	 * displayName already exists in the tag_names table in the case database.
	 *
	 * @param displayName The display name for the new tag name.
	 * @param description The description for the new tag name.
	 * @param color       The HTML color to associate with the new tag name.
	 * @param tagType The TskData.TagType value to associate with the new
	 *                    tag name.
	 *
	 * @return A TagName data transfer object (DTO) for the new row.
	 *
	 * @throws TskCoreException
	 */
	public TagName addOrUpdateTagName(String displayName, String description, TagName.HTML_COLOR color, TskData.TagType tagType) throws TskCoreException {
		String insertQuery = "INSERT INTO tag_names (display_name, description, color, knownStatus) VALUES (?, ?, ?, ?) ON CONFLICT (display_name) DO UPDATE SET description = ?, color = ?, knownStatus = ?";
		boolean isUpdated = false;
		skCase.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = skCase.getConnection()) {
			try (PreparedStatement statement = connection.getPreparedStatement("SELECT * FROM tag_names WHERE display_name = ?", Statement.NO_GENERATED_KEYS)) {
				statement.setString(1, displayName);
				try (ResultSet resultSet = statement.executeQuery()) {
					isUpdated = resultSet.next();
				}
			}

			try (PreparedStatement statement = connection.getPreparedStatement(insertQuery, Statement.RETURN_GENERATED_KEYS);) {
				statement.clearParameters();
				statement.setString(5, description);
				statement.setString(6, color.getName());
				statement.setByte(7, tagType.getTagTypeValue());
				statement.setString(1, displayName);
				statement.setString(2, description);
				statement.setString(3, color.getName());
				statement.setByte(4, tagType.getTagTypeValue());
				statement.executeUpdate();
			}

			try (PreparedStatement statement = connection.getPreparedStatement("SELECT * FROM tag_names where display_name = ?", Statement.NO_GENERATED_KEYS)) {
				statement.setString(1, displayName);
				try (ResultSet resultSet = connection.executeQuery(statement)) {
					resultSet.next();
					TagName newTag = new TagName(resultSet.getLong("tag_name_id"), displayName, description, color, tagType, resultSet.getLong("tag_set_id"), resultSet.getInt("rank"));

					if (!isUpdated) {
						skCase.fireTSKEvent(new TagNamesAddedTskEvent(Collections.singletonList(newTag)));
					} else {
						skCase.fireTSKEvent(new TagNamesUpdatedTskEvent(Collections.singletonList(newTag)));
					}

					return newTag;
				}
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error adding row for " + displayName + " tag name to tag_names table", ex);
		} finally {
			skCase.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Return the TagName object for the given id.
	 *
	 * @param id The TagName id.
	 *
	 * @return The TagName object for the given id.
	 *
	 * @throws TskCoreException
	 */
	public TagName getTagName(long id) throws TskCoreException {
		String preparedQuery = "SELECT * FROM tag_names where tag_name_id = ?";

		skCase.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = skCase.getConnection()) {
			try (PreparedStatement statement = connection.getPreparedStatement(preparedQuery, Statement.NO_GENERATED_KEYS)) {
				statement.clearParameters();
				statement.setLong(1, id);
				try (ResultSet resultSet = statement.executeQuery()) {
					if (resultSet.next()) {
						return new TagName(resultSet.getLong("tag_name_id"),
								resultSet.getString("display_name"),
								resultSet.getString("description"),
								TagName.HTML_COLOR.getColorByName(resultSet.getString("color")),
								TskData.TagType.valueOf(resultSet.getByte("knownStatus")),
								resultSet.getLong("tag_set_id"),
								resultSet.getInt("rank"));
					}
				}
			}
		} catch (SQLException ex) {
			throw new TskCoreException("", ex);
		} finally {
			skCase.releaseSingleUserCaseReadLock();
		}

		return null;
	}

	/**
	 * Determine if the given TagSet contains TagNames that are currently in
	 * use, ie there is an existing ContentTag or ArtifactTag that uses TagName.
	 *
	 * @param tagSet The Tagset to check.
	 *
	 * @return Return true if the TagSet is in use.
	 *
	 * @throws TskCoreException
	 */
	private boolean isTagSetInUse(TagSet tagSet) throws TskCoreException {
		skCase.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = skCase.getConnection()) {
			List<TagName> tagNameList = tagSet.getTagNames();
			if (tagNameList != null && !tagNameList.isEmpty()) {
				String statement = String.format("SELECT tag_id FROM content_tags WHERE tag_name_id IN (SELECT tag_name_id FROM tag_names WHERE tag_set_id = %d)", tagSet.getId());
				try (Statement stmt = connection.createStatement(); ResultSet resultSet = stmt.executeQuery(statement)) {
					if (resultSet.next()) {
						return true;
					}
				} catch (SQLException ex) {
					throw new TskCoreException(String.format("Failed to determine if TagSet is in use (%s)", tagSet.getId()), ex);
				}

				statement = String.format("SELECT tag_id FROM blackboard_artifact_tags WHERE tag_name_id IN (SELECT tag_name_id FROM tag_names WHERE tag_set_id = %d)", tagSet.getId());
				try (Statement stmt = connection.createStatement(); ResultSet resultSet = stmt.executeQuery(statement)) {
					if (resultSet.next()) {
						return true;
					}
				} catch (SQLException ex) {
					throw new TskCoreException(String.format("Failed to determine if TagSet is in use (%s)", tagSet.getId()), ex);
				}
			}
		} finally {
			skCase.releaseSingleUserCaseReadLock();
		}

		return false;
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
	private List<TagName> getTagNamesByTagSetID(int tagSetId) throws TskCoreException {

		if (tagSetId <= 0) {
			throw new IllegalArgumentException("Invalid tagSetID passed to getTagNameByTagSetID");
		}

		List<TagName> tagNameList = new ArrayList<>();

		skCase.acquireSingleUserCaseReadLock();
		String query = String.format("SELECT * FROM tag_names WHERE tag_set_id = %d", tagSetId);
		try (CaseDbConnection connection = skCase.getConnection(); Statement stmt = connection.createStatement(); ResultSet resultSet = stmt.executeQuery(query)) {
			while (resultSet.next()) {
				tagNameList.add(new TagName(resultSet.getLong("tag_name_id"),
						resultSet.getString("display_name"),
						resultSet.getString("description"),
						TagName.HTML_COLOR.getColorByName(resultSet.getString("color")),
						TskData.TagType.valueOf(resultSet.getByte("knownStatus")),
						tagSetId,
						resultSet.getInt("rank")));
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting tag names for tag set (%d)", tagSetId), ex);
		} finally {
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
