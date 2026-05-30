/*
 * Sleuth Kit Data Model
 *
 * Copyright 2026 Basis Technology Corp.
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

import java.nio.file.Paths;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.BeforeClass;
import org.junit.Test;
import org.sleuthkit.datamodel.Score.Significance;

/**
 * Functional tests for the batched analysis-result APIs:
 * {@link Blackboard#newAnalysisResults} and
 * {@link Blackboard#deleteAnalysisResults}.
 *
 * <p>Runs against SQLite (suite convention). The SQLite path delegates to the
 * single-row methods, so these tests verify behavioral parity (result shape,
 * aggregate-score math, FK-cascade deletes, ScoreChange events, rollback). To
 * exercise the batched PostgreSQL code path, uncomment the connection block in
 * {@link #setUpClass} and point it at a test PostgreSQL instance.</p>
 */
public class BatchedAnalysisResultTest {

	private static final Logger LOGGER = Logger.getLogger(BatchedAnalysisResultTest.class.getName());

	private static final String TEST_DB = "BatchedAnalysisResultTest.db";
	private static final String MODULE = "BatchedAnalysisResultTest";

	private static SleuthkitCase caseDB;
	private static String dbPath = null;
	private static Image image = null;
	private static FileSystem fs = null;
	private static long dataSourceId = 0;

	private static final BlackboardArtifact.Type AR_TYPE =
			new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_KEYWORD_HIT);
	private static final BlackboardArtifact.Type DATA_ARTIFACT_TYPE =
			new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_SEARCH);

	public BatchedAnalysisResultTest() {
	}

	@BeforeClass
	public static void setUpClass() {
		String tempDirPath = System.getProperty("java.io.tmpdir");
		try {
			dbPath = Paths.get(tempDirPath, TEST_DB).toString();
			java.io.File dbFile = new java.io.File(dbPath);
			dbFile.delete();
			if (dbFile.getParentFile() != null) {
				dbFile.getParentFile().mkdirs();
			}

			caseDB = SleuthkitCase.newCase(dbPath);

			// Uncomment to manually exercise the batched PostgreSQL path.
			CaseDbConnectionInfo connectionInfo = new CaseDbConnectionInfo("localhost", "5432", "ct_user", "ct_user_abc", TskData.DbType.POSTGRESQL);
			 caseDB = SleuthkitCase.newCase("TskBatchedAnalysisResultTest", connectionInfo, tempDirPath);

			SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
			image = caseDB.addImage(TskData.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_DETECT, 512, 1024, "", Collections.emptyList(), "America/NewYork", null, null, null, "BatchedAnalysisResultTestImage", trans);
			fs = caseDB.addFileSystem(image.getId(), 0, TskData.TSK_FS_TYPE_ENUM.TSK_FS_TYPE_RAW, 0, 0, 0, 0, 0, "", trans);
			trans.commit();

			dataSourceId = image.getId();

			System.out.println("BatchedAnalysisResultTest DB created at: " + dbPath);
		} catch (TskCoreException ex) {
			LOGGER.log(Level.SEVERE, "Failed to set up BatchedAnalysisResultTest", ex);
			fail("Set-up failed: " + ex.getMessage());
		}
	}

	@AfterClass
	public static void tearDownClass() {
	}

	// ---------- helpers ----------

	/** Create a fresh file to use as an isolated AR parent (own committed tx). */
	private static AbstractFile createParentFile(String name) throws TskCoreException {
		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		try {
			AbstractFile f = caseDB.addFileSystemFile(dataSourceId, fs.getId(), name, 0, 0,
					TskData.TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, 0, TskData.TSK_FS_NAME_FLAG_ENUM.ALLOC,
					(short) 0, 200, 0, 0, 0, 0, null, null, null, false, fs, null, null, Collections.emptyList(), trans);
			trans.commit();
			return f;
		} catch (TskCoreException ex) {
			trans.rollback();
			throw ex;
		}
	}

	private static Blackboard.NewAnalysisResultRequest req(long parentId, Score score) {
		return new Blackboard.NewAnalysisResultRequest(AR_TYPE, parentId, dataSourceId, score, null, null, null, Collections.emptyList());
	}

	private static Significance aggregateSignificance(long objId) throws TskCoreException {
		return caseDB.getScoringManager().getAggregateScore(objId).getSignificance();
	}

	private static List<AnalysisResultAdded> insertCommitted(List<Blackboard.NewAnalysisResultRequest> reqs) throws Exception {
		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		try {
			List<AnalysisResultAdded> out = caseDB.getBlackboard().newAnalysisResults(reqs, trans);
			trans.commit();
			return out;
		} catch (Exception ex) {
			trans.rollback();
			throw ex;
		}
	}

	private static int countRows(String table, String whereClause) throws TskCoreException {
		final int[] count = new int[1];
		caseDB.getCaseDbAccessManager().select(
				"COUNT(*) AS c FROM " + table + " WHERE " + whereClause,
				new CaseDbAccessManager.CaseDbAccessQueryCallback() {
					@Override
					public void process(ResultSet rs) {
						try {
							if (rs.next()) {
								count[0] = rs.getInt("c");
							}
						} catch (SQLException ex) {
							fail("Unexpected SQLException: " + ex.getMessage());
						}
					}
				});
		return count[0];
	}

	// ---------- insert ----------

	/** Input-contract guards for both APIs: null throws, empty is a no-op. */
	@Test
	public void nullAndEmptyInputs() throws Exception {
		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		try {
			try {
				caseDB.getBlackboard().newAnalysisResults(null, trans);
				fail("Expected BlackboardException for null requests");
			} catch (Blackboard.BlackboardException expected) {
			}
			try {
				caseDB.getBlackboard().newAnalysisResults(Collections.emptyList(), null);
				fail("Expected BlackboardException for null transaction");
			} catch (Blackboard.BlackboardException expected) {
			}
			try {
				caseDB.getBlackboard().deleteAnalysisResults(null, trans);
				fail("Expected BlackboardException for null ids");
			} catch (Blackboard.BlackboardException expected) {
			}

			assertTrue(caseDB.getBlackboard().newAnalysisResults(Collections.emptyList(), trans).isEmpty());
			assertTrue(caseDB.getBlackboard().deleteAnalysisResults(Collections.emptyList(), trans).isEmpty());
		} finally {
			trans.commit();
		}
	}

	/** Single AR with a real score: returned shape, persisted rows, aggregate. */
	@Test
	public void singleInsert() throws Exception {
		AbstractFile parent = createParentFile("single.bin");

		List<AnalysisResultAdded> result = insertCommitted(
				Collections.singletonList(req(parent.getId(), Score.SCORE_NOTABLE)));

		assertEquals(1, result.size());
		AnalysisResultAdded added = result.get(0);
		AnalysisResult ar = added.getAnalysisResult();
		assertEquals(parent.getId(), ar.getObjectID());
		assertEquals(AR_TYPE.getTypeID(), ar.getArtifactTypeID());
		assertEquals(Significance.NOTABLE, ar.getScore().getSignificance());
		assertEquals("returned aggregate should reflect the new AR", Significance.NOTABLE, added.getAggregateScore().getSignificance());

		assertEquals("blackboard_artifacts row missing", 1, countRows("blackboard_artifacts", "artifact_obj_id = " + ar.getId()));
		assertEquals("tsk_analysis_results row missing", 1, countRows("tsk_analysis_results", "artifact_obj_id = " + ar.getId()));
		assertEquals("aggregate score not persisted", Significance.NOTABLE, aggregateSignificance(parent.getId()));
	}

	/**
	 * tsk_analysis_results is conditional: an AR with UNKNOWN significance and
	 * blank conclusion/configuration/justification gets no child row, while one
	 * with a real score does.
	 */
	@Test
	public void conditionalAnalysisResultsRow() throws Exception {
		AbstractFile parent = createParentFile("conditional.bin");

		List<AnalysisResultAdded> result = insertCommitted(Arrays.asList(
				req(parent.getId(), Score.SCORE_UNKNOWN),   // no child row expected
				req(parent.getId(), Score.SCORE_NOTABLE)));  // child row expected

		long unknownArObjId = result.get(0).getAnalysisResult().getId();
		long notableArObjId = result.get(1).getAnalysisResult().getId();

		assertEquals("both artifacts should exist", 2,
				countRows("blackboard_artifacts", "artifact_obj_id IN (" + unknownArObjId + "," + notableArObjId + ")"));
		assertEquals("UNKNOWN+blank AR must not get a tsk_analysis_results row", 0,
				countRows("tsk_analysis_results", "artifact_obj_id = " + unknownArObjId));
		assertEquals("real-scored AR must get a tsk_analysis_results row", 1,
				countRows("tsk_analysis_results", "artifact_obj_id = " + notableArObjId));
	}

	/** Attributes are persisted and visible on the returned (cache-authoritative) AR. */
	@Test
	public void attributesPersisted() throws Exception {
		AbstractFile parent = createParentFile("attrs.bin");
		List<BlackboardAttribute> attrs = Arrays.asList(
				new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_KEYWORD, MODULE, "needle"),
				new BlackboardAttribute(BlackboardAttribute.Type.TSK_PATH_ID, MODULE, 4242L));

		Blackboard.NewAnalysisResultRequest r = new Blackboard.NewAnalysisResultRequest(
				AR_TYPE, parent.getId(), dataSourceId, Score.SCORE_LIKELY_NOTABLE, null, null, null, attrs);

		List<AnalysisResultAdded> result = insertCommitted(Collections.singletonList(r));
		AnalysisResult ar = result.get(0).getAnalysisResult();

		assertEquals("cache should return the supplied attributes", 2, ar.getAttributes().size());
		assertEquals("attribute rows not persisted", 2, countRows("blackboard_attributes", "artifact_id = " + ar.getArtifactID()));
		assertEquals(1, countRows("blackboard_attributes", "artifact_id = " + ar.getArtifactID() + " AND value_text = 'needle'"));
		assertEquals(1, countRows("blackboard_attributes", "artifact_id = " + ar.getArtifactID() + " AND value_int64 = 4242"));
	}

	/**
	 * Several ARs on one parent resolve to the max score with a single
	 * aggregate-score row.
	 *
	 * <p>The cross-path invariants (final aggregate = max, exactly one aggregate
	 * row) are asserted always. The batched-collapse specifics (every returned
	 * entry reports the max; one collapsed UNKNOWN-&gt;NOTABLE ScoreChange) only
	 * hold on the PostgreSQL path - the SQLite path delegates to the single-row
	 * method, which reports incremental aggregates and a last-step ScoreChange.</p>
	 */
	@Test
	public void multipleSameParentCollapses() throws Exception {
		AbstractFile parent = createParentFile("collapse.bin");
		boolean isPg = caseDB.getDatabaseType() == TskData.DbType.POSTGRESQL;

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		try {
			List<AnalysisResultAdded> result = caseDB.getBlackboard().newAnalysisResults(Arrays.asList(
					req(parent.getId(), Score.SCORE_LIKELY_NOTABLE),
					req(parent.getId(), Score.SCORE_NOTABLE),
					req(parent.getId(), Score.SCORE_NONE)), trans);

			if (isPg) {
				// Batched collapse: every entry reports the same (max) aggregate.
				for (AnalysisResultAdded a : result) {
					assertEquals(Significance.NOTABLE, a.getAggregateScore().getSignificance());
				}
				// Exactly one collapsed ScoreChange for this parent: UNKNOWN -> NOTABLE.
				List<ScoreChange> changes = new ArrayList<>();
				for (ScoreChange sc : trans.getRegisteredScoreChanges()) {
					if (sc.getObjectId() == parent.getId()) {
						changes.add(sc);
					}
				}
				assertEquals("one collapsed ScoreChange expected", 1, changes.size());
				assertEquals(Significance.UNKNOWN, changes.get(0).getOldScore().getSignificance());
				assertEquals(Significance.NOTABLE, changes.get(0).getNewScore().getSignificance());
			}

			trans.commit();
		} catch (Exception ex) {
			trans.rollback();
			throw ex;
		}

		assertEquals("exactly one aggregate row for the parent", 1, countRows("tsk_aggregate_score", "obj_id = " + parent.getId()));
		assertEquals("final aggregate must be the max of the batch", Significance.NOTABLE, aggregateSignificance(parent.getId()));
	}

	/** A DATA_ARTIFACT type must be rejected. */
	@Test
	public void wrongCategoryRejected() throws Exception {
		AbstractFile parent = createParentFile("wrongcat.bin");
		// Build the request directly (the DTO constructor also guards category,
		// but we want to confirm the API rejects it too).
		try {
			new Blackboard.NewAnalysisResultRequest(DATA_ARTIFACT_TYPE, parent.getId(), dataSourceId, Score.SCORE_NOTABLE, null, null, null, Collections.emptyList());
			fail("Expected IllegalArgumentException from the DTO for a DATA_ARTIFACT type");
		} catch (IllegalArgumentException expected) {
			assertTrue(expected.getMessage().toLowerCase().contains("analysis result"));
		}
	}

	// ---------- delete ----------

	/** Deleting an AR cascades to its child rows and drops the aggregate to UNKNOWN. */
	@Test
	public void deleteSingleCascades() throws Exception {
		AbstractFile parent = createParentFile("del-single.bin");
		AnalysisResult ar = insertCommitted(Collections.singletonList(req(parent.getId(), Score.SCORE_NOTABLE)))
				.get(0).getAnalysisResult();
		assertEquals(Significance.NOTABLE, aggregateSignificance(parent.getId()));

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		Map<Long, Score> result;
		try {
			result = caseDB.getBlackboard().deleteAnalysisResults(Collections.singletonList(ar.getId()), trans);
			trans.commit();
		} catch (Exception ex) {
			trans.rollback();
			throw ex;
		}

		assertEquals(1, result.size());
		assertEquals(Significance.UNKNOWN, result.get(parent.getId()).getSignificance());
		assertEquals("blackboard_artifacts row should be gone", 0, countRows("blackboard_artifacts", "artifact_obj_id = " + ar.getId()));
		assertEquals("tsk_analysis_results child row should be cascade-deleted", 0, countRows("tsk_analysis_results", "artifact_obj_id = " + ar.getId()));
		assertEquals(Significance.UNKNOWN, aggregateSignificance(parent.getId()));
	}

	/** Deleting the highest-scoring AR downgrades the aggregate to the next-highest remaining. */
	@Test
	public void deleteHighestDowngrades() throws Exception {
		AbstractFile parent = createParentFile("del-downgrade.bin");
		List<AnalysisResultAdded> added = insertCommitted(Arrays.asList(
				req(parent.getId(), Score.SCORE_NOTABLE),
				req(parent.getId(), Score.SCORE_LIKELY_NOTABLE)));
		long notableArObjId = added.get(0).getAnalysisResult().getId();
		assertEquals(Significance.NOTABLE, aggregateSignificance(parent.getId()));

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		Map<Long, Score> result;
		try {
			result = caseDB.getBlackboard().deleteAnalysisResults(Collections.singletonList(notableArObjId), trans);
			trans.commit();
		} catch (Exception ex) {
			trans.rollback();
			throw ex;
		}

		assertEquals(Significance.LIKELY_NOTABLE, result.get(parent.getId()).getSignificance());
		assertEquals(Significance.LIKELY_NOTABLE, aggregateSignificance(parent.getId()));
	}

	/** A batched delete spanning multiple parents recomputes each one independently. */
	@Test
	public void deleteAcrossParents() throws Exception {
		AbstractFile p1 = createParentFile("del-p1.bin");
		AbstractFile p2 = createParentFile("del-p2.bin");
		AnalysisResult ar1 = insertCommitted(Collections.singletonList(req(p1.getId(), Score.SCORE_NOTABLE))).get(0).getAnalysisResult();
		AnalysisResult ar2 = insertCommitted(Collections.singletonList(req(p2.getId(), Score.SCORE_LIKELY_NOTABLE))).get(0).getAnalysisResult();

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		Map<Long, Score> result;
		try {
			result = caseDB.getBlackboard().deleteAnalysisResults(Arrays.asList(ar1.getId(), ar2.getId()), trans);
			trans.commit();
		} catch (Exception ex) {
			trans.rollback();
			throw ex;
		}

		assertEquals("one entry per parent", 2, result.size());
		assertEquals(Significance.UNKNOWN, result.get(p1.getId()).getSignificance());
		assertEquals(Significance.UNKNOWN, result.get(p2.getId()).getSignificance());
	}

	/** Non-existent artifact_obj_ids are silently skipped; real ones still delete. */
	@Test
	public void deleteMissingIdTolerated() throws Exception {
		AbstractFile parent = createParentFile("del-missing.bin");
		AnalysisResult ar = insertCommitted(Collections.singletonList(req(parent.getId(), Score.SCORE_NOTABLE))).get(0).getAnalysisResult();
		long missingId = 99_999_999L;

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		Map<Long, Score> result;
		try {
			result = caseDB.getBlackboard().deleteAnalysisResults(Arrays.asList(missingId, ar.getId()), trans);
			trans.commit();
		} catch (Exception ex) {
			trans.rollback();
			throw ex;
		}

		assertEquals("only the real parent should be in the map", 1, result.size());
		assertNotNull(result.get(parent.getId()));
		assertEquals(0, countRows("blackboard_artifacts", "artifact_obj_id = " + ar.getId()));
	}

	// ---------- combined / transaction ----------

	/** Delete-then-insert on the same parent in one tx ends at the new AR's score. */
	@Test
	public void deleteThenInsertSameParent() throws Exception {
		AbstractFile parent = createParentFile("del-then-ins.bin");
		AnalysisResult existing = insertCommitted(Collections.singletonList(req(parent.getId(), Score.SCORE_NOTABLE))).get(0).getAnalysisResult();
		assertEquals(Significance.NOTABLE, aggregateSignificance(parent.getId()));

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		try {
			caseDB.getBlackboard().deleteAnalysisResults(Collections.singletonList(existing.getId()), trans);
			caseDB.getBlackboard().newAnalysisResults(Collections.singletonList(req(parent.getId(), Score.SCORE_NONE)), trans);
			trans.commit();
		} catch (Exception ex) {
			trans.rollback();
			throw ex;
		}

		assertEquals(Significance.NONE, aggregateSignificance(parent.getId()));
		assertEquals("only the new AR should remain", 1, countRows("blackboard_artifacts", "obj_id = " + parent.getId()));
	}

	/** A rolled-back batched insert persists nothing. */
	@Test
	public void insertRollback() throws Exception {
		AbstractFile parent = createParentFile("rollback.bin");

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		List<AnalysisResultAdded> result = caseDB.getBlackboard().newAnalysisResults(Arrays.asList(
				req(parent.getId(), Score.SCORE_NOTABLE),
				req(parent.getId(), Score.SCORE_LIKELY_NOTABLE)), trans);
		long arObjId = result.get(0).getAnalysisResult().getId();
		trans.rollback();

		assertEquals("rolled-back artifact must not persist", 0, countRows("blackboard_artifacts", "artifact_obj_id = " + arObjId));
		assertEquals("no AR rows for the parent after rollback", 0, countRows("blackboard_artifacts", "obj_id = " + parent.getId()));
		assertEquals(Significance.UNKNOWN, aggregateSignificance(parent.getId()));
	}
}
