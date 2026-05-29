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
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests for Blackboard#newDataArtifacts, the bulk variant of
 * Blackboard#newDataArtifact.
 *
 * <p>Default execution runs against SQLite (per the suite convention). To
 * exercise the batched PostgreSQL code path, uncomment the connection block
 * in {@link #setUpClass} and point it at a test PostgreSQL instance.</p>
 */
public class BatchedArtifactTest {

	private static final Logger LOGGER = Logger.getLogger(BatchedArtifactTest.class.getName());

	private static final String TEST_DB = "BatchedArtifactTest.db";

	private static SleuthkitCase caseDB;
	private static String dbPath = null;
	private static Image image = null;
	private static FileSystem fs = null;
	private static FsContent rootFile = null;
	private static OsAccount osAccount1 = null;
	private static OsAccount osAccount2 = null;

	public BatchedArtifactTest() {
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
			// CaseDbConnectionInfo connectionInfo = new CaseDbConnectionInfo("localhost", "5432", "ct_user", "ct_user_abc", TskData.DbType.POSTGRESQL);
			//  caseDB = SleuthkitCase.newCase("TskBatchedArtifactTest", connectionInfo, tempDirPath);

			SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();

			image = caseDB.addImage(TskData.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_DETECT, 512, 1024, "", Collections.emptyList(), "America/NewYork", null, null, null, "BatchedArtifactTestImage", trans);
			fs = caseDB.addFileSystem(image.getId(), 0, TskData.TSK_FS_TYPE_ENUM.TSK_FS_TYPE_RAW, 0, 0, 0, 0, 0, "", trans);

			// fs.getDataSource() isn't populated until after commit; use image.getId() directly.
			long dataSourceObjectId = image.getId();
			rootFile = caseDB.addFileSystemFile(dataSourceObjectId, fs.getId(), "root.bin", 0, 0,
					TskData.TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, 0, TskData.TSK_FS_NAME_FLAG_ENUM.ALLOC,
					(short) 0, 200, 0, 0, 0, 0, null, null, null, false, fs, null, null, Collections.emptyList(), trans);

			trans.commit();

			// Create OS accounts for tests that exercise the tsk_data_artifacts side-effect.
			Host host = caseDB.getHostManager().newHost("batched-test-host");
			String realmName = "batched-test-realm";
			String acct1Sid = "S-1-5-21-111111111-222222222-3333333333-1001";
			String acct2Sid = "S-1-5-21-111111111-222222222-3333333333-1002";
			caseDB.getOsAccountRealmManager().newWindowsRealm(acct1Sid, realmName, host, OsAccountRealm.RealmScope.LOCAL);
			osAccount1 = caseDB.getOsAccountManager().newWindowsOsAccount(acct1Sid, null, realmName, host, OsAccountRealm.RealmScope.LOCAL);
			osAccount2 = caseDB.getOsAccountManager().newWindowsOsAccount(acct2Sid, null, realmName, host, OsAccountRealm.RealmScope.LOCAL);

			System.out.println("BatchedArtifactTest DB created at: " + dbPath);
		} catch (TskCoreException | OsAccountManager.NotUserSIDException ex) {
			LOGGER.log(Level.SEVERE, "Failed to set up BatchedArtifactTest", ex);
		}
	}

	@AfterClass
	public static void tearDownClass() {
	}

	// ---------- DB verification helpers ----------

	/** Count rows matching {@code whereClause} (no leading WHERE) on the given table. */
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

	/** Read a single long column from a row identified by the given WHERE clause. */
	private static long selectLong(String column, String table, String whereClause) throws TskCoreException {
		final long[] value = new long[]{Long.MIN_VALUE};
		caseDB.getCaseDbAccessManager().select(
				column + " FROM " + table + " WHERE " + whereClause,
				new CaseDbAccessManager.CaseDbAccessQueryCallback() {
					@Override
					public void process(ResultSet rs) {
						try {
							if (rs.next()) {
								value[0] = rs.getLong(column);
							}
						} catch (SQLException ex) {
							fail("Unexpected SQLException: " + ex.getMessage());
						}
					}
				});
		return value[0];
	}

	/** Join a list of longs as a comma-separated SQL IN-clause body. */
	private static String inList(List<Long> ids) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < ids.size(); i++) {
			if (i > 0) sb.append(',');
			sb.append(ids.get(i));
		}
		return sb.toString();
	}

	/**
	 * Null and empty input guards.
	 */
	@Test
	public void nullAndEmptyInputs() throws TskCoreException {
		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		try {
			try {
				caseDB.getBlackboard().newDataArtifacts(null, trans);
				fail("Expected TskCoreException for null requests");
			} catch (TskCoreException expected) {
			}

			try {
				caseDB.getBlackboard().newDataArtifacts(Collections.emptyList(), null);
				fail("Expected TskCoreException for null transaction");
			} catch (TskCoreException expected) {
			}

			List<DataArtifact> empty = caseDB.getBlackboard().newDataArtifacts(Collections.emptyList(), trans);
			assertNotNull(empty);
			assertEquals(0, empty.size());
		} finally {
			trans.commit();
		}
	}

	/**
	 * Single-request happy path; verify the returned DataArtifact has the
	 * fields the caller supplied.
	 */
	@Test
	public void singleRequest() throws TskCoreException {
		BlackboardArtifact.Type type = new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_SEARCH);
		Long dataSourceId = fs.getDataSource().getId();

		Blackboard.NewDataArtifactRequest req = new Blackboard.NewDataArtifactRequest(
				type, rootFile.getId(), dataSourceId, Collections.emptyList(), null, null);

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		List<DataArtifact> result;
		try {
			result = caseDB.getBlackboard().newDataArtifacts(Collections.singletonList(req), trans);
			trans.commit();
		} catch (TskCoreException ex) {
			trans.rollback();
			throw ex;
		}

		assertEquals(1, result.size());
		DataArtifact a = result.get(0);
		assertEquals(rootFile.getId(), a.getObjectID());
		assertEquals(dataSourceId, a.getDataSourceObjectID());
		assertEquals(type.getTypeID(), a.getArtifactTypeID());

		// DB-level: confirm the rows are actually persisted.
		assertEquals("tsk_objects row missing", 1, countRows("tsk_objects", "obj_id = " + a.getId()));
		assertEquals("tsk_objects par_obj_id mismatch", rootFile.getId(), selectLong("par_obj_id", "tsk_objects", "obj_id = " + a.getId()));

		assertEquals("blackboard_artifacts row missing", 1, countRows("blackboard_artifacts", "artifact_id = " + a.getArtifactID()));
		assertEquals("blackboard_artifacts.obj_id mismatch", rootFile.getId(), selectLong("obj_id", "blackboard_artifacts", "artifact_id = " + a.getArtifactID()));
		assertEquals("blackboard_artifacts.artifact_obj_id mismatch", a.getId(), selectLong("artifact_obj_id", "blackboard_artifacts", "artifact_id = " + a.getArtifactID()));
		assertEquals("blackboard_artifacts.data_source_obj_id mismatch", (long) dataSourceId, selectLong("data_source_obj_id", "blackboard_artifacts", "artifact_id = " + a.getArtifactID()));
		assertEquals("blackboard_artifacts.artifact_type_id mismatch", type.getTypeID(), selectLong("artifact_type_id", "blackboard_artifacts", "artifact_id = " + a.getArtifactID()));

		// No osAccount in this request, so no tsk_data_artifacts row.
		assertEquals("unexpected tsk_data_artifacts row", 0, countRows("tsk_data_artifacts", "artifact_obj_id = " + a.getId()));

		// Parent bitset must be updated for the source (the rootFile that
		// became a parent when this artifact was attached to it).
		assertTrue("parent has-children bit not set", caseDB.getHasChildren(rootFile));
	}

	/**
	 * Mixed artifact types: each returned artifact must carry its request's type.
	 */
	@Test
	public void mixedArtifactTypes() throws TskCoreException {
		BlackboardArtifact.Type gps = new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_SEARCH);
		BlackboardArtifact.Type clip = new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_CLIPBOARD_CONTENT);
		BlackboardArtifact.Type area = new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_AREA);
		Long dataSourceId = fs.getDataSource().getId();

		List<Blackboard.NewDataArtifactRequest> reqs = Arrays.asList(
				new Blackboard.NewDataArtifactRequest(gps, rootFile.getId(), dataSourceId, Collections.emptyList(), null, null),
				new Blackboard.NewDataArtifactRequest(clip, rootFile.getId(), dataSourceId, Collections.emptyList(), null, null),
				new Blackboard.NewDataArtifactRequest(area, rootFile.getId(), dataSourceId, Collections.emptyList(), null, null),
				new Blackboard.NewDataArtifactRequest(gps, rootFile.getId(), dataSourceId, Collections.emptyList(), null, null));

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		List<DataArtifact> result;
		try {
			result = caseDB.getBlackboard().newDataArtifacts(reqs, trans);
			trans.commit();
		} catch (TskCoreException ex) {
			trans.rollback();
			throw ex;
		}

		assertEquals(4, result.size());
		assertEquals(gps.getTypeID(), result.get(0).getArtifactTypeID());
		assertEquals(clip.getTypeID(), result.get(1).getArtifactTypeID());
		assertEquals(area.getTypeID(), result.get(2).getArtifactTypeID());
		assertEquals(gps.getTypeID(), result.get(3).getArtifactTypeID());

		// DB-level: each returned artifact must be present in blackboard_artifacts
		// with the type-id we asked for, and each must have a tsk_objects row.
		List<Long> artifactIds = new ArrayList<>();
		List<Long> objIds = new ArrayList<>();
		for (DataArtifact a : result) {
			artifactIds.add(a.getArtifactID());
			objIds.add(a.getId());
		}
		assertEquals(4, countRows("blackboard_artifacts", "artifact_id IN (" + inList(artifactIds) + ")"));
		assertEquals(4, countRows("tsk_objects", "obj_id IN (" + inList(objIds) + ")"));

		// Per-row type check.
		for (int i = 0; i < result.size(); i++) {
			long readType = selectLong("artifact_type_id", "blackboard_artifacts", "artifact_id = " + result.get(i).getArtifactID());
			assertEquals("type mismatch for row " + i, result.get(i).getArtifactTypeID(), readType);
		}

		// No osAccounts → no tsk_data_artifacts rows.
		assertEquals(0, countRows("tsk_data_artifacts", "artifact_obj_id IN (" + inList(objIds) + ")"));
	}

	/**
	 * Mixed osAccountObjId: requests with non-null osAccount should produce
	 * tsk_data_artifacts rows; requests without should not.
	 */
	@Test
	public void mixedOsAccount() throws TskCoreException {
		BlackboardArtifact.Type type = new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_SEARCH);
		Long dataSourceId = fs.getDataSource().getId();

		List<Blackboard.NewDataArtifactRequest> reqs = Arrays.asList(
				new Blackboard.NewDataArtifactRequest(type, rootFile.getId(), dataSourceId, Collections.emptyList(), osAccount1.getId(), null),
				new Blackboard.NewDataArtifactRequest(type, rootFile.getId(), dataSourceId, Collections.emptyList(), null, null),
				new Blackboard.NewDataArtifactRequest(type, rootFile.getId(), dataSourceId, Collections.emptyList(), osAccount2.getId(), null),
				new Blackboard.NewDataArtifactRequest(type, rootFile.getId(), dataSourceId, Collections.emptyList(), null, null));

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		List<DataArtifact> result;
		try {
			result = caseDB.getBlackboard().newDataArtifacts(reqs, trans);
			trans.commit();
		} catch (TskCoreException ex) {
			trans.rollback();
			throw ex;
		}

		assertEquals(4, result.size());

		// The returned artifacts carry the osAccountObjId from the request via the
		// DataArtifact constructor's last-but-one parameter. Verify via the
		// optional accessor.
		assertTrue(result.get(0).getOsAccountObjectId().isPresent());
		assertTrue(result.get(1).getOsAccountObjectId().isEmpty());
		assertTrue(result.get(2).getOsAccountObjectId().isPresent());
		assertTrue(result.get(3).getOsAccountObjectId().isEmpty());

		// DB-level: 4 rows in blackboard_artifacts; exactly 2 in tsk_data_artifacts.
		List<Long> artifactIds = new ArrayList<>();
		List<Long> objIds = new ArrayList<>();
		for (DataArtifact a : result) {
			artifactIds.add(a.getArtifactID());
			objIds.add(a.getId());
		}
		assertEquals(4, countRows("blackboard_artifacts", "artifact_id IN (" + inList(artifactIds) + ")"));
		assertEquals("tsk_data_artifacts should have rows only for the 2 osAccount requests",
				2, countRows("tsk_data_artifacts", "artifact_obj_id IN (" + inList(objIds) + ")"));

		// The two persisted os_account_obj_id values must be exactly {osAccount1, osAccount2}.
		final Set<Long> persistedOsAccts = new HashSet<>();
		caseDB.getCaseDbAccessManager().select(
				"os_account_obj_id FROM tsk_data_artifacts WHERE artifact_obj_id IN (" + inList(objIds) + ")",
				new CaseDbAccessManager.CaseDbAccessQueryCallback() {
					@Override
					public void process(ResultSet rs) {
						try {
							while (rs.next()) {
								persistedOsAccts.add(rs.getLong("os_account_obj_id"));
							}
						} catch (SQLException ex) {
							fail("Unexpected SQLException: " + ex.getMessage());
						}
					}
				});
		Set<Long> expectedOsAccts = new HashSet<>();
		expectedOsAccts.add(osAccount1.getId());
		expectedOsAccts.add(osAccount2.getId());
		assertEquals(expectedOsAccts, persistedOsAccts);
	}

	/**
	 * Attributes covering multiple value types are persisted and visible via
	 * the artifact's in-memory cache.
	 */
	@Test
	public void withAttributesAcrossValueTypes() throws TskCoreException {
		BlackboardArtifact.Type type = new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_SEARCH);
		Long dataSourceId = fs.getDataSource().getId();
		final String moduleName = "BatchedArtifactTest";

		List<BlackboardAttribute> attrs = new ArrayList<>();
		// STRING
		attrs.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_KEYWORD, moduleName, "needle"));
		// INTEGER
		attrs.add(new BlackboardAttribute(BlackboardAttribute.Type.TSK_MALWARE_DETECTED, moduleName, 1));
		// LONG
		attrs.add(new BlackboardAttribute(BlackboardAttribute.Type.TSK_PATH_ID, moduleName, 9999L));
		// DOUBLE
		attrs.add(new BlackboardAttribute(BlackboardAttribute.Type.TSK_ENTROPY, moduleName, 3.14));
		// DATETIME (uses LONG storage)
		attrs.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME, moduleName, 1700000000L));

		Blackboard.NewDataArtifactRequest req = new Blackboard.NewDataArtifactRequest(
				type, rootFile.getId(), dataSourceId, attrs, null, null);

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		List<DataArtifact> result;
		try {
			result = caseDB.getBlackboard().newDataArtifacts(Collections.singletonList(req), trans);
			trans.commit();
		} catch (TskCoreException ex) {
			trans.rollback();
			throw ex;
		}

		assertEquals(1, result.size());
		// isNew=true means the cache is authoritative; getAttributes() returns
		// what we just added without hitting the DB.
		List<BlackboardAttribute> fetched = result.get(0).getAttributes();
		assertEquals(attrs.size(), fetched.size());

		// DB-level: 5 rows in blackboard_attributes, distributed across the
		// value-type columns we wrote. The driver writes each row into the
		// per-type column (value_text for STRING, value_int32 for INTEGER, etc).
		long artifactId = result.get(0).getArtifactID();
		String whereArtifact = "artifact_id = " + artifactId;
		assertEquals("expected 5 attribute rows", 5, countRows("blackboard_attributes", whereArtifact));

		// Spot-check one row per value type by querying for the expected
		// non-null column.
		assertEquals("STRING attr row not found",
				1, countRows("blackboard_attributes", whereArtifact + " AND value_text = 'needle'"));
		assertEquals("INTEGER attr row not found",
				1, countRows("blackboard_attributes", whereArtifact + " AND value_int32 = 1"));
		// PATH_ID (LONG) and DATETIME (LONG storage) both land in value_int64; their values are distinct.
		assertEquals("LONG attr row (9999) not found",
				1, countRows("blackboard_attributes", whereArtifact + " AND value_int64 = 9999"));
		assertEquals("DATETIME attr row (1700000000) not found",
				1, countRows("blackboard_attributes", whereArtifact + " AND value_int64 = 1700000000"));
		// DOUBLE comparison uses a small range to avoid float-equality flakiness.
		assertEquals("DOUBLE attr row not found",
				1, countRows("blackboard_attributes", whereArtifact + " AND value_double > 3.13 AND value_double < 3.15"));
	}

	/**
	 * A null {@code dataSourceObjId} must persist as NULL in
	 * {@code blackboard_artifacts.data_source_obj_id}, exercising the
	 * {@code setNull(4, Types.BIGINT)} branch in the batched
	 * blackboard_artifacts INSERT.
	 *
	 * (Note: {@code sourceObjId == 0} is not a supported case for data
	 * artifacts — {@code blackboard_artifacts.obj_id} is a FK to
	 * {@code tsk_objects.obj_id} and 0 will not match. Both single-row and
	 * batched paths fail the same way; not tested here.)
	 */
	@Test
	public void nullDataSourceObjIdPersistsAsNull() throws TskCoreException {
		BlackboardArtifact.Type type = new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_SEARCH);

		Blackboard.NewDataArtifactRequest req = new Blackboard.NewDataArtifactRequest(
				type, rootFile.getId(), null, Collections.emptyList(), null, null);

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		List<DataArtifact> result;
		try {
			result = caseDB.getBlackboard().newDataArtifacts(Collections.singletonList(req), trans);
			trans.commit();
		} catch (TskCoreException ex) {
			trans.rollback();
			throw ex;
		}

		assertEquals(1, result.size());
		DataArtifact a = result.get(0);

		assertEquals("data_source_obj_id should be NULL when dataSourceObjId==null",
				1, countRows("blackboard_artifacts", "artifact_id = " + a.getArtifactID() + " AND data_source_obj_id IS NULL"));
	}

	/**
	 * Cross-artifact attribute bucketing: each artifact's attributes must
	 * land against the correct artifact_id even though the helper groups
	 * attributes by value type across the whole chunk.
	 */
	@Test
	public void attributesAcrossMultipleArtifacts() throws TskCoreException {
		BlackboardArtifact.Type type = new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_SEARCH);
		Long dataSourceId = fs.getDataSource().getId();
		final String moduleName = "BatchedArtifactTest";

		// Three artifacts each with two attrs spanning two value-type buckets
		// (STRING + LONG). The batched helper groups by value type across all
		// artifacts; this test catches a bug like "I joined all attrs under
		// the first artifact's id".
		List<BlackboardAttribute> attrsA = Arrays.asList(
				new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_KEYWORD, moduleName, "artA"),
				new BlackboardAttribute(BlackboardAttribute.Type.TSK_PATH_ID, moduleName, 1001L));
		List<BlackboardAttribute> attrsB = Arrays.asList(
				new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_KEYWORD, moduleName, "artB"),
				new BlackboardAttribute(BlackboardAttribute.Type.TSK_PATH_ID, moduleName, 1002L));
		List<BlackboardAttribute> attrsC = Arrays.asList(
				new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_KEYWORD, moduleName, "artC"),
				new BlackboardAttribute(BlackboardAttribute.Type.TSK_PATH_ID, moduleName, 1003L));

		List<Blackboard.NewDataArtifactRequest> reqs = Arrays.asList(
				new Blackboard.NewDataArtifactRequest(type, rootFile.getId(), dataSourceId, attrsA, null, null),
				new Blackboard.NewDataArtifactRequest(type, rootFile.getId(), dataSourceId, attrsB, null, null),
				new Blackboard.NewDataArtifactRequest(type, rootFile.getId(), dataSourceId, attrsC, null, null));

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		List<DataArtifact> result;
		try {
			result = caseDB.getBlackboard().newDataArtifacts(reqs, trans);
			trans.commit();
		} catch (TskCoreException ex) {
			trans.rollback();
			throw ex;
		}

		assertEquals(3, result.size());
		long idA = result.get(0).getArtifactID();
		long idB = result.get(1).getArtifactID();
		long idC = result.get(2).getArtifactID();

		// Each artifact must have exactly 2 attribute rows.
		assertEquals("artA attr count", 2, countRows("blackboard_attributes", "artifact_id = " + idA));
		assertEquals("artB attr count", 2, countRows("blackboard_attributes", "artifact_id = " + idB));
		assertEquals("artC attr count", 2, countRows("blackboard_attributes", "artifact_id = " + idC));

		// Each artifact's STRING attribute carries the artifact-specific marker.
		assertEquals(1, countRows("blackboard_attributes", "artifact_id = " + idA + " AND value_text = 'artA'"));
		assertEquals(1, countRows("blackboard_attributes", "artifact_id = " + idB + " AND value_text = 'artB'"));
		assertEquals(1, countRows("blackboard_attributes", "artifact_id = " + idC + " AND value_text = 'artC'"));

		// Each artifact's LONG attribute carries the artifact-specific marker.
		assertEquals(1, countRows("blackboard_attributes", "artifact_id = " + idA + " AND value_int64 = 1001"));
		assertEquals(1, countRows("blackboard_attributes", "artifact_id = " + idB + " AND value_int64 = 1002"));
		assertEquals(1, countRows("blackboard_attributes", "artifact_id = " + idC + " AND value_int64 = 1003"));
	}

	/**
	 * ANALYSIS_RESULT-category types must be rejected.
	 */
	@Test
	public void wrongCategoryRejected() throws TskCoreException {
		BlackboardArtifact.Type analysisType = new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_KEYWORD_HIT);
		Long dataSourceId = fs.getDataSource().getId();

		Blackboard.NewDataArtifactRequest req = new Blackboard.NewDataArtifactRequest(
				analysisType, rootFile.getId(), dataSourceId, Collections.emptyList(), null, null);

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		try {
			caseDB.getBlackboard().newDataArtifacts(Collections.singletonList(req), trans);
			fail("Expected TskCoreException for non-DATA_ARTIFACT category");
		} catch (TskCoreException expected) {
			assertTrue(expected.getMessage().toLowerCase().contains("data artifact"));
		} finally {
			trans.rollback();
		}
	}
}
