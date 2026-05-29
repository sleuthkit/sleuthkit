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
 * Tests for SleuthkitCase#addFileSystemFiles, the bulk variant of
 * SleuthkitCase#addFileSystemFile.
 *
 * <p>Default execution runs against SQLite. To exercise the batched
 * PostgreSQL code path, uncomment the connection block in {@link #setUpClass}
 * and point it at a test PostgreSQL instance.</p>
 */
public class BatchedFileSystemFileTest {

	private static final Logger LOGGER = Logger.getLogger(BatchedFileSystemFileTest.class.getName());

	private static final String TEST_DB = "BatchedFileSystemFileTest.db";

	private static SleuthkitCase caseDB;
	private static String dbPath = null;
	private static Image image = null;
	private static FileSystem fs = null;
	private static FsContent rootFile = null;
	private static OsAccount osAccount = null;

	public BatchedFileSystemFileTest() {
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
			// caseDB = SleuthkitCase.newCase("TskBatchedFileSystemFileTest", connectionInfo, tempDirPath);

			SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();

			image = caseDB.addImage(TskData.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_DETECT, 512, 1024, "", Collections.emptyList(), "America/NewYork", null, null, null, "BatchedFileSystemFileTestImage", trans);
			fs = caseDB.addFileSystem(image.getId(), 0, TskData.TSK_FS_TYPE_ENUM.TSK_FS_TYPE_RAW, 0, 0, 0, 0, 0, "", trans);

			// fs.getDataSource() isn't populated until after commit; use image.getId() directly.
			long dataSourceObjectId = image.getId();
			rootFile = caseDB.addFileSystemFile(dataSourceObjectId, fs.getId(), "root.dir", 0, 0,
					TskData.TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, 0, TskData.TSK_FS_NAME_FLAG_ENUM.ALLOC,
					(short) 0, 200, 0, 0, 0, 0, null, null, null, false, fs, null, null, Collections.emptyList(), trans);

			trans.commit();

			// One OS account for the withOsAccount test.
			Host host = caseDB.getHostManager().newHost("batched-fs-host");
			String realmName = "batched-fs-realm";
			String acctSid = "S-1-5-21-111111111-222222222-3333333333-2001";
			caseDB.getOsAccountRealmManager().newWindowsRealm(acctSid, realmName, host, OsAccountRealm.RealmScope.LOCAL);
			osAccount = caseDB.getOsAccountManager().newWindowsOsAccount(acctSid, null, realmName, host, OsAccountRealm.RealmScope.LOCAL);

			System.out.println("BatchedFileSystemFileTest DB created at: " + dbPath);
		} catch (TskCoreException | OsAccountManager.NotUserSIDException ex) {
			LOGGER.log(Level.SEVERE, "Failed to set up BatchedFileSystemFileTest", ex);
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

	/** Read a single string column from a row identified by the given WHERE clause. */
	private static String selectString(String column, String table, String whereClause) throws TskCoreException {
		final String[] value = new String[]{null};
		caseDB.getCaseDbAccessManager().select(
				column + " FROM " + table + " WHERE " + whereClause,
				new CaseDbAccessManager.CaseDbAccessQueryCallback() {
					@Override
					public void process(ResultSet rs) {
						try {
							if (rs.next()) {
								value[0] = rs.getString(column);
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

	// ---------- DTO request builder (defaults for terseness) ----------

	private static SleuthkitCase.NewFileSystemFileRequest dirRequest(String name, String normalizedFullPath, Content parent, String inBatchParentPath, String parentPath) {
		return new SleuthkitCase.NewFileSystemFileRequest(
				image.getId(), fs.getId(), name, 0, 0,
				TskData.TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, 0,
				TskData.TSK_FS_NAME_FLAG_ENUM.ALLOC, (short) 0, 0,
				0, 0, 0, 0,
				null, null, null, null, false,
				parent, inBatchParentPath, parentPath, normalizedFullPath,
				null, null, TskData.CollectedStatus.UNKNOWN, Collections.emptyList());
	}

	private static SleuthkitCase.NewFileSystemFileRequest fileRequest(String name, Content parent, String inBatchParentPath, String parentPath, List<Attribute> attrs) {
		return new SleuthkitCase.NewFileSystemFileRequest(
				image.getId(), fs.getId(), name, 0, 0,
				TskData.TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, 0,
				TskData.TSK_FS_NAME_FLAG_ENUM.ALLOC, (short) 0, 100,
				0, 0, 0, 0,
				null, null, null, null, true,
				parent, inBatchParentPath, parentPath, null,
				null, null, TskData.CollectedStatus.UNKNOWN, attrs);
	}

	// ---------- Tests ----------

	/**
	 * Null inputs, empty input, and DTO constructor validation in one place.
	 */
	@Test
	public void nullAndInvalidInputs() throws TskCoreException {
		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		try {
			// Null / empty inputs on the public method.
			try {
				caseDB.addFileSystemFiles(null, trans);
				fail("Expected TskCoreException for null requests");
			} catch (TskCoreException expected) {
			}

			try {
				caseDB.addFileSystemFiles(Collections.<SleuthkitCase.NewFileSystemFileRequest>emptyList(), null);
				fail("Expected TskCoreException for null transaction");
			} catch (TskCoreException expected) {
			}

			List<FsContent> empty = caseDB.addFileSystemFiles(Collections.<SleuthkitCase.NewFileSystemFileRequest>emptyList(), trans);
			assertNotNull(empty);
			assertEquals(0, empty.size());

			// DTO constructor: both parent refs set → IAE.
			try {
				dirRequest("d", "/d/", rootFile, "/something/", "/");
				fail("Expected IAE for both parent refs non-null");
			} catch (IllegalArgumentException expected) {
			}

			// DTO constructor: neither parent ref set → IAE.
			try {
				dirRequest("d", "/d/", null, null, "/");
				fail("Expected IAE for both parent refs null");
			} catch (IllegalArgumentException expected) {
			}

			// DTO constructor: directory row without normalizedFullPath → IAE.
			try {
				dirRequest("d", null, rootFile, null, "/");
				fail("Expected IAE for directory without normalizedFullPath");
			} catch (IllegalArgumentException expected) {
			}

			// DTO constructor: null fileAttributes → IAE.
			try {
				new SleuthkitCase.NewFileSystemFileRequest(
						image.getId(), fs.getId(), "x", 0, 0,
						TskData.TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, 0,
						TskData.TSK_FS_NAME_FLAG_ENUM.ALLOC, (short) 0, 100,
						0, 0, 0, 0,
						null, null, null, null, true,
						rootFile, null, "/", null,
						null, null, TskData.CollectedStatus.UNKNOWN, null);
				fail("Expected IAE for null fileAttributes");
			} catch (IllegalArgumentException expected) {
			}
		} finally {
			trans.rollback();
		}
	}

	/**
	 * Single-file happy path: tsk_objects, tsk_files, parent_path, and
	 * parent has-children bit all populated correctly.
	 */
	@Test
	public void singleFile() throws TskCoreException {
		List<SleuthkitCase.NewFileSystemFileRequest> reqs = Collections.singletonList(
				fileRequest("solo.txt", rootFile, null, "/root.dir/", Collections.<Attribute>emptyList()));

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		List<FsContent> result;
		try {
			result = caseDB.addFileSystemFiles(reqs, trans);
			trans.commit();
		} catch (TskCoreException ex) {
			trans.rollback();
			throw ex;
		}

		assertEquals(1, result.size());
		FsContent file = result.get(0);

		// tsk_objects row exists and points at rootFile as parent.
		assertEquals(1, countRows("tsk_objects", "obj_id = " + file.getId()));
		assertEquals(rootFile.getId(), selectLong("par_obj_id", "tsk_objects", "obj_id = " + file.getId()));

		// tsk_files row with the right fields.
		assertEquals(1, countRows("tsk_files", "obj_id = " + file.getId()));
		assertEquals("solo.txt", selectString("name", "tsk_files", "obj_id = " + file.getId()));
		assertEquals("/root.dir/", selectString("parent_path", "tsk_files", "obj_id = " + file.getId()));
		assertEquals(image.getId(), selectLong("data_source_obj_id", "tsk_files", "obj_id = " + file.getId()));
		assertEquals(fs.getId(), selectLong("fs_obj_id", "tsk_files", "obj_id = " + file.getId()));
		// meta_type = REG for files.
		assertEquals(TskData.TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG.getValue(),
				selectLong("meta_type", "tsk_files", "obj_id = " + file.getId()));

		// Parent has-children bit set.
		assertTrue("parent has-children bit not set", caseDB.getHasChildren(rootFile));
	}

	/**
	 * A batch of mixed dirs + files (both directly under {@code rootFile}).
	 * Verifies row counts and that dir_type/meta_type are set correctly per row.
	 */
	@Test
	public void mixedFilesAndDirs() throws TskCoreException {
		List<SleuthkitCase.NewFileSystemFileRequest> reqs = Arrays.asList(
				dirRequest("etc", "/root.dir/etc/", rootFile, null, "/root.dir/"),
				fileRequest("hosts", rootFile, null, "/root.dir/", Collections.<Attribute>emptyList()),
				dirRequest("var", "/root.dir/var/", rootFile, null, "/root.dir/"),
				fileRequest("README", rootFile, null, "/root.dir/", Collections.<Attribute>emptyList()));

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		List<FsContent> result;
		try {
			result = caseDB.addFileSystemFiles(reqs, trans);
			trans.commit();
		} catch (TskCoreException ex) {
			trans.rollback();
			throw ex;
		}

		assertEquals(4, result.size());

		List<Long> objIds = new ArrayList<>();
		for (FsContent f : result) {
			objIds.add(f.getId());
		}
		assertEquals(4, countRows("tsk_objects", "obj_id IN (" + inList(objIds) + ")"));
		assertEquals(4, countRows("tsk_files", "obj_id IN (" + inList(objIds) + ")"));

		// Two dirs.
		assertEquals(2, countRows("tsk_files",
				"obj_id IN (" + inList(objIds) + ") AND meta_type = " + TskData.TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR.getValue()));
		// Two files.
		assertEquals(2, countRows("tsk_files",
				"obj_id IN (" + inList(objIds) + ") AND meta_type = " + TskData.TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG.getValue()));

		// All four point at rootFile as parent.
		assertEquals(4, countRows("tsk_objects",
				"obj_id IN (" + inList(objIds) + ") AND par_obj_id = " + rootFile.getId()));
	}

	/**
	 * In-batch parent reference: a directory at index 0 is referenced by a
	 * file at index 1 via {@code inBatchParentPath}. Verify the file's
	 * par_obj_id chains to the directory's obj_id.
	 */
	@Test
	public void inBatchParentResolves() throws TskCoreException {
		List<SleuthkitCase.NewFileSystemFileRequest> reqs = Arrays.asList(
				dirRequest("subdir", "/root.dir/subdir/", rootFile, null, "/root.dir/"),
				fileRequest("inside.txt", null, "/root.dir/subdir/", "/root.dir/subdir/", Collections.<Attribute>emptyList()));

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		List<FsContent> result;
		try {
			result = caseDB.addFileSystemFiles(reqs, trans);
			trans.commit();
		} catch (TskCoreException ex) {
			trans.rollback();
			throw ex;
		}

		assertEquals(2, result.size());
		long dirId = result.get(0).getId();
		long fileId = result.get(1).getId();

		// File's par_obj_id is the dir's obj_id.
		assertEquals(dirId, selectLong("par_obj_id", "tsk_objects", "obj_id = " + fileId));
		// Dir's par_obj_id is rootFile.
		assertEquals(rootFile.getId(), selectLong("par_obj_id", "tsk_objects", "obj_id = " + dirId));
	}

	/**
	 * Unresolvable {@code inBatchParentPath} → {@link TskCoreException}.
	 */
	@Test
	public void inBatchParentMissingThrows() throws TskCoreException {
		List<SleuthkitCase.NewFileSystemFileRequest> reqs = Collections.singletonList(
				fileRequest("orphan.txt", null, "/never/declared/", "/never/declared/", Collections.<Attribute>emptyList()));

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		try {
			caseDB.addFileSystemFiles(reqs, trans);
			fail("Expected TskCoreException for unresolvable inBatchParentPath");
		} catch (TskCoreException expected) {
			assertTrue(expected.getMessage().contains("/never/declared/"));
		} finally {
			trans.rollback();
		}
	}

	/**
	 * Deep chain: /a → /a/b → /a/b/c → /a/b/c/d.exe, each row's parent the
	 * previous row via {@code inBatchParentPath}. All four rows committed and
	 * par_obj_id chain checks out.
	 */
	@Test
	public void deepChain() throws TskCoreException {
		List<SleuthkitCase.NewFileSystemFileRequest> reqs = Arrays.asList(
				dirRequest("a", "/a/", rootFile, null, "/root.dir/"),
				dirRequest("b", "/a/b/", null, "/a/", "/a/"),
				dirRequest("c", "/a/b/c/", null, "/a/b/", "/a/b/"),
				fileRequest("d.exe", null, "/a/b/c/", "/a/b/c/", Collections.<Attribute>emptyList()));

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		List<FsContent> result;
		try {
			result = caseDB.addFileSystemFiles(reqs, trans);
			trans.commit();
		} catch (TskCoreException ex) {
			trans.rollback();
			throw ex;
		}

		assertEquals(4, result.size());
		long aId = result.get(0).getId();
		long bId = result.get(1).getId();
		long cId = result.get(2).getId();
		long dId = result.get(3).getId();

		assertEquals(rootFile.getId(), selectLong("par_obj_id", "tsk_objects", "obj_id = " + aId));
		assertEquals(aId, selectLong("par_obj_id", "tsk_objects", "obj_id = " + bId));
		assertEquals(bId, selectLong("par_obj_id", "tsk_objects", "obj_id = " + cId));
		assertEquals(cId, selectLong("par_obj_id", "tsk_objects", "obj_id = " + dId));
	}

	/**
	 * Two directory rows sharing the same {@code normalizedFullPath} within
	 * a single batch must be rejected.
	 */
	@Test
	public void duplicateInBatchPathThrows() throws TskCoreException {
		List<SleuthkitCase.NewFileSystemFileRequest> reqs = Arrays.asList(
				dirRequest("etc", "/root.dir/etc/", rootFile, null, "/root.dir/"),
				dirRequest("etc-copy", "/root.dir/etc/", rootFile, null, "/root.dir/"));

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		try {
			caseDB.addFileSystemFiles(reqs, trans);
			fail("Expected TskCoreException for duplicate normalizedFullPath");
		} catch (TskCoreException expected) {
			assertTrue(expected.getMessage().toLowerCase().contains("duplicate"));
		} finally {
			trans.rollback();
		}
	}

	/**
	 * One file with attributes covering all value-type columns. Verify rows
	 * persist in tsk_file_attributes and each Attribute's id and
	 * attributeParentId are set after the call.
	 */
	@Test
	public void withAttributesAcrossValueTypes() throws TskCoreException {
		// STRING, INTEGER, LONG, DOUBLE, DATETIME (LONG-storage)
		List<Attribute> attrs = new ArrayList<>();
		attrs.add(new Attribute(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_KEYWORD), "needle"));
		attrs.add(new Attribute(BlackboardAttribute.Type.TSK_MALWARE_DETECTED, 1));
		attrs.add(new Attribute(BlackboardAttribute.Type.TSK_PATH_ID, 9999L));
		attrs.add(new Attribute(BlackboardAttribute.Type.TSK_ENTROPY, 3.14));
		attrs.add(new Attribute(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME), 1700000000L));

		List<SleuthkitCase.NewFileSystemFileRequest> reqs = Collections.singletonList(
				fileRequest("attrs.txt", rootFile, null, "/root.dir/", attrs));

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		List<FsContent> result;
		try {
			result = caseDB.addFileSystemFiles(reqs, trans);
			trans.commit();
		} catch (TskCoreException ex) {
			trans.rollback();
			throw ex;
		}

		assertEquals(1, result.size());
		long fileId = result.get(0).getId();

		// 5 rows total in tsk_file_attributes.
		assertEquals(5, countRows("tsk_file_attributes", "obj_id = " + fileId));

		// Spot-check one row per value type.
		assertEquals(1, countRows("tsk_file_attributes", "obj_id = " + fileId + " AND value_text = 'needle'"));
		assertEquals(1, countRows("tsk_file_attributes", "obj_id = " + fileId + " AND value_int32 = 1"));
		assertEquals(1, countRows("tsk_file_attributes", "obj_id = " + fileId + " AND value_int64 = 9999"));
		assertEquals(1, countRows("tsk_file_attributes", "obj_id = " + fileId + " AND value_int64 = 1700000000"));
		assertEquals(1, countRows("tsk_file_attributes", "obj_id = " + fileId + " AND value_double > 3.13 AND value_double < 3.15"));

		// Each Attribute object got id and parentObjId set (mirrors single-row contract).
		for (Attribute a : attrs) {
			assertTrue("attribute id was not assigned", a.getId() > 0);
			assertEquals("attributeParentId mismatch", fileId, a.getAttributeParentId());
		}
	}

	/**
	 * Three files each with two attributes — verify each attribute is
	 * persisted against the correct {@code obj_id} (catches a bug like
	 * "all attrs end up on the first file's id").
	 */
	@Test
	public void attributesAcrossMultipleFiles() throws TskCoreException {
		List<Attribute> attrsA = Arrays.asList(
				new Attribute(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_KEYWORD), "fileA"),
				new Attribute(BlackboardAttribute.Type.TSK_PATH_ID, 1001L));
		List<Attribute> attrsB = Arrays.asList(
				new Attribute(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_KEYWORD), "fileB"),
				new Attribute(BlackboardAttribute.Type.TSK_PATH_ID, 1002L));
		List<Attribute> attrsC = Arrays.asList(
				new Attribute(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_KEYWORD), "fileC"),
				new Attribute(BlackboardAttribute.Type.TSK_PATH_ID, 1003L));

		List<SleuthkitCase.NewFileSystemFileRequest> reqs = Arrays.asList(
				fileRequest("a.txt", rootFile, null, "/root.dir/", attrsA),
				fileRequest("b.txt", rootFile, null, "/root.dir/", attrsB),
				fileRequest("c.txt", rootFile, null, "/root.dir/", attrsC));

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		List<FsContent> result;
		try {
			result = caseDB.addFileSystemFiles(reqs, trans);
			trans.commit();
		} catch (TskCoreException ex) {
			trans.rollback();
			throw ex;
		}

		assertEquals(3, result.size());
		long idA = result.get(0).getId();
		long idB = result.get(1).getId();
		long idC = result.get(2).getId();

		// Each file has exactly 2 attribute rows.
		assertEquals(2, countRows("tsk_file_attributes", "obj_id = " + idA));
		assertEquals(2, countRows("tsk_file_attributes", "obj_id = " + idB));
		assertEquals(2, countRows("tsk_file_attributes", "obj_id = " + idC));

		// Each file's STRING attribute carries the file-specific marker.
		assertEquals(1, countRows("tsk_file_attributes", "obj_id = " + idA + " AND value_text = 'fileA'"));
		assertEquals(1, countRows("tsk_file_attributes", "obj_id = " + idB + " AND value_text = 'fileB'"));
		assertEquals(1, countRows("tsk_file_attributes", "obj_id = " + idC + " AND value_text = 'fileC'"));

		// Each file's LONG attribute carries the file-specific marker.
		assertEquals(1, countRows("tsk_file_attributes", "obj_id = " + idA + " AND value_int64 = 1001"));
		assertEquals(1, countRows("tsk_file_attributes", "obj_id = " + idB + " AND value_int64 = 1002"));
		assertEquals(1, countRows("tsk_file_attributes", "obj_id = " + idC + " AND value_int64 = 1003"));
	}

	/**
	 * A request with a non-null {@code osAccount} produces a row in
	 * tsk_os_account_instances of type ACCESSED.
	 */
	@Test
	public void withOsAccount() throws TskCoreException {
		SleuthkitCase.NewFileSystemFileRequest req = new SleuthkitCase.NewFileSystemFileRequest(
				image.getId(), fs.getId(), "with-os.txt", 0, 0,
				TskData.TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, 0,
				TskData.TSK_FS_NAME_FLAG_ENUM.ALLOC, (short) 0, 100,
				0, 0, 0, 0,
				null, null, null, null, true,
				rootFile, null, "/root.dir/", null,
				null, osAccount, TskData.CollectedStatus.UNKNOWN, Collections.<Attribute>emptyList());

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		List<FsContent> result;
		try {
			result = caseDB.addFileSystemFiles(Collections.singletonList(req), trans);
			trans.commit();
		} catch (TskCoreException ex) {
			trans.rollback();
			throw ex;
		}

		assertEquals(1, result.size());
		long fileId = result.get(0).getId();

		// tsk_files row carries os_account_obj_id.
		assertEquals(osAccount.getId(),
				selectLong("os_account_obj_id", "tsk_files", "obj_id = " + fileId));

		// tsk_os_account_instances row exists for this (os_account_obj_id, data_source_obj_id).
		assertEquals("expected an ACCESSED os_account_instances row",
				1, countRows("tsk_os_account_instances",
						"os_account_obj_id = " + osAccount.getId()
						+ " AND data_source_obj_id = " + image.getId()
						+ " AND instance_type = " + OsAccountInstance.OsAccountInstanceType.ACCESSED.getId()));
	}

	/**
	 * After a batch creating three children under {@code rootFile},
	 * {@code hasChildren(rootFile)} reports true.
	 */
	@Test
	public void hasChildrenPropagates() throws TskCoreException {
		List<SleuthkitCase.NewFileSystemFileRequest> reqs = Arrays.asList(
				fileRequest("c1.txt", rootFile, null, "/root.dir/", Collections.<Attribute>emptyList()),
				fileRequest("c2.txt", rootFile, null, "/root.dir/", Collections.<Attribute>emptyList()),
				fileRequest("c3.txt", rootFile, null, "/root.dir/", Collections.<Attribute>emptyList()));

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		try {
			caseDB.addFileSystemFiles(reqs, trans);
			trans.commit();
		} catch (TskCoreException ex) {
			trans.rollback();
			throw ex;
		}

		assertTrue("parent has-children bit not set", caseDB.getHasChildren(rootFile));
	}
}
