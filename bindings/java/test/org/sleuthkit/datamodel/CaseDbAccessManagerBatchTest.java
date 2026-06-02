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
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests for the batch-insert APIs on CaseDbAccessManager:
 * addToBatch, insertBatch, and getMaxBatchSize.
 */
public class CaseDbAccessManagerBatchTest {

	private static final Logger LOGGER = Logger.getLogger(CaseDbAccessManagerBatchTest.class.getName());

	private static final String TEST_DB = "CaseDbAccessManagerBatchTest.db";
	private static final String TEST_TABLE = "test_batch_insert";

	private static SleuthkitCase caseDB;
	private static String dbPath = null;

	public CaseDbAccessManagerBatchTest() {
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

			caseDB.getCaseDbAccessManager().createTable(
					TEST_TABLE,
					"(id INTEGER PRIMARY KEY, name TEXT NOT NULL, value INTEGER)");

			System.out.println("CaseDbAccessManagerBatchTest DB created at: " + dbPath);
		} catch (TskCoreException ex) {
			LOGGER.log(Level.SEVERE, "Failed to set up batch insert test", ex);
			fail("Failed to set up batch insert test: " + ex.getMessage());
		}
	}

	@AfterClass
	public static void tearDownClass() {
	}

	/**
	 * Inserts a handful of rows via addToBatch + insertBatch, then reads them
	 * back via select and verifies the contents.
	 */
	@Test
	public void batchInsertHappyPath() throws Exception {
		CaseDbAccessManager mgr = caseDB.getCaseDbAccessManager();

		final int rowCount = 5;
		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		try (CaseDbAccessManager.CaseDbPreparedStatement stmt
				= mgr.prepareInsert(TEST_TABLE, "(id, name, value) VALUES (?, ?, ?)", trans)) {

			for (int i = 1; i <= rowCount; i++) {
				stmt.setLong(1, i);
				stmt.setString(2, "row-" + i);
				stmt.setLong(3, i * 100L);
				mgr.addToBatch(stmt);
			}

			int[] counts = mgr.insertBatch(stmt);
			assertEquals(rowCount, counts.length);
		}
		trans.commit();

		final List<Long> readBack = new ArrayList<>();
		mgr.select(
				"value FROM " + TEST_TABLE + " WHERE id BETWEEN 1 AND " + rowCount + " ORDER BY id",
				new CaseDbAccessManager.CaseDbAccessQueryCallback() {
					@Override
					public void process(ResultSet resultSet) {
						try {
							while (resultSet.next()) {
								readBack.add(resultSet.getLong("value"));
							}
						} catch (SQLException ex) {
							fail("Unexpected SQLException reading back rows: " + ex.getMessage());
						}
					}
				});

		assertEquals(rowCount, readBack.size());
		for (int i = 0; i < rowCount; i++) {
			assertEquals((i + 1) * 100L, (long) readBack.get(i));
		}
	}

	/**
	 * The same prepared statement must be reusable for a second batch after
	 * insertBatch has been called.
	 */
	@Test
	public void batchReuseAfterExecute() throws Exception {
		CaseDbAccessManager mgr = caseDB.getCaseDbAccessManager();

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		try (CaseDbAccessManager.CaseDbPreparedStatement stmt
				= mgr.prepareInsert(TEST_TABLE, "(id, name, value) VALUES (?, ?, ?)", trans)) {

			for (int i = 100; i < 103; i++) {
				stmt.setLong(1, i);
				stmt.setString(2, "reuse-a-" + i);
				stmt.setLong(3, i);
				mgr.addToBatch(stmt);
			}
			mgr.insertBatch(stmt);

			for (int i = 200; i < 203; i++) {
				stmt.setLong(1, i);
				stmt.setString(2, "reuse-b-" + i);
				stmt.setLong(3, i);
				mgr.addToBatch(stmt);
			}
			mgr.insertBatch(stmt);
		}
		trans.commit();

		final int[] count = new int[1];
		mgr.select(
				"COUNT(*) AS c FROM " + TEST_TABLE + " WHERE id >= 100 AND id < 300",
				new CaseDbAccessManager.CaseDbAccessQueryCallback() {
					@Override
					public void process(ResultSet resultSet) {
						try {
							if (resultSet.next()) {
								count[0] = resultSet.getInt("c");
							}
						} catch (SQLException ex) {
							fail("Unexpected SQLException: " + ex.getMessage());
						}
					}
				});
		assertEquals(6, count[0]);
	}

	/**
	 * getMaxBatchSize should return floor(65000 / paramsPerRow).
	 */
	@Test
	public void getMaxBatchSizeReflectsColumnCount() throws Exception {
		CaseDbAccessManager mgr = caseDB.getCaseDbAccessManager();

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		try (CaseDbAccessManager.CaseDbPreparedStatement stmt
				= mgr.prepareInsert(TEST_TABLE, "(id, name, value) VALUES (?, ?, ?)", trans)) {
			assertEquals(65000 / 3, mgr.getMaxBatchSize(stmt));
		}
		trans.rollback();
	}

	/**
	 * addToBatch and insertBatch must reject a SELECT prepared statement.
	 */
	@Test
	public void batchRejectsNonInsertStatement() throws Exception {
		CaseDbAccessManager mgr = caseDB.getCaseDbAccessManager();

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		try (CaseDbAccessManager.CaseDbPreparedStatement stmt
				= mgr.prepareSelect("id FROM " + TEST_TABLE + " WHERE id = ?", trans)) {
			try {
				mgr.addToBatch(stmt);
				fail("Expected TskCoreException for non-INSERT statement");
			} catch (TskCoreException expected) {
				assertTrue(expected.getMessage().toLowerCase().contains("incorrect type"));
			}
			try {
				mgr.insertBatch(stmt);
				fail("Expected TskCoreException for non-INSERT statement");
			} catch (TskCoreException expected) {
				assertTrue(expected.getMessage().toLowerCase().contains("incorrect type"));
			}
		}
		trans.rollback();
	}
}
