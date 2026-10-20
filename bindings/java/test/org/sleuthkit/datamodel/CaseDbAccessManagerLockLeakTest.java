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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.After;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Before;
import org.junit.Test;

/**
 * A prepared statement takes the case lock in its constructor and releases it in close(). When the
 * constructor fails after taking the lock, the caller never gets the statement to close, so the
 * constructor must release the lock itself. A leaked lock blocks every later writer, including
 * SleuthkitCase.close() when the case is garbage collected.
 */
public class CaseDbAccessManagerLockLeakTest {

	private static final String TEST_DB = "CaseDbAccessManagerLockLeakTest.db";
	private static final String TEST_TABLE = "test_lock_leak";

	private SleuthkitCase caseDB;
	private ExecutorService executor;

	@Before
	public void setUp() throws Exception {
		String dbPath = Paths.get(System.getProperty("java.io.tmpdir"), TEST_DB).toString();
		new java.io.File(dbPath).delete();
		caseDB = SleuthkitCase.newCase(dbPath);
		caseDB.getCaseDbAccessManager().createTable(TEST_TABLE, "(id INTEGER PRIMARY KEY, name TEXT)");
		executor = Executors.newCachedThreadPool(runnable -> {
			Thread thread = new Thread(runnable);
			thread.setDaemon(true);
			return thread;
		});
	}

	@After
	public void tearDown() {
		executor.shutdownNow();
	}

	@Test
	public void failedSelectStatementDoesNotLeakTheReadLock() throws Exception {
		// Closing the case closes its connection pool, so getConnection() fails once the lock is held.
		caseDB.close();
		try {
			caseDB.getCaseDbAccessManager().prepareSelect("* FROM " + TEST_TABLE);
			fail("expected prepareSelect to fail on a closed case");
		} catch (TskCoreException expected) {
			// the statement was never created
		}

		assertWriteLockAvailable("read lock leaked by a failed prepareSelect");
	}

	/**
	 * Another thread must be able to take the write lock, which is what SleuthkitCase.close() does.
	 */
	private void assertWriteLockAvailable(String message) throws Exception {
		Future<?> writer = executor.submit(() -> {
			caseDB.acquireSingleUserCaseWriteLock();
			caseDB.releaseSingleUserCaseWriteLock();
		});
		try {
			writer.get(10, TimeUnit.SECONDS);
		} catch (TimeoutException ex) {
			fail(message + ": a writer is still blocked after 10 seconds");
		}
		assertTrue(writer.isDone());
	}
}
