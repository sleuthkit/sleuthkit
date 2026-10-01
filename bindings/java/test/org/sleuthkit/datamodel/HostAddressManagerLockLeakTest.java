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
 * newHostAddress takes the case write lock and then gets a connection. Getting the connection fails
 * once the case is closed, and that failure must not leave the lock held: a leaked write lock blocks
 * every later reader and writer of the case, including SleuthkitCase.close().
 */
public class HostAddressManagerLockLeakTest {

	private static final String TEST_DB = "HostAddressManagerLockLeakTest.db";

	private SleuthkitCase caseDB;
	private ExecutorService executor;

	@Before
	public void setUp() throws Exception {
		String dbPath = Paths.get(System.getProperty("java.io.tmpdir"), TEST_DB).toString();
		new java.io.File(dbPath).delete();
		caseDB = SleuthkitCase.newCase(dbPath);
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
	public void failedConnectionDoesNotLeakTheWriteLock() throws Exception {
		// Closing the case closes its connection pool, so getConnection() fails once the lock is held.
		caseDB.close();
		try {
			caseDB.getHostAddressManager()
					.newHostAddress(HostAddress.HostAddressType.HOSTNAME, "leak.example.com");
			fail("expected newHostAddress to fail on a closed case");
		} catch (TskCoreException expected) {
			// no connection could be had
		}

		assertWriteLockAvailable("write lock leaked by a failed newHostAddress");
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
