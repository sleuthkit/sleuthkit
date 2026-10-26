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

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Collection;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.After;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;
import org.sleuthkit.datamodel.CaseDbAccessManager.CaseDbPreparedStatement;

/**
 * CaseDbPreparedStatement.cancel() stops a running select from another thread,
 * leaves the connection and the case lock usable once the statement is closed,
 * and does nothing after close, when the pooled connection may already be
 * running someone else's query.
 *
 * Runs on SQLite, and on PostgreSQL when the system properties tsk.test.pg.host,
 * tsk.test.pg.port, tsk.test.pg.user and tsk.test.pg.password name a server
 * (the test creates a case database there and drops it afterwards).
 */
@RunWith(Parameterized.class)
public class CaseDbAccessManagerCancelTest {

	/** Counts to the bound limit; prepareSelect() adds the leading SELECT. */
	private static final String COUNT_TO = "max(x) AS n FROM (WITH RECURSIVE c(x) AS (SELECT CAST(1 AS BIGINT) UNION ALL SELECT x + 1 FROM c WHERE x < ?) SELECT x FROM c) AS counted";

	/** Far more rows than the test will wait for. */
	private static final long FOREVER = 10_000_000_000L;

	@Parameters(name = "{0}")
	public static Collection<Object[]> dbTypes() {
		return Arrays.asList(new Object[][]{{TskData.DbType.SQLITE}, {TskData.DbType.POSTGRESQL}});
	}

	@Parameter
	public TskData.DbType dbType;

	@Rule
	public TemporaryFolder folder = new TemporaryFolder();

	private CaseDbConnectionInfo postgres;
	private SleuthkitCase caseDB;
	private ExecutorService executor;

	@Before
	public void setUp() throws Exception {
		if (dbType == TskData.DbType.POSTGRESQL) {
			String host = System.getProperty("tsk.test.pg.host");
			Assume.assumeTrue("no PostgreSQL server configured", host != null);
			postgres = new CaseDbConnectionInfo(host, System.getProperty("tsk.test.pg.port", "5432"),
					System.getProperty("tsk.test.pg.user"), System.getProperty("tsk.test.pg.password"), TskData.DbType.POSTGRESQL);
			caseDB = SleuthkitCase.newCase("cancel_test", postgres, folder.getRoot().getPath());
		} else {
			caseDB = SleuthkitCase.newCase(new File(folder.getRoot(), "case.db").getPath());
		}
		executor = Executors.newCachedThreadPool(runnable -> {
			Thread thread = new Thread(runnable);
			thread.setDaemon(true);
			return thread;
		});
	}

	@After
	public void tearDown() throws Exception {
		if (executor != null) {
			executor.shutdownNow();
		}
		if (caseDB != null) {
			String databaseName = caseDB.getDatabaseName();
			caseDB.close();
			if (postgres != null) {
				String url = "jdbc:postgresql://" + postgres.getHost() + ":" + postgres.getPort() + "/postgres";
				// Retried rather than forced: the pool closes its connections in the background, and
				// an autovacuum worker on the new database is not ours to terminate.
				try (Connection admin = DriverManager.getConnection(url, postgres.getUserName(), postgres.getPassword());
						Statement drop = admin.createStatement()) {
					for (int attempt = 1;; attempt++) {
						try {
							drop.execute("DROP DATABASE IF EXISTS \"" + databaseName + "\"");
							break;
						} catch (java.sql.SQLException ex) {
							if (attempt == 30) {
								throw ex;
							}
							Thread.sleep(500);
						}
					}
				}
			}
		}
	}

	@Test
	public void cancelStopsARunningSelect() throws Exception {
		CaseDbPreparedStatement statement = caseDB.getCaseDbAccessManager().prepareSelect(COUNT_TO);
		statement.setLong(1, FOREVER);
		Future<Long> running = executor.submit(() -> countTo(statement));

		Thread.sleep(300);
		cancelUntilStopped(statement, running);
		statement.close();

		assertWriteLockAvailable();
		if (dbType == TskData.DbType.POSTGRESQL) {
			assertEquals("the cancelled statement is still active on the server", 0L, activeCountStatements());
		}
		// The same SQL, likely on the same pooled connection and cached statement, still works
		assertEquals(10L, select(10));
	}

	@Test
	public void cancelAfterCloseDoesNotStopTheNextQuery() throws Exception {
		CaseDbPreparedStatement closed = caseDB.getCaseDbAccessManager().prepareSelect(COUNT_TO);
		closed.close();

		long limit = 3_000_000L;
		CaseDbPreparedStatement next = caseDB.getCaseDbAccessManager().prepareSelect(COUNT_TO);
		next.setLong(1, limit);
		Future<Long> running = executor.submit(() -> countTo(next));
		while (!running.isDone()) {
			closed.cancel();
			Thread.sleep(5);
		}
		assertEquals(limit, (long) running.get());
		next.close();
	}

	/**
	 * Every cancelled statement must give its connection back to the pool when
	 * it closes. The pool waits without limit for a free connection, so one
	 * that leaked would, after maxPoolSize (20) cancels, hang every later query.
	 */
	@Test
	public void cancelledStatementsReturnTheirConnectionsToThePool() throws Exception {
		for (int i = 0; i < 60; i++) {
			Future<?> round = executor.submit(() -> {
				CaseDbPreparedStatement statement = caseDB.getCaseDbAccessManager().prepareSelect(COUNT_TO);
				try {
					statement.setLong(1, FOREVER);
					Future<Long> running = executor.submit(() -> countTo(statement));
					Thread.sleep(20);
					cancelUntilStopped(statement, running);
				} finally {
					statement.close();
				}
				return null;
			});
			try {
				round.get(15, TimeUnit.SECONDS);
			} catch (TimeoutException ex) {
				fail("cancel round " + i + " did not finish: a connection is not back in the pool");
			} catch (ExecutionException ex) {
				if (ex.getCause() instanceof AssertionError) {
					throw (AssertionError) ex.getCause();
				}
				throw ex;
			}
		}
		assertEquals(1000L, select(1000));
		assertWriteLockAvailable();
	}

	@Test
	public void aSelectOnACancelledStatementFailsWithoutRunning() throws Exception {
		try (CaseDbPreparedStatement statement = caseDB.getCaseDbAccessManager().prepareSelect(COUNT_TO)) {
			statement.cancel();
			statement.setLong(1, FOREVER);
			long start = System.nanoTime();
			try {
				countTo(statement);
				fail("a cancelled statement ran its select");
			} catch (TskCoreException expected) {
				assertTrue(TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - start) < 5);
			}
		}
		assertEquals(1000L, select(1000));
	}

	/**
	 * A cancel that arrives after the select returned must not reach the
	 * connection: sqlite3_interrupt would also stop the next query run on it.
	 */
	@Test
	public void cancelAfterTheSelectReturnedDoesNotStopTheNextQuery() throws Exception {
		try (CaseDbPreparedStatement statement = caseDB.getCaseDbAccessManager().prepareSelect(COUNT_TO)) {
			statement.setLong(1, 10);
			assertEquals(10L, countTo(statement));
			statement.cancel();
		}
		for (int i = 0; i < 5; i++) {
			assertEquals(1000L, select(1000));
		}
	}

	private long countTo(CaseDbPreparedStatement statement) throws TskCoreException {
		AtomicLong result = new AtomicLong(-1);
		caseDB.getCaseDbAccessManager().select(statement, resultSet -> {
			try {
				if (resultSet.next()) {
					result.set(resultSet.getLong("n"));
				}
			} catch (java.sql.SQLException ex) {
				throw new IllegalStateException(ex);
			}
		});
		return result.get();
	}

	/**
	 * Cancels until the select stops, as a cancel landing just before the query
	 * starts on PostgreSQL is lost. Fails if it has not stopped within 10 seconds.
	 */
	private static void cancelUntilStopped(CaseDbPreparedStatement statement, Future<Long> running) throws Exception {
		long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
		while (!running.isDone()) {
			if (System.nanoTime() - deadline > 0) {
				fail("the select was not stopped within 10 seconds of the first cancel");
			}
			statement.cancel();
			Thread.sleep(20);
		}
		try {
			running.get();
			fail("the select ran to completion");
		} catch (ExecutionException expected) {
			assertTrue(String.valueOf(expected.getCause()), expected.getCause() instanceof TskCoreException);
		}
	}

	/** PostgreSQL backends, other than this one, still running a COUNT_TO statement. */
	private long activeCountStatements() throws Exception {
		AtomicLong result = new AtomicLong(-1);
		try (CaseDbPreparedStatement statement = caseDB.getCaseDbAccessManager().prepareSelect(
				"count(*) AS n FROM pg_stat_activity WHERE state = 'active' AND pid <> pg_backend_pid() AND query LIKE ?")) {
			statement.setString(1, "%WITH RECURSIVE c(x)%");
			caseDB.getCaseDbAccessManager().select(statement, resultSet -> {
				try {
					resultSet.next();
					result.set(resultSet.getLong("n"));
				} catch (java.sql.SQLException ex) {
					throw new IllegalStateException(ex);
				}
			});
		}
		return result.get();
	}

	private long select(long limit) throws Exception {
		try (CaseDbPreparedStatement statement = caseDB.getCaseDbAccessManager().prepareSelect(COUNT_TO)) {
			statement.setLong(1, limit);
			return countTo(statement);
		}
	}

	/** Another thread must be able to take the write lock: the statement let go of its read lock. */
	private void assertWriteLockAvailable() throws Exception {
		Future<?> writer = executor.submit(() -> {
			caseDB.acquireSingleUserCaseWriteLock();
			caseDB.releaseSingleUserCaseWriteLock();
		});
		try {
			writer.get(10, TimeUnit.SECONDS);
		} catch (TimeoutException ex) {
			fail("a writer is still blocked after 10 seconds");
		}
	}
}
