/*
 * Sleuth Kit Data Model
 * 
 * Copyright 2013 Basis Technology Corp.
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

import java.sql.Connection;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;
import static org.sleuthkit.datamodel.SleuthkitCase.*;

/**
 * implements the Transaction interface
 *
 *
 *
 *
 */
class LogicalFileTransaction implements Transaction {

	/**
	 * private commit state
	 */
	private Boolean committed = false;
	/**
	 * db Connection this transaction is associated with
	 */
	private Connection con;
	private static final Logger logger = Logger.getLogger(LogicalFileTransaction.class.getName());
	private Boolean closed = false;

	/**
	 * private constructor
	 */
	private LogicalFileTransaction() {
	}

	/**
	 * factory creation method
	 *
	 * @param con the {@link  ava.sql.Connection}
	 * @return a LogicalFileTransaction for the given connection
	 * @throws SQLException
	 */
	static public LogicalFileTransaction startTransaction(Connection con) throws SQLException {

		LogicalFileTransaction lft = new LogicalFileTransaction();
		lft.con = con;

		//get the write lock, released in close()
		dbWriteLock();
		try {
			con.setAutoCommit(false);

		} catch (SQLException ex) {
			Logger.getLogger(LogicalFileTransaction.class.getName()).log(Level.SEVERE, "failed to set auto-commit to to false", ex);
			throw ex;
		}

		return lft;
	}

	/**
	 * {@inheritDoc }
	 *
	 * NOTE: this implementation of commit also closes the transaction whether
	 * the commit succeeded or failed
	 */
	@Override
	public void commit() {
		if (!committed && !closed) {
			try {
				con.commit();
			} catch (SQLException ex) {
				rollback();
			} finally {
				close();
			}
		}
	}

	/**
	 * {@inheritDoc }
	 */
	@Override
	public Boolean isCommitted() {
		return committed;

	}

	/**
	 * {@inheritDoc }
	 */
	@Override
	public void rollback() {
		if (!committed && !closed) {
			try {
				con.rollback();
			} catch (SQLException ex1) {
				Logger.getLogger(LogicalFileTransaction.class.getName()).log(Level.SEVERE, "Exception while attempting to rollback!!", ex1);
			}
		}
	}

	/**
	 * {@inheritDoc }
	 *
	 */
	@Override
	public void close() {
		if (!closed) {
			try {
				con.setAutoCommit(true);
			} catch (SQLException ex) {
				logger.log(Level.SEVERE, "Error setting auto-commit to true.", ex);
			} finally {
				con = null;
				committed = true;
				closed = true;
				dbWriteUnlock();
			}
		}
	}

	/**
	 * {@inheritDoc }
	 *
	 */
	@Override
	public Boolean isClosed() {
		return closed;
	}
}
