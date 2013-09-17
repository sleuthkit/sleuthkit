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

/**
 * interface to encapsulate database transactions
 *
 *
 *
 */
public interface Transaction {

	/**
	 * rollback whatever changes this transaction represents
	 */
	public void rollback();

	/**
	 * check whether this transaction has already been committed
	 *
	 * @return whether this transaction has already been committed
	 */
	public Boolean isCommitted();

	/**
	 * commit this transaction to the database
	 */
	public void commit();

	/**
	 *
	 * close this Transaction so it cannot be committed or rolledback. A closed
	 * Transaction no longer has a reference to a db Connection and methods
	 * invoked on a closed Transaction have no effect.
	 */
	public void close();

	/**
	 *
	 * @return true if this transaction is closed
	 */
	public Boolean isClosed();
}
