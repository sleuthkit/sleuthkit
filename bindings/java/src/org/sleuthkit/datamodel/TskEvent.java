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
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 *
 * A marker interface for events published by SleuthKit.
 */
public interface TskEvent {

	/**
	 * Event to indicate that analysis results were deleted.
	 */
	final public static class AnalysisResultsDeletedTskEvent {

		private final List<Long> deletedResultObjIds;

		/**
		 * Constructs a new AnalysisResultsDeletedEvent.
		 *
		 * @param deletedResults List of deleted results.
		 */
		AnalysisResultsDeletedTskEvent(List<Long> deletedResultObjIds) {
			this.deletedResultObjIds = deletedResultObjIds;
		}

		/**
		 * Returns a list of deleted results.
		 *
		 * @return List of AnalysisResult.
		 */
		public List<Long> getObjectIds() {
			return Collections.unmodifiableList(deletedResultObjIds);
		}
	}

	/**
	 * Base event for all host events
	 */
	static class HostTskEvent {

		private final List<Host> hosts;

		/**
		 * Main constructor.
		 *
		 * @param hosts The hosts that are objects of the event.
		 */
		HostTskEvent(List<Host> hosts) {
			this.hosts = hosts;
		}

		/**
		 * Returns the hosts affected in the event.
		 *
		 * @return The hosts affected in the event.
		 */
		public List<Host> getHosts() {
			return Collections.unmodifiableList(new ArrayList<>(hosts));
		}
	}

	/**
	 * Event fired when hosts are created.
	 */
	public static final class HostsAddedTskEvent extends HostTskEvent {

		/**
		 * Main constructor.
		 *
		 * @param hosts The added hosts.
		 */
		HostsAddedTskEvent(List<Host> hosts) {
			super(hosts);
		}
	}

	/**
	 * Event fired when hosts are updated.
	 */
	public static final class HostsChangedTskEvent extends HostTskEvent {

		/**
		 * Main constructor.
		 *
		 * @param hosts The new values for the hosts that were changed.
		 */
		HostsChangedTskEvent(List<Host> hosts) {
			super(hosts);
		}
	}

	/**
	 * Event fired when hosts are deleted.
	 */
	public static final class HostsDeletedTskEvent extends HostTskEvent {

		/**
		 * Main constructor.
		 *
		 * @param hosts The hosts that were deleted.
		 */
		HostsDeletedTskEvent(List<Host> hosts) {
			super(hosts);
		}
	}

	/**
	 * Event fired by OsAccountManager to indicate that a new OsAccount was
	 * created.
	 */
	public static final class OsAccountsAddedTskEvent {

		private final List<OsAccount> accountList;

		/**
		 * Constructs a new AddedEvent
		 *
		 * @param accountList List newly created accounts.
		 */
		OsAccountsAddedTskEvent(List<OsAccount> accountList) {
			this.accountList = accountList;
		}

		/**
		 * Returns a list of the added OsAccounts.
		 *
		 * @return List of OsAccounts.
		 */
		public List<OsAccount> getOsAcounts() {
			return Collections.unmodifiableList(accountList);
		}
	}

	/**
	 * Event fired by OsAccount Manager to indicate that an OsAccount was
	 * updated.
	 */
	public static final class OsAccountsChangedTskEvent {

		private final List<OsAccount> accountList;

		/**
		 * Constructs a new ChangeEvent
		 *
		 * @param accountList List newly created accounts.
		 */
		OsAccountsChangedTskEvent(List<OsAccount> accountList) {
			this.accountList = accountList;
		}

		/**
		 * Returns a list of the updated OsAccounts.
		 *
		 * @return List of OsAccounts.
		 */
		public List<OsAccount> getOsAcounts() {
			return Collections.unmodifiableList(accountList);
		}
	}

	/**
	 * Event fired by OsAccount Manager to indicate that an OsAccount was
	 * deleted.
	 */
	public static final class OsAccountsDeletedTskEvent {

		private final List<Long> accountObjectIds;

		/**
		 * Constructs a new DeleteEvent
		 *
		 * @param accountList List newly deleted accounts.
		 */
		OsAccountsDeletedTskEvent(List<Long> accountObjectIds) {
			this.accountObjectIds = accountObjectIds;
		}

		/**
		 * Returns a list of the deleted OsAccounts.
		 *
		 * @return List of OsAccounts.
		 */
		public List<Long> getOsAcountObjectIds() {
			return Collections.unmodifiableList(accountObjectIds);
		}
	}

	/**
	 * Base event for all person events
	 */
	static class PersonsTskEvent {

		private final List<Person> persons;

		/**
		 * Main constructor.
		 *
		 * @param persons The persons that are objects of the event.
		 */
		PersonsTskEvent(List<Person> persons) {
			this.persons = persons;
		}

		/**
		 * Returns the persons affected in the event.
		 *
		 * @return The persons affected in the event.
		 */
		public List<Person> getPersons() {
			return Collections.unmodifiableList(new ArrayList<>(persons));
		}
	}

	/**
	 * Event fired when persons are created.
	 */
	final public static class PersonsAddedTskEvent extends PersonsTskEvent {

		/**
		 * Main constructor.
		 *
		 * @param persons The added persons.
		 */
		PersonsAddedTskEvent(List<Person> persons) {
			super(persons);
		}
	}

	/**
	 * Event fired when persons are updated.
	 */
	final public static class PersonsChangedTskEvent extends PersonsTskEvent {

		/**
		 * Main constructor.
		 *
		 * @param persons The new values for the persons that were changed.
		 */
		PersonsChangedTskEvent(List<Person> persons) {
			super(persons);
		}
	}

	/**
	 * Event fired when persons are deleted.
	 */
	final public static class PersonsDeletedTskEvent extends PersonsTskEvent {

		/**
		 * Main constructor.
		 *
		 * @param persons The persons that were deleted.
		 */
		PersonsDeletedTskEvent(List<Person> persons) {
			super(persons);
		}
	}
}
