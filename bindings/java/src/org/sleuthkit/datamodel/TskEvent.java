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
 * An interface and implementations for data model events.
 */
public interface TskEvent {

	/**
	 * An abstract base class for data model events.
	 *
	 * @param <T> A data model object type parameter.
	 */
	abstract static class DataModelObjectsEvent<T> implements TskEvent {

		private final List<T> dataModelObjects;

		/**
		 * Constructs an abstract base class for data model events.
		 *
		 * @param dataModelObjects The data model objects that are the subject
		 *                         of the event.
		 */
		DataModelObjectsEvent(List<T> dataModelObjects) {
			this.dataModelObjects = new ArrayList<>();
			this.dataModelObjects.addAll(dataModelObjects);
		}

		/**
		 * Gets the data model objects that are the subjects of the event.
		 *
		 * @return The data model objects.
		 */
		List<T> getDataModelObjects() {
			return Collections.unmodifiableList(dataModelObjects);
		}

	}

	/**
	 * An abstract base class for data model object deletion events.
	 */
	abstract static class DataModelObjectsDeletedEvent extends DataModelObjectsEvent<Long> {

		/**
		 * Constructs an abstract base class for data model object deletion
		 * events.
		 *
		 * @param deletedObjIds The unique numeric IDs (TSK object IDs, case
		 *                      database row IDs, etc.) of the deleted data
		 *                      model objects.
		 */
		DataModelObjectsDeletedEvent(List<Long> deletedObjIds) {
			super(deletedObjIds);
		}

		/**
		 * Gets the unique numeric IDs (TSK object IDs, case database row IDs,
		 * etc.) of the deleted data model objects.
		 *
		 * @return The object IDs.
		 */
		public List<Long> getObjectIds() {
			return getDataModelObjects();
		}

	}

	/**
	 * An event fired when the aggregate scores of one or more objects change.
	 */
	final public static class AggregateScoresChangedEvent extends DataModelObjectsEvent<ScoreChange> {

		/**
		 * Constructs an event fired when the aggregate scores of one or more
		 * objects change.
		 *
		 * @param scoreChanges The score changes.
		 */
		AggregateScoresChangedEvent(List<ScoreChange> scoreChanges) {
			super(scoreChanges);
		}

		/**
		 * Gets the score changes.
		 *
		 * @return The score changes.
		 */
		public List<ScoreChange> getScoreChanges() {
			return getDataModelObjects();
		}

	}

	/**
	 * An event fired when analysis results are deleted.
	 */
	final public static class AnalysisResultsDeletedTskEvent extends DataModelObjectsDeletedEvent {

		/**
		 * Constructs an event fired when analysis results are deleted.
		 *
		 * @param deletedResults The object IDs of the deleted analysis results.
		 */
		AnalysisResultsDeletedTskEvent(List<Long> deletedResultObjIds) {
			super(deletedResultObjIds);
		}

	}

	/**
	 * An abstract base class for host events.
	 */
	abstract static class HostsTskEvent extends DataModelObjectsEvent<Host> {

		/**
		 * Constructs a super class for a host event.
		 *
		 * @param hosts The hosts that are the subjects of the event.
		 */
		HostsTskEvent(List<Host> hosts) {
			super(hosts);
		}

		/**
		 * Gets the hosts.
		 *
		 * @return The hosts.
		 */
		public List<Host> getHosts() {
			return getDataModelObjects();
		}
	}

	/**
	 * An event fired when hosts are added.
	 */
	public static final class HostsAddedTskEvent extends HostsTskEvent {

		/**
		 * Constructs an event fired when hosts are added.
		 *
		 * @param hosts The hosts.
		 */
		HostsAddedTskEvent(List<Host> hosts) {
			super(hosts);
		}

	}

	/**
	 * An event fired when hosts are updated.
	 */
	public static final class HostsUpdatedTskEvent extends HostsTskEvent {

		/**
		 * Constructs an event fired when hosts are updated.
		 *
		 * @param hosts The hosts.
		 */
		HostsUpdatedTskEvent(List<Host> hosts) {
			super(hosts);
		}

	}

	/**
	 * An event fired when hosts are deleted.
	 */
	public static final class HostsDeletedTskEvent extends DataModelObjectsDeletedEvent {

		/**
		 * Constructs an event fired when hosts are deleted.
		 *
		 * @param deletedHostObjIds The object IDs of the deleted hosts.
		 */
		HostsDeletedTskEvent(List<Long> deletedHostObjIds) {
			super(deletedHostObjIds);
		}

	}

	/**
	 * An abstract base class for OS account events.
	 */
	abstract static class OsAccountsTskEvent extends DataModelObjectsEvent<OsAccount> {

		/**
		 * Constructs an abstract base class for OS account events.
		 *
		 * @param hosts The OS accounts that are the subjects of the event.
		 */
		OsAccountsTskEvent(List<OsAccount> osAccounts) {
			super(osAccounts);
		}

		/**
		 * Gets the OS accounts.
		 *
		 * @return The OS accounts.
		 */
		public List<OsAccount> getOsAcounts() {
			return getDataModelObjects();
		}

	}

	/**
	 * An event fired when OS accounts are added.
	 */
	public static final class OsAccountsAddedTskEvent extends OsAccountsTskEvent {

		/**
		 * Constructs an event fired when OS accounts are added.
		 *
		 * @param accountList The OS accounts.
		 */
		OsAccountsAddedTskEvent(List<OsAccount> accountList) {
			super(accountList);
		}

	}

	/**
	 * An event fired when OS accounts are updated.
	 */
	public static final class OsAccountsUpdatedTskEvent extends OsAccountsTskEvent {

		/**
		 * Constructs an event fired when OS accounts are updated.
		 *
		 * @param accountList The OS accounts.
		 */
		OsAccountsUpdatedTskEvent(List<OsAccount> accountList) {
			super(accountList);
		}

	}

	/**
	 * An event fired when OS accounts are deleted.
	 */
	public static final class OsAccountsDeletedTskEvent extends DataModelObjectsDeletedEvent {

		/**
		 * Constructs an event fired when OS accounts are deleted.
		 *
		 * @param accountList The object IDs of the deleted OS accounts.
		 */
		OsAccountsDeletedTskEvent(List<Long> accountObjectIds) {
			super(accountObjectIds);
		}

	}

	/**
	 * An abstract base class for person events.
	 */
	static abstract class PersonsTskEvent extends DataModelObjectsEvent<Person> {

		/**
		 * Csontructs an abstract base class for person events.
		 *
		 * @param persons The persons that are the subjects of the event.
		 */
		PersonsTskEvent(List<Person> persons) {
			super(persons);
		}

		/**
		 * Gets the affected persons.
		 *
		 * @return The affected persons.
		 */
		public List<Person> getPersons() {
			return getDataModelObjects();
		}

	}

	/**
	 * An event fired when persons are added.
	 */
	final public static class PersonsAddedTskEvent extends PersonsTskEvent {

		/**
		 * Constructs an event fired when persons are added.
		 *
		 * @param persons The persons.
		 */
		PersonsAddedTskEvent(List<Person> persons) {
			super(persons);
		}

	}

	/**
	 * An event fired when persons are updated.
	 */
	final public static class PersonsUpdatedTskEvent extends PersonsTskEvent {

		/**
		 * Constructs an event fired when persons are updated.
		 *
		 * @param persons The persons.
		 */
		PersonsUpdatedTskEvent(List<Person> persons) {
			super(persons);
		}

	}

	/**
	 * An event fired when persons are deleted.
	 */
	final public static class PersonsDeletedTskEvent extends DataModelObjectsDeletedEvent {

		/**
		 * Constructs an event fired when persons are deleted.
		 *
		 * @param persons The persons.
		 */
		PersonsDeletedTskEvent(List<Long> personObjectIDs) {
			super(personObjectIDs);
		}

	}

}
