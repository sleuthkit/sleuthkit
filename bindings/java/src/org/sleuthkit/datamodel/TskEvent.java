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
 * Data model events.
 */
public interface TskEvent {

	/**
	 * An abstract super class for data model events for one or more data module
	 * objects.
	 *
	 * @param <T> The type of data model object that is the subject of the
	 *            event.
	 */
	abstract static class TskObjectsEvent<T> implements TskEvent {

		private final List<T> dataModelObjects;

		/**
		 * Constructs the super class part for data model events for one or more
		 * data module objects.
		 *
		 * @param dataModelObjects The data model objects that are the subjects
		 *                         of the event.
		 */
		TskObjectsEvent(List<T> dataModelObjects) {
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
	 * An event published when the aggregate scores of one or more data model
	 * objects change.
	 */
	public final static class AggregateScoresChangedEvent extends TskObjectsEvent<ScoreChange> {

		/**
		 * Constructs an event published when the aggregate scores of one or
		 * more data model objects change.
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
	 * An event published when one or more analysis results are deleted.
	 */
	public final static class AnalysisResultsDeletedTskEvent extends TskObjectsEvent<Long> {

		/**
		 * Constructs an event published when one or more analysis results are
		 * deleted.
		 *
		 * @param deletedResults The TSK object IDs of the deleted analysis
		 *                       results.
		 */
		AnalysisResultsDeletedTskEvent(List<Long> deletedResultObjIds) {
			super(deletedResultObjIds);
		}

		/**
		 * Gets the TSK object IDs of the deleted analysis results.
		 *
		 * @return The TSK object IDs.
		 */
		public List<Long> getAnalysisResultIds() {
			return getDataModelObjects();
		}

	}

	/**
	 * An abstract super class for host events.
	 */
	abstract static class HostsTskEvent extends TskObjectsEvent<Host> {

		/**
		 * Constructs the super class part for a host event.
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
	 * An event published when one or more hosts are added.
	 */
	public final static class HostsAddedTskEvent extends HostsTskEvent {

		/**
		 * Constructs an event published when one or more hosts are added.
		 *
		 * @param hosts The hosts.
		 */
		HostsAddedTskEvent(List<Host> hosts) {
			super(hosts);
		}

	}

	/**
	 * An event published when one or more hosts are updated.
	 */
	public final static class HostsUpdatedTskEvent extends HostsTskEvent {

		/**
		 * Constructs an event published when one or more hosts are updated.
		 *
		 * @param hosts The hosts.
		 */
		HostsUpdatedTskEvent(List<Host> hosts) {
			super(hosts);
		}

	}

	/**
	 * An event published when one or more hosts are deleted.
	 */
	public final static class HostsDeletedTskEvent extends TskObjectsEvent<Long> {

		/**
		 * Constructs an event published when one or more hosts are deleted.
		 *
		 * @param hostIds The host IDs of the deleted hosts.
		 */
		HostsDeletedTskEvent(List<Long> hostIds) {
			super(hostIds);
		}

		/**
		 * Gets the host IDs of the deleted hosts.
		 *
		 * @return The host IDs.
		 */
		public List<Long> getHostIds() {
			return getDataModelObjects();
		}

	}

	/**
	 * An abstract super class for OS account events.
	 */
	abstract static class OsAccountsTskEvent extends TskObjectsEvent<OsAccount> {

		/**
		 * Constructs the super class part for an OS account event.
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
	 * An event published when one or more OS accounts are added.
	 */
	public final static class OsAccountsAddedTskEvent extends OsAccountsTskEvent {

		/**
		 * Constructs an event published when one or more OS accounts are added.
		 *
		 * @param osAccounts The OS accounts.
		 */
		OsAccountsAddedTskEvent(List<OsAccount> osAccounts) {
			super(osAccounts);
		}

	}

	/**
	 * An event published when one or more OS accounts are updated.
	 */
	public final static class OsAccountsUpdatedTskEvent extends OsAccountsTskEvent {

		/**
		 * Constructs an event published when OS accounts are updated.
		 *
		 * @param osAccounts The OS accounts.
		 */
		OsAccountsUpdatedTskEvent(List<OsAccount> osAccounts) {
			super(osAccounts);
		}

	}

	/**
	 * An event published when one or more OS accounts are deleted.
	 */
	public final static class OsAccountsDeletedTskEvent extends TskObjectsEvent<Long> {

		/**
		 * Constructs an event published when one or more OS accounts are
		 * deleted.
		 *
		 * @param accountList The object IDs of the deleted OS accounts.
		 */
		OsAccountsDeletedTskEvent(List<Long> accountObjectIds) {
			super(accountObjectIds);
		}

		/**
		 * Gets the TSK object IDs of the deleted OS accounts.
		 *
		 * @return The TSK object IDs.
		 */
		public List<Long> getOsAccountObjectIds() {
			return getDataModelObjects();
		}

	}

	/**
	 * An abstract super class for person events.
	 */
	static abstract class PersonsTskEvent extends TskObjectsEvent<Person> {

		/**
		 * Constructs the super class part for a person event.
		 *
		 * @param persons The persons that are the subjects of the event.
		 */
		PersonsTskEvent(List<Person> persons) {
			super(persons);
		}

		/**
		 * Gets the persons.
		 *
		 * @return The persons.
		 */
		public List<Person> getPersons() {
			return getDataModelObjects();
		}

	}

	/**
	 * An event published when one or more persons are added.
	 */
	public final static class PersonsAddedTskEvent extends PersonsTskEvent {

		/**
		 * Constructs an event published when one or more persons are added.
		 *
		 * @param persons The persons.
		 */
		PersonsAddedTskEvent(List<Person> persons) {
			super(persons);
		}

	}

	/**
	 * An event published when one or more persons are updated.
	 */
	public final static class PersonsUpdatedTskEvent extends PersonsTskEvent {

		/**
		 * Constructs an event published when one or more persons are updated.
		 *
		 * @param persons The persons.
		 */
		PersonsUpdatedTskEvent(List<Person> persons) {
			super(persons);
		}

	}

	/**
	 * An event published when one or more persons are deleted.
	 */
	public final static class PersonsDeletedTskEvent extends TskObjectsEvent<Long> {

		/**
		 * Constructs an event published when one or more persons are deleted.
		 *
		 * @param persons The persons.
		 */
		PersonsDeletedTskEvent(List<Long> personObjectIDs) {
			super(personObjectIDs);
		}

		/**
		 * Gets the person IDs of the deleted persons.
		 *
		 * @return The person IDs.
		 */
		public List<Long> getPersonIds() {
			return getDataModelObjects();
		}

	}

	/**
	 * An abstract super class for person and host association change events.
	 */
	static abstract class PersonHostsTskEvent extends TskObjectsEvent<Host> {

		private final Person person;

		/**
		 * Constructs the super class part of a person and host association
		 * change event.
		 *
		 * @param person The person that is the subject of the event.
		 * @param hosts  The hosts that are the subjects of the event.
		 */
		PersonHostsTskEvent(Person person, List<Host> hosts) {
			super(hosts);
			this.person = person;
		}

		/**
		 * Gets the person.
		 *
		 * @return The person.
		 */
		public Person getPerson() {
			return person;
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
	 * An event published when one or more hosts are added to a person.
	 */
	public final static class HostsAddedToPersonTskEvent extends PersonHostsTskEvent {

		/**
		 * Contructs an event published when one or more hosts are added to a
		 * person.
		 *
		 * @param person The person.
		 * @param hosts  The hosts.
		 */
		HostsAddedToPersonTskEvent(Person person, List<Host> hosts) {
			super(person, hosts);
		}

	}

	/**
	 * An event published when one or more hosts are removed from a person.
	 */
	public final static class HostsRemovedFromPersonTskEvent extends PersonHostsTskEvent {

		/**
		 * Contructs an event published when one or more hosts are removed from
		 * a person.
		 *
		 * @param person  The person.
		 * @param hostIds The hosts.
		 */
		HostsRemovedFromPersonTskEvent(Person person, List<Host> hostIds) {
			super(person, hostIds);
		}

	}

}
