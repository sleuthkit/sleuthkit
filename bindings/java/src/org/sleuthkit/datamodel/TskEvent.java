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

import com.google.common.collect.ImmutableSet;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Data model events.
 */
public interface TskEvent {

	/**
	 * Gets the data source guaranteed to be associated with the event, if
	 * applicable.
	 *
	 * @return The object ID of the data source associated with the event, if
	 *         specified.
	 */
	default Optional<Long> getDataSourceId() {
		return Optional.ofNullable(null);
	}

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

		private final Long dataSourceObjectId;

		/**
		 * Constructs an event published when the aggregate scores of one or
		 * more data model objects change.
		 *
		 * @param scoreChanges The score changes, must not be empty.
		 */
		AggregateScoresChangedEvent(Long dataSourceObjectId, ImmutableSet<ScoreChange> scoreChanges) {
			super(scoreChanges.asList());
			this.dataSourceObjectId = dataSourceObjectId;
			scoreChanges.stream().forEach(chg -> {
				if (!chg.getDataSourceObjectId().equals(dataSourceObjectId)) {
					throw new IllegalArgumentException("All data source object IDs in List<ScoreChange> must match dataSourceObjectId");
				}
			});
		}

		@Override
		public Optional<Long> getDataSourceId() {
			return Optional.ofNullable(dataSourceObjectId);
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
		 * @param deletedResultObjIds The TSK object IDs of the deleted analysis
		 *                            results.
		 */
		AnalysisResultsDeletedTskEvent(List<Long> deletedResultObjIds) {
			super(deletedResultObjIds);
		}

		/**
		 * Gets the TSK object IDs of the deleted analysis results.
		 *
		 * @return The TSK object IDs.
		 */
		public List<Long> getAnalysisResultObjectIds() {
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
		 * Constructs the super class part of an OS account event.
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
	 * An event published when one or more OS account instances are added.
	 */
	public final static class OsAcctInstancesAddedTskEvent extends TskObjectsEvent<OsAccountInstance> {

		/**
		 * Constructs an event published when one or more OS account instances
		 * are added.
		 *
		 * @param hosts The OS account instances that are the subjects of the
		 *              event.
		 */
		OsAcctInstancesAddedTskEvent(List<OsAccountInstance> osAcctInstances) {
			super(osAcctInstances);
		}

		/**
		 * Gets the OS account instances.
		 *
		 * @return The OS account instances.
		 */
		public List<OsAccountInstance> getOsAccountInstances() {
			return getDataModelObjects();
		}

	}

	/**
	 * An abstract super class for person events.
	 */
	static abstract class PersonsTskEvent extends TskObjectsEvent<Person> {

		/**
		 * Constructs the super class part of a person event.
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
	 * An event published when one or more hosts are added to a person.
	 */
	public final static class HostsAddedToPersonTskEvent extends TskObjectsEvent<Host> {

		private final Person person;

		/**
		 * Constructs the super class part of a person and host association
		 * change event.
		 *
		 * @param person The person that is the subject of the event.
		 * @param hosts  The hosts that are the subjects of the event.
		 */
		HostsAddedToPersonTskEvent(Person person, List<Host> hosts) {
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
	 * An event published when one or more hosts are removed from a person.
	 */
	public final static class HostsRemovedFromPersonTskEvent extends TskObjectsEvent<Long> {

		private final Person person;

		/**
		 * Constructs an event published when one or more hosts are removed from
		 * a person.
		 *
		 * @param person  The person.
		 * @param hostIds The host IDs of the hosts.
		 */
		HostsRemovedFromPersonTskEvent(Person person, List<Long> hostIds) {
			super(hostIds);
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
		 * Gets the host IDs of the deleted hosts.
		 *
		 * @return The host IDs.
		 */
		public List<Long> getHostIds() {
			return getDataModelObjects();
		}

	}

	static abstract class TagNamesTskEvent extends TskObjectsEvent<TagName> {

		public TagNamesTskEvent(List<TagName> tagNames) {
			super(tagNames);
		}

		/**
		 * Returns the list of added or updated TagName objects.
		 *
		 * @return The TagName list.
		 */
		public List<TagName> getTagNames() {
			return getDataModelObjects();
		}

	}

	/**
	 * An event published when one or more TagName are added.
	 */
	public final static class TagNamesAddedTskEvent extends TagNamesTskEvent {

		/**
		 * Construct an event when one or more TagName are created or updated.
		 *
		 * @param tagNames List of added or modified TagName.
		 */
		public TagNamesAddedTskEvent(List<TagName> tagNames) {
			super(tagNames);
		}
	}

	/**
	 * An event published when one or more TagName are updated.
	 */
	public final static class TagNamesUpdatedTskEvent extends TagNamesTskEvent {

		/**
		 * Construct an event when one or more TagName are updated.
		 *
		 * @param tagNames List of added or modified TagName.
		 */
		public TagNamesUpdatedTskEvent(List<TagName> tagNames) {
			super(tagNames);
		}
	}

	/**
	 * An event published when one or more TagName are deleted.
	 */
	public final static class TagNamesDeletedTskEvent extends TskObjectsEvent<Long> {

		/**
		 * Constructs a new event with the given list of TagName ids.
		 *
		 * @param tagNameIds Deleted TagName id list.
		 */
		public TagNamesDeletedTskEvent(List<Long> tagNameIds) {
			super(tagNameIds);
		}

		/**
		 * List of the deleted TagName ids.
		 *
		 * @return The list of deleted TagName Ids.
		 */
		public List<Long> getTagNameIds() {
			return getDataModelObjects();
		}

	}

	/**
	 * An event published when one or more TagSets have been added.
	 */
	public final static class TagSetsAddedTskEvent extends TskObjectsEvent<TagSet> {

		/**
		 * Constructs an added event for one or more TagSets.
		 *
		 * @param tagSets The added TagSet.
		 */
		public TagSetsAddedTskEvent(List<TagSet> tagSets) {
			super(tagSets);
		}

		/**
		 * Return the TagSets list.
		 *
		 * @return The TagSet list.
		 */
		public List<TagSet> getTagSets() {
			return getDataModelObjects();
		}
	}

	/**
	 * An event published when one or more TagSets have been deleted.
	 */
	public final static class TagSetsDeletedTskEvent extends TskObjectsEvent<Long> {

		/**
		 * Constructs a deleted event for one or more TagSets.
		 *
		 * @param tagSetIds The ids of the deleted TagSets.
		 */
		public TagSetsDeletedTskEvent(List<Long> tagSetIds) {
			super(tagSetIds);
		}

		/**
		 * Returns the list of deleted TagSet ids.
		 *
		 * @return The list of deleted TagSet ids.
		 */
		public List<Long> getTagSetIds() {
			return getDataModelObjects();
		}
	}
}
