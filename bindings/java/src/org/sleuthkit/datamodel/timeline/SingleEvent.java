/*
 * Sleuth Kit Data Model
 *
 * Copyright 2018 Basis Technology Corp.
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
package org.sleuthkit.datamodel.timeline;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSortedSet;
import java.util.Collections;
import java.util.Comparator;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import org.joda.time.Interval;
import org.sleuthkit.datamodel.TskData;

/**
 * A single event.
 */
public class SingleEvent implements TimeLineEvent {

	private final long eventID;
	/**
	 * The TSK object ID of the file this event is derived from.
	 */
	private final long objID;

	/**
	 * The TSK artifact ID of the file this event is derived from. Null, if this
	 * event is not derived from an artifact.
	 */
	private final Long artifactID;

	/**
	 * The TSK datasource ID of the datasource this event belongs to.
	 */
	private final long dataSourceID;

	/**
	 * The time of this event in second from the Unix epoch.
	 */
	private final long time;
	/**
	 * The type of this event.
	 */
	private final EventType type;

	/**
	 * The three descriptions (full, med, short) stored in a map, keyed by
	 * DescriptionLOD (Level of Detail)
	 */
	private final ImmutableMap<DescriptionLoD, String> descriptions;

	/**
	 * The known value for the file this event is derived from.
	 */
	private final TskData.FileKnown known;

	/**
	 * True if the file this event is derived from hits any of the configured
	 * hash sets.
	 */
	private final boolean hashHit;

	/**
	 * True if the file or artifact this event is derived from is tagged.
	 */
	private final boolean tagged;

	/**
	 * Single events may or may not have their parent set, since the parent is a
	 * transient property of the current (details) view settings.
	 */
	private MultiEvent<?> parent = null;

	public SingleEvent(long eventID, long dataSourceID, long objID, Long artifactID, long time, EventType type, String fullDescription, String medDescription, String shortDescription, TskData.FileKnown known, boolean hashHit, boolean tagged) {
		this.eventID = eventID;
		this.dataSourceID = dataSourceID;
		this.objID = objID;
		this.artifactID = Long.valueOf(0).equals(artifactID) ? null : artifactID;
		this.time = time;
		this.type = type;
		descriptions = ImmutableMap.<DescriptionLoD, String>of(DescriptionLoD.FULL, fullDescription,
				DescriptionLoD.MEDIUM, medDescription,
				DescriptionLoD.SHORT, shortDescription);
		this.known = known;
		this.hashHit = hashHit;
		this.tagged = tagged;
	}

	/**
	 * Get a new SingleEvent that is the same as this event, but with the given
	 * parent.
	 *
	 * @param newParent the parent of the new event object.
	 *
	 * @return a new SingleEvent that is the same as this event, but with the
	 *         given parent.
	 */
	public SingleEvent withParent(MultiEvent<?> newParent) {
		SingleEvent singleEvent = new SingleEvent(eventID, dataSourceID, objID, artifactID, time, type, descriptions.get(DescriptionLoD.FULL), descriptions.get(DescriptionLoD.MEDIUM), descriptions.get(DescriptionLoD.SHORT), known, hashHit, tagged);
		singleEvent.parent = newParent;
		return singleEvent;
	}

	/**
	 * Is the file or artifact this event is derived from tagged?
	 *
	 * @return true if he file or artifact this event is derived from is tagged.
	 */
	public boolean isTagged() {
		return tagged;
	}

	/**
	 * Is the file this event is derived from in any of the configured hash
	 * sets.
	 *
	 *
	 * @return True if the file this event is derived from is in any of the
	 *         configured hash sets.
	 */
	public boolean isHashHit() {
		return hashHit;
	}

	/**
	 * Get the artifact id of the artifact this event is derived from.
	 *
	 * @return An Optional containing the artifact ID. Will be empty if this
	 *         event is not derived from an artifact
	 */
	public Optional<Long> getArtifactID() {
		return Optional.ofNullable(artifactID);
	}

	/**
	 * Get the event id of this event.
	 *
	 * @return The event id of this event.
	 */
	public long getEventID() {
		return eventID;
	}

	/**
	 * Get the obj id of the file this event is derived from.
	 *
	 * @return the object id.
	 */
	public long getFileID() {
		return objID;
	}

	/**
	 * Get the time of this event (in seconds from the Unix epoch).
	 *
	 * @return the time of this event in seconds from Unix epoch
	 */
	public long getTime() {
		return time;
	}

	@Override
	public EventType getEventType() {
		return type;
	}

	/**
	 * Get the full description of this event.
	 *
	 * @return the full description
	 */
	public String getFullDescription() {
		return getDescription(DescriptionLoD.FULL);
	}

	/**
	 * Get the medium description of this event.
	 *
	 * @return the medium description
	 */
	public String getMedDescription() {
		return getDescription(DescriptionLoD.MEDIUM);
	}

	/**
	 * Get the short description of this event.
	 *
	 * @return the short description
	 */
	public String getShortDescription() {
		return getDescription(DescriptionLoD.SHORT);
	}

	/**
	 * Get the known value of the file this event is derived from.
	 *
	 * @return the known value
	 */
	public TskData.FileKnown getKnown() {
		return known;
	}

	/**
	 * Get the description of this event at the give level of detail(LoD).
	 *
	 * @param lod The level of detail to get.
	 *
	 * @return The description of this event at the given level of detail.
	 */
	public String getDescription(DescriptionLoD lod) {
		return descriptions.get(lod);
	}

	/**
	 * Get the datasource id of the datasource this event belongs to.
	 *
	 * @return the datasource id.
	 */
	public long getDataSourceID() {
		return dataSourceID;
	}

	@Override
	public Set<Long> getEventIDs() {
		return Collections.singleton(eventID);
	}

	@Override
	public Set<Long> getEventIDsWithHashHits() {
		return isHashHit() ? Collections.singleton(eventID) : Collections.emptySet();
	}

	@Override
	public Set<Long> getEventIDsWithTags() {
		return isTagged() ? Collections.singleton(eventID) : Collections.emptySet();
	}

	@Override
	public long getEndMillis() {
		return time * 1000;
	}

	@Override
	public long getStartMillis() {
		return time * 1000;
	}

	@Override
	public int hashCode() {
		int hash = 7;
		hash = 13 * hash + (int) (this.eventID ^ (this.eventID >>> 32));
		return hash;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		final SingleEvent other = (SingleEvent) obj;
		return this.eventID == other.eventID;
	}

	@Override
	public SortedSet<EventCluster> getClusters() {
		EventCluster eventCluster = new EventCluster(new Interval(time * 1000, time * 1000), type, getEventIDs(), getEventIDsWithHashHits(), getEventIDsWithTags(), getFullDescription(), DescriptionLoD.FULL);
		return ImmutableSortedSet.orderedBy(Comparator.comparing(EventCluster::getStartMillis)).add(eventCluster).build();
	}

	@Override
	public String getDescription() {
		return getFullDescription();
	}

	@Override
	public DescriptionLoD getDescriptionLoD() {
		return DescriptionLoD.FULL;
	}

	/**
	 * get the EventStripe (if any) that contains this event, skipping over any
	 * intervening event cluster
	 *
	 * @return an Optional containing the parent stripe of this cluster: empty
	 *         if the cluster has no parent set or the parent has no parent
	 *         stripe.
	 */
	@Override
	public Optional<EventStripe> getParentStripe() {
		if (parent == null) {
			return Optional.empty();
		} else if (parent instanceof EventStripe) {
			return Optional.of((EventStripe) parent);
		} else {
			return parent.getParentStripe();
		}
	}
}
