/*
 * Sleuth Kit Data Model
 *
 * Copyright 2018-2019 Basis Technology Corp.
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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.Lists;
import com.google.common.net.MediaType;
import static java.util.Arrays.asList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import static java.util.stream.Collectors.joining;
import java.util.stream.Stream;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.Property;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import static org.apache.commons.lang3.ObjectUtils.notEqual;
import org.apache.commons.lang3.StringUtils;
import static org.sleuthkit.datamodel.SleuthkitCase.escapeSingleQuotes;

/**
 * An interface for timeline event filters used to selectively query the
 * timeline tables in the case database via the APIs of the timeline manager.
 */
public abstract class TimelineFilter {

	/**
	 * Gets the display name for this filter.
	 *
	 * @return The display name.
	 */
	public abstract String getDisplayName();

	/**
	 * Get the SQL where clause corresponding to this filter.
	 *
	 * @param manager The TimelineManager to use for DB spevific parts of the
	 *                query.
	 *
	 * @return an SQL where clause (without the "where") corresponding to this
	 *         filter
	 */
	abstract String getSQLWhere(TimelineManager manager);

	/**
	 * Makes a copy of this filter.
	 *
	 * @return A copy of this filter.
	 */
	public abstract TimelineFilter copyOf();

	@SuppressWarnings("unchecked")
	static <S extends TimelineFilter, T extends CompoundFilter<S>> T copySubFilters(T from, T to) {
		from.getSubFilters().forEach(subFilter -> to.addSubFilter((S) subFilter.copyOf()));
		return to;
	}

	/**
	 * An intersection filter that ANDs together a collection of timeline event
	 * filters.
	 *
	 * @param <SubFilterType> The type of the filters to be AND'ed together.
	 */
	public static class IntersectionFilter<SubFilterType extends TimelineFilter> extends CompoundFilter<SubFilterType> {

		/**
		 * Constructs an intersection filter that ANDs together a collection of
		 * timeline filters.
		 *
		 * @param subFilters The collection of filters to be AND'ed together.
		 */
		@VisibleForTesting
		public IntersectionFilter(List<SubFilterType> subFilters) {
			super(subFilters);
		}

		@Override
		public IntersectionFilter<SubFilterType> copyOf() {
			@SuppressWarnings("unchecked")
			List<SubFilterType> subfilters = Lists.transform(getSubFilters(), f -> (SubFilterType) f.copyOf()); //make copies of all the subfilters.
			return new IntersectionFilter<>(subfilters);
		}

		@Override
		public String getDisplayName() {
			String subFilterDisplayNames = getSubFilters().stream()
					.map(TimelineFilter::getDisplayName)
					.collect(joining(","));
			return BundleProvider.getBundle().getString("IntersectionFilter.displayName.text") + "[" + subFilterDisplayNames + "]";
		}

		@Override
		String getSQLWhere(TimelineManager manager) {
			String trueLiteral = manager.getSQLWhere(null);
			String join = this.getSubFilters().stream()
					.filter(Objects::nonNull)
					.map(filter -> filter.getSQLWhere(manager))
					.filter(sqlString -> notEqual(sqlString, trueLiteral))
					.collect(Collectors.joining(" AND "));
			return join.isEmpty() ? trueLiteral : "(" + join + ")";
		}

	}

	/**
	 * A timeline event filter used to query for a subset of the event types in
	 * the event types hierarchy. An instance of the filter cn be built with a
	 * recursive descent from any given type in the hierarchy.
	 */
	public static final class EventTypesFilter extends UnionFilter<EventTypesFilter> {

		private final TimelineEventType rootEventType;

		private EventTypesFilter(TimelineEventType rootEventType, boolean recursive) {
			super(FXCollections.observableArrayList());
			this.rootEventType = rootEventType;
			if (recursive) {
				// add subfilters for each subtype
				for (TimelineEventType subType : rootEventType.getChildren()) {
					addSubFilter(new EventTypesFilter(subType));
				}
			}
		}

		/**
		 * Constructs a timeline event filter used to query for a subset of the
		 * event types in the event types hierarchy. The subset of event types
		 * that pass the filter is determined by a recursive descent from any
		 * given type in the hierarchy.
		 *
		 * @param rootEventType The "root" of the event hierarchy for the
		 *                      purposes of this filter.
		 */
		public EventTypesFilter(TimelineEventType rootEventType) {
			this(rootEventType, true);
		}

		/**
		 * Gets the "root" of the event hierarchy for the purposes of this
		 * filter.
		 *
		 * @return The "root" event type.
		 */
		public TimelineEventType getRootEventType() {
			return rootEventType;
		}

		@Override
		public String getDisplayName() {
			return (TimelineEventType.ROOT_EVENT_TYPE.equals(rootEventType)) ? BundleProvider.getBundle().getString("TypeFilter.displayName.text") : rootEventType.getDisplayName();
		}

		@Override
		public EventTypesFilter copyOf() {
			//make a nonrecursive copy of this filter, and then copy subfilters
			return copySubFilters(this, new EventTypesFilter(rootEventType, false));
		}

		@Override
		public int hashCode() {
			int hash = 7;
			hash = 17 * hash + Objects.hashCode(this.rootEventType);
			return hash;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			final EventTypesFilter other = (EventTypesFilter) obj;
			if (notEqual(this.rootEventType, other.rootEventType)) {
				return false;
			}
			return Objects.equals(this.getSubFilters(), other.getSubFilters());
		}

		@Override
		String getSQLWhere(TimelineManager manager) {
			return "(tsk_events.event_type_id IN (" + getSubTypeIDs().collect(Collectors.joining(",")) + "))"; //NON-NLS
		}

		private Stream<String> getSubTypeIDs() {
			if (this.getSubFilters().isEmpty()) {
				return Stream.of(String.valueOf(getRootEventType().getTypeID()));
			} else {
				return this.getSubFilters().stream().flatMap(EventTypesFilter::getSubTypeIDs);
			}
		}

		@Override
		public String toString() {
			return "EventTypeFilter{" + "rootEventType=" + rootEventType + ", subfilters=" + getSubFilters() + '}';
		}

	}

	/**
	 * A timeline event filter used to query for events where the direct source
	 * (file or artifact) of the events has either been tagged or not tagged.
	 */
	public static final class TaggedEventSourcesFilter extends TimelineFilter {

		private final BooleanProperty eventSourcesAreTagged = new SimpleBooleanProperty();

		/**
		 * Constructs a timeline event filter used to query for a events where
		 * the direct source (file or artifact) of the events has not been
		 * tagged.
		 */
		public TaggedEventSourcesFilter() {
		}

		/**
		 * Constructs a timeline event filter used to query for events where the
		 * direct source (file or artifact) of the events has either been tagged
		 * or not tagged.
		 *
		 * @param eventSourceIsTagged Whether the direct sources of the events
		 *                            need to be tagged or not tagged.
		 */
		public TaggedEventSourcesFilter(boolean eventSourceIsTagged) {
			this.eventSourcesAreTagged.set(eventSourceIsTagged);
		}

		/**
		 * Sets whether the direct sources of the events have to be tagged or
		 * not tagged.
		 *
		 * @param eventSourceIsTagged Whether the direct sources of the events
		 *                            have to be tagged or not tagged.
		 */
		public synchronized void setEventSourcesAreTagged(boolean eventSourceIsTagged) {
			this.eventSourcesAreTagged.set(eventSourceIsTagged);
		}

		/**
		 * Indicates whether the direct sources of the events have to be tagged
		 * or not tagged.
		 *
		 * @return True or false.
		 */
		public synchronized boolean getEventSourceAreTagged() {
			return eventSourcesAreTagged.get();
		}

		@Override
		public String getDisplayName() {
			return BundleProvider.getBundle().getString("tagsFilter.displayName.text");
		}

		@Override
		public TaggedEventSourcesFilter copyOf() {
			return new TaggedEventSourcesFilter(eventSourcesAreTagged.get());
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null || !(obj instanceof TaggedEventSourcesFilter)) {
				return false;
			}

			return ((TaggedEventSourcesFilter) obj).getEventSourceAreTagged() == eventSourcesAreTagged.get();
		}

		@Override
		public int hashCode() {
			int hash = 7;
			hash = 67 * hash + Objects.hashCode(this.eventSourcesAreTagged);
			return hash;
		}

		@Override
		String getSQLWhere(TimelineManager manager) {
			String whereStr = "";
			if (eventSourcesAreTagged.get()) {
				whereStr = "tagged = 1";
			} else {
				whereStr = "tagged = 0";
			}

			return whereStr;
		}

	}

	/**
	 * A union filter that ORs together a collection of timeline event filters.
	 *
	 * @param <SubFilterType> The type of the filters to be OR'ed together.
	 */
	public static abstract class UnionFilter<SubFilterType extends TimelineFilter> extends TimelineFilter.CompoundFilter<SubFilterType> {

		UnionFilter(ObservableList<SubFilterType> subFilters) {
			super(subFilters);
		}

		UnionFilter() {
			super(FXCollections.<SubFilterType>observableArrayList());
		}

		@Override
		public void addSubFilter(SubFilterType subfilter) {
			super.addSubFilter(subfilter);
		}

		@Override
		String getSQLWhere(TimelineManager manager) {
			String join = getSubFilters().stream()
					.map(subFilter -> subFilter.getSQLWhere(manager))
					.collect(Collectors.joining(" OR "));
			return join.isEmpty() ? manager.getSQLWhere(null) : "(" + join + ")";
		}

	}

	/**
	 * A timeline event filter used to query for events that have a particular
	 * substring in their short, medium, or full descriptions.
	 */
	public static final class DescriptionSubstringFilter extends TimelineFilter {

		private final SimpleStringProperty textProperty = new SimpleStringProperty();

		/**
		 * Constructs a timeline event filter used to query for events that have
		 * the empty string as a substring in their short, medium, or full
		 * descriptions.
		 */
		public DescriptionSubstringFilter() {
			this("");
		}

		/**
		 * Constructs a timeline event filter used to query for events that have
		 * a given substring in their short, medium, or full descriptions.
		 *
		 * @param substring The substring that must be present in one or more of
		 *                  the descriptions of each event that passes the
		 *                  filter.
		 */
		public DescriptionSubstringFilter(String substring) {
			super();
			this.textProperty.set(substring.trim());
		}

		/**
		 *
		 * @param text
		 */
		public synchronized void setText(String text) {
			this.textProperty.set(text.trim());
		}

		@Override
		public String getDisplayName() {
			return BundleProvider.getBundle().getString("TextFilter.displayName.text");
		}

		/**
		 * Gets the substring that must be present in one or more of the
		 * descriptions of each event that passes the filter.
		 *
		 * @return The required substring.
		 */
		public synchronized String getSubstring() {
			return textProperty.getValue();
		}

		/**
		 * Gets the substring that must be present in one or more of the
		 * descriptions of each event that passes the filter.
		 *
		 * @return The required substring as a Property.
		 */
		public Property<String> substringProperty() {
			return textProperty;
		}

		@Override
		public synchronized DescriptionSubstringFilter copyOf() {
			return new DescriptionSubstringFilter(getSubstring());
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			final DescriptionSubstringFilter other = (DescriptionSubstringFilter) obj;
			return Objects.equals(getSubstring(), other.getSubstring());
		}

		@Override
		public int hashCode() {
			int hash = 5;
			hash = 29 * hash + Objects.hashCode(this.textProperty.get());
			return hash;
		}

		@Override
		String getSQLWhere(TimelineManager manager) {
			if (StringUtils.isNotBlank(this.getSubstring())) {
				return "((med_description like '%" + escapeSingleQuotes(this.getSubstring()) + "%')" //NON-NLS
						+ " or (full_description like '%" + escapeSingleQuotes(this.getSubstring()) + "%')" //NON-NLS
						+ " or (short_description like '%" + escapeSingleQuotes(this.getSubstring()) + "%'))"; //NON-NLS
			} else {
				return manager.getSQLWhere(null);
			}
		}

		@Override
		public String toString() {
			return "TextFilter{" + "textProperty=" + textProperty.getValue() + '}';
		}

	}

	/**
	 * A timeline filter that ANDs together instances of a variety of event
	 * filter types.
	 */
	public static final class MultiFilterFilter extends IntersectionFilter<TimelineFilter> {

		private final ExcludeKnownSourceFilesFilter knownFilesFilter;
		private final TaggedEventSourcesFilter tagsFilter;
		private final SourceFileHashSetsHitFilter hashSetHitsFilter;
		private final DescriptionSubstringFilter descriptionSubstringFilter;
		private final EventTypesFilter eventTypesFilter;
		private final DataSourcesFilter dataSourcesFilter;
		private final CompositeSourceFileTypesFilter fileTypesFilter;
		private final Set<TimelineFilter> additionalFilters = new HashSet<>();

		/**
		 * Get the data sources filter of this multi-filter.
		 *
		 * @return The filter.
		 */
		public DataSourcesFilter getDataSourcesFilter() {
			return dataSourcesFilter;
		}

		/**
		 * Gets the tagged events sources filter of this multi-filter.
		 *
		 * @return The filter.
		 */
		public TaggedEventSourcesFilter getTaggedEventSourcesFilter() {
			return tagsFilter;
		}

		/**
		 * Gets the source file hash set hits filter of this multi-filter.
		 *
		 * @return The filter.
		 */
		public SourceFileHashSetsHitFilter geSourceFileHashSetsHitFilter() {
			return hashSetHitsFilter;
		}

		/**
		 * Gets the event types filter of this multi-filter.
		 *
		 * @return The filter.
		 */
		public EventTypesFilter getEventTypesFilter() {
			return eventTypesFilter;
		}

		/**
		 * Gets the exclude known source files filter of this multi-filter.
		 *
		 * @return The filter.
		 */
		public ExcludeKnownSourceFilesFilter getExcludeKnownEventSourcesFilter() {
			return knownFilesFilter;
		}

		/**
		 * Gets the description substring filter of this multi-filter.
		 *
		 * @return The filter.
		 */
		public DescriptionSubstringFilter getDescriptionSubstringFilter() {
			return descriptionSubstringFilter;
		}

		/**
		 * Gets the composite source file types filter of this multi-filter.
		 *
		 * @return The filter.
		 */
		public CompositeSourceFileTypesFilter getFileTypesFilter() {
			return fileTypesFilter;
		}

		/**
		 * Constructs a timeline filter that ANDs together instances of a
		 * variety of event filter types.
		 *
		 * @param knownFilesFilter           A filter that excludes events with
		 *                                   knwon file event sources.
		 * @param tagsFilter                 A filter that exludes or includes
		 *                                   events with tagged event sources.
		 * @param hashSetHitsFilter          A filter that excludes or includes
		 *                                   events with event sources that have
		 *                                   hash set hits.
		 * @param descriptionSubstringFilter A filter that requires a substring
		 *                                   to be present in the event
		 *                                   description.
		 * @param eventTypesFilter           A filter that accepts events of
		 *                                   specified events types.
		 * @param dataSourcesFilter          A filter that accepts events
		 *                                   associated with a specified subset
		 *                                   of data sources.
		 * @param fileTypesFilterA           A filter that includes or excludes
		 *                                   events with source files of
		 *                                   particular media types.
		 * @param additionalFilters          Additional filters.
		 */
		public MultiFilterFilter(
				ExcludeKnownSourceFilesFilter knownFilesFilter,
				TaggedEventSourcesFilter tagsFilter,
				SourceFileHashSetsHitFilter hashSetHitsFilter,
				DescriptionSubstringFilter descriptionSubstringFilter,
				EventTypesFilter eventTypesFilter,
				DataSourcesFilter dataSourcesFilter,
				CompositeSourceFileTypesFilter fileTypesFilter,
				Collection<TimelineFilter> additionalFilters) {

			super(FXCollections.observableArrayList(descriptionSubstringFilter, knownFilesFilter, tagsFilter, dataSourcesFilter, hashSetHitsFilter, fileTypesFilter, eventTypesFilter));
			getSubFilters().removeIf(Objects::isNull);
			this.knownFilesFilter = knownFilesFilter;
			this.tagsFilter = tagsFilter;
			this.hashSetHitsFilter = hashSetHitsFilter;
			this.descriptionSubstringFilter = descriptionSubstringFilter;
			this.eventTypesFilter = eventTypesFilter;
			this.dataSourcesFilter = dataSourcesFilter;
			this.fileTypesFilter = fileTypesFilter;
			this.additionalFilters.addAll(asList(descriptionSubstringFilter, knownFilesFilter, tagsFilter, dataSourcesFilter, hashSetHitsFilter, fileTypesFilter, eventTypesFilter));
			this.additionalFilters.removeIf(Objects::isNull);
			additionalFilters.stream().
					filter(Objects::nonNull).
					filter(this::isNotNamedSubFilter).
					map(TimelineFilter::copyOf).
					forEach(anonymousFilter -> getSubFilters().add(anonymousFilter));
		}

		@Override
		public MultiFilterFilter copyOf() {
			Set<TimelineFilter> annonymousSubFilters = getSubFilters().stream()
					.filter(this::isNotNamedSubFilter)
					.map(TimelineFilter::copyOf)
					.collect(Collectors.toSet());
			return new MultiFilterFilter(knownFilesFilter.copyOf(), tagsFilter.copyOf(),
					hashSetHitsFilter.copyOf(), descriptionSubstringFilter.copyOf(), eventTypesFilter.copyOf(),
					dataSourcesFilter.copyOf(), fileTypesFilter.copyOf(), annonymousSubFilters);

		}

		private boolean isNotNamedSubFilter(TimelineFilter subFilter) {
			return !(additionalFilters.contains(subFilter));
		}

		@Override
		public String toString() {
			return "RootFilter{" + "knownFilter=" + knownFilesFilter + ", tagsFilter=" + tagsFilter + ", hashFilter=" + hashSetHitsFilter + ", textFilter=" + descriptionSubstringFilter + ", typeFilter=" + eventTypesFilter + ", dataSourcesFilter=" + dataSourcesFilter + ", fileTypesFilter=" + fileTypesFilter + ", namedSubFilters=" + additionalFilters + '}';
		}

		@Override
		public int hashCode() {
			int hash = 7;
			hash = 17 * hash + Objects.hashCode(this.knownFilesFilter);
			hash = 17 * hash + Objects.hashCode(this.tagsFilter);
			hash = 17 * hash + Objects.hashCode(this.hashSetHitsFilter);
			hash = 17 * hash + Objects.hashCode(this.descriptionSubstringFilter);
			hash = 17 * hash + Objects.hashCode(this.eventTypesFilter);
			hash = 17 * hash + Objects.hashCode(this.dataSourcesFilter);
			hash = 17 * hash + Objects.hashCode(this.fileTypesFilter);
			hash = 17 * hash + Objects.hashCode(this.additionalFilters);
			return hash;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			final MultiFilterFilter other = (MultiFilterFilter) obj;
			if (notEqual(this.knownFilesFilter, other.getExcludeKnownEventSourcesFilter())) {
				return false;
			}
			if (notEqual(this.tagsFilter, other.getTaggedEventSourcesFilter())) {
				return false;
			}
			if (notEqual(this.hashSetHitsFilter, other.geSourceFileHashSetsHitFilter())) {
				return false;
			}
			if (notEqual(this.descriptionSubstringFilter, other.getDescriptionSubstringFilter())) {
				return false;
			}
			if (notEqual(this.eventTypesFilter, other.getEventTypesFilter())) {
				return false;
			}
			if (notEqual(this.dataSourcesFilter, other.getDataSourcesFilter())) {
				return false;
			}

			if (notEqual(this.fileTypesFilter, other.getFileTypesFilter())) {
				return false;
			}
			return Objects.equals(this.additionalFilters, other.getSubFilters());
		}

	}

	/**
	 * A timeline event filter used to filter out events that have a direct or
	 * indirect event source that is a known file.
	 */
	public static final class ExcludeKnownSourceFilesFilter extends TimelineFilter {

		@Override
		public String getDisplayName() {
			return BundleProvider.getBundle().getString("hideKnownFilter.displayName.text");
		}

		@Override
		public ExcludeKnownSourceFilesFilter copyOf() {
			return new ExcludeKnownSourceFilesFilter();
		}

		@Override
		public int hashCode() {
			return 7;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null) {
				return false;
			}
			return getClass() == obj.getClass();
		}

		@Override
		String getSQLWhere(TimelineManager manager) {
			return "(known_state != " + TskData.FileKnown.KNOWN.getFileKnownValue() + ")"; // NON-NLS
		}

		@Override
		public String toString() {
			return "HideKnownFilter{" + '}';
		}

	}

	/**
	 * A timeline event filter composed of a collection of event filters.
	 * Concrete implementations can decide how to combine the filters in the
	 * collection.
	 *
	 * @param <SubFilterType> The type of the subfilters.
	 */
	public static abstract class CompoundFilter<SubFilterType extends TimelineFilter> extends TimelineFilter {

		protected void addSubFilter(SubFilterType subfilter) {
			if (getSubFilters().contains(subfilter) == false) {
				getSubFilters().add(subfilter);
			}
		}

		private final ObservableList<SubFilterType> filters = FXCollections.observableArrayList();

		/**
		 * Gets the collection of filters that make up this filter.
		 *
		 * @return The filters.
		 */
		public final ObservableList<SubFilterType> getSubFilters() {
			return filters;
		}

		/**
		 * Indicates whether or not this filter has subfilters.
		 *
		 * @return True or false.
		 */
		public boolean hasSubFilters() {
			return getSubFilters().isEmpty() == false;
		}

		/**
		 * Constructs a timeline event filter composed of a collection of event
		 * filters.
		 *
		 * @param subFilters The collection of filters.
		 */
		protected CompoundFilter(List<SubFilterType> subFilters) {
			super();
			this.filters.setAll(subFilters);
		}

		@Override
		public abstract CompoundFilter<SubFilterType> copyOf();

		@Override
		public int hashCode() {
			int hash = 3;
			hash = 23 * hash + Objects.hashCode(this.filters);
			return hash;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			final CompoundFilter<?> other = (CompoundFilter<?>) obj;
			return Objects.equals(this.getSubFilters(), other.getSubFilters());
		}

		@Override
		public String toString() {
			return this.getClass().getSimpleName() + "{" + "subFilters=" + filters + '}';
		}

	}

	/**
	 * A timeline event filter used to query for events associated with a given
	 * data source.
	 */
	public static final class DataSourceFilter extends TimelineFilter {

		private final String dataSourceName;
		private final long dataSourceID;

		/**
		 * Gets the object ID of the specified data source.
		 *
		 * @return The data source object ID.
		 */
		public long getDataSourceID() {
			return dataSourceID;
		}

		/**
		 * Gets the display name of the specified data source.
		 *
		 * @return The data source display name.
		 */
		public String getDataSourceName() {
			return dataSourceName;
		}

		/**
		 * Constructs a timeline event filter used to query for events
		 * associated with a given data source.
		 *
		 * @param dataSourceName The data source display name.
		 * @param dataSourceID   The data source object ID.
		 */
		public DataSourceFilter(String dataSourceName, long dataSourceID) {
			super();
			this.dataSourceName = dataSourceName;
			this.dataSourceID = dataSourceID;
		}

		@Override
		public synchronized DataSourceFilter copyOf() {
			return new DataSourceFilter(getDataSourceName(), getDataSourceID());
		}

		@Override
		public String getDisplayName() {
			return getDataSourceName() + " (ID: " + getDataSourceID() + ")";
		}

		@Override
		public int hashCode() {
			int hash = 3;
			hash = 47 * hash + Objects.hashCode(this.dataSourceName);
			hash = 47 * hash + (int) (this.dataSourceID ^ (this.dataSourceID >>> 32));
			return hash;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			final DataSourceFilter other = (DataSourceFilter) obj;
			if (this.dataSourceID != other.dataSourceID) {
				return false;
			}
			return Objects.equals(this.dataSourceName, other.dataSourceName);
		}

		@Override
		String getSQLWhere(TimelineManager manager) {
			return "(data_source_obj_id = '" + this.getDataSourceID() + "')"; //NON-NLS
		}

	}

	/**
	 * A timeline event filter used to query for events where the direct or
	 * indirect sources of the events have or do not have hash set hits.
	 *
	 */
	public static final class SourceFileHashSetsHitFilter extends TimelineFilter {

		private final BooleanProperty eventSourcesHaveHashSetHits = new SimpleBooleanProperty();

		/**
		 * Constructs a timeline event filter used to query for events where the
		 * direct or indirect sources of the events do not have hash set hits.
		 */
		public SourceFileHashSetsHitFilter() {
		}

		/**
		 * Construct the hash hit filter and set state based given argument.
		 *
		 * @param hasHashHit True to filter items that have hash hits.
		 */
		public SourceFileHashSetsHitFilter(boolean hasHashHit) {
			eventSourcesHaveHashSetHits.set(hasHashHit);
		}

		/**
		 * Set the state of the filter.
		 *
		 * @param hasHashHit True to filter by items that have hash hits.
		 */
		public synchronized void setEventSourcesHaveHashSetHits(boolean hasHashHit) {
			eventSourcesHaveHashSetHits.set(hasHashHit);
		}

		/**
		 * Returns the current state of the filter.
		 *
		 * @return True to filter by hash hits
		 */
		public synchronized boolean getEventSourcesHaveHashSetHits() {
			return eventSourcesHaveHashSetHits.get();
		}

		@Override
		public String getDisplayName() {
			return BundleProvider.getBundle().getString("hashHitsFilter.displayName.text");
		}

		@Override
		public SourceFileHashSetsHitFilter copyOf() {
			return new SourceFileHashSetsHitFilter(eventSourcesHaveHashSetHits.get());
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null || !(obj instanceof SourceFileHashSetsHitFilter)) {
				return false;
			}

			return ((SourceFileHashSetsHitFilter) obj).getEventSourcesHaveHashSetHits() == eventSourcesHaveHashSetHits.get();
		}

		@Override
		public int hashCode() {
			int hash = 7;
			hash = 67 * hash + Objects.hashCode(this.eventSourcesHaveHashSetHits);
			return hash;
		}

		@Override
		String getSQLWhere(TimelineManager manager) {
			String whereStr = "";
			if (eventSourcesHaveHashSetHits.get()) {
				whereStr = "hash_hit = 1";
			} else {
				whereStr = "hash_hit = 0";
			}

			return whereStr;
		}

	}

	/**
	 * A timeline event filter used to query for events associated with a given
	 * subset of data sources. The filter is a union of one or more single data
	 * source filters.
	 */
	static public final class DataSourcesFilter extends UnionFilter<DataSourceFilter> {

		@Override
		public DataSourcesFilter copyOf() {
			return copySubFilters(this, new DataSourcesFilter());
		}

		@Override
		public String getDisplayName() {
			return BundleProvider.getBundle().getString("DataSourcesFilter.displayName.text");
		}

	}

	/**
	 * A timeline event filter used to query for events with direct or indirect
	 * event sources that are files with a given set of media types. The filter
	 * is a union of one or more file source filters.
	 */
	static public final class CompositeSourceFileTypesFilter extends UnionFilter<SourceFileTypesFilter> {

		@Override
		public CompositeSourceFileTypesFilter copyOf() {
			return copySubFilters(this, new CompositeSourceFileTypesFilter());
		}

		@Override
		public String getDisplayName() {
			return BundleProvider.getBundle().getString("FileTypesFilter.displayName.text");

		}

	}

	/**
	 * A timeline event filter used to query for events with direct or indirect
	 * event sources that are files that do not have a given set of media types.
	 */
	static public class ExcludeSourceFileTypesFilter extends SourceFileTypesFilter {

		public ExcludeSourceFileTypesFilter(String displayName, Collection<String> mediaTypes) {
			super(displayName, mediaTypes);
		}

		@Override
		public ExcludeSourceFileTypesFilter copyOf() {
			return new ExcludeSourceFileTypesFilter(getDisplayName(), super.mediaTypes);
		}

		@Override
		String getSQLWhere(TimelineManager manager) {
			return " NOT " + super.getSQLWhere(manager);
		}
	}

	/**
	 * A timeline event filter used to query for events with direct or indirect
	 * event sources that are files with a given set of media types.
	 */
	public static class SourceFileTypesFilter extends TimelineFilter {

		private final String displayName;
		private final String sqlWhere;
		Collection<String> mediaTypes = new HashSet<>();

		private SourceFileTypesFilter(String displayName, String sql) {
			this.displayName = displayName;
			this.sqlWhere = sql;
		}

		/**
		 * Constructs a timeline event filter used to query for events with
		 * direct or indirect event sources that are files with a given set of
		 * media types.
		 *
		 * @param displayName The display name for the filter.
		 * @param mediaTypes  The event source file media types that pass the
		 *                    filter.
		 */
		public SourceFileTypesFilter(String displayName, Collection<String> mediaTypes) {
			this(displayName,
					mediaTypes.stream()
							.map(MediaType::parse)
							.map(SourceFileTypesFilter::mediaTypeToSQL)
							.collect(Collectors.joining(" OR ", "(", ")")));
			this.mediaTypes = mediaTypes;
		}

		private static String mediaTypeToSQL(MediaType mediaType) {
			return mediaType.hasWildcard()
					? " (tsk_events.mime_type LIKE '" + escapeSingleQuotes(mediaType.type()) + "/_%' ) "
					: " (tsk_events.mime_type = '" + escapeSingleQuotes(mediaType.toString()) + "' ) ";
		}

		@Override
		public String getDisplayName() {
			return displayName;
		}

		@Override
		public SourceFileTypesFilter copyOf() {
			return new SourceFileTypesFilter(displayName, sqlWhere);
		}

		@Override
		public int hashCode() {
			int hash = 7;
			hash = 17 * hash + Objects.hashCode(this.displayName);
			hash = 17 * hash + Objects.hashCode(this.sqlWhere);
			return hash;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			final SourceFileTypesFilter other = (SourceFileTypesFilter) obj;
			if (notEqual(this.displayName, other.displayName)) {
				return false;
			}
			return Objects.equals(this.sqlWhere, other.sqlWhere);
		}

		@Override
		String getSQLWhere(TimelineManager manager) {
			return sqlWhere;
		}

		@Override
		public String toString() {
			return "FileTypeFilter{" + "displayName=" + displayName + ", sqlWhere=" + sqlWhere + '}';
		}

	}

}
