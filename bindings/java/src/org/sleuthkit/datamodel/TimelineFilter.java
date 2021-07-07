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
import java.util.ArrayList;
import java.util.Arrays;
import static java.util.Arrays.asList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import static java.util.stream.Collectors.joining;
import java.util.stream.Stream;
import static org.apache.commons.lang3.ObjectUtils.notEqual;
import org.apache.commons.lang3.StringUtils;
import static org.sleuthkit.datamodel.SleuthkitCase.escapeSingleQuotes;

/**
 * An interface for timeline events filters used to selectively query the
 * timeline tables in the case database for timeline events via the APIs of the
 * timeline manager.
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
	 * A timeline events filter that ANDs together a collection of timeline
	 * event filters.
	 *
	 * @param <SubFilterType> The type of the filters to be AND'ed together.
	 */
	public static class IntersectionFilter<SubFilterType extends TimelineFilter> extends CompoundFilter<SubFilterType> {

		/**
		 * Constructs timeline events filter that ANDs together a collection of
		 * timeline events filters.
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
	 * A timeline events filter used to query for a subset of the event types in
	 * the event types hierarchy. The filter is built via a recursive descent
	 * from any given type in the hierarchy, effectively creating a filter that
	 * accepts the events in a branch of the event types hierarchy.
	 */
	public static final class EventTypeFilter extends UnionFilter<EventTypeFilter> {

		private final TimelineEventType rootEventType;

		/**
		 * Constucts a timeline events filter used to query for a subset of the
		 * event types in the event types hierarchy. The filter is optionally
		 * built via a recursive descent from any given type in the hierarchy,
		 * effectively creating a filter that accepts the events in a branch of
		 * the event types hierarchy. Thsi constructor exists solely for the use
		 * of this filter's implementation of the copyOf API.
		 *
		 * @param rootEventType The "root" of the event hierarchy for the
		 *                      purposes of this filter.
		 * @param recursive     Whether or not to do a recursive descent of the
		 *                      event types hierarchy from the root event type.
		 */
		private EventTypeFilter(TimelineEventType rootEventType, boolean recursive) {
			super(new ArrayList<>());
			this.rootEventType = rootEventType;
			if (recursive) {
				// add subfilters for each subtype
				for (TimelineEventType subType : rootEventType.getChildren()) {
					addSubFilter(new EventTypeFilter(subType));
				}
			}
		}

		/**
		 * Constructs a timeline events filter used to query for a subset of the
		 * event types in the event types hierarchy. The subset of event types
		 * that pass the filter is determined by a recursive descent from any
		 * given type in the hierarchy, effectively creating a filter that
		 * accepts the events in a branch of the event types hierarchy.
		 *
		 * @param rootEventType The "root" of the event hierarchy for the
		 *                      purposes of this filter.
		 */
		public EventTypeFilter(TimelineEventType rootEventType) {
			this(rootEventType, true);
		}

		/**
		 * Gets the "root" of the branch of the event types hierarchy accepted
		 * by this filter.
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
		public EventTypeFilter copyOf() {
			//make a nonrecursive copy of this filter, and then copy subfilters
			// RC (10/1/19): Why?
			return copySubFilters(this, new EventTypeFilter(rootEventType, false));
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
			final EventTypeFilter other = (EventTypeFilter) obj;
			if (notEqual(this.rootEventType, other.getRootEventType())) {
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
				return this.getSubFilters().stream().flatMap(EventTypeFilter::getSubTypeIDs);
			}
		}

		@Override
		public String toString() {
			return "EventTypeFilter{" + "rootEventType=" + rootEventType + ", subfilters=" + getSubFilters() + '}';
		}

	}

	/**
	 * A timeline events filter used to query for events where the direct source
	 * (file or artifact) of the events has either been tagged or not tagged.
	 */
	public static final class TagsFilter extends TimelineFilter {

		private boolean eventSourcesAreTagged;

		/**
		 * Constructs a timeline events filter used to query for a events where
		 * the direct source (file or artifact) of the events has not been
		 * tagged.
		 */
		public TagsFilter() {
		}

		/**
		 * Constructs a timeline events filter used to query for events where
		 * the direct source (file or artifact) of the events has either been
		 * tagged or not tagged.
		 *
		 * @param eventSourcesAreTagged Whether the direct sources of the events
		 *                              need to be tagged or not tagged to be
		 *                              accepted by this filter.
		 */
		public TagsFilter(boolean eventSourcesAreTagged) {
			this.eventSourcesAreTagged = eventSourcesAreTagged;
		}

		/**
		 * Sets whether the direct sources of the events have to be tagged or
		 * not tagged to be accepted by this filter.
		 *
		 * @param eventSourcesAreTagged Whether the direct sources of the events
		 *                              have to be tagged or not tagged to be
		 *                              accepted by this filter.
		 */
		public synchronized void setEventSourcesAreTagged(boolean eventSourcesAreTagged) {
			this.eventSourcesAreTagged = eventSourcesAreTagged;
		}

		/**
		 * Indicates whether the direct sources of the events have to be tagged
		 * or not tagged.
		 *
		 * @return True or false.
		 */
		public synchronized boolean getEventSourceAreTagged() {
			return eventSourcesAreTagged;
		}

		@Override
		public String getDisplayName() {
			return BundleProvider.getBundle().getString("tagsFilter.displayName.text");
		}

		@Override
		public TagsFilter copyOf() {
			return new TagsFilter(eventSourcesAreTagged);
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null || !(obj instanceof TagsFilter)) {
				return false;
			}

			return ((TagsFilter) obj).getEventSourceAreTagged() == getEventSourceAreTagged();
		}

		@Override
		public int hashCode() {
			int hash = 7;
			hash = 67 * hash + Objects.hashCode(this.eventSourcesAreTagged);
			return hash;
		}

		@Override
		String getSQLWhere(TimelineManager manager) {
			String whereStr;
			if (eventSourcesAreTagged) {
				whereStr = "tagged = 1";
			} else {
				whereStr = "tagged = 0";
			}

			return whereStr;
		}

	}

	/**
	 * A timeline events filter that ORs together a collection of timeline
	 * events filters.
	 *
	 * @param <SubFilterType> The type of the filters to be OR'ed together.
	 */
	public static abstract class UnionFilter<SubFilterType extends TimelineFilter> extends TimelineFilter.CompoundFilter<SubFilterType> {

		UnionFilter(List<SubFilterType> subFilters) {
			super(subFilters);
		}

		UnionFilter() {
			super(new ArrayList<SubFilterType>());
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
	 * A timeline events filter used to query for events that have a particular
	 * substring in their short, medium, or full descriptions.
	 */
	public static final class TextFilter extends TimelineFilter {

		private String descriptionSubstring;

		/**
		 * Constructs a timeline events filter used to query for events that
		 * have the empty string as a substring in their short, medium, or full
		 * descriptions.
		 */
		public TextFilter() {
			this("");
		}

		/**
		 * Constructs a timeline events filter used to query for events that
		 * have a given substring in their short, medium, or full descriptions.
		 *
		 * @param descriptionSubstring The substring that must be present in one
		 *                             or more of the descriptions of each event
		 *                             that passes the filter.
		 */
		public TextFilter(String descriptionSubstring) {
			super();
			this.descriptionSubstring = descriptionSubstring.trim();
		}

		/**
		 * Sets the substring that must be present in one or more of the
		 * descriptions of each event that passes the filter.
		 *
		 * @param descriptionSubstring The substring.
		 */
		public synchronized void setDescriptionSubstring(String descriptionSubstring) {
			this.descriptionSubstring = descriptionSubstring.trim();
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
		public synchronized String getDescriptionSubstring() {
			return descriptionSubstring;
		}

		@Override
		public synchronized TextFilter copyOf() {
			return new TextFilter(getDescriptionSubstring());
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			final TextFilter other = (TextFilter) obj;
			return Objects.equals(getDescriptionSubstring(), other.getDescriptionSubstring());
		}

		@Override
		public int hashCode() {
			int hash = 5;
			hash = 29 * hash + Objects.hashCode(this.descriptionSubstring);
			return hash;
		}

		@Override
		String getSQLWhere(TimelineManager manager) {
			if (StringUtils.isNotBlank(this.getDescriptionSubstring())) {
				return "((med_description like '%" + escapeSingleQuotes(this.getDescriptionSubstring()) + "%')" //NON-NLS
						+ " or (full_description like '%" + escapeSingleQuotes(this.getDescriptionSubstring()) + "%')" //NON-NLS
						+ " or (short_description like '%" + escapeSingleQuotes(this.getDescriptionSubstring()) + "%'))"; //NON-NLS
			} else {
				return manager.getSQLWhere(null);
			}
		}

		@Override
		public String toString() {
			return "TextFilter{" + "textProperty=" + descriptionSubstring + '}';
		}

	}

	/**
	 * A timeline events filter that ANDs together instances of a variety of
	 * event filter types to create what is in effect a "tree" of filters.
	 */
	public static final class RootFilter extends IntersectionFilter<TimelineFilter> {

		private final HideKnownFilter knownFilesFilter;
		private final TagsFilter tagsFilter;
		private final HashHitsFilter hashSetHitsFilter;
		private final TextFilter descriptionSubstringFilter;
		private final EventTypeFilter eventTypesFilter;
		private final DataSourcesFilter dataSourcesFilter;
		private final FileTypesFilter fileTypesFilter;
		private final Set<TimelineFilter> additionalFilters = new HashSet<>();

		/**
		 * Get the data sources filter of this filter.
		 *
		 * @return The filter.
		 */
		public DataSourcesFilter getDataSourcesFilter() {
			return dataSourcesFilter;
		}

		/**
		 * Gets the tagged events sources filter of this filter.
		 *
		 * @return The filter.
		 */
		public TagsFilter getTagsFilter() {
			return tagsFilter;
		}

		/**
		 * Gets the source file hash set hits filter of this filter.
		 *
		 * @return The filter.
		 */
		public HashHitsFilter getHashHitsFilter() {
			return hashSetHitsFilter;
		}

		/**
		 * Gets the event types filter of this filter.
		 *
		 * @return The filter.
		 */
		public EventTypeFilter getEventTypeFilter() {
			return eventTypesFilter;
		}

		/**
		 * Gets the exclude known source files filter of this filter.
		 *
		 * @return The filter.
		 */
		public HideKnownFilter getKnownFilter() {
			return knownFilesFilter;
		}

		/**
		 * Gets the description substring filter of this filter.
		 *
		 * @return The filter.
		 */
		public TextFilter getTextFilter() {
			return descriptionSubstringFilter;
		}

		/**
		 * Gets the source file types filter of this filter.
		 *
		 * @return The filter.
		 */
		public FileTypesFilter getFileTypesFilter() {
			return fileTypesFilter;
		}

		/**
		 * Constructs a timeline events filter that ANDs together instances of a
		 * variety of event filter types to create what is in effect a "tree" of
		 * filters.
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
		 * @param fileTypesFilter            A filter that includes or excludes
		 *                                   events with source files of
		 *                                   particular media types.
		 * @param additionalFilters          Additional filters.
		 */
		public RootFilter(
				HideKnownFilter knownFilesFilter,
				TagsFilter tagsFilter,
				HashHitsFilter hashSetHitsFilter,
				TextFilter descriptionSubstringFilter,
				EventTypeFilter eventTypesFilter,
				DataSourcesFilter dataSourcesFilter,
				FileTypesFilter fileTypesFilter,
				Collection<TimelineFilter> additionalFilters) {

			super(Arrays.asList(descriptionSubstringFilter, knownFilesFilter, tagsFilter, dataSourcesFilter, hashSetHitsFilter, fileTypesFilter, eventTypesFilter));
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
					filter(this::hasAdditionalFilter).
					map(TimelineFilter::copyOf).
					forEach(anonymousFilter -> getSubFilters().add(anonymousFilter));
		}

		@Override
		public RootFilter copyOf() {
			Set<TimelineFilter> subFilters = getSubFilters().stream()
					.filter(this::hasAdditionalFilter)
					.map(TimelineFilter::copyOf)
					.collect(Collectors.toSet());
			return new RootFilter(knownFilesFilter.copyOf(), tagsFilter.copyOf(),
					hashSetHitsFilter.copyOf(), descriptionSubstringFilter.copyOf(), eventTypesFilter.copyOf(),
					dataSourcesFilter.copyOf(), fileTypesFilter.copyOf(), subFilters);

		}

		private boolean hasAdditionalFilter(TimelineFilter subFilter) {
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
			final RootFilter other = (RootFilter) obj;
			if (notEqual(this.knownFilesFilter, other.getKnownFilter())) {
				return false;
			}
			if (notEqual(this.tagsFilter, other.getTagsFilter())) {
				return false;
			}
			if (notEqual(this.hashSetHitsFilter, other.getHashHitsFilter())) {
				return false;
			}
			if (notEqual(this.descriptionSubstringFilter, other.getTextFilter())) {
				return false;
			}
			if (notEqual(this.eventTypesFilter, other.getEventTypeFilter())) {
				return false;
			}
			if (notEqual(this.dataSourcesFilter, other.getDataSourcesFilter())) {
				return false;
			}

			if (notEqual(this.fileTypesFilter, other.getFileTypesFilter())) {
				return false;
			}

			return Objects.equals(this.additionalFilters, new HashSet<>(other.getSubFilters()));
		}

	}

	/**
	 * A timeline events filter used to filter out events that have a direct or
	 * indirect event source that is a known file.
	 */
	public static final class HideKnownFilter extends TimelineFilter {

		@Override
		public String getDisplayName() {
			return BundleProvider.getBundle().getString("hideKnownFilter.displayName.text");
		}

		@Override
		public HideKnownFilter copyOf() {
			return new HideKnownFilter();
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
	 * A timeline events filter composed of a collection of event filters.
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

		private final List<SubFilterType> subFilters = new ArrayList<>();

		/**
		 * Gets the collection of filters that make up this filter.
		 *
		 * @return The filters.
		 */
		public final List<SubFilterType> getSubFilters() {
			return subFilters;
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
		 * Constructs a timeline events filter composed of a collection of event
		 * filters.
		 *
		 * @param subFilters The collection of filters.
		 */
		protected CompoundFilter(List<SubFilterType> subFilters) {
			super();
			this.subFilters.addAll(subFilters);
		}

		@Override
		public abstract CompoundFilter<SubFilterType> copyOf();

		@Override
		public int hashCode() {
			int hash = 3;
			hash = 23 * hash + Objects.hashCode(this.subFilters);
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
			return this.getClass().getSimpleName() + "{" + "subFilters=" + subFilters + '}';
		}

	}

	/**
	 * A timeline events filter used to query for events associated with a given
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
		 * Constructs a timeline events filter used to query for events
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
	 * A timeline events filter used to query for events where the files that
	 * are the direct or indirect sources of the events either have or do not
	 * have hash set hits.
	 *
	 */
	public static final class HashHitsFilter extends TimelineFilter {

		private boolean eventSourcesHaveHashSetHits;

		/**
		 * Constructs a timeline events filter used to query for events where
		 * the files that are the direct or indirect sources of the events
		 * either do not have hash set hits.
		 */
		public HashHitsFilter() {
		}

		/**
		 * Constructs a timeline events filter used to query for events where
		 * the files that are the direct or indirect sources of the events
		 * either have or do not have hash set hits.
		 *
		 * @param eventSourcesHaveHashSetHits Whether or not the files
		 *                                    associated with the events have or
		 *                                    do not have hash set hits.
		 */
		public HashHitsFilter(boolean eventSourcesHaveHashSetHits) {
			this.eventSourcesHaveHashSetHits = eventSourcesHaveHashSetHits;
		}

		/**
		 * Sets whether or not the files associated with the events have or do
		 * not have hash set hits
		 *
		 * @param eventSourcesHaveHashSetHits True or false.
		 */
		public synchronized void setEventSourcesHaveHashSetHits(boolean eventSourcesHaveHashSetHits) {
			this.eventSourcesHaveHashSetHits = eventSourcesHaveHashSetHits;
		}

		/**
		 * Indicates whether or not the files associated with the events have or
		 * do not have hash set hits
		 *
		 * @return True or false.
		 */
		public synchronized boolean getEventSourcesHaveHashSetHits() {
			return eventSourcesHaveHashSetHits;
		}

		@Override
		public String getDisplayName() {
			return BundleProvider.getBundle().getString("hashHitsFilter.displayName.text");
		}

		@Override
		public HashHitsFilter copyOf() {
			return new HashHitsFilter(eventSourcesHaveHashSetHits);
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null || !(obj instanceof HashHitsFilter)) {
				return false;
			}

			return ((HashHitsFilter) obj).getEventSourcesHaveHashSetHits() == getEventSourcesHaveHashSetHits();
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
			if (eventSourcesHaveHashSetHits) {
				whereStr = "hash_hit = 1";
			} else {
				whereStr = "hash_hit = 0";
			}

			return whereStr;
		}

	}

	/**
	 * A timeline events filter used to query for events associated with a given
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
	 * A timeline events filter used to query for events with direct or indirect
	 * event sources that are files with a given set of media types. The filter
	 * is a union of one or more file source filters.
	 */
	static public final class FileTypesFilter extends UnionFilter<FileTypeFilter> {

		@Override
		public FileTypesFilter copyOf() {
			return copySubFilters(this, new FileTypesFilter());
		}

		@Override
		public String getDisplayName() {
			return BundleProvider.getBundle().getString("FileTypesFilter.displayName.text");
		}

	}

	/**
	 * A timeline events filter used to query for events with direct or indirect
	 * event sources that are files that do not have a given set of media types.
	 */
	static public class InverseFileTypeFilter extends FileTypeFilter {

		public InverseFileTypeFilter(String displayName, Collection<String> mediaTypes) {
			super(displayName, mediaTypes);
		}

		@Override
		public InverseFileTypeFilter copyOf() {
			return new InverseFileTypeFilter(getDisplayName(), super.mediaTypes);
		}

		@Override
		String getSQLWhere(TimelineManager manager) {
			return " NOT " + super.getSQLWhere(manager);
		}
	}

	/**
	 * A timeline events filter used to query for events with direct or indirect
	 * event sources that are files with a given set of media types.
	 */
	public static class FileTypeFilter extends TimelineFilter {

		private final String displayName;
		private final String sqlWhere;
		Collection<String> mediaTypes = new HashSet<>();

		private FileTypeFilter(String displayName, String sql) {
			this.displayName = displayName;
			this.sqlWhere = sql;
		}

		/**
		 * Constructs a timeline events filter used to query for events with
		 * direct or indirect event sources that are files with a given set of
		 * media types.
		 *
		 * @param displayName The display name for the filter.
		 * @param mediaTypes  The event source file media types that pass the
		 *                    filter.
		 */
		public FileTypeFilter(String displayName, Collection<String> mediaTypes) {
			this(displayName,
					mediaTypes.stream()
							.map(MediaType::parse)
							.map(FileTypeFilter::mediaTypeToSQL)
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
		public FileTypeFilter copyOf() {
			return new FileTypeFilter(displayName, sqlWhere);
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
			final FileTypeFilter other = (FileTypeFilter) obj;
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
