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

import com.google.common.collect.Lists;
import com.google.common.net.MediaType;
import static java.util.Arrays.asList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import static java.util.stream.Collectors.joining;
import java.util.stream.Stream;
import javafx.beans.property.Property;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import static org.apache.commons.lang3.ObjectUtils.notEqual;
import org.apache.commons.lang3.StringUtils;
import static org.sleuthkit.datamodel.SleuthkitCase.escapeSingleQuotes;
import org.sleuthkit.datamodel.TagName;
import org.sleuthkit.datamodel.TimelineManager;
import org.sleuthkit.datamodel.TskData;

/**
 * Interface for timeline event filters. Filters are given to the
 * TimelineManager who interpretes them appropriately for all db queries.
 */
public abstract class TimelineFilter {

	/**
	 * get the display name of this filter
	 *
	 * @return a name for this filter to show in the UI
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

	public abstract TimelineFilter copyOf();

	@SuppressWarnings("unchecked")
	private static <S extends TimelineFilter, T extends CompoundFilter<S>> T copySubFilters(T from, T to) {
		from.getSubFilters().forEach(subFilter -> to.addSubFilter((S) subFilter.copyOf()));
		return to;
	}

	/**
	 * Intersection (And) filter
	 *
	 * @param <S> The type of sub Filters in this IntersectionFilter.
	 */
	public static class IntersectionFilter<S extends TimelineFilter> extends CompoundFilter<S> {

		IntersectionFilter(List<S> subFilters) {
			super(subFilters);
		}

		@Override
		public IntersectionFilter<S> copyOf() {
			@SuppressWarnings("unchecked")
			List<S> subfilters = Lists.transform(getSubFilters(), f -> (S) f.copyOf()); //make copies of all the subfilters.
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
		public String getSQLWhere(TimelineManager manager) {
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
	 * Filter to show only events tag with the tagNames of the selected
	 * subfilters.
	 */
	public static final class TagsFilter extends UnionFilter<TagNameFilter> {

		@Override
		public String getDisplayName() {
			return BundleProvider.getBundle().getString("tagsFilter.displayName.text");
		}

		@Override
		public TagsFilter copyOf() {
			return copySubFilters(this, new TagsFilter());
		}

		public void removeFilterForTag(TagName tagName) {
			getSubFilters().removeIf(subfilter -> subfilter.getTagName().equals(tagName));
			getSubFilters().sort(Comparator.comparing(TagNameFilter::getDisplayName));
		}
	}

	/**
	 * Union(or) filter
	 *
	 * @param <SubFilterType> The type of the subfilters.
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
		public String getSQLWhere(TimelineManager manager) {
			String join = getSubFilters().stream()
					.map(subFilter -> subFilter.getSQLWhere(manager))
					.collect(Collectors.joining(" OR "));
			return join.isEmpty() ? manager.getSQLWhere(null) : "(" + join + ")";
		}

	}

	/**
	 * Event Type Filter. An instance of EventTypeFilter is usually a tree that
	 * parallels the event type hierarchy with one filter/node for each event
	 * type.
	 */
	public final static class EventTypeFilter extends UnionFilter<EventTypeFilter> {

		private static final Comparator<EventTypeFilter> comparator = Comparator.comparing(EventTypeFilter::getEventType);
		/**
		 * the event type this filter passes
		 */
		private final EventType eventType;

		/**
		 * private constructor that enables non recursive/tree construction of
		 * the filter hierarchy for use in EventTypeFilter.copyOf().
		 *
		 * @param eventType the event type this filter passes
		 * @param recursive true if subfilters should be added for each subtype.
		 *                  False if no subfilters should be added.
		 */
		private EventTypeFilter(EventType eventType, boolean recursive) {
			super(FXCollections.observableArrayList());
			this.eventType = eventType;
			if (recursive) {
				// add subfilters for each subtype
				for (EventType subType : eventType.getSubTypes()) {
					addSubFilter(new EventTypeFilter(subType), comparator);
				}
			}
		}

		/**
		 * public constructor. creates a subfilter for each subtype of the given
		 * event type
		 *
		 * @param eventType the event type this filter will pass
		 */
		public EventTypeFilter(EventType eventType) {
			this(eventType, true);
		}

		public EventType getEventType() {
			return eventType;
		}

		@Override
		public String getDisplayName() {
			return (EventType.ROOT_EVENT_TYPE.equals(eventType))
					? BundleProvider.getBundle().getString("TypeFilter.displayName.text")
					: eventType.getDisplayName();
		}

		@Override
		public EventTypeFilter copyOf() {
			//make a nonrecursive copy of this filter, and then copy subfilters
			return copySubFilters(this, new EventTypeFilter(eventType, false));
		}

		@Override
		public int hashCode() {
			int hash = 7;
			hash = 17 * hash + Objects.hashCode(this.eventType);
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
			if (notEqual(this.eventType, other.eventType)) {
				return false;
			}
			return Objects.equals(this.getSubFilters(), other.getSubFilters());
		}

		@Override
		public String getSQLWhere(TimelineManager manager) {
			return "(tsk_events.event_type_id IN (" + getSubTypeIDs().collect(joining(",")) + "))"; //NON-NLS
		}

		private Stream<String> getSubTypeIDs() {
			if (this.getSubFilters().isEmpty()) {
				return Stream.of(String.valueOf(getEventType().getTypeID()));
			} else {
				return this.getSubFilters().stream().flatMap(EventTypeFilter::getSubTypeIDs);
			}
		}
	}

	/**
	 * Filter for text matching
	 */
	public static final class TextFilter extends TimelineFilter {

		private final SimpleStringProperty textProperty = new SimpleStringProperty();

		public TextFilter() {
			this("");
		}

		public TextFilter(String text) {
			super();
			this.textProperty.set(text.trim());
		}

		public synchronized void setText(String text) {
			this.textProperty.set(text.trim());
		}

		@Override
		public String getDisplayName() {
			return BundleProvider.getBundle().getString("TextFilter.displayName.text");
		}

		public synchronized String getText() {
			return textProperty.getValue();
		}

		public Property<String> textProperty() {
			return textProperty;
		}

		@Override
		public synchronized TextFilter copyOf() {
			return new TextFilter(getText());
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
			return Objects.equals(getText(), other.getText());
		}

		@Override
		public int hashCode() {
			int hash = 5;
			hash = 29 * hash + Objects.hashCode(this.textProperty.get());
			return hash;
		}

		@Override
		public String getSQLWhere(TimelineManager manager) {
			if (StringUtils.isNotBlank(this.getText())) {
				return "((med_description like '%" + escapeSingleQuotes(this.getText()) + "%')" //NON-NLS
						+ " or (full_description like '%" + escapeSingleQuotes(this.getText()) + "%')" //NON-NLS
						+ " or (short_description like '%" + escapeSingleQuotes(this.getText()) + "%'))"; //NON-NLS
			} else {
				return manager.getSQLWhere(null);
			}
		}

	}

	/**
	 * An implementation of IntersectionFilter designed to be used as the root
	 * of a filter tree. provides named access to specific subfilters.
	 */
	public static final class RootFilter extends IntersectionFilter<TimelineFilter> {

		private final HideKnownFilter knownFilter;
		private final TagsFilter tagsFilter;
		private final HashHitsFilter hashFilter;
		private final TextFilter textFilter;
		private final EventTypeFilter typeFilter;
		private final DataSourcesFilter dataSourcesFilter;
		private final FileTypesFilter fileTypesFilter;
		private final Set<TimelineFilter> namedSubFilters = new HashSet<>();

		public DataSourcesFilter getDataSourcesFilter() {
			return dataSourcesFilter;
		}

		public TagsFilter getTagsFilter() {
			return tagsFilter;
		}

		public HashHitsFilter getHashHitsFilter() {
			return hashFilter;
		}

		public EventTypeFilter getEventTypeFilter() {
			return typeFilter;
		}

		public HideKnownFilter getKnownFilter() {
			return knownFilter;
		}

		public TextFilter getTextFilter() {
			return textFilter;
		}

		public FileTypesFilter getFileTypesFilter() {
			return fileTypesFilter;
		}

		public RootFilter(HideKnownFilter knownFilter, TagsFilter tagsFilter, HashHitsFilter hashFilter,
				TextFilter textFilter, EventTypeFilter typeFilter, DataSourcesFilter dataSourcesFilter,
				FileTypesFilter fileTypesFilter, Collection<TimelineFilter> annonymousSubFilters) {
			super(FXCollections.observableArrayList(textFilter, knownFilter, dataSourcesFilter, tagsFilter, hashFilter, typeFilter, fileTypesFilter));

			getSubFilters().removeIf(Objects::isNull);
			this.knownFilter = knownFilter;
			this.tagsFilter = tagsFilter;
			this.hashFilter = hashFilter;
			this.textFilter = textFilter;
			this.typeFilter = typeFilter;
			this.dataSourcesFilter = dataSourcesFilter;
			this.fileTypesFilter = fileTypesFilter;

			namedSubFilters.addAll(asList(knownFilter, tagsFilter, hashFilter,
					textFilter, typeFilter, dataSourcesFilter, fileTypesFilter));
			namedSubFilters.removeIf(Objects::isNull);
			annonymousSubFilters.stream().
					filter(Objects::nonNull).
					filter(this::isNamedSubFilter).
					map(TimelineFilter::copyOf).
					forEach(anonymousFilter -> getSubFilters().add(anonymousFilter));
		}

		@Override
		public RootFilter copyOf() {
			Set<TimelineFilter> annonymousSubFilters = getSubFilters().stream()
					.filter(this::isNamedSubFilter)
					.map(TimelineFilter::copyOf)
					.collect(Collectors.toSet());
			return new RootFilter(knownFilter.copyOf(), tagsFilter.copyOf(),
					hashFilter.copyOf(), textFilter.copyOf(), typeFilter.copyOf(),
					dataSourcesFilter.copyOf(), fileTypesFilter.copyOf(), annonymousSubFilters);

		}

		private boolean isNamedSubFilter(TimelineFilter subFilter) {
			return !(namedSubFilters.contains(subFilter));
		}

	}

	/**
	 * Filter to hide known files
	 */
	public static final class HideKnownFilter extends TimelineFilter {

		@Override
		public String getDisplayName() {
			return BundleProvider.getBundle().getString("hideKnownFilter.displayName.text");
		}

		public HideKnownFilter() {
			super();
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
		public String getSQLWhere(TimelineManager manager) {
			return "(known_state != " + TskData.FileKnown.KNOWN.getFileKnownValue() + ")"; // NON-NLS
		}

	}

	/**
	 * A Filter with a collection of sub-filters. Concrete implementations can
	 * decide how to combine the sub-filters.
	 *
	 * @param <SubFilterType> The type of the subfilters.
	 */
	public static abstract class CompoundFilter<SubFilterType extends TimelineFilter> extends TimelineFilter {

		protected void addSubFilter(SubFilterType subfilter) {
			addSubFilter(subfilter, Comparator.comparing(TimelineFilter::getDisplayName));
		}

		protected void addSubFilter(SubFilterType subfilter, Comparator<SubFilterType> comparator) {
			if (getSubFilters().contains(subfilter) == false) {
				getSubFilters().add(subfilter);
			}
			getSubFilters().sort(comparator);
		}

		/**
		 * The list of sub-filters that make up this filter
		 */
		private final ObservableList<SubFilterType> subFilters = FXCollections.observableArrayList();

		public final ObservableList<SubFilterType> getSubFilters() {
			return subFilters;
		}

		public boolean hasSubFilters() {
			return getSubFilters().isEmpty() == false;
		}

		/**
		 * construct a compound filter from a list of other filters to combine.
		 *
		 * @param subFilters
		 */
		CompoundFilter(List<SubFilterType> subFilters) {
			super();
			this.subFilters.setAll(subFilters);
		}

		static < C extends CompoundFilter<?>> boolean areSubFiltersEqual(C oneFilter, C otherFilter) {
			if (oneFilter.getSubFilters().size() != otherFilter.getSubFilters().size()) {
				return false;
			}
			for (int i = 0; i < oneFilter.getSubFilters().size(); i++) {
				TimelineFilter subFilter = oneFilter.getSubFilters().get(i);
				TimelineFilter otherSubFilter = otherFilter.getSubFilters().get(i);
				if (subFilter.equals(otherSubFilter) == false) {
					return false;
				}
			}
			return true;
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
	}

	/**
	 * Filter for an individual hash set
	 */
	static public final class HashSetFilter extends TimelineFilter {

		private final String hashSetName;

		public String getHashSetName() {
			return hashSetName;
		}

		public HashSetFilter(String hashSetName) {
			super();
			this.hashSetName = hashSetName;
		}

		@Override
		public synchronized HashSetFilter copyOf() {
			return new HashSetFilter(getHashSetName());
		}

		@Override
		public String getDisplayName() {
			return hashSetName;
		}

		@Override
		public int hashCode() {
			int hash = 7;
			hash = 79 * hash + Objects.hashCode(this.hashSetName);
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
			final HashSetFilter other = (HashSetFilter) obj;
			return Objects.equals(this.hashSetName, other.hashSetName);
		}

		@Override
		public String getSQLWhere(TimelineManager manager) {
			return "(hash_set_name = '" + escapeSingleQuotes(getHashSetName()) + "' )"; //NON-NLS
		}

	}

	/**
	 * Filter for an individual datasource
	 */
	public static final class DataSourceFilter extends TimelineFilter {

		private final String dataSourceName;
		private final long dataSourceID;

		public long getDataSourceID() {
			return dataSourceID;
		}

		public String getDataSourceName() {
			return dataSourceName;
		}

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
		public String getSQLWhere(TimelineManager manager) {
			return "(data_source_obj_id = '" + this.getDataSourceID() + "')"; //NON-NLS
		}

	}

	/**
	 * Filter for an individual TagName
	 */
	static public final class TagNameFilter extends TimelineFilter {

		private final TagName tagName;

		public TagNameFilter(TagName tagName) {
			super();
			this.tagName = tagName;
		}

		public TagName getTagName() {
			return tagName;
		}

		@Override
		public synchronized TagNameFilter copyOf() {
			return new TagNameFilter(getTagName());
		}

		@Override
		public String getDisplayName() {
			return tagName.getDisplayName();
		}

		@Override
		public int hashCode() {
			int hash = 3;
			hash = 73 * hash + Objects.hashCode(this.tagName);
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
			final TagNameFilter other = (TagNameFilter) obj;
			return Objects.equals(this.tagName, other.tagName);
		}

		@Override
		public String getSQLWhere(TimelineManager manager) {
			return " (tsk_events.tag_name_id = " + getTagName().getId() + " ) "; //NON-NLS
		}

	}

	/**
	 *
	 */
	static public final class HashHitsFilter extends UnionFilter<HashSetFilter> {

		@Override
		public String getDisplayName() {
			return BundleProvider.getBundle().getString("hashHitsFilter.displayName.text");
		}

		@Override
		public HashHitsFilter copyOf() {
			return copySubFilters(this, new HashHitsFilter());
		}
	}

	/**
	 * union of DataSourceFilters
	 */
	static public final class DataSourcesFilter extends UnionFilter< DataSourceFilter> {

		public DataSourcesFilter() {
			super();
		}

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
	 * union of FileTypeFilters
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
	 * Filter for events derived from files with the given media/mime-types.
	 */
	public static class FileTypeFilter extends TimelineFilter {

		private final String displayName;
		private final String sqlWhere;

		private FileTypeFilter(String displayName, String sql) {
			this.displayName = displayName;
			this.sqlWhere = sql;
		}

		public FileTypeFilter(String displayName, Collection<String> mediaTypes) {
			this(displayName,
					mediaTypes.stream()
							.map(MediaType::parse)
							.map(FileTypeFilter::mediaTypeToSQL)
							.collect(Collectors.joining(" OR ", "(", ")")));
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
		protected String getSQLWhere(TimelineManager manager) {
			return sqlWhere;
		}
	}
}
