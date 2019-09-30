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
 * Interface for filters used to query the timeline tables in the case database
 * via the APIs of the TimelineManager. Each implementation of a filter supplies
 * an SQL WHERE clause. 
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

	public abstract TimelineFilter copyOf();

	@SuppressWarnings("unchecked")
	static <S extends TimelineFilter, T extends CompoundFilter<S>> T copySubFilters(T from, T to) {
		from.getSubFilters().forEach(subFilter -> to.addSubFilter((S) subFilter.copyOf()));
		return to;
	}

	/**
	 * Intersection (And) filter
	 *
	 * @param <S> The type of sub Filters in this IntersectionFilter.
	 */
	public static class IntersectionFilter<S extends TimelineFilter> extends CompoundFilter<S> {

		@VisibleForTesting
		public IntersectionFilter(List<S> subFilters) {
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
	 * Event Type Filter. An instance of EventTypeFilter is usually a tree that
	 * parallels the event type hierarchy with one filter/node for each event
	 * type.
	 */
	public static final class EventTypeFilter extends UnionFilter<EventTypeFilter> {

		/**
		 * the event type this filter passes
		 */
		private final TimelineEventType eventType;

		/**
		 * private constructor that enables non recursive/tree construction of
		 * the filter hierarchy for use in EventTypeFilter.copyOf().
		 *
		 * @param eventType the event type this filter passes
		 * @param recursive true if subfilters should be added for each subtype.
		 *                  False if no subfilters should be added.
		 */
		private EventTypeFilter(TimelineEventType eventType, boolean recursive) {
			super(FXCollections.observableArrayList());
			this.eventType = eventType;
			if (recursive) {
				// add subfilters for each subtype
				for (TimelineEventType subType : eventType.getChildren()) {
					addSubFilter(new EventTypeFilter(subType));
				}
			}
		}

		/**
		 * public constructor. creates a subfilter for each subtype of the given
		 * event type
		 *
		 * @param eventType the event type this filter will pass
		 */
		public EventTypeFilter(TimelineEventType eventType) {
			this(eventType, true);
		}

		public TimelineEventType getEventType() {
			return eventType;
		}

		@Override
		public String getDisplayName() {
			return (TimelineEventType.ROOT_EVENT_TYPE.equals(eventType)) ? BundleProvider.getBundle().getString("TypeFilter.displayName.text") : eventType.getDisplayName();
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
		String getSQLWhere(TimelineManager manager) {
			return "(tsk_events.event_type_id IN (" + getSubTypeIDs().collect(Collectors.joining(",")) + "))"; //NON-NLS
		}

		private Stream<String> getSubTypeIDs() {
			if (this.getSubFilters().isEmpty()) {
				return Stream.of(String.valueOf(getEventType().getTypeID()));
			} else {
				return this.getSubFilters().stream().flatMap(EventTypeFilter::getSubTypeIDs);
			}
		}

		@Override
		public String toString() {
			return "EventTypeFilter{" + "eventType=" + eventType + ", subfilters=" + getSubFilters() + '}';
		}

	}

	/**
	 * Filter to show only events that are associated with objects that have
	 * file or result tags.
	 */
	public static final class TagsFilter extends TimelineFilter {

		private final BooleanProperty booleanProperty = new SimpleBooleanProperty();

		/**
		 * Filter constructor.
		 */
		public TagsFilter() {
		}

		/**
		 * Filter constructor and set initial state.
		 *
		 * @param isTagged Boolean initial state for the filter.
		 */
		public TagsFilter(boolean isTagged) {
			booleanProperty.set(isTagged);
		}

		/**
		 * Set the state of the filter.
		 *
		 * @param isTagged True to filter events that are associated tagged
		 *                 items or results
		 */
		public synchronized void setTagged(boolean isTagged) {
			booleanProperty.set(isTagged);
		}

		/**
		 * Returns the current state of this filter.
		 *
		 * @return True to filter by objects that are tagged.
		 */
		public synchronized boolean isTagged() {
			return booleanProperty.get();
		}

		@Override
		public String getDisplayName() {
			return BundleProvider.getBundle().getString("tagsFilter.displayName.text");
		}

		@Override
		public TagsFilter copyOf() {
			return new TagsFilter(booleanProperty.get());
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null || !(obj instanceof TagsFilter)) {
				return false;
			}

			return ((TagsFilter) obj).isTagged() == booleanProperty.get();
		}

		@Override
		public int hashCode() {
			int hash = 7;
			hash = 67 * hash + Objects.hashCode(this.booleanProperty);
			return hash;
		}

		@Override
		String getSQLWhere(TimelineManager manager) {
			String whereStr = "";
			if (booleanProperty.get()) {
				whereStr = "tagged = 1";
			} else {
				whereStr = "tagged = 0";
			}

			return whereStr;
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
		String getSQLWhere(TimelineManager manager) {
			String join = getSubFilters().stream()
					.map(subFilter -> subFilter.getSQLWhere(manager))
					.collect(Collectors.joining(" OR "));
			return join.isEmpty() ? manager.getSQLWhere(null) : "(" + join + ")";
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
		String getSQLWhere(TimelineManager manager) {
			if (StringUtils.isNotBlank(this.getText())) {
				return "((med_description like '%" + escapeSingleQuotes(this.getText()) + "%')" //NON-NLS
						+ " or (full_description like '%" + escapeSingleQuotes(this.getText()) + "%')" //NON-NLS
						+ " or (short_description like '%" + escapeSingleQuotes(this.getText()) + "%'))"; //NON-NLS
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
			super(FXCollections.observableArrayList(textFilter, knownFilter, tagsFilter, dataSourcesFilter, hashFilter, fileTypesFilter, typeFilter));

			getSubFilters().removeIf(Objects::isNull);
			this.knownFilter = knownFilter;
			this.tagsFilter = tagsFilter;
			this.hashFilter = hashFilter;
			this.textFilter = textFilter;
			this.typeFilter = typeFilter;
			this.dataSourcesFilter = dataSourcesFilter;
			this.fileTypesFilter = fileTypesFilter;

			namedSubFilters.addAll(asList(textFilter, knownFilter, tagsFilter, dataSourcesFilter, hashFilter, fileTypesFilter, typeFilter));
			namedSubFilters.removeIf(Objects::isNull);
			annonymousSubFilters.stream().
					filter(Objects::nonNull).
					filter(this::isNotNamedSubFilter).
					map(TimelineFilter::copyOf).
					forEach(anonymousFilter -> getSubFilters().add(anonymousFilter));
		}

		@Override
		public RootFilter copyOf() {
			Set<TimelineFilter> annonymousSubFilters = getSubFilters().stream()
					.filter(this::isNotNamedSubFilter)
					.map(TimelineFilter::copyOf)
					.collect(Collectors.toSet());
			return new RootFilter(knownFilter.copyOf(), tagsFilter.copyOf(),
					hashFilter.copyOf(), textFilter.copyOf(), typeFilter.copyOf(),
					dataSourcesFilter.copyOf(), fileTypesFilter.copyOf(), annonymousSubFilters);

		}

		private boolean isNotNamedSubFilter(TimelineFilter subFilter) {
			return !(namedSubFilters.contains(subFilter));
		}

		@Override
		public String toString() {
			return "RootFilter{" + "knownFilter=" + knownFilter + ", tagsFilter=" + tagsFilter + ", hashFilter=" + hashFilter + ", textFilter=" + textFilter + ", typeFilter=" + typeFilter + ", dataSourcesFilter=" + dataSourcesFilter + ", fileTypesFilter=" + fileTypesFilter + ", namedSubFilters=" + namedSubFilters + '}';
		}

		@Override
		public int hashCode() {
			int hash = 7;
			hash = 17 * hash + Objects.hashCode(this.knownFilter);
			hash = 17 * hash + Objects.hashCode(this.tagsFilter);
			hash = 17 * hash + Objects.hashCode(this.hashFilter);
			hash = 17 * hash + Objects.hashCode(this.textFilter);
			hash = 17 * hash + Objects.hashCode(this.typeFilter);
			hash = 17 * hash + Objects.hashCode(this.dataSourcesFilter);
			hash = 17 * hash + Objects.hashCode(this.fileTypesFilter);
			hash = 17 * hash + Objects.hashCode(this.namedSubFilters);
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
			if (notEqual(this.knownFilter, other.knownFilter)) {
				return false;
			}
			if (notEqual(this.tagsFilter, other.tagsFilter)) {
				return false;
			}
			if (notEqual(this.hashFilter, other.hashFilter)) {
				return false;
			}
			if (notEqual(this.textFilter, other.textFilter)) {
				return false;
			}
			if (notEqual(this.typeFilter, other.typeFilter)) {
				return false;
			}
			if (notEqual(this.dataSourcesFilter, other.dataSourcesFilter)) {
				return false;
			}

			if (notEqual(this.fileTypesFilter, other.fileTypesFilter)) {
				return false;
			}
			return Objects.equals(this.namedSubFilters, other.namedSubFilters);
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
		String getSQLWhere(TimelineManager manager) {
			return "(known_state != " + TskData.FileKnown.KNOWN.getFileKnownValue() + ")"; // NON-NLS
		}

		@Override
		public String toString() {
			return "HideKnownFilter{" + '}';
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
			if (getSubFilters().contains(subfilter) == false) {
				getSubFilters().add(subfilter);
			}
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
		protected CompoundFilter(List<SubFilterType> subFilters) {
			super();
			this.subFilters.setAll(subFilters);
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
		String getSQLWhere(TimelineManager manager) {
			return "(data_source_obj_id = '" + this.getDataSourceID() + "')"; //NON-NLS
		}

	}

	/**
	 * TimelineFilter for events that are associated with objects have Hash
	 * Hits.
	 */
	public static final class HashHitsFilter extends TimelineFilter {

		private final BooleanProperty booleanProperty = new SimpleBooleanProperty();

		/**
		 * Default constructor.
		 */
		public HashHitsFilter() {
		}

		/**
		 * Construct the hash hit filter and set state based given argument.
		 *
		 * @param hasHashHit True to filter items that have hash hits.
		 */
		public HashHitsFilter(boolean hasHashHit) {
			booleanProperty.set(hasHashHit);
		}

		/**
		 * Set the state of the filter.
		 *
		 * @param hasHashHit True to filter by items that have hash hits.
		 */
		public synchronized void setTagged(boolean hasHashHit) {
			booleanProperty.set(hasHashHit);
		}

		/**
		 * Returns the current state of the filter.
		 *
		 * @return True to filter by hash hits
		 */
		public synchronized boolean hasHashHits() {
			return booleanProperty.get();
		}

		@Override
		public String getDisplayName() {
			return BundleProvider.getBundle().getString("hashHitsFilter.displayName.text");
		}

		@Override
		public HashHitsFilter copyOf() {
			return new HashHitsFilter(booleanProperty.get());
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null || !(obj instanceof HashHitsFilter)) {
				return false;
			}

			return ((HashHitsFilter) obj).hasHashHits() == booleanProperty.get();
		}

		@Override
		public int hashCode() {
			int hash = 7;
			hash = 67 * hash + Objects.hashCode(this.booleanProperty);
			return hash;
		}

		@Override
		String getSQLWhere(TimelineManager manager) {
			String whereStr = "";
			if (booleanProperty.get()) {
				whereStr = "hash_hit = 1";
			} else {
				whereStr = "hash_hit = 0";
			}

			return whereStr;
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
	 * Gets all files that are NOT the specified types
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
	 * Filter for events derived from files with the given media/mime-types.
	 */
	public static class FileTypeFilter extends TimelineFilter {

		private final String displayName;
		private final String sqlWhere;
		Collection<String> mediaTypes = new HashSet<>();

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
